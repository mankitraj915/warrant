"""Kernel entry points (DESIGN §1, §5, §8).

``run_task`` is the production path. The kernel builds the planner's input,
derives the plan label from it, invokes the planner once per task id, and runs
the plan. ``run_plan`` runs a given plan under a given plan label; the
non-interference tests use it to quantify over plans directly.

A run is: recover, check, resolve, decide, then execute only if every action
is ALLOWed or the whole set is approved. NEEDS_APPROVAL produces an approval
request (the canonical set and its hash) for ``env.approver``; an approval is
honoured only for this run, for the hash the kernel recomputes, and once
(DESIGN §7, NI-5). The default approver denies. Run ids are single-use. Every
run writes one append-only audit row (``audit`` table) explaining its decision.
"""

import hashlib
import json
import sqlite3
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from functools import partial
from typing import Any, Literal, Protocol

from .approval import Approval, Approver, DenyAll, canonical_set, digest
from .declassify import RuleDecision
from .execution import Executed, PaymentProvider, execute, recover
from .interpreter import Interpreter, ResolvedAction
from .labels import STAR, Label, join
from .plan_lang import PlanRejected, check_plan, parse_plan
from .policy import Verdict, decide
from .tools.database import Database, lossless_text
from .tools.registry import signatures
from .values import Record, Scalar, UnitV, plain, whole_label

OPERATOR = Label.trusted_source("operator")
Outcome = Literal[
    "executed",
    "blocked",
    "needs_approval",
    "approval_invalid",
    "rejected",
    "aborted",
    "partial",
    "indeterminate",
    "executing",  # only in the write-ahead "decided" audit row
]


@dataclass
class Environment:
    db: sqlite3.Connection
    provider: PaymentProvider
    extractor: Callable[[str], list[object]]
    planned_tasks: set[str] = field(default_factory=set)
    approver: Approver = field(default_factory=DenyAll)


@dataclass(frozen=True)
class RunResult:
    run_id: str
    outcome: Outcome
    reason: str
    actions: tuple[ResolvedAction, ...] = ()
    verdicts: tuple[Verdict, ...] = ()
    rule_log: tuple[RuleDecision, ...] = ()
    approval_request: dict[str, Any] | None = None
    approval_hash: str | None = None
    executed: tuple[Executed, ...] = ()
    plan_label: Label = OPERATOR
    planner_input_hash: str | None = None
    approved: bool = False
    answer: Any = None  # the plan's final value, for the operator (plain data)
    answer_sinks: list[str] | None = None  # None: unrestricted


def _origins(label: Label) -> list[str] | str:
    return STAR if STAR in label.untrusted else sorted(label.untrusted)


def _audit(
    db: sqlite3.Connection,
    r: RunResult,
    raw_plan: Any,
    task_id: str | None,
    phase: str = "final",
) -> RunResult:
    """Append one audit row. ``phase`` is "decided" for the write-ahead row committed
    before the first effect, "final" for the outcome (Gate 2 review #5)."""
    record = {
        "phase": phase,
        "task_id": task_id,
        "outcome": r.outcome,
        "reason": r.reason,
        "planner_input_hash": r.planner_input_hash,
        "plan_label": _origins(r.plan_label),
        "plan": raw_plan,
        "actions": [
            {
                "site": list(a.site),
                "tool": a.tool,
                "args": a.canonical_args(),
                "labels": {n: _origins(lbl) for n, lbl in a.component_labels().items()},
            }
            for a in r.actions
        ],
        "verdicts": [{"kind": v.kind, "reason": v.reason, "rule": v.rule} for v in r.verdicts],
        "rules": [
            {"rule": d.rule, "site": list(d.site), "admitted": d.admitted, "reason": d.reason}
            for d in r.rule_log
        ],
        "approval_request": r.approval_request,
        "approval_hash": r.approval_hash,
        "approved": r.approved,
        "answer": r.answer,
        "answer_sinks": r.answer_sinks,
        "executed": [
            {
                "site": list(x.site),
                "tool": x.tool,
                "key": x.idempotency_key,
                "provider_ref": x.provider_ref,
            }
            for x in r.executed
        ],
    }
    text = json.dumps(record, sort_keys=True, ensure_ascii=False, default=repr)
    db.execute("INSERT INTO audit (run_id, record) VALUES (?, ?)", (r.run_id, text))
    db.commit()
    return r


def run_plan(
    raw_plan: Any,
    env: Environment,
    *,
    run_id: str,
    plan_label: Label = OPERATOR,
    task_id: str | None = None,
    planner_input_hash: str | None = None,
) -> RunResult:
    env.db.text_factory = lossless_text
    recover(env.db, env.provider)
    if env.db.execute("SELECT 1 FROM audit WHERE run_id = ?", (run_id,)).fetchone():
        result = RunResult(run_id, "rejected", "run_id already used; run ids are single-use")
    else:
        audit = partial(_audit, raw_plan=raw_plan, task_id=task_id)
        result = _decide_and_execute(raw_plan, env, run_id, plan_label, audit, planner_input_hash)
    result = replace(result, planner_input_hash=planner_input_hash)
    return _audit(env.db, result, raw_plan, task_id)


def _decide_and_execute(
    raw_plan: Any,
    env: Environment,
    run_id: str,
    plan_label: Label,
    audit: Callable[..., RunResult],
    planner_input_hash: str | None,
) -> RunResult:
    try:
        plan = parse_plan(raw_plan)
        check_plan(plan)
    except PlanRejected as exc:
        return RunResult(run_id, "rejected", str(exc), plan_label=plan_label)

    db = Database(env.db)
    interpreter = Interpreter(db, env.extractor, plan_label)
    actions = tuple(interpreter.resolve(plan))
    verdicts, log = decide(actions, db.trusted)
    answer_label = whole_label(interpreter.answer)
    result = RunResult(
        run_id,
        "executed",
        "",
        actions=actions,
        verdicts=tuple(verdicts),
        rule_log=tuple(log),
        plan_label=plan_label,
        answer=None if isinstance(interpreter.answer, UnitV) else plain(interpreter.answer),
        answer_sinks=None if answer_label.sinks is None else sorted(answer_label.sinks),
    )
    blocked = [v.reason for v in verdicts if v.kind == "BLOCK"]
    if blocked:
        return replace(result, outcome="blocked", reason="; ".join(blocked))
    if any(v.kind == "NEEDS_APPROVAL" for v in verdicts):
        request = canonical_set(run_id, actions, verdicts)
        hash_ = digest(request)
        result = replace(result, approval_request=request, approval_hash=hash_)
        env.db.execute(
            "INSERT INTO approvals (run_id, hash, status) VALUES (?, ?, 'requested')",
            (run_id, hash_),
        )
        env.db.commit()
        approval = env.approver.review(request, hash_)
        if approval is None:
            return replace(result, outcome="needs_approval", reason="approval denied")
        problem = _consume(
            env.db, approval, run_id, digest(canonical_set(run_id, actions, verdicts))
        )
        if problem is not None:
            return replace(result, outcome="approval_invalid", reason=problem)
        result = replace(result, approved=True)
    # Write ahead: the decision (verdicts, rule decisions, approval) is durable
    # before any effect, so a crash cannot move money under an unlogged decision.
    decided = replace(result, outcome="executing", planner_input_hash=planner_input_hash)
    audit(env.db, decided, phase="decided")
    outcome, done = execute(actions, verdicts, env.db, env.provider)
    return replace(result, outcome=outcome, reason=outcome, executed=tuple(done))


def _consume(db: sqlite3.Connection, approval: Approval, run_id: str, hash_: str) -> str | None:
    """Accept an approval only for this run, for the recomputed hash, once. The
    approval is consumed (committed) before any provider call."""
    if approval.run_id != run_id:
        return "approval was issued for another run"
    if approval.hash != hash_:
        return "approval does not match the action set about to execute"
    used = db.execute(
        "UPDATE approvals SET status = 'consumed'"
        " WHERE run_id = ? AND hash = ? AND status = 'requested'",
        (run_id, hash_),
    )
    db.commit()
    return None if used.rowcount == 1 else "approval already used"


@dataclass(frozen=True)
class PlannerInput:
    """Everything the planner sees, built by the kernel."""

    request: str
    tool_signatures: str
    context: tuple[tuple[str, Label], ...] = ()

    def label(self) -> Label:
        return join(OPERATOR, *(lbl for _, lbl in self.context))

    def digest(self) -> str:
        parts = [self.request, self.tool_signatures, *(text for text, _ in self.context)]
        return hashlib.sha256("\x00".join(parts).encode("utf-8")).hexdigest()


class Planner(Protocol):
    def plan(self, planner_input: PlannerInput) -> Any: ...


def run_task(
    task_id: str,
    request: str,
    planner: Planner,
    env: Environment,
    *,
    leak_ticket_bodies: tuple[int, ...] = (),
    run_id: str | None = None,
) -> RunResult:
    """Plan once and run. ``run_id`` defaults to a fresh random UUID (DESIGN §7);
    evaluation passes one derived from its seed, for reproducibility.

    ``leak_ticket_bodies`` simulates broken planner isolation (the leaked-context
    configuration): those ticket bodies are shown to the planner, and the plan
    label, which literals and the root pc inherit, becomes as untrusted as they are.
    """
    run_id = run_id or str(uuid.uuid4())
    planned = env.db.execute(
        "SELECT 1 FROM audit WHERE json_extract(record, '$.task_id') = ?", (task_id,)
    ).fetchone()
    if task_id in env.planned_tasks or planned:  # durable across Environments (Gate 2 #7)
        refused = RunResult(run_id, "rejected", "task already planned; re-planning is forbidden")
        return _audit(env.db, refused, None, task_id)
    env.planned_tasks.add(task_id)
    env.db.text_factory = lossless_text
    context: list[tuple[str, Label]] = []
    for ticket_id in leak_ticket_bodies:
        for record in Database(env.db).read_ticket(Scalar(ticket_id, OPERATOR)).items:
            assert isinstance(record, Record)
            body = record.field("body")
            assert isinstance(body, Scalar)
            context.append((str(body.value), body.label))
    planner_input = PlannerInput(request, signatures(), tuple(context))
    return run_plan(
        planner.plan(planner_input),
        env,
        run_id=run_id,
        plan_label=planner_input.label(),
        task_id=task_id,
        planner_input_hash=planner_input.digest(),
    )
