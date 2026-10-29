"""Kernel entry points (DESIGN §1, §5, §8).

``run_task`` is the production path. The kernel builds the planner's input,
derives the plan label from it, invokes the planner once per task id, and runs
the plan. ``run_plan`` runs a given plan under a given plan label; the
non-interference tests use it to quantify over plans directly.

A run is: recover, check, resolve, decide, then execute only if every action
is ALLOWed. Phase 1 has no approval-execution path, so NEEDS_APPROVAL produces
an approval request and executes nothing (the denying approver). Every run
writes one append-only audit row (``audit`` table) explaining its decision.
"""

import hashlib
import json
import sqlite3
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from typing import Any, Literal, Protocol

from .approval import canonical_set, digest
from .declassify import RuleDecision
from .execution import Executed, PaymentProvider, execute, recover
from .interpreter import Interpreter, ResolvedAction
from .labels import STAR, Label, join
from .plan_lang import PlanRejected, check_plan, parse_plan
from .policy import Verdict, decide
from .tools.database import Database, lossless_text
from .tools.registry import signatures
from .values import Record, Scalar

OPERATOR = Label.trusted_source("operator")
Outcome = Literal[
    "executed", "blocked", "needs_approval", "rejected", "aborted", "partial", "indeterminate"
]


@dataclass
class Environment:
    db: sqlite3.Connection
    provider: PaymentProvider
    extractor: Callable[[str], list[object]]
    planned_tasks: set[str] = field(default_factory=set)


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


def _origins(label: Label) -> list[str] | str:
    return STAR if STAR in label.untrusted else sorted(label.untrusted)


def _audit(db: sqlite3.Connection, r: RunResult, raw_plan: Any, task_id: str | None) -> RunResult:
    record = {
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
    result = _decide_and_execute(raw_plan, env, run_id, plan_label)
    result = replace(result, planner_input_hash=planner_input_hash)
    return _audit(env.db, result, raw_plan, task_id)


def _decide_and_execute(
    raw_plan: Any, env: Environment, run_id: str, plan_label: Label
) -> RunResult:
    try:
        plan = parse_plan(raw_plan)
        check_plan(plan)
    except PlanRejected as exc:
        return RunResult(run_id, "rejected", str(exc), plan_label=plan_label)

    db = Database(env.db)
    actions = tuple(Interpreter(db, env.extractor, plan_label).resolve(plan))
    verdicts, log = decide(actions, db.trusted)
    result = RunResult(
        run_id,
        "executed",
        "",
        actions=actions,
        verdicts=tuple(verdicts),
        rule_log=tuple(log),
        plan_label=plan_label,
    )
    blocked = [v.reason for v in verdicts if v.kind == "BLOCK"]
    if blocked:
        return replace(result, outcome="blocked", reason="; ".join(blocked))
    if any(v.kind == "NEEDS_APPROVAL" for v in verdicts):
        request = canonical_set(run_id, actions, verdicts)
        return replace(
            result,
            outcome="needs_approval",
            reason="approval required; no approver in Phase 1 (denied)",
            approval_request=request,
            approval_hash=digest(request),
        )
    outcome, done = execute(actions, verdicts, env.db, env.provider)
    return replace(result, outcome=outcome, reason=outcome, executed=tuple(done))


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
    if task_id in env.planned_tasks:
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
