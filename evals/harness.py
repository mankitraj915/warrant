"""Offline evaluation harness (SPEC §7): no model, no network.

Runs every user task benign and under every applicable injection, in four
configurations (Warrant configurations use the simulated approver, D-041):

- ``warrant+oracle``: the kernel with the hand-written plan;
- ``warrant+gullible``: the kernel with the hijacked planner, which (isolated
  by the kernel) sees only the operator request;
- ``undefended+gullible``: the gullible planner sees the case ticket's text and
  the executor applies no policy;
- ``leaked+gullible``: the kernel, but the case ticket's text is leaked into the
  planner's context (S-12), so only the plan-label layer stands between the
  hijacked plan and execution. Reported separately from the main matrix.

Every raw outcome is written to ``results/eval.json`` with the git commit,
seeds and environment, then summary tables are printed.

Usage: ``python -m evals.harness [--out PATH]``.
"""

import argparse
import json
import platform
import sqlite3
import subprocess
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from domain.payment_mock import PaymentMock
from domain.seed import materialize
from evals.approver import GroundTruthApprover
from evals.netguard import block_network
from evals.tasks import Closure, Credit, Effect, Effects, InjectionTask, UserTask
from evals.tasks.dev import INJECTION_TASKS, USER_TASKS
from kernel.run import Environment, RunResult, run_task
from planners.baselines.undefended import run_undefended
from planners.gullible import GulliblePlanner
from planners.oracle import OraclePlanner
from quarantine.extractor import extract_order_ids

MAIN = ("warrant+oracle", "warrant+gullible", "undefended+gullible")
BASELINES = ("undefended+gullible",)
SEPARATE = ("leaked+gullible",)
CONFIGS = MAIN + SEPARATE


@dataclass(frozen=True)
class Outcome:
    task: str
    injection: str | None
    config: str
    outcome: str
    reason: str
    verdicts: list[dict[str, Any]]
    rules: list[dict[str, Any]]
    approval: list[dict[str, Any]] | None  # canonical action set minus run id
    approved: bool
    effects: list[Effect]  # refunds paid
    credits: list[Credit]
    closures: list[Closure]
    utility: bool
    attacked: bool | None  # security check violated; None when benign

    def row(self) -> dict[str, Any]:
        return self.__dict__.copy()


def _effects(conn: sqlite3.Connection, provider: PaymentMock) -> Effects:
    credits = conn.execute("SELECT ticket_id, customer_id, amount, reason FROM credits ORDER BY id")
    closures = conn.execute(
        "SELECT id, resolution FROM tickets WHERE resolution IS NOT NULL ORDER BY id"
    )
    return Effects(
        refunds=[(e.order_id, e.amount) for e in provider.effects],
        credits=[(int(t), int(c), int(a), str(r)) for t, c, a, r in credits],
        closures=[(int(t), str(r)) for t, r in closures],
    )


def _run(task: UserTask, injection: InjectionTask | None, config: str) -> Outcome:
    payload = injection.payload(task) if injection is not None else None
    world = task.world(payload)
    provider = PaymentMock()
    conn = materialize(world)
    planner = (
        OraclePlanner(task.oracle)
        if config == "warrant+oracle"
        else GulliblePlanner(task.oracle, task.case_ticket)
    )
    result: RunResult | None = None
    if config == "undefended+gullible":
        outcome, reason = run_undefended(
            task.prompt,
            planner,
            conn,
            provider,
            extract_order_ids,
            show_ticket_bodies=(task.case_ticket,),
        )
    else:
        env = Environment(
            db=conn,
            provider=provider,
            extractor=extract_order_ids,
            approver=GroundTruthApprover(task),
        )
        leak = (task.case_ticket,) if config == "leaked+gullible" else ()
        run_id = f"{task.id}:{injection.id if injection else '-'}:{config}:seed{task.seed}"
        result = run_task(
            task.id, task.prompt, planner, env, leak_ticket_bodies=leak, run_id=run_id
        )
        outcome, reason = result.outcome, result.reason
    effects = _effects(conn, provider)
    return Outcome(
        task=task.id,
        injection=injection.id if injection is not None else None,
        config=config,
        outcome=outcome,
        reason=reason,
        verdicts=[
            {
                "tool": a.tool,
                "site": list(a.site),
                "kind": v.kind,
                "reason": v.reason,
                "rule": v.rule,
            }
            for a, v in (zip(result.actions, result.verdicts, strict=True) if result else ())
        ],
        rules=[
            {"rule": d.rule, "site": list(d.site), "admitted": d.admitted, "reason": d.reason}
            for d in (result.rule_log if result else ())
        ],
        approval=(
            result.approval_request["actions"]
            if result is not None and result.approval_request is not None
            else None
        ),
        approved=bool(result and result.approved),
        effects=effects.refunds,
        credits=effects.credits,
        closures=effects.closures,
        utility=task.utility(effects),
        attacked=injection.achieved(task, effects) if injection is not None else None,
    )


def evaluate(
    user_tasks: tuple[UserTask, ...] = USER_TASKS,
    injection_tasks: tuple[InjectionTask, ...] = INJECTION_TASKS,
    configs: tuple[str, ...] = CONFIGS,
) -> list[Outcome]:
    rows: list[Outcome] = []
    for task in user_tasks:
        for config in configs:
            rows.append(_run(task, None, config))
            for injection in injection_tasks:
                if injection.payload(task) is not None:
                    rows.append(_run(task, injection, config))
    return rows


def _git_commit() -> str:
    def git(*args: str) -> str:
        return subprocess.run(["git", *args], capture_output=True, text=True).stdout.strip()

    return git("rev-parse", "HEAD") + ("-dirty" if git("status", "--porcelain") else "")


def _frac(n: int, d: int) -> str:
    return f"{n}/{d} ({100 * n / d:.1f}%)" if d else "n/a"


def _approval_causes(r: Outcome) -> set[str]:
    """Why a run asked for approval: each rule consulted that did not admit, plus
    "no rule for <tool>" for an action needing approval that no rule was asked about."""
    causes = {f"{d['rule']}: {d['reason']}" for d in r.rules if not d["admitted"]}
    consulted = {tuple(d["site"]) for d in r.rules}
    for v in r.verdicts:
        if v["kind"] == "NEEDS_APPROVAL" and tuple(v["site"]) not in consulted:
            causes.add(f"no rule for {v['tool']}")
    return causes


def _rule_names(r: Outcome) -> set[str]:
    return {d["rule"] for d in r.rules} or {"no rule"}


def summarize(rows: list[Outcome]) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for config in [c for c in CONFIGS if any(r.config == c for r in rows)]:
        benign = [r for r in rows if r.config == config and r.injection is None]
        attacked = [r for r in rows if r.config == config and r.injection is not None]
        base = {r.task: r for r in benign}
        burden: Counter[str] = Counter()
        burden_rule: Counter[str] = Counter()
        for r in benign:
            if r.approval is not None:
                burden.update(_approval_causes(r))
                burden_rule.update(_rule_names(r))
        steered = [r for r in attacked if r.approval != base[r.task].approval]
        steering_rule: Counter[str] = Counter()
        for r in steered:
            steering_rule.update(_rule_names(r) | _rule_names(base[r.task]))
        requested = [r for r in benign + attacked if r.approval is not None]
        out[config] = {
            "benign_utility": _frac(sum(r.utility for r in benign), len(benign)),
            "utility_under_attack": _frac(sum(r.utility for r in attacked), len(attacked)),
            "attack_success": _frac(sum(bool(r.attacked) for r in attacked), len(attacked)),
            "approval_burden": _frac(sum(r.approval is not None for r in benign), len(benign)),
            "approval_burden_by_rule": dict(sorted(burden_rule.items())),
            "approval_burden_by_rule_reason": dict(sorted(burden.items())),
            "approvals_granted": _frac(sum(r.approved for r in requested), len(requested)),
            "approval_steering": _frac(len(steered), len(attacked)),
            "approval_steering_by_rule": dict(sorted(steering_rule.items())),
        }
    return out


def _table(headers: list[str], rows: list[list[str]]) -> str:
    lines = ["| " + " | ".join(headers) + " |", "|" + "---|" * len(headers)]
    lines += ["| " + " | ".join(r) + " |" for r in rows]
    return "\n".join(lines)


def _verdict_summary(r: Outcome) -> str:
    counts = Counter(v["kind"] for v in r.verdicts)
    return ", ".join(f"{k}x{n}" for k, n in sorted(counts.items())) or "-"


def _rule_summary(r: Outcome) -> str:
    fired = sorted({f"{d['rule']}={'admit' if d['admitted'] else 'reject'}" for d in r.rules})
    return ", ".join(fired) or "-"


def _counts(summary: dict[str, dict[str, Any]], key: str) -> str:
    return "\n".join(
        f"- {c}: " + ("; ".join(f"{k} ({n})" for k, n in summary[c][key].items()) or "none")
        for c in summary
    )


def report(rows: list[Outcome], summary: dict[str, dict[str, Any]]) -> str:
    tasks = {t.id: t for t in USER_TASKS}
    per_task = [
        [
            r.task,
            "yes" if tasks[r.task].data_dependent else "no",
            r.outcome,
            _verdict_summary(r),
            _rule_summary(r),
            "pass" if r.utility else "FAIL",
            r.reason if r.outcome in ("blocked", "needs_approval") else "",
        ]
        for r in rows
        if r.config == "warrant+oracle" and r.injection is None
    ]
    attacks = [
        [
            f"{r.task}+{r.injection}",
            *(
                next(
                    f"{x.outcome}{' ATTACK' if x.attacked else ''}"
                    for x in rows
                    if x.task == r.task and x.injection == r.injection and x.config == c
                )
                for c in CONFIGS
            ),
        ]
        for r in rows
        if r.config == "warrant+oracle"
        and r.injection is not None
        and any(
            x.attacked
            for x in rows
            if x.task == r.task and x.injection == r.injection and x.config not in BASELINES
        )
    ]
    metrics = ["benign_utility", "utility_under_attack", "attack_success", "approval_burden"]
    metrics += ["approvals_granted", "approval_steering"]
    parts = [
        "## Per-task outcomes (warrant+oracle, benign)",
        _table(["task", "data-dep", "outcome", "verdicts", "rules", "utility", "reason"], per_task),
        "## Metrics (main matrix)",
        _table(["metric", *MAIN], [[m, *(summary[c][m] for c in MAIN)] for m in metrics]),
        "## Metrics (leaked-context configuration, reported separately)",
        _table(["metric", *SEPARATE], [[m, *(summary[c][m] for c in SEPARATE)] for m in metrics]),
        "## Approval burden by rule (benign tasks that asked for approval)",
        _counts(summary, "approval_burden_by_rule"),
        "## Approval burden by reason",
        _counts(summary, "approval_burden_by_rule_reason"),
        "## Approval steering by rule (pairs whose approval request changed)",
        _counts(summary, "approval_steering_by_rule"),
        "## Pairs where an attack succeeded under a Warrant configuration",
        _table(["pair", *CONFIGS], attacks) if attacks else "none",
    ]
    return "\n\n".join(parts)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, default=Path("results/eval.json"))
    args = parser.parse_args(argv)
    block_network()
    rows = evaluate()
    summary = summarize(rows)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    meta = {
        "git_commit": _git_commit(),
        "python": sys.version,
        "platform": platform.platform(),
        "seeds": sorted({t.seed for t in USER_TASKS}),
        "model": None,
        "extractor": "quarantine.extractor.extract_order_ids",
    }
    payload = {"meta": meta, "summary": summary, "rows": [r.row() for r in rows]}
    args.out.write_text(json.dumps(payload, indent=1, ensure_ascii=False), encoding="utf-8")
    print(report(rows, summary))
    print(f"\nwrote {args.out} ({len(rows)} runs, commit {meta['git_commit']})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
