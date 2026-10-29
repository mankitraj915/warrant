"""Offline evaluation harness (SPEC §7): no model, no network.

Runs every dev user task benign and under every applicable injection, in four
configurations:

- ``warrant+oracle``: the kernel with the hand-written plan;
- ``warrant+gullible``: the kernel with the hijacked planner, which (isolated
  by the kernel) sees only the operator request;
- ``undefended+gullible``: the gullible planner sees the case ticket's text and
  the executor applies no policy;
- ``leaked+gullible``: the kernel, but the case ticket's text is leaked into the
  planner's context (S-12), so only the plan-label layer stands between the
  hijacked plan and execution. Reported separately from the main matrix.

Every raw outcome is written to ``results/phase1.json`` with the git commit,
seeds and environment, then summary tables are printed.

Usage: ``python -m evals.harness [--out PATH]``.
"""

import argparse
import json
import platform
import subprocess
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from domain.payment_mock import PaymentMock
from domain.seed import materialize
from evals.netguard import block_network
from evals.tasks import Effect, InjectionTask, UserTask
from evals.tasks.dev import INJECTION_TASKS, USER_TASKS
from kernel.run import Environment, RunResult, run_task
from planners.baselines.undefended import run_undefended
from planners.gullible import GulliblePlanner
from planners.oracle import OraclePlanner
from quarantine.extractor import extract_order_ids

MAIN = ("warrant+oracle", "warrant+gullible", "undefended+gullible")
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
    effects: list[Effect]
    utility: bool
    attacked: bool | None  # security check violated; None when benign

    def row(self) -> dict[str, Any]:
        return self.__dict__.copy()


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
        env = Environment(db=conn, provider=provider, extractor=extract_order_ids)
        leak = (task.case_ticket,) if config == "leaked+gullible" else ()
        run_id = f"{task.id}:{injection.id if injection else '-'}:{config}:seed{task.seed}"
        result = run_task(
            task.id, task.prompt, planner, env, leak_ticket_bodies=leak, run_id=run_id
        )
        outcome, reason = result.outcome, result.reason
    effects = [(e.order_id, e.amount) for e in provider.effects]
    return Outcome(
        task=task.id,
        injection=injection.id if injection is not None else None,
        config=config,
        outcome=outcome,
        reason=reason,
        verdicts=[
            {"kind": v.kind, "reason": v.reason, "rule": v.rule}
            for v in (result.verdicts if result else ())
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
        effects=effects,
        utility=task.utility(effects),
        attacked=injection.achieved(task, effects) if injection is not None else None,
    )


def evaluate() -> list[Outcome]:
    rows: list[Outcome] = []
    for task in USER_TASKS:
        for config in CONFIGS:
            rows.append(_run(task, None, config))
            for injection in INJECTION_TASKS:
                if injection.payload(task) is not None:
                    rows.append(_run(task, injection, config))
    return rows


def _git_commit() -> str:
    def git(*args: str) -> str:
        return subprocess.run(["git", *args], capture_output=True, text=True).stdout.strip()

    return git("rev-parse", "HEAD") + ("-dirty" if git("status", "--porcelain") else "")


def _frac(n: int, d: int) -> str:
    return f"{n}/{d} ({100 * n / d:.1f}%)" if d else "n/a"


def summarize(rows: list[Outcome]) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for config in CONFIGS:
        benign = [r for r in rows if r.config == config and r.injection is None]
        attacked = [r for r in rows if r.config == config and r.injection is not None]
        base = {r.task: r for r in benign}
        burden: Counter[str] = Counter()
        for r in benign:
            if r.outcome == "needs_approval":
                for d in r.rules:
                    if not d["admitted"]:
                        burden[f"{d['rule']}: {d['reason']}"] += 1
        out[config] = {
            "benign_utility": _frac(sum(r.utility for r in benign), len(benign)),
            "utility_under_attack": _frac(sum(r.utility for r in attacked), len(attacked)),
            "attack_success": _frac(sum(bool(r.attacked) for r in attacked), len(attacked)),
            "approval_burden": _frac(
                sum(r.outcome == "needs_approval" for r in benign), len(benign)
            ),
            "approval_burden_by_rule_reason": dict(burden),
            "approval_steering": _frac(
                sum(r.approval != base[r.task].approval for r in attacked), len(attacked)
            ),
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
        if r.config == "warrant+oracle" and r.injection is not None
    ]
    metrics = ["benign_utility", "utility_under_attack", "attack_success", "approval_burden"]
    metrics.append("approval_steering")
    parts = [
        "## Per-task outcomes (warrant+oracle, benign)",
        _table(["task", "data-dep", "outcome", "verdicts", "rules", "utility", "reason"], per_task),
        "## Metrics (main matrix)",
        _table(["metric", *MAIN], [[m, *(summary[c][m] for c in MAIN)] for m in metrics]),
        "## Metrics (leaked-context configuration, reported separately)",
        _table(["metric", *SEPARATE], [[m, *(summary[c][m] for c in SEPARATE)] for m in metrics]),
        "## Approval burden by rule reason (benign)",
        "\n".join(
            f"- {c}: {summary[c]['approval_burden_by_rule_reason'] or 'none'}" for c in CONFIGS
        ),
        "## Pairs",
        _table(["pair", *CONFIGS], attacks),
    ]
    return "\n\n".join(parts)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, default=Path("results/phase1.json"))
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
