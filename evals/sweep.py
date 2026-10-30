"""Auto-refund cap sweep (Gate 1 owner decision 2; DECISIONS D-038, D-041).

Runs the Warrant configurations of the evaluation at each cap value in
``CAPS`` (fixed before any run) and reports, per value, attack success,
benign utility, utility under attack, approval burden and approval steering.
The undefended baseline does not depend on the cap and is not rerun. No
default is chosen here.

Usage: ``python -m evals.sweep [--suite dev|holdout] [--out PATH]``.
"""

import argparse
import json
import sys
from pathlib import Path
from typing import Any

import kernel.declassify
from evals.harness import SUITES, _git_commit, _table, evaluate, injections, summarize
from evals.netguard import block_network

# Paise: None (no cap), then ₹5,000, ₹2,000, ₹1,000, ₹500, ₹250 and 0.
CAPS: tuple[int | None, ...] = (None, 500_000, 200_000, 100_000, 50_000, 25_000, 0)
CONFIGS = ("warrant+oracle", "warrant+gullible", "leaked+gullible")
METRICS = (
    "attack_success",
    "benign_utility",
    "utility_under_attack",
    "approval_burden",
    "approval_steering",
)


def sweep(suite: str = "dev") -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    old = kernel.declassify.AUTO_REFUND_CAP
    try:
        for cap in CAPS:
            kernel.declassify.AUTO_REFUND_CAP = cap
            rows = evaluate(injection_tasks=injections(suite), configs=CONFIGS)
            out[str(cap)] = summarize(rows)
    finally:
        kernel.declassify.AUTO_REFUND_CAP = old
    return out


def _rupees(cap: str) -> str:
    return "none" if cap == "None" else f"Rs {int(cap) // 100:,}"


def report(results: dict[str, dict[str, Any]]) -> str:
    parts = []
    for config in CONFIGS:
        rows = [[_rupees(cap), *(s[config][m] for m in METRICS)] for cap, s in results.items()]
        parts += [f"## {config}", _table(["cap", *METRICS], rows)]
    return "\n\n".join(parts)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--suite", choices=SUITES, default="dev")
    parser.add_argument("--out", type=Path)
    args = parser.parse_args(argv)
    dev = args.suite == "dev"
    args.out = args.out or Path(
        "results/cap_sweep.json" if dev else "results/cap_sweep_holdout.json"
    )
    block_network()
    results = sweep(args.suite)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    meta = {"git_commit": _git_commit(), "suite": args.suite, "caps": list(CAPS)}
    payload = {"meta": meta, "results": results}
    args.out.write_text(json.dumps(payload, indent=1, ensure_ascii=False), encoding="utf-8")
    print(report(results))
    print(f"\nwrote {args.out} (commit {payload['meta']['git_commit']})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
