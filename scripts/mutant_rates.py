"""Per-mutant detection measurement for the NI harness (D-049, D-053, D-056).

Every measurement runs in its own process from a clean state: an explicit seed,
no example database, and generation pinned to the seed (``tests/determinism.py``).
So a result does not depend on what else ran, and each process's memory is bounded.

Modes:

- ``rates``: for every mutant, property (NI, multirun, NI-5) and plan source
  (shapes, grammar), run ``--examples`` examples to the end with each ``--seed``
  (repeatable) and count the examples with an ``NIViolation``. Examples within one
  seed are not independent (Hypothesis explores around earlier examples), so
  rates come from several seeds. These rates set the budgets in
  ``tests/test_ni_mutants.py`` (rule in DECISIONS D-056).
- ``verify``: for every mutant, property and source, run the property at its
  budget (``BUDGETS``) at each of ``VERIFY_SEEDS`` (fresh: none set a budget),
  stopping at the first violation, and record caught or missed and the example
  index of the detection. A shapes miss, or a miss of a mutant listed in
  ``GRAMMAR_CATCHES``, makes the exit code 1 and is followed by an ``extend``
  count run at four times the budget at the same seed, which records where the
  first detection actually came (for a corrected budget, reported separately).
  Other grammar rows are the coverage table.

``--rule gate2`` runs with the Phase 1-2 existence rule (taint kept, no halt), to
attribute a rate change to D-054. One JSON line per measurement goes to
``--out``; ``--resume`` skips measurements already in it.

Usage: ``python scripts/mutant_rates.py rates --examples 3000 --seed 7 --out FILE``
or ``python scripts/mutant_rates.py verify --out FILE``.
"""

import argparse
import json
import math
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from tests.determinism import pin_generation  # noqa: E402

pin_generation()

from hypothesis import HealthCheck, given, seed, settings  # noqa: E402
from hypothesis import strategies as st  # noqa: E402

import kernel.tools.database  # noqa: E402
from tests.ni_properties import NIViolation  # noqa: E402
from tests.test_ni_mutants import (  # noqa: E402
    BUDGETS,
    GRAMMAR_CATCHES,
    PROPERTIES,
    VERIFY_SEEDS,
    _run_property,
)

SOURCES = ("shapes", "grammar")


def count(prop_fn: Any, source: str, examples: int, seed_: int) -> dict[str, Any]:
    stats: dict[str, Any] = {"examples": 0, "violations": 0, "first_violation": None}

    @seed(seed_)
    @settings(
        max_examples=examples,
        derandomize=False,
        database=None,
        deadline=None,
        suppress_health_check=list(HealthCheck),
    )
    @given(st.data())
    def counted(data: Any) -> None:
        stats["examples"] += 1
        try:
            prop_fn(data, source)
        except NIViolation:
            stats["violations"] += 1
            if stats["first_violation"] is None:
                stats["first_violation"] = stats["examples"]

    counted()
    return stats


def catch(prop_fn: Any, source: str, examples: int, seed_: int) -> dict[str, Any]:
    calls = [0]

    def counted(data: Any, source_: str) -> None:
        calls[0] += 1
        prop_fn(data, source_)

    try:
        _run_property(examples, counted, source, seed_)()
    except NIViolation:
        return {"caught": True, "detected_at": calls[0]}
    return {"caught": False, "detected_at": None, "calls": calls[0]}


def one(spec: dict[str, Any]) -> dict[str, Any]:
    """One measurement, in this (fresh) process."""
    assert spec["rule"] in ("current", "gate2")
    if spec["rule"] == "gate2":
        kernel.tools.database.POINT_READ_EXISTENCE = True
        kernel.tools.database.HALT_ON_ABSENT_TRUSTED_TICKET = False
    mutants, prop_fn = PROPERTIES[spec["property"]]
    module, attribute, value = mutants[spec["mutant"]]
    setattr(module, attribute, value)
    start = time.monotonic()
    measure = catch if spec["measurement"] == "catch" else count
    result = measure(prop_fn, spec["source"], spec["examples"], spec["seed"])
    return {**spec, **result, "seconds": round(time.monotonic() - start, 1)}


def git_commit() -> str:
    def git(*args: str) -> str:
        out = subprocess.run(["git", *args], capture_output=True, text=True, cwd=ROOT)
        return out.stdout.strip()

    return git("rev-parse", "HEAD") + ("-dirty" if git("status", "--porcelain") else "")


def key(spec: dict[str, Any]) -> tuple[Any, ...]:
    return tuple(
        spec[k] for k in ("measurement", "property", "source", "mutant", "examples", "seed", "rule")
    )


def specs(args: argparse.Namespace) -> list[dict[str, Any]]:
    out = []
    for prop, (mutants, _) in PROPERTIES.items():
        if args.property and prop not in args.property:
            continue
        for source in args.source or SOURCES:
            for name in sorted(mutants):
                if args.mutant and name not in args.mutant:
                    continue
                base = {"property": prop, "source": source, "mutant": name, "rule": args.rule}
                if args.mode == "rates":
                    for seed_ in args.seed or [20261101]:
                        out.append(
                            {
                                **base,
                                "measurement": "count",
                                "examples": args.examples,
                                "seed": seed_,
                            }
                        )
                else:
                    budget = BUDGETS[prop, source]
                    for seed_ in VERIFY_SEEDS:
                        out.append(
                            {**base, "measurement": "catch", "examples": budget, "seed": seed_}
                        )
    return out


def required(row: dict[str, Any]) -> bool:
    """A verify row that must be caught: every shapes row, and the grammar's listed ones."""
    return row["source"] == "shapes" or row["mutant"] in GRAMMAR_CATCHES[row["property"]]


def wilson_low(k: int, n: int, z: float = 1.96) -> float:
    if n == 0:
        return 0.0
    p = k / n
    centre = p + z * z / (2 * n)
    spread = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return max(0.0, (centre - spread) / (1 + z * z / n))


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=["rates", "verify", "one"])
    parser.add_argument("--out", type=Path)
    parser.add_argument("--examples", type=int, default=3000)
    parser.add_argument("--seed", type=int, action="append")
    parser.add_argument("--rule", choices=["current", "gate2"], default="current")
    parser.add_argument("--property", action="append")
    parser.add_argument("--source", action="append", choices=SOURCES)
    parser.add_argument("--mutant", action="append")
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--spec")
    args = parser.parse_args(argv)
    if args.mode == "one":
        print(json.dumps(one(json.loads(args.spec))), flush=True)
        return 0
    assert args.out is not None, "--out is required"
    args.out.parent.mkdir(parents=True, exist_ok=True)
    done: dict[tuple[Any, ...], dict[str, Any]] = {}
    if args.resume and args.out.exists():
        lines = args.out.read_text(encoding="utf-8").splitlines()
        done = {key(row): row for row in map(json.loads, filter(None, lines))}
    commit = git_commit()

    def measured(spec: dict[str, Any]) -> dict[str, Any] | None:
        if key(spec) in done:
            return done[key(spec)]
        cmd = [sys.executable, __file__, "one", "--spec", json.dumps(spec)]
        proc = subprocess.run(cmd, capture_output=True, text=True, cwd=ROOT)
        if proc.returncode != 0:
            print(proc.stdout + proc.stderr, flush=True)
            return None
        row: dict[str, Any] = json.loads(proc.stdout.strip().splitlines()[-1])
        row["commit"] = commit
        if row["measurement"] != "catch":
            row["rate"] = row["violations"] / max(row["examples"], 1)
            row["rate_wilson95_low"] = wilson_low(row["violations"], row["examples"])
        with args.out.open("a", encoding="utf-8") as f:
            f.write(json.dumps(row) + "\n")
        print(json.dumps(row), flush=True)
        return row

    missed = 0
    for spec in specs(args):
        row = measured(spec)
        if row is None:
            return 2
        if row["measurement"] == "catch" and not row["caught"] and required(row):
            missed += 1  # a miss against the D-056 rule: find where detection came
            extend = {**spec, "measurement": "extend", "examples": 4 * spec["examples"]}
            if measured(extend) is None:
                return 2
    return 1 if missed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
