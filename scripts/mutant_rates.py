"""Per-mutant detection measurement for the NI harness (D-049, D-053).

For every mutant in ``tests/test_ni_mutants.py`` and each plan generator:

- ``mixed``: the fuzzer as configured (``planners.fuzz.PLAN_SOURCES``: shapes and
  grammar), multirun plans as in ``test_noninterference``;
- ``grammar``: every plan from the grammar generator alone, and both multirun plans
  random (so from the grammar too),

it runs two derandomized measurements at the mutant's budget (3,000 single-run,
3,000 multirun, 2,000 NI-5):

- ``count``: every example runs to the end; the number of examples with an
  ``NIViolation`` and the first such example;
- ``catch``: the property as the mutant test runs it (stops at the first
  violation): caught or missed.

Derandomized seeds come from the wrapped function, so the example sequences differ
from ``check``'s. One JSON line per (generator, mutant, measurement) goes to ``--out``.

Usage: ``python scripts/mutant_rates.py --out results/mutant_rates.jsonl
[--generator mixed|grammar] [--property NI|multirun|NI-5]``.
"""

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

import planners.fuzz
import tests.test_noninterference as tn
from tests.ni_properties import NIViolation
from tests.test_approval_binding import ni5_property
from tests.test_ni_mutants import (
    MULTIRUN_BUDGET,
    MULTIRUN_MUTANTS,
    MUTANTS,
    NI5_BUDGET,
    NI5_MUTANTS,
    NI_BUDGET,
    _run_property,
)

# Outside pytest, tests/conftest.py's profiles are not loaded: no deadline, as there.
settings.register_profile("mutant_rates", deadline=None)
settings.load_profile("mutant_rates")

GROUPS = [
    ("NI", MUTANTS, NI_BUDGET, "ni_property"),
    ("multirun", MULTIRUN_MUTANTS, MULTIRUN_BUDGET, "multirun_property"),
    ("NI-5", NI5_MUTANTS, NI5_BUDGET, "ni5_property"),
]


def _grammar_run_plan(data: Any, world: Any, tickets: Any, first: bool, credit: bool) -> Any:
    source, plan = data.draw(planners.fuzz.sourced_plans(world), label="plan")
    return source, plan


def set_generator(name: str) -> None:
    if name == "grammar":
        planners.fuzz.PLAN_SOURCES = ("grammar",)
        tn._run_plan = _grammar_run_plan


def prop_fn(name: str) -> Any:
    return ni5_property if name == "ni5_property" else getattr(tn, name)


def count(budget: int, prop: Any) -> dict[str, Any]:
    stats = {"examples": 0, "violations": 0, "first_violation": None}

    @settings(
        max_examples=budget,
        derandomize=True,
        database=None,
        deadline=None,
        suppress_health_check=list(HealthCheck),
    )
    @given(st.data())
    def counted(data: Any) -> None:
        stats["examples"] += 1
        try:
            prop(data)
        except NIViolation:
            stats["violations"] += 1
            if stats["first_violation"] is None:
                stats["first_violation"] = stats["examples"]

    counted()
    return stats


def catch(budget: int, prop: Any) -> dict[str, Any]:
    try:
        _run_property(budget, prop)()
    except NIViolation:
        return {"caught": True}
    return {"caught": False}


def git_commit() -> str:
    def git(*args: str) -> str:
        return subprocess.run(["git", *args], capture_output=True, text=True).stdout.strip()

    return git("rev-parse", "HEAD") + ("-dirty" if git("status", "--porcelain") else "")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--generator", choices=["mixed", "grammar"], action="append")
    parser.add_argument("--property", choices=[g[0] for g in GROUPS], action="append")
    args = parser.parse_args(argv)
    generators = args.generator or ["mixed", "grammar"]
    if len(generators) > 1:  # the grammar patch is process-wide: one process per generator
        code = 0
        for g in generators:
            extra = [a for p in args.property or [] for a in ("--property", p)]
            cmd = [sys.executable, __file__, "--out", str(args.out), "--generator", g, *extra]
            code |= subprocess.call(cmd)
        return code
    generator = generators[0]
    set_generator(generator)
    commit = git_commit()
    args.out.parent.mkdir(parents=True, exist_ok=True)
    missed = 0
    for group, mutants, budget, prop_name in GROUPS:
        if args.property and group not in args.property:
            continue
        prop = prop_fn(prop_name)
        for name, (module, attribute, value) in sorted(mutants.items()):
            for measurement in ("count", "catch"):
                old = getattr(module, attribute)
                setattr(module, attribute, value)
                start = time.monotonic()
                try:
                    result = (count if measurement == "count" else catch)(budget, prop)
                finally:
                    setattr(module, attribute, old)
                row = {
                    "generator": generator,
                    "property": group,
                    "mutant": name,
                    "measurement": measurement,
                    "budget": budget,
                    **result,
                    "seconds": round(time.monotonic() - start, 1),
                    "commit": commit,
                }
                missed += measurement == "catch" and not result["caught"]
                with args.out.open("a", encoding="utf-8") as f:
                    f.write(json.dumps(row) + "\n")
                print(json.dumps(row), flush=True)
    return 1 if missed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
