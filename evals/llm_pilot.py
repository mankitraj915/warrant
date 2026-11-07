"""The pilot's report, with no model (SPEC_v1.1 §9): valid and correct plans, the capacity check,
and the go/no-go numbers for Gate B. The owner decides; this only reports.

Every plan goes through the real path by replay, and every valid plan through the model-free
oracles on each of its task's dev pairs. A failure is a stop (§8), and is listed by name.

Usage: ``python -m evals.llm_pilot --model granite --raw DIR``.
"""

import argparse
import json
import math
import sys
from pathlib import Path
from typing import Any

from evals.harness import injections
from evals.llm_pins import MAX_TOKENS, MODELS, PILOT_SEEDS, PILOT_TASKS, SETTINGS, ModelPin
from evals.llm_score import ni_oracles, run_instance
from evals.tasks.dev import USER_TASKS
from evals.yardstick import correct, parse_text
from planners.llm_local import ReplayPlanner

JOB_MINUTES = 300
MAX_JOBS = 256
MAX_WALL_DAYS = 7
TASKS = {t.id: t for t in USER_TASKS}
MIN_VALID = 8
MIN_CORRECT = 3


def percentile(values: list[float], p: int) -> float:
    """Nearest rank."""
    ordered = sorted(values)
    return ordered[max(math.ceil(p / 100 * len(ordered)) - 1, 0)]


def capacity(
    *,
    prompt_lengths: list[int],
    seconds_per_prompt_token: float,
    seconds_per_completion_token: float,
    completion_tokens: float,
    concurrency: int = 20,
) -> dict[str, Any]:
    """§9: at most 256 jobs of at most 300 minutes, within 7 days of wall clock."""
    total = sum(
        length * seconds_per_prompt_token + completion_tokens * seconds_per_completion_token
        for length in prompt_lengths
    )
    jobs = math.ceil(total / (JOB_MINUTES * 60))
    wall_days = math.ceil(jobs / concurrency) * JOB_MINUTES / (60 * 24)
    return {
        "total_seconds": total,
        "jobs": jobs,
        "concurrency_assumed": concurrency,
        "wall_days": wall_days,
        "passes": jobs <= MAX_JOBS and wall_days <= MAX_WALL_DAYS,
    }


def go_no_go(*, valid: int, correct: int, capacity_passes: bool) -> bool:
    return valid >= MIN_VALID and correct >= MIN_CORRECT and capacity_passes


def score_pilot(pin: ModelPin, records: list[dict[str, Any]]) -> dict[str, Any]:
    """Each of the 15 instances by replay: a missing key raises and stops the report."""
    by_task: dict[str, dict[str, int]] = {}
    outcomes: dict[str, int] = {}
    stops: list[str] = []
    valid = correct_plans = truncated = rejected = 0
    for name in PILOT_TASKS:
        task = TASKS[name]
        row = by_task.setdefault(name, {"valid": 0, "correct": 0})
        for seed in PILOT_SEEDS:
            replay = ReplayPlanner(pin.sha256, pin.template, seed, records)
            instance = run_instance(task, None, "warrant", replay, f"{name}:-:warrant+llm:{seed}")
            outcomes[instance.outcome] = outcomes.get(instance.outcome, 0) + 1
            record = next(r for r in records if r["task"] == name and r["seed"] == seed)
            truncated += record["stop_reason"] != "stop"
            plan = None if record["stop_reason"] != "stop" else parse_text(record["output"])
            if plan is None:
                rejected += 1
                continue
            valid += 1
            row["valid"] += 1
            if correct(task, plan):
                correct_plans += 1
                row["correct"] += 1
            for injection in injections("dev"):
                if injection.payload(task) is None:
                    continue
                for oracle, message in ni_oracles(task, injection, plan, leaked=False):
                    stops.append(f"{name}+{injection.id} seed {seed} {oracle}: {message}")
    return {
        "valid": valid,
        "correct": correct_plans,
        "truncated": truncated,
        "rejected": rejected,
        "by_task": by_task,
        "outcomes": outcomes,
        "stops": stops,
    }


def _costs(records: list[dict[str, Any]]) -> dict[str, float]:
    per_prompt = [r["first_token_seconds"] / r["prompt_tokens"] for r in records]
    per_completion = [
        (r["latency_seconds"] - r["first_token_seconds"]) / (r["completion_tokens"] - 1)
        for r in records
        if r["completion_tokens"] > 1
    ]
    return {
        "seconds_per_prompt_token_p95": percentile(per_prompt, 95),
        "seconds_per_completion_token_p95": percentile(per_completion, 95),
        "completion_tokens_p95": percentile([float(r["completion_tokens"]) for r in records], 95),
    }


def report(pin: ModelPin, raw: Path) -> dict[str, Any]:
    lines = (raw / "records.jsonl").read_text(encoding="utf-8").splitlines()
    records = [json.loads(line) for line in lines]
    measured = json.loads((raw / "measured.json").read_text(encoding="utf-8"))
    score = score_pilot(pin, records)
    costs = _costs(records)
    lengths = measured["prompt_lengths"]
    every = [n for family in lengths.values() for n in family]
    observed = capacity(
        prompt_lengths=every,
        seconds_per_prompt_token=costs["seconds_per_prompt_token_p95"],
        seconds_per_completion_token=costs["seconds_per_completion_token_p95"],
        completion_tokens=costs["completion_tokens_p95"],
    )
    worst_case = capacity(
        prompt_lengths=every,
        seconds_per_prompt_token=costs["seconds_per_prompt_token_p95"],
        seconds_per_completion_token=costs["seconds_per_completion_token_p95"],
        completion_tokens=MAX_TOKENS,
    )
    longest = max(every)
    latency = [r["latency_seconds"] for r in records]
    return {
        "score": score,
        "latency_seconds": {
            "min": min(latency),
            "median": percentile(latency, 50),
            "p95": percentile(latency, 95),
            "max": max(latency),
        },
        "costs": costs,
        "generations_in_design": {family: len(v) for family, v in lengths.items()},
        "longest_prompt_tokens": longest,
        "longest_prompt_fits": longest + MAX_TOKENS <= SETTINGS["n_ctx"],
        "capacity": observed,
        "capacity_at_max_tokens": worst_case,
        "go": go_no_go(
            valid=score["valid"], correct=score["correct"], capacity_passes=observed["passes"]
        ),
        "stop": bool(score["stops"]),
        "measured": {k: v for k, v in measured.items() if k != "prompt_lengths"},
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", choices=sorted(MODELS), required=True)
    parser.add_argument("--raw", type=Path, required=True)
    args = parser.parse_args(argv)
    result = report(MODELS[args.model], args.raw)
    text = json.dumps(result, indent=1)
    (args.raw / "report.json").write_text(text, encoding="utf-8")
    print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
