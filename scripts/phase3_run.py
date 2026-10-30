"""Owner-run Phase 3 measurements: every step in order, outside a Claude Code session.

Runs from a clean worktree at a fixed commit (it refuses a dirty tree) and writes
everything to ``--out``:

- ``steps.jsonl``: one row per step (name, command, exit code, seconds, commit,
  available memory before the step, log file);
- ``NN-<step>.log``: the step's full output;
- the steps' own outputs (mutant rates, chunk logs, evaluation and sweep JSON,
  audit databases).

A failing step is recorded and the run continues, so one run yields every
result. ``--resume`` skips steps that already passed in ``steps.jsonl`` (the
chunked fuzz steps also resume chunk by chunk).

Steps:
  a. ``check``;
  b. per-mutant detection, for the mixed generator and the grammar generator alone
     (``scripts/mutant_rates.py``);
  c. NI statistics (2,000 randomized examples per property, halts and NI-checked
     shares per generator), then the chunked random fuzz with the new generator
     (20 x 1,000 examples per property);
  d. dev and holdout evaluations (every configuration, both attacker models);
  e. dev and holdout cap sweeps.

Usage: ``python scripts/tasks.py phase3-run --out <dir> [--resume]``.
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from fuzz_chunks import available_mb

PY = sys.executable
NI = "tests/test_noninterference.py::test_noninterference"
MULTIRUN = "tests/test_noninterference.py::test_noninterference_multirun"
NI5 = "tests/test_approval_binding.py::test_ni5_executed_set_is_the_approved_set"
# Fresh seeds for the Phase 3 code (the Gate 2 run used 2026108xx-2026110xx).
STATS_SEEDS = {NI: 202612700, MULTIRUN: 202612701, NI5: 202612702}
CHUNK_SEEDS = {NI: 202612800, MULTIRUN: 202612900, NI5: 202613000}


def git(*args: str) -> str:
    return subprocess.run(["git", *args], capture_output=True, text=True).stdout.strip()


def steps(out: Path) -> list[tuple[str, list[str], dict[str, str], list[str]]]:
    """(name, command, extra environment, files to copy from results/ into out)."""
    stats_env = {"HYPOTHESIS_PROFILE": "fuzz", "WARRANT_FUZZ_EXAMPLES": "2000"}
    found: list[tuple[str, list[str], dict[str, str], list[str]]] = [
        ("check", [PY, "scripts/tasks.py", "check"], {}, []),
        (
            "mutant-rates",
            [PY, "scripts/mutant_rates.py", "--out", str(out / "mutant_rates.jsonl")],
            {},
            [],
        ),
    ]
    for test, seed in STATS_SEEDS.items():
        name = test.rsplit("::", 1)[1]
        cmd = [PY, "-m", "pytest", test, "--hypothesis-show-statistics"]
        cmd += [f"--hypothesis-seed={seed}", "-p", "no:cacheprovider", "-q"]
        found.append((f"ni-stats-{name}", cmd, stats_env, []))
    for test, seed in CHUNK_SEEDS.items():
        name = test.rsplit("::", 1)[1]
        cmd = [PY, "scripts/fuzz_chunks.py", "--resume", "--chunks", "20", "--examples", "1000"]
        cmd += ["--log", str(out / "fuzz_chunks_phase3.jsonl"), "--test", test]
        cmd += ["--base-seed", str(seed)]
        found.append((f"fuzz-chunks-{name}", cmd, {}, []))
    for suite, audit in (("dev", "audit.sqlite"), ("holdout", "audit_holdout.sqlite")):
        cmd = [
            PY,
            "-m",
            "evals.harness",
            "--suite",
            suite,
            "--out",
            str(out / f"eval_{suite}.json"),
        ]
        found.append((f"eval-{suite}", cmd, {}, [audit]))
    for suite in ("dev", "holdout"):
        cmd = [PY, "-m", "evals.sweep", "--suite", suite]
        cmd += ["--out", str(out / f"cap_sweep_{suite}.json")]
        found.append((f"sweep-{suite}", cmd, {}, []))
    return found


def passed(log: Path) -> set[str]:
    if not log.exists():
        return set()
    rows = [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines() if line]
    return {r["step"] for r in rows if r.get("exit") == 0}


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--resume", action="store_true")
    args = parser.parse_args(argv)
    if git("status", "--porcelain"):
        print("refusing to run: the working tree is not clean (commit or use a clean worktree)")
        return 2
    commit = git("rev-parse", "HEAD")
    out = args.out.resolve()
    log = out / "steps.jsonl"
    if log.exists() and not args.resume:
        print(f"refusing to run: {log} exists (pass --resume to continue it)")
        return 2
    out.mkdir(parents=True, exist_ok=True)
    done = passed(log)
    failures = 0
    plan = steps(out)
    for i, (name, cmd, env, copies) in enumerate(plan, 1):
        if name in done:
            print(f"[{i}/{len(plan)}] {name}: already passed, skipped", flush=True)
            continue
        step_log = out / f"{i:02d}-{name}.log"
        free = available_mb()
        print(f"[{i}/{len(plan)}] {name} (available {free} MB) ...", flush=True)
        start = time.monotonic()
        with step_log.open("w", encoding="utf-8") as f:
            f.write("$ " + " ".join(cmd) + "\n")
            f.flush()
            code = subprocess.call(
                cmd, env={**os.environ, **env}, stdout=f, stderr=subprocess.STDOUT
            )
        seconds = round(time.monotonic() - start, 1)
        for name_ in copies:  # outputs the step writes only under results/
            if Path("results", name_).exists():
                shutil.copy2(Path("results", name_), out / name_)
        row = {
            "step": name,
            "command": cmd,
            "env": env,
            "exit": code,
            "seconds": seconds,
            "commit": commit,
            "dirty_after": bool(git("status", "--porcelain")),
            "available_mb_before": free,
            "log": step_log.name,
        }
        with log.open("a", encoding="utf-8") as f:
            f.write(json.dumps(row) + "\n")
        failures += code != 0
        print(f"    exit {code}, {seconds} s", flush=True)
    print(f"done: {len(plan)} steps, {failures} failed; see {log}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
