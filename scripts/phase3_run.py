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

Stage ``a`` (``--stage a``, the default; run at 6e27f60):
  a. ``check``;
  b. per-mutant detection, for the mixed generator and the grammar generator alone
     (``scripts/mutant_rates.py``);
  c. NI statistics (2,000 randomized examples per property, halts and NI-checked
     shares per generator), then the chunked random fuzz with the new generator
     (20 x 1,000 examples per property);
  d. dev and holdout evaluations (every configuration, both attacker models);
  e. dev and holdout cap sweeps.

Stage ``b`` (``--stage b``; D-056: after pinning generation and splitting the NI
properties by plan source):
  1. ``check``;
  2. ``mutant-verify``: every mutant against the shapes and the grammar properties
     from a clean state, at the budgets and three fresh seeds; a required miss is
     followed by a run at four times the budget (``mutant_rates.py verify``, which
     D-058 replaced with ``kseed``; run it from commit c4b52a6);
  3. NI statistics, 2,000 randomized examples for each of the six properties;
  4. chunked random fuzz of the three grammar properties (10 x 1,000 examples each;
     the shapes were fuzzed in stage a and their generator is unchanged).

The evaluations and sweeps are not repeated: stage b changes no code they run.

Stage ``rates`` (``--stage rates``; D-056, before stage b): clean-state detection
counts for every mutant, property and source, 1,000 examples at each of five
seeds (``RATE_SEEDS``). They set the stage-b budgets and the seed witnesses that
``check`` runs.

Stage ``c`` (``--stage c``; D-058): ``check``, then ``mutant-kseed``: every required mutant
at its k-seed design (k fresh seeds of n examples, caught if any seed catches it;
``mutant_rates.py kseed``).

Usage: ``python scripts/tasks.py phase3-run --out <dir> [--stage a|b|c|rates] [--resume]``.
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
            # stage a ran the pre-D-056 script (mixed and grammar-only, no mode argument)
            [PY, "scripts/mutant_rates.py", "verify", "--out", str(out / "mutant_rates.jsonl")],
            {},
            [],
        ),
    ]
    for test, seed in STATS_SEEDS.items():
        name = test.rsplit("::", 1)[1]
        cmd = [PY, "-m", "pytest", test, "--hypothesis-show-statistics"]
        cmd += [f"--hypothesis-seed={seed}", "-p", "no:cacheprovider"]
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


GRAMMAR = {
    NI: "tests/test_noninterference.py::test_noninterference_grammar",
    MULTIRUN: "tests/test_noninterference.py::test_noninterference_multirun_grammar",
    NI5: "tests/test_approval_binding.py::test_ni5_executed_set_is_the_approved_set_grammar",
}
STATS_SEEDS_B = dict(zip([*GRAMMAR, *GRAMMAR.values()], range(202614700, 202614706), strict=True))
CHUNK_SEEDS_B = dict(zip(GRAMMAR.values(), (202614800, 202614900, 202615000), strict=True))


def steps_b(out: Path) -> list[tuple[str, list[str], dict[str, str], list[str]]]:
    stats_env = {"HYPOTHESIS_PROFILE": "fuzz", "WARRANT_FUZZ_EXAMPLES": "2000"}
    verify = [PY, "scripts/mutant_rates.py", "verify", "--resume"]
    verify += ["--out", str(out / "mutant_verify.jsonl")]
    found: list[tuple[str, list[str], dict[str, str], list[str]]] = [
        ("check", [PY, "scripts/tasks.py", "check"], {}, []),
        ("mutant-verify", verify, {}, []),
    ]
    for test, seed in STATS_SEEDS_B.items():
        cmd = [PY, "-m", "pytest", test, "--hypothesis-show-statistics"]
        cmd += [f"--hypothesis-seed={seed}", "-p", "no:cacheprovider"]
        found.append((f"ni-stats-{test.rsplit('::', 1)[1]}", cmd, stats_env, []))
    for test, seed in CHUNK_SEEDS_B.items():
        cmd = [PY, "scripts/fuzz_chunks.py", "--resume", "--chunks", "10", "--examples", "1000"]
        cmd += ["--log", str(out / "fuzz_chunks_grammar.jsonl"), "--test", test]
        cmd += ["--base-seed", str(seed)]
        found.append((f"fuzz-chunks-{test.rsplit('::', 1)[1]}", cmd, {}, []))
    return found


RATE_SEEDS = range(202616001, 202616006)


def steps_rates(out: Path) -> list[tuple[str, list[str], dict[str, str], list[str]]]:
    cmd = [PY, "scripts/mutant_rates.py", "rates", "--resume", "--examples", "1000"]
    cmd += [f"--seed={s}" for s in RATE_SEEDS]
    cmd += ["--out", str(out / "rates.jsonl")]
    return [("mutant-rates", cmd, {}, [])]


def steps_c(out: Path) -> list[tuple[str, list[str], dict[str, str], list[str]]]:
    kseed = [PY, "scripts/mutant_rates.py", "kseed", "--resume"]
    kseed += ["--out", str(out / "mutant_kseed.jsonl")]
    return [("check", [PY, "scripts/tasks.py", "check"], {}, []), ("mutant-kseed", kseed, {}, [])]


def passed(log: Path) -> set[str]:
    if not log.exists():
        return set()
    rows = [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines() if line]
    return {r["step"] for r in rows if r.get("exit") == 0}


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--stage", choices=["a", "b", "c", "rates"], default="a")
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
    plan = {"a": steps, "b": steps_b, "c": steps_c, "rates": steps_rates}[args.stage](out)
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
