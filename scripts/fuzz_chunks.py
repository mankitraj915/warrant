"""Bounded fuzzing: run one NI property as sequential chunks, each in its own
process with its own recorded seed, and measure each chunk's peak RSS.

Usage (normally through ``scripts/tasks.py fuzz-chunks``)::

    python scripts/fuzz_chunks.py --test test_noninterference --chunks 20 \
        --examples 1000 --base-seed 20261030

``--test`` is a property in ``tests/test_noninterference.py`` or a full
``path::name`` id (e.g. the NI-5 property in ``tests/test_approval_binding.py``).
``--test`` and ``--base-seed`` may be repeated in pairs to run several properties
in sequence. Chunk ``i`` uses seed ``base_seed + i``. Each chunk appends one JSON
line to ``results/fuzz_chunks.jsonl``: test, seed, examples, exit code, seconds,
peak RSS in MB, Hypothesis's summary, the git commit and the machine's available
memory before the chunk. ``--resume`` skips chunks whose test and seed already
have a passing row in the log, so an interrupted run continues where it stopped.

Peak RSS is measured inside the pytest process by ``tests/conftest.py``: on
Windows the venv's ``python.exe`` is a launcher, so the child
process handle would report the launcher's memory.

Why chunks (D-024): Hypothesis keeps per-run bookkeeping for every generated
example (about 28 KB each here), released only when the run ends, so one long
run grows linearly. The run stops at the first failing chunk; its seed
reproduces it.
"""

import argparse
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

PY = sys.executable
NI_FILE = "tests/test_noninterference.py"


def test_id(test: str) -> str:
    return test if "::" in test else f"{NI_FILE}::{test}"


def available_mb() -> float:
    """Available physical memory on this machine, in MB."""
    if sys.platform == "win32":
        import ctypes

        class Status(ctypes.Structure):
            _fields_ = [("dwLength", ctypes.c_ulong), ("dwMemoryLoad", ctypes.c_ulong)] + [
                (name, ctypes.c_ulonglong)
                for name in (
                    "ullTotalPhys",
                    "ullAvailPhys",
                    "ullTotalPageFile",
                    "ullAvailPageFile",
                    "ullTotalVirtual",
                    "ullAvailVirtual",
                    "ullAvailExtendedVirtual",
                )
            ]

        status = Status()
        status.dwLength = ctypes.sizeof(Status)
        if not ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
            return float("nan")
        return round(status.ullAvailPhys / 2**20, 1)
    for line in Path("/proc/meminfo").read_text().splitlines():
        if line.startswith("MemAvailable:"):
            return round(int(line.split()[1]) / 1024, 1)
    return float("nan")


def git_commit() -> str:
    def git(*args: str) -> str:
        return subprocess.run(["git", *args], capture_output=True, text=True).stdout.strip()

    return git("rev-parse", "HEAD") + ("-dirty" if git("status", "--porcelain") else "")


def passed(log: Path) -> set[tuple[str, int]]:
    """(test id, seed) of every chunk with a passing row in the log."""
    if not log.exists():
        return set()
    rows = [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines() if line]
    return {(test_id(r["test"]), int(r["seed"])) for r in rows if r["exit"] == 0}


def run_chunk(test: str, seed: int, examples: int) -> dict[str, object]:
    cmd = [
        PY,
        "-m",
        "pytest",
        test_id(test),
        "--hypothesis-show-statistics",
        f"--hypothesis-seed={seed}",
        "-p",
        "no:cacheprovider",
        "-q",
    ]
    rss_file = Path(tempfile.mkdtemp()) / "peak_rss_mb"
    env = {
        **os.environ,
        "HYPOTHESIS_PROFILE": "fuzz",
        "WARRANT_FUZZ_EXAMPLES": str(examples),
        "WARRANT_RSS_FILE": str(rss_file),  # tests/conftest.py writes the pytest process's peak
    }
    free = available_mb()
    start = time.monotonic()
    proc = subprocess.run(cmd, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    out = proc.stdout
    seconds = time.monotonic() - start
    peak = float(rss_file.read_text()) if rss_file.exists() else float("nan")
    lines = out.strip().splitlines()
    summary = next((ln for ln in reversed(lines) if " passed" in ln or " failed" in ln), "")
    stats = next((ln.strip() for ln in lines if "passing," in ln), "")
    return {
        "test": test,
        "seed": seed,
        "examples": examples,
        "exit": proc.returncode,
        "seconds": round(seconds, 1),
        "peak_rss_mb": round(peak, 1),
        "summary": summary.strip(" ="),
        "hypothesis": stats,
        "commit": git_commit(),
        "available_mb_before": free,
        "output": out if proc.returncode != 0 else "",
    }


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--test", action="append", required=True)
    parser.add_argument("--chunks", type=int, required=True)
    parser.add_argument("--examples", type=int, required=True)
    parser.add_argument("--base-seed", type=int, action="append", required=True)
    parser.add_argument("--first", type=int, default=0, help="index of the first chunk to run")
    parser.add_argument("--resume", action="store_true", help="skip chunks already passed")
    parser.add_argument("--log", type=Path, default=Path("results/fuzz_chunks.jsonl"))
    args = parser.parse_args(argv)
    if len(args.test) != len(args.base_seed):
        parser.error("give one --base-seed per --test")
    args.log.parent.mkdir(parents=True, exist_ok=True)
    done = passed(args.log) if args.resume else set()
    for test, base_seed in zip(args.test, args.base_seed, strict=True):
        for i in range(args.first, args.chunks):
            if (test_id(test), base_seed + i) in done:
                print(f"chunk {i} seed={base_seed + i} {test}: already passed, skipped")
                continue
            row = run_chunk(test, base_seed + i, args.examples)
            with args.log.open("a", encoding="utf-8") as f:
                f.write(json.dumps(row) + "\n")
            print(
                f"chunk {i} seed={row['seed']} exit={row['exit']} {row['seconds']}s"
                f" peak_rss={row['peak_rss_mb']}MB available={row['available_mb_before']}MB"
                f" | {row['hypothesis']} | {row['summary']}",
                flush=True,
            )
            if row["exit"] != 0:
                print(row["output"])
                return int(row["exit"])  # type: ignore[call-overload]
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
