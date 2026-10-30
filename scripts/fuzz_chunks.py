"""Bounded fuzzing: run one NI property as sequential chunks, each in its own
process with its own recorded seed, and measure each chunk's peak RSS.

Usage (normally through ``scripts/tasks.py fuzz-chunks``)::

    python scripts/fuzz_chunks.py --test test_noninterference --chunks 20 \
        --examples 1000 --base-seed 20261030

``--test`` is a property in ``tests/test_noninterference.py`` or a full
``path::name`` id (e.g. the NI-5 property in ``tests/test_approval_binding.py``).
Chunk ``i`` uses seed ``base_seed + i``. Each chunk appends one JSON line to
``results/fuzz_chunks.jsonl``: test, seed, examples, exit code, seconds, peak
RSS in MB and Hypothesis's summary. Peak RSS is measured inside the pytest
process by ``tests/conftest.py``: on Windows the venv's ``python.exe`` is a
launcher, so the child process handle would report the launcher's memory.

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


def run_chunk(test: str, seed: int, examples: int) -> dict[str, object]:
    cmd = [
        PY,
        "-m",
        "pytest",
        test if "::" in test else f"tests/test_noninterference.py::{test}",
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
        "output": out if proc.returncode != 0 else "",
    }


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--test", required=True)
    parser.add_argument("--chunks", type=int, required=True)
    parser.add_argument("--examples", type=int, required=True)
    parser.add_argument("--base-seed", type=int, required=True)
    parser.add_argument("--first", type=int, default=0, help="index of the first chunk to run")
    parser.add_argument("--log", type=Path, default=Path("results/fuzz_chunks.jsonl"))
    args = parser.parse_args(argv)
    args.log.parent.mkdir(parents=True, exist_ok=True)
    for i in range(args.first, args.chunks):
        row = run_chunk(args.test, args.base_seed + i, args.examples)
        with args.log.open("a", encoding="utf-8") as f:
            f.write(json.dumps(row) + "\n")
        print(
            f"chunk {i} seed={row['seed']} exit={row['exit']} {row['seconds']}s"
            f" peak_rss={row['peak_rss_mb']}MB | {row['hypothesis']} | {row['summary']}",
            flush=True,
        )
        if row["exit"] != 0:
            print(row["output"])
            return int(row["exit"])  # type: ignore[call-overload]
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
