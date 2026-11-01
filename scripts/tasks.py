"""Canonical task runner (the Makefile is a thin alias).

Usage: ``python scripts/tasks.py <target> [extra args]``. Each target is a fixed list of
commands run in order with the current interpreter, each with optional extra
environment variables; the first failure stops the run and its exit code is
returned. Extra arguments are appended to the target's last command, e.g.
``tasks.py fuzz --hypothesis-seed=1`` to reproduce a fuzz run.
"""

import os
import subprocess
import sys

PY = sys.executable
FUZZ_ENV = {"HYPOTHESIS_PROFILE": "fuzz"}

LINT = [
    [PY, "-m", "ruff", "check", "."],
    [PY, "-m", "ruff", "format", "--check", "."],
]
TYPECHECK = [[PY, "-m", "mypy"]]
TEST = [[PY, "-m", "pytest"]]

FUZZ = [
    [
        PY,
        "-m",
        "pytest",
        "tests/test_noninterference.py",
        "--hypothesis-show-statistics",
        "-p",
        "no:cacheprovider",
    ]
]
EVAL = [[PY, "-m", "evals.harness"]]
SWEEP = [[PY, "-m", "evals.sweep"]]
TRACE = [[PY, "-m", "evals.trace"]]
FUZZ_CHUNKS = [[PY, "scripts/fuzz_chunks.py"]]
PHASE3_RUN = [[PY, "scripts/phase3_run.py"]]

TARGETS: dict[str, list[list[str]]] = {
    "lint": LINT,
    "typecheck": TYPECHECK,
    "test": TEST,
    "check": LINT + TYPECHECK + TEST,
    "fuzz": FUZZ,
    "fuzz-chunks": FUZZ_CHUNKS,
    "phase3-run": PHASE3_RUN,
    "eval": EVAL,
    "sweep": SWEEP,
    "trace": TRACE,
}
ENV: dict[str, dict[str, str]] = {"fuzz": FUZZ_ENV}


def main(argv: list[str]) -> int:
    if not argv or argv[0] not in TARGETS:
        print(f"usage: tasks.py {{{','.join(TARGETS)}}} [extra args]", file=sys.stderr)
        return 2
    commands = [list(c) for c in TARGETS[argv[0]]]
    commands[-1] += argv[1:]
    for cmd in commands:
        print("$", " ".join(cmd[1:] if cmd[0] == PY else cmd), flush=True)
        code = subprocess.call(cmd, env={**os.environ, **ENV.get(argv[0], {})})
        if code != 0:
            return code
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
