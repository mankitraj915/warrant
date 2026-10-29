"""Task runner behind the Makefile.

Usage: ``python scripts/tasks.py <target>``. Each target is a fixed list of
commands run in order with the current interpreter; the first failure stops the
run and its exit code is returned.
"""

import subprocess
import sys

PY = sys.executable

LINT = [
    [PY, "-m", "ruff", "check", "."],
    [PY, "-m", "ruff", "format", "--check", "."],
]
TYPECHECK = [[PY, "-m", "mypy"]]
TEST = [[PY, "-m", "pytest"]]

TARGETS: dict[str, list[list[str]]] = {
    "lint": LINT,
    "typecheck": TYPECHECK,
    "test": TEST,
    "check": LINT + TYPECHECK + TEST,
}


def main(argv: list[str]) -> int:
    if len(argv) != 1 or argv[0] not in TARGETS:
        print(f"usage: tasks.py {{{','.join(TARGETS)}}}", file=sys.stderr)
        return 2
    for cmd in TARGETS[argv[0]]:
        print("$", " ".join(cmd[1:] if cmd[0] == PY else cmd), flush=True)
        code = subprocess.call(cmd)
        if code != 0:
            return code
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
