"""Check that the tests a change adds fail on the base commit.

A regression test is evidence of a fix only if it fails without the fix. This
script collects test ids at HEAD and at ``--base``; the new ids are those at HEAD
only. It checks the base commit out in a temporary worktree, copies HEAD's
version of every changed file under ``tests/`` over it, and runs only the new
tests there, with this environment's interpreter (so the base commit's code and
HEAD's tests).

Every new test must fail on base: a FAILED or ERROR result, or not being
collectable there (for example because it imports a name the fix adds). A new
test that passes or is skipped on base makes the exit code 1. No new tests:
exit code 0.

Usage: ``python scripts/new_tests_fail_on_base.py --base <commit>``.
"""

import argparse
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PYTEST = [sys.executable, "-m", "pytest", "-p", "no:cacheprovider"]


def git(*args: str, cwd: Path = ROOT) -> str:
    return subprocess.run(
        ["git", *args], cwd=cwd, capture_output=True, text=True, check=True
    ).stdout


def collect(cwd: Path) -> set[str]:
    out = subprocess.run(
        [*PYTEST, "--collect-only"], cwd=cwd, capture_output=True, text=True
    ).stdout
    return {line.strip() for line in out.splitlines() if "::" in line}


def outcomes(cwd: Path, ids: list[str]) -> dict[str, str]:
    """Each test id's outcome from pytest's short summary (``-rA``)."""
    out = subprocess.run(
        [*PYTEST, "-rA", "--tb=no", *ids], cwd=cwd, capture_output=True, text=True
    ).stdout
    found: dict[str, str] = {}
    for line in out.splitlines():
        word, _, rest = line.partition(" ")
        if word in ("PASSED", "FAILED", "ERROR", "SKIPPED", "XFAIL", "XPASS"):
            node = rest.split(" - ", 1)[0].strip()
            if node in ids:
                found[node] = word
    return found


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", required=True)
    args = parser.parse_args(argv)
    base = git("rev-parse", args.base).strip()
    new = sorted(collect(ROOT) - collect_at(base))
    if not new:
        print("No tests added relative to the base commit.")
        return 0
    with tempfile.TemporaryDirectory() as tmp:
        tree = Path(tmp) / "base"
        git("worktree", "add", "--detach", str(tree), base)
        try:
            changed = git("diff", "--name-only", "--diff-filter=AM", base, "HEAD", "--", "tests")
            for name in changed.split():
                (tree / name).parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(ROOT / name, tree / name)
            results = outcomes(tree, new)
        finally:
            git("worktree", "remove", "--force", str(tree))
    passing = []
    for node in new:
        outcome = results.get(node, "NOT COLLECTED")
        print(f"{outcome:13} on base  {node}")
        if outcome not in ("FAILED", "ERROR", "NOT COLLECTED"):
            passing.append(node)
    if passing:
        print(f"\n{len(passing)} new test(s) pass on {base[:7]}: not evidence of a fix.")
        return 1
    print(f"\nAll {len(new)} new test(s) fail on {base[:7]}.")
    return 0


def collect_at(commit: str) -> set[str]:
    with tempfile.TemporaryDirectory() as tmp:
        tree = Path(tmp) / "collect"
        git("worktree", "add", "--detach", str(tree), commit)
        try:
            return collect(tree)
        finally:
            git("worktree", "remove", "--force", str(tree))


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
