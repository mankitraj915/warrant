"""Check that the tests a change adds fail on the base commit.

A regression test is evidence of a fix only if it fails without the fix. This
script collects test ids at HEAD and at ``--base``; the new ids are those at HEAD
only. It checks the base commit out in a temporary worktree, copies HEAD's
test files over it, and runs only the new tests there, with this environment's
interpreter (so the base commit's code and HEAD's tests). It compares commits, so
commit before running it locally.

HEAD's test files are: every added file under ``tests/``, and every modified
``test_*.py``, ``conftest.py`` and ``deterministic_mutants.py``. Other modified
helpers (the NI oracles in ``ni_properties.py``, ``support.py``) stay at base:
when a change fixes an oracle, the oracle is the code under test (D-066).

Every new test must fail on base: a FAILED or ERROR result, or not being
collectable there (for example because it imports a name the fix adds). A new
test that passes or is skipped on base makes the exit code 1. No new tests:
exit code 0.

Each new test module runs in its own pytest process on base, so one module that
fails to collect there cannot hide the others (Gate 3 fix re-review #4). A module
that fails to collect on base (typically because it imports what the fix adds) is
reported as ``COLLECTION ERROR``: it counts as failing, but its assertions never
ran on base, so the summary counts these separately for the PR reviewer.

Two kinds of new test are judged differently (D-063):
- ``@pytest.mark.harness_gap("<mutant>")``: a test of code that was already
  correct (a harness gap, not a bug), so it cannot fail on base as it stands.
  It must pass on base unmutated and fail there with its named mutant applied
  (``WARRANT_MUTANT=*``). Mutants that the PR adds to ``deterministic_mutants.py``
  are listed by name: whether a new mutant reintroduces the bug its test claims is
  for the PR reviewer to check (Gate 3 fix re-review #5).
- ``test_harness_catches_*``: a test that a mutant is detected passes on any
  commit where both the code and the detecting test exist. These are listed,
  not judged; the PR's ``check`` run is their evidence.

Not judged, but listed: existing test functions whose source changed (a test changed
in place could have been weakened; Gate 3 fix re-review #6). The script compares
commits, so it refuses to run while ``tests/`` has uncommitted changes.

Usage: ``python scripts/new_tests_fail_on_base.py --base <commit>``.
"""

import argparse
import ast
import os
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


def collect(cwd: Path, *args: str) -> set[str]:
    out = subprocess.run(
        [*PYTEST, "--collect-only", *args], cwd=cwd, capture_output=True, text=True
    ).stdout
    return {line.strip() for line in out.splitlines() if "::" in line}


def outcomes(cwd: Path, ids: list[str], mutant: str | None = None) -> dict[str, str]:
    """Each test id's outcome from pytest's short summary (``-rA``), one pytest
    process per module. A module that fails to collect gives its tests
    ``COLLECTION ERROR``; an id missing from a module that ran gives ``MISSING``."""
    env = {**os.environ, "WARRANT_MUTANT": mutant} if mutant else None
    by_module: dict[str, list[str]] = {}
    for node in ids:
        by_module.setdefault(node.split("::")[0], []).append(node)
    found: dict[str, str] = {}
    for module, nodes in sorted(by_module.items()):
        out = subprocess.run(
            [*PYTEST, "-rA", "--tb=no", *nodes], cwd=cwd, capture_output=True, text=True, env=env
        ).stdout
        seen: dict[str, str] = {}
        collection_error = False
        for line in out.splitlines():
            word, _, rest = line.partition(" ")
            node = rest.split(" - ", 1)[0].strip()
            if word == "ERROR" and node == module:
                collection_error = True
            elif word in ("PASSED", "FAILED", "ERROR", "SKIPPED", "XFAIL", "XPASS"):
                seen[node] = word
        for node in nodes:
            found[node] = "COLLECTION ERROR" if collection_error else seen.get(node, "MISSING")
    return found


INFRASTRUCTURE = ("conftest.py", "deterministic_mutants.py")


def _test_files(base: str) -> list[str]:
    """Files under tests/ to take from HEAD: added files, and modified test modules
    and test infrastructure. Modified helpers such as oracles stay at base."""
    added = git("diff", "--name-only", "--diff-filter=A", base, "HEAD", "--", "tests").split()
    modified = git("diff", "--name-only", "--diff-filter=M", base, "HEAD", "--", "tests").split()
    keep = [
        m for m in modified if Path(m).name.startswith("test_") or Path(m).name in INFRASTRUCTURE
    ]
    return added + keep


def _test_sources(source: str) -> dict[str, str]:
    """Source of each ``test_*`` function (qualified by class), by name."""
    found: dict[str, str] = {}
    for top in ast.parse(source).body:
        inner = top.body if isinstance(top, ast.ClassDef) else [top]
        prefix = f"{top.name}::" if isinstance(top, ast.ClassDef) else ""
        for node in inner:
            is_function = isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef)
            if is_function and node.name.startswith("test_"):
                found[prefix + node.name] = ast.get_source_segment(source, node) or ""
    return found


def changed_in_place(base: str) -> list[str]:
    """Test functions present at base and at HEAD whose source differs."""
    modified = git("diff", "--name-only", "--diff-filter=M", base, "HEAD", "--", "tests").split()
    changed = []
    for name in modified:
        if not Path(name).name.startswith("test_"):
            continue
        before = _test_sources(git("show", f"{base}:{name}"))
        after = _test_sources(git("show", f"HEAD:{name}"))
        changed += [f"{name}::{t}" for t in sorted(before) if t in after and before[t] != after[t]]
    return changed


def _mutant_names(source: str) -> set[str]:
    """The string keys of the ``DETERMINISTIC_MUTANTS`` dict literal."""
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Assign | ast.AnnAssign):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            names = [t.id for t in targets if isinstance(t, ast.Name)]
            if "DETERMINISTIC_MUTANTS" in names and isinstance(node.value, ast.Dict):
                return {k.value for k in node.value.keys if isinstance(k, ast.Constant)}
    return set()


def new_mutants(base: str) -> list[str]:
    """Deterministic mutants that HEAD defines and base does not."""
    path = "tests/deterministic_mutants.py"
    if not git("ls-tree", "HEAD", "--", path).strip():
        return []
    before = git("show", f"{base}:{path}") if git("ls-tree", base, "--", path).strip() else ""
    return sorted(_mutant_names(git("show", f"HEAD:{path}")) - _mutant_names(before))


def _name(node: str) -> str:
    return node.split("::")[-1].split("[")[0]


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", required=True)
    args = parser.parse_args(argv)
    if git("status", "--porcelain", "--", "tests").strip():
        print("tests/ has uncommitted changes; commit first (this script compares commits).")
        return 2
    base = git("rev-parse", args.base).strip()
    for node in changed_in_place(base):
        print(f"{'CHANGED':16} in place, not judged (review it)  {node}")
    for name in new_mutants(base):
        print(f"{'NEW MUTANT':16} added by this change (review what it breaks)  {name}")
    new = sorted(collect(ROOT) - collect_at(base))
    if not new:
        print("No tests added relative to the base commit.")
        return 0
    gaps = sorted(collect(ROOT, "-m", "harness_gap") & set(new))
    validation = [n for n in new if _name(n).startswith("test_harness_catches_")]
    regression = [n for n in new if n not in gaps and n not in validation]
    with tempfile.TemporaryDirectory() as tmp:
        tree = Path(tmp) / "base"
        git("worktree", "add", "--detach", str(tree), base)
        try:
            for name in _test_files(base):
                (tree / name).parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(ROOT / name, tree / name)
            results = outcomes(tree, regression)
            unmutated = outcomes(tree, gaps)
            under_mutant = outcomes(tree, gaps, mutant="*")
        finally:
            git("worktree", "remove", "--force", str(tree))
    failing_wrongly = []
    for node in regression:
        print(f"{results[node]:16} on base  {node}")
        if results[node] not in ("FAILED", "ERROR", "COLLECTION ERROR"):
            failing_wrongly.append(node)
    for node in gaps:
        print(f"{unmutated[node]:16} on base unmutated  {node}")
        print(f"{under_mutant[node]:16} on base under its mutant  {node}")
        # it must pass as base stands, and run and fail under its mutant
        if unmutated[node] != "PASSED" or under_mutant[node] != "FAILED":
            failing_wrongly.append(node)
    for node in validation:
        print(f"{'LISTED':16} mutant-detection test, not judged  {node}")
    if failing_wrongly:
        print(f"\n{len(failing_wrongly)} new test(s) do not fail as required on {base[:7]}.")
        return 1
    import_only = sum(results[n] == "COLLECTION ERROR" for n in regression)
    print(
        f"\nAll {len(regression) + len(gaps)} judged new test(s) fail on {base[:7]}"
        f" ({len(gaps)} of them under their mutant; {import_only} only because their module"
        f" does not collect there); {len(validation)} listed, not judged."
    )
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
