"""``scripts/new_tests_fail_on_base.py`` judges what a change's tests prove (D-060, D-063,
D-073). Each test builds a small git repository with a base commit and a change, copies
the script into it, and runs it there, so the script under test is the one in this tree.
"""

import os
import shutil
import subprocess
import sys
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "new_tests_fail_on_base.py"
GIT_ENV = {
    **os.environ,
    "GIT_AUTHOR_NAME": "t",
    "GIT_AUTHOR_EMAIL": "t@example.invalid",
    "GIT_COMMITTER_NAME": "t",
    "GIT_COMMITTER_EMAIL": "t@example.invalid",
}


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=repo, env=GIT_ENV, capture_output=True, text=True, check=True
    ).stdout.strip()


def _write(repo: Path, files: dict[str, str]) -> None:
    for name, text in files.items():
        (repo / name).parent.mkdir(parents=True, exist_ok=True)
        (repo / name).write_text(text, encoding="utf-8")


def _repo(tmp_path: Path) -> tuple[Path, str]:
    """A base commit with one test, then a change that adds a module and three tests,
    changes the old test in place, and adds a mutant."""
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    _write(
        repo,
        {
            # the options the script relies on, as in pyproject.toml
            "pytest.ini": "[pytest]\ntestpaths = tests\npythonpath = .\naddopts = -q\n",
            "tests/test_old.py": "def test_old():\n    assert 1 + 1 == 2\n",
            "tests/deterministic_mutants.py": "DETERMINISTIC_MUTANTS = {}\n",
        },
    )
    (repo / "scripts").mkdir()
    shutil.copy2(SCRIPT, repo / "scripts" / SCRIPT.name)
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "base")
    base = _git(repo, "rev-parse", "HEAD")
    _write(
        repo,
        {
            "newmod.py": "X = 1\n",
            "tests/test_imports_new.py": "import newmod\n\n\ndef test_uses_new():\n"
            "    assert newmod.X == 1\n",
            "tests/test_passes_on_base.py": "def test_passes():\n    assert True\n",
            "tests/test_old.py": "def test_old():\n    assert True\n",
            "tests/deterministic_mutants.py": (
                "DETERMINISTIC_MUTANTS = {'arbitrary': (None, 'x', None)}\n"
            ),
        },
    )
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "change")
    return repo, base


def _run(repo: Path, base: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "scripts/" + SCRIPT.name, "--base", base],
        cwd=repo,
        capture_output=True,
        text=True,
    )


def test_a_module_that_fails_to_collect_on_base_does_not_hide_a_test_that_passes(
    tmp_path: Path,
) -> None:
    """Gate 3 fix re-review #4, #5, #6: one module's collection error on base used to mark
    every new test "not collected" and accept them all, including one that passes on
    base; in-place changes and new mutants went unmentioned."""
    repo, base = _repo(tmp_path)
    run = _run(repo, base)
    lines = run.stdout.splitlines()
    assert run.returncode == 1, run.stdout + run.stderr
    assert any(
        line.startswith("PASSED") and "test_passes_on_base.py::test_passes" in line
        for line in lines
    )
    assert any(
        line.startswith("COLLECTION ERROR") and "test_imports_new.py::test_uses_new" in line
        for line in lines
    )
    assert any(line.startswith("CHANGED") and "test_old.py::test_old" in line for line in lines)
    assert any(line.startswith("NEW MUTANT") and "arbitrary" in line for line in lines)


def test_uncommitted_tests_are_refused(tmp_path: Path) -> None:
    """The script compares commits; an uncommitted test file was 'not collected' on base
    and accepted (Gate 3 fix re-review #6, hypothesis)."""
    repo, base = _repo(tmp_path)
    _write(repo, {"tests/test_uncommitted.py": "def test_u():\n    assert True\n"})
    run = _run(repo, base)
    assert run.returncode == 2, run.stdout + run.stderr
    assert "uncommitted" in run.stdout
