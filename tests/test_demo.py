"""The scripted demonstration (``tasks.py demo``) holds, and its committed transcript is
the output of a real run of the current code."""

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TRANSCRIPT = ROOT / "docs" / "demo_transcript.txt"


def test_demo_checks_hold_and_the_committed_transcript_is_current() -> None:
    out = subprocess.run(
        [sys.executable, "scripts/demo.py"], cwd=ROOT, capture_output=True, text=True
    )
    assert out.returncode == 0, out.stdout + out.stderr
    assert out.stdout.rstrip().endswith("demo checks: all hold")
    assert out.stdout == TRANSCRIPT.read_text(encoding="utf-8"), (
        "docs/demo_transcript.txt is stale: regenerate it with"
        " `uv run --locked python scripts/demo.py > docs/demo_transcript.txt`"
    )
