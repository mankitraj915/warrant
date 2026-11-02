"""Every relative link in the Markdown docs resolves to a file, and every ``#anchor`` to a
heading in it, so the README's and the decision records' evidence links stay usable."""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from check_links import main  # noqa: E402


def test_markdown_links_resolve() -> None:
    docs = [*ROOT.glob("*.md"), *ROOT.glob("docs/**/*.md")]
    assert docs
    assert main([str(d) for d in docs]) == 0
