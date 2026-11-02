"""Check that relative Markdown links in docs resolve: the file exists and, for
``file.md#anchor``, a heading in it produces that anchor (GitHub's slug rules).

Usage: ``python scripts/check_links.py README.md docs/*.md``. Exit 1 on a broken link.
"""

import re
import sys
from pathlib import Path

LINK = re.compile(r"\]\(([^)\s]+)\)")


def slug(heading: str) -> str:
    text = heading.strip().lower()
    text = re.sub(r"[^\w\- ]", "", text)
    return text.replace(" ", "-")


def anchors(path: Path) -> set[str]:
    found: set[str] = set()
    counts: dict[str, int] = {}
    in_code = False
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith("```"):
            in_code = not in_code
        if in_code or not line.startswith("#"):
            continue
        base = slug(line.lstrip("#"))
        n = counts.get(base, 0)
        counts[base] = n + 1
        found.add(base if n == 0 else f"{base}-{n}")
    return found


def main(paths: list[str]) -> int:
    broken = 0
    for name in paths:
        source = Path(name)
        for target in LINK.findall(source.read_text(encoding="utf-8")):
            if re.match(r"[a-z]+:", target):
                continue  # external
            file_part, _, anchor = target.partition("#")
            dest = (source.parent / file_part).resolve() if file_part else source.resolve()
            if not dest.exists():
                print(f"{source}: missing file {target}")
                broken += 1
            elif anchor and dest.suffix == ".md" and anchor not in anchors(dest):
                print(f"{source}: missing anchor {target}")
                broken += 1
    print(f"{broken} broken link(s)")
    return 1 if broken else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
