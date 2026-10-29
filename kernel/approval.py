"""Canonical action sets and their hash (DESIGN §7).

The hashed object carries each argument's value and untrusted origins, the pc's
origins and the verdict, so an approval view rendered from it shows exactly
what is hashed. Verdict *reasons* are not hashed: they explain, they do not
authorize (D-023). Phase 1 builds requests only; binding approvals to runs and
executing approved sets is Phase 2.
"""

import hashlib
import json
from collections.abc import Sequence
from typing import Any

from .interpreter import ResolvedAction
from .labels import STAR, Label
from .policy import Verdict


def _origins(label: Label) -> list[str] | str:
    return STAR if STAR in label.untrusted else sorted(label.untrusted)


def canonical_set(
    run_id: str, actions: Sequence[ResolvedAction], verdicts: Sequence[Verdict]
) -> dict[str, Any]:
    return {
        "run_id": run_id,
        "actions": [
            {
                "tool": a.tool,
                "args": a.canonical_args(),
                "labels": {n: _origins(lbl) for n, lbl in a.component_labels().items()},
                "verdict": v.kind,
            }
            for a, v in zip(actions, verdicts, strict=True)
        ],
    }


def digest(canonical: dict[str, Any]) -> str:
    """SHA-256 of the canonical JSON serialization."""
    text = json.dumps(canonical, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()
