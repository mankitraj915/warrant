"""Canonical action sets and their hash (DESIGN §7).

The hashed object carries each argument's value and untrusted origins, the pc's
origins and the verdict, so an approval view rendered from it shows exactly
what is hashed. Verdict *reasons* are not hashed: they explain, they do not
authorize (D-023).

An ``Approval`` names a run and a hash. The kernel accepts it only for that run,
only if the hash equals its own recomputation of the set it is about to
execute, and only once (DESIGN §7, NI-5).
"""

import hashlib
import json
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any, Protocol

from .interpreter import ResolvedAction
from .labels import STAR, Label
from .policy import Verdict


@dataclass(frozen=True)
class Approval:
    run_id: str
    hash: str


class Approver(Protocol):
    def review(self, request: dict[str, Any], hash_: str) -> Approval | None: ...


class DenyAll:
    """The default approver: approves nothing (Phase 1 behaviour)."""

    def review(self, request: dict[str, Any], hash_: str) -> Approval | None:
        return None


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
