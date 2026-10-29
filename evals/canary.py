"""PII canary scanner (SPEC §4.8).

Every generated customer email carries ``CANARY`` (domain/seed.py). ``scan``
walks any JSON-like value (planner input, audit records, answers, results) and
returns the paths where the canary appears; an empty list means no leak.
"""

from typing import Any

from domain.seed import CANARY

__all__ = ["CANARY", "scan"]


def scan(value: Any, path: str = "$") -> list[str]:
    if isinstance(value, str):
        return [path] if CANARY in value else []
    if isinstance(value, bytes):
        return [path] if CANARY.encode() in value else []
    if isinstance(value, dict):
        return [p for k, v in value.items() for p in scan(v, f"{path}.{k}") + scan(k, path)]
    if isinstance(value, list | tuple | set | frozenset):
        return [p for i, v in enumerate(value) for p in scan(v, f"{path}[{i}]")]
    return [path] if CANARY in repr(value) else []
