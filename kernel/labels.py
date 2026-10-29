"""Provenance labels (DESIGN §2).

A label is ``(untrusted, sinks, provenance)``:

- ``untrusted``: origins of untrusted data (``table[key].column``), or ``{STAR}``
  when there were too many to track. Empty means trusted for authority.
- ``sinks``: sinks the value may flow to; ``None`` means unrestricted.
- ``provenance``: trusted sources, for the audit trail only. Never used in a
  decision and ignored by the order.

Join is union on ``untrusted`` and ``provenance`` and intersection on ``sinks``.
"""

from dataclasses import dataclass
from functools import reduce

STAR = "★"
MAX_ORIGINS = 32


def cell_origin(table: str, key: int, column: str) -> str:
    """The origin name of one database cell."""
    return f"{table}[{key}].{column}"


@dataclass(frozen=True, slots=True)
class Label:
    untrusted: frozenset[str] = frozenset()
    sinks: frozenset[str] | None = None
    provenance: frozenset[str] = frozenset()

    @property
    def trusted(self) -> bool:
        """Trusted for authority: no untrusted origin at all."""
        return not self.untrusted

    @staticmethod
    def untrusted_cell(table: str, key: int, column: str) -> "Label":
        return Label(untrusted=frozenset({cell_origin(table, key, column)}))

    @staticmethod
    def trusted_source(source: str) -> "Label":
        return Label(provenance=frozenset({source}))


BOTTOM = Label()


def _join2(a: Label, b: Label) -> Label:
    if a is b:
        return a
    untrusted = a.untrusted | b.untrusted
    if STAR in untrusted or len(untrusted) > MAX_ORIGINS:
        untrusted = frozenset({STAR})
    if a.sinks is None:
        sinks = b.sinks
    elif b.sinks is None:
        sinks = a.sinks
    else:
        sinks = a.sinks & b.sinks
    return Label(untrusted, sinks, a.provenance | b.provenance)


def join(*labels: Label) -> Label:
    """Least upper bound of ``labels`` (``BOTTOM`` for none)."""
    return reduce(_join2, labels, BOTTOM)


def leq(a: Label, b: Label) -> bool:
    """``a ⊑ b``: b is at least as untrusted and at least as restricted as a."""
    untrusted_ok = STAR in b.untrusted or a.untrusted <= b.untrusted
    # None is the set of all sinks, so it is a superset of anything.
    sinks_ok = a.sinks is None or (b.sinks is not None and b.sinks <= a.sinks)
    return untrusted_ok and sinks_ok
