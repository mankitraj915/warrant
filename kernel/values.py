"""Labelled runtime values (DESIGN §3).

Scalars carry a label. Records carry a selection label and lists a structure
label; reading a field or an element always joins it, so no value can leave a
compound without the label of how it was chosen.
"""

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from .labels import Label, join

Py = int | str | bool


@dataclass(frozen=True, slots=True)
class Scalar:
    value: Py
    label: Label


@dataclass(frozen=True, slots=True)
class Record:
    fields: Mapping[str, "Value"]
    label: Label

    def field(self, name: str) -> "Value":
        return joined(self.fields[name], self.label)


@dataclass(frozen=True, slots=True)
class ListV:
    items: tuple["Value", ...]
    label: Label

    def element(self, index: int) -> "Value":
        return joined(self.items[index], self.label)


@dataclass(frozen=True, slots=True)
class UnitV:
    """The result of a consequential call; it can never be bound or read."""


UNIT_VALUE = UnitV()
Value = Scalar | Record | ListV | UnitV


def joined(v: Value, extra: Label) -> Value:
    """``v`` with ``extra`` joined into its outermost label."""
    if isinstance(v, Scalar):
        return Scalar(v.value, join(v.label, extra))
    if isinstance(v, Record):
        return Record(v.fields, join(v.label, extra))
    if isinstance(v, ListV):
        return ListV(v.items, join(v.label, extra))
    return v


def whole_label(v: Value) -> Label:
    """Label of a value used as a whole: its own label joined with every leaf."""
    if isinstance(v, Scalar):
        return v.label
    if isinstance(v, Record):
        return join(v.label, *(whole_label(f) for f in v.fields.values()))
    if isinstance(v, ListV):
        return join(v.label, *(whole_label(i) for i in v.items))
    return Label()


def plain(v: Value) -> Any:
    """The unlabelled Python value (for canonical serialization and comparison)."""
    if isinstance(v, Scalar):
        return v.value
    if isinstance(v, Record):
        return {k: plain(f) for k, f in v.fields.items()}
    if isinstance(v, ListV):
        return [plain(i) for i in v.items]
    return None
