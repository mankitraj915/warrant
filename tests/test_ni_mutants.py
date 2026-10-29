"""The NI harness must catch deliberately broken kernels (it must not be vacuous).

Each mutant disables one mechanism the design relies on. The NI property is
then run with a fixed seed and must fail. Written before the kernel; the
patched names are the kernel's extension points for exactly this test.
"""

from collections.abc import Callable
from typing import Any

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

import kernel.declassify
import kernel.interpreter
import kernel.policy
from kernel.labels import BOTTOM, Label
from tests.ni_properties import NIViolation
from tests.test_noninterference import ni_property


def _filter_ignores_predicates(over: Label, preds: list[Label]) -> Label:
    return over


def _body_pc_ignores_list(pc: Label, structure: Label) -> Label:
    return pc


def _extraction_trusted(text: Label) -> Label:
    return BOTTOM


def _at_ignores_index(structure: Label, index: Label) -> Label:
    return structure


MUTANTS: dict[str, tuple[Any, str, Any]] = {
    "filter ignores predicate labels": (
        kernel.interpreter,
        "filter_structure_label",
        _filter_ignores_predicates,
    ),
    "map body pc ignores list structure": (kernel.interpreter, "body_pc", _body_pc_ignores_list),
    "extractor output labelled trusted": (
        kernel.interpreter,
        "extraction_label",
        _extraction_trusted,
    ),
    "at ignores index label": (kernel.interpreter, "at_structure_label", _at_ignores_index),
    "policy ignores pc": (kernel.policy, "PC_IS_A_COMPONENT", False),
    "ownership rule drops uniqueness": (kernel.declassify, "REQUIRE_UNIQUE_ELIGIBLE", False),
}


def _run_property(max_examples: int) -> Callable[[], None]:
    @settings(
        max_examples=max_examples,
        derandomize=True,
        database=None,
        report_multiple_bugs=False,
        suppress_health_check=list(HealthCheck),
    )
    @given(st.data())
    def prop(data: Any) -> None:
        ni_property(data)

    return prop


@pytest.mark.parametrize("name", sorted(MUTANTS))
def test_ni_harness_catches_mutant(name: str, monkeypatch: pytest.MonkeyPatch) -> None:
    module, attribute, replacement = MUTANTS[name]
    monkeypatch.setattr(module, attribute, replacement)
    with pytest.raises(NIViolation):
        _run_property(600)()
