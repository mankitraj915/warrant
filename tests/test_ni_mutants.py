"""The NI harness must catch deliberately broken kernels (it must not be vacuous).

Each mutant disables one mechanism the design relies on. The NI property is
then run with a fixed seed and must fail. Written before the kernel; the
patched names are the kernel's extension points for exactly this test.
"""

from collections.abc import Callable
from dataclasses import replace
from typing import Any

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

import kernel.declassify
import kernel.execution
import kernel.interpreter
import kernel.policy
import kernel.tools.database
from kernel.labels import BOTTOM, Label
from kernel.tools.database import TrustedReader
from tests.ni_properties import NIViolation
from tests.test_approval_binding import ni5_property
from tests.test_noninterference import multirun_property, ni_property


def _filter_ignores_predicates(over: Label, preds: list[Label]) -> Label:
    return over


def _body_pc_ignores_list(pc: Label, structure: Label) -> Label:
    return pc


def _extraction_trusted(text: Label, seen: Label) -> Label:
    return BOTTOM


def _at_ignores_index(structure: Label, index: Label) -> Label:
    return structure


_rule = kernel.declassify.ticket_order_ownership


def _rule_ignores_origins(action: Any, components: Any, actions: Any, reader: Any) -> Any:
    """The ownership rule endorses untrusted data from anywhere, not just the ticket."""
    return _rule(action, {n: BOTTOM for n in components}, actions, reader)


_goodwill = kernel.declassify.ticket_goodwill_credit


def _goodwill_ignores_origins(action: Any, components: Any, actions: Any, reader: Any) -> Any:
    return _goodwill(action, {n: BOTTOM for n in components}, actions, reader)


def _goodwill_ignores_amount(action: Any, components: Any, actions: Any, reader: Any) -> Any:
    """Admits whenever the amount is the only reason found (later checks skipped)."""
    d = _goodwill(action, components, actions, reader)
    return replace(d, admitted=True) if d.reason.startswith("amount is not") else d


def _never(self: Any, *args: Any) -> bool:
    return False


# Examples per mutant. The rarest fires about once per 310 examples (measured
# 2026-10-30, D-049), so 600 left too little margin; a caught mutant stops early.
NI_BUDGET = 3000
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
    # Gate 1 decision 3: point reads of a trusted ticket id without the existence taint.
    "point ticket read drops existence origin": (
        kernel.tools.database,
        "POINT_READ_EXISTENCE",
        False,
    ),
    # Added after the Gate 1 review (findings 2, 3 and 6).
    "ownership rule ignores origin set": (
        kernel.policy,
        "ticket_order_ownership",
        _rule_ignores_origins,
    ),
    # Phase 2: the goodwill credit rule.
    "goodwill rule ignores origin set": (
        kernel.policy,
        "ticket_goodwill_credit",
        _goodwill_ignores_origins,
    ),
    "goodwill rule ignores amount": (
        kernel.policy,
        "ticket_goodwill_credit",
        _goodwill_ignores_amount,
    ),
    # Gate 2 review findings 1-2: extraction under untrusted control.
    "extraction ignores control": (kernel.interpreter, "EXTRACTION_FOLLOWS_CONTROL", False),
}
# The rarest multirun mutant fires about once per 330 examples (measured 2026-10-30,
# D-049); at 600 examples one was missed by chance.
MULTIRUN_BUDGET = 3000
MULTIRUN_MUTANTS: dict[str, tuple[Any, str, Any]] = {
    "ownership rule drops once-per-ticket across runs": (
        TrustedReader,
        "ticket_has_refund",
        _never,
    ),
    "ownership rule drops never-refunded order": (TrustedReader, "order_has_refund", _never),
    "goodwill rule drops the per-customer bound": (TrustedReader, "customer_has_credit", _never),
    "execution writes no record before the provider call": (
        kernel.execution,
        "PENDING_FIRST",
        False,
    ),
}


def _run_property(max_examples: int, prop_fn: Any = ni_property) -> Callable[[], None]:
    @settings(
        max_examples=max_examples,
        derandomize=True,
        database=None,
        report_multiple_bugs=False,
        suppress_health_check=list(HealthCheck),
    )
    @given(st.data())
    def prop(data: Any) -> None:
        prop_fn(data)

    return prop


@pytest.mark.parametrize("name", sorted(MUTANTS))
def test_ni_harness_catches_mutant(name: str, monkeypatch: pytest.MonkeyPatch) -> None:
    module, attribute, replacement = MUTANTS[name]
    monkeypatch.setattr(module, attribute, replacement)
    with pytest.raises(NIViolation):
        _run_property(NI_BUDGET)()


@pytest.mark.parametrize("name", sorted(MULTIRUN_MUTANTS))
def test_multirun_harness_catches_mutant(name: str, monkeypatch: pytest.MonkeyPatch) -> None:
    module, attribute, replacement = MULTIRUN_MUTANTS[name]
    monkeypatch.setattr(module, attribute, replacement)
    with pytest.raises(NIViolation):
        _run_property(MULTIRUN_BUDGET, multirun_property)()


# Gate 2 review finding 4: an approved set must not stop because its own effects
# relaxed a later verdict (NEEDS_APPROVAL -> ALLOW). Reversing the order makes
# relaxation count as stricter, which is the behaviour the reviewer found.
# About 1 detection in 180 examples (D-049); NI-5 runs are cheap.
NI5_BUDGET = 2000
NI5_MUTANTS: dict[str, tuple[Any, str, Any]] = {
    "re-check treats a relaxed verdict as stricter": (
        kernel.execution,
        "_STRICTNESS",
        {"ALLOW": 2, "NEEDS_APPROVAL": 1, "BLOCK": 0},
    ),
}


@pytest.mark.parametrize("name", sorted(NI5_MUTANTS))
def test_ni5_harness_catches_mutant(name: str, monkeypatch: pytest.MonkeyPatch) -> None:
    module, attribute, replacement = NI5_MUTANTS[name]
    monkeypatch.setattr(module, attribute, replacement)
    with pytest.raises(NIViolation):
        _run_property(NI5_BUDGET, ni5_property)()
