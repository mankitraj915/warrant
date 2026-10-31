"""The NI harness must catch deliberately broken kernels (it must not be vacuous).

Each mutant disables one mechanism the design relies on. The NI property is
then run with a fixed seed and must fail. Written before the kernel; the
patched names are the kernel's extension points for exactly this test.

A mutant counts as caught only from a clean state (D-056): an explicit seed, no
example database, and generation pinned to the seed (``tests/determinism.py``),
so the result does not depend on what else the process ran. Every mutant runs
against the shapes properties; the grammar properties run the mutants the
grammar generator catches on its own (D-056 coverage table). ``check`` replays
one measured detection per mutant (``WITNESSES``); the full budgets
(``BUDGETS``) run in the owner-run ``scripts/mutant_rates.py verify``.
"""

from collections.abc import Callable
from dataclasses import replace
from typing import Any

import pytest
from hypothesis import HealthCheck, Phase, given, seed, settings
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
    # Gate 1 decision 3 / D-054: point reads of a trusted ticket id carry no existence
    # taint only because a missing row halts the run; without the halt it is unsound.
    "point read of a missing trusted ticket does not halt": (
        kernel.tools.database,
        "HALT_ON_ABSENT_TRUSTED_TICKET",
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


# Gate 2 review finding 4: an approved set must not stop because its own effects
# relaxed a later verdict (NEEDS_APPROVAL -> ALLOW). Reversing the order makes
# relaxation count as stricter, which is the behaviour the reviewer found.
NI5_MUTANTS: dict[str, tuple[Any, str, Any]] = {
    "re-check treats a relaxed verdict as stricter": (
        kernel.execution,
        "_STRICTNESS",
        {"ALLOW": 2, "NEEDS_APPROVAL": 1, "BLOCK": 0},
    ),
}


PROPERTIES: dict[str, tuple[dict[str, tuple[Any, str, Any]], Any]] = {
    "NI": (MUTANTS, ni_property),
    "multirun": (MULTIRUN_MUTANTS, multirun_property),
    "NI-5": (NI5_MUTANTS, ni5_property),
}
SEED = 20261031  # the full-budget seed (owner-run verify); rates used other seeds (D-056)
# Examples per (property, plan source), from the clean-state rates (results/phase3-rates,
# results/phase3b/budgets.json): for each mutant, its latest first detection over five seeds
# plus ln(1000)/p, p the 95% lower bound of its pooled rate, rounded up to 500; the property
# takes the largest (D-056). The full budgets run in the owner-run stage b, not in ``check``.
BUDGETS: dict[tuple[str, str], int] = {
    ("NI", "shapes"): 3000,
    ("multirun", "shapes"): 3500,
    ("NI-5", "shapes"): 8000,
    ("NI", "grammar"): 4000,
    ("multirun", "grammar"): 3000,  # catches nothing alone: coverage rows only
    ("NI-5", "grammar"): 3000,  # catches nothing alone: coverage rows only
}
# Mutants the grammar generator catches on its own at every rate seed (D-056 coverage table).
GRAMMAR_CATCHES: dict[str, tuple[str, ...]] = {
    "NI": (
        "extractor output labelled trusted",
        "map body pc ignores list structure",
        "point read of a missing trusted ticket does not halt",
        "policy ignores pc",
    ),
    "multirun": (),
    "NI-5": (),
}
# ``check`` replays each mutant's earliest measured detection: the rate run's settings
# (WITNESS_EXAMPLES) at the seed below, which stops at its first violation. Generation is
# pinned, so this is exact. It is a regression check that the harness still reaches the
# mutant, not a detection-rate claim; the budgets above are that claim (D-056).
WITNESS_EXAMPLES = 1000
WITNESSES: dict[tuple[str, str, str], int] = {
    ("NI", "grammar", "extractor output labelled trusted"): 202616003,  # first at 86
    ("NI", "grammar", "map body pc ignores list structure"): 202616003,  # first at 86
    ("NI", "grammar", "point read of a missing trusted ticket does not halt"): 202616002,  # 91
    ("NI", "grammar", "policy ignores pc"): 202616005,  # first at 122
    ("NI", "shapes", "at ignores index label"): 202616001,  # first at 7
    ("NI", "shapes", "extraction ignores control"): 202616003,  # first at 359
    ("NI", "shapes", "extractor output labelled trusted"): 202616001,  # first at 3
    ("NI", "shapes", "filter ignores predicate labels"): 202616001,  # first at 3
    ("NI", "shapes", "goodwill rule ignores amount"): 202616004,  # first at 168
    ("NI", "shapes", "goodwill rule ignores origin set"): 202616004,  # first at 265
    ("NI", "shapes", "map body pc ignores list structure"): 202616004,  # first at 5
    ("NI", "shapes", "ownership rule drops uniqueness"): 202616001,  # first at 3
    ("NI", "shapes", "ownership rule ignores origin set"): 202616003,  # first at 107
    ("NI", "shapes", "point read of a missing trusted ticket does not halt"): 202616004,  # 3
    ("NI", "shapes", "policy ignores pc"): 202616002,  # first at 60
    ("NI-5", "shapes", "re-check treats a relaxed verdict as stricter"): 202616002,  # 253
    ("multirun", "shapes", "execution writes no record before the provider call"): 202616004,
    ("multirun", "shapes", "goodwill rule drops the per-customer bound"): 202616005,  # 42
    ("multirun", "shapes", "ownership rule drops never-refunded order"): 202616002,  # 3
    ("multirun", "shapes", "ownership rule drops once-per-ticket across runs"): 202616004,
}


def _run_property(
    max_examples: int, prop_fn: Any = ni_property, source: str = "shapes", seed_: int = SEED
) -> Callable[[], None]:
    @seed(seed_)
    @settings(
        max_examples=max_examples,
        derandomize=False,
        database=None,
        deadline=None,
        report_multiple_bugs=False,
        phases=(Phase.generate,),  # caught is enough: no shrinking (no database, so no reuse)
        suppress_health_check=list(HealthCheck),
    )
    @given(st.data())
    def prop(data: Any) -> None:
        prop_fn(data, source)

    return prop


def _cases() -> list[tuple[str, str, str]]:
    cases = [
        (prop, "shapes", name) for prop, (mutants, _) in PROPERTIES.items() for name in mutants
    ]
    cases += [(prop, "grammar", name) for prop, names in GRAMMAR_CATCHES.items() for name in names]
    return sorted(cases)


@pytest.mark.parametrize(("prop", "source", "name"), _cases(), ids=str)
def test_harness_catches_mutant(
    prop: str, source: str, name: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    mutants, prop_fn = PROPERTIES[prop]
    module, attribute, replacement = mutants[name]
    monkeypatch.setattr(module, attribute, replacement)
    with pytest.raises(NIViolation):
        _run_property(WITNESS_EXAMPLES, prop_fn, source, WITNESSES[prop, source, name])()


def test_every_required_mutant_has_a_witness() -> None:
    assert sorted(WITNESSES) == _cases()
