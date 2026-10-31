"""Examples depend on the seed alone, not on which modules a process has loaded (D-056)."""

import importlib

import pytest
from hypothesis import given, seed, settings
from hypothesis import strategies as st
from hypothesis.internal.conjecture import providers
from sortedcontainers import SortedSet

from tests.determinism import pinned


def test_generation_is_pinned_before_any_test_runs() -> None:
    assert pinned()


def test_loading_more_local_modules_adds_no_constants() -> None:
    importlib.import_module("evals.harness")  # hundreds of literals in evals/ and domain/
    importlib.import_module("planners.grammar_fuzz")
    assert len(providers._get_local_constants()) == 0


def _draws() -> list[int]:
    out: list[int] = []

    @seed(20261031)
    @settings(max_examples=300, database=None, derandomize=False)
    @given(st.integers())
    def collect(x: int) -> None:
        out.append(x)

    collect()
    return out


def test_a_harvested_pool_changes_examples_and_the_pin_removes_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The mechanism behind D-056: a non-empty pool (what loading a module with literals
    adds) changes the examples a fixed seed generates; the pin restores them."""
    pinned_draws = _draws()
    pool = providers.Constants(
        integers=SortedSet([424242, 7000]),
        floats=SortedSet(key=providers.float_to_int),
        bytes=SortedSet(),
        strings=SortedSet(),
    )
    monkeypatch.setattr(providers, "_get_local_constants", lambda: pool)
    providers.CONSTANTS_CACHE.cache.clear()
    assert _draws() != pinned_draws
    monkeypatch.undo()
    providers.CONSTANTS_CACHE.cache.clear()
    assert pinned() and _draws() == pinned_draws
