"""Label lattice laws (DESIGN §2). Written before kernel/labels.py."""

import dataclasses

import pytest
from hypothesis import given
from hypothesis import strategies as st

from kernel.labels import (
    BOTTOM,
    MAX_ORIGINS,
    STAR,
    Label,
    cell_origin,
    join,
    leq,
)

origins = st.sampled_from([cell_origin("tickets", k, "body") for k in range(5)] + [STAR])
sinks = st.none() | st.frozensets(st.sampled_from(["operator", "customer:1", "customer:2"]))
labels = st.builds(
    Label,
    untrusted=st.frozensets(origins, max_size=3).map(
        lambda u: frozenset({STAR}) if STAR in u else u
    ),
    sinks=sinks,
    provenance=st.frozensets(st.sampled_from(["operator", "db:orders.amount"]), max_size=2),
)


def _same(a: Label, b: Label) -> bool:
    return a.untrusted == b.untrusted and a.sinks == b.sinks


@given(labels, labels)
def test_join_is_commutative(a: Label, b: Label) -> None:
    assert _same(join(a, b), join(b, a))


@given(labels, labels, labels)
def test_join_is_associative(a: Label, b: Label, c: Label) -> None:
    assert _same(join(join(a, b), c), join(a, join(b, c)))


@given(labels)
def test_join_is_idempotent_and_bottom_is_identity(a: Label) -> None:
    assert _same(join(a, a), a)
    assert _same(join(a, BOTTOM), a)


@given(labels, labels)
def test_join_is_an_upper_bound(a: Label, b: Label) -> None:
    j = join(a, b)
    assert leq(a, j) and leq(b, j)


@given(labels)
def test_trusted_iff_no_untrusted_origin(a: Label) -> None:
    assert a.trusted == (len(a.untrusted) == 0)


def test_bottom_is_trusted_and_allows_every_sink() -> None:
    assert BOTTOM.trusted and BOTTOM.sinks is None


def test_untrusted_origin_survives_join_with_trusted() -> None:
    t = Label.untrusted_cell("tickets", 42, "body")
    assert not join(BOTTOM, t).trusted
    assert join(BOTTOM, t).untrusted == {"tickets[42].body"}


def test_star_absorbs() -> None:
    star = Label(untrusted=frozenset({STAR}))
    assert join(star, Label.untrusted_cell("tickets", 1, "body")).untrusted == {STAR}


def test_origins_collapse_to_star_above_limit() -> None:
    parts = [Label.untrusted_cell("orders", k, "customer_note") for k in range(MAX_ORIGINS + 1)]
    assert join(*parts).untrusted == {STAR}
    assert join(*parts[:MAX_ORIGINS]).untrusted != {STAR}


def test_sinks_intersect() -> None:
    a = Label(sinks=frozenset({"operator", "customer:1"}))
    b = Label(sinks=frozenset({"operator"}))
    assert join(a, b).sinks == {"operator"}
    assert join(a, BOTTOM).sinks == {"operator", "customer:1"}


def test_provenance_is_ignored_by_order() -> None:
    a = Label(provenance=frozenset({"operator"}))
    b = Label(provenance=frozenset({"db:orders.amount"}))
    assert leq(a, b) and leq(b, a)


def test_labels_are_immutable() -> None:
    with pytest.raises(dataclasses.FrozenInstanceError):
        BOTTOM.untrusted = frozenset({"x"})  # type: ignore[misc]
