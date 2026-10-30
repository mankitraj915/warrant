"""Gate 1 decision 3: does a point read of an operator-supplied ticket id need the
existence taint (D-028), or can its existence only suppress a run?

The narrowed variant (``POINT_READ_EXISTENCE = False``) drops the taint for point
reads of a trusted id. These tests show it is unsound: existence becomes a value
(how often a map body runs, ``len``, ``at``) that can choose *between* executed
actions, not just whether a run executes. That violates NI-3 itself, not only
the stricter NI-1. The current rule (taint kept) passes the same tests.

Phase 3 (owner, Gate 2 decision 6; D-054) adds a third configuration, the D-036
variant: the taint is dropped, but a point read of a trusted ticket id that
finds no row *halts* the run during resolution. Existence then reaches only
whole-run suppression, which NI-3 permits. NI-1 is stated for pairs of runs
that both finish resolution. Written before the variant was implemented.
"""

from collections.abc import Iterator

import pytest

import kernel.tools.database
from domain.seed import Ticket, World, materialize
from kernel.labels import Label
from kernel.run import RunResult
from kernel.tools.database import Database
from kernel.values import Scalar
from planners.builders import Json, call, expr, lit, map_, op, plan, ref
from planners.fuzz import OTHER_CUSTOMER, _case_world
from tests.ni_properties import NIViolation, check_ni1, check_ni3, effects
from tests.support import run_world

A, B = 4001, 4002  # ticket ids an attacker may or may not open


def _world(*opened: int) -> World:
    base = _case_world(1, "delivered")  # case customer has orders 7000 and 7001
    return base.extend(tickets=tuple(Ticket(t, OTHER_CUSTOMER, "hi", "x") for t in opened))


def _refund_under(ticket: int, order: int, amount: int) -> Json:
    return expr(
        map_(
            ref(f"t{ticket}"),
            f"tk{ticket}",
            call("issue_refund", ticket_id=lit(4000), order_id=lit(order), amount=lit(amount)),
        )
    )


# Existence picks which of two refunds executes: both runs execute, effects differ.
STEER_BY_TWO_READS = plan(
    call("read_ticket", f"t{A}", ticket_id=lit(A)),
    call("read_ticket", f"t{B}", ticket_id=lit(B)),
    _refund_under(A, 7000, 120_000),
    _refund_under(B, 7001, 450_000),
)

# Existence becomes an index: len(read_ticket(A)) picks order 7000 or 7001.
STEER_BY_INDEX = plan(
    call("read_ticket", "t", ticket_id=lit(A)),
    call("query_orders", "orders", customer_id=lit(100)),
    expr(op("at", ref("orders"), op("len", ref("t"))), "picked"),
    expr(
        map_(
            ref("picked"),
            "p",
            call(
                "issue_refund",
                ticket_id=lit(4000),
                order_id=ref("p", "id"),
                amount=ref("p", "refundable"),
            ),
        )
    ),
)


# (POINT_READ_EXISTENCE, HALT_ON_ABSENT_TRUSTED_TICKET) per configuration
CONFIGS = {"taint kept": (True, False), "narrowed": (False, False), "variant": (False, True)}


@pytest.fixture(params=list(CONFIGS))
def config(request: pytest.FixtureRequest) -> Iterator[str]:
    db = kernel.tools.database
    old = db.POINT_READ_EXISTENCE, db.HALT_ON_ABSENT_TRUSTED_TICKET
    db.POINT_READ_EXISTENCE, db.HALT_ON_ABSENT_TRUSTED_TICKET = CONFIGS[request.param]
    yield request.param
    db.POINT_READ_EXISTENCE, db.HALT_ON_ABSENT_TRUSTED_TICKET = old


def _ni3_holds(p: Json, w1: World, w2: World) -> bool:
    r1, p1, _ = run_world(p, w1)
    r2, p2, _ = run_world(p, w2)
    try:
        check_ni3(r1, effects(p1), r2, effects(p2))
    except NIViolation:
        return False
    return True


@pytest.mark.parametrize("p", [STEER_BY_TWO_READS, STEER_BY_INDEX], ids=["two-reads", "index"])
def test_point_read_existence_can_steer_not_only_suppress(p: Json, config: str) -> None:
    w1, w2 = (_world(A), _world(B)) if p is STEER_BY_TWO_READS else (_world(), _world(A))
    assert _ni3_holds(p, w1, w2) is (config != "narrowed")


def test_reviewers_probe_is_caught_by_ni1_only_when_narrowed_without_halting(
    config: str,
) -> None:
    """The reviewer's original probe: one point read gating a trusted refund. With
    the bare narrowing it is NI-3-permitted suppression (one side empty) but NI-1
    still flags it; with the taint it is clean; under the variant the run without
    the ticket halts, so the pair is outside NI-1 and only suppression remains."""
    p = plan(call("read_ticket", f"t{A}", ticket_id=lit(A)), _refund_under(A, 7000, 120_000))
    r1, p1, _ = run_world(p, _world())
    r2, _, _ = run_world(p, _world(A))
    if config == "narrowed":
        with pytest.raises(NIViolation):
            check_ni1(r1, r2)
    else:
        check_ni1(r1, r2)
    assert (r1.outcome == "halted") is (config == "variant")
    if config == "variant":
        assert r1.actions == () and p1.effects == []


def _halted(r: RunResult) -> bool:
    return r.outcome == "halted" and r.actions == () and r.verdicts == ()


def test_variant_halts_only_trusted_point_reads_of_missing_tickets(config: str) -> None:
    """A trusted id that names no ticket halts; an existing ticket, or an id taken
    from untrusted text, reads as before (the empty list for a missing row)."""
    missing = plan(call("read_ticket", "t", ticket_id=lit(A)))
    present = plan(call("read_ticket", "t", ticket_id=lit(4000)))
    assert _halted(run_world(missing, _world())[0]) is (config == "variant")
    assert run_world(present, _world())[0].outcome == "executed"
    # An untrusted ticket id is not a point read of an operator-named ticket.
    db = Database(materialize(_world()))
    untrusted_id = Scalar(A, Label.untrusted_cell("tickets", 4000, "body"))
    assert db.read_ticket(untrusted_id).items == ()
