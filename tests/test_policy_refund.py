"""Refund policy without declassification (DESIGN §6). Written before the policy."""

from domain.seed import World
from planners.builders import Json, call, expr, lit, map_, plan, ref
from planners.fuzz import CASE_TICKET, _case_world
from tests.support import run_world


def world() -> World:
    return _case_world(2, "in_transit")


def refund(order: int, amount: int, ticket: int = CASE_TICKET) -> Json:
    return call("issue_refund", ticket_id=lit(ticket), order_id=lit(order), amount=lit(amount))


def test_trusted_full_refund_is_allowed() -> None:
    result, provider, _ = run_world(plan(refund(7000, 120_000)), world())
    assert result.outcome == "executed" and [v.kind for v in result.verdicts] == ["ALLOW"]
    assert [(e.order_id, e.amount) for e in provider.effects] == [(7000, 120_000)]


def test_trusted_partial_refund_is_allowed() -> None:
    result, provider, _ = run_world(plan(refund(7000, 20_000)), world())
    assert result.outcome == "executed"
    assert provider.effects[0].amount == 20_000


def test_business_invariants_block() -> None:
    cases = {
        "above refundable": plan(refund(7000, 120_001)),
        "zero amount": plan(refund(7000, 0)),
        "ineligible status": plan(refund(7001, 1_000)),
        "other customer's order": plan(refund(7100, 1_000)),
        "missing order": plan(refund(999_999, 1_000)),
        "missing ticket": plan(refund(7000, 1_000, ticket=999_999)),
        "duplicate order": plan(refund(7000, 1_000), refund(7000, 1_000)),
    }
    for name, p in cases.items():
        result, provider, _ = run_world(p, world())
        assert result.outcome == "blocked", name
        assert provider.effects == [], name


def test_one_untrusted_action_holds_up_the_whole_run() -> None:
    """Atomic decision (D-005/D-014): a trusted refund does not execute alone.

    Two distinct eligible orders (7000, 7001), so no business invariant fires."""
    tainted = expr(
        map_(
            ref("t"),
            "tk",
            call("extract_order_ids", "oids", text=ref("tk", "body")),
            expr(map_(ref("oids"), "x", refund(7001, 1_000))),
        )
    )
    p = plan(call("read_ticket", "t", ticket_id=lit(CASE_TICKET)), tainted, refund(7000, 5_000))
    result, provider, _ = run_world(p, _case_world(2, "delivered"))
    assert [v.kind for v in result.verdicts] == ["NEEDS_APPROVAL", "ALLOW"]
    assert result.outcome == "needs_approval" and provider.effects == []
    assert result.approval_request is not None and result.approval_hash is not None


def test_rejected_plan_executes_nothing() -> None:
    result, provider, _ = run_world(plan(call("delete_everything")), world())
    assert result.outcome == "rejected" and provider.effects == []
