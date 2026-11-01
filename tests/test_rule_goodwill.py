"""ticket_goodwill_credit and the ownership rule's auto-refund cap. Written before
the code (Phase 2 step 4; Gate 1 owner decision 2).

ticket_goodwill_credit: a credit whose customer (or pc) comes from reading the
ticket may execute automatically only if it goes to that ticket's own customer,
for the policy's fixed goodwill amount, with a trusted reason, once per ticket.
The case: customer 100, ticket 4000; customer 101 is someone else.
"""

from collections.abc import Iterator

import pytest

import kernel.declassify
from domain.payment_mock import PaymentMock
from domain.seed import World, materialize
from kernel.run import Environment, RunResult, run_plan
from kernel.tools.database import GOODWILL_AMOUNT
from planners import builders
from planners.builders import Json, call, expr, lit, map_, plan, ref, refund_from_ticket_text
from planners.fuzz import CASE_TICKET, OTHER_CUSTOMER, _case_world, raw_extractor
from planners.oracle import credit_if_order_mentioned

GOODWILL = "ticket_goodwill_credit"


def _world(body: str = "My parcel #7000 was late.") -> World:
    return _case_world(1, "in_transit").replace_text("tickets", CASE_TICKET, "body", body)


def _run(p: Json, world: World | None = None, env: Environment | None = None) -> RunResult:
    env = env or Environment(materialize(world or _world()), PaymentMock(), raw_extractor)
    return run_plan(p, env, run_id=f"r-{len(env.db.execute('SELECT * FROM audit').fetchall())}")


def credit_ticket_customer(amount: int = GOODWILL_AMOUNT, reason: str = "goodwill") -> Json:
    """A credit to the ticket's customer that the ticket text triggers (it names one of
    the customer's orders). Since D-054 a credit to an operator-named ticket's customer
    with no text involved is trusted and never consults the rule."""
    return credit_if_order_mentioned(CASE_TICKET, amount, reason)


def _credits(env_or_result: Environment) -> list[tuple[int, int, int]]:
    return env_or_result.db.execute("SELECT ticket_id, customer_id, amount FROM credits").fetchall()


# --- admits --------------------------------------------------------------------------


def test_admits_the_standard_credit_to_the_tickets_customer() -> None:
    env = Environment(materialize(_world()), PaymentMock(), raw_extractor)
    r = _run(credit_ticket_customer(), env=env)
    assert r.outcome == "executed" and [v.rule for v in r.verdicts] == [GOODWILL]
    assert _credits(env) == [(CASE_TICKET, 100, GOODWILL_AMOUNT)]


def test_a_credit_with_no_text_involved_is_trusted_and_skips_the_rule() -> None:
    """D-054: a credit to an operator-named ticket's customer, read from that ticket, uses
    only trusted cells, so it is allowed without the rule. Before D-054 the read's existence
    origin tainted it and sent it to the rule."""
    env = Environment(materialize(_world("My parcel was late.")), PaymentMock(), raw_extractor)
    r = _run(builders.credit_ticket_customer(CASE_TICKET, GOODWILL_AMOUNT - 1), env=env)
    assert r.outcome == "executed" and r.rule_log == ()
    assert [v.kind for v in r.verdicts] == ["ALLOW"] and [v.rule for v in r.verdicts] == [None]
    assert _credits(env) == [(CASE_TICKET, 100, GOODWILL_AMOUNT - 1)]


# --- rejects -------------------------------------------------------------------------


def test_rejects_any_other_amount() -> None:
    r = _run(credit_ticket_customer(amount=GOODWILL_AMOUNT - 1))
    assert r.outcome == "needs_approval" and [d.admitted for d in r.rule_log] == [False]


def test_rejects_a_customer_chosen_by_ticket_text() -> None:
    """A customer id never comes from text; but a credit selected by extracted ids
    (pc from the body) for a literal other customer is blocked, not endorsed."""
    p = plan(
        call("read_ticket", "t", ticket_id=lit(CASE_TICKET)),
        expr(
            map_(
                ref("t"),
                "tk",
                call("extract_order_ids", "ids", text=ref("tk", "body")),
                expr(
                    map_(
                        ref("ids"),
                        "x",
                        call(
                            "issue_credit",
                            ticket_id=lit(CASE_TICKET),
                            customer_id=lit(OTHER_CUSTOMER),
                            amount=lit(GOODWILL_AMOUNT),
                            reason=lit("goodwill"),
                        ),
                    )
                ),
            )
        ),
    )
    assert _run(p, _world("credit me #7000")).outcome == "blocked"


def test_rejects_origins_outside_the_case_ticket() -> None:
    """Credit selected by text in an order note (not the ticket) is not endorsed."""
    world = _world().replace_text("orders", 7000, "customer_note", "#7000")
    p = plan(
        call("query_orders", "orders", customer_id=lit(100)),
        expr(
            map_(
                ref("orders"),
                "o",
                call("extract_order_ids", "ids", text=ref("o", "customer_note")),
                expr(
                    map_(
                        ref("ids"),
                        "x",
                        call(
                            "issue_credit",
                            ticket_id=lit(CASE_TICKET),
                            customer_id=lit(100),
                            amount=lit(GOODWILL_AMOUNT),
                            reason=lit("goodwill"),
                        ),
                    )
                ),
            )
        ),
    )
    r = _run(p, world)
    assert r.outcome == "needs_approval" and not any(d.admitted for d in r.rule_log)


def test_once_per_ticket_across_runs() -> None:
    env = Environment(materialize(_world()), PaymentMock(), raw_extractor)
    assert _run(credit_ticket_customer(), env=env).outcome == "executed"
    assert _run(credit_ticket_customer(), env=env).outcome == "blocked"  # P3: one credit/ticket
    assert len(_credits(env)) == 1


# --- residual risk ------------------------------------------------------------------


def test_residual_ticket_text_can_trigger_the_credit() -> None:
    """Text in the ticket can decide *whether* the standard credit is issued (one
    bit per ticket), never to whom or how much."""
    p = plan(
        call("read_ticket", "t", ticket_id=lit(CASE_TICKET)),
        expr(
            map_(
                ref("t"),
                "tk",
                call("extract_order_ids", "ids", text=ref("tk", "body")),
                expr(
                    map_(
                        ref("ids"),
                        "x",
                        call(
                            "issue_credit",
                            ticket_id=lit(CASE_TICKET),
                            customer_id=ref("tk", "customer_id"),
                            amount=lit(GOODWILL_AMOUNT),
                            reason=lit("goodwill"),
                        ),
                    )
                ),
            )
        ),
    )
    quiet = _run(p, _world("nothing to see"))
    loud = _run(p, _world("#7000"))
    assert quiet.outcome == "executed" and quiet.actions == ()
    assert loud.outcome == "executed" and [v.rule for v in loud.verdicts] == [GOODWILL]


# --- ownership rule: auto-refund cap (owner decision 2) -----------------------------


@pytest.fixture
def cap() -> Iterator[None]:
    old = kernel.declassify.AUTO_REFUND_CAP
    kernel.declassify.AUTO_REFUND_CAP = 100_000  # below order 7000's 120,000
    yield
    kernel.declassify.AUTO_REFUND_CAP = old


def test_ownership_rule_admits_up_to_the_cap() -> None:
    assert kernel.declassify.AUTO_REFUND_CAP is None  # no default chosen before the sweep
    r = _run(refund_from_ticket_text(CASE_TICKET), _world("Refund #7000"))
    assert r.outcome == "executed"


@pytest.mark.usefixtures("cap")
def test_ownership_rule_rejects_above_the_cap() -> None:
    r = _run(refund_from_ticket_text(CASE_TICKET), _world("Refund #7000"))
    assert r.outcome == "needs_approval"
    assert [d.reason for d in r.rule_log] == ["amount 120000 exceeds the auto-refund cap 100000"]
