"""Regression tests for the Gate 1 independent review (docs/reviews/GATE1_REVIEW.md).

Each test reproduces one reviewer probe and was run against commit 0c25bff,
where it failed, before the fix it guards.
"""

from typing import Any

import pytest

from domain.payment_mock import PaymentMock, ProviderTimeout
from domain.seed import Ticket as TicketRow
from domain.seed import World, materialize
from kernel.declassify import ticket_order_ownership
from kernel.interpreter import ResolvedAction
from kernel.labels import Label, cell_origin
from kernel.policy import components
from kernel.run import OPERATOR, Environment, RunResult, run_plan
from kernel.tools.database import EXISTS, TrustedReader
from kernel.tools.registry import TOOLS
from kernel.values import Scalar
from planners.builders import call, expr, lit, map_, op, plan, ref, refund_from_ticket_text
from planners.fuzz import CASE_CUSTOMER, CASE_TICKET, OTHER_CUSTOMER, _case_world, raw_extractor
from planners.oracle import refund_amount, refund_in_full
from tests.ni_properties import check_ni1, check_ni2, check_ni3, effects
from tests.support import run_world


def _env(world: World, provider: Any = None) -> Environment:
    return Environment(materialize(world), provider or PaymentMock(), raw_extractor)


def _open_ticket(env: Environment, ticket: int, body: str) -> None:
    env.db.execute(
        "INSERT INTO tickets (id, customer_id, subject, body, status)"
        " VALUES (?, ?, 'again', ?, 'open')",
        (ticket, CASE_CUSTOMER, body),
    )
    env.db.commit()


def _paid(provider: PaymentMock, order: int) -> int:
    return sum(e.amount for e in provider.effects if e.order_id == order)


# Finding 1: customers can open tickets, so a ticket row's existence is untrusted.
# Since D-054 an operator-named ticket that does not exist halts the run, so its
# existence can only suppress the whole run (NI-3), never select what executes.
def test_ticket_existence_can_only_suppress_a_run() -> None:
    base = _case_world(1, "in_transit")
    with_ticket = base.extend(tickets=(TicketRow(4001, OTHER_CUSTOMER, "hi", "anything"),))
    p = plan(
        call("read_ticket", "t", ticket_id=lit(4001)),
        expr(
            map_(
                ref("t"),
                "tk",
                call("issue_refund", ticket_id=lit(4000), order_id=lit(7000), amount=lit(120_000)),
            )
        ),
    )
    r1, _, _ = run_world(p, base)
    r2, p2, _ = run_world(p, with_ticket)
    p1 = run_world(p, base)[1]
    assert r1.outcome == "halted" and r1.actions == () and effects(p1) == []
    check_ni1(r1, r2)  # not applicable: r1 halted during resolution
    check_ni3(r1, effects(p1), r2, effects(p2))
    assert r2.outcome == "executed" and effects(p2) != []
    # Within a run the operator-named row exists, so its read carries no existence origin.
    assert cell_origin("tickets", 4001, "@row") not in r2.actions[0].pc.untrusted


@pytest.mark.harness_gap("rule origin set omits @row")
def test_case_ticket_existence_is_endorsable_by_the_rule() -> None:
    """The existence origin of the case ticket itself is inside the rule's origin set.

    Until Gate 3 this ran a text-triggered refund end to end. Since D-054 that run no
    longer carries ``tickets[T].@row`` (a trusted-id read is not labelled with it), so
    the test kept its name but tested something else (Gate 3 review #4); that scenario
    is ``test_rule_ownership.py::test_admits_the_customers_only_eligible_order``. It now
    calls the rule on an action whose order and amount depend on T's existence."""
    reader = TrustedReader(materialize(_case_world(1, "in_transit")))
    row = Label.untrusted_cell("tickets", CASE_TICKET, EXISTS)
    action = ResolvedAction(
        (0,),
        "issue_refund",
        {
            "ticket_id": Scalar(CASE_TICKET, OPERATOR),
            "order_id": Scalar(7000, row),
            "amount": Scalar(120_000, row),
        },
        row,
    )
    decision = ticket_order_ownership(action, components(action), [action], reader)
    assert decision.admitted, decision.reason


# Finding 2: a provider failure must not lose the refund record.
def test_commit_then_failure_is_recorded_and_not_paid_twice() -> None:
    world = _case_world(1, "in_transit").replace_text(
        "tickets", CASE_TICKET, "body", "Refund #7000"
    )
    provider = PaymentMock()
    env = _env(world, provider)
    provider.inject("fail_after_commit")
    r1 = run_plan(refund_from_ticket_text(CASE_TICKET), env, run_id="run-1")
    assert r1.outcome == "executed"
    _open_ticket(env, 4002, "Refund #7000")
    r2 = run_plan(refund_from_ticket_text(4002), env, run_id="run-2")
    assert r2.outcome != "executed"
    assert _paid(provider, 7000) == 120_000


class _TimeoutOnSecondCall(PaymentMock):
    def refund(self, idempotency_key: str, order_id: int, amount: int) -> str:
        if len(self.effects) == 1:
            raise ProviderTimeout(idempotency_key)
        return super().refund(idempotency_key, order_id, amount)


def test_timeout_mid_run_is_reported_as_partial() -> None:
    provider = _TimeoutOnSecondCall()
    env = _env(_case_world(1, "delivered"), provider)
    r = run_plan(refund_in_full(CASE_TICKET, 7000, 7001), env, run_id="run")
    assert r.outcome == "partial" and len(r.executed) == 1
    rows = env.db.execute(
        "SELECT order_id, provider_ref FROM refunds WHERE order_id IN (7000, 7001) ORDER BY id"
    ).fetchall()
    assert rows == [(7000, r.executed[0].provider_ref)]


# Finding 3: the rule must not auto-refund the remainder of an already-refunded order.
def test_rule_does_not_release_the_remainder_of_a_refunded_order() -> None:
    provider = PaymentMock()
    env = _env(_case_world(1, "in_transit"), provider)
    assert run_plan(refund_amount(CASE_TICKET, 7000, 10_000), env, run_id="op").outcome == (
        "executed"
    )
    _open_ticket(env, 4003, "Refund order #7000 please")
    r = run_plan(refund_from_ticket_text(4003), env, run_id="resolve-4003")
    assert r.outcome == "needs_approval"
    assert [d.admitted for d in r.rule_log] == [False]
    assert _paid(provider, 7000) == 10_000


# Finding 4: an extractor with memory must not launder ids into trusted labels.
def test_stateful_extractor_cannot_launder_ids_within_a_run() -> None:
    memory: list[object] = []

    def stateful(text: str) -> list[object]:
        found = raw_extractor(text)
        if found:
            memory[:] = found
            return found
        return list(memory)

    world = _case_world(1, "delivered").replace_text("tickets", CASE_TICKET, "body", "Refund #7001")
    p = plan(
        call("read_ticket", "t", ticket_id=lit(CASE_TICKET)),
        expr(
            map_(
                ref("t"),
                "tk",
                call("extract_order_ids", "junk", text=ref("tk", "body")),
                expr(lit(1)),
            )
        ),
        call("extract_order_ids", "ids", text=lit("no ids here")),
        expr(
            map_(
                ref("ids"),
                "o",
                call("compute_refund_amount", "amt", order_id=ref("o")),
                call(
                    "issue_refund", ticket_id=lit(CASE_TICKET), order_id=ref("o"), amount=ref("amt")
                ),
            )
        ),
    )
    r, provider, _ = run_world(p, world, extractor=stateful)
    assert r.outcome == "needs_approval" and provider.effects == []


# Finding 5: sites identify actions uniquely, and NI-2 does not rely on them.
def test_action_sites_are_unique() -> None:
    def tainted_map(var: str, ids: str, amt: str) -> dict[str, Any]:
        return map_(
            ref(ids),
            var,
            call("compute_refund_amount", amt, order_id=ref(var)),
            call("issue_refund", ticket_id=lit(CASE_TICKET), order_id=ref(var), amount=ref(amt)),
            expr(lit(1)),
        )

    p = plan(
        call("read_ticket", "t", ticket_id=lit(CASE_TICKET)),
        expr(
            map_(
                ref("t"),
                "tk",
                call("extract_order_ids", "oids", text=ref("tk", "body")),
                call("extract_order_ids", "oids2", text=ref("tk", "subject")),
                expr(
                    op(
                        "eq",
                        op("len", tainted_map("x", "oids", "amt")),
                        op("len", tainted_map("y", "oids2", "amt2")),
                    )
                ),
            )
        ),
    )
    world = (
        _case_world(1, "in_transit")
        .replace_text("tickets", CASE_TICKET, "body", "Refund #7000")
        .replace_text("tickets", CASE_TICKET, "subject", "about #7000")
    )
    r, _, _ = run_world(p, world)
    assert len(r.actions) == 2
    assert len({a.site for a in r.actions}) == 2


def test_ni2_catches_an_unendorsed_allow_sharing_a_site() -> None:
    world = _case_world(1, "in_transit").replace_text(
        "tickets", CASE_TICKET, "body", "Refund #7000"
    )
    r, _, _ = run_world(refund_from_ticket_text(CASE_TICKET), world)
    admitted = r.actions[0]
    forged = type(admitted)(admitted.site, admitted.tool, admitted.args, admitted.pc)
    bad = RunResult(
        r.run_id,
        r.outcome,
        r.reason,
        actions=(admitted, forged),
        verdicts=(r.verdicts[0], type(r.verdicts[0])("ALLOW", "bug")),
        rule_log=r.rule_log,
    )
    try:
        check_ni2(bad)
    except AssertionError:
        return
    raise AssertionError("NI-2 accepted an untrusted ALLOW without its own rule decision")


# Finding 7: a second refund on the same order and ticket is not silently dropped.
def test_second_refund_on_same_order_and_ticket_is_blocked_not_dropped() -> None:
    provider = PaymentMock()
    env = _env(_case_world(1, "in_transit"), provider)
    assert run_plan(refund_amount(4000, 7000, 10_000), env, run_id="r1").outcome == "executed"
    r2 = run_plan(refund_amount(4000, 7000, 10_000), env, run_id="r2")
    assert r2.outcome == "blocked"
    assert _paid(provider, 7000) == 10_000


# Finding 8: no tool parameter may shadow the pc component.
def test_no_tool_parameter_is_named_pc() -> None:
    assert all("pc" not in (name for name, _ in spec.params) for spec in TOOLS.values())
