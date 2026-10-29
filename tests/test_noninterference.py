"""The headline test: non-interference under random and adversarial plans (SPEC §5).

For a plan P and two worlds that agree on every trusted cell and differ only in
attacker-controlled text, run P in both with a denying approver (Phase 1 has no
approval-execution path) and check NI-1..NI-4. Written before the interpreter.

Statistics (``--hypothesis-show-statistics``) report how often a rule was
consulted, how often projections were equal, and how often a run was suppressed,
so a vacuous pass is visible.

The multi-run property (DESIGN §9.4) runs two plans in sequence on one evolving
environment: a provider failure may be injected into the first run, and between
runs the attacker rewrites the case ticket and may open a new ticket. NI-2 and
NI-4 (including the cross-run postconditions) are checked on both runs, and no
order may ever be refunded more than was paid. Added after the Gate 1 review.
"""

import sqlite3
from typing import Any

from hypothesis import event, given
from hypothesis import strategies as st

from domain.payment_mock import PaymentMock
from domain.seed import Ticket, World, materialize
from kernel.run import Environment, run_plan
from planners.builders import Json, refund_from_ticket_text
from planners.fuzz import (
    CASE_CUSTOMER,
    CASE_TICKET,
    mutated,
    payloads,
    plans,
    raw_extractor,
    worlds,
)
from planners.oracle import refund_amount
from tests.ni_properties import (
    NIViolation,
    check_ni1,
    check_ni2,
    check_ni3,
    check_ni4,
    effects,
    projection,
)
from tests.support import run_world

NEW_TICKET = 4002


def ni_property(data: Any) -> None:
    world = data.draw(worlds(), label="world")
    plan: Json = data.draw(plans(world), label="plan")
    w1 = data.draw(mutated(world), label="E1")
    w2 = data.draw(mutated(world), label="E2")
    r1, p1, pre1 = run_world(plan, w1)
    r2, p2, pre2 = run_world(plan, w2)
    x1, x2 = effects(p1), effects(p2)

    consulted = bool(r1.rule_log or r2.rule_log)
    equal = projection(r1) == projection(r2)
    event(f"outcomes {r1.outcome}/{r2.outcome}")
    event(f"rule consulted={consulted} projection_equal={equal}")
    event(f"suppressed={bool(x1) != bool(x2)}")
    event(f"rule admitted={any(d.admitted for d in r1.rule_log + r2.rule_log)}")

    check_ni1(r1, r2)
    check_ni2(r1)
    check_ni2(r2)
    check_ni3(r1, x1, r2, x2)
    check_ni4(r1, pre1)
    check_ni4(r2, pre2)


@given(st.data())
def test_noninterference(data: Any) -> None:
    ni_property(data)


def _snapshot(db: sqlite3.Connection) -> sqlite3.Connection:
    copy = sqlite3.connect(":memory:")
    db.backup(copy)
    return copy


def _run_plan(data: Any, world: World, tickets: list[int], first: bool) -> Json:
    """A random plan, or one of the paths cross-run state matters for, weighted
    towards them: trusted partial or full refunds (mostly in the first run) and
    the canonical data-dependent plan (mostly in the second)."""
    kinds = ["trusted"] * 3 + ["canonical"] * 2 if first else ["canonical"] * 3 + ["trusted"]
    kind = data.draw(st.sampled_from(["random", *kinds]), label="plan kind")
    ticket = data.draw(st.sampled_from(tickets), label="plan ticket")
    event(f"run {1 if first else 2} plan={kind} ticket={ticket}")
    if kind == "random":
        plan: Json = data.draw(plans(world), label="plan")
        return plan
    if kind == "canonical":
        return refund_from_ticket_text(ticket)
    order = data.draw(st.sampled_from([7000, 7001]), label="order")
    amount = data.draw(st.sampled_from([10_000, 10_000, 120_000, 450_000]), label="amount")
    return refund_amount(ticket, order, amount)


# Payload text for the attacker's edits, biased towards naming the case's orders.
def _ticket_text(world: World) -> st.SearchStrategy[Any]:
    named = st.sampled_from(["Please refund order #7000."] * 2 + ["Please refund order #7001."])
    return st.one_of(named, payloads(world))


def multirun_property(data: Any) -> None:
    world = data.draw(worlds(), label="world")
    w = data.draw(mutated(world), label="E")
    provider = PaymentMock()
    env = Environment(materialize(w), provider, raw_extractor)
    paid = dict(env.db.execute("SELECT order_id, SUM(amount) FROM payments GROUP BY order_id"))

    failure = data.draw(st.sampled_from([None, "fail_after_commit", "timeout"]))
    if failure is not None:
        provider.inject(failure)
    pre1 = _snapshot(env.db)
    plan1 = _run_plan(data, world, [CASE_TICKET], first=True)
    r1 = run_plan(plan1, env, run_id="run-1")
    check_ni2(r1)
    check_ni4(r1, pre1)

    case_body = data.draw(_ticket_text(world), label="case ticket edit")
    env.db.execute("UPDATE tickets SET body = ? WHERE id = ?", (case_body, CASE_TICKET))
    later, tickets = world, [CASE_TICKET]
    if data.draw(st.sampled_from([True, True, False]), label="open a new ticket"):
        tickets = [NEW_TICKET, NEW_TICKET, NEW_TICKET, CASE_TICKET]
        body = data.draw(_ticket_text(world), label="new ticket body")
        env.db.execute(
            "INSERT INTO tickets (id, customer_id, subject, body, status)"
            " VALUES (?, ?, 'again', ?, 'open')",
            (NEW_TICKET, CASE_CUSTOMER, body),
        )
        later = world.extend(tickets=(Ticket(NEW_TICKET, CASE_CUSTOMER, "again", body),))
    env.db.commit()
    pre2 = _snapshot(env.db)
    plan2 = _run_plan(data, later, tickets, first=False)
    r2 = run_plan(plan2, env, run_id="run-2")
    event(f"failure={failure}")
    event(f"runs {r1.outcome}/{r2.outcome}")
    event(f"run 2 rule admitted={any(d.admitted for d in r2.rule_log)}")
    check_ni2(r2)
    check_ni4(r2, pre2)

    refunded: dict[int, int] = {}
    for e in provider.effects:
        refunded[e.order_id] = refunded.get(e.order_id, 0) + e.amount
    for order, total in refunded.items():
        if total > paid.get(order, 0):
            raise NIViolation(f"order {order} refunded {total}, paid {paid.get(order, 0)}")


@given(st.data())
def test_noninterference_multirun(data: Any) -> None:
    multirun_property(data)
