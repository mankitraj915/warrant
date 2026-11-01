"""Regression tests for the Gate 2 independent review (docs/reviews/GATE2_REVIEW.md).

Each test reproduces a reviewer probe and fails on the code the reviewer saw
(commit fc55a2c). Findings 1-2: extraction labels; 4: execution re-check;
5: write-ahead audit; 6: per-customer goodwill bound; 7: durable one plan per
task id.
"""

import json
from collections.abc import Callable
from typing import Any

import pytest

from domain.payment_mock import PaymentMock
from domain.seed import Ticket, World, materialize
from kernel.approval import Approval
from kernel.run import Environment, RunResult, run_plan, run_task
from planners.builders import (
    Json,
    call,
    credit_ticket_customer,
    expr,
    filter_,
    lit,
    map_,
    op,
    plan,
    ref,
    refund_from_ticket_text,
)
from planners.fuzz import CASE_CUSTOMER, CASE_TICKET, _case_world, raw_extractor
from planners.oracle import (
    OraclePlanner,
    credit,
    credit_if_order_mentioned,
    refund_amount,
    steps_of,
)
from tests.ni_properties import check_ni1, check_ni3, effects

# --- findings 1 and 2: the cumulative extraction label --------------------------------


def _select_by_note(*body: Json) -> list[Json]:
    """Map over the case customer's orders whose (untrusted) note says "go"."""
    return [
        call("query_orders", "orders", customer_id=lit(CASE_CUSTOMER)),
        expr(filter_(ref("orders"), "o", op("eq", ref("o", "customer_note"), lit("go"))), "sel"),
        expr(map_(ref("sel"), "s", *body)),
    ]


def _run(p: Json, world: World, extractor: Callable[[str], list[object]]) -> tuple[RunResult, Any]:
    env = Environment(materialize(world), PaymentMock(), extractor)
    r = run_plan(p, env, run_id="probe")
    assert isinstance(env.provider, PaymentMock)
    return r, effects(env.provider, env.db)


def test_literal_extraction_after_a_tainted_map_has_a_syntax_determined_label() -> None:
    """Probe A (finding 2): with a stateless extractor, whether a later extraction
    of a literal was trusted depended on whether a note-selected map ran."""
    p = plan(
        *_select_by_note(call("extract_order_ids", "junk", text=ref("s", "customer_note"))),
        call("extract_order_ids", "ids", text=lit("please refund #7000")),
        expr(
            map_(
                ref("ids"),
                "i",
                call("issue_refund", ticket_id=lit(CASE_TICKET), order_id=ref("i"), amount=lit(1)),
            )
        ),
    )
    base = _case_world(1, "in_transit")
    r1, _ = _run(p, base, raw_extractor)
    r2, _ = _run(p, base.replace_text("orders", 7001, "customer_note", "go"), raw_extractor)
    check_ni1(r1, r2)


def _counting_extractor() -> Callable[[str], list[object]]:
    calls = [0]

    def extract(text: str) -> list[object]:
        calls[0] += 1
        if text == "pick":
            return [7000] if calls[0] == 1 else [7001]
        return []

    return extract


def test_extractor_call_count_under_a_tainted_pc_cannot_choose_a_trusted_refund() -> None:
    """Probe B (finding 1): an extractor that counts its calls returned a "trusted"
    id chosen by how many extractions ran under a note-tainted pc."""
    p = plan(
        *_select_by_note(call("extract_order_ids", "junk", text=lit("noop"))),
        call("extract_order_ids", "ids", text=lit("pick")),
        expr(
            map_(
                ref("ids"),
                "i",
                call("compute_refund_amount", "amt", order_id=ref("i")),
                call(
                    "issue_refund",
                    ticket_id=lit(CASE_TICKET),
                    order_id=ref("i"),
                    amount=ref("amt"),
                ),
            )
        ),
    )
    both = _case_world(1, "delivered")
    r1, x1 = _run(p, both, _counting_extractor())
    r2, x2 = _run(
        p, both.replace_text("orders", 7000, "customer_note", "go"), _counting_extractor()
    )
    check_ni1(r1, r2)
    check_ni3(r1, x1, r2, x2)
    assert all(v.kind != "ALLOW" for v in r1.verdicts + r2.verdicts)


# --- finding 4: re-check before the first effect, monotone during execution ---------


class _ApproveAll:
    def __init__(self, hook: Callable[[], None] | None = None) -> None:
        self.hook = hook

    def review(self, request: dict[str, Any], hash_: str) -> Approval | None:
        if self.hook is not None:
            self.hook()
        return Approval(request["run_id"], hash_)


def _paid(env: Environment) -> list[tuple[int, int]]:
    assert isinstance(env.provider, PaymentMock)
    return [(e.order_id, e.amount) for e in env.provider.effects]


def test_an_approved_set_is_not_cut_short_by_its_own_effects() -> None:
    """Probe C: the first (trusted) refund made 7001 the unique eligible order, so
    the second action's re-check moved NEEDS_APPROVAL -> ALLOW and the approved
    set stopped as partial."""
    world = _case_world(1, "delivered").extend(tickets=(Ticket(4002, CASE_CUSTOMER, "s", "b"),))
    world = world.replace_text("tickets", CASE_TICKET, "body", "Refund #7001")
    p = plan(
        call("issue_refund", ticket_id=lit(4002), order_id=lit(7000), amount=lit(120_000)),
        *refund_from_ticket_text(CASE_TICKET)["steps"],
    )
    env = Environment(materialize(world), PaymentMock(), raw_extractor, approver=_ApproveAll())
    r = run_plan(p, env, run_id="c")
    assert r.outcome == "executed"
    assert _paid(env) == [(7000, 120_000), (7001, 450_000)]


def test_a_change_to_a_later_action_while_deciding_aborts_before_any_effect() -> None:
    """Probe D: another writer refunded action 2's order while the human decided;
    action 1 still executed. The pre-pass must abort with nothing executed."""
    world = _case_world(1, "delivered").replace_text(
        "tickets", CASE_TICKET, "body", "Refund #7000 #7001"
    )
    holder: list[Environment] = []

    def external_refund() -> None:
        holder[0].db.execute(
            "INSERT INTO refunds (order_id, ticket_id, amount, idempotency_key, provider_ref)"
            " VALUES (7001, 4000, 1, 'elsewhere', 'pay-x')"
        )
        holder[0].db.commit()

    env = Environment(
        materialize(world), PaymentMock(), raw_extractor, approver=_ApproveAll(external_refund)
    )
    holder.append(env)
    r = run_plan(refund_from_ticket_text(CASE_TICKET), env, run_id="d")
    assert r.outcome == "aborted" and _paid(env) == []


# --- finding 5: the decision is logged before any effect -----------------------------


class _Crash(BaseException):
    pass


class _CrashAfterCommit(PaymentMock):
    armed = True

    def refund(self, idempotency_key: str, order_id: int, amount: int) -> str:
        ref_ = super().refund(idempotency_key, order_id, amount)
        if self.armed:
            self.armed = False
            raise _Crash
        return ref_


def test_a_rule_admitted_refund_is_logged_before_the_provider_is_called() -> None:
    """Probe E: a crash after the provider committed left no audit row recording
    the admitting rule decision."""
    env = Environment(materialize(_case_world(1, "in_transit")), _CrashAfterCommit(), raw_extractor)
    with pytest.raises(_Crash):
        run_plan(refund_from_ticket_text(CASE_TICKET), env, run_id="e-1")
    assert _paid(env) == [(7000, 120_000)]
    rows = [json.loads(r) for (r,) in env.db.execute("SELECT record FROM audit WHERE run_id='e-1'")]
    assert any(
        d["admitted"] and d["rule"] == "ticket_order_ownership" for x in rows for d in x["rules"]
    )
    # The restarted kernel's recovery is audited too, and the crashed run id stays used.
    again = run_plan(refund_from_ticket_text(CASE_TICKET), env, run_id="e-1")
    assert again.outcome == "rejected"
    recovered = env.db.execute("SELECT COUNT(*) FROM audit WHERE run_id = 'recover'").fetchone()
    assert recovered == (1,)


# --- finding 6: the goodwill rule is bounded per customer ----------------------------


def test_goodwill_credits_are_bounded_per_customer_not_only_per_ticket() -> None:
    """Probe F: one customer opening four tickets got four automatic credits. Each
    credit is triggered by its ticket's text (since D-054 a credit to an operator-named
    ticket's customer with no text involved is trusted and needs no rule)."""
    world = _case_world(1, "in_transit").extend(
        tickets=tuple(Ticket(t, CASE_CUSTOMER, "hi", "late #7000") for t in (4002, 4003, 4004))
    )
    world = world.replace_text("tickets", CASE_TICKET, "body", "late #7000")
    env = Environment(materialize(world), PaymentMock(), raw_extractor)
    outcomes = [
        run_plan(credit_if_order_mentioned(t, 10_000, "goodwill"), env, run_id=f"f-{t}").outcome
        for t in (CASE_TICKET, 4002, 4003, 4004)
    ]
    assert outcomes == ["executed", "needs_approval", "needs_approval", "needs_approval"]
    count = env.db.execute("SELECT COUNT(*) FROM credits WHERE customer_id = ?", (CASE_CUSTOMER,))
    assert count.fetchone() == (1,)


def test_probe_f_original_form_plain_read_credits_are_bounded_per_customer() -> None:
    """Probe F as first written (Gate 3 review #2): plain ticket reads, no ticket text.
    Since D-054 these credits are fully trusted and skip the goodwill rule, so the bound
    must live in the credit policy itself; without it, four credits executed."""
    world = _case_world(1, "in_transit").extend(
        tickets=tuple(Ticket(t, CASE_CUSTOMER, "hi", "late again") for t in (4002, 4003, 4004))
    )
    env = Environment(materialize(world), PaymentMock(), raw_extractor)
    outcomes = [
        run_plan(credit_ticket_customer(t), env, run_id=f"f-{t}").outcome
        for t in (CASE_TICKET, 4002, 4003, 4004)
    ]
    assert outcomes == ["executed", "needs_approval", "needs_approval", "needs_approval"]
    count = env.db.execute("SELECT COUNT(*) FROM credits WHERE customer_id = ?", (CASE_CUSTOMER,))
    assert count.fetchone() == (1,)


def test_two_trusted_credits_to_one_customer_in_one_set_need_approval() -> None:
    """The per-customer bound within one action set, for operator-stated credits."""
    world = _case_world(1, "in_transit").extend(
        tickets=(Ticket(4002, CASE_CUSTOMER, "hi", "late again"),)
    )
    env = Environment(materialize(world), PaymentMock(), raw_extractor)
    both = steps_of(
        credit(CASE_TICKET, CASE_CUSTOMER, 10_000, "goodwill"),
        credit(4002, CASE_CUSTOMER, 10_000, "goodwill"),
    )
    result = run_plan(both, env, run_id="two")
    assert [v.kind for v in result.verdicts] == ["NEEDS_APPROVAL", "NEEDS_APPROVAL"]
    assert result.outcome == "needs_approval"


# --- finding 7: one plan per task id survives a new Environment ----------------------


def test_one_plan_per_task_id_is_durable() -> None:
    """Probe G: a second Environment over the same database accepted a new plan
    for a task id that had already run."""
    db = materialize(_case_world(1, "in_transit"))
    provider = PaymentMock()
    first = run_task(
        "T-1",
        "refund",
        OraclePlanner(refund_amount(CASE_TICKET, 7000, 10)),
        Environment(db, provider, raw_extractor),
    )
    second = run_task(
        "T-1",
        "refund",
        OraclePlanner(refund_amount(CASE_TICKET, 7000, 20)),
        Environment(db, provider, raw_extractor),
    )
    assert first.outcome == "executed"
    assert second.outcome == "rejected" and "task" in second.reason
    assert [e.amount for e in provider.effects] == [10]
