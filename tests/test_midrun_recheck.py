"""The re-check between effects stops a run whose later action became stricter
(DESIGN §10, Gate 2 review #4, Gate 3 review #3).

The fuzz harness cannot produce this: a set's own effects never make a later
action stricter, and the harness has no concurrent writer. Before these tests a
mutant whose re-check never stops passed the whole suite and paid twice. Both are
``harness_gap`` tests (D-063): the kernel was already correct, so their evidence is
that they fail under the "re-check never stops" mutant.
"""

import os
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path

import pytest

from domain.payment_mock import PaymentMock
from domain.seed import Ticket, materialize
from kernel.run import Environment, run_plan
from planners.builders import refund_from_ticket_text
from planners.fuzz import CASE_CUSTOMER, CASE_TICKET, OTHER_CUSTOMER, _case_world, raw_extractor
from planners.oracle import refund_amount, steps_of
from tests.deterministic_mutants import DETERMINISTIC_MUTANTS
from tests.test_approval_binding import ApproveAll

ROOT = Path(__file__).resolve().parent.parent
PYTEST = [sys.executable, "-m", "pytest", "-p", "no:cacheprovider"]


class DuringFirstRefund(PaymentMock):
    """Applies ``change`` to the database once, while the first refund is at the provider
    (after it committed there)."""

    def __init__(self, change: Callable[[], None]) -> None:
        super().__init__()
        self.change, self.fired = change, False

    def refund(self, idempotency_key: str, order_id: int, amount: int) -> str:
        ref = super().refund(idempotency_key, order_id, amount)
        if not self.fired:
            self.fired = True
            self.change()
        return ref


@pytest.mark.harness_gap("re-check never stops")
def test_new_order_mid_run_stops_a_rule_admitted_refund() -> None:
    """In scope (DESIGN §10: other parties may add orders): the ownership rule admitted
    the second refund because 7000 was the customer's unique eligible order. Another
    party adds a paid order while the first refund is at the provider, so 7000 is no
    longer unique, the refund needs approval, and the run stops as partial."""
    world = _case_world(1, "in_transit").replace_text(
        "tickets", CASE_TICKET, "body", "Refund #7000"
    )
    db = materialize(world.extend(tickets=(Ticket(4003, OTHER_CUSTOMER, "Refund", "please"),)))

    def new_order() -> None:
        db.execute(
            "INSERT INTO orders VALUES (7002, ?, 80000, 'delivered', ?, '')",
            (CASE_CUSTOMER, world.today - 1),
        )
        db.execute("INSERT INTO payments (order_id, amount) VALUES (7002, 80000)")
        db.commit()

    provider = DuringFirstRefund(new_order)
    env = Environment(db, provider, raw_extractor)
    both = steps_of(refund_amount(4003, 7100, 300_000), refund_from_ticket_text(CASE_TICKET))
    result = run_plan(both, env, run_id="new-order")
    assert [v.kind for v in result.verdicts] == ["ALLOW", "ALLOW"]
    moved = [(e.order_id, e.amount) for e in provider.effects]
    assert result.outcome == "partial" and moved == [(7100, 300_000)]


@pytest.mark.harness_gap("re-check never stops")
def test_order_refunded_elsewhere_mid_run_is_not_paid_again() -> None:
    """The reviewer's probe: an approved two-refund set. While 7000 is at the provider,
    7001 is refunded in full by a writer outside the kernel (out of scope since D-061,
    but the check must still hold). The approval was given against state that no
    longer holds, so 7001's refund is now BLOCKed and the run stops as partial."""
    world = _case_world(1, "delivered").replace_text(
        "tickets", CASE_TICKET, "body", "Refund #7000 #7001"
    )
    db = materialize(world)

    def refunded_elsewhere() -> None:
        db.execute(
            "INSERT INTO refunds (order_id, ticket_id, amount, idempotency_key, provider_ref)"
            " VALUES (7001, 4000, 450000, 'elsewhere', 'pay-x')"
        )
        db.commit()

    provider = DuringFirstRefund(refunded_elsewhere)
    env = Environment(db, provider, raw_extractor, approver=ApproveAll())
    result = run_plan(refund_from_ticket_text(CASE_TICKET), env, run_id="mid")
    moved = [(e.order_id, e.amount) for e in provider.effects]
    assert result.outcome == "partial" and moved == [(7000, 120_000)]


@pytest.mark.parametrize("name", sorted(DETERMINISTIC_MUTANTS))
def test_harness_catches_deterministic_mutant(name: str) -> None:
    """Every deterministic mutant has at least one marked test, and every test marked
    with it fails under it (run in a fresh process, as the base-commit job does)."""
    out = subprocess.run(
        [*PYTEST, "-rA", "--tb=no", "-m", "harness_gap", "tests/"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        env={**os.environ, "WARRANT_MUTANT": name},
    ).stdout
    words = [line.split(" ", 1)[0] for line in out.splitlines()]
    assert words.count("FAILED") >= 1, out
    assert "PASSED" not in words and "ERROR" not in words, out
