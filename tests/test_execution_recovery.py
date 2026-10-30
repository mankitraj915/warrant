"""Execution layer (SPEC §4.7, DESIGN §10): crash injection and recovery.

A crash is simulated with an exception the kernel does not catch
(``SimulatedCrash`` derives from ``BaseException``), raised either just after
the provider committed the refund or just before the provider was called. The
"restarted" kernel is a new ``run_plan`` on the same database and provider.
Written before recovery was implemented.
"""

from typing import Any

import pytest

from domain.payment_mock import PaymentMock
from domain.seed import materialize
from kernel.run import Environment, run_plan
from kernel.tools.database import TrustedReader
from planners.builders import call, credit_ticket_customer, lit, plan
from planners.fuzz import CASE_TICKET, _case_world, raw_extractor
from planners.oracle import refund_in_full


class SimulatedCrash(BaseException):
    """The process died; nothing after this point ran."""


class CrashingProvider(PaymentMock):
    """Crashes once, either after committing the refund or before calling it."""

    def __init__(self, when: str) -> None:
        super().__init__()
        self.when: str | None = when

    def refund(self, idempotency_key: str, order_id: int, amount: int) -> str:
        when, self.when = self.when, None
        if when == "before_call":
            raise SimulatedCrash
        ref = super().refund(idempotency_key, order_id, amount)
        if when == "after_commit":
            raise SimulatedCrash
        return ref


def _env(provider: Any) -> Environment:
    return Environment(materialize(_case_world(1, "in_transit")), provider, raw_extractor)


def _rows(env: Environment) -> list[tuple[Any, ...]]:
    return env.db.execute(
        "SELECT order_id, ticket_id, amount, provider_ref FROM refunds WHERE order_id = 7000"
    ).fetchall()


@pytest.mark.parametrize("when", ["after_commit", "before_call"])
def test_crash_then_restart_refunds_exactly_once(when: str) -> None:
    provider = CrashingProvider(when)
    env = _env(provider)
    plan = refund_in_full(CASE_TICKET, 7000)
    with pytest.raises(SimulatedCrash):
        run_plan(plan, env, run_id="before-crash")
    assert [r[3] for r in _rows(env)] == ["pending"]  # the record precedes the money

    restarted = run_plan(plan, env, run_id="after-restart")
    paid = [(e.order_id, e.amount) for e in provider.effects]
    assert paid == [(7000, 120_000)]
    rows = _rows(env)
    assert len(rows) == 1 and rows[0][3] == provider.effects[0].provider_ref
    # after a commit the retry is recognised as already done; otherwise it executes now
    assert restarted.outcome == ("blocked" if when == "after_commit" else "executed")


def test_pending_row_with_unknown_status_stays_and_blocks() -> None:
    class Unreachable(PaymentMock):
        def status(self, idempotency_key: str) -> str | None:
            raise TimeoutError

    provider = CrashingProvider("after_commit")
    env = _env(provider)
    plan = refund_in_full(CASE_TICKET, 7000)
    with pytest.raises(SimulatedCrash):
        run_plan(plan, env, run_id="before-crash")
    env.provider = Unreachable()
    again = run_plan(plan, env, run_id="provider-down")
    assert again.outcome == "blocked"
    assert [r[3] for r in _rows(env)] == ["pending"]


# --- local effects whose precondition changed after the last re-check ----------------


def _race(monkeypatch: pytest.MonkeyPatch, method: str) -> None:
    """Another writer acts between the re-check and the write: the re-check no
    longer sees the conflicting row."""
    monkeypatch.setattr(TrustedReader, method, lambda self, *a: False)


def test_duplicate_credit_after_recheck_aborts_cleanly(monkeypatch: pytest.MonkeyPatch) -> None:
    env = Environment(materialize(_case_world(1, "delivered")), PaymentMock(), raw_extractor)
    assert run_plan(credit_ticket_customer(CASE_TICKET), env, run_id="r-1").outcome == "executed"
    _race(monkeypatch, "ticket_has_credit")
    r = run_plan(credit_ticket_customer(CASE_TICKET), env, run_id="r-2")
    assert r.outcome == "aborted"
    assert env.db.execute("SELECT COUNT(*) FROM credits").fetchone() == (1,)
    assert env.db.execute("SELECT COUNT(*) FROM audit WHERE run_id = 'r-2'").fetchone() == (1,)


def test_closing_a_closed_ticket_after_recheck_aborts(monkeypatch: pytest.MonkeyPatch) -> None:
    env = Environment(materialize(_case_world(1, "delivered")), PaymentMock(), raw_extractor)
    close = plan(call("close_ticket", ticket_id=lit(CASE_TICKET), resolution=lit("no_action")))
    assert run_plan(close, env, run_id="r-1").outcome == "executed"
    monkeypatch.setattr(TrustedReader, "ticket_status", lambda self, *a: "open")
    r = run_plan(close, env, run_id="r-2")
    assert r.outcome == "aborted" and r.executed == ()
