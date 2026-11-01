"""Single-writer concurrency model (Gate 3 review #1, issue #1, DESIGN §10).

One run at a time per database. A run takes the database's run lock before
``recover()`` and holds it until its final audit row is written. A run that
finds the lock held is refused with ``RunLocked`` and touches nothing. Without
the lock, a second run's ``recover()`` deleted an in-flight refund's pending
row; the provider then committed, the record was lost, and the ownership rule
admitted a second automatic refund of the same order.
"""

import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

from domain.payment_mock import PaymentMock
from domain.seed import materialize
from kernel.run import Environment, run_plan
from planners.builders import plan, refund_from_ticket_text
from planners.fuzz import CASE_CUSTOMER, CASE_TICKET, _case_world, raw_extractor


class ConcurrentRunDuringRefund(PaymentMock):
    """While the first refund is in flight, another run starts on the same database
    (the interleaving two processes sharing it would produce)."""

    def __init__(self) -> None:
        super().__init__()
        self.env: Environment | None = None
        self.concurrent: BaseException | None = None
        self.fired = False

    def refund(self, idempotency_key: str, order_id: int, amount: int) -> str:
        if not self.fired and self.env is not None:
            self.fired = True
            other = Environment(self.env.db, self, raw_extractor)
            try:
                run_plan(plan({"expr": {"lit": 1}}), other, run_id="concurrent")
            except Exception as exc:  # refused, as it should be
                self.concurrent = exc
        return super().refund(idempotency_key, order_id, amount)


def _refund_world() -> Environment:
    world = _case_world(1, "in_transit").replace_text(
        "tickets", CASE_TICKET, "body", "Refund #7000"
    )
    return Environment(materialize(world), PaymentMock(), raw_extractor)


def test_concurrent_run_cannot_lose_an_in_flight_refund_record() -> None:
    """The reviewer's probe: run-1's record survives and the order is paid back once."""
    env = _refund_world()
    provider = ConcurrentRunDuringRefund()
    env.provider = provider
    provider.env = env
    r1 = run_plan(refund_from_ticket_text(CASE_TICKET), env, run_id="run-1")
    assert r1.outcome == "executed"
    assert type(provider.concurrent).__name__ == "RunLocked"
    rows = env.db.execute(
        "SELECT idempotency_key, provider_ref FROM refunds WHERE order_id = 7000"
    ).fetchall()
    assert rows == [("refund:7000:4000", "pay-1")]
    env.db.execute(
        "INSERT INTO tickets (id, customer_id, subject, body, status)"
        " VALUES (4002, ?, 'again', 'Refund #7000', 'open')",
        (CASE_CUSTOMER,),
    )
    env.db.commit()
    r2 = run_plan(refund_from_ticket_text(4002), env, run_id="run-2")
    assert r2.outcome != "executed"
    paid = sum(e.amount for e in provider.effects if e.order_id == 7000)
    assert paid == 120_000  # paid once, not twice


def test_refused_run_touches_nothing() -> None:
    """A refused run writes no audit row, so its run id stays usable."""
    from kernel.runlock import RunLocked, run_lock

    env = _refund_world()
    with run_lock(env.db), pytest.raises(RunLocked):
        run_plan(refund_from_ticket_text(CASE_TICKET), env, run_id="r")
    assert env.db.execute("SELECT count(*) FROM audit").fetchone() == (0,)
    assert run_plan(refund_from_ticket_text(CASE_TICKET), env, run_id="r").outcome == "executed"


HOLDER = """
import sqlite3, sys
from kernel.runlock import run_lock
with run_lock(sqlite3.connect(sys.argv[1])):
    print("held", flush=True)
    sys.stdin.read()
"""


def test_run_lock_excludes_another_process(tmp_path: Path) -> None:
    """Across processes: a run on a file database is refused while another process
    holds its lock, and proceeds once that process has exited."""
    from kernel.runlock import RunLocked

    path = tmp_path / "shared.sqlite"
    world = _case_world(1, "in_transit").replace_text(
        "tickets", CASE_TICKET, "body", "Refund #7000"
    )
    materialize(world, path).close()
    holder = subprocess.Popen(
        [sys.executable, "-c", HOLDER, str(path)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        text=True,
        cwd=Path(__file__).resolve().parent.parent,
    )
    try:
        assert holder.stdout is not None and holder.stdout.readline().strip() == "held"
        env = Environment(sqlite3.connect(path), PaymentMock(), raw_extractor)
        with pytest.raises(RunLocked):
            run_plan(refund_from_ticket_text(CASE_TICKET), env, run_id="r")
    finally:
        assert holder.stdin is not None
        holder.stdin.close()
        holder.wait(timeout=30)
    result = run_plan(refund_from_ticket_text(CASE_TICKET), env, run_id="r")
    assert result.outcome == "executed"


class DeletesPendingRow(PaymentMock):
    """Something outside the kernel deletes the pending row while the provider call is
    in flight; the provider then commits."""

    def __init__(self) -> None:
        super().__init__()
        self.db: sqlite3.Connection | None = None

    def refund(self, idempotency_key: str, order_id: int, amount: int) -> str:
        assert self.db is not None
        self.db.execute("DELETE FROM refunds WHERE idempotency_key = ?", (idempotency_key,))
        self.db.commit()
        return super().refund(idempotency_key, order_id, amount)


def test_lost_record_fails_loudly_and_is_restored() -> None:
    """If recording the provider's reference matches no row, the kernel restores the
    record (money moved) and raises instead of reporting a clean execution."""
    env = _refund_world()
    provider = DeletesPendingRow()
    provider.db = env.db
    env.provider = provider
    with pytest.raises(Exception) as exc:
        run_plan(refund_from_ticket_text(CASE_TICKET), env, run_id="r")
    assert type(exc.value).__name__ == "RecordLost"
    rows = env.db.execute(
        "SELECT idempotency_key, provider_ref FROM refunds WHERE order_id = 7000"
    ).fetchall()
    assert rows == [("refund:7000:4000", "pay-1")]
