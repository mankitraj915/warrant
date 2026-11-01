"""Audit log and run identity (DESIGN §7, Phase 2 step 1). Written before the code.

Every run writes exactly one append-only "final" audit row that is enough to
explain the decision: planner-input hash, plan, resolved actions with labels,
verdicts, rule decisions, approval request and hash, and what executed. A run
that reaches execution also writes a "decided" row first, before any effect
(Gate 2 review #5).
"""

import json
import sqlite3
from typing import Any

import pytest

from domain.payment_mock import PaymentMock
from domain.seed import materialize
from kernel.run import Environment, PlannerInput, run_plan, run_task
from planners.builders import refund_from_ticket_text
from planners.fuzz import CASE_TICKET, _case_world, raw_extractor
from planners.oracle import OraclePlanner, refund_in_full


def _env(second_status: str = "in_transit", body: str = "Refund #7000") -> Environment:
    world = _case_world(1, second_status).replace_text("tickets", CASE_TICKET, "body", body)
    return Environment(materialize(world), PaymentMock(), raw_extractor)


def _audit(env: Environment) -> list[dict[str, Any]]:
    rows = env.db.execute("SELECT run_id, record FROM audit ORDER BY id").fetchall()
    return [{"run_id": r, **json.loads(rec)} for r, rec in rows]


def test_each_run_writes_one_explanatory_audit_row() -> None:
    env = _env()
    result = run_plan(refund_from_ticket_text(CASE_TICKET), env, run_id="r-1")
    decided, row = _audit(env)
    assert (decided["phase"], row["phase"]) == ("decided", "final")
    assert decided["outcome"] == "executing" and decided["executed"] == []
    assert decided["rules"] == row["rules"] and decided["actions"] == row["actions"]
    assert row["run_id"] == "r-1" and row["outcome"] == result.outcome == "executed"
    [action] = row["actions"]
    assert action["tool"] == "issue_refund" and action["args"]["order_id"] == 7000
    assert f"tickets[{CASE_TICKET}].body" in action["labels"]["order_id"]
    assert row["verdicts"][0]["rule"] == "ticket_order_ownership"
    assert row["rules"][0]["admitted"] is True
    assert row["executed"][0]["provider_ref"].startswith("pay-")
    assert row["plan"]["version"] == 1


def test_approval_requests_and_rejections_are_audited() -> None:
    env = _env("delivered")  # two eligible orders: the rule does not admit
    needs = run_plan(refund_from_ticket_text(CASE_TICKET), env, run_id="r-approval")
    bad = run_plan({"version": 1, "steps": [{"call": "nope", "args": {}}]}, env, run_id="r-bad")
    rows = {r["run_id"]: r for r in _audit(env)}
    assert rows["r-approval"]["approval_hash"] == needs.approval_hash is not None
    assert rows["r-bad"]["outcome"] == bad.outcome == "rejected"


def test_audit_is_append_only() -> None:
    env = _env()
    run_plan(refund_in_full(CASE_TICKET, 7000), env, run_id="r-1")
    with pytest.raises(sqlite3.DatabaseError):
        env.db.execute("UPDATE audit SET record = '{}'")
    with pytest.raises(sqlite3.DatabaseError):
        env.db.execute("DELETE FROM audit")


def test_run_task_uses_a_fresh_run_id_and_records_the_planner_input() -> None:
    plan = refund_in_full(CASE_TICKET, 7000)
    env_a, env_b = _env(), _env()
    a = run_task("T", "refund 7000", OraclePlanner(plan), env_a)
    b = run_task("T", "refund 7000", OraclePlanner(plan), env_b)
    assert a.run_id != b.run_id and a.run_id != "T"
    [row] = [r for r in _audit(env_a) if r["phase"] == "final"]
    assert row["planner_input_hash"] == a.planner_input_hash is not None
    assert row["task_id"] == "T"


def test_evaluation_can_fix_the_run_id() -> None:
    env = _env()
    r = run_task("T", "x", OraclePlanner(refund_in_full(CASE_TICKET, 7000)), env, run_id="seed-1")
    assert r.run_id == "seed-1"
    assert PlannerInput("x", "").label().trusted


# --- Gate 3 review #7: failures outside the documented paths are audited ------------


class RaisingApprover:
    def review(self, request: dict[str, Any], hash_: str) -> Any:
        raise RuntimeError("approver UI crashed")


def test_an_approver_that_raises_is_audited_and_its_approval_rejected() -> None:
    """The exception still propagates, but the run leaves a final audit row, the
    approval request is marked rejected, and a retry of the run id is refused cleanly
    (it used to fail with an IntegrityError on the approvals table)."""
    env = _env("delivered")  # two eligible orders: the set needs approval
    env.approver = RaisingApprover()
    with pytest.raises(RuntimeError, match="approver UI crashed"):
        run_plan(refund_from_ticket_text(CASE_TICKET), env, run_id="r-x")
    [row] = [r for r in _audit(env) if r["run_id"] == "r-x"]
    assert row["phase"] == "final" and row["outcome"] == "failed"
    assert "RuntimeError" in row["reason"]
    status = env.db.execute("SELECT status FROM approvals WHERE run_id = 'r-x'").fetchall()
    assert status == [("rejected",)]
    retry = run_plan(refund_from_ticket_text(CASE_TICKET), env, run_id="r-x")
    assert retry.outcome == "rejected"
    assert env.provider.effects == []  # type: ignore[attr-defined]


def test_run_task_with_a_leaked_missing_ticket_is_audited_as_halted() -> None:
    """The leaked-context configuration read a missing ticket outside run_plan, so the
    halt escaped with no audit row."""
    env = _env()
    result = run_task(
        "T-x",
        "resolve",
        OraclePlanner(refund_in_full(CASE_TICKET, 7000)),
        env,
        leak_ticket_bodies=(4999,),
        run_id="r-leak",
    )
    assert result.outcome == "halted"
    [row] = [r for r in _audit(env) if r["run_id"] == "r-leak"]
    assert row["outcome"] == "halted" and row["task_id"] == "T-x"


class DeletesPendingRow(PaymentMock):
    def __init__(self, db: sqlite3.Connection) -> None:
        super().__init__()
        self.db = db

    def refund(self, idempotency_key: str, order_id: int, amount: int) -> str:
        self.db.execute("DELETE FROM refunds WHERE idempotency_key = ?", (idempotency_key,))
        self.db.commit()
        return super().refund(idempotency_key, order_id, amount)


def test_a_kernel_failure_during_execution_gets_a_final_audit_row() -> None:
    """RecordLost (D-061) is raised from execution, after the write-ahead row; the run
    must still end with a final row that says it failed."""
    env = _env()
    env.provider = DeletesPendingRow(env.db)
    with pytest.raises(Exception, match="refund"):
        run_plan(refund_from_ticket_text(CASE_TICKET), env, run_id="r-lost")
    phases = [(r["phase"], r["outcome"]) for r in _audit(env) if r["run_id"] == "r-lost"]
    assert phases == [("decided", "executing"), ("final", "failed")]
