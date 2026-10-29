"""Audit log and run identity (DESIGN §7, Phase 2 step 1). Written before the code.

Every run writes exactly one append-only audit row that is enough to explain
the decision: planner-input hash, plan, resolved actions with labels, verdicts,
rule decisions, approval request and hash, and what executed.
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
    [row] = _audit(env)
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
    [row] = _audit(env_a)
    assert row["planner_input_hash"] == a.planner_input_hash is not None
    assert row["task_id"] == "T"


def test_evaluation_can_fix_the_run_id() -> None:
    env = _env()
    r = run_task("T", "x", OraclePlanner(refund_in_full(CASE_TICKET, 7000)), env, run_id="seed-1")
    assert r.run_id == "seed-1"
    assert PlannerInput("x", "").label().trusted
