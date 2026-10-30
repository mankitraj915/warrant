"""Decision-trace CLI (Phase 2 step 7). Written before the code.

``evals/trace.py`` renders one run's audit row as a readable explanation: what
was asked, every resolved action with the provenance of each argument, the
verdict and the rule decision behind it, the approval request, and what
executed. It reads only the audit table.
"""

import sqlite3
from contextlib import closing
from pathlib import Path

from domain.payment_mock import PaymentMock
from domain.seed import materialize
from evals.trace import copy_audit, main, render
from kernel.run import Environment, run_plan
from planners.builders import refund_from_ticket_text
from planners.fuzz import CASE_TICKET, _case_world, raw_extractor


def _env(second_status: str) -> Environment:
    world = _case_world(1, second_status).replace_text("tickets", CASE_TICKET, "body", "#7000")
    return Environment(materialize(world), PaymentMock(), raw_extractor)


def test_trace_explains_a_rule_admitted_refund() -> None:
    env = _env("in_transit")
    run_plan(refund_from_ticket_text(CASE_TICKET), env, run_id="r-1")
    text = render(env.db, "r-1")
    assert "run r-1: executed" in text
    assert "issue_refund(amount=120000, order_id=7000, ticket_id=4000)" in text
    [provenance] = [ln for ln in text.splitlines() if ln.strip().startswith("order_id <-")]
    assert f"tickets[{CASE_TICKET}].body" in provenance
    assert "ALLOW by ticket_order_ownership" in text
    assert "rule ticket_order_ownership: admitted" in text
    assert "executed: issue_refund key=refund:7000:4000" in text


def test_trace_shows_the_approval_request() -> None:
    env = _env("delivered")  # two eligible orders: needs approval, denied by default
    run_plan(refund_from_ticket_text(CASE_TICKET), env, run_id="r-2")
    text = render(env.db, "r-2")
    assert "run r-2: needs_approval" in text
    assert "approval requested: hash " in text and "approved: no" in text
    assert "rule ticket_order_ownership: rejected (customer has 2 eligible orders)" in text


def test_unknown_run_and_cli(tmp_path: Path, capsys: object) -> None:
    env = _env("in_transit")
    run_plan(refund_from_ticket_text(CASE_TICKET), env, run_id="r-3")
    db_path = tmp_path / "audit.sqlite"
    copy_audit(env.db, db_path)
    assert main(["r-3", "--db", str(db_path)]) == 0
    assert main(["nope", "--db", str(db_path)]) == 1
    with closing(sqlite3.connect(db_path)) as db:
        assert "no audit record" in render(db, "nope")
