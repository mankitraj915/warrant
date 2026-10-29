"""Phase 2 tools (SPEC Phase 2, DECISIONS "Phase 2 plan" step 3). Written first.

- ``incident_orders``: staff-recorded incidents are trusted authority.
- ``close_ticket`` and ``issue_credit``: consequential, with business BLOCKs.
- ``order_stats``: aggregate-only, minimum group size, sinks ``{operator}``;
  P5 BLOCKs aggregates from parameterizing a customer-facing action.
- Strings in consequential arguments are NFC-normalised at resolution (D-025).
- PII canaries seeded in ``customers.email`` never reach agent-visible output.
"""

import json
import unicodedata
from typing import Any

from domain.payment_mock import PaymentMock
from domain.seed import Incident, World, generate, materialize
from evals.canary import CANARY, scan
from kernel.run import Environment, RunResult, run_plan
from kernel.tools.database import MIN_GROUP
from planners.builders import Json, call, expr, lit, map_, op, plan, ref
from planners.fuzz import CASE_CUSTOMER, CASE_TICKET, _case_world, raw_extractor

INCIDENT = 90


def _world() -> World:
    base = _case_world(1, "delivered")  # case customer: orders 7000 and 7001, both eligible
    return base.extend(incidents=(Incident(INCIDENT, "Warehouse flood", base.today - 2, (7000,)),))


def _run(p: Json, world: World | None = None) -> tuple[RunResult, Environment]:
    env = Environment(materialize(world or _world()), PaymentMock(), raw_extractor)
    return run_plan(p, env, run_id="r"), env


def _close(resolution: Json, ticket: int = CASE_TICKET) -> Json:
    return call("close_ticket", ticket_id=lit(ticket), resolution=resolution)


def _credit(amount: Json, customer: int = CASE_CUSTOMER, reason: str = "goodwill") -> Json:
    return call(
        "issue_credit",
        ticket_id=lit(CASE_TICKET),
        customer_id=lit(customer),
        amount=amount,
        reason=lit(reason),
    )


# --- incidents --------------------------------------------------------------------


def test_incident_bulk_refund_is_trusted_and_executes() -> None:
    p = plan(
        call("incident_orders", "affected", incident_id=lit(INCIDENT)),
        expr(
            map_(
                ref("affected"),
                "o",
                call(
                    "issue_refund",
                    ticket_id=lit(CASE_TICKET),
                    order_id=ref("o", "id"),
                    amount=ref("o", "refundable"),
                ),
            )
        ),
    )
    r, env = _run(p)
    assert r.outcome == "executed" and r.rule_log == ()
    assert all(not lbl.untrusted for lbl in r.actions[0].component_labels().values())
    provider = env.provider
    assert isinstance(provider, PaymentMock)
    assert [(e.order_id, e.amount) for e in provider.effects] == [(7000, 120_000)]


# --- close_ticket -----------------------------------------------------------------


def test_trusted_close_executes_and_records_the_resolution() -> None:
    r, env = _run(plan(_close(lit("refunded"))))
    assert r.outcome == "executed"
    row = env.db.execute(
        "SELECT status, resolution FROM tickets WHERE id = ?", (CASE_TICKET,)
    ).fetchone()
    assert row == ("closed", "refunded")


def test_close_blocks_unknown_resolution_and_closed_tickets() -> None:
    assert _run(plan(_close(lit("whatever"))))[0].outcome == "blocked"
    r, env = _run(plan(_close(lit("no_action"))))
    again = run_plan(plan(_close(lit("no_action"))), env, run_id="r2")
    assert r.outcome == "executed" and again.outcome == "blocked"


def test_close_selected_by_ticket_text_needs_approval() -> None:
    world = _world().replace_text("tickets", CASE_TICKET, "body", "#7000")
    p = plan(
        call("read_ticket", "t", ticket_id=lit(CASE_TICKET)),
        expr(
            map_(
                ref("t"),
                "tk",
                call("extract_order_ids", "ids", text=ref("tk", "body")),
                expr(map_(ref("ids"), "x", _close(lit("refunded")))),
            )
        ),
    )
    r, _ = _run(p, world)
    assert r.outcome == "needs_approval"


# --- issue_credit -----------------------------------------------------------------


def test_trusted_credit_executes_once_per_ticket() -> None:
    r, env = _run(plan(_credit(lit(10_000))))
    assert r.outcome == "executed"
    rows = env.db.execute("SELECT ticket_id, customer_id, amount, reason FROM credits").fetchall()
    assert rows == [(CASE_TICKET, CASE_CUSTOMER, 10_000, "goodwill")]
    assert run_plan(plan(_credit(lit(10_000))), env, run_id="r2").outcome == "blocked"


def test_credit_business_blocks() -> None:
    assert _run(plan(_credit(lit(10_000), customer=101)))[0].outcome == "blocked"
    assert _run(plan(_credit(lit(10**7))))[0].outcome == "blocked"
    assert _run(plan(_credit(lit(0))))[0].outcome == "blocked"
    assert _run(plan(_credit(lit(10_000), reason="because")))[0].outcome == "blocked"


# --- aggregates, P5 and the operator answer --------------------------------------


def test_order_stats_suppresses_small_groups_and_is_operator_only() -> None:
    world = generate(5, n_customers=12)
    r, _ = _run(plan(call("order_stats", "s")), world)
    assert r.outcome == "executed" and r.actions == ()
    answer: Any = r.answer
    assert answer and all(row["orders"] >= MIN_GROUP for row in answer)
    counts: dict[str, int] = {}
    for o in world.orders:
        counts[o.status] = counts.get(o.status, 0) + 1
    assert {row["status"] for row in answer} == {s for s, n in counts.items() if n >= MIN_GROUP}
    assert r.answer_sinks == ["operator"]


def test_aggregates_cannot_parameterize_a_customer_facing_action() -> None:
    p = plan(
        call("order_stats", "s"),
        expr(op("len", ref("s")), "n"),
        expr(map_(ref("s"), "row", _credit(ref("row", "total")))),
    )
    r, _ = _run(p, generate(5, n_customers=12).extend(**_world_rows()))
    assert r.outcome == "blocked"
    assert any("sink" in v.reason for v in r.verdicts)


def _world_rows() -> dict[str, Any]:
    w = _world()
    return {"customers": w.customers[-2:], "orders": w.orders[-3:], "tickets": w.tickets[-1:]}


# --- strings ----------------------------------------------------------------------


def test_strings_in_actions_are_nfc_normalised() -> None:
    composed, decomposed = "café", "café"
    assert unicodedata.normalize("NFC", decomposed) == composed
    r1, _ = _run(plan(_close(lit(composed))))
    r2, _ = _run(plan(_close(lit(decomposed))))
    assert r1.actions[0].canonical_args() == r2.actions[0].canonical_args()


# --- PII canaries -----------------------------------------------------------------


def test_canaries_are_seeded_and_scanner_finds_them() -> None:
    world = generate(5, n_customers=3)
    assert all(CANARY in c.email for c in world.customers)
    assert scan({"leak": world.customers[0].email}) and not scan({"ok": "nothing here"})


def test_no_canary_reaches_agent_visible_output() -> None:
    world = generate(5, n_customers=12).extend(**_world_rows())
    p = plan(call("order_stats", "s"), call("read_ticket", "t", ticket_id=lit(500)))
    r, env = _run(p, world)
    audit = [json.loads(rec) for (rec,) in env.db.execute("SELECT record FROM audit")]
    assert not scan({"answer": r.answer, "audit": audit})
