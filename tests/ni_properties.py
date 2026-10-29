"""Non-interference properties NI-1..NI-4 (DESIGN §9.3), checked on run results.

Written before the interpreter. Everything here is computed independently of
the kernel's policy code: effective labels are re-joined from component labels,
release projections are rebuilt from the rule log, and the NI-4 oracle
recomputes eligibility with its own SQL.
"""

import sqlite3
from typing import Any

from domain.payment_mock import PaymentMock
from domain.seed import REFUND_WINDOW_DAYS
from kernel.labels import join
from kernel.run import RunResult

OWNERSHIP = "ticket_order_ownership"


class NIViolation(AssertionError):
    """A non-interference property failed."""


def effective_trusted(action: Any) -> bool:
    return join(*action.component_labels().values()).trusted


def trusted_actions(r: RunResult) -> list[tuple[Any, ...]]:
    return [
        (a.site, a.tool, tuple(sorted(a.canonical_args().items())))
        for a in r.actions
        if effective_trusted(a)
    ]


def projection(r: RunResult) -> tuple[tuple[Any, ...], ...]:
    """Release projection for theta = 0: (rule, site, outcome) only."""
    return tuple((d.rule, d.site, d.admitted) for d in r.rule_log)


def effects(provider: PaymentMock) -> list[tuple[int, int, str]]:
    return [(e.order_id, e.amount, e.idempotency_key) for e in provider.effects]


def check_ni1(r1: RunResult, r2: RunResult) -> None:
    if trusted_actions(r1) != trusted_actions(r2):
        raise NIViolation(
            f"NI-1 trusted actions differ:\n{trusted_actions(r1)}\n{trusted_actions(r2)}"
        )


def check_ni2(r: RunResult) -> None:
    admitted = {d.site for d in r.rule_log if d.admitted}
    for a, v in zip(r.actions, r.verdicts, strict=True):
        if v.kind == "ALLOW" and not effective_trusted(a) and a.site not in admitted:
            raise NIViolation(f"NI-2 untrusted action allowed without a rule: {a.site} {v}")


def check_ni3(
    r1: RunResult, x1: list[tuple[int, int, str]], r2: RunResult, x2: list[tuple[int, int, str]]
) -> None:
    if projection(r1) == projection(r2) and x1 and x2 and x1 != x2:
        raise NIViolation(f"NI-3 executed effects differ with equal projections:\n{x1}\n{x2}")


def _refundable(db: sqlite3.Connection, order_id: int) -> int:
    row = db.execute(
        "SELECT o.status, c.today - o.placed_day,"
        " (SELECT COALESCE(SUM(amount), 0) FROM payments WHERE order_id = o.id)"
        " - (SELECT COALESCE(SUM(amount), 0) FROM refunds WHERE order_id = o.id)"
        " FROM orders o, clock c WHERE o.id = ?",
        (order_id,),
    ).fetchone()
    if row is None:
        return 0
    status, age, balance = row
    return int(balance) if status == "delivered" and age <= REFUND_WINDOW_DAYS else 0


def _eligible(db: sqlite3.Connection, customer_id: int) -> set[int]:
    ids = [i for (i,) in db.execute("SELECT id FROM orders WHERE customer_id = ?", (customer_id,))]
    return {i for i in ids if _refundable(db, i) > 0}


def check_ni4(r: RunResult, pre: sqlite3.Connection) -> None:
    """Every executed refund admitted by the ownership rule meets its postcondition."""
    if r.outcome != "executed":
        return
    by_ticket: dict[int, int] = {}
    for a in r.actions:
        if a.tool == "issue_refund":
            t = int(a.canonical_args()["ticket_id"])
            by_ticket[t] = by_ticket.get(t, 0) + 1
    for a, v in zip(r.actions, r.verdicts, strict=True):
        if v.rule != OWNERSHIP:
            continue
        args = a.canonical_args()
        ticket, order, amount = int(args["ticket_id"]), int(args["order_id"]), int(args["amount"])
        row = pre.execute("SELECT customer_id FROM tickets WHERE id = ?", (ticket,)).fetchone()
        problems = []
        if row is None or _eligible(pre, row[0]) != {order}:
            problems.append("order is not the customer's unique eligible order")
        if amount != _refundable(pre, order):
            problems.append("amount is not the full refundable amount")
        if pre.execute("SELECT 1 FROM refunds WHERE ticket_id = ?", (ticket,)).fetchone():
            problems.append("ticket already had a refund")
        if by_ticket[ticket] != 1:
            problems.append("more than one refund for the ticket in this run")
        if problems:
            raise NIViolation(f"NI-4 postcondition failed for {args}: {problems}")
