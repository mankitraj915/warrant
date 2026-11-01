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
from kernel.labels import cell_origin, join
from kernel.run import RunResult

OWNERSHIP = "ticket_order_ownership"
GOODWILL = "ticket_goodwill_credit"
GOODWILL_AMOUNT = 10_000  # restated, not imported: the oracle must not share the kernel's code


def coverage_events(source: str, plan: Any) -> None:
    """Hypothesis statistics: where the plan came from and, for grammar plans,
    each grammar construct it uses (D-053)."""
    from hypothesis import event

    from planners.grammar_fuzz import constructs

    event(f"plan source={source}")
    if source == "grammar":
        for construct in sorted(constructs(plan["steps"])):
            event(f"grammar: {construct}")


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


def effects(provider: PaymentMock, db: sqlite3.Connection | None = None) -> list[tuple[Any, ...]]:
    """Executed effects: money moved by the provider, in order, then (with ``db``)
    the consequential database writes: credits and ticket closures."""
    moved: list[tuple[Any, ...]] = [
        (e.order_id, e.amount, e.idempotency_key) for e in provider.effects
    ]
    if db is None:
        return moved
    credits = db.execute(
        "SELECT 'credit', ticket_id, customer_id, amount, reason FROM credits ORDER BY id"
    ).fetchall()
    closed = db.execute(
        "SELECT 'close', id, resolution FROM tickets WHERE resolution IS NOT NULL ORDER BY id"
    ).fetchall()
    return moved + credits + closed


def check_ni1(r1: RunResult, r2: RunResult) -> None:
    """Stated for pairs of runs that both finish resolution: a run halted during
    resolution has no action set, only whole-run suppression (NI-3, D-054)."""
    if "halted" in (r1.outcome, r2.outcome):
        return
    if trusted_actions(r1) != trusted_actions(r2):
        raise NIViolation(
            f"NI-1 trusted actions differ:\n{trusted_actions(r1)}\n{trusted_actions(r2)}"
        )


# Each rule's declared endorsable origins (DESIGN §6.2, §6.3), restated independently.
def _case_ticket_origins(ticket: int) -> set[str]:
    return {cell_origin("tickets", ticket, c) for c in ("subject", "body", "@row")}


def check_ni2(r: RunResult) -> None:
    """Every untrusted ALLOW has its own logged admitting decision, and the
    endorsed origins lie within that rule's declared set."""
    sites = [a.site for a in r.actions]
    if len(set(sites)) != len(sites):
        raise NIViolation(f"NI-2 action sites are not unique: {sites}")
    admitted = {d.site: d.rule for d in r.rule_log if d.admitted}
    for a, v in zip(r.actions, r.verdicts, strict=True):
        if v.kind != "ALLOW" or effective_trusted(a):
            continue
        if admitted.get(a.site) is None or admitted[a.site] != v.rule:
            raise NIViolation(f"NI-2 untrusted action allowed without a rule: {a.site} {v}")
        if v.rule in (OWNERSHIP, GOODWILL):
            allowed = _case_ticket_origins(int(a.canonical_args()["ticket_id"]))
            origins = join(*a.component_labels().values()).untrusted
            if not origins <= allowed:
                raise NIViolation(f"NI-2 endorsed origins {sorted(origins)} outside the rule's set")


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
    """Every executed action admitted by a rule meets that rule's postcondition."""
    if r.outcome not in ("executed", "partial", "indeterminate"):
        return
    by_ticket: dict[tuple[str, int], int] = {}
    credits_to: dict[int, int] = {}  # credits per customer in this run (Gate 3 review #6)
    for a in r.actions:
        args = a.canonical_args()
        key = (a.tool, int(args.get("ticket_id", -1)))
        by_ticket[key] = by_ticket.get(key, 0) + 1
        if a.tool == "issue_credit":
            credits_to[int(args["customer_id"])] = credits_to.get(int(args["customer_id"]), 0) + 1
    for a, v in zip(r.actions, r.verdicts, strict=True):
        if v.rule == GOODWILL:
            _check_goodwill(a.canonical_args(), pre, by_ticket, credits_to)
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
        if pre.execute("SELECT 1 FROM refunds WHERE order_id = ?", (order,)).fetchone():
            problems.append("order already had a refund")
        if by_ticket[("issue_refund", ticket)] != 1:
            problems.append("more than one refund for the ticket in this run")
        if problems:
            raise NIViolation(f"NI-4 postcondition failed for {args}: {problems}")


def _check_goodwill(
    args: dict[str, Any],
    pre: sqlite3.Connection,
    by_ticket: dict[tuple[str, int], int],
    credits_to: dict[int, int],
) -> None:
    """ticket_goodwill_credit: the standard amount, to the ticket's own customer,
    for an allowed reason, once per ticket and once per customer."""
    ticket = int(args["ticket_id"])
    row = pre.execute("SELECT customer_id FROM tickets WHERE id = ?", (ticket,)).fetchone()
    problems = []
    if row is None or int(args["customer_id"]) != row[0]:
        problems.append("credit is not to the ticket's customer")
    if int(args["amount"]) != GOODWILL_AMOUNT:
        problems.append("amount is not the standard goodwill amount")
    if args["reason"] not in ("goodwill", "late_delivery"):
        problems.append("reason is not an allowed credit reason")
    if pre.execute("SELECT 1 FROM credits WHERE ticket_id = ?", (ticket,)).fetchone():
        problems.append("ticket already had a credit")
    customer = int(args["customer_id"])
    if pre.execute("SELECT 1 FROM credits WHERE customer_id = ?", (customer,)).fetchone():
        problems.append("customer already had a credit")
    if by_ticket[("issue_credit", ticket)] != 1:
        problems.append("more than one credit for the ticket in this run")
    if credits_to[customer] != 1:
        problems.append("more than one credit for the customer in this run")
    if problems:
        raise NIViolation(f"NI-4 goodwill postcondition failed for {args}: {problems}")
