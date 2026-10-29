"""Undefended baseline (SPEC §6): the planner sees untrusted content directly and
the executor applies no policy.

It lives outside the kernel so the kernel has no "policy off" switch. It reuses
the plan checker and interpreter (the same plan means the same resolved
actions) and the same idempotency key as the kernel's executor, so it differs
from Warrant only in planner isolation and policy, not in execution hygiene.
"""

import sqlite3
from collections.abc import Callable
from typing import Any

from kernel.interpreter import Interpreter
from kernel.labels import Label
from kernel.plan_lang import PlanRejected, check_plan, parse_plan
from kernel.run import OPERATOR, Planner, PlannerInput
from kernel.tools.database import Database, lossless_text
from kernel.tools.registry import signatures


def run_undefended(
    request: str,
    planner: Planner,
    conn: sqlite3.Connection,
    provider: Any,
    extractor: Callable[[str], list[object]],
    *,
    show_ticket_bodies: tuple[int, ...] = (),
) -> tuple[str, str]:
    """Plan with the ticket bodies in context, then execute every action.

    Returns ``(outcome, reason)``; effects are read from the provider.
    """
    conn.text_factory = lossless_text
    context: list[tuple[str, Label]] = []
    for ticket in show_ticket_bodies:
        row = conn.execute("SELECT body FROM tickets WHERE id = ?", (ticket,)).fetchone()
        if row is not None:
            context.append((str(row[0]), OPERATOR))
    raw = planner.plan(PlannerInput(request, signatures(), tuple(context)))
    try:
        plan = parse_plan(raw)
        check_plan(plan)
    except PlanRejected as exc:
        return "rejected", str(exc)
    actions = Interpreter(Database(conn), extractor, OPERATOR).resolve(plan)
    for action in actions:
        args = action.canonical_args()
        ticket, order, amount = int(args["ticket_id"]), int(args["order_id"]), int(args["amount"])
        key = f"refund:{order}:{ticket}"
        ref = provider.status(key) or provider.refund(key, order, amount)
        conn.execute(
            "INSERT OR IGNORE INTO refunds (order_id, ticket_id, amount, idempotency_key,"
            " provider_ref) VALUES (?, ?, ?, ?, ?)",
            (order, ticket, amount, key, ref),
        )
        conn.commit()
    return "executed", f"{len(actions)} actions, no policy"
