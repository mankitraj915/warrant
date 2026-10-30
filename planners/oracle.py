"""Oracle planner: a hand-written correct plan per task, independent of the model.

The shapes below are the plans a competent planner would write for the
operator requests in the dev suite. ``OraclePlanner`` ignores its input and
returns its fixed plan.
"""

from typing import Any

from planners.builders import Json, call, expr, filter_, lit, map_, op, plan, ref


class OraclePlanner:
    def __init__(self, fixed_plan: Json) -> None:
        self._plan = fixed_plan

    def plan(self, planner_input: Any) -> Json:
        return self._plan


def _refund(ticket: int, order: Json, amount: Json) -> Json:
    return call("issue_refund", ticket_id=lit(ticket), order_id=order, amount=amount)


def refund_in_full(ticket: int, *orders: int) -> Json:
    """Refund named orders for their full refundable amount."""
    steps: list[Json] = []
    for i, order in enumerate(orders):
        steps.append(call("compute_refund_amount", f"amt{i}", order_id=lit(order)))
        steps.append(_refund(ticket, lit(order), ref(f"amt{i}")))
    return plan(*steps)


def refund_amount(ticket: int, order: int, amount: int) -> Json:
    return plan(_refund(ticket, lit(order), lit(amount)))


def refund_customer_orders(
    ticket: int, customer: int, where: Json | None = None, amount: Json | None = None
) -> Json:
    """Refund a customer's eligible orders matching ``where`` (over record ``o``)."""
    eligible = op("gt", ref("o", "refundable"), lit(0))
    predicate = eligible if where is None else op("and", eligible, where)
    return plan(
        call("query_orders", "orders", customer_id=lit(customer)),
        expr(filter_(ref("orders"), "o", predicate), "sel"),
        expr(
            map_(ref("sel"), "s", _refund(ticket, ref("s", "id"), amount or ref("s", "refundable")))
        ),
    )


def refund_ticket_customer_orders(ticket: int) -> Json:
    """Refund every eligible order of the customer who opened the ticket."""
    return plan(
        call("read_ticket", "t", ticket_id=lit(ticket)),
        expr(
            map_(
                ref("t"),
                "tk",
                call("query_orders", "orders", customer_id=ref("tk", "customer_id")),
                expr(filter_(ref("orders"), "o", op("gt", ref("o", "refundable"), lit(0))), "sel"),
                expr(
                    map_(ref("sel"), "s", _refund(ticket, ref("s", "id"), ref("s", "refundable")))
                ),
            )
        ),
    )


def refund_mentioned_eligible(ticket: int) -> Json:
    """Data-dependent: refund the ticket customer's eligible orders that the
    ticket text mentions. Ids not owned by the customer are filtered out by a
    trusted query; the selection itself stays labelled with the ticket text."""
    mentioned = op("contains", ref("oids"), ref("o", "id"))
    eligible = op("gt", ref("o", "refundable"), lit(0))
    return plan(
        call("read_ticket", "t", ticket_id=lit(ticket)),
        expr(
            map_(
                ref("t"),
                "tk",
                call("extract_order_ids", "oids", text=ref("tk", "body")),
                call("query_orders", "orders", customer_id=ref("tk", "customer_id")),
                expr(filter_(ref("orders"), "o", op("and", mentioned, eligible)), "sel"),
                expr(
                    map_(ref("sel"), "s", _refund(ticket, ref("s", "id"), ref("s", "refundable")))
                ),
            )
        ),
    )


def steps_of(*plans: Json) -> Json:
    """Run several plans' steps in sequence (their ``let`` names must not clash)."""
    return plan(*(step for p in plans for step in p["steps"]))


def close(ticket: int, resolution: str) -> Json:
    return plan(call("close_ticket", ticket_id=lit(ticket), resolution=lit(resolution)))


def credit(ticket: int, customer: int, amount: int, reason: str) -> Json:
    """A credit with every argument stated by the operator."""
    return plan(
        call(
            "issue_credit",
            ticket_id=lit(ticket),
            customer_id=lit(customer),
            amount=lit(amount),
            reason=lit(reason),
        )
    )


def refund_incident_orders(ticket: int, incident: int, customer: int | None = None) -> Json:
    """Refund in full the eligible orders a staff-recorded incident lists
    (optionally only one customer's)."""
    eligible = op("gt", ref("io", "refundable"), lit(0))
    if customer is not None:
        eligible = op("and", eligible, op("eq", ref("io", "customer_id"), lit(customer)))
    return plan(
        call("incident_orders", "affected", incident_id=lit(incident)),
        expr(filter_(ref("affected"), "io", eligible), "hit"),
        expr(map_(ref("hit"), "h", _refund(ticket, ref("h", "id"), ref("h", "refundable")))),
    )


def credit_if_order_mentioned(ticket: int, amount: int, reason: str) -> Json:
    """Data-dependent: one credit to the ticket's customer if the ticket text
    names one of that customer's orders."""
    mentioned = op("contains", ref("cids"), ref("co", "id"))
    return plan(
        call("read_ticket", "ct", ticket_id=lit(ticket)),
        expr(
            map_(
                ref("ct"),
                "ctk",
                call("extract_order_ids", "cids", text=ref("ctk", "body")),
                call("query_orders", "corders", customer_id=ref("ctk", "customer_id")),
                expr(filter_(ref("corders"), "co", mentioned), "csel"),
                expr(op("at", ref("csel"), lit(0)), "cone"),
                expr(
                    map_(
                        ref("cone"),
                        "c1",
                        call(
                            "issue_credit",
                            ticket_id=lit(ticket),
                            customer_id=ref("ctk", "customer_id"),
                            amount=lit(amount),
                            reason=lit(reason),
                        ),
                    )
                ),
            )
        ),
    )


def credit_ticket_customer_amount(ticket: int, amount: int, reason: str) -> Json:
    """Credit the customer who opened the ticket (customer id read from the ticket)."""
    return plan(
        call("read_ticket", "gt", ticket_id=lit(ticket)),
        expr(
            map_(
                ref("gt"),
                "gtk",
                call(
                    "issue_credit",
                    ticket_id=lit(ticket),
                    customer_id=ref("gtk", "customer_id"),
                    amount=lit(amount),
                    reason=lit(reason),
                ),
            )
        ),
    )
