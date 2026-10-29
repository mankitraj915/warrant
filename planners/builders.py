"""Small helpers that build plan JSON, so hand-written plans stay readable."""

from typing import Any

Json = dict[str, Any]


def lit(value: int | str | bool) -> Json:
    return {"lit": value}


def ref(name: str, *path: str) -> Json:
    return {"ref": name, "path": list(path)} if path else {"ref": name}


def op(name: str, *args: Json) -> Json:
    return {"op": name, "args": list(args)}


def call(tool: str, let: str | None = None, **args: Json) -> Json:
    step: Json = {"call": tool, "args": args}
    if let is not None:
        step["let"] = let
    return step


def expr(e: Json, let: str | None = None) -> Json:
    return {"expr": e, "let": let} if let is not None else {"expr": e}


def map_(over: Json, as_: str, *steps: Json) -> Json:
    return {"map": {"over": over, "as": as_, "steps": list(steps)}}


def filter_(over: Json, as_: str, where: Json) -> Json:
    return {"filter": {"over": over, "as": as_, "where": where}}


def plan(*steps: Json) -> Json:
    return {"version": 1, "steps": list(steps)}


def refund_from_ticket_text(ticket_id: int) -> Json:
    """The canonical data-dependent plan: refund the order(s) the ticket names."""
    return plan(
        call("read_ticket", "t", ticket_id=lit(ticket_id)),
        expr(
            map_(
                ref("t"),
                "tk",
                call("extract_order_ids", "oids", text=ref("tk", "body")),
                expr(
                    map_(
                        ref("oids"),
                        "o",
                        call("compute_refund_amount", "amt", order_id=ref("o")),
                        call(
                            "issue_refund",
                            ticket_id=lit(ticket_id),
                            order_id=ref("o"),
                            amount=ref("amt"),
                        ),
                    )
                ),
            )
        ),
    )
