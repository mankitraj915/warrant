"""Label propagation through the interpreter (DESIGN §3). Written before the interpreter."""

from collections.abc import Callable

from domain.seed import World
from kernel.run import RunResult
from planners.builders import Json, call, expr, filter_, lit, map_, op, plan, ref
from planners.fuzz import CASE_TICKET, _case_world
from tests.support import run_world

BODY = f"tickets[{CASE_TICKET}].body"
# Customers can open tickets, so a ticket read carries its row's existence origin
# (Gate 1 review #1): everything inside a map over read_ticket has it in its pc.
ROW = f"tickets[{CASE_TICKET}].@row"


def world(body: str | bytes = "Refund #7000") -> World:
    return _case_world(3, "in_transit").replace_text("tickets", CASE_TICKET, "body", body)


def labels_of(result: RunResult, index: int = 0) -> dict[str, frozenset[str]]:
    return {k: v.untrusted for k, v in result.actions[index].component_labels().items()}


def in_ticket_map(*steps: Json) -> Json:
    return plan(
        call("read_ticket", "t", ticket_id=lit(CASE_TICKET)),
        expr(
            map_(
                ref("t"),
                "tk",
                call("extract_order_ids", "oids", text=ref("tk", "body")),
                *steps,
            )
        ),
    )


def refund(order: Json, amount: Json) -> Json:
    return call("issue_refund", ticket_id=lit(CASE_TICKET), order_id=order, amount=amount)


def test_literals_inside_a_tainted_map_stay_trusted_but_pc_is_tainted() -> None:
    p = in_ticket_map(expr(map_(ref("oids"), "x", refund(lit(7000), lit(10)))))
    result, _, _ = run_world(p, world())
    assert labels_of(result) == {
        "ticket_id": frozenset(),
        "order_id": frozenset(),
        "amount": frozenset(),
        "pc": frozenset({BODY, ROW}),
    }


def test_ticket_read_taints_only_with_the_tickets_existence() -> None:
    p = plan(
        call("read_ticket", "t", ticket_id=lit(CASE_TICKET)),
        expr(
            map_(
                ref("t"),
                "tk",
                call("query_orders", "orders", customer_id=ref("tk", "customer_id")),
                expr(map_(ref("orders"), "o", refund(ref("o", "id"), ref("o", "refundable")))),
            )
        ),
    )
    result, _, _ = run_world(p, world())
    assert len(result.actions) == 2
    for i in range(2):
        assert labels_of(result, i) == {
            "ticket_id": frozenset(),
            "order_id": frozenset({ROW}),
            "amount": frozenset({ROW}),
            "pc": frozenset({ROW}),
        }


def test_filter_joins_every_predicate_label_into_the_structure() -> None:
    p = in_ticket_map(
        call("query_orders", "orders", customer_id=lit(100)),
        expr(filter_(ref("orders"), "o", op("contains", ref("oids"), ref("o", "id"))), "sel"),
        expr(map_(ref("sel"), "s", refund(lit(7000), lit(10)))),
    )
    result, _, _ = run_world(p, world())
    assert labels_of(result)["pc"] == {BODY, ROW}


def test_tainted_index_taints_the_selected_record() -> None:
    p = plan(
        call("query_orders", "orders", customer_id=lit(100)),
        call("read_ticket", "t", ticket_id=lit(CASE_TICKET)),
        expr(
            map_(
                ref("t"),
                "tk",
                call("extract_order_ids", "oids", text=ref("tk", "body")),
                expr(op("at", ref("orders"), op("sub", op("len", ref("oids")), lit(1))), "p"),
                expr(map_(ref("p"), "q", refund(ref("q", "id"), ref("q", "refundable")))),
            )
        ),
    )
    result, _, _ = run_world(p, world())
    assert labels_of(result)["order_id"] == {BODY, ROW}


def test_amount_selected_by_tainted_id_is_tainted() -> None:
    p = in_ticket_map(
        expr(
            map_(
                ref("oids"),
                "o",
                call("compute_refund_amount", "amt", order_id=ref("o")),
                refund(lit(7000), ref("amt")),
            )
        )
    )
    result, _, _ = run_world(p, world())
    assert labels_of(result)["amount"] == {BODY, ROW}


def test_order_note_fields_carry_their_own_origin() -> None:
    p = plan(
        call("query_orders", "orders", customer_id=lit(100)),
        expr(
            map_(
                ref("orders"),
                "o",
                call("extract_order_ids", "ids", text=ref("o", "customer_note")),
                expr(map_(ref("ids"), "x", refund(ref("x"), lit(10)))),
            )
        ),
    )
    w = world().replace_text("orders", 7000, "customer_note", "#7000")
    result, _, _ = run_world(p, w)
    assert labels_of(result)["order_id"] == {"orders[7000].customer_note"}


def _extracting(extractor: Callable[[str], list[object]], body: str | bytes = "x") -> RunResult:
    p = in_ticket_map(expr(map_(ref("oids"), "o", refund(ref("o"), lit(10)))))
    result, _, _ = run_world(p, world(body), extractor=extractor)
    return result


def test_extractor_outputs_are_validated() -> None:
    def bad(_: str) -> list[object]:
        return [True, "7000", 7000.0, 2**80, -3, 7000, 7000, 7000, 7000, 7000, 7000]

    # bools, strings, floats and out-of-range ints are dropped; at most 5 kept.
    assert [a.canonical_args()["order_id"] for a in _extracting(bad).actions] == [7000] * 5


def test_extractor_exception_yields_no_ids() -> None:
    def boom(_: str) -> list[object]:
        raise RuntimeError("model crashed")

    assert _extracting(boom).actions == ()


def test_invalid_utf8_in_untrusted_text_does_not_raise() -> None:
    def ids(text: str) -> list[object]:
        return [int(t) for t in text.replace("#", " ").split() if t.isdigit()]

    result = _extracting(ids, body=b"\xff\xfe #7000")
    assert [a.canonical_args()["order_id"] for a in result.actions] == [7000]
