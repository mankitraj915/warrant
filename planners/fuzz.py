"""Hypothesis strategies for non-interference fuzzing (DESIGN §9.4).

- ``worlds()``: small seeded worlds, each with a "case" customer (100) whose
  ticket (4000) the attacker can write, so declassification is exercised.
- ``mutated(world)``: the same world with attacker-controlled cells rewritten,
  and possibly with customer-created ticket rows added or removed (a ticket
  ``PROBE_TICKET`` opened by another customer, or the case ticket deleted).
  Payloads name the case's own orders, other customers' orders, duplicates, too
  many ids, extreme integers, booleans and invalid UTF-8.
- ``plans(world)``: compositions of the known laundering shapes (selection by
  tainted predicate, tainted index, tainted amount arithmetic, nested
  map/filter, literal-argument calls in tainted maps, text from other origins,
  trusted actions mixed with tainted ones, actions under a read of a ticket
  that may not exist, credits and closures under a ticket read, ticket ids
  taken from the read record, text from ``subject``, filters over maps).
  Selection and index shapes are also driven by order-note
  text, outside any ticket read, so label bugs cannot hide behind the ownership
  rule. Amounts and predicates inside the
  shapes are drawn from a type-directed expression generator.
- ``raw_extractor``: every integer or TRUE/FALSE token, in order, with no
  dedupe and no cap, so extractor outputs are effectively arbitrary.
"""

import re
from collections.abc import Callable
from dataclasses import replace
from itertools import count

from hypothesis import strategies as st

from domain.seed import Customer, Order, Payment, Text, Ticket, World, generate
from planners.builders import Json, call, expr, filter_, lit, map_, op, plan, ref

CASE_CUSTOMER, OTHER_CUSTOMER, CASE_TICKET = 100, 101, 4000
PROBE_TICKET = 4001  # a ticket id another customer may or may not have opened
UNTRUSTED_CELLS = (
    ("tickets", "subject"),
    ("tickets", "body"),
    ("orders", "customer_note"),
    ("customers", "display_name"),
)
_TOKEN = re.compile(r"TRUE|FALSE|-?\d+")


def raw_extractor(text: str) -> list[object]:
    return [
        True if t == "TRUE" else False if t == "FALSE" else int(t) for t in _TOKEN.findall(text)
    ]


def _case_world(seed: int, second_status: str) -> World:
    today = generate(seed, n_customers=0).today
    orders = (
        Order(7000, CASE_CUSTOMER, 120_000, "delivered", today - 5, ""),
        Order(7001, CASE_CUSTOMER, 450_000, second_status, today - 3, ""),
        Order(7100, OTHER_CUSTOMER, 300_000, "delivered", today - 2, ""),
    )
    return generate(seed, n_customers=4).extend(
        customers=(
            Customer(CASE_CUSTOMER, "Case Customer", "case@example.test"),
            Customer(OTHER_CUSTOMER, "Other Customer", "other@example.test"),
        ),
        orders=orders,
        payments=tuple(Payment(o.id, o.amount) for o in orders if o.status != "cancelled"),
        tickets=(Ticket(CASE_TICKET, CASE_CUSTOMER, "Refund", "Please refund order #7000."),),
    )


def worlds() -> st.SearchStrategy[World]:
    # second_status "delivered" gives the case customer two eligible orders.
    return st.builds(
        _case_world, st.integers(0, 2**16), st.sampled_from(["in_transit", "delivered"])
    )


def _order_ids(world: World) -> list[int]:
    return [o.id for o in world.orders]


def payloads(world: World) -> st.SearchStrategy[Text]:
    ids = st.one_of(
        st.sampled_from([7000, 7001, 7100]), st.sampled_from([*_order_ids(world), 999_999])
    )
    return st.one_of(
        st.just("Please refund order #7000."),
        ids.map(lambda i: f"Please refund order #{i}."),
        st.lists(ids, min_size=2, max_size=7).map(lambda xs: " ".join(f"#{i}" for i in xs)),
        st.sampled_from(["", "TRUE", "-5", "99999999999999999999999", "#0", "FALSE 7000"]),
        ids.map(lambda i: b"\xff\xfe order #" + str(i).encode()),
        st.text(max_size=30),
    )


def mutated(world: World) -> st.SearchStrategy[World]:
    cells = [(t, row.id, c) for t, c in UNTRUSTED_CELLS for row in getattr(world, t)]
    cell = st.one_of(
        st.just(("tickets", CASE_TICKET, "body")),
        st.sampled_from([("orders", o, "customer_note") for o in (7000, 7001)]),
        st.sampled_from(cells),
    )
    rows = st.sampled_from(["same", "same", "same", "open_probe", "delete_case"])

    def build(edits: list[tuple[tuple[str, int, str], Text]], row_change: str) -> World:
        w = world
        if row_change == "open_probe":
            w = w.extend(tickets=(Ticket(PROBE_TICKET, OTHER_CUSTOMER, "Hi", "Refund #7100"),))
        for (table, key, column), value in edits:
            if any(t.id == key for t in w.tickets) or table != "tickets":
                w = w.replace_text(table, key, column, value)
        if row_change == "delete_case":
            w = replace(w, tickets=tuple(t for t in w.tickets if t.id != CASE_TICKET))
        return w

    return st.builds(build, st.lists(st.tuples(cell, payloads(world)), max_size=6), rows)


# --- plans -------------------------------------------------------------------------


class _Names:
    def __init__(self) -> None:
        self._n = count()

    def __call__(self, prefix: str) -> str:
        return f"{prefix}{next(self._n)}"


Draw = Callable[[st.SearchStrategy[object]], object]


def _amount(draw: Draw, money_refs: list[Json], depth: int = 0) -> Json:
    """A Money expression: literal, an available Money value, or arithmetic."""
    # Weighted towards available Money values, so many plans pass the amount checks.
    options = ["lit"] + (["ref"] * 4 if money_refs else []) + (["op"] if depth < 2 else [])
    kind = draw(st.sampled_from(options))
    if kind == "lit":
        return lit(draw(st.sampled_from([1, 100, 5_000, 120_000, 300_000, 450_000, 10**15])))
    if kind == "ref":
        return draw(st.sampled_from(money_refs))
    name = draw(st.sampled_from(["add", "sub", "min", "max"]))
    return op(name, _amount(draw, money_refs, depth + 1), _amount(draw, money_refs, depth + 1))


def _predicate(draw: Draw, rec: str, oid_lists: list[Json], depth: int = 0) -> Json:
    """A Bool predicate over an Order record, possibly using extracted ids."""
    atoms: list[Json] = [
        op("gt", ref(rec, "refundable"), lit(0)),
        op("eq", ref(rec, "status"), lit("delivered")),
        op("eq", ref(rec, "id"), lit(draw(st.sampled_from([7000, 7001, 7100])))),
        op("lt", ref(rec, "amount"), lit(200_000)),
    ]
    atoms += [op("contains", ids, ref(rec, "id")) for ids in oid_lists]
    if depth < 1 and draw(st.booleans()):
        name = draw(st.sampled_from(["and", "or"]))
        return op(name, _predicate(draw, rec, oid_lists, 1), _predicate(draw, rec, oid_lists, 1))
    atom = draw(st.sampled_from(atoms))
    return op("not", atom) if draw(st.booleans()) and depth else atom


def _ids(draw: Draw, world: World) -> tuple[int, int, int]:
    """Ticket, customer, order: usually coherent (the ticket's customer and one of
    their orders), sometimes arbitrary, so both allowed and blocked paths are hit."""
    other_tickets = st.sampled_from([t.id for t in world.tickets] + [PROBE_TICKET])
    ticket = draw(st.one_of(st.just(CASE_TICKET), st.just(CASE_TICKET), other_tickets))
    owner = {t.id: t.customer_id for t in world.tickets}.get(ticket, OTHER_CUSTOMER)
    coherent = draw(st.sampled_from([True, True, True, False]))
    customers = [owner] if coherent else [CASE_CUSTOMER, OTHER_CUSTOMER, 1]
    customer = draw(st.sampled_from(customers))
    own = [o.id for o in world.orders if o.customer_id == customer] or _order_ids(world)
    order = draw(st.sampled_from(own if coherent else [7000, 7001, 7100, *_order_ids(world)]))
    return ticket, customer, order


def _refund(ticket: Json, order: Json, amount: Json) -> Json:
    return call("issue_refund", ticket_id=ticket, order_id=order, amount=amount)


def _shape(draw: Draw, world: World, n: _Names) -> list[Json]:
    """One laundering shape, as a list of top-level steps."""
    t_id, c_id, o_id = _ids(draw, world)
    t, tk, oids, o, amt = n("t"), n("tk"), n("oids"), n("o"), n("amt")
    read = call("read_ticket", t, ticket_id=lit(t_id))
    field = draw(st.sampled_from(["body", "body", "body", "subject"]))
    extract = call("extract_order_ids", oids, text=ref(tk, field))
    # The ticket id inside a ticket read: the literal, or the read record's own id.
    t_arg = draw(st.sampled_from([lit(t_id), lit(t_id), ref(tk, "id")]))
    kind = draw(
        st.sampled_from(
            [
                "direct",
                "note",
                "select",
                "index",
                "amount",
                "literal",
                "trusted",
                "nested",
                "note_select",
                "note_index",
                "probe",
                "filter_map",
                "credit",
                "credit",
                "close",
            ]
        )
    )
    if kind == "direct":  # canonical: refund each extracted id
        body = map_(
            ref(oids),
            o,
            call("compute_refund_amount", amt, order_id=ref(o)),
            _refund(t_arg, ref(o), _amount(draw, [ref(amt)])),
        )
        return [read, expr(map_(ref(t), tk, extract, expr(body)))]
    if kind in ("credit", "close"):  # the Phase 2 consequential tools
        x = n("x")
        # Under a ticket read (possibly triggered by its text), or triggered by
        # order-note text with no ticket read (map nesting is limited to 2).
        trigger = draw(st.sampled_from(["none", "ticket", "note", "note"]))
        in_read = trigger != "note"
        ticket_arg = t_arg if in_read else lit(t_id)
        if kind == "credit":
            # The standard amount, others within the credit limit, or arbitrary;
            # mostly standard when triggered by notes, so origin checks are reached.
            standard = [lit(10_000)] * (2 if in_read else 6)
            amount = draw(st.sampled_from([*standard, lit(5_000), lit(50_000), None]))
            amount = amount or _amount(draw, [])
            reason = draw(st.sampled_from(["goodwill", "goodwill", "late_delivery", "because"]))
            customers = [ref(tk, "customer_id")] * 2 if in_read else []
            customer = draw(st.sampled_from([*customers, lit(c_id)]))
            action = call(
                "issue_credit",
                ticket_id=ticket_arg,
                customer_id=customer,
                amount=amount,
                reason=lit(reason),
            )
        else:
            from_text = [ref(tk, field)] if in_read else []
            resolution = draw(
                st.sampled_from([lit("refunded"), lit("no_action"), lit("bogus"), *from_text])
            )
            action = call("close_ticket", ticket_id=ticket_arg, resolution=resolution)
        if trigger == "ticket":  # triggered by the ticket's own text
            return [read, expr(map_(ref(t), tk, extract, expr(map_(ref(oids), x, action))))]
        if trigger == "note":  # at most once: the first id in one order's note
            orders, first = n("orders"), n("first")
            note_ids = call("extract_order_ids", oids, text=ref(o, "customer_note"))
            once = map_(op("at", ref(oids), lit(0)), x, action)
            return [
                call("query_orders", orders, customer_id=lit(c_id)),
                expr(op("at", ref(orders), lit(draw(st.sampled_from([0, 1])))), first),
                expr(map_(ref(first), o, note_ids, expr(once))),
            ]
        return [read, expr(map_(ref(t), tk, action))]
    if kind == "note":  # ids from order notes, i.e. not from the case ticket
        orders, x = n("orders"), n("x")
        note_ids = call("extract_order_ids", oids, text=ref(o, "customer_note"))
        body = map_(ref(oids), x, _refund(lit(t_id), ref(x), _amount(draw, [])))
        return [
            call("query_orders", orders, customer_id=lit(c_id)),
            expr(map_(ref(orders), o, note_ids, expr(body))),
        ]
    if kind in ("select", "nested", "filter_map"):  # selection by a tainted predicate
        orders, sel, s = n("orders"), n("sel"), n("s")
        pred = _predicate(draw, o, [ref(oids)])
        source = ref(orders)
        if kind == "filter_map":  # the filter's source is itself a map
            y = n("y")
            source = map_(ref(orders), y, expr(ref(y)))
        customer = ref(tk, "customer_id") if kind == "nested" else lit(c_id)
        if draw(st.booleans()):  # act on the selected record
            action = _refund_rec(t_id, s, draw)
        else:  # act on a fixed order, once per selected record
            action = _refund(lit(t_id), lit(o_id), _amount(draw, []))
        return [
            read,
            expr(
                map_(
                    ref(t),
                    tk,
                    extract,
                    call("query_orders", orders, customer_id=customer),
                    expr(filter_(source, o, pred), sel),
                    expr(map_(ref(sel), s, action)),
                )
            ),
        ]
    if kind == "index":  # a list index chosen by tainted data
        orders, picked, p = n("orders"), n("picked"), n("p")
        index = (
            op("len", ref(oids)) if draw(st.booleans()) else op("sub", op("len", ref(oids)), lit(1))
        )
        return [
            call("query_orders", orders, customer_id=lit(c_id)),
            read,
            expr(
                map_(
                    ref(t),
                    tk,
                    extract,
                    expr(op("at", ref(orders), index), picked),
                    expr(map_(ref(picked), p, _refund_rec(t_id, p, draw))),
                )
            ),
        ]
    if kind == "amount":  # fixed target, amount computed from a tainted selection
        x = n("x")
        body = map_(
            ref(oids),
            x,
            call("compute_refund_amount", amt, order_id=ref(x)),
            _refund(t_arg, lit(o_id), _amount(draw, [ref(amt)])),
        )
        return [read, expr(map_(ref(t), tk, extract, expr(body)))]
    if kind in ("note_select", "note_index"):  # selection by order-note text
        orders, sel, s, picked = n("orders"), n("sel"), n("s"), n("picked")
        note_ids = call("extract_order_ids", oids, text=ref(o, "customer_note"))
        if kind == "note_select":
            mentioned = op("contains", ref(oids), ref(s, "id"))
            pred = draw(st.sampled_from([mentioned, op("and", mentioned, _predicate(draw, s, []))]))
            pick = expr(filter_(ref(orders), s, pred), sel)
        else:
            index = op("sub", op("len", ref(oids)), lit(draw(st.sampled_from([0, 1]))))
            pick = expr(op("at", ref(orders), index), sel)
        return [
            call("query_orders", orders, customer_id=lit(c_id)),
            expr(
                map_(
                    ref(orders),
                    o,
                    note_ids,
                    pick,
                    expr(map_(ref(sel), picked, _refund_rec(t_id, picked, draw))),
                )
            ),
        ]
    if kind == "probe":  # actions under a read of a ticket that may not exist
        probe = call("read_ticket", t, ticket_id=lit(PROBE_TICKET))
        return [probe, expr(map_(ref(t), tk, _refund(lit(t_id), lit(o_id), _amount(draw, []))))]
    if kind == "literal":  # all-literal call inside a tainted map
        x = n("x")
        body = map_(ref(oids), x, _refund(t_arg, lit(o_id), _amount(draw, [])))
        return [read, expr(map_(ref(t), tk, extract, expr(body)))]
    return [_refund(lit(t_id), lit(o_id), _amount(draw, []))]  # trusted only


def _refund_rec(ticket_id: int, rec: str, draw: Draw) -> Json:
    amount = _amount(draw, [ref(rec, "refundable"), ref(rec, "amount")])
    return _refund(lit(ticket_id), ref(rec, "id"), amount)


@st.composite
def plans(draw: Draw, world: World) -> Json:
    """One to three laundering shapes in sequence."""
    names = _Names()
    steps: list[Json] = []
    for _ in range(draw(st.sampled_from([1, 1, 1, 2, 3]))):
        steps += _shape(draw, world, names)
    return plan(*steps)
