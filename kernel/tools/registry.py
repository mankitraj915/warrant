"""Plan-language types and tool signatures (part of the TCB).

Types are small frozen dataclasses so they can be compared and printed in
checker errors. Every tool the plan language can name is listed in ``TOOLS``;
there is no other way to reach a tool.
"""

from dataclasses import dataclass
from typing import Literal

ScalarName = Literal["Int", "Money", "Bool", "Str"]
IdKind = Literal["Order", "Customer", "Ticket", "Incident"]


@dataclass(frozen=True)
class TScalar:
    name: ScalarName

    def __str__(self) -> str:
        return self.name


@dataclass(frozen=True)
class TId:
    kind: IdKind

    def __str__(self) -> str:
        return f"Id[{self.kind}]"


@dataclass(frozen=True)
class TRec:
    name: str

    def __str__(self) -> str:
        return self.name


@dataclass(frozen=True)
class TList:
    item: "Type"

    def __str__(self) -> str:
        return f"List[{self.item}]"


@dataclass(frozen=True)
class TUnit:
    def __str__(self) -> str:
        return "Unit"


Type = TScalar | TId | TRec | TList | TUnit

INT, MONEY, BOOL, STR = TScalar("Int"), TScalar("Money"), TScalar("Bool"), TScalar("Str")
UNIT = TUnit()


def is_scalar(t: Type) -> bool:
    return isinstance(t, TScalar | TId)


def contains_unit(t: Type) -> bool:
    return isinstance(t, TUnit) or (isinstance(t, TList) and contains_unit(t.item))


# Row types returned by read tools. Field order is the column order.
RECORDS: dict[str, dict[str, Type]] = {
    "Ticket": {
        "id": TId("Ticket"),
        "customer_id": TId("Customer"),
        "subject": STR,
        "body": STR,
        "status": STR,
    },
    "Order": {
        "id": TId("Order"),
        "customer_id": TId("Customer"),
        "amount": MONEY,
        "status": STR,
        "placed_day": INT,
        "refundable": MONEY,
        "customer_note": STR,
    },
    # Aggregate row: orders grouped by status (groups smaller than MIN_GROUP suppressed).
    "OrderStat": {"status": STR, "orders": INT, "total": MONEY},
}

# Closed vocabularies for string arguments of consequential tools (policy-checked).
RESOLUTIONS = frozenset({"refunded", "credited", "no_action", "escalated"})
CREDIT_REASONS = frozenset({"goodwill", "late_delivery"})


@dataclass(frozen=True)
class ToolSpec:
    name: str
    params: tuple[tuple[str, Type], ...]
    result: Type
    consequential: bool
    doc: str


TOOLS: dict[str, ToolSpec] = {
    spec.name: spec
    for spec in (
        ToolSpec(
            "read_ticket",
            (("ticket_id", TId("Ticket")),),
            TList(TRec("Ticket")),
            False,
            "The ticket with this id, as a list of length 0 or 1.",
        ),
        ToolSpec(
            "query_orders",
            (("customer_id", TId("Customer")),),
            TList(TRec("Order")),
            False,
            "All orders of a customer, ordered by id, with their refundable amount.",
        ),
        ToolSpec(
            "compute_refund_amount",
            (("order_id", TId("Order")),),
            MONEY,
            False,
            "Refundable amount of an order now (0 if missing or ineligible).",
        ),
        ToolSpec(
            "extract_order_ids",
            (("text", STR),),
            TList(TId("Order")),
            False,
            "Order ids mentioned in untrusted text (quarantined extractor, at most 5).",
        ),
        ToolSpec(
            "incident_orders",
            (("incident_id", TId("Incident")),),
            TList(TRec("Order")),
            False,
            "Orders affected by a staff-recorded incident, with their refundable amount.",
        ),
        ToolSpec(
            "order_stats",
            (),
            TList(TRec("OrderStat")),
            False,
            "Order counts and totals by status (aggregate; for the operator only).",
        ),
        ToolSpec(
            "close_ticket",
            (("ticket_id", TId("Ticket")), ("resolution", STR)),
            UNIT,
            True,
            f"Close a ticket. resolution is one of {sorted(RESOLUTIONS)}.",
        ),
        ToolSpec(
            "issue_credit",
            (
                ("ticket_id", TId("Ticket")),
                ("customer_id", TId("Customer")),
                ("amount", MONEY),
                ("reason", STR),
            ),
            UNIT,
            True,
            f"Account credit for the ticket's customer. reason is one of {sorted(CREDIT_REASONS)}.",
        ),
        ToolSpec(
            "issue_refund",
            (("ticket_id", TId("Ticket")), ("order_id", TId("Order")), ("amount", MONEY)),
            UNIT,
            True,
            "Refund `amount` on an order, for the given ticket.",
        ),
    )
}


# The policy names the pc component "pc" (Gate 1 review #8).
assert all(name != "pc" for spec in TOOLS.values() for name, _ in spec.params)


def signatures() -> str:
    """Human-readable tool signatures: the planner's view of the tools."""
    lines = []
    for spec in TOOLS.values():
        params = ", ".join(f"{name}: {t}" for name, t in spec.params)
        lines.append(f"{spec.name}({params}) -> {spec.result}  # {spec.doc}")
    for name, fields in RECORDS.items():
        lines.append(f"record {name} {{{', '.join(f'{f}: {t}' for f, t in fields.items())}}}")
    return "\n".join(lines)
