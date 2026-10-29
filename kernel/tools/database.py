"""Database access: column labelling, read tools, and the policy read API.

``UNTRUSTED_COLUMNS`` is the labelling map Λ (DESIGN §2.1): these columns are
attacker-writable; every other column readable here is trusted. Row-level PII
(``customers.email``) is not readable through this module at all.

``Database`` implements the read tools and labels what they return.
``TrustedReader`` is the only interface policies and rules get, and it exposes
trusted columns only.
"""

import sqlite3
from dataclasses import dataclass

from ..labels import Label
from ..values import ListV, Record, Scalar, Value

UNTRUSTED_COLUMNS: dict[str, frozenset[str]] = {
    "tickets": frozenset({"subject", "body"}),
    "orders": frozenset({"customer_note"}),
    "customers": frozenset({"display_name"}),
}
REFUND_WINDOW_DAYS = 30
MAX_LIST = 100


def lossless_text(raw: bytes) -> str:
    """sqlite3 text factory: invalid UTF-8 written by an attacker cannot raise."""
    return raw.decode("utf-8", errors="replace")


def _cell(table: str, key: int, column: str, value: object) -> Scalar:
    if isinstance(value, bytes):  # a BLOB stored in an untrusted text column
        value = lossless_text(value)
    if column in UNTRUSTED_COLUMNS.get(table, frozenset()):
        label = Label.untrusted_cell(table, key, column)
    else:
        label = Label.trusted_source(f"db:{table}.{column}")
    assert isinstance(value, int | str)
    return Scalar(value, label)


@dataclass(frozen=True)
class OrderFacts:
    customer_id: int
    status: str


class TrustedReader:
    """Policy read API: trusted columns only (review finding 11)."""

    def __init__(self, db: sqlite3.Connection) -> None:
        self._db = db

    def ticket_customer(self, ticket_id: int) -> int | None:
        row = self._db.execute("SELECT customer_id FROM tickets WHERE id = ?", (ticket_id,))
        found = row.fetchone()
        return None if found is None else int(found[0])

    def order(self, order_id: int) -> OrderFacts | None:
        row = self._db.execute(
            "SELECT customer_id, status FROM orders WHERE id = ?", (order_id,)
        ).fetchone()
        return None if row is None else OrderFacts(int(row[0]), str(row[1]))

    def refundable(self, order_id: int) -> int:
        """Paid minus refunded, if delivered within the refund window; else 0."""
        row = self._db.execute(
            "SELECT o.status, c.today - o.placed_day,"
            " (SELECT COALESCE(SUM(amount), 0) FROM payments WHERE order_id = o.id),"
            " (SELECT COALESCE(SUM(amount), 0) FROM refunds WHERE order_id = o.id)"
            " FROM orders o, clock c WHERE o.id = ?",
            (order_id,),
        ).fetchone()
        if row is None:
            return 0
        status, age, paid, refunded = row
        if status != "delivered" or age > REFUND_WINDOW_DAYS:
            return 0
        return max(0, int(paid) - int(refunded))

    def eligible_orders(self, customer_id: int) -> list[int]:
        rows = self._db.execute(
            "SELECT id FROM orders WHERE customer_id = ? ORDER BY id", (customer_id,)
        )
        return [int(i) for (i,) in rows if self.refundable(int(i)) > 0]

    def ticket_has_refund(self, ticket_id: int) -> bool:
        row = self._db.execute("SELECT 1 FROM refunds WHERE ticket_id = ?", (ticket_id,))
        return row.fetchone() is not None


class Database:
    """Read tools. Each result's structure label is the label of the arguments
    that selected it; selection here only reads trusted key columns."""

    def __init__(self, db: sqlite3.Connection) -> None:
        self._db = db
        self.trusted = TrustedReader(db)

    def read_ticket(self, ticket_id: Scalar) -> ListV:
        row = self._db.execute(
            "SELECT id, customer_id, subject, body, status FROM tickets WHERE id = ?",
            (ticket_id.value,),
        ).fetchone()
        records: tuple[Value, ...] = ()
        if row is not None:
            names = ("id", "customer_id", "subject", "body", "status")
            fields = {n: _cell("tickets", row[0], n, v) for n, v in zip(names, row, strict=True)}
            records = (Record(fields, ticket_id.label),)
        return ListV(records, ticket_id.label)

    def query_orders(self, customer_id: Scalar) -> ListV:
        rows = self._db.execute(
            "SELECT id, customer_id, amount, status, placed_day, customer_note"
            " FROM orders WHERE customer_id = ? ORDER BY id LIMIT ?",
            (customer_id.value, MAX_LIST),
        ).fetchall()
        names = ("id", "customer_id", "amount", "status", "placed_day", "customer_note")
        records: list[Value] = []
        for row in rows:
            fields = {n: _cell("orders", row[0], n, v) for n, v in zip(names, row, strict=True)}
            fields["refundable"] = Scalar(
                self.trusted.refundable(row[0]), Label.trusted_source("kernel:refundable")
            )
            records.append(Record(fields, customer_id.label))
        return ListV(tuple(records), customer_id.label)

    def compute_refund_amount(self, order_id: Scalar) -> Scalar:
        """Computed from trusted columns of the row ``order_id`` selects."""
        return Scalar(self.trusted.refundable(int(order_id.value)), order_id.label)
