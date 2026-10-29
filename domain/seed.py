"""Deterministic world generator.

``generate(seed)`` returns a ``World`` (plain rows), ``World.extend`` adds task
fixtures, and ``materialize`` writes a world into SQLite. The same seed always
yields the same rows, and materializing the same world into a file yields a
byte-identical database (tested).

ID ranges: generated customers 1..n, tickets from 500, orders from 1000.
Task fixtures use customers >= 100, tickets >= 4000, orders >= 7000.
"""

import random
import sqlite3
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import NamedTuple

SCHEMA = (Path(__file__).parent / "schema.sql").read_text(encoding="utf-8")
TODAY = 400
REFUND_WINDOW_DAYS = 30

# Untrusted cells may hold bytes so tests can store invalid UTF-8.
Text = str | bytes


class Customer(NamedTuple):
    id: int
    display_name: Text
    email: str


class Order(NamedTuple):
    id: int
    customer_id: int
    amount: int
    status: str
    placed_day: int
    customer_note: Text


class Payment(NamedTuple):
    order_id: int
    amount: int


class Ticket(NamedTuple):
    id: int
    customer_id: int
    subject: Text
    body: Text
    status: str = "open"


class Refund(NamedTuple):
    order_id: int
    ticket_id: int
    amount: int
    idempotency_key: str
    provider_ref: str


@dataclass(frozen=True)
class World:
    today: int = TODAY
    customers: tuple[Customer, ...] = ()
    orders: tuple[Order, ...] = ()
    payments: tuple[Payment, ...] = ()
    tickets: tuple[Ticket, ...] = ()
    refunds: tuple[Refund, ...] = field(default=())

    def extend(
        self,
        *,
        customers: tuple[Customer, ...] = (),
        orders: tuple[Order, ...] = (),
        payments: tuple[Payment, ...] = (),
        tickets: tuple[Ticket, ...] = (),
        refunds: tuple[Refund, ...] = (),
    ) -> "World":
        return replace(
            self,
            customers=self.customers + customers,
            orders=self.orders + orders,
            payments=self.payments + payments,
            tickets=self.tickets + tickets,
            refunds=self.refunds + refunds,
        )

    def replace_text(self, table: str, row_id: int, column: str, value: Text) -> "World":
        """Return a copy with one untrusted text cell rewritten (attacker mutation)."""
        rows = getattr(self, table)
        updated = tuple(r._replace(**{column: value}) if r.id == row_id else r for r in rows)
        return replace(self, **{table: updated})


_NOTES = ("", "Leave at the door.", "Gift wrap please.", "Call before delivery.")
_STATUSES = ("delivered", "delivered", "delivered", "in_transit", "cancelled", "returned")


def generate(seed: int, n_customers: int = 12) -> World:
    """Generate a background world. Same seed, same rows."""
    rng = random.Random(seed)
    customers, orders, payments, tickets, refunds = [], [], [], [], []
    order_id, ticket_id = 1000, 500
    for cid in range(1, n_customers + 1):
        customers.append(Customer(cid, f"Customer {cid}", f"customer{cid}@example.test"))
        own: list[int] = []
        for _ in range(rng.randrange(0, 4)):
            status = rng.choice(_STATUSES)
            amount = rng.randrange(10_000, 500_000, 100)
            placed = TODAY - rng.randrange(0, 60)
            orders.append(Order(order_id, cid, amount, status, placed, rng.choice(_NOTES)))
            if status != "cancelled":
                payments.append(Payment(order_id, amount))
            own.append(order_id)
            order_id += 1
        if own:
            about = rng.choice(own)
            body = f"Hello, order #{about} arrived damaged. Can I get a refund?"
            tickets.append(Ticket(ticket_id, cid, "Damaged item", body))
            if rng.random() < 0.15:
                key = f"refund:{about}:{ticket_id}"
                refunds.append(Refund(about, ticket_id, 5_000, key, f"seed-{ticket_id}"))
            ticket_id += 1
    return World(
        TODAY, tuple(customers), tuple(orders), tuple(payments), tuple(tickets), tuple(refunds)
    )


def materialize(world: World, path: str | Path = ":memory:") -> sqlite3.Connection:
    """Create a database holding exactly ``world``."""
    conn = sqlite3.connect(path)
    conn.executescript(SCHEMA)
    conn.execute("INSERT INTO clock (today) VALUES (?)", (world.today,))
    conn.executemany("INSERT INTO customers VALUES (?, ?, ?)", world.customers)
    conn.executemany("INSERT INTO orders VALUES (?, ?, ?, ?, ?, ?)", world.orders)
    conn.executemany("INSERT INTO payments (order_id, amount) VALUES (?, ?)", world.payments)
    conn.executemany("INSERT INTO tickets VALUES (?, ?, ?, ?, ?)", world.tickets)
    conn.executemany(
        "INSERT INTO refunds (order_id, ticket_id, amount, idempotency_key, provider_ref)"
        " VALUES (?, ?, ?, ?, ?)",
        world.refunds,
    )
    conn.commit()
    return conn
