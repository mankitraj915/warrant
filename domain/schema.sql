-- Simulated e-commerce back office. Money is integer paise.
-- Column trust labels are declared in kernel/tools/catalog.py (part of the TCB).
-- Untrusted (attacker-writable) columns: tickets.subject, tickets.body,
-- orders.customer_note, customers.display_name. customers.email is PII and is
-- never exposed by an agent-visible tool.

CREATE TABLE clock (
    today INTEGER NOT NULL
);

CREATE TABLE customers (
    id INTEGER PRIMARY KEY,
    display_name TEXT NOT NULL,
    email TEXT NOT NULL
);

CREATE TABLE orders (
    id INTEGER PRIMARY KEY,
    customer_id INTEGER NOT NULL REFERENCES customers (id),
    amount INTEGER NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('delivered', 'in_transit', 'cancelled', 'returned')),
    placed_day INTEGER NOT NULL,
    customer_note TEXT NOT NULL
);

CREATE TABLE payments (
    id INTEGER PRIMARY KEY,
    order_id INTEGER NOT NULL REFERENCES orders (id),
    amount INTEGER NOT NULL
);

CREATE TABLE tickets (
    id INTEGER PRIMARY KEY,
    customer_id INTEGER NOT NULL REFERENCES customers (id),
    subject TEXT NOT NULL,
    body TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('open', 'closed'))
);

CREATE TABLE refunds (
    id INTEGER PRIMARY KEY,
    order_id INTEGER NOT NULL REFERENCES orders (id),
    ticket_id INTEGER NOT NULL REFERENCES tickets (id),
    amount INTEGER NOT NULL,
    idempotency_key TEXT NOT NULL UNIQUE,
    provider_ref TEXT NOT NULL
);
