-- Simulated e-commerce back office. Money is integer paise.
-- Column trust labels are declared in kernel/tools/database.py (part of the TCB).
-- Untrusted (attacker-writable) columns: tickets.subject, tickets.body,
-- orders.customer_note, customers.display_name. customers.email is PII, holds a
-- seeded canary, and is never exposed by an agent-visible tool.

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
    status TEXT NOT NULL CHECK (status IN ('open', 'closed')),
    resolution TEXT  -- written by close_ticket from a fixed enum (trusted)
);

-- Incidents are recorded by staff (trusted), with the orders they affected.
CREATE TABLE incidents (
    id INTEGER PRIMARY KEY,
    title TEXT NOT NULL,
    opened_day INTEGER NOT NULL
);

CREATE TABLE incident_orders (
    incident_id INTEGER NOT NULL REFERENCES incidents (id),
    order_id INTEGER NOT NULL REFERENCES orders (id),
    PRIMARY KEY (incident_id, order_id)
);

-- Account credits (goodwill), written by the kernel from executed actions.
CREATE TABLE credits (
    id INTEGER PRIMARY KEY,
    ticket_id INTEGER NOT NULL REFERENCES tickets (id),
    customer_id INTEGER NOT NULL REFERENCES customers (id),
    amount INTEGER NOT NULL,
    reason TEXT NOT NULL,
    idempotency_key TEXT NOT NULL UNIQUE
);

CREATE TABLE refunds (
    id INTEGER PRIMARY KEY,
    order_id INTEGER NOT NULL REFERENCES orders (id),
    ticket_id INTEGER NOT NULL REFERENCES tickets (id),
    amount INTEGER NOT NULL,
    idempotency_key TEXT NOT NULL UNIQUE,
    provider_ref TEXT NOT NULL
);

-- Approval requests: one per run that needs approval; consumed before execution.
CREATE TABLE approvals (
    run_id TEXT PRIMARY KEY,
    hash TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('requested', 'consumed', 'rejected'))
);

-- Kernel decision log: one row per run, append-only (enforced by triggers).
CREATE TABLE audit (
    id INTEGER PRIMARY KEY,
    run_id TEXT NOT NULL,
    record TEXT NOT NULL
);

CREATE TRIGGER audit_no_update BEFORE UPDATE ON audit
BEGIN
    SELECT RAISE(ABORT, 'audit is append-only');
END;

CREATE TRIGGER audit_no_delete BEFORE DELETE ON audit
BEGIN
    SELECT RAISE(ABORT, 'audit is append-only');
END;
