"""Thin execution layer (DESIGN §10, D-022).

Before the first effect every action is re-decided (in the context of the
whole set) against current state, and any divergence aborts the run with
nothing executed. During execution the run's own earlier effects change state
legitimately (a refund can make another order the unique eligible one), so
each later action is re-decided again just before it runs and stops the run
as partial only if its verdict became *stricter* (Gate 2 review #4). Refunds
use the business idempotency key ``refund:{order}:{ticket}`` and the provider
is asked for the key's status before any call.

A refund row is written as ``pending`` *before* the provider call and counts as
refunded for every policy read, so a provider failure can never leave money
moved without a record (Gate 1 review #2). If the call raises, the provider is
asked for the key's status: a committed refund is recorded and the run goes on;
otherwise the pending row is removed (or kept, if the status is unknown) and
the run stops as aborted or partial. ``recover`` reconciles rows a crash left
pending, by provider status, at the start of every run
(tests/test_execution_recovery.py injects the crash).
"""

import json
import sqlite3
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Literal, Protocol

from .interpreter import ResolvedAction
from .policy import Verdict, decide_one
from .tools.database import TrustedReader


class PaymentProvider(Protocol):
    def refund(self, idempotency_key: str, order_id: int, amount: int) -> str: ...

    def status(self, idempotency_key: str) -> str | None: ...


@dataclass(frozen=True)
class Executed:
    site: tuple[int, ...]
    tool: str
    idempotency_key: str
    provider_ref: str


Outcome = Literal["executed", "aborted", "partial", "indeterminate"]
PENDING = "pending"
# Extension point for the mutant tests; always True in use. False restores the
# pre-Gate-1 behaviour: record only after the provider confirms, so a failure
# after the provider committed loses the record.
PENDING_FIRST = True


class _Unknown:
    """The provider could not say whether a refund happened."""


UNKNOWN = _Unknown()


def _execute_local(action: ResolvedAction, db: sqlite3.Connection) -> Executed | None:
    """Effects that only write this database (no provider): one transaction each.
    None if the write's precondition no longer holds (another writer got there
    after the re-check): the ticket is not open, or it already has a credit."""
    args = action.canonical_args()
    ticket = int(args["ticket_id"])
    if action.tool == "close_ticket":
        key = f"close:{ticket}"
        changed = db.execute(
            "UPDATE tickets SET status = 'closed', resolution = ? WHERE id = ? AND status = 'open'",
            (args["resolution"], ticket),
        ).rowcount
    else:
        assert action.tool == "issue_credit"
        key = f"credit:{ticket}"
        changed = db.execute(
            "INSERT OR IGNORE INTO credits"
            " (ticket_id, customer_id, amount, reason, idempotency_key) VALUES (?, ?, ?, ?, ?)",
            (ticket, int(args["customer_id"]), int(args["amount"]), args["reason"], key),
        ).rowcount
    db.commit()
    return Executed(action.site, action.tool, key, "local") if changed == 1 else None


def recover(db: sqlite3.Connection, provider: PaymentProvider) -> None:
    """Reconcile refund rows left ``pending`` by a crash, before any decision.

    Committed at the provider → record its reference; known not to have happened →
    delete the row; provider unreachable → leave it pending (it still counts as
    refunded, so nothing can pay the order twice)."""
    pending = db.execute(
        "SELECT idempotency_key FROM refunds WHERE provider_ref = ?", (PENDING,)
    ).fetchall()
    reconciled: list[dict[str, str | None]] = []
    for (key,) in pending:
        try:
            ref = provider.status(key)
        except Exception:
            reconciled.append({"key": key, "result": "unknown; left pending"})
            continue
        if ref is None:
            db.execute("DELETE FROM refunds WHERE idempotency_key = ?", (key,))
            reconciled.append({"key": key, "result": "not at provider; removed"})
        else:
            db.execute("UPDATE refunds SET provider_ref = ? WHERE idempotency_key = ?", (ref, key))
            reconciled.append({"key": key, "result": f"committed at provider as {ref}"})
    if reconciled:  # every reconciliation is audited (Gate 2 review #5)
        record = json.dumps({"phase": "recover", "reconciled": reconciled}, sort_keys=True)
        db.execute("INSERT INTO audit (run_id, record) VALUES ('recover', ?)", (record,))
    db.commit()


_STRICTNESS = {"ALLOW": 0, "NEEDS_APPROVAL": 1, "BLOCK": 2}


def execute(
    actions: Sequence[ResolvedAction],
    verdicts: Sequence[Verdict],
    db: sqlite3.Connection,
    provider: PaymentProvider,
) -> tuple[Outcome, list[Executed]]:
    for action, decided in zip(actions, verdicts, strict=True):
        now, _ = decide_one(action, actions, TrustedReader(db))
        if now.kind != decided.kind:
            return "aborted", []
    done: list[Executed] = []
    for action, decided in zip(actions, verdicts, strict=True):
        if done:
            now, _ = decide_one(action, actions, TrustedReader(db))
            if _STRICTNESS[now.kind] > _STRICTNESS[decided.kind]:
                return "partial", done
        if action.tool != "issue_refund":
            local = _execute_local(action, db)
            if local is None:
                return ("partial" if done else "aborted"), done
            done.append(local)
            continue
        args = action.canonical_args()
        ticket, order, amount = int(args["ticket_id"]), int(args["order_id"]), int(args["amount"])
        key = f"refund:{order}:{ticket}"
        if not PENDING_FIRST:
            try:
                confirmed = provider.status(key) or provider.refund(key, order, amount)
            except Exception:
                return ("partial" if done else "aborted"), done
            db.execute(
                "INSERT INTO refunds (order_id, ticket_id, amount, idempotency_key, provider_ref)"
                " VALUES (?, ?, ?, ?, ?)",
                (order, ticket, amount, key, confirmed),
            )
            db.commit()
            done.append(Executed(action.site, action.tool, key, confirmed))
            continue
        db.execute(
            "INSERT INTO refunds (order_id, ticket_id, amount, idempotency_key, provider_ref)"
            " VALUES (?, ?, ?, ?, ?)",
            (order, ticket, amount, key, PENDING),
        )
        db.commit()
        ref = _call_provider(provider, key, order, amount)
        if ref is None:  # known not to have happened
            db.execute("DELETE FROM refunds WHERE idempotency_key = ?", (key,))
            db.commit()
        if isinstance(ref, _Unknown):
            return "indeterminate", done
        if ref is None:
            return ("partial" if done else "aborted"), done
        db.execute("UPDATE refunds SET provider_ref = ? WHERE idempotency_key = ?", (ref, key))
        db.commit()
        done.append(Executed(action.site, action.tool, key, ref))
    return "executed", done


def _call_provider(
    provider: PaymentProvider, key: str, order: int, amount: int
) -> str | _Unknown | None:
    """The provider reference; None if the refund is known not to have happened;
    ``UNKNOWN`` if the provider cannot say (the pending row then stays and blocks
    any later refund of the order until Phase 2 recovery reconciles it)."""
    try:
        return provider.status(key) or provider.refund(key, order, amount)
    except Exception:
        try:
            return provider.status(key)
        except Exception:
            return UNKNOWN
