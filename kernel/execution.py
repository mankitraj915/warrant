"""Thin execution layer (DESIGN §10, D-022).

Each action is re-decided (in the context of the whole set) against current
state immediately before it runs; a divergence before the first effect aborts
the run, a later one stops it as partial. Refunds use the business idempotency
key ``refund:{order}:{ticket}`` and the provider is asked for the key's status
before any call.

A refund row is written as ``pending`` *before* the provider call and counts as
refunded for every policy read, so a provider failure can never leave money
moved without a record (Gate 1 review #2). If the call raises, the provider is
asked for the key's status: a committed refund is recorded and the run goes on;
otherwise the pending row is removed (or kept, if the status is unknown) and
the run stops as aborted or partial. ``recover`` reconciles rows a crash left
pending, by provider status, at the start of every run
(tests/test_execution_recovery.py injects the crash).
"""

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


def recover(db: sqlite3.Connection, provider: PaymentProvider) -> None:
    """Reconcile refund rows left ``pending`` by a crash, before any decision.

    Committed at the provider → record its reference; known not to have happened →
    delete the row; provider unreachable → leave it pending (it still counts as
    refunded, so nothing can pay the order twice)."""
    pending = db.execute(
        "SELECT idempotency_key FROM refunds WHERE provider_ref = ?", (PENDING,)
    ).fetchall()
    for (key,) in pending:
        try:
            ref = provider.status(key)
        except Exception:
            continue
        if ref is None:
            db.execute("DELETE FROM refunds WHERE idempotency_key = ?", (key,))
        else:
            db.execute("UPDATE refunds SET provider_ref = ? WHERE idempotency_key = ?", (ref, key))
    db.commit()


def execute(
    actions: Sequence[ResolvedAction],
    verdicts: Sequence[Verdict],
    db: sqlite3.Connection,
    provider: PaymentProvider,
) -> tuple[Outcome, list[Executed]]:
    done: list[Executed] = []
    for action, decided in zip(actions, verdicts, strict=True):
        now, _ = decide_one(action, actions, TrustedReader(db))
        if now.kind != decided.kind:
            return ("partial" if done else "aborted"), done
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
