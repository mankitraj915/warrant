"""Thin execution layer (DESIGN §10, D-022).

Each action is re-decided (in the context of the whole set) against current
state immediately before it runs; a divergence before the first effect aborts
the run, a later one stops it as partial. Refunds use the business idempotency
key ``refund:{order}:{ticket}`` and the provider is asked for the key's status
before any call. Intent records
and the crash-injection test are Phase 2.
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


Outcome = Literal["executed", "aborted", "partial"]


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
        ref = provider.status(key) or provider.refund(key, order, amount)
        db.execute(
            "INSERT OR IGNORE INTO refunds (order_id, ticket_id, amount, idempotency_key,"
            " provider_ref) VALUES (?, ?, ?, ?, ?)",
            (order, ticket, amount, key, ref),
        )
        db.commit()
        done.append(Executed(action.site, action.tool, key, ref))
    return "executed", done
