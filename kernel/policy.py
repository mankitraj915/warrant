"""Policies: one verdict per resolved action (DESIGN §6).

Rules every policy here obeys:
- P0 set-level constraints only tighten as actions are added;
- P1 an action with any untrusted component (an argument or the pc) is
  ALLOWed only if a declassification rule endorses it;
- P3 business invariants BLOCK whatever the labels;
- P4 amounts are checked against the policy's own recomputation.
Rules are consulted for every action with an untrusted component, before the
BLOCK checks, so whether a decision is logged depends only on labels.
"""

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Literal

from .declassify import RuleDecision, ticket_order_ownership
from .interpreter import ResolvedAction
from .labels import Label
from .tools.database import TrustedReader
from .values import plain, whole_label

Kind = Literal["ALLOW", "NEEDS_APPROVAL", "BLOCK"]
# Extension point for the mutant tests; always True in use.
PC_IS_A_COMPONENT = True


@dataclass(frozen=True)
class Verdict:
    kind: Kind
    reason: str
    rule: str | None = None


def components(action: ResolvedAction) -> dict[str, Label]:
    labels = {name: whole_label(v) for name, v in action.args.items()}
    if PC_IS_A_COMPONENT:
        labels["pc"] = action.pc
    return labels


def _describe(untrusted: dict[str, Label]) -> str:
    return "; ".join(f"{n} from {sorted(lbl.untrusted)}" for n, lbl in sorted(untrusted.items()))


def _refund_block_reason(
    action: ResolvedAction, actions: Sequence[ResolvedAction], reader: TrustedReader
) -> str | None:
    args = action.canonical_args()
    ticket, order, amount = int(args["ticket_id"]), int(args["order_id"]), int(args["amount"])
    customer = reader.ticket_customer(ticket)
    facts = reader.order(order)
    if customer is None:
        return "ticket does not exist"
    if facts is None:
        return "order does not exist"
    if facts.customer_id != customer:
        return "order does not belong to the ticket's customer"
    if amount <= 0:
        return "amount must be positive"
    refundable = reader.refundable(order)
    if amount > refundable:
        return f"amount {amount} exceeds refundable {refundable}"
    duplicates = [
        a for a in actions if a.tool == "issue_refund" and plain(a.args["order_id"]) == order
    ]
    if len(duplicates) > 1:
        return "the same order is refunded more than once in this action set"
    return None


def decide_one(
    action: ResolvedAction, actions: Sequence[ResolvedAction], reader: TrustedReader
) -> tuple[Verdict, RuleDecision | None]:
    """Verdict for one action in the context of the whole set, and any rule decision."""
    comps = components(action)
    untrusted = {n: lbl for n, lbl in comps.items() if not lbl.trusted}
    decision = ticket_order_ownership(action, comps, actions, reader) if untrusted else None
    block = _refund_block_reason(action, actions, reader)
    if block is not None:
        return Verdict("BLOCK", block), decision
    if not untrusted:
        return Verdict("ALLOW", "all components trusted"), decision
    if decision is not None and decision.admitted:
        return Verdict("ALLOW", decision.reason, decision.rule), decision
    reason = decision.reason if decision is not None else ""
    return Verdict("NEEDS_APPROVAL", f"untrusted: {_describe(untrusted)} ({reason})"), decision


def decide(
    actions: Sequence[ResolvedAction], reader: TrustedReader
) -> tuple[list[Verdict], list[RuleDecision]]:
    """Verdicts for every action, plus the log of every rule consultation."""
    verdicts: list[Verdict] = []
    log: list[RuleDecision] = []
    for action in actions:
        verdict, decision = decide_one(action, actions, reader)
        verdicts.append(verdict)
        if decision is not None:
            log.append(decision)
    return verdicts, log
