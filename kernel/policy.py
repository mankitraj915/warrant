"""Policies: one verdict per resolved action (DESIGN §6).

Rules every policy here obeys:
- P0 set-level constraints only tighten as actions are added;
- P1 an action with any untrusted component (an argument or the pc) is
  ALLOWed only if a declassification rule endorses it;
- P3 business invariants BLOCK whatever the labels;
- P4 amounts are checked against the policy's own recomputation;
- P5 every component, pc included, must be allowed to flow to the action's sink
  (`customer:C`); aggregates may flow only to the operator.
Rules are consulted for every action with an untrusted component, before the
BLOCK checks, so whether a decision is logged depends only on labels.
"""

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Literal

from .declassify import RuleDecision, ticket_goodwill_credit, ticket_order_ownership
from .interpreter import ResolvedAction
from .labels import Label
from .tools.database import CREDIT_MAX, TrustedReader
from .tools.registry import CREDIT_REASONS, RESOLUTIONS
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


def _customer_of(action: ResolvedAction, reader: TrustedReader) -> int | None:
    """The customer a customer-facing action affects: the ticket's customer."""
    return reader.ticket_customer(int(action.canonical_args()["ticket_id"]))


def _sink_block_reason(action: ResolvedAction, reader: TrustedReader) -> str | None:
    """P5: every component (pc included) must be allowed to flow to the action's sink."""
    sink = f"customer:{_customer_of(action, reader)}"
    for name, label in components(action).items():
        if label.sinks is not None and sink not in label.sinks:
            return f"{name} may flow only to {sorted(label.sinks)}, not to sink {sink}"
    return None


def _same_tool(action: ResolvedAction, actions: Sequence[ResolvedAction], key: str) -> int:
    value = plain(action.args[key])
    return sum(1 for a in actions if a.tool == action.tool and plain(a.args[key]) == value)


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
    if reader.refund_exists(order, ticket):  # Gate 1 review #7: never a silent no-op
        return "this order was already refunded for this ticket"
    if _same_tool(action, actions, "order_id") > 1:
        return "the same order is refunded more than once in this action set"
    return None


def _close_block_reason(
    action: ResolvedAction, actions: Sequence[ResolvedAction], reader: TrustedReader
) -> str | None:
    args = action.canonical_args()
    status = reader.ticket_status(int(args["ticket_id"]))
    if status is None:
        return "ticket does not exist"
    if status != "open":
        return "ticket is already closed"
    if args["resolution"] not in RESOLUTIONS:
        return f"resolution must be one of {sorted(RESOLUTIONS)}"
    if _same_tool(action, actions, "ticket_id") > 1:
        return "the same ticket is closed more than once in this action set"
    return None


def _credit_block_reason(
    action: ResolvedAction, actions: Sequence[ResolvedAction], reader: TrustedReader
) -> str | None:
    args = action.canonical_args()
    ticket, customer, amount = int(args["ticket_id"]), int(args["customer_id"]), int(args["amount"])
    owner = reader.ticket_customer(ticket)
    if owner is None:
        return "ticket does not exist"
    if customer != owner:
        return "credit must go to the ticket's customer"
    if amount <= 0:
        return "amount must be positive"
    if amount > CREDIT_MAX:
        return f"amount {amount} exceeds the credit limit {CREDIT_MAX}"
    if args["reason"] not in CREDIT_REASONS:
        return f"reason must be one of {sorted(CREDIT_REASONS)}"
    if reader.ticket_has_credit(ticket):
        return "this ticket already has a credit"
    if _same_tool(action, actions, "ticket_id") > 1:
        return "more than one credit for this ticket in this action set"
    return None


_BLOCK_REASONS = {
    "issue_refund": _refund_block_reason,
    "close_ticket": _close_block_reason,
    "issue_credit": _credit_block_reason,
}


def _block_reason(
    action: ResolvedAction, actions: Sequence[ResolvedAction], reader: TrustedReader
) -> str | None:
    return _sink_block_reason(action, reader) or _BLOCK_REASONS[action.tool](
        action, actions, reader
    )


def decide_one(
    action: ResolvedAction, actions: Sequence[ResolvedAction], reader: TrustedReader
) -> tuple[Verdict, RuleDecision | None]:
    """Verdict for one action in the context of the whole set, and any rule decision."""
    comps = components(action)
    untrusted = {n: lbl for n, lbl in comps.items() if not lbl.trusted}
    rule = {"issue_refund": ticket_order_ownership, "issue_credit": ticket_goodwill_credit}.get(
        action.tool
    )
    decision = rule(action, comps, actions, reader) if untrusted and rule else None
    block = _block_reason(action, actions, reader)
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
