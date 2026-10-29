"""Declassification rules: policy-time endorsement of one action (DESIGN §6.1).

A rule never relabels a value. Consulted by a policy for one action, it may
endorse that action's untrusted components, and every consultation is logged
as a ``RuleDecision`` whether it admits or not.

Rule ``ticket_order_ownership`` (DESIGN §6.2): an order id read from a ticket
may target a refund only when it is that ticket's customer's single eligible
order, for its full refundable amount, once per ticket ever.

- Release (theta = 0): one bit per ticket, whether the rule admits. The admitted
  action itself is a function of trusted data. Release projection:
  ``(rule, site, admitted)``.
- Residual risk: injected text can suppress the run (route it to approval or
  block it); it cannot redirect the refund.
"""

from collections.abc import Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING

from .labels import Label, cell_origin
from .tools.database import TrustedReader
from .values import plain

if TYPE_CHECKING:
    from .interpreter import ResolvedAction

OWNERSHIP = "ticket_order_ownership"
# Extension point for the mutant and residual-risk tests; always True in use.
REQUIRE_UNIQUE_ELIGIBLE = True


@dataclass(frozen=True)
class RuleDecision:
    rule: str
    site: tuple[int, ...]
    admitted: bool
    reason: str


def ticket_order_ownership(
    action: "ResolvedAction",
    components: dict[str, Label],
    actions: Sequence["ResolvedAction"],
    reader: TrustedReader,
) -> RuleDecision:
    """Decide whether the ownership rule endorses this ``issue_refund``."""

    def decision(admitted: bool, reason: str) -> RuleDecision:
        return RuleDecision(OWNERSHIP, action.site, admitted, reason)

    if action.tool != "issue_refund":
        return decision(False, "rule applies to issue_refund only")
    if not components["ticket_id"].trusted:
        return decision(False, "ticket_id is untrusted")
    args = action.canonical_args()
    ticket, order, amount = int(args["ticket_id"]), int(args["order_id"]), int(args["amount"])
    case_text = {cell_origin("tickets", ticket, c) for c in ("subject", "body")}
    for name, label in components.items():
        if not label.untrusted <= case_text:
            return decision(False, f"{name} has untrusted origins outside ticket {ticket}")

    customer = reader.ticket_customer(ticket)
    facts = reader.order(order)
    if customer is None or facts is None or facts.customer_id != customer:
        return decision(False, "order does not belong to the ticket's customer")
    eligible = reader.eligible_orders(customer)
    if order not in eligible:
        return decision(False, "order is not eligible for a refund")
    if REQUIRE_UNIQUE_ELIGIBLE and len(eligible) != 1:
        return decision(False, f"customer has {len(eligible)} eligible orders")
    if amount != reader.refundable(order):
        return decision(False, "amount is not the full refundable amount")
    if any(
        other is not action
        and other.tool == "issue_refund"
        and plain(other.args["ticket_id"]) == ticket
        for other in actions
    ):
        return decision(False, "another refund for this ticket is in the action set")
    if reader.ticket_has_refund(ticket):
        return decision(False, "this ticket already has a refund")
    return decision(True, "unique eligible order of the ticket's customer, full amount")
