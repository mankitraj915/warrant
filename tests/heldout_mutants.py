"""Held-out mutants (D-057), written without seeing the test harness."""

import sqlite3
from collections.abc import Sequence
from typing import Any

import kernel.approval
import kernel.declassify
import kernel.interpreter
import kernel.policy
import kernel.run
import kernel.tools.database
from kernel.declassify import GOODWILL, OWNERSHIP, RuleDecision, _case_ticket_origins
from kernel.labels import Label
from kernel.tools.database import GOODWILL_AMOUNT, TrustedReader
from kernel.values import ListV, Record, Scalar, Value, plain

# ---------------------------------------------------------------------------------
# 1. ownership_amount_at_most_refundable
# Bug: the ownership rule's amount check was "relaxed" from
# ``amount != refundable`` to ``amount > refundable`` ("let the rule admit partial
# refunds too"). The amount of an admitted refund can now be any value in
# [1, refundable], so untrusted ticket text can choose the refund amount.
# Everything else is a faithful copy of kernel.declassify.ticket_order_ownership.


def _ownership_partial_ok(
    action: Any,
    components: dict[str, Label],
    actions: Sequence[Any],
    reader: TrustedReader,
) -> RuleDecision:
    def decision(admitted: bool, reason: str) -> RuleDecision:
        return RuleDecision(OWNERSHIP, action.site, admitted, reason)

    if action.tool != "issue_refund":
        return decision(False, "rule applies to issue_refund only")
    if not components["ticket_id"].trusted:
        return decision(False, "ticket_id is untrusted")
    args = action.canonical_args()
    ticket, order, amount = int(args["ticket_id"]), int(args["order_id"]), int(args["amount"])
    case_ticket = _case_ticket_origins(ticket)
    for name, label in components.items():
        if not label.untrusted <= case_ticket:
            return decision(False, f"{name} has untrusted origins outside ticket {ticket}")

    customer = reader.ticket_customer(ticket)
    facts = reader.order(order)
    if customer is None or facts is None or facts.customer_id != customer:
        return decision(False, "order does not belong to the ticket's customer")
    eligible = reader.eligible_orders(customer)
    if order not in eligible:
        return decision(False, "order is not eligible for a refund")
    if kernel.declassify.REQUIRE_UNIQUE_ELIGIBLE and len(eligible) != 1:
        return decision(False, f"customer has {len(eligible)} eligible orders")
    if reader.order_has_refund(order):
        return decision(False, "order already has a refund")
    if amount > reader.refundable(order):  # MUTATION: was `!=`
        return decision(False, "amount exceeds the refundable amount")
    cap = kernel.declassify.AUTO_REFUND_CAP
    if cap is not None and amount > cap:
        return decision(False, f"amount {amount} exceeds the auto-refund cap {cap}")
    if any(
        other is not action
        and other.tool == "issue_refund"
        and plain(other.args["ticket_id"]) == ticket
        for other in actions
    ):
        return decision(False, "another refund for this ticket is in the action set")
    if reader.ticket_has_refund(ticket):
        return decision(False, "this ticket already has a refund")
    return decision(True, "eligible order of the ticket's customer, within refundable")


# ---------------------------------------------------------------------------------
# 2. goodwill_reason_not_required_trusted
# Bug: the goodwill rule's trusted-precondition loop dropped "reason" ("the
# reason is enum-checked by the BLOCK policy anyway"). An untrusted reason that
# happens to be a valid enum member (e.g. the ticket subject "late_delivery") is
# now endorsed, so ticket text parameterizes the credit's reason, which is
# written to the credits table. Otherwise a faithful copy of
# kernel.declassify.ticket_goodwill_credit.


def _goodwill_untrusted_reason(
    action: Any,
    components: dict[str, Label],
    actions: Sequence[Any],
    reader: TrustedReader,
) -> RuleDecision:
    def decision(admitted: bool, reason: str) -> RuleDecision:
        return RuleDecision(GOODWILL, action.site, admitted, reason)

    if action.tool != "issue_credit":
        return decision(False, "rule applies to issue_credit only")
    for name in ("ticket_id", "amount"):  # MUTATION: "reason" dropped
        if not components[name].trusted:
            return decision(False, f"{name} is untrusted")
    args = action.canonical_args()
    ticket, customer = int(args["ticket_id"]), int(args["customer_id"])
    allowed = _case_ticket_origins(ticket)
    for name, label in components.items():
        if not label.untrusted <= allowed:
            return decision(False, f"{name} has untrusted origins outside ticket {ticket}")
    if reader.ticket_customer(ticket) != customer:
        return decision(False, "credit is not for the ticket's customer")
    if int(args["amount"]) != GOODWILL_AMOUNT:
        return decision(False, f"amount is not the standard goodwill credit {GOODWILL_AMOUNT}")
    if any(
        other is not action
        and other.tool == "issue_credit"
        and plain(other.args["ticket_id"]) == ticket
        for other in actions
    ):
        return decision(False, "another credit for this ticket is in the action set")
    if any(
        other is not action
        and other.tool == "issue_credit"
        and plain(other.args["customer_id"]) == customer
        for other in actions
    ):
        return decision(False, "another credit for this customer is in the action set")
    if reader.ticket_has_credit(ticket):
        return decision(False, "this ticket already has a credit")
    if reader.customer_has_credit(customer):
        return decision(False, "this customer already has a credit")
    return decision(True, "standard goodwill credit to the ticket's customer")


# ---------------------------------------------------------------------------------
# 3. contains_ignores_element_labels
# Bug: in the interpreter, `contains` labels its result with the list's
# structure label only ("membership is about the list's structure"), not
# struct ⊔ every element. A map result list has a trusted structure but
# element labels from untrusted cells, so `contains` over it launders them.
# Patched as kernel.interpreter.whole_label, which the interpreter uses (by
# global name) only in `contains` and in ResolvedAction.component_labels;
# consequential arguments are scalars, so the latter is unaffected.


def _outer_label_only(v: Value) -> Label:
    if isinstance(v, Scalar | Record | ListV):
        return v.label
    return Label()


# ---------------------------------------------------------------------------------
# 4. order_note_labelled_trusted
# Bug: the labelling map Λ lost the `orders` entry (for example during a schema
# refactor that moved customer_note handling elsewhere), so
# `orders.customer_note`, attacker-writable free text, is read as trusted.

_LAMBDA_WITHOUT_ORDER_NOTE: dict[str, frozenset[str]] = {
    "tickets": frozenset({"subject", "body"}),
    "customers": frozenset({"display_name"}),
}


# ---------------------------------------------------------------------------------
# 5. approval_hash_not_compared
# Bug: `_consume` was "simplified" on the reasoning that the approvals row is
# keyed by run and was inserted with the request's hash, so the explicit
# `approval.hash != hash_` comparison looked redundant; the UPDATE now matches
# on run_id and status only. Any approval naming this run is honoured,
# whatever hash it approved, so the executed set need not match the approved hash.


def _consume_ignoring_hash(
    db: sqlite3.Connection, approval: kernel.approval.Approval, run_id: str, hash_: str
) -> str | None:
    if approval.run_id != run_id:
        return "approval was issued for another run"
    used = db.execute(
        "UPDATE approvals SET status = 'consumed' WHERE run_id = ? AND status = 'requested'",
        (run_id,),
    )
    db.commit()
    return None if used.rowcount == 1 else "approval already used"


HELDOUT: dict[str, list[tuple[Any, str, Any]]] = {
    "ownership_amount_at_most_refundable": [
        (kernel.policy, "ticket_order_ownership", _ownership_partial_ok),
        (kernel.declassify, "ticket_order_ownership", _ownership_partial_ok),
    ],
    "goodwill_reason_not_required_trusted": [
        (kernel.policy, "ticket_goodwill_credit", _goodwill_untrusted_reason),
        (kernel.declassify, "ticket_goodwill_credit", _goodwill_untrusted_reason),
    ],
    "contains_ignores_element_labels": [
        (kernel.interpreter, "whole_label", _outer_label_only),
    ],
    "order_note_labelled_trusted": [
        (kernel.tools.database, "UNTRUSTED_COLUMNS", _LAMBDA_WITHOUT_ORDER_NOTE),
    ],
    "approval_hash_not_compared": [
        (kernel.run, "_consume", _consume_ignoring_hash),
    ],
}
