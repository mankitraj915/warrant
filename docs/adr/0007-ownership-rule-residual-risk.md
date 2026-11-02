# 0007 The ownership rule, and the triggering risk it keeps

## Context

The most common support request is "refund my order #N", where N comes from the customer's
ticket, which is untrusted text. Requiring a human for every one of these defeats the purpose of
automation. Trusting the text lets an injection redirect money.

## Decision

`ticket_order_ownership` may endorse a refund's `order_id`, `amount` and `pc` when their
untrusted origins come only from the case ticket (`subject`, `body`, `@row`)
([DESIGN §6.2](../DESIGN.md#62-rule-ticket_order_ownership-proposed-the-only-phase-1-rule)). It
admits only when:
1. the order belongs to the ticket's customer;
2. the order is that customer's **single** eligible order;
3. the amount is the full refundable amount, recomputed by the rule;
4. the order has never been refunded;
5. the ticket has no other refund, in this run or any earlier one.

With the default threshold, the admitted action is a function of trusted data alone. Untrusted
text decides one bit per ticket: whether the rule admits.

## Rejected alternatives

- **A rule that also picks among several eligible orders.** No rule can tell the customer's
  genuine choice from an injected one, because both are text in the same untrusted field. These
  cases go to approval.
- **Closing the triggering risk** (below). That would need either a rule that never admits,
  which means no data-dependent automation, or task-specific logic. Both are worse than
  reporting the risk ([F-1](../DECISIONS.md#f-1-finding-the-ownership-rule-lets-ticket-text-trigger-a-refund-dev-pairs-t13i1-t13i4)).
- **A time window per customer instead of "never refunded".** It adds a parameter for no extra
  protection on this data ([D-030](../DECISIONS.md#d-030-the-ownership-rule-requires-the-order-never-to-have-been-refunded)).

## Consequences

- **Residual risk: triggering.** Injected text can turn "no refund" into an automatic refund of
  the customer's single eligible order, for its refundable amount, once per ticket. The money
  still goes only to the ticket's own customer. Every Warrant refund-attack success in both
  suites is this case: dev T13 and T33 with I1 and I4; holdout T13 and T33 with H02 and H11
  ([RESULTS](../RESULTS.md#the-three-defences-side-by-side)).
- **Residual risk: suppression.** Injected text can turn an automatic refund into an approval
  request.
- **An auto-refund cap** is a deployment parameter, default none. The sweep at 6e27f60 shows a
  cap of ₹250 or less removes these refunds (dev 5 → 1, holdout 4 → 0), at the price of 7 more
  benign approvals in 40 ([RESULTS](../RESULTS.md#the-auto-refund-cap-is-a-deployment-parameter)).

## Evidence

DESIGN §6.2; [F-1](../DECISIONS.md#f-1-finding-the-ownership-rule-lets-ticket-text-trigger-a-refund-dev-pairs-t13i1-t13i4),
[D-030](../DECISIONS.md#d-030-the-ownership-rule-requires-the-order-never-to-have-been-refunded),
[D-038](../DECISIONS.md#d-038-auto-refund-cap-is-a-rule-parameter-default-none);
`kernel/declassify.py`; `tests/test_rule_ownership.py`,
`tests/test_evals.py::test_ownership_rule_triggering_is_a_measured_residual_risk`.
