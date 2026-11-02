# 0002 Declassification endorses parts of one action; it never relabels a value

## Context

Pure non-interference would forbid useful automation: a customer's ticket naming their own
order must sometimes lead to a refund without a human. Some untrusted influence has to be
allowed. The question is how to allow it without the permission leaking to other actions.

## Decision

A declassification rule is consulted by a policy for one action. It may endorse named
components of that action (arguments and/or `pc`), and only when their untrusted origins lie
inside an origin set the rule names
([DESIGN §6.1](../DESIGN.md#61-declassification-as-policy-time-endorsement-d-006)). Every rule
documents:
- its admission predicate, evaluated by kernel code over trusted columns;
- a **release projection**: the part of each decision that may depend on untrusted data;
- a postcondition over trusted data, checked by test code written independently of the kernel.

Every consultation is logged with its rule, site, outcome and reason. There are two rules:
`ticket_order_ownership` ([0007](0007-ownership-rule-residual-risk.md)) and
`ticket_goodwill_credit`.

## Rejected alternatives

- **An `endorse(x)` operator in the plan language** that returns a trusted value, in the style
  of a capability upgrade. An endorsed value could then be the condition of a `filter` or the
  list of a `map`, and select *other* actions. Its release would no longer be bounded by the
  rule's postcondition, and the planner would have to know when to call it.

## Consequences

- An endorsement cannot be stored and reused as trusted, except where the admitted action itself
  writes a trusted record (the refund row), which the postcondition names.
- NI-3 compares runs only up to each rule's release projection. A rule that releases more than
  it declares fails NI-3 instead of hiding behind it.
- Each rule is a named, reviewable exception. The cost is that useful patterns the rules do not
  cover go to approval; that cost is measured as approval burden.

## Evidence

[D-006](../DECISIONS.md#d-006-declassification-is-policy-time-endorsement-of-specific-action-components),
[D-015](../DECISIONS.md#d-015-ni-3-conditions-on-per-rule-release-projections-not-on-full-decisions),
[D-037](../DECISIONS.md#d-037-second-rule-ticket_goodwill_credit-phase-2-step-4);
`kernel/declassify.py`; `tests/test_rule_ownership.py`, `tests/test_rule_goodwill.py`; NI-3 and
NI-4 in `tests/ni_properties.py`.
