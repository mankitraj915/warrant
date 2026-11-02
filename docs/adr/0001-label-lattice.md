# 0001 Labels are sets of untrusted origins, allowed sinks and provenance

## Context

Every value a plan computes needs a label that answers two questions: may this value decide a
consequential action, and if not, where did the untrusted part come from? The first answer
drives policy; the second decides whether a declassification rule applies. The ownership rule,
for example, must accept an order id read from the case's own ticket and refuse one read from
another customer's order note, although both are equally untrusted.

## Decision

A label is `(U, S, P)` ([DESIGN §2](../DESIGN.md#2-label-lattice-d-002)):
- `U`: the set of untrusted cell origins, such as `tickets[4001].body`. Join is union; above 32
  origins it collapses to `★`.
- `S`: the sinks the value may reach. Join is intersection.
- `P`: trusted provenance, kept for the audit trace only.

A value is trusted for authority exactly when `U` is empty. Control dependence is tracked as a
separate `pc` label on each consequential action rather than joined into values. The plan
language has no `if`, and `filter` joins every predicate's label into its result
([D-003](../DECISIONS.md#d-003-control-dependence-no-if-pc-recorded-on-effects-not-values-filter-joins-all-predicates)).

## Rejected alternatives

- **One set mixing sources and origins** (`{OPERATOR, SYSTEM_DB, UNTRUSTED}` plus origins). It
  conflates what decides with what explains, and no policy ever needs OPERATOR vs SYSTEM_DB.
- **Two-point integrity** (trusted/untrusted). It is too coarse for the ownership rule: only
  origins separate the case ticket from another customer's note.
- **A decentralised label model** with owners and readers per principal. It is more expressive
  and a natural formal reading of customer ownership. But it is heavier than one rule
  justifies, and it would make the kernel harder to read in an hour.
- **Character-level string taint.** Free text never reaches a consequential argument except
  through the extractor, so typed values are enough.
- **Joining `pc` into values.** It tainted the operator's own ticket-id literal inside a refund
  `map`, so no rule keyed on "the case's ticket" could ever apply.

## Consequences

- Policies are simple set tests, and the audit trace can name every untrusted origin of every
  component.
- `pc` must be checked explicitly by every policy. A mutant that forgets it ("policy ignores
  pc") is in the mutant suite and is caught.
- The `★` collapse loses origin detail on very wide joins; any `★` component is refused by
  every rule.

## Evidence

[D-002](../DECISIONS.md#d-002-label-lattice-untrusted-origins-allowed-sinks-trusted-provenance),
[D-003](../DECISIONS.md#d-003-control-dependence-no-if-pc-recorded-on-effects-not-values-filter-joins-all-predicates);
`kernel/labels.py`; `tests/test_labels.py`, `tests/test_interpreter_labels.py`; the label
mutants in `tests/test_ni_mutants.py`.
