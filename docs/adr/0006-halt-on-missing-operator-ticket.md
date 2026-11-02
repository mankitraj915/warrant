# 0006 A missing operator-named ticket halts the whole run

## Context

The existence taint ([0005](0005-existence-taint.md)) cost approvals on benign tasks. A refund
reached through the operator's own ticket read was decided by the ownership rule. It needed
approval whenever the customer had two eligible orders. The narrower taint was unsound, because
an empty list for a missing ticket lets existence choose between actions. The alternative noted
in D-036 was to remove the empty list for that one case.

## Decision

A `read_ticket` whose id is trusted (operator-named) and finds no row raises `ResolutionHalted`.
The run ends as `halted` during resolution, before any verdict, so nothing executes. Such a read
carries no existence origin. Reads by untrusted ids keep the origin and still return an empty
list. NI-1 is now stated only for pairs where both runs finish resolution
([DESIGN §9.3](../DESIGN.md#93-properties-for-every-well-typed-p-and-every-e1--e2)).

## Rejected alternatives

- **Keep the taint.** Approval burden stays at 5/40 benign dev tasks, for no measured security
  gain once the halt exists.
- **Halt on any missing ticket, including untrusted ids.** Untrusted text could then halt runs at
  will by naming tickets that do not exist. With the existence origin, those reads are already
  safe.

## Consequences

- **Existence can only suppress.** A missing operator-named ticket stops the whole run, which
  NI-3 permits, and can no longer choose what executes.
- **Approval burden fell from 5/40 to 3/40** on the benign dev tasks: T20 and T26 no longer ask
  ([RESULTS](../RESULTS.md#approval-burden-warrant-benign-dev-tasks)). Operator-named credits now
  execute without a human checkpoint.
- **NI-1 checks fewer pairs.** 18–22% of single-run fuzz runs halted in the adoption test, and
  NI-1 does not apply to those pairs.
- **A per-customer bound was lost.** The credit bound per customer lived in the goodwill rule,
  and plain-read credits stopped going through that rule. The adoption record called the changed
  test "equal". The Gate 3 review found the loss. The bound moved into the credit policy (P6), and
  the original probe was restored as a test
  ([D-062](../DECISIONS.md#d-062-per-customer-credit-bound-in-the-credit-policy-2026-11-02-gate-3-finding-2-issue-2)).

## Evidence

[D-054](../DECISIONS.md#d-054-d-036-variant-adopted-a-missing-operator-named-ticket-halts-the-run-phase-3-step-4),
including its adoption-test table and the per-test table of what changed;
`HALT_ON_ABSENT_TRUSTED_TICKET` in `kernel/tools/database.py`;
`tests/test_gate1_regressions.py::test_ticket_existence_can_only_suppress_a_run`; the mutant
"point read of a missing trusted ticket does not halt".
