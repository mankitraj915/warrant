# 0003 A run's whole action set is decided and executed as one unit

## Context

A plan can produce many consequential actions, for example a bulk refund. Some may be allowed,
some may need approval, some may be blocked. The kernel has to decide what executes.

## Decision

The interpreter resolves every consequential call into an ordered list `A` before anything
executes. `A` executes only if every action is ALLOW, or a human approved the hash of exactly
`A`. Any BLOCK executes nothing
([DESIGN §5](../DESIGN.md#5-evaluation-model-d-005)).

Before the first effect, every action is decided again against current state, and any change in
either direction aborts the run with nothing executed. Between effects, the run stops (as
`partial`) only if a verdict became stricter. A verdict that relaxes cannot authorise anything
outside a set that was already authorised
([D-045](../DECISIONS.md#d-045-execution-pre-pass-then-a-re-check-that-stops-only-on-a-stricter-verdict-finding-4)).

## Rejected alternatives

- **Execute the ALLOW subset and ask approval for the rest.** Better utility for bulk refunds.
  But the human would approve a remainder whose meaning depends on what already ran, and the
  executed set would no longer be the hashed set.
- **Fix NI-3 ad hoc once the fuzzer showed atomicity breaks it.** The Gate 0 review showed that,
  as first written, NI-3 was false under atomic decisions. One tainted action in a `map` can stop
  a fully trusted refund in the same run. Weakening the property after seeing the failure was
  rejected; it was restated before any implementation
  ([D-014](../DECISIONS.md#d-014-keep-atomic-decisions-restate-ni-3-to-admit-whole-run-suppression-only)).
- **Re-deciding later actions against a predicted post-effect state.** That would reimplement
  effect semantics inside the policy path, for no safety gain over the monotone rule.

## Consequences

- **Suppression is accepted.** Outside each declassification rule's declared release, untrusted
  data can stop a whole run (outcome blocked or needs approval), but cannot change what
  executes. NI-3 states exactly this, and THREAT_MODEL §6
  names whole-run suppression as out of scope. Plans run one per ticket to limit how much one
  ticket can hold up.
- An attacker who gets one action of a batch blocked holds up the batch. This is measured as
  utility under attack.
- Plans should filter ineligible items with trusted predicates before acting.

## Evidence

[D-005](../DECISIONS.md#d-005-resolve-the-whole-action-set-first-decide-atomically),
[D-014](../DECISIONS.md#d-014-keep-atomic-decisions-restate-ni-3-to-admit-whole-run-suppression-only),
[D-045](../DECISIONS.md#d-045-execution-pre-pass-then-a-re-check-that-stops-only-on-a-stricter-verdict-finding-4);
`kernel/run.py`, `kernel/execution.py`; `tests/test_approval_binding.py`
(`test_state_change_while_deciding_aborts`), `tests/test_midrun_recheck.py`; NI-3 and NI-5.
