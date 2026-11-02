# 0004 An approval binds one run id and the hash of the exact action set

## Context

When a set of actions needs a human, the human's yes must authorise that set and nothing else:
not a later run with the same actions, not a set that changed after it was shown, and not a set
whose labels differ from what the human saw.

## Decision

The kernel builds a canonical object `{"run_id", "actions": [...]}`. Each action carries its
tool, arguments, per-component untrusted origins (including `pc`) and verdict. The approval
binds `(run_id, SHA-256 of the canonical JSON)`
([DESIGN §7](../DESIGN.md#7-approval-binding)). It is single-use and is marked consumed in the
same write as the run's intent records, before the first provider call. Before executing, the
kernel recomputes the hash of the set it is about to execute, and any mismatch aborts with
nothing executed. The approval view is rendered from the hashed object, so the human sees every
component's origins.

## Rejected alternatives

- **Hash of the action set alone.** An approval for "refund order 1007, ₹1,299" could be
  replayed in a later run that produced the same set
  ([D-013](../DECISIONS.md#d-013-approval-records-bind-the-run-and-are-single-use)).
- **Hashing the verdict reasons as well.** Reasons explain; labels and verdicts authorise.
  Hashing free text would invalidate pending approvals whenever a message was reworded, without
  any change to what executes
  ([D-023](../DECISIONS.md#d-023-verdict-reasons-are-not-hashed-supersedes-part-of-d-018)).

## Consequences

- An approval is worthless outside its run and set: a stale hash or another run's id executes
  nothing. The demo shows the stale case (`tasks.py demo`, section 1b).
- A run id is spent once its run starts, even if the run fails (D-067).
- Evaluation uses a simulated approver that approves exactly the intended set. It is an
  idealised human, so the measured approval safety is an upper bound, reported next to the
  approval-steering rate.

## Evidence

[D-013](../DECISIONS.md#d-013-approval-records-bind-the-run-and-are-single-use),
[D-018](../DECISIONS.md#d-018-approval-object-includes-labels-pc-and-reasons-ni-5-covers-approval),
[D-023](../DECISIONS.md#d-023-verdict-reasons-are-not-hashed-supersedes-part-of-d-018);
`kernel/approval.py`; `tests/test_approval_binding.py` (NI-5, with an approver that sometimes
answers with a stale hash or another run's id since
[D-070](../DECISIONS.md#d-070-generator-coverage-domain-valid-untrusted-values-2026-11-02-issue-13-step-13));
`docs/demo_transcript.txt`.
