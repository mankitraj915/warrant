# Process

How the work was organised, so the evidence can be weighed with its method in view.

## Phases and gates

The work followed the phases in [SPEC.md](SPEC.md). Each phase ended at a gate, where the
results were reported in a fixed template and the owner decided whether to continue, change
direction or stop. Gate outcomes are recorded in [DECISIONS.md](DECISIONS.md) ("Gate N
outcome").

## Independent review at every gate

Before each gate report, a separate reviewer received the threat model, the design and the code.
At Gate 3 it also received the specification, the earlier reviews, and three extracts about the
mutant evidence that the owner asked it to check (listed in DECISIONS, "Gate 3 independent
review: responses"). No gate reviewer saw the evaluation results. Its job was to break the
invariant. Each report is kept verbatim in [docs/reviews/](reviews/), and every finding has a
written response in DECISIONS: fixed, accepted with its cost stated, or disputed with reasons.
Every review found real problems. At Gate 0, before any code, one property as first stated was
false under the design's own semantics. At Gate 3 the review found the double refund described
in [WHAT_WENT_WRONG](WHAT_WENT_WRONG.md#a-double-refund-that-only-a-reviewer-found). The fixes were
themselves reviewed again ([GATE3_FIX_REVIEW](reviews/GATE3_FIX_REVIEW.md)).

## Tests before code, and tests that must fail first

- **Invariant tests first.** The rule was that tests for the invariant itself
  (non-interference, the declassification rules and approval binding) are written before the
  code they test. A test written afterwards tends to encode the implementation's assumptions.
- **Regression tests fail on the old code.** Every regression test must fail on the commit
  before its fix. Continuous integration checks this on every pull request
  (`scripts/new_tests_fail_on_base.py`). A test of code that was already correct must instead
  fail with the bug reintroduced as a named mutant.
- **Blocking checks are findings.** When a check blocked a legitimate task, that was recorded
  as a finding. The check was not weakened to get green.

## Measurements

- **Every number is traceable.** Each number in RESULTS names the command, the commit and where
  the output is recorded.
- **Heavy runs are scripted.** Memory-heavy runs (long fuzzing, k-seed mutant runs, held-out
  runs) go through one script, `tasks.py phase3-run`, or a manual CI workflow. Each step's log
  is kept.
- **Held-out sets are written separately.** The held-out injections were written by an author
  who never saw the policies. The held-out mutants were written by one who never saw the
  generators or the tests, and saw the existing mutants only as the design names them. Both are
  reported separately. Once a held-out result is known, it no longer counts as held out for
  later changes: the generator fix designed after three held-out mutant misses has its result
  reported as post-fix, not held out ([ADR 0010](adr/0010-held-out-attacks-and-mutants.md)).
- **Bad results stay in the record.** When a measurement design was disproved, the design was
  changed and the failed run kept ([ADR 0009](adr/0009-k-independent-seeds.md)). Results that
  show a real cost are reported, not smoothed over.

## Changes

- **One change per issue.** Each change has an issue, a branch and a pull request, merged with a
  merge commit. Commit messages say why the change was made.
- **Decisions are written down.** Any decision that is not obvious goes into DECISIONS with the
  alternatives rejected. The [ADRs](adr/) summarise the ten that shape the kernel.
