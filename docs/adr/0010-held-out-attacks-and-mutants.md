# 0010 Attacks and mutants held out from the people who tune

## Context

Two parts of the evidence were at risk of fitting what they measure:
- **The attacks.** The dev injections, the scripted gullible planner and the policies were all
  written together.
- **The mutants.** The fuzzer's plan shapes were adjusted while known mutants were measured. So
  "every mutant is caught" says less than it seems: the generator and the mutant list are no
  longer independent.

## Decision

**Held-out attacks**
([D-043](../DECISIONS.md#d-043-step-6-held-out-suite-and-its-results-commit-2344fbb)):
- A separate author wrote 15 injections (H01–H15), given only the threat model, the schema, the
  tool signatures and the task format, and no other repository file.
- The file was committed unmodified before any run against it, and it is never edited to change
  results.
- Holdout results are always reported separately from dev.
- A structured attacker-plan model that parses no text was added, so the attack rate does not
  depend on the scripted planner's phrasing
  ([D-052](../DECISIONS.md#d-052-attack-plans-and-the-attacker-plan-planner-phase-3-step-2-fixes-f-3)).

**Held-out mutants**
([D-057](../DECISIONS.md#d-057-held-out-mutants-at-gate-3-owner-2026-10-31)):
- At Gate 3, a separate reviewer wrote five new mutants, seeing only the design and `kernel/`:
  not the generators, the tests or the existing mutants.
- They ran at the largest k-seed designs, and the generator was not changed before the report.

## Rejected alternatives

- **Writing the held-out sets ourselves.** Whoever knows the generator or the policies writes
  attacks and mutants they already handle.
- **Showing the reviewer the existing mutants.** It would write variations of them.
- **Adapting the gullible planner to the holdout's wording.** That would be tuning against it.

## Consequences

- The holdout showed that the gullible planner was fitted to dev: the undefended baseline went
  from 393/414 on dev to 39/488 on the holdout, against 451/488 with the attacker-plan model.
  Warrant's holdout successes are 4/488, all the ownership rule's triggering case
  ([0007](0007-ownership-rule-residual-risk.md)).
- Three of the five held-out mutants were missed at every design, 108,462 examples each. The
  misses are permanent entries in RESULTS. The generator fix that followed
  ([D-070](../DECISIONS.md#d-070-generator-coverage-domain-valid-untrusted-values-2026-11-02-issue-13-step-13))
  has its post-fix result reported separately.
- Once used, a held-out set is no longer held out for the next change. New gates need fresh ones.

## Evidence

[D-043](../DECISIONS.md#d-043-step-6-held-out-suite-and-its-results-commit-2344fbb),
[F-3](../DECISIONS.md#f-3-finding-the-gullible-planners-triggers-are-fitted-to-the-dev-phrasing-owner-gate-2),
[D-057](../DECISIONS.md#d-057-held-out-mutants-at-gate-3-owner-2026-10-31),
[Gate 3 baseline](../DECISIONS.md#gate-3-baseline-stage-c-results-commit-7da1652-verified-2026-11-02);
`evals/tasks/holdout/`; `tests/heldout_mutants.py`; `scripts/mutant_rates.py heldout`.
