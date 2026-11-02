# What went wrong

The mistakes, wrong turns and weak evidence found while building Warrant, and what each changed.
Each paragraph links to the record that has the details and the commands. Numbers are from the
runs named there.

## 60,000 fuzz examples passed while three real bugs went unseen

At commit fc55a2c, the chunked fuzz passed 20,000 examples for each of the three
non-interference properties, 60,000 in all, with no failure. The Gate 2 review then found three
real bugs in that same code:
- two ways extraction under untrusted control could launder labels;
- trusted actions on a second ticket of the case customer.

The fuzzer could not have found any of them, because its fixed plan shapes never
produced those plans. A passing fuzz run is evidence about the shapes it samples and nothing
more. That led to new shapes, a grammar-based plan generator, and mutant tests that require
the harness to fail on a deliberately broken kernel.
([Gate 2 review](DECISIONS.md#gate-2-review-2026-10-30), [GATE2_REVIEW.md](reviews/GATE2_REVIEW.md) finding 3,
[D-053](DECISIONS.md#d-053-grammar-based-plan-generator-for-the-ni-fuzzer-phase-3-step-3))

## Hypothesis harvested literals from whatever modules were loaded

At commit 6e27f60, a mutant test caught its mutant inside `check` but missed it when the same
test ran alone. The obvious suspect was a stale example database; it was ruled out first.

The cause was a property-testing library feature:
- Hypothesis 6.170.13 draws about 5% of its integers and strings from a pool of literals.
- That pool is harvested from every local module the process has imported.
- So under `derandomize=True`, the same test generated different examples depending on import
  order: a 295-literal pool missed the mutant, and a 649-literal pool caught it.

Every mutant result before 2026-10-31 had depended on process state. Generation is now pinned
to the seed (`tests/determinism.py`), each measurement runs in a fresh process with an explicit
seed, and the earlier gate claims it affected were corrected in RESULTS.
([D-056](DECISIONS.md#d-056-mutant-results-depended-on-process-state-clean-state-mutant-tests-split-ni-properties-2026-10-31))

## The scripted attacker was fitted to the dev suite: 393/414 against 39/488

Without a defence, the scripted "gullible" planner was hijacked in 393 of 414 dev attack pairs,
but in only 39 of 488 holdout pairs. The holdout injections were not weaker:
- The planner obeys only phrasings it was written alongside: a refund, credit or close verb
  together with an agent-addressed cue.
- The holdout's injections, written separately, mostly use other phrasings, so the 39/488 measured the
  script, not the attacks.

A structured attacker-plan model, which parses no text, was added. It reaches 451/488 against
the undefended baseline on the holdout. The gullible planner was deliberately not adapted to
the holdout's wording, because that would be tuning against it.
([F-3](DECISIONS.md#f-3-finding-the-gullible-planners-triggers-are-fitted-to-the-dev-phrasing-owner-gate-2),
[D-052](DECISIONS.md#d-052-attack-plans-and-the-attacker-plan-planner-phase-3-step-2-fixes-f-3),
[RESULTS](RESULTS.md#the-three-defences-side-by-side))

## Two rules for mutant budgets were disproved before the k-seed design

The first rule, `ln(1000)/p` examples, assumed each generated example is an independent trial.
Its guard (a seed with no detection means a coverage gap) fired on three mutants. Every one of
those seeds did catch its mutant when run longer, just later. Detections come in bursts, which is
consistent with Hypothesis building each example from earlier ones.

The second rule added a warm-up: `W + ln(1000)/p`, rounded up. At the first fresh seed tested,
the NI-5 mutant was missed at its 8,000-example budget, and it was first detected at example
9,080. The burst analysis had predicted misses of this size.

The final design treats a seed, not an example, as the independent unit:
- k independent seeds of n examples each;
- k chosen from a lower confidence bound on the per-seed catch rate.

The miss at seed 202617002 stays in the record.
([D-056 budgets](DECISIONS.md#d-056-mutant-results-depended-on-process-state-clean-state-mutant-tests-split-ni-properties-2026-10-31),
[stage b results](DECISIONS.md#phase-3-owner-run-stage-b-results-commit-c4b52a6-verified-2026-11-01),
[D-058](DECISIONS.md#d-058-mutant-detection-as-k-independent-seeds-owner-2026-11-01-final-redesign))

## A double refund that only a reviewer found

The Gate 3 reviewer started a second run on the same database while a refund was in flight:
1. The second run's recovery step deleted the first run's pending refund row.
2. The payment provider then committed the refund.
3. The kernel's attempt to record it matched no row, and the run still reported success.
4. A later ticket naming the same order was admitted by the ownership rule, so an order paid
   120,000 was refunded 240,000.

Nothing in the design stated whether two processes may share a database, and no test ran two
runs at once. The fix is a per-database run lock held from recovery to the final audit row,
plus a loud failure when a refund record goes missing. The concurrency model is now stated in
DESIGN §10 and THREAT_MODEL §6.
([GATE3_REVIEW.md](reviews/GATE3_REVIEW.md) finding 1,
[D-061](DECISIONS.md#d-061-single-writer-run-lock-2026-11-02-gate-3-finding-1-issue-1),
`tests/test_concurrency.py`)

## A held-out mutant no generator could reach

At Gate 3, a reviewer who saw only the design and the kernel wrote five new mutants. The fuzzer
missed three of them at every design, 102,000 examples each. One of these was approval
consumption that ignores the approved hash:
- The approval-binding property's approver always answered with the right hash for the right
  run.
- So no generated run could ever present a mismatched approval, and the mutant was invisible
  to the property, however long it ran.
- Unit tests covered replay and cross-run use, but the property could not.

The fix changed the generators: untrusted text can now be a valid reason code or an existing
id, the grammar can build a trusted list of untrusted elements, and the approver sometimes
answers with a stale hash or another run's id. Afterwards the approval mutant was caught at
the first seed. The other two were still missed in 102,000 examples, so the cause given for them
was not sufficient. No deterministic test covers either mechanism. They are open, and the three
Gate 3 misses stay in RESULTS as permanent entries.
([D-057](DECISIONS.md#d-057-held-out-mutants-at-gate-3-owner-2026-10-31),
[Gate 3 baseline](DECISIONS.md#gate-3-baseline-stage-c-results-commit-7da1652-verified-2026-11-02),
[D-070](DECISIONS.md#d-070-generator-coverage-domain-valid-untrusted-values-2026-11-02-issue-13-step-13))

## The T08 hypothesis that turned out wrong

Dev task T08 was costing approvals, because reading a ticket by an operator-supplied id
carried the ticket's existence as untrusted. The hypothesis, raised at Gate 1, was that a point read of a trusted id
does not need that taint: existence could only suppress a whole run, which the invariant
allows.

It does not hold. The existence bit becomes a value: how many times a `map` body runs, a `len`,
an `at` index. That value chooses between two different refunds, and both versions of the run execute
with no rule involved. The
taint was kept, and the cost stood as measured.

The cost was later removed another way. A point read of a trusted id that finds no row now
halts the run, so existence can only suppress (D-054). That change had its own cost: it quietly
removed a per-customer bound, which the next review found.
([D-036](DECISIONS.md#d-036-point-reads-of-a-trusted-ticket-id-keep-the-existence-taint-t08-hypothesis-rejected),
[D-054](DECISIONS.md#d-054-d-036-variant-adopted-a-missing-operator-named-ticket-halts-the-run-phase-3-step-4),
[D-062](DECISIONS.md#d-062-per-customer-credit-bound-in-the-credit-policy-2026-11-02-gate-3-finding-2-issue-2))

## The leaked-context result is weaker than it looks

The leaked-context configuration deliberately shows the planner the ticket text, as if
isolation had failed, to test the label layer alone. It reported 0 attack successes in both
suites, under both attacker models. That says less than it seems to:
- **Gullible planner.** It obeys few holdout phrasings, so its holdout zero would have been
  low anyway.
- **What actually stops the attacks.** Under leaked context the plan label taints every
  literal. With the attacker-plan model the kernel blocked 290 of 488 holdout pairs outright and
  sent the other 198 for approval, where the simulated approver, which approves only the
  intended set, refused every one.
- **The cost.** 93.6% of holdout pairs were steered (their approval request differs from the
  benign run's), and utility under attack fell to 8.8%. With a real human approver, the 198
  would depend on that human.

The zero shows that labels block or route to a person everything an attack plan does when
isolation fails. It does not
show that labels alone are a practical defence.
([F-3](DECISIONS.md#f-3-finding-the-gullible-planners-triggers-are-fitted-to-the-dev-phrasing-owner-gate-2),
[RESULTS](RESULTS.md#the-three-defences-side-by-side))

## A CI fuzz run that repeated the same examples twenty times

The first fuzz of the six non-interference properties at v1.0 (GitHub Actions run 41429151228)
passed every chunk, and none of it counts. On a CI runner, Hypothesis 6.170.13 loads its own
`ci` profile, which sets `derandomize=True`. The project's `fuzz` profile did not set
`derandomize`, so it inherited `True` and ignored each chunk's seed. Every chunk of a property
ran the same 1,000 examples: 20,000 reported examples were really 1,000.

Nothing failed, so no check flagged it. It was caught by reading the per-chunk statistics:
all 20 chunks of each property reported identical counts, for example 1,000 passing and 29
invalid in every single-run shape chunk. Chunks with different seeds should not agree like that.

The rerun (run 41430446343) unset the CI variables and first checked that the loaded `fuzz`
profile had `derandomize=False`; all six jobs printed it. The chunks' statistics then differed
(13 to 18 distinct invalid counts per property), and all 120,000 examples passed. Earlier large
fuzz runs were local and the mutant measurements fix their own seeds, so neither was affected.
The profile fix and a test that fails if the `fuzz` profile is ever derandomized are
[issue #52](https://github.com/mankitraj915/warrant/issues/52).
([Fuzz at v1.0](DECISIONS.md#fuzz-of-all-six-ni-properties-at-v10-github-actions-run-41430446343-verified-2026-11-02-issue-49))
