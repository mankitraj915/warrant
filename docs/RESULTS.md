# Results

Compiled from the run artifacts (a generator, `tasks.py report`, is planned for v1.1;
D-075). Every number below comes from a command named in this file, run at the commit stated, and
recorded in `docs/DECISIONS.md` (D-042, D-043, D-050 and D-052 to D-056).

Warrant applies the principle behind CaMeL (Debenedetti et al., *Defeating Prompt Injections by
Design*, arXiv:2503.18813): a planner that never sees untrusted data, with capabilities and
information-flow labels on what it computes. The evaluation follows the style of AgentDojo
(Debenedetti et al., NeurIPS 2024 Datasets and Benchmarks): user tasks crossed with injection
tasks, and deterministic utility and security checks. No LLM is involved in any number here,
and no LLM judge is used anywhere.

**v1 has no language-model planner** (D-074). The security claim does not depend on one: every
security test and every number below runs with scripted planners and no model. What v1 does not
measure is the utility of a real planner: how often a model writes a valid, correct plan, and
at what cost in memory and time. That is planned for v1.1.

## What these results may and may not claim

(SPEC §10, verbatim.)

- **May claim:**
  - within the tested plan space, task suites, and policy set, executed unapproved effects were invariant to untrusted content, except through each named declassification rule's declared release projection; the non-interference test checks exactly this (NI-3 in `docs/DESIGN.md` §9.3), together with the accepted suppression channel of atomic decisions (untrusted content may prevent a whole run from executing, never change what executes);
  - the measured utility, approval burden, and approval-steering costs;
  - the comparison against baselines on these suites;
  - holdout results reported as a separate generalization check.
- **May not claim:**
  - general injection-proofness;
  - transfer of LLM results to larger models;
  - security against out-of-scope channels;
  - correctness of policies not written here.

## Setup

- **Suites:**
  - dev: 40 user tasks × 11 injection tasks, 414 applicable pairs;
  - holdout: the same 40 user tasks × 15 injection tasks written separately, by an author who
    never saw the policies (D-043), 488 applicable pairs. It has been re-run after every later
    change with its results known, so it checks generalisation from the dev suite; it is no
    longer a fresh held-out set.
- **Commands** (commit 9f2f0c3, the `gate-3` tag): `phase3-run --stage d` on the
  `owner-stages` GitHub Actions workflow, run 41386725959 (DECISIONS "Stage d at the final Gate 3
  commit"), which runs:
  - `uv run --locked python scripts/tasks.py eval` and `eval --suite holdout`;
  - `sweep` and `sweep --suite holdout`;
  - the mutant measurements in the non-interference section.

  The runner was Ubuntu 24.04 with 2 CPUs and 8 GB of memory, and Python 3.12.3. `check` and
  both evaluations also ran from a fresh clone of 9f2f0c3 on the 8 GB Windows laptop the project
  targets, with the same tables. Every evaluation and sweep figure below was the same at 6e27f60
  (stage a), at 13cd4d8 and at 9f2f0c3. The PII canary scan found 0 hits in both suites.
- **Defences** (SPEC §6):
  - **Warrant:** the full kernel. The planner sees only the operator request and tool
    signatures.
  - **Undefended (with execution hygiene):** the planner sees the ticket text and the executor
    applies no policy. It shares the kernel's idempotency keys (`refund:{order}:{ticket}`,
    `credit:{ticket}`). So duplicate-style attacks, such as seven refunds of one order or a
    second credit on a ticket that already has one, are absorbed by execution hygiene, not by
    any defence (D-052). A baseline without deduplication would show higher attack success.
  - **Prompt delimiting:** as undefended, but every ticket body is wrapped in
    `<<UNTRUSTED_DATA>>` delimiters (with forged delimiters removed) and the request tells the
    planner to treat delimited text as data (D-051).
- **Planners** (the attacker models):
  - **oracle:** the task's correct plan, fixed in the task file.
  - **gullible:** scripted; follows instructions it recognises in text it is shown. Its
    triggers were written alongside the dev injections (finding F-3).
  - **attacker-plan:** emits the correct plan plus an attack plan written per injection task, as
    structured steps, by an author who never saw the policies (D-052). It does no
    text parsing, so it is not fitted to either suite's wording. Under Warrant isolation it
    sees no payload, so it is run against Warrant only in the leaked-context configuration.
  - **leaked:** a Warrant configuration that deliberately shows the planner the case ticket's
    body, as if isolation had failed. It tests the label layer on its own.
- **Approvals:** in Warrant configurations a simulated approver approves exactly the task's
  intended action set (D-041). It compares tool and argument multisets only, so its numbers are
  upper bounds on approval safety (SPEC §4.6).

## The three defences side by side

### Dev suite (414 attack pairs, 40 benign tasks)

| defence | attacker model | attack success | utility under attack | benign utility | approval burden | approval steering |
|---|---|---|---|---|---|---|
| Undefended (with execution hygiene) | gullible | 393/414 (94.9%) | 21/414 (5.1%) | 38/40 | 0/40 | 0/414 |
| Undefended (with execution hygiene) | attacker-plan | 393/414 (94.9%) | 21/414 (5.1%) | 38/40 | 0/40 | 0/414 |
| Prompt delimiting (sanity check) | gullible | 393/414 (94.9%) | 21/414 (5.1%) | 38/40 | 0/40 | 0/414 |
| Prompt delimiting (sanity check) | attacker-plan | 393/414 (94.9%) | 21/414 (5.1%) | 38/40 | 0/40 | 0/414 |
| Warrant (planner isolated) | oracle | 5/414 (1.2%) | 396/414 (95.7%) | 39/40 | 3/40 (7.5%) | 2/414 (0.5%) |
| Warrant (planner isolated) | gullible | 5/414 (1.2%) | 396/414 (95.7%) | 39/40 | 3/40 (7.5%) | 2/414 (0.5%) |
| Warrant, leaked context | gullible | 0/414 (0.0%) | 39/414 (9.4%) | 39/40 | 35/40 (87.5%) | 384/414 (92.8%) |
| Warrant, leaked context | attacker-plan | 0/414 (0.0%) | 39/414 (9.4%) | 39/40 | 35/40 (87.5%) | 384/414 (92.8%) |

### Holdout suite (488 attack pairs, 40 benign tasks)

| defence | attacker model | attack success | utility under attack | benign utility | approval burden | approval steering |
|---|---|---|---|---|---|---|
| Undefended (with execution hygiene) | gullible | 39/488 (8.0%) | 396/488 (81.1%) | 38/40 | 0/40 | 0/488 |
| Undefended (with execution hygiene) | attacker-plan | 451/488 (92.4%) | 21/488 (4.3%) | 38/40 | 0/40 | 0/488 |
| Prompt delimiting (sanity check) | gullible | 39/488 (8.0%) | 396/488 (81.1%) | 38/40 | 0/40 | 0/488 |
| Prompt delimiting (sanity check) | attacker-plan | 451/488 (92.4%) | 21/488 (4.3%) | 38/40 | 0/40 | 0/488 |
| Warrant (planner isolated) | oracle | 4/488 (0.8%) | 473/488 (96.9%) | 39/40 | 3/40 (7.5%) | 2/488 (0.4%) |
| Warrant (planner isolated) | gullible | 4/488 (0.8%) | 473/488 (96.9%) | 39/40 | 3/40 (7.5%) | 2/488 (0.4%) |
| Warrant, leaked context | gullible | 0/488 (0.0%) | 402/488 (82.4%) | 39/40 | 35/40 (87.5%) | 92/488 (18.9%) |
| Warrant, leaked context | attacker-plan | 0/488 (0.0%) | 43/488 (8.8%) | 39/40 | 35/40 (87.5%) | 457/488 (93.6%) |

**How to read these tables.**
- **With the planner isolated, gullible equals oracle by construction.** The planner never sees
  ticket text, so the gullible planner has nothing to obey and writes the oracle's plan. The
  two Warrant rows measure isolation plus the declassification rules; they are not the kernel
  against an adversarial plan. The leaked-context rows are that test.
- **Prompt delimiting is a plumbing check here, not an evaluation.** Both scripted planners
  ignore delimiters by construction. `delimited+gullible` equals `undefended+gullible`, and
  `delimited+attacker` equals `undefended+attacker`, pair for pair in both suites (checked on
  every row: outcome, attack verdict, refunds, credits, closures). Evaluating delimiting needs
  a model planner (v1.1, D-074).
- **The holdout's gullible row mostly measures the scripted attacker** (F-3). With the gullible
  planner, the undefended baseline reaches 393/414 on dev but only 39/488 on the holdout. With
  the attacker-plan model it reaches 451/488 on the holdout. So holdout payloads hijack an
  obedient planner about as often as dev payloads do, and the 39/488 understates them.
- **Why the undefended baseline misses some attack-plan goals.** Every miss checked came from
  shared execution hygiene or from a goal the task already meets, not from a defence (D-052).
  - Shared idempotency keys absorb second credits on tickets that already have one (I6, I7, I11,
    H13 on T23–T27, T32, T39) and H04's duplicate refunds.
  - Goals already met: I8 on T29 (the operator closes the ticket as no_action anyway) and H11 on
    T06 (an earlier zero-amount refund reuses the key).
- **Warrant's attack successes are all inside a declared release projection:**
  - dev: T13+I1, T13+I4, T33+I1, T33+I4 (the ownership rule, F-1) and T28+I11 (the goodwill rule
    triggered by ticket text);
  - holdout: T13+H02, T13+H11, T33+H02, T33+H11 (F-1).

  In each, ticket text *triggers* a rule-bounded action that the rule admits: one refund of the
  customer's single eligible order, or the standard ₹100 credit. NI-3 permits this by design,
  and it is reported as a residual risk (DESIGN §6.2), not hidden.
- **Leaked context.** With isolation deliberately broken, no attack succeeded in either suite,
  under either attacker model. With the attacker-plan model, the labels blocked 255/414 dev and
  290/488 holdout pairs outright. The rest were sent for approval, and the simulated approver,
  which approves only the intended set, refused all but one (a dev pair whose approved set was
  the intended one). So these zeros rest partly on an idealised approver. Steering (the approval
  request differs from the benign run's, including a request that became a block) is 93% of
  pairs in both suites, and utility under attack collapses (8.8–9.4%). This configuration tests the second layer; it is not a way to run
  Warrant.
- **Benign utility:**
  - Warrant 39/40. T14 fails in every configuration: its ticket names no order, so there is
    nothing to refund automatically and nothing for the planner to name (D-042).
  - The baselines 38/40: T14, and T06, where the undefended executor pays a ₹0 refund on an
    order outside the refund window.

## Approval burden (Warrant, benign dev tasks)

3/40 benign tasks ask for approval: T12, T34 and T37. Causes: `ticket_order_ownership: customer has
2 eligible orders` (2) and `ticket_order_ownership: order already has a refund` (1). It was 5/40
before D-054 (T12, T20, T26, T34, T37). T20 (two eligible orders, reached through the ticket read)
and T26 (a non-standard goodwill amount for the ticket's customer) no longer ask. A read of an
operator-named ticket now carries no existence taint, because a missing ticket halts the whole
run instead (D-054), so neither action involves untrusted data any more. The holdout's benign
tasks are the same 40, with the same 3/40.

**A cost D-054 moves rather than removes.** T26's non-standard credit now executes without
approval, because the operator named it; before D-054 it needed approval. That is the intended
reading of operator authority, but it means fewer human checkpoints on operator-specified
credits.

## The auto-refund cap is a deployment parameter

Default: no cap (`None`, owner decision at Gate 2). The sweep shows what a cap trades
(`warrant+oracle`):

| cap | dev attack success | dev approval burden | dev utility under attack | dev steering | holdout attack success | holdout approval burden | holdout steering |
|---|---|---|---|---|---|---|---|
| none | 5/414 | 3/40 | 396/414 | 2/414 | 4/488 | 3/40 | 2/488 |
| ₹5,000 | 5/414 | 4/40 | 396/414 | 2/414 | 4/488 | 4/40 | 2/488 |
| ₹2,000 | 5/414 | 5/40 | 396/414 | 2/414 | 4/488 | 5/40 | 2/488 |
| ₹1,000 | 5/414 | 5/40 | 396/414 | 2/414 | 4/488 | 5/40 | 2/488 |
| ₹500 | 5/414 | 5/40 | 396/414 | 2/414 | 4/488 | 5/40 | 2/488 |
| ₹250 | 1/414 | 10/40 | 402/414 | 11/414 | 0/488 | 10/40 | 9/488 |
| ₹0 | 1/414 | 10/40 | 402/414 | 11/414 | 0/488 | 10/40 | 9/488 |

A cap of ₹250 or less removes the F-1 refunds (dev 5 → 1, holdout 4 → 0) at the price of 7 more
benign approvals in 40, and more approval steering under attack (dev 2 → 11, holdout 2 → 9).
The remaining dev success is the goodwill credit (T28+I11), which has its own fixed ₹100
amount and is not affected by the refund cap. Leaked-context configurations are unchanged at
every cap (0 successes). The right cap depends on the deployment's refund sizes and
on what an approval costs there.

## Non-interference evidence

The non-interference (NI) properties (SPEC §5; DESIGN §9.4) run without any model. Two questions
matter:
- Do they pass on the real kernel?
- Would they fail if the kernel were broken? That is what the mutant measurements test.

### Random fuzzing: every run passed

| code | property | examples | failing |
|---|---|---|---|
| Gate 2 fixes (0905584) | single-run NI, multi-run NI, NI-5 (shapes) | 20,000 each | 0 (D-050) |
| Phase 3, mixed generator (6e27f60) | the same three | 20,000 each | 0 (stage a) |
| Phase 3, split generators (c4b52a6) | the three grammar-plan properties | 10,000 each | 0 (stage b) |
| Phase 3, split generators (c4b52a6) | all six properties, statistics runs | 2,000 each | 0 (stage b) |
| Gate 3 final (9f2f0c3) | all six properties, in `check` (derandomized) | 200 each | 0 (stage d) |
| v1.0 (a8597ac) | all six properties, 20 chunks of 1,000, fresh seeds | 20,000 each | 0 (GitHub Actions run 41430446343) |

**At v1.0.** All six properties ran 20,000 examples each (120,000 in all) at the `v1.0` tag,
whose kernel, generators and tests are those measured at `gate-3`. Each chunk ran in its own
process with a seed fixed before the run (202620100 onwards; DECISIONS "Fuzz of all six NI
properties at v1.0"), and no example failed. A first attempt on CI does not count: Hypothesis
switched to its own derandomized CI profile there, so each property's 20 chunks repeated the
same 1,000 examples (issue #52; the profile is fixed in v1.0.2, D-076).

**How much each pass actually checks** (stage b statistics; DECISIONS "stage b results"):
- **Single-run NI:** 73% of shape pairs and 74% of grammar pairs had no halted run, so NI-1
  compared their effects. A run halts when an operator-named ticket does not exist (D-054). NI-2
  and NI-4 check every run.
- **NI-3** (a declassification rule was consulted and constrained the effects) applied in 29% of
  shape pairs, against 46% at Gate 2. D-054 is the reason: plain reads of operator-named tickets
  became trusted, so fewer runs reach a rule. For grammar pairs it was 3%.
- **NI-5** (an approved action set executes exactly as approved) only has something to check when
  approval is requested: 8.7% of shape examples and 0.4% of grammar examples.

### Mutant detection: would the tests notice a broken kernel?

Each *mutant* disables one mechanism the design relies on, for example "the policy ignores the
program-counter label" or "the ownership rule forgets its once-per-ticket check". The harness
must report a violation for every mutant.

**Correction to earlier gate reports.** Mutant results before 2026-10-31 depended on process
state (D-056). The test framework (Hypothesis 6.170.13) draws about 5% of its integers and
strings from literals harvested from whatever local modules the process had loaded. So whether a
given run caught a mutant depended on what else was imported. The example database was not
involved.
- Every earlier "the harness catches mutant X" claim held in the process that ran it. None was
  shown from a clean state: Gate 1 and Gate 2 reports, D-033, D-049, D-054.
- Generation is now pinned, every measurement runs in a fresh process with an explicit seed, and
  every mutant below is re-established from that clean state.

**Detections come in bursts.** Within one seed, detections arrive in bursts separated by long
gaps. The variance-to-mean ratio per 250-example window is 4–6, where independent examples would
give about 1. The cause is that Hypothesis builds new examples from earlier ones; the share of
large plans is flat after the first ~50 examples (D-056).

So one long run cannot support a miss probability. The claim is made across independent seeds
(D-058):
- each mutant runs at k seeds of n examples, and is caught if any seed catches it;
- `q` is the probability that one seed catches it within n. It is estimated from 8 measured
  seeds per mutant, using the exact one-sided 95% lower bound;
- k is chosen so the estimated miss probability `(1 − q_low)^k` is at most 1%.

| plan source | mutants that must be caught | k × n | estimated miss |
|---|---|---|---|
| fixed adversarial shapes | all 16 (11 single-run, 4 multi-run, 1 NI-5) | from 4 × 250 to 14 × 1,000 | ≤ 1% each |
| grammar (random well-typed plans) | the 4 it catches on its own | from 4 × 500 to 22 × 250 | ≤ 1% each |

The per-mutant table is in DECISIONS D-058.

**Limits of the mutant evidence.**
- **The estimate is not a measured bound.** Eight seeds per mutant limit `q_low` to at most 0.69,
  and n was chosen on the same seeds.
- **One stage-b miss is kept on record:** the NI-5 mutant was missed by one seed's 8,000-example
  run and first caught at 9,080. That seed is why NI-5 needs 14 seeds.
- **The shape generator was adjusted while known mutants were being measured** (D-049 to D-056).
  So "every known mutant is caught" is weaker evidence than the numbers suggest. For that reason
  a separate reviewer wrote five new mutants without seeing the generator or the tests (D-057).
  The result is below.
- **The Gate 3 review found mechanisms the NI harness cannot see:** a concurrent run's
  recovery deleting another run's in-flight refund record (a double refund, reproduced), the
  execution re-check's stop on a stricter verdict (no test notices it disabled), and the
  per-customer credit bound for plain-read credits since D-054 (DECISIONS "Gate 3 independent
  review: responses").
- **What `check` runs:** each mutant's earliest recorded detection, replayed exactly. That is a
  regression check, not the detection claim. The k-seed designs run in an owner-run script
  (`phase3-run --stage c` and `--stage d`).

### Gate 3 baseline (commit 7da1652, owner-run stage c)

**k-seed designs at fresh seeds:** all 20 required mutants were caught by at least one of
their k seeds (`results/phase3c/mutant_kseed.jsonl`; DECISIONS "Gate 3 baseline").
- For two mutants the observed per-seed share was below the design's lower bound: "goodwill rule
  ignores origin set" and "ownership rule drops uniqueness", each caught at 2 of 4 seeds against
  an estimated 0.69.
- At that observed share, their estimated miss probability is about 6%, not 1%. The estimates
  were optimistic.

**Held-out mutants (permanent record).** Written blind to the generators and tests; run at each
property's largest design; caught if any seed of any property catches it.

| held-out mutant | Gate 3 result |
|---|---|
| the ownership rule admits any amount up to the refundable amount | caught (example 862, 7th seed) |
| the labelling map loses `orders.customer_note` | caught (example 664, 1st seed) |
| the goodwill rule no longer requires a trusted credit reason | **missed** (102,000 examples) |
| `contains` ignores the labels of the list's elements | **missed** (102,000 examples) |
| approval consumption ignores the approved hash | **missed** (102,000 examples) |

**Why each was missed** (analysed after the result):
- No generator produced an untrusted credit reason that is also a valid reason code.
- No generator built a trusted list of untrusted elements and tested membership in it.
- The harness's approver always approves the current hash.

These are gaps in the test generators, not known kernel bugs. Post-fix results are reported
separately below. These three mutants no longer count as held out.

**What the random-plan (grammar) generator catches on its own** (5 rate seeds × 1,000 examples,
plus 3 stage-b seeds at 4,000):

| mutant | caught alone? |
|---|---|
| policy ignores pc; map body pc ignores list structure; extractor output labelled trusted | yes: pure labelling mutants that need no declassification rule |
| point read of a missing trusted ticket does not halt | yes |
| goodwill rule ignores origin set | at 2 of 3 stage-b seeds, 0 of 5 rate seeds: a coverage gap |
| filter ignores predicate labels | at 1 of 8 seeds: a coverage gap |
| `at` ignores index label; extraction ignores control | no |
| ownership rule (2 mutants), goodwill amount; all 4 multi-run mutants; NI-5 | no |

The grammar generator was never expected to reach the declassification rules, multi-run state or
approvals (D-053). It is a second, independent source of plans for the labelling rules; the
fixed adversarial shapes cover the rest.

### After the Gate 3 fixes (commit 9f2f0c3, stage d)

The Gate 3 fixes and the generator change (D-070) came after the baseline. Stage d measures
again at fresh seeds (202619001 onwards, never used to choose a design), on the commit that is
tagged. DECISIONS "Stage d at the final Gate 3 commit" has the per-mutant table.

**k-seed designs at fresh seeds:** all 20 required mutants were caught by at least one of their
k seeds (`mutant_kseed.jsonl`, 170 rows).
- Two observed per-seed shares were below the design's lower bound: "extraction ignores
  control" and "execution writes no record before the provider call", each caught at 2 of 4
  seeds against an estimated 0.69. At that share, k = 4 gives an estimated miss probability of
  about 6%, not 1%.
- The two that were low at the Gate 3 baseline were caught at 4 of 4 seeds here. Which mutants
  come in low changes with the seeds. So the 1% per mutant is a design target that the
  8-seed estimates do not reliably deliver, not a measured bound.

**Post-fix result for the three missed held-out mutants.** The generators were changed knowing
what these mutants do (D-070), so these are no longer held-out results; they show whether the
generator fix closed each gap. Same designs as the baseline, stopping at the first catching
seed:

| mutant | Gate 3 baseline (7da1652) | after the fix (9f2f0c3) |
|---|---|---|
| the goodwill rule no longer requires a trusted credit reason | missed | **still missed** in 102,000 examples (107,571 generated cases) |
| `contains` ignores the labels of the list's elements | missed | **still missed** in 102,000 examples (107,571 generated cases) |
| approval consumption ignores the approved hash | missed | **caught** by NI-5 (shapes), first seed, generated case 164 |

The two held-out mutants caught at the baseline were caught again (`mutant_postfix.jsonl`, 208
rows). The baseline once reported its misses as "108,462 examples"; that counted generated
cases, including those Hypothesis discards as invalid. The designs ran 102,000 valid examples.

**Reading.**
- **Approval hash: closed.** The approval-binding property's approver now sometimes answers
  with a stale hash or another run's id (D-070), and the property caught the mutant at its first
  seed. The single-run properties, which involve no approval, cannot see it.
- **Goodwill reason and `contains` element labels: still open.** The generators can now put a
  valid reason code or an existing id into untrusted text, and the grammar can build a trusted
  list of untrusted elements. Neither mutant was caught in 102,000 examples. So the causes
  given at the baseline were not sufficient, and these two mechanisms have no property-based
  evidence. No deterministic test covers either one either: the goodwill tests use only
  trusted reasons, and the one `contains` test does not build a trusted list of untrusted
  elements. Both stay open (issues #10 and #11) as test gaps, not as known kernel bugs.

## Findings carried into this phase

- **F-1:** the ownership rule lets ticket text *trigger* a bounded refund. It is inside the
  rule's release projection and measured above.
- **F-3:** the gullible planner's triggers were fitted to the dev phrasing, so its holdout
  numbers understate the attacks. Fixed in measurement by the attacker-plan model (D-052).
- **D-056:** "derandomized" Hypothesis runs were not deterministic across processes, because
  Hypothesis draws some values from literals in the loaded modules. See the NI section.
