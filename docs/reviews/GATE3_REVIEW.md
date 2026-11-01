# Gate 3 independent review (Warrant, branch phase3-wip, commit 6fd8e31)

**Scope.** I read `docs/THREAT_MODEL.md`, `docs/DESIGN.md`, all of `kernel/` (including
`kernel/tools/`), `domain/schema.sql`, `domain/payment_mock.py`, `planners/fuzz.py`,
`planners/grammar_fuzz.py`, `planners/builders.py`, part of `planners/oracle.py`, and from
`tests/`: `ni_properties.py`, `test_noninterference.py`, `test_approval_binding.py`,
`test_ni_mutants.py`, `determinism.py`, `support.py`, `conftest.py`,
`test_interpreter_labels.py`, `test_point_read_existence.py`, parts of
`test_gate1_regressions.py`, `test_gate2_regressions.py`, `test_rule_goodwill.py` and
`test_evals.py`, and the mutant sections of `docs/reviews/GATE1_REVIEW.md` and
`GATE2_REVIEW.md`. I also read the three gate3 extracts. I did not read `docs/DECISIONS.md`,
`docs/RESULTS.md` or `results/`. **Disclosure:** a `grep -n partial tests/*.py` printed four
lines of the tracked file `tests/heldout_mutants.py` (lines 21, 27, 183, 184: an ownership-rule
mutant that accepts partial amounts). I did not open the file, and nothing below uses it.

**What I ran.** All commands were run from the repo root. I did not modify any repository
file; `git status --short` was empty at the end. Scratch files are in
`scratchpad/gate3/rev/`. To keep `__pycache__` out of the repo I set
`PYTHONDONTWRITEBYTECODE=1`, and every scratch script calls `tests.determinism.pin_generation()`
(or goes through `tests/conftest.py`).

- `uv run --locked pytest -p no:cacheprovider tests/test_ni_mutants.py -q`: 21 passed, 31 s.
- `narrow_mutants.py`: additional and narrowed mutants, run through the repository's own
  `_run_property` (clean state, explicit seeds 9101–9103, `n` = 1,500, shapes source).
- `test_recover_race.py`, `test_d054_probes.py`, `test_midrun_stricter.py`,
  `test_inrun_customer_bound.py`: deterministic probes.
- Small pytest plugins (`plug/*.py`) that apply one mutation before the repository's
  own tests run: `-p never_stops_plugin`, `-p no_prepass_plugin`, `-p phase12_plugin`, and
  the filter, at and body-pc label mutants.

---

## Findings (invariant)

### 1. HIGH (reproduced): a concurrent run's `recover()` deletes an in-flight refund's pending row; the record is lost and the ownership rule admits a second automatic refund of the same order

**Mechanism.**
- `execute` commits the `pending` refund row before the provider call
  (`kernel/execution.py:553-559`).
- Every `run_plan` starts with `recover(env.db, env.provider)` (`kernel/run.py:432`).
  `recover` deletes every pending row whose key the provider does not yet know
  (`kernel/execution.py:490-502`). That includes a row belonging to a run in another
  process that is between its pending insert and its provider call.
- The provider then commits the money. `UPDATE refunds SET provider_ref = ? WHERE
  idempotency_key = ?` matches zero rows, and the rowcount is not checked
  (`kernel/execution.py:567-569`). The run reports `executed`, with an `Executed` entry
  for a refund that has no record.
- Every later policy and rule read sees the order as never refunded:
  `order_has_refund`, `ticket_has_refund` and `refundable` in
  `kernel/tools/database.py:85-113` all read the `refunds` table.
- So the next ticket that names the order is admitted automatically by
  `ticket_order_ownership` (`kernel/declassify.py:79-94`), under a new idempotency key
  `refund:7000:4002`. The provider's key deduplication does not help.

**Reproduction** (`scratchpad/gate3/rev/test_recover_race.py::test_recover_race_loses_record_and_rule_pays_twice`).
- Setup: case world, ticket 4000 says "Refund #7000", and 7000 is the unique eligible order.
- The provider subclass starts another `run_plan` on the same database inside its first
  `refund()` call, before committing. This is the interleaving two processes sharing the
  database would produce.
- Output:
  ```
  run-1 executed ['ticket_order_ownership'] (Executed(... key='refund:7000:4000', provider_ref='pay-1'),)
  refund rows after run-1: []
  run-2 executed ['ticket_order_ownership'] ["unique eligible order of the ticket's customer, full amount"]
  provider effects: [(7000, 120000, 'refund:7000:4000'), (7000, 120000, 'refund:7000:4002')]
  ```
- Order 7000 was paid 120,000 and refunded 240,000. The second refund was triggered by
  ticket text and admitted by a logged rule decision.

**Why it matters for the invariant.**
- Clause (a) holds only while the rule releases what DESIGN §6.2 says it releases: an
  admitted refund "is the first refund ever recorded for that order".
- Here the rule's never-refunded and once-per-ticket predicates read a record that the
  kernel itself lost. Ticket text then triggers money movement beyond the declared release.

**Why nothing catches it.**
- The NI-4 oracle uses the kernel's own `refunds` table as ground truth for "order already
  had a refund" (`tests/ni_properties.py:155-158`), so it passes on run 2.
- Only the multirun "refunded more than paid" check, which reads `provider.effects`, would
  fire. The harness never runs two runs concurrently.

**Severity.** HIGH if more than one process may run against one database. DESIGN §5 and §10
explicitly reason about "another writer", and nothing serializes runs. MEDIUM if a single
process is a stated deployment assumption, but I found that assumption nowhere in
DESIGN/THREAT_MODEL.

**Related hypothesis (not reproduced; it needs true threads).** No transaction spans the
pre-pass, the between-effects re-check and the pending insert (`kernel/execution.py:521-558`).
Two concurrent runs on two tickets of one customer can both pass their re-checks for the same
order before either inserts its pending row, and both then pay. The refunds table's only
uniqueness is the key `refund:{order}:{ticket}`, which differs between the two runs.

### 2. MEDIUM (reproduced): D-054 silently undoes the Gate 2 #6 per-customer bound for plain-read credits; the original probe F now executes four automatic credits

**Mechanism.**
- Since D-054, a credit to an operator-named ticket's customer that involves no ticket text
  is fully trusted (`kernel/tools/database.py:150-154`). `decide_one` therefore ALLOWs it
  without consulting `ticket_goodwill_credit` (`kernel/policy.py:310-315`).
- The per-customer bound lives only in that rule (`kernel/declassify.py:141-153`). The
  credit's P3 checks are per ticket only (`kernel/policy.py:279-282`).

**Reproduction** (`test_d054_probes.py::test_gate2_probe_f_original_form_now_executes_four_credits`).
- Gate 2 probe F exactly as first written: `builders.credit_ticket_customer(t)` on the case
  ticket plus 4002, 4003 and 4004, all opened by customer 100.
- Output: `['executed', 'executed', 'executed', 'executed']` and four credits of 10,000 to
  customer 100.

**Assessment.**
- Under D-054's model this is not a formal violation: the operator named each ticket. But
  Gate 2 #6's whole argument was that customers open tickets freely, so a per-ticket bound
  is no per-customer bound. That argument applies unchanged whenever the operator's workflow
  is "resolve each new ticket". The attacker controls how many tickets exist, and THREAT_MODEL
  §3 still lists ticket existence as attacker-influenced.
- The D-054 table marks the probe-F test "Equal". Its input was changed to text-triggered
  credits, so the original probe, which now succeeds, is no longer run anywhere.
- This should be recorded as a cost of D-054 (and the T26 approval-burden "benefit" is the
  same effect seen from the other side), or the per-customer bound should move into the
  credit policy's P3 checks.

### 3. MEDIUM (reproduced; harness gap): the "stop on a stricter verdict between effects" check is untested; a mutant that never stops passes the whole suite and double-pays

**Mechanism.** `kernel/execution.py:526-530` re-decides each later action and stops on a
stricter verdict. The NI-5 mutant reverses `_STRICTNESS`. It is detected only through its
*relaxation* half, a spurious partial that the NI-5 harness flags at
`tests/test_approval_binding.py:162`. The other half, a real stricter verdict that must stop
the run, cannot arise in the harness: a set's own effects cannot make a later action stricter
(duplicates are already BLOCKed set-wide), and there is no concurrent writer.

**Reproduction.**
- Mutant: `_STRICTNESS` all 0 (`plug/never_stops_plugin.py`). Run against
  `tests/test_gate1_regressions.py`, `test_gate2_regressions.py`, `test_execution_recovery.py`
  and `test_approval_binding.py`: 28 passed, 0 failed. Run against the whole suite (minus
  `test_ni_mutants.py`): 229 of 229 tests passed (pytest exit code 0, with derandomized
  `check`-profile NI properties included). No test in the repository detects this mutant.
- My test `test_midrun_stricter.py`:
  - Setup: an approved two-refund set, and another writer refunds 7001 in full while the
    provider processes 7000.
  - Real kernel: `partial [(7000, 120000)]`.
  - With the mutant: `executed [(7000, 120000), (7001, 450000)]`. Order 7001 is paid out
    twice, once elsewhere and once by the approved set, whose approval was given against
    state that no longer holds.
- For comparison, removing the *pre-pass* (`plug/no_prepass_plugin.py`) is caught by
  `test_a_change_to_a_later_action_while_deciding_aborts_before_any_effect` and
  `test_state_change_while_deciding_aborts`.

### 4. LOW-MEDIUM (reproduced; harness gap from D-054): untrusted-id ticket reads and their existence origin are no longer exercised or asserted

**Mechanism.**
- Since D-054, every `read_ticket` in the shapes uses a literal (trusted) id: `probe`
  (`planners/fuzz.py:438-440`), the `exists` control of `_lit_extract`
  (`planners/fuzz.py:469-475`), and every `read` in `_shape`.
- Each of these reads now either halts, which skips NI-1 for the pair
  (`tests/ni_properties.py:76-77`), or is fully trusted. The "map that extracts under an
  existence-selected pc" control D-049 added can no longer produce an untrusted pc. It is dead
  as a test of extraction-under-control.
- The production branch that joins `tickets[T].@row` for untrusted ids
  (`kernel/tools/database.py:152-154`) is asserted by no test. `grep @row tests/` finds only
  the D-054 negative assertion, and `test_point_read_existence.py:137-141` checks `.items`,
  not the label.

**Reproduction.**
- Mutant `untrusted_read_drops_row` (untrusted-id reads omit `@row`): NOT caught at seeds
  9101, 9102 and 9103 × 1,500 shapes examples.
- `test_d054_probes.py::test_untrusted_id_existence_origin_is_not_asserted_anywhere` shows the
  production label (it passes).

**Severity.** Low for the invariant: an untrusted id's label is already untrusted, so `@row`
only changes which origins a rule sees. But Ω_T's `@row` member, and the rule's claim to
endorse it, now have no test.
`tests/test_gate1_regressions.py::test_case_ticket_existence_is_endorsable_by_the_rule`
still has that name and docstring but no longer involves `@row`. In my probe the run's only
origin is `tickets[4000].body`, and the test passes under both the Phase 1–2 and the D-054
settings (`-p phase12_plugin`). It is now a test of something else, and the D-054 table does
not list it.

### 5. LOW (reproduced; harness gap): NI checks only integrity; the P5 sink check can be deleted without any NI property noticing

Mutant `sink_check_removed` (`kernel/policy._sink_block_reason` returns None): NOT caught at
seeds 9101–9103 × 1,500. Aggregates are `U = ∅`, so NI-1 and NI-3 treat them as trusted and
identical in both worlds. Confidentiality is covered only by
`tests/test_tools_phase2.py` (for example `test_order_stats_suppresses_small_groups_and_is_operator_only`).
That is fine if stated, but DESIGN §9.4 lists the `order_stats` shapes as NI coverage.

### 6. LOW (reproduced; oracle gap): NI-4's goodwill oracle has no in-run per-customer check

`_check_goodwill` (`tests/ni_properties.py:165-187`) checks per-customer credits only in
`pre` and per-ticket counts in the run.
- Mutant `gw_no_inrun_customer_bound` (rule drops "another credit for this customer is in the
  action set"): NOT caught at 9101–9103 × 1,500.
- The execution re-check backstops it. In `test_inrun_customer_bound.py`, two
  subject-triggered standard credits to customer 100 on tickets 4000 and 4005 give `partial`,
  with one credit, under that mutant.
- With both the rule check and the re-check stop removed (`-p never_stops_plugin` plus the
  mutant), the run executes two automatic credits to customer 100 and `check_ni2` and
  `check_ni4` both pass.
- The two defences of one postcondition are each untested by the property meant to check
  it. See finding 3.

Side observation from the same probe: with text-triggered (extracting) credits on two tickets
in one plan, the second credit is never admissible ("pc has untrusted origins outside ticket
4005"). The run's cumulative extraction label mixes both tickets' bodies. That is sound, but
it is an unmeasured utility cost of the cumulative label for multi-ticket plans.

### 7. LOW (reproduced): failures outside the documented paths leave no audit row

- An approver that raises: `run_plan` commits an `approvals` row with status `requested`
  (`kernel/run.py:482-486`), then `env.approver.review` raises out of `run_plan`. That leaves
  0 audit rows for the run, against the module docstring's "every run writes one audit row".
  A retry with the same run id fails with `IntegrityError: UNIQUE constraint failed:
  approvals.run_id`, not a `rejected` row. Nothing executes, so this is not an invariant
  violation, but the audit trail and run-id lifecycle have a hole
  (`test_recover_race.py::test_approver_exception_leaves_no_audit_and_burns_run_id`).
- `run_task(..., leak_ticket_bodies=(missing,))` raises `ResolutionHalted` from
  `kernel/run.py:566-567`, outside `run_plan`, with no audit row. `env.planned_tasks` is
  already updated in memory but not durably
  (`test_run_task_leak_of_missing_ticket_escapes_unaudited`). This only affects the leaked
  configuration.

### 8. LOW (spec/harness consistency)

- **NI-3 and partial runs.** NI-3 says each executed sequence is "empty or equal to X*", but
  a partial run (provider failure, or a stricter re-check) executes a prefix. The single-run
  harness never injects failures, and the multirun property does not check NI-3, so the
  inconsistency is never exercised.
- **NI-5 and partial prefixes.** DESIGN §9.3 NI-5 allows "a reported partial prefix", but the
  harness treats any partial as a violation (`tests/test_approval_binding.py:162`). The NI-5
  mutant is detectable only because of that stricter-than-spec check.
- **The NI-5 property never checks run binding.** `ApproveAll` always answers with the
  current run's hash. Replay and cross-run rejection are unit tests only.

### 9. What the NI harness does not generate or compare (assessment)

- **Not compared:**
  - approval requests (by design: steering is only recorded);
  - the durable audit row: NI-2 reads the in-memory `RunResult.rule_log`
    (`tests/ni_properties.py:95`), so clause (a)'s "the decision was logged" is checked only
    by `tests/test_audit.py`;
  - pending refund rows;
  - execution order across tools: `effects()` concatenates refunds, then credits, then
    closures (`tests/ni_properties.py:56-70`), not "in execution order" as DESIGN §9.2 says.
- **Not generated:**
  - concurrency of any kind (findings 1 and 3);
  - an approver that approves under NI-3: NI-3 runs only with deny;
  - extractors with cross-run state (documented);
  - untrusted ticket ids (finding 4);
  - provider failures in paired runs;
  - a rule-admitted action together with a halt elsewhere in the plan, where the halt is
    the only thing differing.
- **Vacuity.** NI-1 is skipped for every pair with a halted run, about 26% of single-run
  pairs per the stage-b statistics extract. A kernel that halts more often passes more
  easily. That is safe for effects, but it reduces what NI-1 measures.

### Checked and found sound (no finding)

- **Label rules.** Map body `pc`, `filter` (every predicate joins the structure), `at`
  (index label), `len` (structure), `contains` (whole list plus needle), field access
  (selection label), and literals labelled with `plan_label`.
- **Extraction.** The cumulative label with `pc` and the map pre-join: `_extracts` covers
  call arguments, op arguments, nested map sources and filter sources. Filter predicates
  cannot contain calls or maps.
- **D-054 halt argument.** A trusted ticket id's value is identical in both worlds (it comes
  from literals or `t.id` of a trusted read; ids admit no arithmetic). Within a continuing
  run, every trusted point read that executed found its row. A read under an untrusted `map`
  that did not execute contributes nothing. I found no trusted ticket id that can differ
  between worlds and no read path other than `Database.read_ticket`. Existence used by the
  policy without a read (for example a trusted `close_ticket` of a missing ticket) gives
  BLOCK, which is whole-run suppression only.
- **Ω_T closure.** Origins in Ω_T are obtainable only by reading ticket T. Trusted reads of
  T halt if it is absent, and untrusted ids carry an origin outside Ω_T, so a rule cannot be
  steered by another row's existence through T's origin set.
- **Sites, approval and execution.** Sites are unique. The approval hash covers tool, args,
  labels (pc included) and verdict. The run-bound, single-use approval is consumed before
  any effect. NFC normalisation happens before hashing. The pre-pass compares kinds, which
  for untrusted actions implies the same rule admission.
- **Narrowed mutants.** These narrower and additional mutants are all caught: the ownership
  and goodwill rules ignoring only the origin set (trust preconditions kept: 3/3 seeds each,
  via NI-2's origin check), `contains` ignoring list labels (3/3), `len` ignoring structure
  (3/3) and the ownership rule ignoring the amount (2/2, on the first example). The map
  pre-join alone removed (`_extracts` returns False) is caught at 2 of 3 seeds within 1,500
  (missed at 9102). This is consistent with the existing "extraction ignores control" mutant
  needing k = 4 seeds × 2,000.

---

## D-054 table

I opened every test, compared its assertions with the "asserts now" column, and checked the
old version with `git show bfe2991`. For the label tests I also checked that each still
discriminates its target mechanism: I ran `tests/test_interpreter_labels.py` under the
filter, at and body-pc mutants (`plug/*_mut_plugin.py`), and all 7 changed tests (plus
`test_ticket_existence_can_only_suppress_a_run`) under the Phase 1–2 setting
(`-p phase12_plugin`).

| # | test | "asserts now" matches the code? | my judgement | agree with the table's strength? |
|---|---|---|---|---|
| 1 | `test_literals_inside_a_tainted_map_stay_trusted_but_pc_is_tainted` | Yes (`test_interpreter_labels.py:43-51`, exact dict equality) | Equal. It still fails under the body-pc mutant. | Agree. |
| 2 | `test_filter_joins_every_predicate_label_into_the_structure` | Yes (`:79-86`) | Equal, arguably cleaner: the enclosing map over the trusted read now has a trusted pc, so `{BODY}` in pc can only come from the filter's predicate labels. It fails under the filter mutant (and the body-pc mutant). | Agree. |
| 3 | `test_tainted_index_taints_the_selected_record` | Yes (`:89-104`) | Equal. It fails under the at mutant. | Agree. |
| 4 | `test_amount_selected_by_tainted_id_is_tainted` | Yes (`:107-119`) | Equal. | Agree. |
| 5 | `test_read_of_an_operator_named_ticket_is_trusted` | Yes (`:54-76`, all four labels empty for 2 actions) | Weaker on its own: it now guards against spurious taint, and existence protection moved to the halt. **Where it moved:** `test_point_read_existence.py` (the `variant` config asserts the halt in `test_reviewers_probe_…` and `test_variant_halts_only_…`), `test_ticket_existence_can_only_suppress_a_run` (asserts `halted`, no actions, no effects) and the mutant. All exist and assert the halt. **But** nothing that moved covers the *untrusted-id* half of the old guarantee: no test asserts `@row` on an untrusted-id read (finding 4). The "3 configurations" of `test_point_read_existence.py` include two non-production ones; only `variant` guards production. | Agree "weaker", with the caveat above. |
| 6 | `test_ticket_existence_can_only_suppress_a_run` | Yes (`test_gate1_regressions.py:42-63`) | Weaker property, by design, as stated. Two of its calls are vacuous: `check_ni1(r1, r2)` returns immediately because r1 halted, and `check_ni3(...)` holds because one side is empty. The substantive assertions are `halted`/no actions/no effects, `r2` executed, and `@row` not in pc. "NI-3 holds" in the table overstates what the test shows; it shows suppression, not a non-trivial NI-3 comparison. | Agree on "weaker"; the test proves less than the row says. |
| 7 | `test_goodwill_credits_are_bounded_per_customer_not_only_per_ticket` | Yes (`test_gate2_regressions.py:212-227`) | **Disagree with "Equal".** The assertion is unchanged, but the scenario the test was written for (probe F, plain reads) no longer goes through the rule and now executes four credits (finding 2, reproduced). The test now covers only text-triggered credits. The bound protects strictly less than before, and the original probe is no longer run anywhere. | **No: weaker coverage of the Gate 2 #6 property, not equal.** |
| 8 | `test_rule_goodwill`: helper `credit_ticket_customer` and `_world` default body | Yes (`test_rule_goodwill.py:27-40`; the three named tests use the helper) | Equal for the rule: each named test still reaches `ticket_goodwill_credit`. I checked the new `test_a_credit_with_no_text_involved_is_trusted_and_skips_the_rule` under the Phase 1–2 setting: **it fails**, as claimed. Same caveat as row 7: the plain-read path is now pinned as *trusted*, so the rule's bounds no longer apply to it. | Agree for the rule's own checks. |
| 9 | `test_simulated_approver_approves_exactly_the_intended_set` | Yes (`test_evals.py:123-131`, task T37) | Equal for the approver. The reason holds as stated (T20 no longer asks; I did not run the eval). | Agree. |
| 10 | mutant "point read of a missing trusted ticket does not halt" | Yes. `git show dcd3434` vs now: old = `POINT_READ_EXISTENCE=False` with no halt flag; new = `HALT_ON_ABSENT_TRUSTED_TICKET=False` with `POINT_READ_EXISTENCE` default False. | Equal kernel configuration. The witness test passes (seed 202616004). | Agree. |
| 11 | `multirun_property`, plan kind `credit` | Yes (`test_noninterference.py:315-336`) | Equal for exercising the rule across runs; the per-customer mutant witness (202616005) passes. Plain-read credits still occur in shapes (`trigger == "none"`, 1 in 6 credit shapes), but in those the rule is never consulted, so they test nothing about the bound. Same caveat as row 7. | Agree for its stated purpose. |
| 12 | `test_point_read_existence` (both tests) | Yes (old `point_read_existence` fixture replaced by `config`; the old assertions are kept for `taint kept` and `narrowed`) | Stronger, as stated. In `variant`, both `two-reads` worlds halt and `index` has one side halted, so "NI-3 holds" there is vacuous (empty effects). The real `variant` evidence is the halt assertions. | Agree. |

**Tests whose meaning changed but are not in the table:**
- `test_gate1_regressions.py::test_case_ticket_existence_is_endorsable_by_the_rule`. Its
  assertions are unchanged and it passes under both settings. Its name and docstring ("the
  existence origin of the case ticket itself is inside the rule's origin set") no longer
  describe what it exercises: no `@row` origin arises (finding 4).
- More generally, the table was built from changed assertions. A test whose assertions still
  pass but whose input no longer reaches the mechanism is invisible to that method. That is
  exactly how probe F's original form (row 7) dropped out.

---

## Earlier mutant claims

**Current clean-state evidence.**
- `tests/test_ni_mutants.py::test_harness_catches_mutant` replays one witness seed per
  required mutant: 1,000 examples, pinned generation, no database, generate phase only.
  This session: 21 passed, 31 s.
- `KSEED` holds the k-seed designs. Their execution (stage c) is not in the evidence I was
  given, so for every row below **the k-seed claim is a design, not yet a result**.
- The only clean-state *results* I can confirm are:
  - the witnesses (this session);
  - the stage-b fresh-seed validation reported in `clean_state_evidence.md` (all required
    mutants caught at 3 fresh seeds, except NI-5 at 202617002);
  - the 8-seed first-detection table (`clean_state_evidence.md`, D-058).

### Every earlier claim

| # | source | claim | status now | evidence / remarks |
|---|---|---|---|---|
| 1 | D-033 / Phase 1 (4fb4858) | "filter ignores predicate labels" caught | **Re-established** | Witness 202616001 (first at 3); 8/8 seeds within 500. Same patch as 4fb4858. Exact mutant. |
| 2 | D-033 / Phase 1 | "map body pc ignores list structure" caught | **Re-established** (shapes and grammar) | Witnesses 202616004 / 202616003. **Broader than its name:** `body_pc` is also used for the extraction pre-join (`kernel/interpreter.py:213-218`), so it disables two mechanisms. |
| 3 | D-033 / Phase 1 | "extractor output labelled trusted" caught | **Re-established** (shapes and grammar) | Witnesses 202616001 / 202616003. Exact (`_extracted` still accumulates; only the output label is BOTTOM). |
| 4 | D-033 / Phase 1 | "at ignores index label" caught | **Re-established** | Witness 202616001; 6/8 seeds within 250. Exact. |
| 5 | D-033 / Phase 1 | "policy ignores pc" caught | **Re-established** (shapes and grammar) | Witnesses. Broader than "policy": `components()` feeds P1, both rules' origin checks and P5 (`kernel/policy.py:192-196, 211, 305-310`). Caught via NI-2, which uses `component_labels()` with pc. |
| 6 | D-033 / Phase 1 | "ownership rule drops uniqueness" caught | **Re-established** | Witness 202616001. Exact (`REQUIRE_UNIQUE_ELIGIBLE`). |
| 7 | D-033 | "rule ignores origin set (single-run)" caught | **Re-established, mis-specified** | Witness 202616003. The patch (`test_ni_mutants.py:55-57`) passes BOTTOM for *every* component, so it also removes the `ticket_id is untrusted` precondition (`kernel/declassify.py:61-62`). It is "rule ignores all labels". I ran the narrow version (origin set ignored, ticket_id trust kept): caught at 9101/9102/9103 by NI-2's origin check. **So the claim holds for the narrow mechanism too**, on my 3 seeds × ≤1,500, not at a designed k. |
| 8 | D-033 | multirun "rule drops once-per-ticket" caught | **Re-established**, weakest of the multirun set | Witness 202616004. `ticket_has_refund` is used only by the rule (`kernel/declassify.py:92`). Exact. 4/8 seeds within 250, k = 22. |
| 9 | D-033 | multirun "rule drops never-refunded" caught | **Re-established** | Witness 202616002. `order_has_refund` is used only by the rule (`:79`). Exact. 5/8 seeds within 250, k = 14. |
| 10 | D-033 | multirun "execution records only after the provider confirms" caught | **Re-established** | Witness 202616004. Exact (`PENDING_FIRST=False`, `kernel/execution.py:540-552`). |
| 11 | D-033 | "All 10 mutants are caught at 600 derandomized examples" | **Not re-established (superseded)** | Derandomized 600 was process-state dependent. Current budgets differ (n from 250 to 2,000, k from 4 to 22). The per-mutant claims are re-established individually (rows 1–10); this aggregate claim at that budget is not. |
| 12 | D-049 | "extraction ignores control" caught by the new shapes (old generator missed at 600) | **Re-established** for the current shapes. The "missed by the old generator" half is **not re-established** (process-state result; moot). | Witness 202616003 (first at 359); 8/8 within 2,000, k = 4. It disables both the pc join and the pre-join. A pc-join-only variant is equivalent: inside maps the pre-join already puts the body pc into `seen`, and at top level pc = plan label. My pre-join-only mutant: 2/3 seeds within 1,500. **Note:** the `exists` control D-049 added for this mutant is dead since D-054 (finding 4), so detection rests on the `note` control alone. |
| 13 | D-049 | NI-5 "re-check treats a relaxed verdict as stricter" caught (old generator missed at 600) | **Re-established, with a known miss; half of the reversal untested** | Witness 202616002 (253). Stage-b miss at 202617002 (first at 9,080); 5/8 within 1,000, k = 14. The reversed `_STRICTNESS` also turns real stricter verdicts into "relaxations". That half is caught by **nothing** in the suite (finding 3, reproduced). The name matches the half that is caught. |
| 14 | D-049 | multirun "goodwill rule drops the per-customer bound" caught | **Re-established** (persisted bound only) | Witness 202616005 (42). Exact for `customer_has_credit`. The *in-run* per-customer check is a separate mechanism with no mutant and no oracle (finding 6). |
| 15 | D-049 table | "point ticket read drops existence origin" caught, 110/1,552 | **Changed (renamed), equivalent** | Now "point read of a missing trusted ticket does not halt": same kernel configuration (`git show dcd3434`). Witnesses: shapes 202616004 (3), grammar 202616002 (91). The rate number is not re-established, being process-state dependent. |
| 16 | D-049 table / Phase 2 (838f360) | "goodwill rule ignores origin set" caught (5/1,552) | **Re-established, mis-specified** | Witness 202616004 (265). Like row 7, the patch zeroes every component, so it also drops the "ticket_id/amount/reason must be trusted" preconditions (`kernel/declassify.py:121-123`). My narrow version (trust preconditions kept): caught 3/3 via NI-2. Grammar does not catch it (1/8 seeds), so it is correctly not in `GRAMMAR_CATCHES`. |
| 17 | D-049 table / Phase 2 | "goodwill rule ignores amount" caught (7/1,552) | **Re-established, broader than its name** | Witness 202616004 (168); 4/8 within 250, k = 22. The patch admits whenever the *first* failing check is the amount, skipping the later set, ticket and customer bounds (its docstring says so). The amount part is what NI-4's amount check sees. Acceptable, but the catch is not attributable to the amount alone. |
| 18 | D-049 rate table (all 16 rates) | per-example detection rates and budgets of 3,000/3,000/2,000 | **Not re-established (superseded)** | Process-state dependent. Replaced by the clean-state 8-seed table and k-seed designs (D-058). |
| 19 | D-049 | "The execution pre-pass has no mutant" | Still true; **now shown covered by regression tests** | My `no_prepass_plugin` (pre-pass skipped) fails `test_a_change_to_a_later_action_while_deciding_aborts_before_any_effect` and `test_state_change_while_deciding_aborts`. |
| 20 | D-050 | `check` runs "the mutants at 3,000/3,000/2,000" | **Not re-established (superseded)** | `check` now replays one witness per mutant at 1,000 examples. That is a regression replay, not a detection claim (the module docstring says so). |
| 21 | D-054 | "narrowed-taint mutant … still caught, with an NI-1 violation after 970 runs" (adoption test) | **Re-established** (as row 15). The "970 runs" figure is **not** re-established. | Same as row 15. |
| 22 | D-054 table row "multirun credit kind" | "With the change [the per-customer-bound mutant] is caught again" | **Re-established** | Witness 202616005 passes. |
| 23 | GATE1 review M1 | rule ignores origin set: NOT caught (then) | Fixed. **Re-established** as row 7 | See row 7. |
| 24 | GATE1 review M2 | ownership rule ignores amount: caught (NI-4) | **Not in the suite, so not re-established by the project.** I reproduced it: caught at 9101 and 9102 on the first example (NI-4 "amount is not the full refundable amount"). | Never added to `MUTANTS`. Cheap to add. |
| 25 | GATE1 review M3 | `contains` ignores list labels: caught (NI-1) | **Not in the suite, so not re-established by the project.** I reproduced it: caught at 9101/9102/9103 (NI-1). | Never added. |
| 26 | GATE1 review M4 | field drops selection label: equivalent | **Agree it is equivalent.** Records are reachable only through list binders (map/filter element joins the structure) and filter structures join the over label, so the selection label is always carried by pc or structure. | No action. |
| 27 | GATE1 review M5 | rule drops persistent once-per-ticket: NOT caught (then) | Fixed. **Re-established** as row 8 | See row 8. |
| 28 | GATE2 response | "NI-5 catches a mutant that reverses the strictness order" | As row 13 | |
| 29 | GATE2 response #6 | "a multirun mutant that drops the bound is caught" | As row 14 | |
| 30 | GATE2 response #3 | "Before the new shapes existed, … the extraction and NI-5 mutants escaped the old generator at 600 examples" | **Not re-established** (process-state result; the old generator is gone) | Moot for current coverage. |

### Do the current mutants do what their names say?

- **Exact:**
  - filter ignores predicate labels;
  - extractor output labelled trusted;
  - at ignores index label;
  - ownership rule drops uniqueness;
  - point read of a missing trusted ticket does not halt;
  - all four multirun mutants (each patched reader method is called only by the rule it
    names, or `PENDING_FIRST` only by `execute`).
- **Broader than named, so a "caught" could come from the extra mechanism:**
  - "ownership rule ignores origin set" and "goodwill rule ignores origin set": both also
    drop the trust preconditions. The narrow versions are caught too, in my runs.
  - "goodwill rule ignores amount": also skips later bounds.
  - "map body pc ignores list structure": also weakens the extraction pre-join.
  - "policy ignores pc": also affects rules and sinks.
  - "extraction ignores control": both pc join and pre-join.
  - NI-5 reversal: both directions; only the relaxation direction is caught.
- **Mechanisms with no mutant (mutants I ran):**
  - untrusted-id `@row` (not caught, finding 4);
  - the P5 sink check (not caught, finding 5);
  - the in-run goodwill per-customer check (not caught, finding 6);
  - the between-effects stricter stop (not caught by any test, finding 3);
  - `contains` and `len` label rules (caught, but not in the suite);
  - ownership amount (caught, not in the suite).

---

## Summary for the gate

- **Fix before claiming the execution layer is sound:**
  - Finding 1: the recovery race. Money moved twice and the rule's release was exceeded.
    Reproduced deterministically.
  - Finding 3: the untested stricter-stop. A one-line mutant passes the whole suite and
    double-pays in my probe.
- **Correct the D-054 record:**
  - Row 7 is not "Equal": probe F's original form now executes four credits (finding 2).
  - Rows 6 and 12 contain vacuous NI calls.
  - The `@row` path for untrusted ids lost its only coverage (finding 4).
  - `test_case_ticket_existence_is_endorsable_by_the_rule` no longer tests what it says.
- **No label-propagation violation found.** The D-054 halt argument holds on inspection.
  Every narrowed label and rule mutant I tried was caught, except the three integrity-adjacent
  gaps above (`@row`, sinks, in-run goodwill bound) and the execution re-check.
