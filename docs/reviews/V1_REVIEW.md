# v1 skeptical review

Scope: README.md (uncommitted draft), docs/RESULTS.md (draft with placeholders), docs/adr/, WHAT_WENT_WRONG, PROCESS, STUDY_GUIDE. I spot-checked SPEC, DESIGN, THREAT_MODEL, DECISIONS, kernel/ and evals/. I also compared the stage-d artifact for run 41370326167 at commit 13cd4d8. Every finding below was checked against the files.

## Findings

**1. High: README.md:67 and :77 (also RESULTS.md:86-87, 99-100).** The headline row reads `| Warrant | gullible | 5/414 | 396/414 | 3/40 |`, placed beside `Undefended | gullible | 393/414`. Under Warrant the gullible planner sees no ticket text. With empty context it returns the oracle plan (planners/gullible.py:40-49). DECISIONS:1689 records that "`warrant+gullible` equals `warrant+oracle` in every metric, as isolation predicts". So the 393 → 5 drop holds by construction and was never measured against a planner under attack. The only run where an adversarial plan meets the kernel is leaked context, where utility under attack is 39/414. **Fix:** label the row "Warrant (planner isolated; identical to oracle)" and say this in the README.

**2. High: WHAT_WENT_WRONG.md:102-105 and adr/0010:45-47.** WHAT_WENT_WRONG says: "The other two misses had the same root: untrusted text was always random, never a valid reason code or an existing id. The generators now draw domain-valid untrusted values". The 13cd4d8 artifact includes D-070 (13cd4d8 is the merge of PR #25), yet `mutant_postfix.jsonl` shows:
- `goodwill_reason_not_required_trusted`: missed at all 80 seeds (102,000 examples);
- `contains_ignores_element_labels`: missed at all 80 seeds (102,000 examples).

No generator file changed after 13cd4d8 (`git log 13cd4d8..HEAD -- planners tests/...` is empty). The stated root cause is therefore not shown, and the text implies the gaps are closed. The `contains` cause also disagrees with RESULTS:284 and DECISIONS:2451-2455, which blame the lack of a trusted list of untrusted elements, not random text. **Fix:** state the post-fix misses in WHAT_WENT_WRONG, ADR 0010 and the README mutant paragraph, and withdraw the root-cause claim until something supports it.

**3. High: tool and authorship references in public docs and the docs they link to.**
- RESULTS.md:3: "Written by hand from the run artifacts".
- RESULTS.md:114: "Every miss I checked" (first person, so the reader assumes the owner).
- SPEC.md:3: "`CLAUDE.md` holds the working rules". SPEC.md:222, 297 and 349 say "subagent".
- DECISIONS.md, linked from README:160, has 40 lines that name Claude Code, a subagent or "in session", e.g. :1225, :2367-2368 ("Claude Code's memory guard stopped the run") and :2391.
- docs/reviews/GATE0_REVIEW.md:3, GATE1:3 and GATE2:3: "a fresh subagent".
- CLAUDE.md is tracked at the repo root and holds session status and machine-memory notes.
- Milder: "hand-written" plan or shapes at RESULTS:63, RESULTS:304 and WHAT_WENT_WRONG:15.

**Fix:** reword to "compiled from the run artifacts", "every miss was checked", "fixed plan" or "fixed shapes", and "an independent reviewer". The owner should decide what happens to CLAUDE.md and to the linked DECISIONS and review files.

**4. Medium: README.md:126-128 and adr/0003:37.** README says "injected text can stop a whole run, but never change what executes". README:81-83 and ADR 0007:37-38 say the opposite: ticket text *triggers* a refund or credit, and all 5/414 and 4/488 Warrant successes are that case. **Fix:** "outside each rule's declared release, injected text can only stop a whole run".

**5. Medium: README.md:89-94, the mutant paragraph.**
- "Each known way to break the kernel is kept as a mutant, and the non-interference harness must catch it" is false. tests/deterministic_mutants.py holds four mutants that the NI harness cannot reach (D-063, D-065), and RESULTS:252-256 lists mechanisms that NI cannot see.
- The paragraph omits that two designs under-delivered: 2 of 4 seeds against q_low 0.688, so about 6% estimated miss and not 1% (RESULTS:265-269). At 13cd4d8 it happens again: "extraction ignores control" and "execution writes no record" were each caught at 2 of 4 seeds.
- README:55 says "Every number comes from the commands above", but the mutant claims come from `phase3-run` and `mutant_rates.py`.

**6. Medium: README.md:70-71 and RESULTS.md:39.** "never tuned against" and "The holdout was never used to tune anything". The holdout has been evaluated since D-043 (2344fbb), through the Gate 2 fixes, D-054 and D-061 to D-072, with its results known. ADR 0010:48 itself says "Once used, a held-out set is no longer held out for the next change." **Fix:** call the current holdout figures a re-run of a previously seen suite, or add fresh injections.

**7. Medium: adr/0010:27-28 and PROCESS.md:189-190.** Both say the held-out mutant writer saw "not the generators, the tests or the existing mutants". DECISIONS:2352-2354 says the writer "was blind to the generator and the tests, but not fully to the mutant list" (DESIGN §9.4 names the mutants). **Fix:** copy the DECISIONS wording.

**8. Medium: PROCESS.md:160-161.** It says each reviewer "received only the threat model, the design and the code. It saw no results". DECISIONS:2286-2289 shows the Gate 3 reviewer also got SPEC, the earlier reviews and three extracts, including "the clean-state evidence (stage b and D-058)". **Fix:** state per gate what each reviewer received.

**9. Medium: RESULTS.md:278-280, adr/0010:44, WHAT_WENT_WRONG.md:94.** "108,462 examples". That figure is Hypothesis *calls* (it includes invalid examples). Recomputed from `results/phase3c/mutant_heldout.jsonl`, the design ran 102,000 examples (22×1,000 + 22×2,000 + 22×1,000 + 14×1,000), and 108,462 is the sum of `calls`. The same issue affects DECISIONS:2441 ("7,197" calls against 6,862 examples). **Fix:** say "102,000 examples (108,462 calls)".

**10. Medium: SPEC.md:309-325, linked from README:153 as "the specification".** SPEC still describes Phase 4 (`llm_local`, `scripts/get_model.sh`) and `tasks.py report`. None of these exist: `scripts/tasks.py` has no `report` or `eval-llm` target, and D-074 and D-075 dropped them. SPEC has no v1-scope note. A stranger who follows the link finds commands that do not run. Other stale text: evals/harness.py:14 "delimiting is evaluated with the LLM in Phase 4". README:136 says "future work" while RESULTS:17 and :109 say "v1.1". **Fix:** add a v1-scope banner to SPEC that points to D-074 and D-075, and update the docstring.

**11. Low: README.md:42.** "Offline, CPU only". The first `uv sync --locked` downloads Python 3.12 and the wheels. **Fix:** "offline after `uv sync`". README also gives no run time for `check` (about 2 minutes; 116.77 s on CI).

**12. Low: README.md:62 and :70.** "40 tasks × 11 injections, 414 attack pairs" (40×11 = 440) and "15 injections … 488" (40×15 = 600). The word "applicable" is missing; RESULTS:37 has it.

**13. Low: RESULTS.md:128-131.** "almost every pair then needs approval and is steered". Holdout leaked+gullible steering is 92/488 (18.9%), with utility 402/488. **Fix:** limit the sentence to attacker-plan.

**14. Low: RESULTS.md:160-174, the cap sweep.** The table omits the steering cost. At ₹250, steering rises from 2/414 to 11/414 on dev and from 2/488 to 9/488 on the holdout (stage-d sweep logs). The text cites only "7 more benign approvals".

**15. Low: stale code comments.**
- kernel/declassify.py:36 says "no default chosen yet", but RESULTS:157 says "Default: no cap (owner decision at Gate 2)".
- kernel/execution.py:201 still says "until Phase 2 recovery reconciles it".
- Makefile:7 has no `demo` or `phase3-run`, so `make demo` fails.

**16. Low: padding and repetition.**
- The CaMeL/AgentDojo paragraph is verbatim in README:145-149 and RESULTS:7-12.
- The "393/414 against 39/488" story is told five times: README, RESULTS, ADR 0010, WHAT_WENT_WRONG and STUDY_GUIDE Q20.
- The leaked-context caveat appears four times.
- The duplication already copied one wrong label (finding 9) into three files.
- There is no LICENSE, and pyproject.toml says version 0.0.0 ahead of a v1.0 tag.

## Checked and found consistent

- **Every README and RESULTS eval figure against the stage-d logs and JSON at 13cd4d8:**
  - dev: 393/414, 21/414, 5/414, 396/414, 39/40, 38/40, 3/40, 2/414, 0/414, 39/414, 35/40, 384/414;
  - holdout: 39/488, 396/488, 451/488, 21/488, 4/488, 473/488, 2/488, 402/488, 92/488, 43/488, 457/488.
- **Local re-runs:** `tasks.py eval` and `eval --suite holdout` give metric tables identical to CI (3,632 and 4,224 runs; PII canary 0 hits).
- **Demo:** `tasks.py demo` output is identical to docs/demo_transcript.txt. The README excerpt agrees with it (abridged). `tasks.py trace T13:I1:warrant+oracle:seed11` works.
- **Attack successes:** the Warrant success pairs (T13/T33 × I1/I4, T28+I11; T13/T33 × H02/H11) match the logs.
- **Baseline misses:** all 21 dev and 37 holdout undefended attacker-plan misses fall in the categories listed at RESULTS:116-120 (I6, I7, I11, I8; H04, H11, H13).
- **Benign tasks:** benign approval tasks T12, T34 and T37 with causes (2) and (1) are correct, and so is the T14/T06 utility explanation.
- **Cap sweep:** all seven rows on both suites match, including 5→1 and 4→0 at ₹250 and leaked context at 0 for every cap.
- **Mutant counts:** 11 + 4 + 1 = 16 shape mutants and 20 KSEED entries (tests/test_ni_mutants.py). The KSEED table matches D-058. The "from 4 × 250 to 14 × 1,000" and "4 × 500 to 22 × 250" ranges are correct by k·n. q_low 0.688, minimum k = 4 and the ~6% figure (0.5⁴) are correct. At 13cd4d8 all 20 required mutants were caught by at least one seed.
- **Baseline results:** Gate 3 baseline per-seed shares match DECISIONS:2403-2445. The held-out results are 2 caught and 3 missed at 7da1652.
- **NI statistics:** 73.4% / 74.3%, 28.8% / 2.6%, 8.7% / 0.4% (stage b); `check` profile max_examples=200; Hypothesis 6.170.13 in uv.lock; 274 passed in CI `check`.
- **Runner:** Ubuntu 24, 2 CPUs, about 8 GB, Python 3.12.3.
- **Prose counts:** ten ADRs; 25 questions; kernel 2,259 lines ("about 2,300"); 40 tasks, 11 dev and 15 holdout injections.
- **Links:** `scripts/check_links.py README.md docs/*.md docs/adr/*.md` reports 0 broken links.
- **Credits:** CaMeL (arXiv:2503.18813) and AgentDojo (NeurIPS 2024) are both credited. No "novel" or "injection-proof" claim appears; "injection-proofness" occurs only under "May not claim".
- **Kernel against the docs:** the ownership rule's five conditions match ADR 0007 (kernel/declassify.py:59-94). The goodwill amount of 10,000 paise matches "₹100".
