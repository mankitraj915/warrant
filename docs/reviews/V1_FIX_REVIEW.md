# v1 fix re-review

Nine problems remain. The two most serious are the leaked-context claims and the "cannot change what executes" wording. Every README number matches the 9f2f0c3 artifact (run 41386725959) and RESULTS. `scripts/check_links.py README.md docs/*.md docs/adr/*.md` reports "0 broken link(s)", and it checks anchors. No code under kernel/, planners/, evals/, tests/, scripts/ or domain/ has changed since 9f2f0c3.

1. **Medium-High: finding 13 is resolved wrongly, and the finding 1 fix adds an overclaim.**
   - **Where:** README.md:86-88, README.md:163-165 and RESULTS.md:134-137.
   - **Quotes:** README:86-88 says "The leaked-context rows test the kernel against attack plans… The labels alone stop every one, but almost every pair then needs a human". RESULTS:134-137 says "almost every pair then needs approval and is steered (93% of pairs in both suites)". README:164-165 says "The steering rate shows how often a human would be asked to decide under attack."
   - **Why:** The eval JSON for leaked+attacker shows otherwise:

     | suite | blocked, no approval request | approval requested, simulated approver refused | executed after approval |
     |---|---|---|---|
     | dev | 255 | 158 | 1 |
     | holdout | 290 | 198 | 0 |

     So about 38-41% of pairs reached a human, not "almost every pair". In those pairs the idealised approver stopped the attack, not the labels; WHAT_WENT_WRONG.md:138-140 says this itself. The 93% is steering. evals/harness.py:256 defines steering as `r.approval != base[r.task].approval`, so it also counts a benign approval request turning into a block. It is therefore not "asked to decide".
   - **Fix:** In all three places, state the split between blocked and routed to approval. Attribute the routed pairs to the approver. Define steering as "the approval request differs from the benign run's".

2. **Medium: the finding 4 fix is incomplete (README.md:144-145, adr/0003-atomic-runs.md:36-38).**
   - **Quote:** "Outside the two rules' declared releases, injected text can stop a whole run but cannot change what executes."
   - **Why:** This ignores the approval path. Untrusted text can change what a human is asked to approve, and THREAT_MODEL.md:74-79 says steering is "measured, not prevented". README:24 and SPEC §10 correctly say "unapproved effects".
   - **Fix:** "…cannot change the unapproved effects that execute."

3. **Medium: finding 3 is still open for the linked docs, and this diff adds more of the same wording.**
   - **New in this diff:**
     - docs/reviews/V1_REVIEW.md:18-21 quotes "Claude Code" and "subagent". The README links docs/reviews/ (README:187).
     - New DECISIONS sections say "this session" (DECISIONS.md:3138, 3196).
     - The new SPEC banner links the D-075 anchor `…results-stays-hand-written-in-v1…`, directly above "`CLAUDE.md` holds the working rules".
   - **Why:** The response's "Not changed" is accurate, but the README routes readers to these files.
   - **Fix:** This is an open item for the owner to decide before publishing. Record it in the hand-off as a blocker.

4. **Low: README.md:101 gives the wrong count.**
   - **Quote:** "20 mutants the non-interference harness must catch".
   - **Why:** mutant_kseed.jsonl has 16 distinct mutants. The 20 are pairs of mutant and generator (RESULTS:245 says "all 16" shape mutants plus 4 grammar ones that repeat them).
   - **Fix:** "16 mutants (20 mutant-generator designs)".

5. **Low: README.md:104 is ambiguous.**
   - **Quote:** "Two came in below their estimated per-seed share (about 6%)".
   - **Why:** It reads as if the share were 6%. It is the estimated miss probability; the share was 2 of 4 against 0.688.
   - **Fix:** "…per-seed share (2 of 4 seeds; estimated miss about 6%)".

6. **Low: README.md:56 and :108-109 have the wrong source.**
   - **Quote:** README:56 says "the mutant results from `tasks.py phase3-run --stage d`".
   - **Why:** "3 were missed at Gate 3" comes from stage c at 7da1652 (`results/phase3c/mutant_heldout.jsonl`), not from stage d.
   - **Fix:** Name stage c for the baseline.

7. **Low: PROCESS.md:16-17 is now contradicted by the new review.**
   - **Quote:** "No reviewer saw the evaluation results."
   - **Why:** The same paragraph says each report is kept in docs/reviews/. V1_REVIEW.md is now there, and that reviewer compared every evaluation figure with the stage-d artifact.
   - **Fix:** Scope the sentence to the gate reviewers.

8. **Low: the finding 1 response overstates where the label is.**
   - **Why:** The response says the rows are labelled "planner isolated" and lists RESULTS. RESULTS.md:88-89 and :101-102 still read just "Warrant". RESULTS:107-110 does explain it.
   - **Fix:** Label those rows, or correct the response.

9. **Low: the new Makefile target does not run (Makefile:6-9).**
   - **Why:** `make phase3-run` passes no arguments, but `--out` is required (scripts/phase3_run.py:208), so it fails with an argparse error. Its default stage is also `a`.
   - **Fix:** Drop the target, or document `make` as not covering it.

## Checked and resolved

- **Finding 2:** WHAT_WENT_WRONG, ADR 0010 and RESULTS match mutant_postfix.jsonl. The three post-fix results are caught, missed in 102,000 examples (107,571 generated cases), and caught by NI-5 at seed 202619001, case 164. The two other held-out mutants were also caught again.
- **Finding 5:** the four deterministic mutants are confirmed, each with `harness_gap` tests. The two low shares at stage d are "extraction ignores control" and "execution writes no record", the only entries below q_low.
- **Finding 6:** fixed, apart from the leaked-context wording in item 1 above.
- **Finding 7:** fixed; the wording matches DECISIONS:2353-2354.
- **Finding 8:** fixed for Gate 3.
- **Finding 9:** fixed. The baseline file recomputes to 102,000 examples and 108,462 calls for each of the three missed mutants.
- **Finding 10:** the SPEC banner is in place. The docstring is deferred, as the response says.
- **Findings 11 and 12:** fixed.
- **Finding 14:** the steering column matches the sweep logs (2→11 on dev, 2→9 on the holdout).
- **Finding 15:** `make demo` is fixed. The deferred comments are still present, as the response says.
- **Finding 16:** pyproject.toml and uv.lock are 1.0.0, and there is no LICENSE, as stated.
- **Public docs:** README, ADRs, WHAT_WENT_WRONG, PROCESS and STUDY_GUIDE contain no tool or authorship wording.
- **"No deterministic test covers" the two open mechanisms:** confirmed. The goodwill tests use only `lit("goodwill")` reasons.
