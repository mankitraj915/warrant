# Warrant

An information-flow-controlled action kernel for AI agents. Every consequential action an agent takes must be *warranted*, either by trusted provenance, by a named declassification rule, or by a human approval of the exact action. The guarantee must hold regardless of what the model does.

The full specification is in `docs/SPEC.md`. Read it completely before starting any phase. This file holds the rules that apply in every session.

## The invariant

No consequential effect may be selected or parameterized by untrusted data unless:

- (a) a named declassification rule permitted it, and that decision was logged; or
- (b) a human approved the hash of the exact, fully resolved action set, and the executed set matches that hash.

The non-interference test in `docs/SPEC.md` §5 is how we check this invariant. It is the most important test in the repository, so treat any failure as a stop-everything bug.

## Constraints and why they exist

- **Runs on 8 GB RAM, CPU only, fully offline, ₹0.** Anyone reviewing this project must be able to reproduce every headline result on an ordinary laptop with no accounts or keys. That reproducibility is a core part of what makes the project credible.
- **The LLM affects utility, never safety.** All security tests run without any model. A local model (via `llama-cpp-python`) is an optional extra; hosted models may appear only as an off-by-default comparison adapter.
- **No agent frameworks, vector databases, queues, or container-required services.** The kernel is the contribution. Frameworks would hide exactly the code a reviewer wants to inspect.
- **Keep the execution and recovery layer thin.** The owner's existing project AegisFlow already demonstrates durable execution and recovery. This project's evidence should be about authority and information flow.

## How to work

- **Plan each phase before coding.** Append the plan and any non-obvious decision (with the alternatives you rejected) to `docs/DECISIONS.md`. The decision log is a deliverable: it is how the owner defends the design in interviews.
- **Write invariant tests before the code they test.** That applies to the non-interference property, the declassification rules, and approval binding. A test written after the implementation tends to encode the implementation's assumptions.
- **Verify before reporting.** Run `uv run --locked python scripts/tasks.py check` and the relevant eval targets, and read the output yourself before claiming anything works. Report only numbers produced by commands run in this session, and quote the commands.
- **If a test, policy, or invariant blocks a legitimate task, that is a finding.** Record it; do not weaken the check. Results that show real costs are more valuable than results that look good.
- **Stop at every gate** (`⛔ GATE` in the spec). Post a report using the template in `docs/SPEC.md` §9, then wait for the owner's decision.
- **At each gate, run an independent review first.** Spawn a reviewer subagent that gets only the threat model, the design doc, and the code. It never sees your reasoning or the eval results. Its job is to find a way to violate the invariant. Include its findings verbatim in the gate report and address each one.
- **Commit after each coherent step** with a descriptive message. Keep `scripts/tasks.py check` green on every commit.
- **No attribution lines.** No co-author trailer or "Generated with" line on commits, pull requests or releases (owner, 2026-11-06; `.claude/settings.json`). Earlier commits stay as they are. Nothing may claim that code or text was written by hand.
- **Ask the owner** only about scope changes or gate outcomes that change direction. For everything else, decide, record it in `docs/DECISIONS.md`, and continue.
- **Keep this file current.** Update "Current status" and "Commands" as they change, so a future session can resume cold.

## Things to avoid

- Letting the planner or any consequential tool see raw untrusted text.
- Special-casing a policy for a particular task to improve the numbers.
- Using an LLM-based injection classifier as a defence. It may appear only as an optional extra layer, evaluated separately.
- Using an LLM as a judge anywhere in scoring.
- Describing the project as novel research or as "injection-proof". It applies the principle behind CaMeL (arXiv:2503.18813) and evaluates in the style of AgentDojo (NeurIPS 2024). Credit both.
- Adding features outside `docs/SPEC.md` without asking.

## Commands

The canonical interface is `uv run --locked python scripts/tasks.py <target>`; use it in docs, reports
and gate reports. The `Makefile` is a thin convenience alias (`make <target>` runs the same thing) and
`make` is deliberately not installed on the development machine. Setup: `uv sync --locked`
(Python 3.12, dependencies pinned in `uv.lock`).

- `check`: ruff lint + format check, `mypy --strict` on `kernel/`, pytest (Hypothesis derandomized
  via the `check` profile). Also `lint`, `typecheck`, `test`.
- `fuzz`: non-interference fuzzing, 20,000 randomized examples (`HYPOTHESIS_PROFILE=fuzz`).
  Extra arguments pass through: `tasks.py fuzz --hypothesis-seed=N` reproduces a run.
- `fuzz-chunks`: the same fuzzing as sequential chunks with recorded seeds and measured peak
  RSS (`--test --chunks --examples --base-seed`; log in `results/fuzz_chunks.jsonl`; D-024).
  Up to v1.0.1, Hypothesis's `ci` profile derandomized the fuzz profile on CI runners and the
  seed was ignored; fixed in v1.0.2 (issue #52, D-076). `.github/workflows/fuzz-six.yml` still
  unsets `CI`/`GITHUB_ACTIONS` and checks `derandomize: False`, because it checks out `v1.0`.
- `eval`: default offline evaluation (no LLM): dev suite (40 user tasks, 11 injections) ×
  {warrant+oracle, warrant+gullible, undefended+gullible, delimited+gullible, leaked+gullible,
  undefended+attacker, delimited+attacker, leaked+attacker} (D-051, D-052), Warrant
  configurations with the simulated approver (D-041); writes `results/eval.json` (gitignored)
  and prints tables; also copies every run's audit row to `results/audit.sqlite`.
- `trace <run_id>`: explain one run from its audit row (actions, argument provenance, verdicts,
  rule decisions, approval, executed effects). Evaluation run ids look like
  `T12:I1:warrant+oracle:seed11`; `--db PATH` reads another audit database.
- `sweep`: the auto-refund cap sweep over the Warrant configurations; writes
  `results/cap_sweep.json` and prints one table per configuration.
- `eval --suite holdout` / `sweep --suite holdout`: the same against the held-out injections
  (`evals/tasks/holdout/`, independent red-team agent, D-043); writes `results/holdout.json`,
  `results/audit_holdout.sqlite`, `results/cap_sweep_holdout.json`. Never tune against it.
- `phase3-run --out DIR [--stage a|b|c|d|rates] [--resume]`: the owner-run Phase 3 measurements
  (`scripts/phase3_run.py`). Stage a (done at 6e27f60): check, mutants, NI statistics, chunked
  fuzz, both evals, both sweeps. Stage rates: clean-state per-mutant detection counts, 5 seeds x
  1,000 examples (`scripts/mutant_rates.py rates`). Stage b: check, `mutant_rates.py verify` at
  the budgets, NI statistics for the six split properties, grammar fuzz chunks (done at c4b52a6).
  Stage c: check, then every required mutant at its k-seed design (`mutant_rates.py kseed`,
  D-058). `mutant_rates.py heldout` runs the Gate 3 held-out mutants (D-057). Stage d: check,
  k-seed and former held-out mutants at fresh seeds (`--seed-base`), evals, sweeps. Refuses a dirty
  tree; logs each step to `DIR/steps.jsonl` and `DIR/NN-<step>.log`; continues past failures.
  Run only outside a session, from a clean worktree (DECISIONS "Phase 3 owner run", D-056).
- CI (D-060): `.github/workflows/check.yml` (every PR), `new-tests-fail-on-base.yml`
  (`scripts/new_tests_fail_on_base.py --base <commit>`, also runnable locally after committing;
  a `@pytest.mark.harness_gap("<mutant>")` test must instead fail on base under its mutant from
  `tests/deterministic_mutants.py`, D-063; it lists tests changed in place and new mutants, and
  refuses uncommitted changes under `tests/`, D-073), and the manual
  `owner-stages.yml` (`gh workflow run owner-stages.yml -f stage=d`), which uploads results.
- `eval-llm`: evaluation with a local model. Not in v1 (D-074): v1 ships without a
  language-model planner; planned for v1.1, with no CI-only model job before then.
- `report`: regenerate `docs/RESULTS.md`. Not in v1 (D-075): RESULTS is hand-written from the
  run artifacts; planned for v1.1.
- `demo`: scripted demonstration (`scripts/demo.py`): an outage bulk refund approved by hash
  and executed exactly, a stale approval that executes nothing, and an injected ticket that is
  blocked, each explained from its audit row. `tests/test_demo.py` keeps
  `docs/demo_transcript.txt` identical to a real run (regenerate:
  `uv run --locked python scripts/demo.py > docs/demo_transcript.txt`).

## Current status

Phase: **v1.0.2 shipped** (Gate 3 passed 2026-11-02, tag `gate-3` at 9f2f0c3; v1.0 on PR #48's
merge commit a8597ac; v1.0.1, docs only, on PR #53's merge commit 620cff4; v1.0.2 on the merge
commit of the release PR for issue #61). Everything is on `main` (repo
github.com/mankitraj915/warrant, public since the owner published it). Work goes through one issue, branch and PR per
change, merged with merge commits; CI runs `check` and the new-tests-fail-on-base job (D-060,
D-063, D-066). History through stage c: DECISIONS D-056 to D-059 and "Gate 3 baseline" (every
required mutant caught at its k-seed design; held-out 2 caught, 3 missed, permanent in RESULTS).

Gate 3 findings 1-9 are fixed (PRs #16-#24, D-061 to D-069) and generator coverage (#13) is
merged (PR #25, D-070). The re-review of the fixes is done (`docs/reviews/GATE3_FIX_REVIEW.md`);
its six findings are fixed in PRs #36-#38 (D-071 to D-073). Stage d (issue #26) ran twice on
GitHub Actions: run 41370326167 at 13cd4d8 (a record) and run 41386725959 at 9f2f0c3, the final
Gate 3 commit, tagged `gate-3`. RESULTS and README numbers come from the 9f2f0c3 run only
(owner); both runs are identical row for row (DECISIONS "Stage d at the final Gate 3 commit").
Post-fix held-out: #12 caught and closed; #10 and #11 still missed, open, in README Limitations.
v1.0's `kernel/`, `planners/`, `evals/`, `scripts/` and `tests/` are kept byte-identical to
9f2f0c3, so stale code comments (v1 review findings 10 and 15) wait for v1.1. Local memory: the commit charge has reached 32 GB of 32.6 GB with
other projects running; when a local run fails with "memory allocation failed", verify on CI.

**Owner delegation (2026-11-02): ship v1 autonomously.** Needs the owner's explicit yes:
(a) rewriting git history, (b) making the GitHub repo public, (c) weakening the invariant, a
test or a policy. Every gate still gets an independent reviewer; act on its findings, record
them in DECISIONS. Public docs (README, ADRs, WHAT_WENT_WRONG) discuss engineering only, not
the tools used to build the project, and never claim the owner wrote code or prose by hand.
Memory-heavy runs (fuzz, k-seed, held-out, evals at scale, models) go to owner-run commands or
GitHub Actions, never in session. Plan and progress (tick as done):
1. [x] 1.1 Record stage c as the Gate 3 baseline.
2. [x] Step 2: history scan (report; a rewrite needs the owner); merge phase3-wip into main
   --no-ff; annotated tags gate-0..gate-3; private GitHub repo; push; releases; labels; one
   issue per Gate 3 finding; PR template; Actions (check on PRs; tests-fail-on-base job;
   manual owner-run-stages workflow); record runner memory and free-minute limits. (gate-3
   tag not yet created: it goes on the final Gate 3 commit, item 4.)
3. [x] Steps 1.2/1.3 as issue + branch + PR each (merge commits): findings 1-9 with
   regression tests failing on 7da1652; generator coverage (domain-valid values in untrusted
   fields); post-fix held-out result reported separately (in stage d).
4. [x] Step 3 (stage d) on the fixed commit: check, k-seed at fresh seeds, post-fix held-out,
   evals and sweeps (run 41386725959 at 9f2f0c3); RESULTS updated; re-review and its fixes;
   tag gate-3 at 9f2f0c3.
5. [x] Step 4: v1 ships without a local LLM planner (D-074; RESULTS says so); the optional
   CI-only small-model job is skipped (owner, 2026-11-02). RESULTS stays hand-written (D-075).
6. [x] Step 5: README (numbers from the 9f2f0c3 stage d run; `tests/test_doc_links.py` checks
   its links), WHAT_WENT_WRONG, docs/adr/ (10), PROCESS, STUDY_GUIDE, code trimming pass
   (DECISIONS, nothing removed), `tasks.py demo` plus a committed transcript.
7. [x] Step 6: skeptical review (`docs/reviews/V1_REVIEW.md`) and fix re-review
   (`V1_FIX_REVIEW.md`), responses in DECISIONS; fixes (PR #48); fresh-clone reproduction
   following only the README (local, 341ad19: check, both evals, demo; DECISIONS "v1 release");
   v1.0 tagged on PR #48's merge commit, with a GitHub release; hand-off report given. Repo
   stays private. Before publishing, the owner decides whether the working records (CLAUDE.md,
   DECISIONS, docs/reviews/, SPEC's process text), which name the tooling, stay in a public
   repo. Open: #10, #11, #60 (v1.1), the language-model planner and `tasks.py report` (v1.1),
   stale comments deferred by the v1 review.
8. [x] Fuzz at v1.0 (issue #49): all six NI properties, 20 x 1,000 each, seeds from 202620100,
   0 failing in 120,000 examples (GitHub Actions run 41430446343; the first attempt,
   41429151228, was derandomized and does not count, #52). Recorded in RESULTS and DECISIONS,
   README limitation removed, released as v1.0.1 (PR #53). MIT LICENSE added after the tag
   (PR #51, issue #50).
9. [x] v1.0.2: the `fuzz` profile no longer inherits Hypothesis's CI profile (#52, PR #59,
   D-076; the base-fail job cannot judge a conftest fix and was red by decision, #60);
   WHAT_WENT_WRONG entry on the derandomized run (#57, PR #58); version 1.0.2 (#61).

Never run the fuzz or the owner-run stages inside a session. `check` takes about 2 min
(witness replays under the issue #13 generators, D-070).
