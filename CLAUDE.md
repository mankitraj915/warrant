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
- `eval`: default offline evaluation (no LLM): dev suite (40 user tasks, 11 injections) ×
  {warrant+oracle, warrant+gullible, undefended+gullible, leaked+gullible}, Warrant
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
- `eval-llm`: evaluation with the local model. Phase 4, not yet.
- `report`: regenerate `docs/RESULTS.md`. Phase 5, not yet.
- `demo`: scripted demonstration. Phase 5, not yet.

## Current status

Phase: 2 complete, at **⛔ Gate 2**, waiting for the owner's decision (Gate 1 approved
2026-10-30). All Phase 2 plan steps are done (D-037–D-043). The Gate 2 independent review
(`docs/reviews/GATE2_REVIEW.md`) found seven issues, all fixed, with regression tests in
`tests/test_gate2_regressions.py` (D-044–D-049). Evaluation re-runs after the fixes are in
D-050 (unchanged). The post-fix chunked fuzz is still owed: it was stopped for low system
memory after 1 of 60 chunks (D-050), so rerun it only with the owner's go-ahead and enough
free memory (base seeds 202610800 / 202610900 / 202611000; `--first 1` resumes the first
property). Next: the owner's Gate 2 decision, then Phase 3. `check` takes about 4 min.
