# Study guide

For a reader who wants to check the kernel rather than take the documents' word for it. The
kernel is about 2,300 lines in `kernel/`; the order below reads it in roughly an hour. Then come
25 questions a skeptical reviewer should be able to answer, each with a pointer to where the
answer can be worked out (the answers are not given), and three small exercises.

## Reading order through `kernel/`

1. `labels.py`: the label `(untrusted origins, sinks, provenance)` and its join.
   [DESIGN §2](DESIGN.md#2-label-lattice-d-002).
2. `values.py`: scalars, records and lists, and why reading a field or an element joins the
   container's label. [DESIGN §3](DESIGN.md#3-values-and-propagation).
3. `tools/registry.py`, then `tools/database.py`: tool signatures, which columns are
   attacker-writable, the existence origin `@row`, and the halt on a missing operator-named
   ticket. [DESIGN §2.1](DESIGN.md#21-column-labelling).
4. `plan_lang.py`: the plan language and its static checker. There is no `if`, `map` bodies are
   scoped, and `filter` is pure. [DESIGN §4](DESIGN.md#4-plan-language-d-004).
5. `interpreter.py`: how a plan resolves into labelled actions, `pc` inside `map`, the `filter`
   and `at` label rules, and the extractor's cumulative label.
   [DESIGN §3.1](DESIGN.md#31-program-counter-label).
6. `declassify.py`: the two rules, their origin sets and admission predicates.
   [DESIGN §6.1–6.3](DESIGN.md#61-declassification-as-policy-time-endorsement-d-006).
7. `policy.py`: one verdict per action, P0–P6. [DESIGN §6](DESIGN.md#6-policies).
8. `approval.py`: the canonical set and its hash. [DESIGN §7](DESIGN.md#7-approval-binding).
9. `execution.py`: the pre-pass, the re-check between effects, write-ahead refund rows, and
   recovery. [DESIGN §10](DESIGN.md#10-execution-layer-thin).
10. `runlock.py`: one writer per database.
11. `run.py`: the entry points that tie it together, and the audit rows.

Then the evidence, in `tests/`:
- `ni_properties.py`: the non-interference properties as executable checks;
- `test_noninterference.py`: the fuzzing that runs them;
- `test_ni_mutants.py` and `deterministic_mutants.py`: the deliberately broken kernels the
  harness must catch.

## 25 questions

1. What stops the planner from seeing ticket text, and what fails if that is broken?
   (`run.py` `PlannerInput`; `tests/test_import_boundary.py`; the leaked-context configuration
   in [RESULTS](RESULTS.md#setup).)
2. Why is `pc` a separate component of each action instead of being joined into values? What
   would a policy that ignored it let through?
   ([D-003](DECISIONS.md#d-003-control-dependence-no-if-pc-recorded-on-effects-not-values-filter-joins-all-predicates);
   the mutant "policy ignores pc".)
3. `filter` joins every predicate's label into its result. Construct the plan that per-element
   labels would get wrong. (D-003, "Rejected".)
4. Why does reading a ticket carry the row's existence as untrusted? What can a customer do with
   whether a row exists? ([D-028](DECISIONS.md#d-028-a-ticket-read-carries-its-rows-existence-origin-supersedes-d-021).)
5. A missing operator-named ticket halts the run. Why is that suppression rather than selection,
   and which property stops checking those pairs?
   ([D-054](DECISIONS.md#d-054-d-036-variant-adopted-a-missing-operator-named-ticket-halts-the-run-phase-3-step-4);
   DESIGN §9.3.)
6. The ownership rule admits only the customer's single eligible order. What does the ticket
   text still control? (DESIGN §6.2; [ADR 0007](adr/0007-ownership-rule-residual-risk.md).)
7. What is a release projection, and how would the tests catch a rule that releases more than
   it declares? (DESIGN §6.1; NI-3 in `tests/ni_properties.py`.)
8. Why can an endorsed value not become the condition of a `filter` that selects another
   action? (`declassify.py`; [ADR 0002](adr/0002-declassification-as-endorsement.md).)
9. The extractor is untrusted code that may keep state between calls. How does its cumulative
   label stop it from laundering a choice?
   ([D-044](DECISIONS.md#d-044-extraction-labels-follow-control-gate-2-findings-1-and-2); `interpreter.py`.)
10. What does the approval hash cover, and what does it deliberately leave out?
    (`approval.py`; [D-023](DECISIONS.md#d-023-verdict-reasons-are-not-hashed-supersedes-part-of-d-018).)
11. Could an approver be steered into approving an injected set? What does the evaluation
    measure about that, and why is it an upper bound?
    ([D-041](DECISIONS.md#d-041-step-5-design-effects-simulated-approver-per-rule-metrics-cap-sweep); approval steering in RESULTS.)
12. Why is the whole action set decided as one unit, and what does an attacker gain from that
    choice? ([ADR 0003](adr/0003-atomic-runs.md).)
13. Between effects, the run stops only if a verdict becomes stricter. Why is a relaxed verdict
    safe to ignore? ([D-045](DECISIONS.md#d-045-execution-pre-pass-then-a-re-check-that-stops-only-on-a-stricter-verdict-finding-4).)
14. Why is the refund row written before the provider call, and what does recovery do with a
    row left pending? (`execution.py`;
    [D-029](DECISIONS.md#d-029-refund-rows-are-written-before-the-provider-call).)
15. What exactly does the run lock lock, and which database configurations does the kernel
    refuse? (`runlock.py`; [ADR 0008](adr/0008-single-writer.md).)
16. NI-1 compares two runs whose untrusted inputs differ. What must be equal between the two
    environments, and what may differ?
    ([DESIGN §9.1](DESIGN.md#91-environments), §9.2.)
17. The fuzzer passed 60,000 examples while three real bugs were present. What does a passing
    fuzz run show, and what does it not show?
    ([WHAT_WENT_WRONG](WHAT_WENT_WRONG.md#60000-fuzz-examples-passed-while-three-real-bugs-went-unseen).)
18. How do you know the harness would notice a broken kernel, and why is the claim made over
    seeds rather than examples? ([ADR 0009](adr/0009-k-independent-seeds.md); `KSEED` in
    `tests/test_ni_mutants.py`.)
19. Three held-out mutants were missed. What could the generators not produce, and how would
    you tell whether the fix was tuned to those three?
    ([D-057](DECISIONS.md#d-057-held-out-mutants-at-gate-3-owner-2026-10-31),
    [D-070](DECISIONS.md#d-070-generator-coverage-domain-valid-untrusted-values-2026-11-02-issue-13-step-13).)
20. The scripted attacker succeeded in 393/414 dev pairs and 39/488 holdout pairs. Which number
    measures the attacks, and which measures the script?
    ([F-3](DECISIONS.md#f-3-finding-the-gullible-planners-triggers-are-fitted-to-the-dev-phrasing-owner-gate-2).)
21. With isolation deliberately broken, no attack succeeded. Why is that weak evidence for the
    label layer? ([WHAT_WENT_WRONG](WHAT_WENT_WRONG.md#the-leaked-context-result-is-weaker-than-it-looks).)
22. Which channels are out of scope, and which would matter first in a real deployment?
    ([THREAT_MODEL §6](THREAT_MODEL.md#6-out-of-scope).)
23. Every Warrant attack success falls inside a declared release projection. Is "inside the
    projection" the same as "harmless"? ([RESULTS](RESULTS.md#the-three-defences-side-by-side).)
24. What does an audit row not record, and could you replay a decision from it?
    ([DESIGN §6.1](DESIGN.md#61-declassification-as-policy-time-endorsement-d-006); `evals/trace.py`.)
25. What would change with a real language-model planner, and which results would carry over?
    ([RESULTS](RESULTS.md#what-these-results-may-and-may-not-claim), "may not claim".)

## Terms for the real-model evaluation

[SPEC_v1.1 §6.3](SPEC_v1.1.md#63-injection-serving-plans-and-hijack) keeps these apart. Can you say why each pair differs?

- **Injection-serving plan rate:** plans containing an action that serves the injection, whatever the cause. A correct plan acting on injected ids counts.
- **Hijack rate:** the part attributable to the injection: the plan serves it and a valid control plan, generated without it, does not. On dev it is shown beside the placebo arm's rate.
- **Unauthorized effect rate:** a serving plan led to an executed effect outside the intended set, the rules' releases, the approved set and the benign run's effects.

## Exercises

1. **Choose a refund with ticket text and no rule.** Write a plan that reads the case ticket,
   extracts order ids from its body, and uses `len` of that list as an `at` index to pick one of
   two orders to refund. Run it with `run_plan` (copy the setup from `scripts/demo.py`). Read
   the verdicts and the trace. Then predict which component labels make it need approval, and
   check your prediction in the audit row.
2. **Break the ownership rule.** In `kernel/declassify.py`, delete one admission condition of
   `ticket_order_ownership`, for example "never refunded" or "single eligible order". Run
   `uv run --locked python scripts/tasks.py check`. Which tests fail, and do they fail for the
   reason you expected? If none fails, write the test that would.
3. **Approve the wrong thing.** In `scripts/demo.py`, section 1b approves the hash of an earlier
   version of the set. Change it to approve the hash of the same actions with two amounts
   swapped. Predict the outcome and the audit row before running `tasks.py demo`.
