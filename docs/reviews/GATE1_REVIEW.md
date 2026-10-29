# Gate 1 independent review

**Reviewer:** a fresh subagent, given only `docs/THREAT_MODEL.md`, `docs/DESIGN.md` and the code
as of commit `0c25bff`, excluding `tests/test_evals.py` (which pins evaluation results). It did
not see `DECISIONS.md`, `SPEC.md`, `CLAUDE.md`, `docs/reviews/`, `results/`, git history, the
author's reasoning, or any evaluation results. Its job was to find a way to violate the
invariant. Its probes live in the session scratchpad (local temp path redacted by author) and
are not part of the repository; the regression tests named in Part 2 reproduce them.

Part 1 is the review, verbatim. Part 2 is the author's response to each finding.

---

## Part 1: Findings (verbatim)

## Warrant Gate 1 independent review: findings

Scope: I read only docs/THREAT_MODEL.md, docs/DESIGN.md, kernel/, quarantine/, planners/, domain/, evals/harness.py, evals/tasks/, evals/netguard.py, scripts/tasks.py, pyproject.toml, and tests/ except test_evals.py. I modified no repository file. All probes are in `<scratchpad>\gate1_review\` and were run from the repo root with `uv run --locked python <probe path>`. I also ran `uv run --locked python -m pytest tests/test_noninterference.py --hypothesis-show-statistics -p no:cacheprovider` (check profile). It passed with 200 examples and 7 invalid cases. Rule consulted with equal projection: 59.9% of examples. Rule admitted: 11.6%. Suppressed: 4.8%. Outcomes blocked/blocked: 58.0%. Outcomes executed/executed: 17.9%.

I found no way for an arbitrary plan, under the shipped kernel, shipped extractor and a healthy provider, to make untrusted ticket or note text select or parameterize an executed refund other than through the ownership rule's documented one bit. The findings below are the places where the guarantee or its evidence is weaker than the documents claim.

---

### 1. Whether a customer-created ticket row exists decides a fully trusted, rule-free refund (NI-1 fails under DESIGN §9.1's own environment relation)

**Severity:** invariant violation under the design's own NI definition. The practical impact is low.

**Affected:**
- kernel/tools/database.py:355-365. `read_ticket` gives the structure label `ticket_id.label` only. Row existence is not labelled.
- DESIGN §2.1 taints existence only for ticket enumeration. DESIGN §9.1 lets ticket row sets differ between E1 and E2.
- planners/fuzz.py:85-95. `mutated()` only rewrites text cells. It never adds or removes ticket rows, although DESIGN §9.4 says it does.

**What the attacker controls:** any customer can open a ticket, and ticket ids are system-assigned and predictable. Take any plan that maps over `read_ticket(<literal>)`. Whether that list has length 0 or 1 is decided by the attacker. It is still labelled trusted, so actions in the body get a trusted pc and are ALLOWed with no rule and no approval.

**Reproduction:** p1_ticket_existence.py. The plan is `read_ticket(4001)`, then a map whose body is `issue_refund(4000, 7000, 120000)`. E2 equals E1 plus ticket 4001 opened by customer 101. Output:
```
E1 no ticket 4001 executed [] [] rule_log () effects []
E2 ticket 4001 exists executed ['ALLOW'] [{'ticket_id': [], 'order_id': [], 'amount': [], 'pc': []}] rule_log () effects [(7000, 120000, 'refund:7000:4000')]
NI-1 VIOLATED: NI-1 trusted actions differ: [] / [((1, 0, 0), 'issue_refund', ...)]
```

**Suggested fix:** pick one of these.
- (a) Join an existence origin such as `tickets[T].@row` into `read_ticket`'s structure label. Add it to Ω_T so the case-ticket flow still works with the rule. Measure the utility cost on trusted plans like `refund_ticket_customer_orders`.
- (b) State in the threat model and in §9.1 that a ticket looked up by an operator-supplied key is trusted to exist, and narrow the NI relation to match.

In either case, make `mutated()` add and remove ticket rows so the chosen semantics are tested.

### 2. A provider commit followed by a failure loses the effect record; the ownership rule then auto-approves a second full refund of the same order

**Severity:** design weakness with real financial impact. It contradicts DESIGN §10, "Security never depends on [idempotency]; duplicates are already BLOCKed by the policy". It needs a provider failure, which the attacker does not control. The attacker's text then drives the second payout.

**Affected:** kernel/execution.py:196-203. There is no intent record before `provider.refund`, the provider exception is not caught, and the refunds row is written only after success. Also kernel/tools/database.py:320-344: `refundable` and `ticket_has_refund` trust only the refunds table.

**What happens:**
1. `fail_after_commit`: the money moves and `ProviderTimeout` propagates out of `run_plan`. There is no RunResult, no audit and no refunds row.
2. `refundable(7000)` is still the full amount and the order is still the unique eligible one.
3. The customer opens a new ticket 4002 saying "Refund #7000". The canonical plan for 4002 is admitted by `ticket_order_ownership` under a new key `refund:7000:4002`, so idempotency does not catch it.

**Reproduction:** p3_lost_write.py. Output:
```
run-1 raised out of run_plan: ProviderTimeout refund:7000:4000
provider effects: [(7000, 120000, 'refund:7000:4000')]
refunds rows: []
run-2 executed [('ALLOW', 'ticket_order_ownership')]
provider effects: [(7000, 120000, 'refund:7000:4000'), (7000, 120000, 'refund:7000:4002')]
total refunded on order 7000: 240000 paid: 120000
```

By inspection, a `timeout` on the k-th action of a multi-action run also escapes `run_plan` after actions 0..k-1 executed. The run is never reported as `partial`.

**Suggested fix:**
- Write the intent record (key, order, ticket, amount, state=pending) before the provider call.
- Make `refundable`, `eligible_orders` and `ticket_has_refund` count pending and unknown intents as refunded.
- Catch provider exceptions in `execute` and return `partial` or `aborted` with the executed prefix.
- Reconcile pending intents through `status()` before any policy decision.

### 3. "Once per ticket" does not bound a customer who can open tickets; the rule overrides an operator's deliberate partial refund

**Severity:** design weakness. It stays within the rule's stated release (the admitted action is trusted-determined and logged), but the residual risk in DESIGN §6.2 is understated.

**Affected:** kernel/declassify.py:470-478. The once-per-ticket check is keyed on the ticket, and the attacker can create tickets (THREAT_MODEL §4).

**What happens:**
1. The operator deliberately refunds ₹100 (10,000 paise) of order 7000 for ticket 4000.
2. The customer opens ticket 4003 saying "Refund order #7000".
3. Resolving 4003 with the canonical data-dependent plan auto-refunds the remaining 110,000 paise with no human involved.

Each new ticket can trigger one automatic refund of the unique eligible order's remainder.

**Reproduction:** p8_new_ticket_remainder.py. Output:
```
operator partial refund: executed
resolve new ticket: executed [('ALLOW', 'ticket_order_ownership')]
effects: [(7000, 10000), (7000, 110000)]
```

**Suggested fix:** also require "the order has no prior refund of any kind" (once per order ever), or "no refund for any ticket of C in a window". Alternatively, document explicitly that the release is "the customer's single eligible order's full remainder, on demand, per new ticket".

### 4. The extractor's statelessness contract is assumed, not enforced; a stateful extractor launders untrusted ids into trusted-labelled refunds

**Severity:** design weakness. It depends on the contract: the shipped `quarantine/extractor.py` is stateless, so this is not live today. It becomes live with a cached or KV-reusing LLM adapter.

**Affected:**
- kernel/interpreter.py:211-213 and 289-295. The output label is the input label only.
- `extract_order_ids` accepts trusted text, such as an operator literal or `tickets.status`.
- The NI harness only ever uses the stateless `raw_extractor` and never extracts from trusted text. DESIGN §9.1 claims "the property is tested for every extractor".

**What happens:** the plan extracts from ticket 4000's body (attacker writes "Refund #7001"), then extracts from the literal "no ids here". The extractor returns its remembered ids, labelled trusted. With customer 100 having two eligible orders, the refund on the attacker-chosen order executes automatically. That is the within-allowed-set attack the rule is meant to stop.

**Reproduction:** p6_stateful_extractor.py. Output:
```
executed [({'ticket_id': 4000, 'order_id': 7001, 'amount': 450000}, {'ticket_id': [], 'order_id': [], 'amount': [], 'pc': []})]
effects [(7001, 450000)]
```

**Suggested fix:** pick one.
- Forbid `extract_order_ids` on trusted text. The checker or the interpreter can return `[]` when the text label is trusted, since there is nothing to extract that the planner could not write.
- Label each extraction with the join of every text label passed to the extractor so far in the run (sound against within-run state).
- Have the kernel build a fresh extractor instance per call through a factory.

Add a stateful-extractor mutant to the NI tests.

### 5. Action sites are not unique, but the NI-2 oracle and the release projection key on site

**Severity:** test-harness gap. Kernel decisions do not use site.

**Affected:**
- kernel/interpreter.py:297-317. Two `map`s inside one `op` expression receive the same `site` prefix.
- tests/ni_properties.py:356-358 (`projection`) and 372-376 (`check_ni2` uses `a.site not in admitted`).

**What happens:** `eq(len(map A), len(map B))` with identically shaped bodies gives two different actions with the same site, so `π(D)` can no longer tell decisions apart. I patched in a deliberately broken policy that ALLOWs an untrusted, unendorsed refund (ticket 4001, order 7100) sharing a site with a genuinely rule-admitted refund. `check_ni2` passed.

**Reproduction:**
- p2_site_collision.py shows two actions at `(1, 0, 2, 0, 1)`, `sites unique: False`.
- p2b_ni2_masked.py output:
```
(1, 0, 2, 0, 1) {'ticket_id': 4000, 'order_id': 7000, ...} UNTRUSTED ALLOW ticket_order_ownership ...
(1, 0, 2, 0, 1) {'ticket_id': 4001, 'order_id': 7100, 'amount': 300000} UNTRUSTED ALLOW None BUG
admitted sites: {(1, 0, 2, 0, 1)}
check_ni2 PASSED despite an untrusted unendorsed ALLOW
```

**Suggested fix:** make sites unique by including an expression path or a per-run sequence number. Assert uniqueness in the interpreter. Key NI-2 on action identity or index, not on site.

### 6. NI harness coverage gaps (mutants it does not catch; environment and plan classes it never generates)

**Severity:** test-harness gap.

**Reproduction:** p9_extra_mutants.py, 600 derandomized examples, the same setup as tests/test_ni_mutants.py. Output:
```
M1 rule ignores origin set: NOT CAUGHT
M2 rule ignores amount: caught (NI-4)
M3 contains ignores list labels: caught (NI-1)
M4 field drops selection label: NOT CAUGHT   [equivalent mutant: records are only reachable through list binders, so struct/pc always carry the selection; not a real gap]
M5 rule drops persistent once-per-ticket: NOT CAUGHT
```

- **M1:** with θ=0 none of NI-1..NI-4 depends on the Ω_T origin restriction. That kernel check is covered only by the unit test `test_rejects_ids_from_text_outside_the_case_ticket`. NI-2 does not check that endorsed origins lie within the rule's permitted set.
- **M5:** the property never runs sequences of runs, and the case ticket never has a prior refund, so the cross-run NI-4 postcondition DESIGN §9.4 promises is untested by the fuzzer.

Further gaps, by inspection of planners/fuzz.py:
- No ticket-row addition or removal (see finding 1).
- The extractor is fixed. The fuzzer never produces exceptions, non-list results, non-int types, stateful behaviour or extraction from trusted text (see finding 4).
- The ticket id is always a literal.
- It never extracts from `subject`.
- It never puts maps inside ops or in filter `over`, so finding 5 cannot arise.
- `customers.display_name` is mutated but never readable.

**Suggested fix:**
- Add M1 and M5 to the MUTANTS list.
- Add an NI-2 origin check against each rule's declared origin set.
- Add a multi-run property on an evolving world, with attacker edits and new tickets between runs.
- Add ticket-row mutations, extractor-behaviour draws, and the missing plan shapes.

### 7. The idempotency key `refund:{order}:{ticket}` silently drops a legitimate second refund and reports it as executed

**Severity:** minor (correctness and audit).

**Affected:** kernel/execution.py:195-203.

**What happens:** a second trusted partial refund on the same order and ticket, in a later run, finds the old key through `status()`. Nothing is paid, `INSERT OR IGNORE` writes nothing, and the outcome is still `executed`.

**Reproduction:** p7_key_reuse.py. Output:
```
r1 executed [('refund:7000:4000', 'pay-1')]
r2 executed [('refund:7000:4000', 'pay-1')]
provider effects [(7000, 10000)]
```

**Suggested fix:** include a per-action intent id (run_id plus site) in the key. Alternatively, BLOCK a second refund on the same (order, ticket) explicitly rather than silently deduplicating it.

### 8. Latent hazards in what is labelled and bound (not reproduced; by inspection)

**Severity:** minor.

- **"pc" key collision:** `ResolvedAction.component_labels` (kernel/interpreter.py:226-229) and `policy.components` (kernel/policy.py:329-333) store the pc under the key `"pc"` after the arguments. A future tool parameter named `pc` would have its label silently replaced, possibly by a trusted pc. Assert in the registry that no parameter is named `pc`.
- **Approval run_id:** `run_task` uses `run_id=task_id` (kernel/run.py:141-142). DESIGN §7 requires a fresh random UUID per run so approvals cannot be replayed. This matters once Phase 2 executes approvals; `planned_tasks` is per Environment only.
- **What the canonical approval set leaves out:** kernel/approval.py does not bind site, the rule decisions, the plan label or sinks.
- **P5 sinks:** not enforced anywhere in kernel/policy.py. Harmless now, because no Phase 1 tool has a sink argument.

---

### Things I tried that held up

- **Label propagation:**
  - Tainted predicates in `filter`, including `contains` of extracted ids.
  - Tainted `at` indices, `len` of tainted lists, and `add`/`sub`/`min`/`max` on tainted money.
  - Nested map/filter, trusted values bound outside and returned or used inside tainted maps, and all-literal calls inside tainted maps (the pc carries the taint).
  - Map results escaping through `len`, `at` and `contains`. The no-`if`, block-scoped design held: no value left a body without the structure label.
- **Unit results:** `List[Unit]` cannot be bound, nor used in `len`, `at`, `contains`, `eq`, `map`/`filter` over, or as an argument. Names are globally unique and body scopes are copies.
- **Static checker:**
  - Id kinds do not mix; there is no arithmetic on Ids; bools are not ints and ints are not bools; Money and Int do not mix.
  - Map is rejected inside predicates and depth is bounded.
  - Pydantic coerces int and str subclasses to plain `int`/`str`.
  - 3000 nested `not`s and 200 chained `add`s are rejected cleanly as PlanRejected, with no escaping RecursionError.
- **Extractor boundary:** bools, int subclasses, ≤0 or >10^15 values, non-list results, more than 5 ids and exceptions all yield validated ints or `[]`. Invalid UTF-8 and BLOBs in untrusted cells decode without raising.
- **Ownership rule:**
  - An untrusted `ticket_id`, origins outside the ticket's own subject/body (order notes, other tickets) and ★-collapsed origins are all rejected.
  - Two eligible orders, a non-full amount, and more than one refund for the ticket in the same action set are rejected. The same order twice is BLOCKed.
  - With θ=0 the admitted action is always (T, the unique eligible order, the recomputed full amount), so I found no redirection or inflation.
- **Policy ordering and atomicity:** the rule is consulted before the BLOCK checks, and any BLOCK or NEEDS_APPROVAL executes nothing. Phase 1 has no approval-execution path.
- **Re-check partial runs:** I could not build a run where executing one ALLOWed refund flips a later one's verdict. Duplicate orders and two refunds for one ticket in a run are already rejected, and admissions for different customers are independent.
- **Leaked-context configuration:** the plan label taints every literal and the root pc, so the rule rejects (ticket_id untrusted) and nothing is ALLOWed.
- **Persistence:** refund records are kernel-written facts about executed, warranted actions. No agent-writable untrusted column exists in Phase 1.
- **Import boundary and network guard:** I read both. The audit-hook guard covers the C socket layer. Bypassing it would require hostile code, which is outside the threat model.

---

## Part 2: Responses

Regression tests are in `tests/test_gate1_regressions.py`. Run against commit `0c25bff` before
any fix, `pytest tests/test_gate1_regressions.py` gave **8 failed, 2 passed**. The two passing
tests are the `pc` parameter guard and a check that the case ticket's own flow still works; the
eight failing ones reproduce findings 1–5 and 7.

| # | Verdict | Response | Where |
|---|---|---|---|
| 1 | **Accepted; fixed.** This was a real violation of NI-1 as the design defines it. D-021 had argued that keyed ticket lookups are trusted, but DESIGN §9.1 had not been narrowed to match and the fuzzer never varied rows. | `read_ticket(T)` now joins the existence origin `tickets[T].@row`, which the ownership rule may endorse. The fuzzer now opens ticket 4001 for another customer or deletes the case ticket, and has a `probe` shape. The cost is measured: T08 is now rule-decided (still admitted). One side effect was found and fixed: two label mutants were masked by the rule until note-driven selection shapes were added. | D-028; `kernel/tools/database.py`, `kernel/declassify.py`, `planners/fuzz.py` |
| 2 | **Accepted; fixed.** | A `pending` refund row is written before every provider call and counts as refunded. Provider exceptions are reconciled by status, and the run reports `aborted`, `partial` or `indeterminate` instead of raising. Both of the reviewer's scenarios are regression tests. The new multi-run property also checks that no order is refunded beyond its payments, under injected `fail_after_commit` and `timeout`. | D-029; `kernel/execution.py` |
| 3 | **Accepted; fixed** with the reviewer's first option. | The rule also requires that the order has never been refunded. NI-4's independent oracle checks the same condition, and a multi-run mutant shows the harness catches its removal. | D-030; `kernel/declassify.py`, `tests/ni_properties.py` |
| 4 | **Accepted; partly fixed.** | Extraction labels are now cumulative within a run, which closes the reviewer's probe (regression test). Cross-run extractor state is still a contract requirement and is not enforced by labels. This is stated in DESIGN §3 and §9.1, which no longer claim that "every extractor" is covered. I did not add a stateful-extractor mutant to the fuzzer: a dedicated regression test covers the within-run case, and the fuzzer's raw extractor stays stateless by design. | D-031; `kernel/interpreter.py` |
| 5 | **Accepted; fixed.** | Sites are unique paths. NI-2 now fails on duplicate sites and requires each untrusted ALLOW to have its own admitting decision from the same rule. Both behaviours have regression tests. | D-032; `kernel/interpreter.py`, `tests/ni_properties.py` |
| 6 | **Accepted; mostly fixed.** | Fixed: M1 (rule ignores origin set) is caught by the new NI-2 origin check. M5 is caught by the new multi-run property. Two further cross-run mutants were added (never-refunded order, record before the provider call). All 10 mutants are caught. Added: ticket-row mutations and the multi-run property. I agree with the reviewer that M4 is an equivalent mutant. Not closed and recorded for Phase 2: non-literal ticket ids, extraction from `subject`, maps in filter sources, a readable `display_name`, and fuzzer-drawn extractor behaviours. | D-033, D-035 |
| 7 | **Accepted; fixed** by the reviewer's second option. | The policy now BLOCKs a second refund on the same order and ticket, so it is never reported as executed while silently deduplicated. Intent-id keys come with Phase 2 recovery. | D-034; `kernel/policy.py` |
| 8 | **Accepted; one fixed, the rest deferred with reasons.** | `pc` parameter collision: the registry now asserts this at import. Random `run_id`, and binding rule decisions or plan label: Phase 2, when approvals execute. Site is deliberately not bound. P5 sinks: enforced with the first sink-bearing tool. | D-035 |

**Did I accept anything mainly because the reviewer raised it?** No, but finding 3's fix is a
judgement call I would defend on its own terms. "Never refunded" narrows the rule more than
the bug strictly requires. "Not refunded through any ticket of this customer within N days"
would also have closed it. I chose the simpler condition because it needs no new parameter
and has no utility cost on the dev suite.
