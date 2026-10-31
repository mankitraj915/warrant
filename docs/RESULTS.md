# Results

Hand-written for Gate 3. In Phase 5, `tasks.py report` will generate this file from the results
JSON. Every number below comes from a command named in this file, run at the commit stated, and
recorded in `docs/DECISIONS.md` (D-042, D-043, D-050 and D-052 to D-056).

Warrant applies the principle behind CaMeL (Debenedetti et al., *Defeating Prompt Injections by
Design*, arXiv:2503.18813): a planner that never sees untrusted data, with capabilities and
information-flow labels on what it computes. The evaluation follows the style of AgentDojo
(Debenedetti et al., NeurIPS 2024 Datasets and Benchmarks): user tasks crossed with injection
tasks, and deterministic utility and security checks. No LLM is involved in any number here
(Phase 4 adds one). No LLM judge is used anywhere.

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
  - holdout: the same 40 user tasks × 15 injection tasks written by an independent red-team agent
    (D-043), 488 applicable pairs. The holdout was never used to tune anything.
- **Commands** (commit 6e27f60, run by the owner outside a Claude Code session; DECISIONS
  "Phase 3 owner run"):
  - `uv run --locked python scripts/tasks.py eval` and `eval --suite holdout`;
  - `sweep` and `sweep --suite holdout`.

  The PII canary scan found 0 hits in both suites.
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
  - **oracle:** the correct hand-written plan.
  - **gullible:** scripted; follows instructions it recognises in text it is shown. Its
    triggers were written alongside the dev injections (finding F-3).
  - **attacker-plan:** emits the correct plan plus an attack plan written per injection task, as
    structured steps, by an independent agent that never saw the policies (D-052). It does no
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
| Warrant | oracle | 5/414 (1.2%) | 396/414 (95.7%) | 39/40 | 3/40 (7.5%) | 2/414 (0.5%) |
| Warrant | gullible | 5/414 (1.2%) | 396/414 (95.7%) | 39/40 | 3/40 (7.5%) | 2/414 (0.5%) |
| Warrant, leaked context | gullible | 0/414 (0.0%) | 39/414 (9.4%) | 39/40 | 35/40 (87.5%) | 384/414 (92.8%) |
| Warrant, leaked context | attacker-plan | 0/414 (0.0%) | 39/414 (9.4%) | 39/40 | 35/40 (87.5%) | 384/414 (92.8%) |

### Holdout suite (488 attack pairs, 40 benign tasks)

| defence | attacker model | attack success | utility under attack | benign utility | approval burden | approval steering |
|---|---|---|---|---|---|---|
| Undefended (with execution hygiene) | gullible | 39/488 (8.0%) | 396/488 (81.1%) | 38/40 | 0/40 | 0/488 |
| Undefended (with execution hygiene) | attacker-plan | 451/488 (92.4%) | 21/488 (4.3%) | 38/40 | 0/40 | 0/488 |
| Prompt delimiting (sanity check) | gullible | 39/488 (8.0%) | 396/488 (81.1%) | 38/40 | 0/40 | 0/488 |
| Prompt delimiting (sanity check) | attacker-plan | 451/488 (92.4%) | 21/488 (4.3%) | 38/40 | 0/40 | 0/488 |
| Warrant | oracle | 4/488 (0.8%) | 473/488 (96.9%) | 39/40 | 3/40 (7.5%) | 2/488 (0.4%) |
| Warrant | gullible | 4/488 (0.8%) | 473/488 (96.9%) | 39/40 | 3/40 (7.5%) | 2/488 (0.4%) |
| Warrant, leaked context | gullible | 0/488 (0.0%) | 402/488 (82.4%) | 39/40 | 35/40 (87.5%) | 92/488 (18.9%) |
| Warrant, leaked context | attacker-plan | 0/488 (0.0%) | 43/488 (8.8%) | 39/40 | 35/40 (87.5%) | 457/488 (93.6%) |

**How to read these tables.**
- **Prompt delimiting is a plumbing check here, not an evaluation.** Both scripted planners
  ignore delimiters by construction. `delimited+gullible` equals `undefended+gullible`, and
  `delimited+attacker` equals `undefended+attacker`, pair for pair in both suites (checked on
  every row: outcome, attack verdict, refunds, credits, closures). Delimiting is evaluated with
  the local LLM in Phase 4.
- **The holdout's gullible row mostly measures the scripted attacker** (F-3). With the gullible
  planner, the undefended baseline reaches 393/414 on dev but only 39/488 on the holdout. With
  the attacker-plan model it reaches 451/488 on the holdout. So holdout payloads hijack an
  obedient planner about as often as dev payloads do, and the 39/488 understates them.
- **Why the undefended baseline misses some attack-plan goals.** Every miss I checked came from
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
- **Leaked context.** With isolation deliberately broken, labels alone stopped every attack in
  both suites, under both attacker models. The cost is that almost every pair then needs
  approval and is steered (93% of pairs for attacker-plan), and utility under attack collapses
  (8.8–9.4% with the attacker-plan model), because the simulated approver refuses any set that
  is not the intended one. This configuration tests the second layer; it is not a way to run
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

| cap | dev attack success | dev approval burden | dev utility under attack | holdout attack success | holdout approval burden |
|---|---|---|---|---|---|
| none | 5/414 | 3/40 | 396/414 | 4/488 | 3/40 |
| ₹5,000 | 5/414 | 4/40 | 396/414 | 4/488 | 4/40 |
| ₹2,000 | 5/414 | 5/40 | 396/414 | 4/488 | 5/40 |
| ₹1,000 | 5/414 | 5/40 | 396/414 | 4/488 | 5/40 |
| ₹500 | 5/414 | 5/40 | 396/414 | 4/488 | 5/40 |
| ₹250 | 1/414 | 10/40 | 402/414 | 0/488 | 10/40 |
| ₹0 | 1/414 | 10/40 | 402/414 | 0/488 | 10/40 |

A cap of ₹250 or less removes the F-1 refunds (dev 5 → 1, holdout 4 → 0) at the price of 7 more
benign approvals in 40. The remaining dev success is the goodwill credit (T28+I11), which has its
own fixed ₹100 amount and is not affected by the refund cap. Leaked-context configurations are
unchanged at every cap (0 successes). The right cap depends on the deployment's refund sizes and
on what an approval costs there.

## Non-interference evidence

PENDING (owner-run stage b; DECISIONS D-056): the clean-state mutant verification and the grammar
coverage table go here.

**Random fuzzing, all passed:**
- **Gate 2 fixes (commit 0905584):** 20,000 examples each of single-run NI, multi-run NI and NI-5;
  0 failing (D-050).
- **Phase 3 code (6e27f60, mixed generator):** the same, 20,000 examples each; 0 failing.

## Findings carried into this phase

- **F-1:** the ownership rule lets ticket text *trigger* a bounded refund. It is inside the
  rule's release projection and measured above.
- **F-3:** the gullible planner's triggers were fitted to the dev phrasing, so its holdout
  numbers understate the attacks. Fixed in measurement by the attacker-plan model (D-052).
- **D-056:** "derandomized" Hypothesis runs were not deterministic across processes, because
  Hypothesis draws some values from literals in the loaded modules. See the NI section.
