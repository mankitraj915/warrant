# Decision log

Each entry records a decision, the alternatives rejected, and why. Newest phases are appended at
the end. `DESIGN.md` states the resulting design; this file is the argument for it.

---

## Phase 0 plan (2026-10-29)

1. Read CLAUDE.md and SPEC.md completely.
2. Scaffold tooling: uv lockfile, ruff, `mypy --strict` on `kernel/`, pytest, Hypothesis profiles,
   network-blocking fixture, import-boundary test, Makefile. No feature code.
3. Write THREAT_MODEL.md, keeping it free of policy detail because the holdout red team will read it.
4. Write DESIGN.md: lattice, pc semantics, grammar, policy and declassification semantics,
   re-planning decision, NI statement.
5. Record decisions (below) and spec issues (end of file).
6. Independent review by a subagent given only THREAT_MODEL.md, DESIGN.md and the code.
7. Gate 0 report.

---

## D-001 Re-planning: forbidden; plans are single-shot

**Decision.** The planner is invoked once, before any tool runs, with a kernel-built input of the
operator request and tool signatures. Data-dependence is expressed inside the plan (extractor,
`map`, `filter`). The kernel gives every plan a *plan label*, the join of its inputs' labels,
which literals and the root `pc` inherit. It is `⊥` in the standard configuration.

**Rejected: re-planning with outputs labelled by the join of everything the prompt saw (spec
option b).**
- It is sound. But once the planner has seen any untrusted result, the whole re-plan, including
  which tools it calls, is untrusted-selected. Every consequential action in it then needs
  approval or a rule.
- A rule could admit such an action equally well in a single-shot plan. So re-planning buys no
  automatic utility on consequential actions. It only buys flexibility in non-consequential
  exploration, which `map`/`filter` already cover.
- Costs: multi-round state, an adaptive planner in the NI harness (plans would depend on `E`, so
  NI must quantify over planner strategies, not plans), and a larger TCB.

**Kept from option (b):** the plan-label mechanism. Literals need *some* label anyway; making it
the join of the planner's inputs costs nothing and lets us run a "gullible with leaked context"
stress test soundly (S-12).

**Expected cost (measure in Phase 1):** tasks whose action kind must be read from the ticket
("refund or credit?") will have an untrusted `pc` and go to approval. Re-planning would not
avoid that either.

## D-002 Label lattice: (untrusted origins, allowed sinks, trusted provenance)

**Decision.** `ℓ = (U, S, P)`. `U` is a set of untrusted cell origins (union, collapse to `★`
above 32). `S` is a set of allowed sinks (intersection). `P` is trusted provenance, used for
audit only. Trusted for authority ⇔ `U = ∅`.

**Rejected:**
- *The spec's single set mixing sources `{OPERATOR, SYSTEM_DB, UNTRUSTED}` with origins.* It
  conflates what decides (is anything untrusted?) with what explains (where did it come from?).
  OPERATOR vs SYSTEM_DB is never needed by a policy.
- *Two-point integrity {trusted, untrusted} without origins.* Too coarse. The ownership rule must
  admit an order ID taken from *this case's ticket* and refuse one injected through another
  customer's order note. Only origins tell these apart.
- *Decentralised label model (owners/readers per principal, Myers–Liskov).* It is more
  expressive: customers as principals with authority over their own orders is the natural
  formal reading of the ownership rule. But it is heavier than one rule justifies, and it
  makes the kernel harder to read in an hour (SPEC §11).
- *Character-level taint on strings.* Values crossing into plans are typed; free text never
  reaches a consequential argument without going through the extractor.

## D-003 Control dependence: no `if`; `pc` recorded on effects, not values; filter joins all predicates

**Decision.**
- The language has no conditional; `filter` (and `at` / list-shaped absence) covers selection.
- `pc = plan_label ⊔ struct(xs)` inside a `map` body. `filter` evaluates every predicate (no
  short-circuit, including `and`/`or`) and joins **all** predicate labels into the result's
  structure label. List element reads always join the structure label.
- `pc` is recorded on each consequential action and checked explicitly by policy. It is not
  joined into pure values.

**Why not join `pc` into values too.** First draft did; writing the canonical refund example
showed it taints the operator's `ticket_id` literal inside the refund `map`, so no rule keyed on
"the case's ticket" could ever apply. Joining is unnecessary for soundness here: the language is
pure and block-scoped, so values leave a body only through the result list, whose structure
label carries the dependence.

**Rejected:**
- *Per-element filter labels* (each kept element joined only with its own predicate label).
  Unsound: dropping element *i* shifts every later index, so `at(filtered, 0)` would be
  selected by untrusted predicates while looking trusted.
- *Including `if`.* Sound with `pc`, but redundant with filter-over-singleton, and it adds a
  second implicit-flow construct for the fuzzer to cover.
- *Checking `pc` only through argument labels* (the spec's "effective argument labels include
  `pc`"). A consequential call with no arguments, or whose arguments are all literals, would
  escape. So `pc` is a separate component of every action.

## D-004 Plan grammar: JSON AST, block-scoped `map`, pure `filter`, `Unit`-typed effects

**Decision.** See DESIGN §4.
- `let`/`call`/`expr` steps; `lit`, `ref`+`path`, `op` (fixed operator set); `map` whose body is a
  scoped block of steps; `filter` with a pure predicate.
- Tool names form a JSON Schema enum.
- Consequential tools return `Unit`, which cannot be bound.
- Nesting depth ≤ 2 and a static work budget.

**Rejected:**
- *Python subset (CaMeL).* Larger interpreter, harder static checking, harder to grammar-constrain.
  The spec's contribution #1 is precisely the restricted language.
- *Flat SSA of tool calls only.* Cannot express predicates or per-element computation.
- *`map` body as a single call.* Cannot compute a per-element amount before acting. Found while
  writing the §4 example.
- *Allowing consequential results to be referenced* (for example a refund ID in a closing note).
  It would interleave execution with evaluation, so the full action set could not be resolved
  and hashed before approval (§4.6), and a later block would leave earlier effects half-done.
  The kernel can link records itself.
- *Unbounded recursive schema.* With a fixed `MAX_DEPTH`, the JSON Schema can be emitted unrolled
  if the llama.cpp grammar converter (Phase 4) mishandles recursive `$ref`. Not yet verified;
  this is a Phase 4 risk.

## D-005 Resolve the whole action set first; decide atomically

**Decision.** Resolve all consequential calls into an ordered list `A`, then decide. Execute `A`
only if every action is `ALLOW`, or the human approved `hash(A)`. Any `BLOCK` executes nothing.

**Rejected: execute the ALLOW subset and request approval for the rest.**
- Better utility for bulk refunds.
- But the human would approve a remainder whose meaning depends on what already ran. It also
  breaks "approve the exact set": the executed set would not be the hashed set.

**Cost:**
- An attacker who gets one action in a batch BLOCKed or routed to approval holds up the whole
  batch. That is suppression, which is out of scope (THREAT_MODEL §6) but measured as utility
  under attack.
- Plans should filter ineligible items (trusted filter) before acting.

## D-006 Declassification is policy-time endorsement of specific action components

**Decision.**
- A rule never relabels a value.
- Consulted by a policy for one action, a rule may endorse named components (arguments and/or
  `pc`) whose untrusted origins lie within an origin set the rule names.
- Each consultation is logged with its inputs and outcome.

**Rejected: an `endorse(x)` operator in the plan language that returns a trusted value (CaMeL-style
capability upgrade).**
- An endorsed value could then be used as a `filter` condition or a `map` list to select
  *other* actions. Its release would no longer be bounded by the rule's postcondition.
- The planner would also have to know to call it.

## D-007 Evaluation is total

**Decision.**
- No partial operators (`at` returns a ≤1-element list).
- Tools return empty lists or `0` for missing data.
- Lists are truncated at `MAX_LIST`, and the truncation is logged.
- Worst-case work is bounded statically.
- Any exception is a kernel bug that fails the NI test.

**Rejected:**
- *Abort on error, and termination-insensitive NI* (the standard relaxation). An attacker who can
  make extraction raise could suppress a whole plan's trusted actions through an unlabelled
  channel.
- *A runtime work budget.* Exceeding it would depend on tainted list lengths: the same abort
  channel again.

## D-008 Non-interference is stated as four checkable properties

**Decision.** NI-1 trusted-action determinism, NI-2 policy soundness, NI-3 delimited release of
effects (`D(E1) = D(E2) ⇒ X(E1) = X(E2)` with a denying approver), NI-4 rule postconditions.
The fraction of pairs where a rule was consulted and the fraction where `D` differed are
reported with every run (DESIGN §9).

**Rejected: the spec's single check plus "unless it is an enumerated residual risk".** Not
mechanically checkable: whether a difference is "the documented residual risk" would be a
judgment call made after seeing the difference. NI-3 is the delimited-release formulation
(Sabelfeld & Myers, 2004), which makes "documented residual" precise: rules release only
through `D`.

**Why NI-1 as well.** NI-3 is vacuous on pairs where `D` differs. NI-1 needs no precondition, and
it catches laundering bugs even when effects happen to coincide.

## D-009 Refund signature and money

**Decision.**
- `issue_refund(ticket_id, order_id, amount)`. The ticket is a trusted argument: the case anchor
  for the ownership rule, and the second half of the idempotency key `refund:{order}:{ticket}`
  that SPEC §4.7 already requires.
- Money is integer minor units (paise) everywhere, never float, so canonical hashing is exact.
- No "amount ≤ cap" acceptance of untrusted amounts (S-5).

## D-010 Within-allowed-set: approval unless the order is the customer's only eligible one

**Decision.** `ticket_order_ownership` admits only the customer's unique eligible order, for its
full refundable amount, once per ticket (`θ = 0`). The threshold variant (`… or refundable ≤ θ`)
is a single parameter, measured in Phase 1.

**Rejected:**
- *Admit any owned eligible order.* Leaves redirection among the customer's orders unbounded.
- *Admit by amount threshold alone.* It bounds the loss but still lets text choose the target.
  It remains available as `θ > 0` if the measured approval burden of `θ = 0` is too high.
- *Classify whether text is "the customer's own words".* Impossible to do soundly; both are
  bytes in the same field. It would also be an LLM-based defence, which is forbidden as a
  primary layer.

**Consequence:** with `θ = 0`, the admitted action is a function of trusted data only. Untrusted
text decides one bit per ticket (auto-execute vs approval).

## D-011 Tooling

**Decision.**
- Python 3.12 (uv-managed), `uv.lock` committed, `[tool.uv] package = false`.
- `make` targets delegate to `scripts/tasks.py`, which runs every recipe with the venv's
  interpreter.
- A hand-rolled network guard in `tests/conftest.py` patches `socket` at `pytest_configure`, so
  it also covers collection-time imports.

**Why the task runner.**
- GNU make is not installed on the development machine (no winget, choco or scoop either), and
  Windows make recipes behave differently under `cmd` and `sh`.
- With one-line recipes, the Makefile cannot diverge from what is verified here with
  `uv run --locked python scripts/tasks.py check`.

**Rejected:**
- *pytest-socket.* One more dependency for about ten lines that a reviewer can read.
- *A session-scoped fixture.* Misses imports at collection time.
- *A function-scoped autouse fixture.* Interacts badly with Hypothesis' function-scoped-fixture
  health check.

## D-012 Layout refinements

**Decision.**
- `kernel/` defines the interfaces it needs (an `Extractor` protocol, the tool registry). The
  extractor and planners implement them outside `kernel/` and are wired at a composition root
  in `evals/`. Required by the import boundary (SPEC §4.1).
- Phase 0 creates only `kernel/__init__.py`. Other packages appear when they get code (no empty
  stubs).
- The import-boundary test also forbids `importlib`/`__import__` inside `kernel/`. Otherwise a
  dynamic import would bypass the static check.

## D-013 Approval records bind the run and are single-use

**Decision.** Approve `(run_id, sha256(canonical A))`. The approval is consumed on execution, and
BLOCK checks are re-run at execution time.

**Rejected: hash of the action set alone.** An approval for "refund order 1007, ₹1,299" could be
replayed in a later run producing the same set.

---

## Spec issues raised at Gate 0

Each issue has a proposed fix. Fixes marked (adopted) are already reflected in DESIGN.md; the
owner may overrule.

| # | Spec § | Issue | Proposed fix |
|---|---|---|---|
| S-1 | 4.2, 4.9 | "SYSTEM_DB" is treated as trusted, but tickets (and other attacker-written text) live in the same SQLite DB | Column-level labelling map `Λ` (adopted, D-002) |
| S-2 | 4.2 | Sources and origins are mixed in one set; the OPERATOR/SYSTEM_DB distinction is unused; yet origins are *needed* for decisions (rule scoping) | `(U, S, P)` lattice (adopted, D-002) |
| S-3 | 4.2 | pc rule says "label of the condition", but `map` has no condition (the list governs); per-element filter labelling misses index shifts; calls with untainted or no args escape | D-003 (adopted) |
| S-4 | 4.2 | pc is described for integrity only; confidentiality has implicit flows too | Policy checks `pc.S` against each argument's sink (adopted, DESIGN P5) |
| S-5 | 4.5 | "`amount` … or at most a configured cap" accepts an untrusted-chosen amount without a named, logged rule: this contradicts the invariant | Drop it, or make it a named rule with its own tests and residual risk (dropped, D-009) |
| S-6 | 4.5 | Declassification semantics unspecified (relabel values vs. approve actions) | Policy-time endorsement (adopted, D-006) |
| S-7 | 4.5, 4.7 | Ownership rule needs "the ticket's customer", but `issue_refund(order_id, amount)` has no ticket; inferring it from origins is ambiguous when an ID mixes origins | Trusted `ticket_id` argument (adopted, D-009) |
| S-8 | 4.5 | The rule as written constrains only the argument, not `pc` or the action set: a `map` over several extracted IDs, or a duplicated ID, multiplies refunds | Rule endorses `pc` only under per-ticket uniqueness; duplicates are BLOCKed (adopted, DESIGN §6.2) |
| S-9 | 5 | "Unless it is an enumerated, documented residual risk" is not mechanically checkable | NI-1…NI-4 with delimited release and vacuity reporting (adopted, D-008) |
| S-10 | 4.6 | Approval replay across runs; time-of-check/time-of-use between approval and execution | Bind `run_id`, single-use, re-check BLOCK conditions (adopted, D-013) |
| S-11 | 5 | NI is stated for a fixed environment pair, but the extractor (possibly an LLM) is part of the untrusted path | Quantify over extractor outputs in the harness (adopted, DESIGN §9.1) |
| S-12 | 4.3, 6 | Under Warrant the planner never sees untrusted content, so "Warrant + gullible" degenerates to a blind planner and only tests data-path attacks; the spec doesn't define gullible's input per defence | Report "Warrant + gullible (blind)" and add a "leaked context" stress config, where gullible sees the ticket and the plan label taints its literals and root `pc`. **Owner decision requested.** |
| S-13 | 10 | "Executed unapproved effects were invariant to untrusted content" is false by design whenever a rule fires | Amend to "…invariant to untrusted content except through the logged decisions of named declassification rules, whose release is stated per rule". **Owner decision requested** (§10 is verbatim text). |
| S-14 | 5 | Abort/exception channel not addressed: an attacker who makes evaluation fail suppresses trusted actions | Total evaluation (adopted, D-007) |
| S-15 | 4.4, 4.6 | Not stated that consequential results can't feed later steps; without that, "approve the fully resolved action set" is impossible | `Unit`-typed effects, resolve-then-decide (adopted, D-004/D-005) |
| S-16 | 4.6, 7 | Simulated approver approves exactly ground truth, so it is an idealised human | Report evaluated approval safety as an upper bound beside the steering rate (adopted, DESIGN §7) |
| S-17 | 4.8 | Minimum group size alone doesn't stop differencing (overlapping aggregates). Also, the planner-context canary check is satisfied by construction when re-planning is forbidden | Fixed, predefined groupings only; keep the planner-context scan as a regression check and say it is structural |
| S-18 | — | Persistence laundering (write tainted value, read back as trusted later) is not covered | Storage label rule (adopted, DESIGN §11) |
| S-19 | 4.2 | "Values cannot be constructed without a label outside kernel/" is unenforceable against in-process Python code | Scope it by the threat model (attacker doesn't control code), plus private constructors (adopted, DESIGN §2) |
| S-20 | repo | The file is `Claude.md`; on case-sensitive filesystems tools look for `CLAUDE.md` | Rename with `git mv`. **Owner decision requested** (not done) |

---

## Gate 0 independent review: responses (2026-10-29)

The verbatim findings and a point-by-point response are in `docs/reviews/GATE0_REVIEW.md`. The
decisions it changed:

## D-014 Keep atomic decisions; restate NI-3 to admit whole-run suppression only

The reviewer showed that, as first written, NI-3 was false for the design's own atomic
semantics. A tainted, literal-argument action in a `map` can make a fully trusted refund in the
same run not execute, with no rule involved (finding 1).

**Decision.**
- Keep atomicity (D-005): one plan is one intent.
- Restate NI-3: with equal release projections, each side's effects are either empty or one
  common sequence.
- Name whole-run suppression in THREAT_MODEL §6, and run one plan per ticket to bound it.

**Rejected:**
- *Partial execution.* It makes the original NI-3 true, but executes subsets of an intent.
- *Weakening NI-3 ad hoc once the fuzzer found it.* That is exactly what the reviewer predicted
  would happen.

**Owner decision requested:** atomic vs partial is a direction choice.

## D-015 NI-3 conditions on per-rule release projections, not on full decisions

Finding 2: with the admitted action inside `D`, NI-3 became vacuous exactly when a rule leaked
more than it claimed.

**Decision.** Each rule declares `π_R`. For the ownership rule at `θ = 0` it is
`(rule, site, outcome)`.

## D-016 Cross-run state is part of the security argument

Findings 3, 4 and 7:
- "Once per ticket" now consults the persistent refunds record.
- The storage rule counts row keys and `pc`, makes approval the warrant for an approved
  action's writes (shown to the approver), and stores origins for agent-written untrusted
  cells. `tickets.subject/body` are customer-channel-only.
- Ticket row existence is customer-controlled: enumerations carry an existence origin, `~`
  varies ticket rows, and NI-4 runs over sequences of runs.

## D-017 Enforce rather than assume: planner invocation, extractor contract, policy reads

Findings 5, 8 and 11:
- The kernel invokes the planner itself, once per task id.
- The extractor is stateless per call, bounded in tokens, and its output is validated with
  exact types.
- Policies read through a trusted-columns-only API, and set constraints are monotone.

## D-018 Approval object includes labels, pc and reasons; NI-5 covers approval

Finding 9: the hashed object now carries per-component origins, `pc` and verdict reasons;
strings are normalised at resolution; and consumption is written before the first provider call.

## D-019 Smaller fixes adopted

- Per-action re-check before execution, with reported partial runs (finding 10).
- Restated label-determinism lemma; selection labels cover every SQL clause; `ORDER BY` a
  trusted key (finding 12).
- Saturating bounded numerics, lossless decoding of untrusted text (finding 13).
- Principal-scoped `customer:C` sinks (finding 14).
- Network guard via audit hook, and broader static plus runtime import-boundary checks
  (findings 15 and 16; code fixed, regression tests failed on the old code first).
