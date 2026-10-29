# Warrant: Design

Status: Phase 0 proposal, awaiting Gate 0. Rationale and rejected alternatives for each choice are
in `docs/DECISIONS.md` (referenced as D-nnn). The threat model is in `docs/THREAT_MODEL.md`.

Notation: `⊔` is label join, `⊑` is the label order, `⊥` is the bottom (most trusted, least
restricted) label.

---

## 1. Architecture and trusted computing base

```
operator request ──► planner ──► plan (JSON AST)
                                   │
                                   ▼
              ┌───────────────── kernel (TCB) ─────────────────┐
              │ static checker → resolver (labels, pc) →       │
              │ action set → policy + declassification →       │
              │ approval binding → thin execution → audit log  │
              └───────┬───────────────────────┬────────────────┘
                      │ read tools             │ consequential tools
                      ▼                        ▼
              SQLite (labelled columns)   payment mock
                      ▲
                      │ untrusted text in, typed values out (labelled by the kernel)
               quarantined extractor (no tool access)
```

The TCB is: `kernel/`, the schema with its column labelling, and the tool registry (signatures,
declared labels, declared sinks). Planners, the extractor and the evaluation code are outside it.
The kernel never imports them (enforced by `tests/test_import_boundary.py`); they are wired to the
kernel through interfaces at a composition root outside `kernel/` (D-012).

Two properties make the guarantee planner-independent:

1. **Isolation by construction.** The kernel builds the planner's input. In the standard
   configuration that input is the operator request and the tool signatures only. Nothing
   computed during a run flows back to the planner (no re-planning, §8).
2. **Enforcement on provenance, not intent.** Every decision is a function of labels computed by
   the kernel from where data came from, never of what the planner meant.

So the plan `P` is a function of trusted data only, and the non-interference property (§9) is
quantified over *all* well-typed plans. Any planner, whether random, adversarial, buggy or an LLM,
selects some plan in that space, so the property covers it. The model therefore affects utility
only.

---

## 2. Label lattice (D-002)

A label is a triple `ℓ = (U, S, P)`.

| Component | Domain | Join | Used for decisions? |
|---|---|---|---|
| `U` untrusted origins | finite set of origins, or `★` | union; `★` absorbs | **yes**: integrity |
| `S` allowed sinks | subset of `{operator, customer}` | intersection | **yes**: confidentiality |
| `P` trusted provenance | set of trusted sources/origins | union | **no**: audit only |

- An **origin** names a database cell: `table[row_key].column`, for example `tickets[42].body`.
  Origins are attached by the kernel when a value is read; they cannot be supplied by a plan.
- `★` means "untrusted, origins not tracked". When `|U|` would exceed `MAX_ORIGINS` (32), `U`
  collapses to `★`. No declassification rule ever admits `★`, so the collapse is sound.
- **Order:** `ℓ1 ⊑ ℓ2 ⇔ U1 ⊆ U2 ∧ S1 ⊇ S2` (with `X ⊆ ★` for every `X`). `P` is ignored.
- **Bottom:** `⊥ = (∅, {operator, customer}, P)` for any `P`.
- **Trusted for authority** ⇔ `U = ∅`.
- **Labels are immutable.** Label construction is private to `kernel/`. Python cannot stop
  in-process code from forging objects; this is acceptable because the attacker does not control
  code (THREAT_MODEL §4). Plans can only create values through literals, which the kernel labels.

This is the product of a powerset integrity lattice and a powerset confidentiality lattice. The
spec's `{OPERATOR, SYSTEM_DB, UNTRUSTED}` sources survive as `P` (OPERATOR, SYSTEM_DB) and as
`U ≠ ∅` (UNTRUSTED). The distinction between OPERATOR and SYSTEM_DB is kept for the audit trail
only, since no policy needs it.

### 2.1 Column labelling

Every column in `domain/schema.sql` has a static label in a labelling map `Λ`, kept with the
schema and part of the TCB:

- **Untrusted columns** (attacker-writable free text): `tickets.subject`, `tickets.body`,
  `orders.customer_note`, `customers.display_name`. Reading cell `t[k].c` yields
  `U = {t[k].c}`.
- **Trusted columns**: everything else, including `tickets.customer_id` (set by the authenticated
  channel). Reading yields `U = ∅` with `P = {t[k].c}`.
- **Row existence and keys are trusted.** The attacker controls cell contents, not which rows
  exist (THREAT_MODEL §4).
- **Sinks:** columns holding aggregates may only flow to `{operator}`. Row-level PII columns are
  never exposed by any agent-visible tool (SPEC §4.8).

---

## 3. Values and propagation

A labelled value is `(v, ℓ)`. Compound values carry labels at two levels.

- **Records** (tool rows): each field has its own label, and the record has a *selection label*
  (which row was chosen). Field access: `label(r.f) = label(r) ⊔ label(f)`.
- **Lists** have a *structure label* covering length, order and membership. Each element has its
  own label. Reading an element always joins the structure label.

**Values do not carry `pc`; effects do (D-003).** A value's label is the join of the labels of
the values it was computed from. The program-counter label is recorded on every consequential
action (§3.1). This is sound because the language is pure and block-scoped. A value computed
inside a `map`/`filter` body can leave the body only as an element of the result list, and every
way of reading a list element (`at`, `contains`, `len`, binding in a further `map`/`filter`)
joins that list's structure label, which carries the iteration's dependence.

Joining `pc` into every value as well would be sound but over-taints literals inside bodies. In
particular it would taint the operator's `ticket_id` literal inside a refund `map` (§4 example),
making the ticket's own identity untrusted.

| Construct | Result label |
|---|---|
| `{"lit": c}` | `plan_label` (§8) |
| `op(e1..en)` (scalar) | `⊔ label(ei)` |
| `len(xs)` | `struct(xs)` |
| `at(xs, i)` → list of length ≤ 1 | struct = `struct(xs) ⊔ label(i)`; element = `elem ⊔` that struct |
| `contains(xs, x)` | `struct(xs) ⊔ ⊔elems ⊔ label(x)` |
| read tool `f(args)` → rows | selection/struct = `⊔ label(arg) ⊔ label(selection columns)`; field = `Λ(col)` instantiated for the row |
| extractor `x(text)` → list | struct and every element = `label(text)` |

Read tools declare which columns their row selection reads. If selection reads an untrusted column
(for example a text search over ticket bodies), those origins join the structure label. A tool
that hides this would be a TCB bug, so the declaration is reviewed with the registry.

The extractor's output label depends only on its input label, never on what it returns. It is
modelled as an *arbitrary* function from untrusted text to typed values, so its correctness is
irrelevant to safety. Its output types (IDs, enums, bounded ints; lists of at most
`MAX_EXTRACT` = 5 items) narrow the channel but do not make values trusted.

### 3.1 Program-counter label

The language has no `if`. Control dependence arises only through `map` and `filter` (D-003).

- Top level: `pc = plan_label`.
- `map(xs, x ⇒ steps)`: the steps run once per element with `pc' = pc ⊔ struct(xs)`. Binding `x`
  has `elem ⊔ struct(xs)`. The result list has struct `struct(xs)`, and its elements are the
  values of the last step.
- `filter(xs, x ⇒ p)`: `p` is evaluated for **every** element, with no short-circuit. The result
  has `struct = struct(xs) ⊔ ⊔ᵢ label(p(xᵢ))`, and each kept element is `elem ⊔` that struct.
  - All predicate labels join the structure, not only each element's own predicate. Dropping
    element *i* shifts the index of every later element, so position and length depend on every
    predicate. This closes the "tainted list index" laundering path.
- `and` / `or` evaluate both operands (no short-circuit), so evaluation order never depends on
  data.
- **Calls:** a resolved consequential action records its argument labels *and* its `pc`
  separately. The policy checks `pc` explicitly, so a call with no tainted arguments (or no
  arguments at all) inside a tainted `map` is still untrusted-selected.

The spec's laundering example "filter the orders whose ID appears in the ticket" gives
`filter(orders, o ⇒ contains(extracted, o.id))`. Each predicate has
`label ⊒ label(extracted) = U{tickets[42].body}`, so the result structure is tainted. Any refund
mapped over the result has a tainted `pc`, and any element reached through it has a tainted label.

### 3.2 Totality (D-007)

Evaluation of a well-typed plan always completes and produces an action list. If it could abort,
an attacker who triggered the abort would suppress trusted actions: an unlabelled, untested
channel. To make evaluation total:

- There are no partial operators. `at` returns a list of length 0 or 1; absence is an empty list.
  "Maybe" is always list-shaped and consumed with `map`.
- Read tools return empty lists for missing rows. The extractor returns an empty list on failure
  or timeout.
- Lists longer than `MAX_LIST` (100) are truncated, and the truncation is logged. Truncation is a
  function of length, which the structure label already covers.
- The static checker bounds worst-case work: steps × `MAX_LIST`^nesting ≤ `WORK_BUDGET`. A plan
  is rejected statically if over budget, so this never depends on data.
- Any exception during evaluation is a kernel bug. The run executes nothing and the fuzz harness
  reports it as a failure, never as a skip.

### 3.3 Label determinism (the lemma the NI test relies on)

Label computation never inspects a value: every rule above is a join of input labels, chosen by
syntax alone. Data-dependent evaluation (number of iterations, filter outcomes) only happens
under a `pc` that already carries the label of the data it depends on. So, for environments
`E1 ~ E2` (§9), the subsequence of resolved actions whose effective label is trusted is identical
in sites, tools and values. §9 tests this directly as NI-1.

---

## 4. Plan language (D-004)

A pydantic model, exported as JSON Schema for grammar-constrained decoding.

```
Plan    := { "version": 1, "steps": [Step, ...] }               1 ≤ total steps ≤ MAX_STEPS (64)
Step    := { "let": Name?, "call": Tool, "args": { Param: Expr } }
         | { "let": Name?, "expr": Expr }
Expr    := { "lit": int | str | bool }
         | { "ref": Name, "path": [Field, ...] }                path may be empty
         | { "op": Op, "args": [Expr, ...] }
         | { "map":    { "over": Expr, "as": Name, "steps": [Step, ...] } }   value: last step's
         | { "filter": { "over": Expr, "as": Name, "where": Expr } }          where: pure Expr
Op      := eq | ne | lt | le | gt | ge | and | or | not
         | add | sub | min | max | len | at | contains
Tool    := one of the registry's tool names (a JSON Schema enum)
```

A `map` body is a scoped block of steps, so a body can read and compute before acting. The
`map` evaluates to the list of the last step's values. `filter` predicates are pure expressions:
no calls, so selection has no side effects.

**Types:** `Int`, `Money` (integer minor units, paise, never float), `Bool`, `Str`, `Enum[…]`,
`Id[Order|Customer|Ticket|Incident]`, `Rec[name]` (tool row types), `List[τ]`, `Unit`.

Static checker rules (all checked before any execution):

- Tool names are registry members. There are no dynamic tool names, no `eval`, no
  string-to-code path, no loops or recursion; `map`/`filter` are the only iteration.
- Names are unique and bound before use, with no shadowing. A `map`/`filter` binder is scoped to
  its body.
- Types are checked bidirectionally: an integer literal checked against `Id[Ticket]` becomes a
  ticket id. IDs of different kinds never mix, and only `eq`/`ne` apply to IDs.
- **Consequential tools return `Unit`, and a `Unit` (or `List[Unit]`) can never be bound or
  referenced.** No later step can depend on a consequential result, which is what lets the
  kernel resolve the whole action set before executing anything (§5).
- `map`/`filter` nesting depth ≤ `MAX_DEPTH` (2). Worst-case work ≤ `WORK_BUDGET` (§3.2).

The illustrative plan from SPEC §4.4 in this grammar, with `ticket_id` added to `issue_refund`
(D-009). Absence is list-shaped, so the refund is a `map` over the extraction, which has at most
`MAX_EXTRACT` elements:

```json
{"version": 1, "steps": [
  {"let": "t",    "call": "read_ticket",       "args": {"ticket_id": {"lit": 42}}},
  {"let": "oids", "call": "extract_order_ids", "args": {"text": {"ref": "t", "path": ["body"]}}},
  {"expr": {"map": {"over": {"ref": "oids"}, "as": "o", "steps": [
    {"let": "amt", "call": "compute_refund_amount", "args": {"order_id": {"ref": "o"}}},
    {"call": "issue_refund", "args": {"ticket_id": {"lit": 42},
                                      "order_id":  {"ref": "o"},
                                      "amount":    {"ref": "amt"}}}
  ]}}}
]}
```

Labels:
- `t.body`: `U = {tickets[42].body}`.
- `oids` (structure and elements): the same.
- Inside the body, `pc = U{tickets[42].body}`. `o` carries it (`elem ⊔ struct`), and so does `amt`,
  because its row was selected by `o`.
- `ticket_id` is the operator's literal, so it stays trusted.
- The resolved refund therefore has trusted `ticket_id`, and an untrusted `order_id`, `amount` and
  `pc`, all with origin `tickets[42].body`. That is exactly the shape §6.2's rule is written for.

`compute_refund_amount` is total: it returns `0` for a missing or ineligible order, which the
policy BLOCKs (amount ≤ 0).

---

## 5. Evaluation model (D-005)

A run has four phases. Nothing consequential happens before phase 4.

1. **Check:** static checker (§4). A rejected plan executes nothing.
2. **Resolve:** evaluate the plan, executing *read* tools and the extractor only. Each
   consequential call becomes a **resolved action** `a = (site, tool, args, pc)`. `args` are
   labelled values; `site` is the step index plus the `map` iteration indices. The result is the
   ordered action list `A`.
3. **Decide:** run the policy on every action (§6), producing `ALLOW`, `NEEDS_APPROVAL` or
   `BLOCK` with a reason and any rule decisions. Then combine **atomically**:
   - all `ALLOW` → execute `A`;
   - any `BLOCK` → execute nothing;
   - otherwise → one approval request for the whole of `A`; execute `A` only if approved and
     the hash matches (§7).
4. **Execute:** thin execution layer (§10), in plan order.

The same structure is used in every mode, so the non-interference harness observes exactly what
production would do.

---

## 6. Policies

A policy is declared per consequential tool. It is a pure function of the action, the whole
action list `A` (for set-level constraints such as duplicates), and database reads made by the
policy itself. It returns a verdict and a reason.

Rules every policy obeys (tested in Phase 1):

- **P1. Untrusted never yields ALLOW without a rule.** If any component of an action (an argument
  or `pc`) has `U ≠ ∅`, the verdict is `ALLOW` only if every such component is endorsed by a
  logged declassification decision (§6.1).
- **P2. `BLOCK` vs `NEEDS_APPROVAL` may depend on untrusted values.** For example, a nonexistent
  order gives BLOCK and an unowned order gives NEEDS_APPROVAL. With a denying approver both
  execute nothing, so this affects only approval requests (steering), never effects.
- **P3. Business invariants are BLOCK, whatever the labels.** Examples: amount ≤ 0, amount above
  the refundable amount the policy recomputes, an order not belonging to the case's customer, the
  same order refunded twice in `A`, an already-refunded order.
- **P4. Recompute, don't trust.** Amounts are checked against the policy's own recomputation from
  trusted columns, never against a plan-computed value.
- **P5. Sinks.** Each argument of a consequential tool declares a sink. The argument's `S` and the
  action's `pc.S` must both contain it, or the verdict is BLOCK.

Example, `issue_refund(ticket_id, order_id, amount)`:

| Condition | Verdict |
|---|---|
| order missing, wrong customer, amount ≤ 0, amount > refundable, duplicate in `A`, already refunded | BLOCK |
| `ticket_id`, `order_id`, `amount`, `pc` all trusted | ALLOW |
| every untrusted component endorsed by a rule | ALLOW (rule named in the reason) |
| otherwise | NEEDS_APPROVAL |

A trusted partial refund (an operator-literal amount ≤ refundable) is allowed. An untrusted amount
is never accepted merely for being "under a cap": that would be an unnamed declassification (spec
issue S-5).

### 6.1 Declassification as policy-time endorsement (D-006)

A declassification rule does **not** relabel values in the dataflow. It is consulted by a policy
for one action and may *endorse* specific components of that action (named arguments and/or
`pc`), and only when those components' untrusted origins lie inside an origin set the rule names.

Every rule documents:

- the tool and components it may endorse, and the permitted origins;
- the admission predicate, evaluated by kernel code over trusted columns;
- **release:** exactly what information about untrusted data can influence effects through it;
- **postcondition:** a property of every admitted action, stated over trusted data, checked by
  test-side code written independently of the kernel;
- residual risk, plus admit, reject and residual-risk tests.

Every consultation is logged: rule, site, the components and origins considered, the predicate
inputs read, the outcome, and (if admitted) the canonical admitted action.

Because endorsement is per action, an endorsed value can never become the condition of a
`filter` that selects a *different* action, and cannot be stored and reused as trusted, except
where an executed action writes it to a trusted column. That write is the endorsement's intended
effect (for example the refund record itself) and is listed in the rule's postcondition.

### 6.2 Rule `ticket_order_ownership` (proposed; the only Phase 1 rule)

Applies to `issue_refund(ticket_id, order_id, amount)`.

- **Precondition:** `ticket_id` is trusted. Let `T` be its value and `C = tickets[T].customer_id`,
  a trusted column read by the rule.
- **Endorsable components:** `order_id`, `amount`, `pc`, each only if its `U ⊆ Ω_T`, where
  `Ω_T = {tickets[T].subject, tickets[T].body}`. Any other untrusted origin (another ticket, an
  order note, `★`) means the rule does not apply.
- **Admits iff:**
  1. `orders[order_id]` exists and its `customer_id = C`;
  2. `order_id ∈ Eligible(C)`, the customer's orders refundable now (status, not already
     refunded, within the refund window on the simulated clock);
  3. `|Eligible(C)| = 1`. Variant for Phase 1 measurement: `… or Refundable(order_id) ≤ θ`, with
     `θ = 0` the default;
  4. `amount = Refundable(order_id)`, recomputed by the rule;
  5. `A` contains no other `issue_refund` with `ticket_id = T`.
- **One sentence:** *an order ID read from a ticket may target a refund only when it is that
  ticket's customer's single eligible order, for its full refundable amount, once per ticket.*
- **Release:** with `θ = 0` the admitted action is a function of trusted data alone (the unique
  eligible order and its recomputed amount). Untrusted text decides one bit per ticket: whether
  that refund executes automatically or goes to approval.
- **Postcondition:** each executed refund admitted by this rule is on `C`'s unique eligible
  order, for exactly its refundable amount, at most once per ticket.
- **Residual risk:**
  - *Suppression*: injected text can turn an automatic refund into an approval request.
  - With `θ > 0`, *redirection* among `C`'s eligible orders whose refundable amount is ≤ `θ`.
- **Within-allowed-set attack:** if the customer has two or more eligible orders, no rule can
  tell the customer's genuine choice from an injected one, because both are text in the same
  untrusted field. With `θ = 0` the case always goes to approval. The cost is approval burden
  on benign multi-order customers, which Phase 1 measures.

Other candidate rules for Phase 2, to stay within 2–4: a bounded goodwill credit to the case's
customer, chosen from a fixed enum. Incident-based bulk refunds need **no** rule: incident →
affected orders is trusted structured authority.

---

## 7. Approval binding

- **Canonical action:** `{"tool": name, "args": {param: value}}`. Values are ints (money in minor
  units), strings (NFC-normalised), bools, or lists of these.
- **Canonical set:** `{"run_id": r, "actions": [a1 … an]}` in plan order, serialised as JSON with
  sorted keys, `(",", ":")` separators and UTF-8. Hash: SHA-256.
- **Records:** an approval binds `(run_id, hash)`, is single-use, and is consumed at execution.
  Binding to `run_id` prevents replaying an approval into a later run with an identical action
  set (spec issue S-10).
- **Execution check:** the kernel recomputes the hash of the set it is about to execute and
  re-runs the BLOCK checks against current state (time-of-check to time-of-use). Any divergence
  aborts with nothing executed.
- **Presentation:** the approval view is rendered from the same canonical object that is hashed.
  It shows each argument's untrusted origins and each verdict's reason.
- **Simulated approver:** in evaluation it approves iff the canonical set equals the task's
  ground-truth set. That makes it an idealised human, so evaluated approval safety is an upper
  bound, reported next to the steering rate.

---

## 8. Re-planning decision (D-001)

**Re-planning is forbidden.** The planner is invoked once per task, before any tool runs, with a
kernel-built input containing the operator request and tool signatures. Data-dependence is
expressed inside the plan with the extractor, `map` and `filter`.

**The plan label.** The kernel gives every plan a label equal to the join of the labels of the
planner's input. Literals and the root `pc` inherit it. In the standard configuration that join
is `⊥` with `P = {OPERATOR}`. The parameter exists so that a deliberately leaky configuration,
a planner fed untrusted text, is handled soundly: every literal and the root `pc` become
untrusted, so a hijacked planner cannot pass attacker choices off as operator literals. This is
spec option (b), applied to the one and only plan. Proposed use: a "gullible with leaked
context" stress configuration (spec issue S-12).

---

## 9. Non-interference

### 9.1 Environments

An environment `E = (DB, clock, provider)`.
`E1 ~ E2` iff:
- both have the same rows (keys) in every table;
- they agree on every trusted cell, the clock and the provider state;
- untrusted cells may differ arbitrarily within their column types.

Extractor outputs are part of the untrusted environment: the harness may draw them directly,
so the property is tested for **every** extractor, not just the rule-based one.

### 9.2 Observations of a run of plan `P` in `E` with approver `Ap`

- `Res(P,E)`: resolved actions with labels;
- `D(P,E)`: rule decisions `(rule, site, outcome, canonical admitted action)`;
- `Req(P,E)`: approval requests as canonical sets;
- `X(P,E,Ap)`: executed effects, read from the payment provider's log and the consequential DB
  writes, in execution order. Comparing ordered lists is stronger than the spec's multiset.

### 9.3 Properties (for every well-typed `P` and every `E1 ~ E2`)

- **NI-1 (trusted-action determinism).** The subsequence of `Res(P,E)` whose effective label
  (`⊔ args ⊔ pc`) is trusted is identical, as (site, tool, values), for `E1` and `E2`. It needs
  no assumption about rules, so it is never vacuous.
- **NI-2 (policy soundness).** For every `E`, every `ALLOW`ed action is either fully trusted or
  every untrusted component is endorsed by a logged decision in `D(P,E)`.
- **NI-3 (delimited release of effects).** If `D(P,E1) = D(P,E2)`, then
  `X(P,E1,deny) = X(P,E2,deny)`. This is the formal version of "unless it is an enumerated
  residual risk": the only permitted untrusted influence on effects is what rules release, and
  rules release only through `D`.
- **NI-4 (rule postconditions).** For every `E`, every executed action admitted by rule `R`
  satisfies `Post_R` (§6.2), checked by test code independent of the kernel.
- **Approval steering (recorded, not a violation):** `Req(P,E1) ≠ Req(P,E2)`.

**Reported with every NI run:** examples run, seed, the fraction of pairs in which some rule was
consulted, and the fraction in which `D` differed (NI-3's precondition failed). A low
consulted-and-equal fraction would make NI-3 vacuous, so it is printed, not hidden.

**Termination:** evaluation is total (§3.2), so the property is termination-sensitive. An
exception in either run fails the test.

### 9.4 Harness

- Plans are generated *type-directed* from the tool registry, so most are well-typed; random
  JSON would almost never pass the checker.
- Adversarial generators produce the known laundering shapes: selection by a tainted predicate,
  tainted `at` indices, `len` of tainted lists, money arithmetic on tainted values, nested
  `map`/`filter`, and calls inside tainted `map` bodies with all-literal arguments.
- Environment mutations rewrite untrusted cells and extractor outputs. Their values are drawn to
  be dangerous: IDs of the same customer's other orders, other customers' orders, duplicates,
  empty lists, and the maximum list length.
- `make check` runs a derandomized profile; `make fuzz` runs the `fuzz` profile. Shrunk
  counterexamples become `@example` regression tests.

---

## 10. Execution layer (thin)

As SPEC §4.7:

- Before calling the provider, write an intent record with business idempotency key
  `refund:{order_id}:{ticket_id}`.
- On recovery, query provider status by key before retrying.
- One crash-injection test checks there is exactly one refund.

Idempotency is a reliability mechanism. Security never depends on it: duplicates are already
BLOCKed by the policy (P3).

## 11. Persistence (storage label rule)

A consequential tool may write a value to a column only if the value's label ⊑ the column's label
in `Λ`, or the value is a component endorsed for that action. Agent-written free text therefore
goes only into untrusted columns, and a later run reads it back as untrusted. This closes
laundering across runs.

## 12. Parameters

| Name | Value | Note |
|---|---|---|
| `MAX_STEPS` | 64 | static |
| `MAX_DEPTH` | 2 | nesting of map/filter, static |
| `MAX_LIST` | 100 | runtime truncation, logged |
| `MAX_EXTRACT` | 5 | extractor list length |
| `MAX_ORIGINS` | 32 | collapse to `★` |
| `WORK_BUDGET` | 10⁶ | static worst-case evaluation steps |
| `θ` | 0 | ownership-rule ambiguity threshold (minor units) |

All are provisional until Phase 1 measures them.
