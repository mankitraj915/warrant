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

1. **Isolation by construction.** The *kernel* invokes the planner through a `Planner`
   protocol, with an input it builds itself. In the standard configuration that input is the
   operator request and the tool signatures only. The kernel logs a hash of the input, computes
   the plan label from it (§8), and accepts exactly one plan per task id. The task id is
   recorded in the audit table, so the limit holds across `Environment` objects and restarts
   over the same database (Gate 2 review #7). Nothing computed during a run flows back to the
   planner (no re-planning, §8), and no caller-side retry loop can re-sample plans after seeing
   outcomes (review finding 8). `run_plan`, which takes a plan and a plan label directly, is for
   the trusted composition root and the tests; a caller that passes a trusted label for a plan
   built from untrusted text is outside the TCB's guarantee.
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
| `S` allowed sinks | subset of `{operator} ∪ {customer:C}` | intersection | **yes**: confidentiality |
| `P` trusted provenance | set of trusted sources/origins | union | **no**: audit only |

- An **origin** names a database cell: `table[row_key].column`, for example `tickets[42].body`.
  Origins are attached by the kernel when a value is read; they cannot be supplied by a plan.
- `★` means "untrusted, origins not tracked". When `|U|` would exceed `MAX_ORIGINS` (32), `U`
  collapses to `★`. No declassification rule ever admits `★`, so the collapse is sound.
- **Order:** `ℓ1 ⊑ ℓ2 ⇔ U1 ⊆ U2 ∧ S1 ⊇ S2` (with `X ⊆ ★` for every `X`). `P` is ignored.
- **Bottom:** `⊥ = (∅, all sinks, P)` for any `P`.
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
- **Row existence.** Keys are trusted. Rows of most tables are created by trusted processes;
  an order exists only through checkout and payment. **Tickets are different:** any customer,
  including the attacker, can open them (review finding 7), and ticket ids are predictable.
  - A keyed lookup `read_ticket(T)` of an *untrusted* id joins the existence origin
    `tickets[T].@row` into its structure label, whether or not the row exists (Gate 1 review
    #1; this replaces D-021's deferral). Everything computed under a `map` over such a read
    has an untrusted `pc`, and only a rule that endorses `tickets[T].@row` can let it act
    automatically.
  - A keyed lookup of a *trusted* id (an operator-named ticket) that finds no row **halts the
    run during resolution**: no action set exists, nothing executes, and the outcome is
    `halted` (D-054, adopted in Phase 3 from the D-036 alternative). Within a run that
    continues, the row therefore always exists, so its existence carries no information and
    the read joins no existence origin. Existence can only suppress the whole run, which NI-3
    permits. Without the halt, dropping the origin is unsound: existence becomes a count, an
    index or a choice between maps (D-036). That is a mutant the harness must catch.
  - Enumerating tickets (any read tool that returns a *set* of tickets) joins an existence
    origin `tickets[*@C]` for each customer `C` whose tickets could appear into the structure
    label. A `map` over "all open tickets" therefore has an untrusted `pc`, and the number of
  actions it produces cannot be set by an attacker without showing up in labels. Set-level
  limits in policies are scoped per customer as well as per ticket.
- **Sinks** carry a principal: `operator` and `customer:C` (review finding 14). Columns holding
  aggregates may only flow to `{operator}`. Row-level PII columns are never exposed by any
  agent-visible tool (SPEC §4.8).

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

**Read tools.**
- A read tool declares every column that affects row *membership, order, multiplicity or count*.
  That covers `WHERE`, `JOIN`, `ORDER BY`, `DISTINCT` and `LIMIT`, not just the filter
  (review finding 12).
- The labels of those columns join the structure label.
- Results are always `ORDER BY` a trusted key, so order never depends on SQLite's query plan.
- A tool that under-declares is a TCB bug, so the declarations are reviewed with the registry.

**Compound values used whole** (review finding 6).
- The label of a list or record used as a single value (an operator argument, or a
  consequential argument of list type) is its structure or selection label joined with the
  labels of all its leaves, recursively.
- `elem ⊔ struct` joins into a nested record's selection label and into a nested list's
  structure label alike.
- P1, P5 and the "effective label" (§9) range over every leaf.
- Operators other than `len`/`at`/`contains` accept scalars only; `min`/`max` are binary.

**The extractor** is modelled as an *arbitrary* function from untrusted text to typed values, so
its correctness is irrelevant to safety. Its output label joins, whatever it returns, the
input text's label, the `pc` of the call, and the text label and `pc` of every extraction
already made in the same run (Gate 1 review #4, Gate 2 review #1). The `pc` matters because an
extractor can carry state other than the texts it saw, such as a call counter: how many
extractions ran under an untrusted `pc` is untrusted. Entering a `map` whose body syntactically
contains an extraction joins the body's `pc` into the cumulative label before the first
iteration, even when there are none (Gate 2 review #2), so whether a later extraction is
trusted is fixed by syntax (§3.3). Together these make state carried *within* a run harmless:
its texts, their order and the number of calls are all covered. State carried *across* runs (a
cache, reused KV state) is not covered by labels, so the contract still requires statelessness,
and it is enforced only by review and, in Phase 4, by a test of the LLM adapter:
- **Stateless per call.** No shared context, cache, or KV state across calls, and no run-wide
  budgets.
- **Bounded per call.** A deterministic per-call limit, in tokens rather than wall-clock time.
- **Validated by the kernel:**
  - outputs must be exact builtin types (`type(x) is int`, so not `bool` and not a subclass) and
    within declared bounds;
  - lists are capped at `MAX_EXTRACT` (5);
  - exceptions and over-budget calls yield `[]`.

Phase 4 adds a test that the LLM adapter's output for an input does not depend on the calls
made before it. Output types narrow the channel but do not make values trusted.

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
- Worst-case work is bounded statically by `MAX_STEPS` × `MAX_LIST`^`MAX_DEPTH`
  (64 × 100² = 6.4×10⁵ evaluations), so it never depends on data (D-022's plan note).
- Numeric domains are bounded (review finding 13):
  - `Int` and `Money` are bounded to ±10¹⁵;
  - `add`/`sub` saturate at the bounds, so arithmetic never overflows and never reaches SQLite
    as an out-of-range integer;
  - a negative `Money` is a value like any other, and policies BLOCK amounts ≤ 0.
- Untrusted TEXT cells are read as bytes and decoded with replacement, so invalid UTF-8 written
  by an attacker cannot raise.
- Extractor exceptions and over-budget calls yield `[]` (§3).
- Any remaining exception during evaluation is a kernel bug. The run executes nothing and the
  fuzz harness reports it as a failure, never as a skip. The environment generators
  deliberately include extreme integers and invalid UTF-8.

### 3.3 Label determinism (the lemma the NI test relies on)

Stated precisely (review finding 12): **whether a value's `U` is empty** is determined by the
plan's syntax and the labels of trusted inputs, never by untrusted values. Every rule above is a
join chosen by syntax. Data-dependent evaluation (number of iterations, filter outcomes) only
happens under a `pc`, or inside a structure label, that already carries the data it depends on.

The extractor's cumulative label was the one place this failed (Gate 2 review #2): it joined
only the extractions that actually ran, so a `map` over an untrusted selection that ran zero
times left a later extraction of a literal trusted, and one that ran left it untrusted. The
pre-join in §3 restores the lemma: the cumulative label depends on which `map` bodies contain
an extraction, which is syntax.

The *contents* of `U` (which origins, and whether it collapsed to `★`) may depend on values,
because origins name row keys. That affects only which rules can apply, and rules report
through `D` (§9).

Consequence: for environments `E1 ~ E2` (§9), the subsequence of resolved actions whose
effective label is trusted is identical in sites, tools and values. §9 tests this directly as
NI-1.

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
- `map`/`filter` nesting depth ≤ `MAX_DEPTH` (2), which bounds worst-case work (§3.2).

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
   labelled values; `site` is the path to the call: step indices and `map` iteration indices,
   plus `-(i+1)` for the i-th argument of a call or operator and `-1` for a `map`/`filter`
   source, so every action in a run has a distinct site (Gate 1 review #5). Sites depend only
   on plan structure and iteration counts. The result is the ordered action list `A`.
3. **Decide:** run the policy on every action (§6), producing `ALLOW`, `NEEDS_APPROVAL` or
   `BLOCK` with a reason and any rule decisions. Then combine **atomically**:
   - all `ALLOW` → execute `A`;
   - any `BLOCK` → execute nothing;
   - otherwise → one approval request for the whole of `A`; execute `A` only if approved and
     the hash matches (§7).
4. **Execute:** thin execution layer (§10), in plan order (D-022).
   - The decision (actions, verdicts, rule decisions, approval) is committed to the audit log
     as a `decided` row before the first effect (Gate 2 review #5).
   - Before the first effect, the kernel re-runs every action's full policy, including rule
     admission, against current state. Any divergence, stricter or more permissive, aborts the
     run with nothing executed: the state changed after the decision or the approval was
     made (Gate 2 review #4).
   - Between effects, each action is re-checked again, and the run stops only if its verdict
     became *stricter*. A change there can come from another writer or from the set's own
     earlier effects. A set's own effects can also *relax* a later verdict: a trusted full
     refund of one order can make another order the customer's unique eligible one, turning
     NEEDS_APPROVAL into ALLOW. That is not a reason to stop an approved set, so a relaxation
     is ignored (Gate 2 review #4). On a stop, the executed prefix is reported as *partial*.
     Payments cannot be rolled back, so a partial run is surfaced, never hidden.

The same structure is used in every mode, so the non-interference harness observes exactly what
production would do.

**Atomicity is a deliberate suppression channel** (review finding 1). Under a denying approver
a run executes either all of `A` or nothing. Untrusted data that turns one action into
NEEDS_APPROVAL or BLOCK therefore suppresses every other action in the run, including fully
trusted ones. It can never *change* what executes, only whether the whole set does.

Atomicity is kept because the actions of one plan express one intent (refund *and* close the
ticket): executing a subset can be wrong in its own right. The channel is stated in
THREAT_MODEL §6 and NI-3 is formulated to match it (§9.3). Its cost is measured. To keep the
blast radius to one case, evaluation runs one plan per ticket. A batch over many tickets is many
runs, except incident-driven bulk actions, whose targets are trusted.

---

## 6. Policies

A policy is declared per consequential tool. It is a pure function of three things:
- the action;
- the whole action list `A`, for set-level constraints such as duplicates;
- database reads made through a **policy read API that can only read trusted columns**
  (review finding 11), and that includes the persistent record of past effects.

It returns a verdict and a reason.

Rules every policy obeys (tested in Phase 1):

- **P0. Set-level constraints are monotone.** Adding actions to `A` can only tighten a verdict
  (ALLOW → NEEDS_APPROVAL → BLOCK), never loosen one. So a tainted action can never help a
  trusted one become ALLOW.
- **P1. Untrusted never yields ALLOW without a rule.** If any component of an action (an argument
  or `pc`) has `U ≠ ∅`, the verdict is `ALLOW` only if every such component is endorsed by a
  logged declassification decision (§6.1).
- **P2. `BLOCK` vs `NEEDS_APPROVAL` may depend on untrusted values.** For example, an untrusted
  `order_id` naming a nonexistent order gives BLOCK, and one naming an eligible order of the
  case's customer that no rule admits gives NEEDS_APPROVAL. Under a denying approver neither
  executes, so the difference shows up only in approval requests (steering). Through atomicity
  (§5), it can also decide whether the rest of the run executes; NI-3 is stated to allow for
  that.
- **P3. Business invariants are BLOCK, whatever the labels.** Examples: amount ≤ 0, amount above
  the refundable amount the policy recomputes, an order not belonging to the case's customer, the
  same order refunded twice in `A`, an already-refunded order.
- **P4. Recompute, don't trust.** Amounts are checked against the policy's own recomputation from
  trusted columns, never against a plan-computed value.
- **P5. Sinks.** Each argument of a consequential tool declares a sink. The argument's `S` and the
  action's `pc.S` must both contain it, or the verdict is BLOCK.
- **P6. Per-customer credit bound.** A credit that would be the customer's second (one is
  already recorded, or `A` holds another credit to them) is NEEDS_APPROVAL whatever its labels.
  Customers open tickets freely, so a per-ticket bound alone is no per-customer bound (Gate 2
  #6). It lives in the policy so it holds for trusted credits too (Gate 3 #2, D-062).

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
- **release:** exactly what information about untrusted data can influence effects through it,
  together with a **release projection** `π_R`: the part of each decision that is allowed to
  depend on untrusted data. NI-3 conditions on `π_R` and nothing more, so a rule that releases
  more than its projection fails NI-3 instead of hiding behind it (review finding 2);
- **postcondition:** a property of every admitted action, stated over trusted data, checked by
  test-side code written independently of the kernel;
- residual risk, plus admit, reject and residual-risk tests.

Every consultation is logged in the run's audit row: rule, site, outcome and the reason (which
names the first failing predicate). The same row holds each action's canonical arguments and the
untrusted origins of each component, so the components and origins a rule considered can be
read from it. The predicate inputs (the trusted rows read) are not logged; the trace shows the
decision, not a replay of it. Each run writes a `decided` row before its first effect and a
`final` row with the outcome; recovery of pending refunds writes its own `recover` rows
(Gate 2 review #5). A run that an exception escapes still writes its `final` row:
- the outcome is `failed`, and the reason names the exception;
- the unfinished step is rolled back, and a pending approval request is marked `rejected`;
- the exception is re-raised, and the run id is spent;
- a leaked ticket that does not exist is audited as `halted`, like an in-plan halt.
(Gate 3 review #7, D-067.) Only a run refused by the run lock writes nothing, because it
touched nothing (D-061).

Because endorsement is per action, an endorsed value can never become the condition of a
`filter` that selects a *different* action, and cannot be stored and reused as trusted, except
where an executed action writes it to a trusted column. That write is the endorsement's intended
effect (for example the refund record itself) and is listed in the rule's postcondition.

### 6.2 Rule `ticket_order_ownership` (proposed; the only Phase 1 rule)

Applies to `issue_refund(ticket_id, order_id, amount)`.

- **Precondition:** `ticket_id` is trusted. Let `T` be its value and `C = tickets[T].customer_id`,
  a trusted column read by the rule.
- **Endorsable components:** `order_id`, `amount`, `pc`, each only if its `U ⊆ Ω_T`, where
  `Ω_T = {tickets[T].subject, tickets[T].body, tickets[T].@row}`. Any other untrusted origin (another ticket, an
  order note, `★`) means the rule does not apply.
- **Admits iff:**
  1. `orders[order_id]` exists and its `customer_id = C`;
  2. `order_id ∈ Eligible(C)`, the customer's orders refundable now (status, not already
     refunded, within the refund window on the simulated clock);
  3. `|Eligible(C)| = 1`. Variant for Phase 1 measurement: `… or Refundable(order_id) ≤ θ`, with
     `θ = 0` the default;
  4. `amount = Refundable(order_id)`, recomputed by the rule, and the order has **never been
     refunded** (no refund record of any kind, pending ones included; Gate 1 review #3).
     Without this, every new ticket the customer opens could release the remainder of a
     deliberate partial refund;
  5. `A` contains no other `issue_refund` with `ticket_id = T`, **and** the persistent refunds
     record holds no refund for ticket `T` from any earlier run (review finding 3). The
     attacker can edit the ticket between runs, so a per-run check would allow one refund per
     re-run.
- **One sentence:** *an order ID read from a ticket may target a refund only when it is that
  ticket's customer's single eligible, never-refunded order, for its full amount, once per
  ticket.*
- **Release:** with `θ = 0` the admitted action is a function of trusted data alone (the unique
  eligible order and its recomputed amount). Untrusted text decides one bit per ticket: whether
  the rule admits. Because decisions are atomic (§5), that bit decides whether the *whole run*
  executes automatically or goes to approval, not just the refund.
  - **Release projection** `π = (rule, site, outcome)`. With `θ > 0` it becomes
    `(rule, site, outcome, order_id)`. NI-3 compares exactly this projection (§9.3).
- **Postcondition:** each executed refund admitted by this rule is on `C`'s unique eligible
  order, for exactly its refundable amount, is the first refund ever recorded for that order,
  and is the only refund ever executed for ticket `T`, across all runs.
- **Residual risk:** the one bit cuts both ways.
  - *Suppression*: injected text can turn an automatic refund into an approval request.
  - *Triggering* (measured in Phase 1, DECISIONS F-1): injected text can turn "no refund" into
    an automatic refund of `C`'s single eligible order, for its refundable amount, once per
    ticket. The money still goes only to the ticket's own customer and the action is fully
    determined by trusted data; what the text controls is whether it happens.
  - With `θ > 0`, *redirection* among `C`'s eligible orders whose refundable amount is ≤ `θ`.
- **Within-allowed-set attack:** if the customer has two or more eligible orders, no rule can
  tell the customer's genuine choice from an injected one, because both are text in the same
  untrusted field. With `θ = 0` the case always goes to approval. The cost is approval burden
  on benign multi-order customers, which Phase 1 measures.

- **Auto-refund cap** (Phase 2, D-038): `AUTO_REFUND_CAP` in paise, default `None`. Above it the
  rule does not admit, so the refund goes to approval. The value is chosen from a sweep curve,
  not before it.

Incident-based bulk refunds need **no** rule: incident → affected orders is trusted structured
authority (`incident_orders`).

### 6.3 Rule `ticket_goodwill_credit` (Phase 2, D-037)

- **Applies to** `issue_credit(ticket_id, customer_id, amount, reason)`.
- **Admits** when `ticket_id`, `amount` and `reason` are trusted; every untrusted origin of any
  component (including `pc`) is in `Ω_T = {tickets[T].subject, tickets[T].body, tickets[T].@row}`;
  the customer is `T`'s customer; the amount is `GOODWILL_AMOUNT` (10,000 paise); no other
  credit for `T`, or for that customer, is in `A`; `T` has never had a credit; and the customer
  has never had a credit.
- **One sentence:** *ticket text may trigger the standard goodwill credit to that ticket's own
  customer, once per ticket and once per customer.*
- **Why per customer** (Gate 2 review #6): customers open tickets freely (§2.1), so a bound per
  ticket alone is no bound per customer: four tickets gave four automatic credits. Later credits
  for the same customer need approval.
- **Release:** one bit per ticket, whether the rule admits; projection `(rule, site, outcome)`.
- **Postcondition** (NI-4): credit to `T`'s customer, for the standard amount, with an allowed
  reason, the only credit ever for `T` and for that customer.
- **Residual risk:** triggering or suppression of the standard credit, as for F-1. Never
  redirection or a different amount.

### 6.4 Phase 2 tools and their policies

| Tool | Kind | BLOCK (P3) | Notes |
|---|---|---|---|
| `incident_orders(incident_id)` | read | | staff-written, trusted |
| `order_stats()` | read | | groups with fewer than `MIN_GROUP` orders suppressed; sinks `{operator}` |
| `close_ticket(ticket_id, resolution)` | consequential | missing or closed ticket, resolution not in the enum, same ticket twice in `A` | no rule: untrusted pc or args go to approval |
| `issue_credit(ticket_id, customer_id, amount, reason)` | consequential | not the ticket's customer, amount ≤ 0 or > `CREDIT_MAX`, reason not in the enum, two credits for one ticket in `A`, ticket already credited | rule `ticket_goodwill_credit`; P6: a customer's second credit (already credited, or two credits to them in `A`) needs approval whatever the labels (Gate 3 #2, D-062) |

P5 is enforced from Phase 2: refunds and credits have sink `customer:C`, so an aggregate (sinks
`{operator}`) in any argument or in `pc` gives BLOCK. Strings in consequential arguments are
NFC-normalised at resolution. Local effects (credits, closures) are one transaction each; if
the write's precondition no longer holds (another writer got there after the re-check), the
run stops as `aborted` or `partial` (D-040).

---

## 7. Approval binding

- **Canonical action** (review finding 9):
  `{"tool", "args": {param: value}, "labels": {param: U, "pc": U}, "verdict"}`. Verdict
  *reasons* are shown to the approver but not hashed: they explain a verdict and do not
  authorize anything (D-023).
  - Values are ints (money in minor units), strings, bools, or lists of these.
  - `U` is the sorted origin list (or `"★"`).
  - Strings are to be NFC-normalised **at resolution**, so the executed bytes are the hashed
    bytes. Not yet implemented: no Phase 1 consequential tool takes a string (D-025).
  - The kernel executes exactly the canonical values.
- **Canonical set:** `{"run_id": r, "actions": [a1 … an]}` in plan order, serialised as JSON with
  sorted keys, `(",", ":")` separators and UTF-8. Hash: SHA-256.
- **Records:**
  - An approval binds `(run_id, hash)` and is single-use.
  - `run_id` is a fresh random UUID per run. In evaluation it is derived from the seed, for
    reproducibility.
  - The approval is marked consumed in the same write as the run's intent records, before the
    first provider call, so a crash cannot make it reusable.
  - Binding to `run_id` prevents replaying an approval into a later run with an identical action
    set (spec issue S-10).
- **Execution check:** the kernel recomputes the hash of the set it is about to execute; any
  divergence aborts with nothing executed. Per-action re-checks follow §5 step 4.
- **Presentation:** the approval view is rendered from the hashed object. It therefore shows
  every argument's *and the pc's* untrusted origins, each verdict, and (unhashed) each reason.
  A literal-argument action under a tainted `map` is visibly untrusted-selected.
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
- both have the same rows (keys) in every table, except tables whose rows customers can create
  (tickets, §2.1), whose row sets may differ;
- they agree on every trusted cell of the common rows, the clock and the provider state;
- untrusted cells may differ arbitrarily. That includes values outside the "intended" type:
  extreme integers in extractor output, and invalid UTF-8 (§3.2).

Extractor outputs are part of the untrusted environment. The harness uses a "raw" extractor
whose output is an arbitrary function of the text, so the property covers every *stateless*
extractor. In a third of examples each run instead gets a fresh *counting* extractor, whose
output for token-free text depends on the parity of its call count. That samples extractors
with within-run memory; it does not cover all of them. The argument for all of them is the
cumulative label (§3).

### 9.2 Observations of a run of plan `P` in `E` with approver `Ap`

- `Res(P,E)`: resolved actions with labels;
- `D(P,E)`: rule decisions `(rule, site, outcome, canonical admitted action)`, and its release
  projection `π(D)`, which applies each rule's `π_R` to its decisions (§6.1);
- `Req(P,E)`: approval requests as canonical sets;
- `X(P,E,Ap)`: executed effects, read from the payment provider's log and the consequential DB
  writes. The harness (`tests/ni_properties.py::effects`) groups them by table: refunds, then
  credits, then closures, each in execution order. Comparing these ordered lists is stronger
  than the spec's multiset, but it does not compare the interleaving across tools (Gate 3
  review #9).

### 9.3 Properties (for every well-typed `P` and every `E1 ~ E2`)

- **NI-1 (trusted-action determinism).** The subsequence of `Res(P,E)` whose effective label
  (`⊔ args ⊔ pc`) is trusted is identical, as (site, tool, values), for `E1` and `E2`. It needs
  no assumption about rules, so it is never vacuous. It is stated for pairs in which both runs
  finish resolution: a run halted during resolution (§3, D-054) has no action set, and the
  halt itself is whole-run suppression, covered by NI-3.
- **NI-2 (policy soundness).** For every `E`, every `ALLOW`ed action is either fully trusted or
  every untrusted component is endorsed by a logged decision in `D(P,E)`.
- **NI-3 (delimited release of effects, modulo whole-run suppression).** If
  `π(D(P,E1)) = π(D(P,E2))`, then each of `X(P,E1,deny)` and `X(P,E2,deny)` is either empty or
  equal to one common sequence `X*`. Untrusted data may only *suppress the whole run* (§5),
  never change what executes. Effects may differ in content only through what rules release,
  and rules release only through `π(D)`.
  - This is the formal version of "unless it is an enumerated residual risk". The precondition
    compares the projection, not the admitted actions, so a rule that admits a different action
    than its release claims fails NI-3 directly (review findings 1 and 2).
  - **Partial runs.** A run that stops as `partial` or `indeterminate` executes a prefix. That
    happens after a provider failure, or after a verdict that became stricter between effects
    (§10). Its `X` is a prefix of `X*`, not `X*`, so the statement above holds for runs that
    finish. For a partial run, NI-3 claims only that `X` is a prefix of `X*`.
  - **What the harness checks** (Gate 3 review #8):
    - The single-run property injects no provider failures and has no concurrent writer, so a
      partial run cannot arise in it. It checks "empty or `X*`".
    - The multi-run property, which does inject provider failures, checks NI-2 and NI-4, not
      NI-3.
    - The prefix clause is therefore stated but not exercised.
- **NI-4 (rule postconditions).** For every `E`, every executed action admitted by rule `R`
  satisfies `Post_R` (§6.2). It is checked by test code independent of the kernel, **over
  sequences of runs** on an evolving environment, because some postconditions ("only refund
  ever for ticket `T`") span runs (review finding 3).
- **NI-5 (approval binding).** With an approver that approves hash `h`:
  - the executed canonical set hashes to `h`, or nothing (or a reported partial prefix, §5)
    executes;
  - an approval issued in run `r` is rejected in any run `r′ ≠ r`, and on a second use in `r`.
  - **What the harness checks** (Gate 3 review #8):
    - The property (`tests/test_approval_binding.py`) treats *any* partial run as a violation,
      which is stricter than the statement. Without injected failures or a concurrent writer
      (as above), a partial run there can only come from a kernel bug, such as a re-check
      that counts a relaxed verdict as stricter. The NI-5 mutant is caught only because of
      that stricter check.
    - The property's approver always answers with the current run's hash, so it never tests
      the second clause. Replay, cross-run use and second use are deterministic unit tests in
      the same file.
- **Approval steering (recorded, not a violation):** `Req(P,E1) ≠ Req(P,E2)`.

**Reported with every NI run:**
- examples run and seed;
- the fraction of pairs in which some rule was consulted;
- the fraction in which `π(D)` differed (NI-3's precondition failed);
- the fraction suppressed (one side empty, the other not).

A low consulted-and-equal fraction would make NI-3 vacuous, so it is printed, not hidden.

**Termination:** evaluation is total (§3.2), so the property is termination-sensitive. An
exception in either run fails the test.

### 9.4 Harness

- Plans come from two generators (`planners.fuzz.plans(world, source)`): hand-written shapes
  (Gate 2 review #3) and a grammar-based generator (`planners.grammar_fuzz`, Phase 3, D-053).
  Each NI property (single-run, multi-run, NI-5) runs once per generator, as separate tests
  with separate budgets, so grammar plans never take examples from the shapes (D-056).
  - **Shapes.** Amounts and predicates inside them come from a small type-directed expression
    generator.
  - **Grammar plans.** These are arbitrary well-typed plans derived from the plan grammar and
    the tool registry. Every expression is generated for an expected type from the names and
    record fields in scope, per-type literal pools (the world's ids plus ids that name
    nothing) and operators. `map`/`filter` nest up to `MAX_DEPTH`, plans have at most 40 steps,
    and expressions are at most 2 operators deep. It is biased towards untrusted data in
    control (D-056): half the plans open by extracting order ids from a record's text, and
    iteration, `at`, `len` and `contains` prefer data derived from untrusted text, with mostly
    consequential calls under it. It targets the labelling rules, not the declassification
    rules.
  - Every generated plan passes the checker.
  - Hypothesis's statistics output counts each plan's source and, for grammar plans, each
    construct used (every tool, operator, iteration depth, field path, consequential call under
    a `map`).
  - The guarantee covers every well-typed plan. The fuzzer samples a distribution over them,
    so a passing run is evidence about that distribution. The grammar generator widens it
    beyond the shapes, but it is not exhaustive.
- The shapes are the known laundering patterns: selection by a tainted predicate, tainted `at`
  indices, `len` of tainted lists, money arithmetic on tainted values, nested `map`/`filter`,
  calls inside tainted `map` bodies with all-literal arguments, credits and closures under a
  ticket read or triggered by order notes, and selection by the ticket's `status` or
  `subject`. Added after the Gate 2 review: extraction from literal text after a `map` that
  extracts under a note- or existence-selected `pc`; a trusted refund on the case customer's
  second ticket followed by rule-path refunds on the case ticket; `order_stats` in `pc` and
  arguments; and `incident_orders` under a trusted `pc` and under a ticket read.
  The `order_stats` shapes exercise label propagation only. The NI properties are integrity
  properties, and an aggregate carries `U = ∅`, so they cannot see a confidentiality (P5 sink)
  violation; removing the sink check goes unnoticed by every NI property (Gate 3 review #5).
  P5 is covered by deterministic tests instead, marked with the "sink check removed" mutant
  (`tests/test_tools_phase2.py`, D-065).
- Environment mutations rewrite untrusted cells, add a ticket opened by another customer, add
  a second ticket for the case customer, or delete the case ticket. `customers.display_name`
  is mutated, but no tool reads it, so those mutations have no effect. Their values are drawn to be dangerous: IDs of the same
  customer's other orders, other customers' orders, duplicates, empty lists, the maximum list
  length, extreme integers, and invalid UTF-8.
- A multi-run property runs two plans on one evolving environment. A provider failure may be
  injected into the first run; between runs the attacker rewrites the case ticket and may open
  a new ticket. NI-2 and NI-4 (with its cross-run postconditions) are checked on both runs, and
  no order may be refunded more than was paid.
- Mutant tests break one mechanism each (four label rules, the pc component, rule uniqueness,
  the rule's origin set, once-per-ticket, never-refunded, record-before-call, the halt on a
  missing trusted ticket (D-054), the goodwill rule's origins, amount and per-customer bound, extraction under control,
  and the execution re-check's direction) and require the harness to fail. Every mutant runs
  against the shapes properties, and the grammar properties run the mutants the grammar catches
  on its own. A mutant counts as caught only from a clean state: an explicit seed, no example
  database, and Hypothesis's generation pinned to the seed (`tests/determinism.py`, D-056). The
  execution pre-pass has no mutant: the harness has no concurrent writer, so it is covered by
  regression tests only.
- Deterministic mutants (`tests/deterministic_mutants.py`, D-063) cover checks the NI harness
  cannot reach: the re-check stopping on a stricter verdict, the existence origin on
  untrusted-id reads and in the rules' origin set, and the P5 sink check. Each is caught by
  tests marked `harness_gap("<mutant>")`, and `check` re-proves every kill.
- **Limits of the harness** (Gate 3 review #9). A passing NI run says nothing about these.
  - *Not compared:*
    - approval requests (by design: steering is recorded, §9.3);
    - the durable audit row: NI-2 reads the in-memory rule log, so "the decision was logged"
      is checked against the audit table only by `tests/test_audit.py`;
    - pending refund rows;
    - the interleaving of effects across tools (§9.2).
  - *Not generated:*
    - concurrency of any kind: the run lock (§10) and the re-check have deterministic tests
      only;
    - an approver that approves under NI-3, which runs with deny only;
    - extractors with state across runs;
    - untrusted ticket ids (D-064);
    - provider failures in paired runs (§9.3);
    - a rule-admitted action alongside a halt elsewhere in the plan, where the halt is the
      only difference.
  - *Vacuity:*
    - NI-1 is skipped for every pair in which a run halts: 27% of shapes pairs and 16% of
      grammar pairs, single-run property (DECISIONS, "Halts and NI-checked shares",
      stage-a statistics). A kernel that halts more often would pass NI-1 more easily. That
      is safe for effects, but it narrows what NI-1 measures.
    - The fraction is printed with every run.
- `tasks.py check` runs a derandomized profile; `tasks.py fuzz` runs the `fuzz` profile. Neither
  uses an example database. Shrunk
  counterexamples become `@example` regression tests.

---

## 10. Execution layer (thin)

As SPEC §4.7:

- Before calling the provider, write the refund row as `pending` with business idempotency
  key `refund:{order_id}:{ticket_id}`. Pending rows count as refunded for every policy read.
- If the provider call raises, ask the provider for the key's status: committed → record it
  and continue; not committed → delete the pending row and stop (`aborted` or `partial`);
  status unknown → keep the row pending and stop (`indeterminate`). Phase 2 adds recovery of
  pending rows and the crash-injection test.
- A second refund on the same order and ticket is BLOCKed by the policy (P3), never absorbed
  silently by the key (Gate 1 review #7).

Idempotency is a reliability mechanism. Security never depends on it: duplicates are already
BLOCKed by the policy (P3), and the record is written before money moves (Gate 1 review #2).

**Concurrency model: a single writer per database (Gate 3 review #1, D-061).**
- Each database has one run at a time. `run_plan` and `run_task` take the database's run lock
  (`kernel/runlock.py`) before `recover()`, and hold it until the final audit row is written.
- A run that finds the lock held raises `RunLocked`. It writes nothing, and its run id stays
  unused.
- How the lock works:
  - Within a process, the lock is a registry of held databases.
  - Across processes, it is an exclusive SQLite transaction on `<database>.runlock`.
  - The operating system releases that transaction when the holder dies, so a crash leaves
    no stale lock.
- Kernel runs are the only writers of `refunds`, `credits`, `approvals`, `audit` and ticket
  status. Other parties may add tickets, orders and customers concurrently; their existence
  is already attacker-influenced (§2.1).
- Without the lock, a second run's `recover()` could delete an in-flight run's pending row.
  The provider then committed, the record was lost, and the ownership rule paid the order a
  second time.
- If the provider's reference matches no pending row, the kernel restores the record and
  raises `RecordLost`. It never reports a clean execution. Under the lock, only a writer
  outside the kernel can cause this.
- Tests: `tests/test_concurrency.py` (the reviewer's probe, re-entry, a second process, a lost
  record).

## 11. Persistence (storage label rule)

Revised after review finding 4.

- **Every executed write is part of a warranted action**: fully trusted, rule-endorsed, or
  approved. A write's *trust* comes from that warrant. The approval view (§7) lists every
  trusted column an approved action will write, with the pc and argument origins. A human who
  approves "escalate ticket 77" sees that `tickets[77].priority` will become a trusted `high`,
  and that the choice of 77 came from untrusted text.
- **Trusted columns** may be written only when
  `label(value) ⊔ label(row-selecting args) ⊔ pc` is trusted, or when every untrusted part of
  that join is endorsed by a rule or covered by the approval of this exact action.
  - The row key and the `pc` count, not just the value.
  - Effect records (refunds, credits) are written by the kernel from the canonical action and
    state what executed. They are trusted facts about the past, not plan-supplied data.
- **Untrusted columns** written by the agent (free-text notes) store their origin set alongside
  the cell, and the cell is read back with that `U` (or `★` if none was stored). The agent may
  never write `tickets.subject` or `tickets.body`. Those columns are written only by the
  customer channel, so `Ω_T` (§6.2) really means "text that arrived on ticket `T`", and text
  from elsewhere cannot be relabelled into it.

This closes laundering across runs.

## 12. Parameters

| Name | Value | Note |
|---|---|---|
| `MAX_STEPS` | 64 | static |
| `MAX_DEPTH` | 2 | nesting of map/filter, static |
| `MAX_LIST` | 100 | runtime truncation (`LIMIT` on reads, cap on `map`); not logged in Phase 1 |
| `MAX_EXTRACT` | 5 | extractor list length |
| `MAX_ORIGINS` | 32 | collapse to `★` |
| `θ` | 0 | ownership-rule ambiguity threshold (minor units) |
| `AUTO_REFUND_CAP` | `None` | ownership rule; chosen from the step 5 sweep |
| `GOODWILL_AMOUNT` | 10,000 | goodwill rule; the only amount it admits |
| `CREDIT_MAX` | 50,000 | P3 limit on any credit |
| `MIN_GROUP` | 5 | smallest group `order_stats` reports |

All are provisional until Phase 1 measures them.
