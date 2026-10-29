# Gate 0 independent review

**Reviewer:** a fresh subagent, given only `docs/THREAT_MODEL.md`, `docs/DESIGN.md` (as of
commit `4488294`) and the code. It did not see `DECISIONS.md`, `SPEC.md`, `CLAUDE.md`, the
author's reasoning, or any results. Its job was to find a way to violate the invariant.

Part 1 is the review, verbatim. Part 2 is the author's response to each finding.

---

## Part 1: Findings (verbatim)

# Warrant — independent security review (read-only)

Scope read: `docs/THREAT_MODEL.md`, `docs/DESIGN.md`, `kernel/` (only `__init__.py`), `tests/`, `scripts/tasks.py`, `pyproject.toml`, `Makefile`. No repo files modified. One probe script written to the scratchpad (`<scratchpad>\probe.py`, [local temp path redacted by author]).

Commands run: `.venv/Scripts/python.exe -B -m pytest -p no:cacheprovider -q` → `7 passed`; `.venv/Scripts/python.exe -B -I <scratchpad>/probe.py <repo>` → bypass results quoted in findings 15–16.

---

## 1. NI-3 is false for the design as written: atomic decision lets one untrusted bit gate trusted actions with `D` identical
**Severity:** High. **Where:** DESIGN §5 (atomic combine), §6 P1, §9.3 NI-3; THREAT_MODEL §6 (availability) vs §7.

**Attack.** Plan with no rule involvement:
```
t    = read_ticket(42)
oids = extract_order_ids(t.body)
map(oids, o ⇒ close_ticket(ticket_id={"lit":42}))          # tainted pc, literal args, no rule
issue_refund(ticket_id={"lit":43}, order_id={"lit":900}, amount={"lit":1000})   # fully trusted, valid
```
E1: extractor → `[]` ⇒ A = [refund], ALLOW ⇒ X = [refund]. E2: extractor → `[7]` ⇒ A = [close(42), refund]; close is NEEDS_APPROVAL; deny ⇒ X = []. No rule consulted, so D(E1)=D(E2)=∅, precondition holds, conclusion fails. The adversarial generator ("calls inside tainted map bodies with all-literal arguments") will hit this immediately, and the likely response is an ad-hoc weakening of the most important test. In batch use, any one ticket's author decides whether every other customer's trusted, auto-allowed actions execute (a stray non-existent ID → BLOCK suppresses all of A). The §6.2 release ("decides one bit per ticket: whether *that refund* executes automatically") understates this — the bit gates all of A.

**Fix.** Either make whole-run suppression explicit in the threat model and restate NI-3 to match the atomic semantics (for E1~E2 with equal release projection — see #2 — X(P,E1,deny) and X(P,E2,deny) are each either ∅ or one common sequence X*), plus a separate check that every executed action was ALLOW/approved; or drop atomicity (but that changes semantics).

## 2. NI-3's precondition includes the admitted action, so it cannot catch a rule that releases more than claimed
**Severity:** High. **Where:** §9.2 (D contains "canonical admitted action"), §9.3 NI-3, §6.2 release.

**Failure scenario.** An honest implementer drops or mis-codes condition 3 (`|Eligible(C)| = 1`). The rule now admits whichever eligible order the text names. E1 text names O1, E2 names O2 → admitted actions differ → D(E1) ≠ D(E2) → pair is counted in the "D differed" fraction instead of failing. NI-3 is vacuous exactly when the rule leaks; only NI-4 could catch it, and only if the independently written postcondition is complete.

**Fix.** Each rule declares a *release projection*; for θ=0 it is `(rule, site, outcome)` only (θ>0 adds the admitted order). NI-3's precondition becomes equality of projections. This directly tests the claim "the admitted action is a function of trusted data alone".

## 3. "Once per ticket" is only enforced inside one run
**Severity:** Medium. **Where:** §6.2 condition 5 ("A contains no other issue_refund with ticket_id = T"), postcondition "at most once per ticket"; NI-4 is per-run.

**Attack.** Day 1: Eligible(C) = {1001}; ticket 42 text makes extractor return [1001] → rule admits, refund executes. Day 2: order 1002 becomes C's only eligible order; attacker edits `tickets[42].body` (they control it); operator (or batch job) runs "resolve ticket 42" again → rule admits again. Second automatic refund on the same ticket, violating the stated postcondition; no per-run property can see it.

**Fix.** Condition 5 must also check the persistent refunds table (trusted) for any prior refund with `ticket_id = T`; NI-4 must be checked over sequences of runs.

## 4. Storage rule (§11) ignores row selection and pc, is silent on approval, and loses origins
**Severity:** Medium. **Where:** §11, §6.1 last paragraph, §7 Presentation.

(a) Only the written *value's* label is checked. `escalate_ticket(ticket_id)` writing the tool constant `'high'` to trusted `tickets.priority`, called with ticket_id extracted from text (or literal args under a tainted map): NEEDS_APPROVAL; human approves "escalate 77" (view shows no pc origins, see #9); storage check passes since the constant is ⊥; a later trusted plan ("goodwill credit for high-priority tickets") reads the cell as trusted and is ALLOWed. The human approved an escalation, not a credit — this is THREAT_MODEL §5 "persistence laundering".
(b) An approved-but-unendorsed refund has a tainted `order_id`; under §11 it cannot write its own refund record to a trusted column. An implementer will plausibly treat "approved" as "endorsed", laundering every approved tainted value into trusted columns.
(c) Untrusted→untrusted writes relabel origin: on read, an untrusted cell gets `U = {t[k].c}`. If any tool writes agent text into `tickets[T].body/subject` (e.g. "append internal note"), text derived from another ticket or a third party's order note becomes "T's customer's own text" — inside Ω_T for the ownership rule. With θ=0 the third party controls T's bit; with θ>0 they redirect. Also "label ⊑ Λ(column)" is ill-defined since Λ for untrusted columns is a per-cell origin.

**Fix.** Require `label(value) ⊔ label(row-selecting args) ⊔ pc ⊑ column label` unless endorsed; state that approval is not endorsement for storage and define the label of the effect's own system record separately; store provenance (origin set or ★) with each agent-written untrusted cell and restore it on read.

## 5. "Values carry no pc" assumes extractor/read tools are pure; timeouts/budgets/state break it
**Severity:** Medium. **Where:** §3 ("sound because the language is pure"), §3.2 (extractor timeout → `[]`), §3.3, §9.1 (harness draws extractor outputs directly).

**Attack.** A map over an attacker-sized list (nesting permits up to 10⁴ iterations) calls the LLM extractor repeatedly under tainted pc. If there is a run-wide wall-clock budget, shared model context/KV/prompt cache, or a per-run call cap, those calls change a *later, top-level* extractor call (timeout or different output). That later call's output label is only `label(text)`: if its text is trusted, the output is trusted-labelled and auto-ALLOWed while depending on untrusted data; if its text is from Ω_42, the output is attributed solely to ticket 42 while ticket 43's author influenced it (rule mis-attribution). The harness models the extractor as a pure function of its own input, so it can never detect this. Related "arbitrary function" interface gaps: outputs must be exact builtin types (`bool` is an `int`, `True == 1`; `int`/`str` subclasses can override `__eq__`/`__hash__`); extractor exceptions/hangs must be caught/bounded kernel-side.

**Fix.** Require fresh state per call and a deterministic per-call budget (tokens, not wall-clock); forbid calling the extractor on trusted text (it doesn't need quarantine); or join labels of all earlier extractor inputs in the run into the output; strict exact-type validation; a test calling the real adapter with different preceding calls and checking identical outputs.

## 6. Label rules for compound values used whole are unspecified
**Severity:** Medium. **Where:** §3 table (`op(e1..en)` "scalar", `min`/`max` arity), §7 (list-valued args allowed), §6 P1/P5, §9.3 "⊔ args".

**Failure scenario.** `notes = map(list_orders({"lit":C}), r ⇒ r.customer_note)` has trusted structure and tainted elements. A natural implementation of `label(list) = struct` makes `eq`/`min`/`max` over the list, or passing it as a `List[...]` argument (Phase 2 bulk/incident tools), look trusted. Same question for `elem ⊔ struct` when elem is itself a record/list (does the join reach the inner record's selection label / inner list's struct?).

**Fix.** Define the label of a compound value used whole as struct ⊔ (all element/field labels, recursively); P1/P5/effective-label range over every leaf; type checker restricts `op`s to scalars and states `min`/`max` binary.

## 7. Row existence assumed trusted, but the threat model's attacker can create tickets/orders
**Severity:** Medium. **Where:** DESIGN §2.1 "Row existence and keys are trusted", §9.1 (~ fixes all rows) vs THREAT_MODEL §4 ("may also be a legitimate customer with their own account, orders and tickets").

**Failure scenario.** `map(list_tickets(customer={"lit":C}), t ⇒ …)` or `list_open_tickets()` yields a trusted structure whose length the attacker sets by opening tickets; every trusted-arg action in the body is auto-ALLOWed and multiplied (THREAT_MODEL "Duplication"). The proposed Phase 2 "goodwill credit to the case's customer" rule likewise scales per ticket. The NI harness can never find this because ~ never varies rows.

**Fix.** Give existence of customer-creatable rows an origin (e.g. per-customer origin on the row), or scope set-level limits per customer rather than per ticket; extend ~ to vary customer-created rows.

## 8. Planner independence depends on properties enforced outside the TCB
**Severity:** Medium. **Where:** §1 ("kernel builds the planner's input"; wiring at a composition root outside `kernel/`), §8 (plan label, "invoked once per task").

**Failure scenario.** If the composition root calls the planner, the kernel cannot know what the planner saw, so `plan_label` is whatever it is told. A plausible retry loop — `for attempt in range(3): plan = planner(req); r = kernel.run(plan); if r.ok: break` (re-sampling at temperature after BLOCK/denial) — lets untrusted outcomes choose *which* plan executes; NI is quantified per plan and cannot see it.

**Fix.** Kernel calls a Planner interface with an input it builds itself and logs a hash of; plan label computed from that; kernel refuses a second run for the same task id (or labels subsequent plans with prior outcomes' labels).

## 9. The hashed approval object omits pc, origins and reasons; no property covers the approval path
**Severity:** Medium-Low. **Where:** §7, §9.3.

Canonical object is `{tool, args}` — no pc, origins, or verdict reasons — so the view cannot be "rendered from the same canonical object that is hashed" and also show origins/reasons. Presentation shows *argument* origins only, so a literal-args action under a tainted map looks fully trusted to the approver (approval steering; feeds #4a). NFC normalisation if applied only for hashing lets executed bytes differ from approved bytes. `run_id` uniqueness/unpredictability and atomic consumption across a crash are unspecified. NI-1..4 all use the deny approver, so path (b) is never exercised.

**Fix.** Put per-component labels (incl. pc) and reasons into the hashed object; execute exactly the canonical values; add NI-5: with an approver approving hash h, the executed canonical set hashes to h or nothing executes, and an approval from run r is rejected in run r′.

## 10. Within-run TOCTOU; recheck only for approved sets
**Severity:** Low. **Where:** §5 step 4, §7 Execution check.

Rule admission (`|Eligible|=1`, already-refunded, ownership) is decided on pre-run state; for an all-ALLOW A nothing re-checks as earlier actions in A change state; approved-set recheck only covers BLOCK checks. Partial-execution semantics (vs "executed set matches hash") are undefined.

**Fix.** Re-evaluate the full policy (including rule admission) per action against current state immediately before executing it; define abort/partial semantics.

## 11. Policy inputs unrestricted; policy spec self-contradictory
**Severity:** Low. **Where:** §6 intro, P2 vs P3/table.

Policies may make "database reads" with no restriction to trusted columns — a policy reading `customer_note` makes the verdict depend on untrusted data outside P1's component check. Set-level constraints over A aren't required to be monotone (a tainted action could make a trusted one ALLOW). P2 says an unowned order gives NEEDS_APPROVAL; P3 and the table say wrong customer → BLOCK.

**Fix.** Policy read API refuses untrusted columns; require set constraints to be monotone (more actions only tighten verdicts); resolve the P2/P3 contradiction.

## 12. §3.3 lemma is wrong as stated; selection labels underspecified
**Severity:** Low. **Where:** §3.3, §3 read-tool row.

"Label computation never inspects a value" is false: origins are built from row keys (values), and ★-collapse depends on |U| (which rows were read, dedup of equal IDs). The trusted bit (U=∅) does appear syntax-determined; restate the lemma that way. "Selection columns" must cover every column affecting membership, order, multiplicity or length (WHERE, ORDER BY, JOIN, DISTINCT, LIMIT); require `ORDER BY` on trusted keys, otherwise SQLite order can follow index/planner choices.

## 13. Totality gaps an honest implementer will miss
**Severity:** Low (suppression). **Where:** §3.2.

Unbounded integers: `add`/`sub` grow without bound and SQLite raises `OverflowError` beyond 64 bits; negative Money needs a stated domain. Invalid UTF-8 in attacker-controlled TEXT cells makes `sqlite3` raise on row read. Extractor raising/hanging propagates. The "within column types" generators won't produce these.

**Fix.** Checked or saturating bounded numeric types; lossless byte decoding; wrap extractor calls.

## 14. Confidentiality sink has no principal
**Severity:** Low. **Where:** §2 `S ⊆ {operator, customer}`, P5.

"customer" doesn't say *which* customer, so any trusted non-PII row (order amounts/statuses) may flow to any customer's reply. Today only integrity (approval) stops attacker-selected cross-customer replies; any future rule endorsing reply arguments turns this into exfiltration.

**Fix.** Parameterise the sink by customer id (`customer:C`).

## 15. Network guard is bypassable (verified)
**Severity:** Low. **Where:** `tests/conftest.py:25-30`.

Verified in this session after `_block_network()` was applied: `socket.gethostbyname("localhost")` → `'127.0.0.1'` (resolver not patched); `_socket.socket(AF_INET, SOCK_STREAM).connect_ex(("127.0.0.1", 9))` → real connection attempt, returned `10061` (connection refused). `sendmsg` with an address is also unpatched (absent on Windows, works on POSIX). Subprocesses are not covered. The guard only applies under pytest, not to `make eval/fuzz/demo`.

**Fix.** Install a `sys.addaudithook` refusing `socket.connect`, `socket.getaddrinfo`, `socket.gethostbyname`, `socket.sendto`, `socket.sendmsg` events (these fire for `_socket` too), and install it in eval/fuzz entry points as well.

## 16. Import-boundary scanner misses common dynamic-import forms (verified)
**Severity:** Low (code is not attacker-controlled). **Where:** `tests/test_import_boundary.py:39-44`.

Verified: `boundary_violations(src, "kernel.policy")` returns `[]` for `builtins.__import__('planners')`, `exec('import planners')`, `sys.modules['planners']`, `pkgutil.resolve_name('planners:x')`, `runpy.run_module('planners')`, `from pydantic import ImportString`, and `getattr(__builtins__, '__imp'+'ort__')(...)` — while the module docstring claims dynamic imports are forbidden.

**Fix.** Also flag `__import__` as an attribute, `exec`/`eval`/`compile`, `__builtins__`, `builtins`, `sys.modules`, `pkgutil`, `runpy`, `ImportString`; better, add a runtime check: import every kernel module in a subprocess with a meta-path finder that raises on the forbidden packages, then assert they're absent from `sys.modules`.

---

## Overall assessment

The core information-flow design is careful and mostly holds up: explicit pc on calls with pc not joined into values, all-predicate filter/struct joins, list-valued `at`, all-element `contains`, the plan label for a leaky planner, and policy-time per-action endorsement are sound choices, and I did not find a plan in which untrusted data *causes* a new consequential effect to auto-execute within a single run if the label rules are implemented as written. The serious problems are in the checking machinery and at the edges. NI-3 as written is both false under the design's own atomic semantics (#1) and blind to exactly the rule leaks it exists to catch (#2) — both need restating before any fuzzing result means anything. Cross-run and persistence gaps — "once per ticket" (#3), the storage rule ignoring row-keys/pc/approval and losing origins (#4), attacker-created rows (#7) — are invisible to an NI harness that compares single runs over environments with fixed rows. Several soundness assumptions live outside the TCB or in components treated as pure (planner invocation #8, extractor statefulness #5), and should be enforced rather than stated. The existing tests pass (7 passed) but overstate what the network guard and import-boundary checks enforce (#15, #16).

---

## Part 2: Responses

All findings were accepted. None was rejected. Design changes are in `DESIGN.md` (from the commit
after `718c66f`) and in `DECISIONS.md` D-014…D-019. Code fixes are in commit `718c66f`.

| # | Sev. | Response | Where |
|---|---|---|---|
| 1 | High | **Accepted; this was a real error in my design.** Atomic decisions make whole-run suppression a channel, and NI-3 as first written was false. I kept atomicity, because a plan is one intent. NI-3 now says each side is ∅ or one common `X*`. Suppression is named in THREAT_MODEL §6, and runs are per ticket to bound it. NI-2 already checks that every executed action was ALLOW or approved. Atomic vs partial is flagged for the owner. | DESIGN §5, §9.3; D-014 |
| 2 | High | **Accepted.** Each rule declares a release projection `π_R`; NI-3 conditions on `π(D)`. For `θ = 0`: `(rule, site, outcome)`. | DESIGN §6.1, §6.2, §9.2–9.3; D-015 |
| 3 | Med | **Accepted.** Condition 5 consults the persistent refunds record. The postcondition is "only refund ever for `T`", and NI-4 runs over sequences of runs with the attacker editing between runs. | DESIGN §6.2, §9.3, §9.4; D-016 |
| 4 | Med | **Accepted, all three parts.** (a) The trusted-column write condition includes the row-selecting args and `pc`. (b) Approval is the warrant for an approved action's writes, *and* the approval view lists every trusted column it will write with origins. Effect records are kernel-written facts. (c) Agent-written untrusted cells store and restore origins (★ if none). The agent can never write `tickets.subject/body`. | DESIGN §11, §7; D-016 |
| 5 | Med | **Accepted.** Extractor contract: stateless per call, token-bounded per call, no run-wide budgets; exact-type validation; exceptions give `[]`. A Phase 4 test checks the LLM adapter's output is independent of earlier calls. I did not adopt "forbid the extractor on trusted text" or the history-label join, because statelessness addresses the cause. I can revisit if Phase 4 cannot guarantee statelessness. | DESIGN §3; D-017 |
| 6 | Med | **Accepted.** A compound value used whole is labelled struct ⊔ all leaves, recursively. Ops are scalar-only except `len`/`at`/`contains`; `min`/`max` are binary. P1/P5 range over leaves. | DESIGN §3 |
| 7 | Med | **Accepted.** Ticket enumeration carries per-customer existence origins `tickets[*@C]`. Set limits are per customer too, `~` varies ticket rows, and the fuzzer adds and removes them. Order existence stays trusted, since orders are created through checkout and payment. That is a stated assumption. | DESIGN §2.1, §9.1, §9.4; D-016 |
| 8 | Med | **Accepted.** The kernel invokes the `Planner` protocol with an input it builds, logs the input hash, derives the plan label, and accepts one plan per task id. | DESIGN §1; D-017 |
| 9 | Med-Low | **Accepted.** The hashed object carries per-component origins, including `pc`, plus verdicts and reasons. NFC is applied at resolution, and the kernel executes exactly the canonical values. `run_id` is a random UUID (seed-derived in evals). Consumption is written with the intent records. NI-5 added. | DESIGN §7, §9.3; D-018 |
| 10 | Low | **Accepted.** The full policy, including rule admission, is re-run per action just before execution. On divergence execution stops, and the executed prefix is recorded and reported as partial. | DESIGN §5; D-019 |
| 11 | Low | **Accepted.** The policy read API is trusted-columns-only, P0 requires monotone set constraints, and the P2 example is fixed (it now matches P3). | DESIGN §6; D-017 |
| 12 | Low | **Accepted.** The lemma is restated as "emptiness of `U` is syntax-determined". Selection labels cover WHERE/JOIN/ORDER BY/DISTINCT/LIMIT, and results are `ORDER BY` a trusted key. | DESIGN §3, §3.3; D-019 |
| 13 | Low | **Accepted.** Bounded saturating `Int`/`Money` (±10¹⁵); untrusted TEXT is decoded with replacement; extractor calls are wrapped. Generators include these cases. | DESIGN §3.2, §9.1; D-019 |
| 14 | Low | **Accepted.** Sinks are `operator` and `customer:C`. | DESIGN §2, §2.1 |
| 15 | Low | **Accepted and fixed; I verified it myself.** I added regression tests for `gethostbyname` and a C-level `_socket.connect_ex`. Both **failed on the old guard** (`2 failed, 4 passed`). The guard is now a `sys.addaudithook` covering connect, sendto, sendmsg and name resolution. The guard does not reach subprocesses, and installing it in the eval/fuzz entry points is a Phase 1 item; both are recorded. | `tests/conftest.py`, `tests/test_network_guard.py` |
| 16 | Low | **Accepted and fixed; I verified it myself.** The reviewer's forms were added as test cases and **failed on the old scanner**. The static denylist is broadened, and a runtime check imports every kernel module in a fresh interpreter that refuses the forbidden packages. The probe was confirmed non-vacuous: forbidding `csv` and importing it gives `ImportError`. | `tests/test_import_boundary.py` |
