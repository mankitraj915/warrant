# Gate 3 fix re-review (independent; range 14b9c26..08c24cb)

The reviewer's report follows verbatim. The only edit: the absolute local path of the scratch
directory is shortened to `scratchpad\gate3fix\`. ("RecumentLost" in finding 2 is in the
original; the exception is `RecordLost`.) The responses are in `docs/DECISIONS.md`, "Gate 3 fix
re-review: responses".

---

## Independent review of the Gate 3 fixes (14b9c26..HEAD)

I read docs/THREAT_MODEL.md, docs/DESIGN.md, all of kernel/, and the changes in the range: kernel, schema, tests, planners and scripts. I wrote the reproductions under scratchpad\gate3fix\ and ran them from the repo root with `PYTHONPATH=. uv run --locked pytest -p no:cacheprovider <file> -q --rootdir=.`.

I did not run the CI script inside the repository, because it creates git worktrees. I ran it in a local clone at `...\scratchpad\gate3fix\clone`. I modified no repository file and made no commits or pushes in the repository. Kernel code at main HEAD (08c24cb) is the same as at 13cd4d8.

### Findings

**1. MEDIUM: The run lock is keyed by connection or file name, not by the database being written. Two kernel runs on the same data can then refund one order twice, both times automatically through the ownership rule.**
- **Mechanism:**
  - `kernel/runlock.py:27-32`: `_path` looks only at the `main` entry of `PRAGMA database_list`, which is `""` for any in-memory database.
  - `runlock.py:38`: `key = path or id(db)`, so an in-memory database is locked per connection object.
  - `runlock.py:44-46`: no side-file lock is taken for an in-memory main database.
  - `runlock.py:47`: the side file is `path + ".runlock"`, so each name of a hard-linked file gets its own side file.
  - The kernel's SQL uses unqualified table names (`kernel/tools/database.py`, `kernel/execution.py`, `kernel/run.py`), so the tables can live in a database attached to a `:memory:` main.
- **Three configurations are not excluded:**
  - (a) Two connections to one shared-cache in-memory database (`file:x?mode=memory&cache=shared`, `uri=True`). `database_list` gives `[(0, 'main', '')]`, so the keys are `id(c1)` and `id(c2)`.
  - (b) Two hard-linked names of one database file.
  - (c) Tables in a database attached to a `:memory:` main. No `.runlock` file is created at all, so there is no exclusion across processes either.
- **Reproduction:** `...\gate3fix\test_lock_bypass.py`.
  - Run A uses connection c1 on ticket 4000 ("Refund #7000"). While A's refund is at the provider and not yet committed there, the provider starts run B on c2, for ticket 4002 of the same customer ("Refund #7000").
  - B's `recover()` deletes A's pending row, because the provider status is None.
  - B's ownership rule then admits 7000: it is the customer's only eligible order and no refund is on record. B pays.
  - A's provider call then pays as well. A raises `RecordLost` and restores its record.
  - Output, identical for all three configurations:
    - `provider effects: [(7000, 120000, 'refund:7000:4002'), (7000, 120000, 'refund:7000:4000')]`
    - `refund rows: [..., (7000, 4002, 120000, 'pay-1'), (7000, 4000, 120000, 'pay-2')]`
  - Two control tests behave as designed:
    - Two connections opened with the same path: B gets `RunLocked`.
    - The path spelled in upper case: it misses the in-process registry, but the side file is the same file, so B is refused with "another process holds...".
  - Result: `5 passed in 1.14s`.
- **Why it matters:**
  - An order paid 120,000 is refunded 240,000. Both refunds are effects parameterized by ticket text and admitted by `ticket_order_ownership`.
  - This breaks the rule's postcondition (§6.2, NI-4: "the first refund ever recorded for that order") and P3.
  - `RecordLost` detects the problem only after the money has moved.
  - THREAT_MODEL §6 and DESIGN §10 say the run lock enforces one run at a time per database. It actually enforces one run per connection object or per file name, and it gives no warning in the configurations above.
  - Choosing how the database is opened is up to the trusted composition root, not the attacker. That is why this is MEDIUM rather than HIGH.
  - Possible fixes: refuse these configurations (an in-memory main database, a non-temp attached database), or lock on the file's identity (device and inode) or on the database file itself rather than its name.

**2. LOW: When a run fails, its final audit row records nothing executed, even if money moved.**
- **Mechanism:**
  - `kernel/run.py:246-253`: `_audit_failure` writes a `RunResult` with no `actions` and no `executed` list.
  - `kernel/execution.py:273-280`: `RecordLost` is raised after earlier effects in the same run, and `execute`'s `done` list is lost with the exception.
- **Reproduction:** `...\gate3fix\test_audit_gaps.py::test_failed_final_row_records_no_effects_although_money_moved`.
  - Output: `provider effects: [(7100, 300000), (7000, 120000)]`.
  - Final row: `{'phase': 'final', 'outcome': 'failed', 'reason': "RecumentLost: ('refund:7000:4000', 'pay-2')", 'executed': [], 'actions': [], 'verdicts': []}`. Result: passed.
- **Why it matters:**
  - Condition (a) still holds, because the decision was written to the `decided` row before any effect.
  - But the audit asset ("explain every decision afterwards") states that no effect ran, when two refunds were paid. `trace` will say the same. Only the refunds table and the provider log show what happened.

**3. LOW: Some exceptions still leave no audit row, and the task id is not used up.**
- **Mechanism:** these all happen outside the `try` in `_run_plan`:
  - `planner.plan` (`run.py:404-405`);
  - `recover()` (`run.py:218`);
  - any `BaseException`.
- **Reproduction:** `...\gate3fix\test_audit_gaps.py::test_planner_exception_leaves_no_audit_row_and_task_can_be_planned_again`.
  - After the planner raises, `SELECT count(*) FROM audit` returns `(0,)`.
  - A new `Environment` on the same database plans task "T1" again, with outcome `executed`. The planner was invoked twice for T1. Result: passed.
- **Why it matters:**
  - This contradicts DESIGN §6.1 ("A run that an exception escapes still writes its final row").
  - It also weakens §1: "one plan per task id, durable across Environments" holds only when the run reaches an audit row.
  - I found no direct effect on the invariant, because the planner's input is trusted, or labelled untrusted in the leaked-context configuration.

**4. MEDIUM (CI gate): `scripts/new_tests_fail_on_base.py` accepts every new regression test in a PR if any one new test module fails to collect on base.**
- **Mechanism:**
  - Lines 56-71 run all regression ids in a single pytest call. One collection error interrupts that whole session.
  - Every id missing from the summary becomes "NOT COLLECTED" (line 117).
  - Line 119 counts "NOT COLLECTED", like ERROR, as failing on base.
- **Reproduction:** clone branch `demoA` (6f6af56), base 08c24cb.
  - The commit adds `kernel/newthing.py`, `tests/test_probe_fooling.py` (imports `kernel.newthing`, then asserts `1 + 1 == 2`) and `tests/test_probe_passes_on_base.py` (an ordinary test that passes on base: I ran it alone and got `1 passed`).
  - Script output: `NOT COLLECTED on base` for both tests, then `All 2 judged new test(s) fail on 08c24cb`, `exit=0`.
- **Related weakness:** a test that fails on base only because it imports a name the fix adds is accepted without its assertions ever running there. In this range, `test_concurrency.py::test_refused_run_touches_nothing` and `::test_run_lock_excludes_another_process` fail on base only with `ModuleNotFoundError: No module named 'kernel.runlock'`.

**5. LOW (CI gate): A `harness_gap` test is judged only under a mutant that the same PR may define.**
- **Mechanism:**
  - Lines 101 and 112: gap tests are run only with `WARRANT_MUTANT=*`, and `tests/deterministic_mutants.py` is copied from HEAD (line 74).
  - Nothing runs the test unmutated on base, and nothing checks that the mutant touches the code the test claims to cover.
- **Reproduction:** clone branch `demoB` (1dc0370).
  - The PR adds the mutant `"arbitrary": (Database, "__init__", lambda *a: 1 / 0)` and a test marked `harness_gap("arbitrary")` that passes on base unmutated (`-rA` gives `PASSED`).
  - Script output: `FAILED on base under its mutant`, then `All 1 judged new test(s) fail on 08c24cb (1 of them under their mutant)`, `exit=0`.
  - `test_harness_catches_deterministic_mutant` would pass for this mutant too.
- **Why it matters:** whether a test counts as a harness gap is decided by the PR author, not checked by the script.

**6. LOW (CI gate): Tests changed in place are never judged.**
- **Mechanism:** line 97 treats only test ids that are new at HEAD as new.
- **Reproduction:** in `demoA`, I weakened an existing `test_concurrency.py` assertion to `assert True`. The script output does not mention it.
- **In this range:**
  - `test_gate1_regressions.py::test_case_ticket_existence_is_endorsable_by_the_rule` was rewritten in place. The script does not judge it; only `test_harness_catches_deterministic_mutant` covers it.
  - The NI-5 properties in `test_approval_binding.py` gained the adversarial approver under unchanged ids, so the script does not judge them either.
- **Hypothesis, not reproduced:** run locally, `collect(ROOT)` reads the working tree, but `_test_files` copies only committed differences. An uncommitted new test file would therefore be "NOT COLLECTED" on base and accepted. The script's docstring does say to commit first.

### Q2: do the new tests test what they claim?

- **Every `harness_gap` test fails under its own mutant, and for the stated reason.** I ran each mutant over the marked tests.
  - "sink check removed": the credit actually executes (`'executed' == 'blocked'`).
  - "re-check never stops": `'executed' == 'partial'`; the second refund is paid.
  - "untrusted-id ticket read drops @row": `'tickets[4999].@row' in frozenset({'orders[7000].customer_note'})` fails.
  - "rule origin set omits @row": `order_id has untrusted origins outside ticket 4000`.
  - Each patched name is looked up at its point of use, so every mutant really takes effect. A mutant on `kernel.policy.decide` would be inert, because `run.py` imports `decide` by name; my first probe mutant was inert for this reason. None of the existing mutants has that defect.
- **All 10 new regression tests fail on base.** I ran HEAD's tests against the 14b9c26 code in a worktree of the clone. The failures are behavioural, apart from the two import-only cases in finding 4:
  - "DID NOT RAISE";
  - `'NoneType' == 'RunLocked'`;
  - `['executed', ..., 'executed']` versus `needs_approval`;
  - `['ALLOW','ALLOW']`;
  - "DID NOT RAISE NIViolation".
- **One docstring overclaims.** `test_concurrent_run_cannot_lose_an_in_flight_refund_record` says it reproduces "the interleaving two processes sharing it would produce". It uses one connection object, so it only exercises the case where both runs have the same lock key. The two-connection case in finding 1 is untested.
- **One property is not pinned by any test:** that the lock is held through the final audit row. The code does hold it.

### Checked and found sound

- **Lock lifetime:** both entry points hold the lock from before `recover()` until after the final or failure audit row (`run.py:205`, `run.py:371`).
- **Lock behaviour:**
  - Re-entry on the same connection or path raises `RunLocked` without deadlock.
  - The registry entry is released in `finally`, even when taking the side-file lock fails.
  - A different-case spelling of the path is excluded through the side file (control test above).
- **Failure handler:** `rollback()` discards only uncommitted work. Every write that matters is committed before the next provider call or `raise`: the pending refund row, the approval being consumed, local effects, and the `RecordLost` restore. A pending row whose provider-reference update fails to commit stays pending, and `recover()` reconciles it later.
- **Approval rows left "requested":** this happens after a denial, after `approval_invalid`, or after a `BaseException`. Such a row cannot be consumed: either the run id is already spent in the audit table, or a retry fails at the approvals primary key before `_consume`.
- **P6 (per-customer credit bound):**
  - It covers every ALLOW path for credits, both trusted and rule-admitted. Untrusted credits the rule does not admit already need approval.
  - It is monotone (P0), keeps BLOCK precedence, and agrees with the pre-execution re-check and the between-effects re-check.
  - The rule decision is still logged as admitted when P6 then requires approval, so the NI-3 release projection is unaffected.
  - It is consistent with the goodwill rule.
- **`RecordLost`:** the record is restored and committed before the exception is raised.
- **NI-4 goodwill oracle:** the new per-customer count within a run is correct.
- **Kernel core:** this review found no bypass in:
  - the label rules for map, filter, at, len and contains;
  - the extractor's cumulative label with its syntactic pre-join;
  - the halt on a missing operator-named ticket;
  - P1, P3 and P5;
  - approval binding (run id, recomputed hash, single use);
  - the write-ahead `decided` row.
