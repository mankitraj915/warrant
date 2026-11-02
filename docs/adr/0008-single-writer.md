# 0008 One writer per database, enforced by a run lock

## Context

The kernel writes a pending refund row before calling the payment provider, so that a crash
cannot lose the record. At startup it recovers pending rows left by a crashed run. Nothing said
whether two processes may share one database. The Gate 3 review started a second run while a
refund was in flight:
- its recovery deleted the first run's pending row, and the provider then committed;
- the first run's record update matched no row, yet the run reported success;
- a later ticket naming the same order was admitted by the ownership rule.

The order was paid 120,000 and refunded 240,000.

## Decision

There is a single writer per database
([DESIGN §10](../DESIGN.md#10-execution-layer-thin)). `run_plan` and `run_task` hold a lock from
before recovery until the final audit row (`kernel/runlock.py`). The lock names the database
the kernel writes, not the connection or file name used to reach it:
- **A file database** is locked by its resolved path: a registry within one process, and across
  processes an exclusive SQLite transaction on `<database>.runlock`, which the operating system
  releases if the holder dies.
- **An in-memory database**, which several connections can share, is locked by a row inside it,
  visible to every connection. It cannot go stale, because the memory dies with the process.
- **A database the lock cannot name** is refused before anything is touched
  (`UnlockableDatabase`). That covers a file with more than one hard link, and a connection with
  another database attached.

A run that finds the lock held raises `RunLocked` immediately and touches nothing. A provider
reference that matches no pending row restores the record and raises `RecordLost`, instead of
reporting success.

## Rejected alternatives

- **A blocking lock with a timeout.** A run started from inside a run would deadlock until the
  timeout. Refusing at once is simpler, and a caller can retry.
- **One SQLite transaction spanning the run.** The pending row must be committed before the
  provider call, or a crash loses it.
- **A lock row with a lease, for file databases.** A crash leaves the lock held until the lease
  expires, so the lease length becomes a safety parameter. For in-memory databases the row is
  safe, because a crash takes the row with it.
- **A lock keyed by connection or by the name the file was opened with.** This was the first
  version. The re-review of the fixes showed three ways to give two runs on the same data
  different keys: a shared in-memory database, a hard-linked file and an attached database. Each
  paid the same order twice.
- **Recovery skips rows of runs in flight.** This fixes the probe but not the related race: two
  runs on two tickets of one customer could both pass their re-checks before either writes its
  pending row.

## Consequences

- Runs on one database are serialised. Throughput across databases is unaffected; concurrent
  runs on one database are refused, not queued.
- Writers that bypass the kernel are out of scope
  ([THREAT_MODEL §6](../THREAT_MODEL.md#6-out-of-scope)).
- The mid-run re-check stays, for that out-of-scope case.

## Evidence

[D-061](../DECISIONS.md#d-061-single-writer-run-lock-2026-11-02-gate-3-finding-1-issue-1),
[D-071](../DECISIONS.md#d-071-the-run-lock-names-the-database-not-the-connection-2026-11-02-re-review-1-issue-33),
[GATE3_REVIEW.md](../reviews/GATE3_REVIEW.md) finding 1,
[GATE3_FIX_REVIEW.md](../reviews/GATE3_FIX_REVIEW.md) finding 1; `tests/test_concurrency.py`.
Each of its regression tests fails on the code before its change, including one that holds the
lock from another process and three that reach one database by two routes.
