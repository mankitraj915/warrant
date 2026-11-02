# 0005 A ticket read carries its row's existence as untrusted

## Context

Customers can open tickets, and ticket ids are predictable. So whether `read_ticket(T)` returns
a row at all is something an attacker can influence, even when `T` itself comes from the
operator. The first design (D-021) treated a lookup by an operator-named key as fully trusted.
The Gate 1 review produced a plan in which that one bit selects a fully trusted refund,
violating NI-1.

## Decision

`read_ticket(T)` joins the origin `tickets[T].@row` into its structure label, whether or not the
row exists. The ownership rule's endorsable origin set includes `@row`, so a case ticket's own
existence does not stop the rule from applying
([D-028](../DECISIONS.md#d-028-a-ticket-read-carries-its-rows-existence-origin-supersedes-d-021)).

## Rejected alternatives

- **Narrow the NI relation to fixed ticket rows.** This weakens the property exactly where the
  threat model says the attacker acts.
- **A narrower taint: no existence origin for a point read of an operator-supplied id**
  ([D-036](../DECISIONS.md#d-036-point-reads-of-a-trusted-ticket-id-keep-the-existence-taint-t08-hypothesis-rejected)).
  - The hypothesis was that such a read can only suppress a run, which NI-3 allows. It was
    tested and it does not hold.
  - The existence bit becomes a value: a `map` iteration count, a `len`, an `at` index. That
    value can choose *between* two different refunds, and both versions of the run execute with
    no rule involved. NI-3 itself fails, not only NI-1.
  - The counterexamples are kept as tests in `tests/test_point_read_existence.py`.

## Consequences

- Any plan step under a case-ticket read is existence-tainted, so the ownership rule, not plain
  trust, decides it. Dev task T08 moved from trusted to rule-decided. It was still admitted, but
  a customer with two eligible orders would have needed approval.
- The fuzzer had to gain selection and index shapes driven by order-note text outside ticket
  reads. With every case-ticket map tainted, the rule masked two label mutants until then.
- The approval cost was later removed by a different route, the halt rule
  ([0006](0006-halt-on-missing-operator-ticket.md)). Reads by untrusted ids keep the existence
  origin under that rule.

## Evidence

[D-021](../DECISIONS.md#d-021-ticket-row-existence-review-7-is-deferred-to-the-first-ticket-enumerating-tool),
[D-028](../DECISIONS.md#d-028-a-ticket-read-carries-its-rows-existence-origin-supersedes-d-021),
[D-036](../DECISIONS.md#d-036-point-reads-of-a-trusted-ticket-id-keep-the-existence-taint-t08-hypothesis-rejected),
[D-064](../DECISIONS.md#d-064-the-existence-origin-is-asserted-again-2026-11-02-gate-3-finding-4-issue-4);
`kernel/tools/database.py`; `tests/test_point_read_existence.py`, `tests/test_existence_origin.py`.
