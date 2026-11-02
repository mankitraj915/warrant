# Architecture decision records

One page each: the context, the decision, the alternatives rejected, the consequences and the
evidence. The full reasoning, with commands and measurements, is in
[DECISIONS.md](../DECISIONS.md); each record links its entries there.

| # | decision |
|---|---|
| [0001](0001-label-lattice.md) | Labels are sets of untrusted origins, allowed sinks and provenance |
| [0002](0002-declassification-as-endorsement.md) | Declassification endorses parts of one action; it never relabels a value |
| [0003](0003-atomic-runs.md) | A run's whole action set is decided and executed as one unit |
| [0004](0004-approval-binds-run-and-hash.md) | An approval binds one run id and the hash of the exact action set |
| [0005](0005-existence-taint.md) | A ticket read carries its row's existence as untrusted |
| [0006](0006-halt-on-missing-operator-ticket.md) | A missing operator-named ticket halts the whole run |
| [0007](0007-ownership-rule-residual-risk.md) | The ownership rule, and the triggering risk it keeps |
| [0008](0008-single-writer.md) | One writer per database, enforced by a run lock |
| [0009](0009-k-independent-seeds.md) | Mutant detection is claimed over k independent seeds |
| [0010](0010-held-out-attacks-and-mutants.md) | Attacks and mutants held out from the people who tune |
