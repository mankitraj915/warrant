# 0009 Mutant detection is claimed over k independent seeds

## Context

A passing fuzz run says something only if the same fuzzer would fail on a broken kernel. So
each known way to break the kernel is kept as a mutant, and the harness must catch each one.
The question is how many examples are enough to claim that it does. Two budget rules were tried
and disproved:
- **`ln(1000)/p` examples**, from a per-example detection rate `p`. It assumes independent
  examples. Detections come in bursts within one seed, which is consistent with Hypothesis
  generating each example from earlier ones. So seeds with no detection in the budget did catch
  the mutant later.
- **`W + ln(1000)/p`** with a warm-up `W`. At the first fresh seed tested (202617002), the NI-5
  mutant was missed at its 8,000-example budget; its first detection was at 9,080.

## Decision

The independent unit is a seed: one fresh process with pinned generation. For each required
mutant there are k seeds of n examples, and the mutant is caught if any seed catches it
([D-058](../DECISIONS.md#d-058-mutant-detection-as-k-independent-seeds-owner-2026-11-01-final-redesign)):
- `q_low` is the exact one-sided 95% Clopper–Pearson lower bound on the per-seed catch rate,
  from the 8 measured seeds per mutant;
- `k` is the smallest value with `(1 - q_low)^k ≤ 1%`;
- `n` comes from a fixed grid and minimises k·n;
- k·n above 50,000, fixed before computing, would have been called a coverage gap.

The designs run at seeds that were not used to estimate `q`.

## Rejected alternatives

- **Pooling examples across seeds into one rate.** The bursts make its binomial bound wrong.
- **A Wilson bound.** With 8 of 8 it is close to Clopper–Pearson, which avoids arguing about
  approximations at small samples.
- **Measuring more seeds first to shrink k.** The design was declared final, and whatever the
  run showed would be reported as it was.

## Consequences

- With 8 seeds the best possible `q_low` is 0.688, so k ≥ 4 for every mutant. The largest
  design is NI-5's, k = 14 × 1,000 examples, because of the 202617002 seed.
- The 1% figure is an estimate. `n` was picked on the same seeds it is evaluated on, and the
  bound rests on 8 observations.
- `check` does not run the designs. It replays one measured detection per mutant (the
  witnesses); the designs run in owner-run stages and on CI.

## Evidence

[D-056](../DECISIONS.md#d-056-mutant-results-depended-on-process-state-clean-state-mutant-tests-split-ni-properties-2026-10-31),
[stage b results](../DECISIONS.md#phase-3-owner-run-stage-b-results-commit-c4b52a6-verified-2026-11-01),
[D-058](../DECISIONS.md#d-058-mutant-detection-as-k-independent-seeds-owner-2026-11-01-final-redesign),
[Gate 3 baseline](../DECISIONS.md#gate-3-baseline-stage-c-results-commit-7da1652-verified-2026-11-02)
(every required mutant caught at its design); `KSEED` in `tests/test_ni_mutants.py`;
`scripts/mutant_rates.py kseed`.
