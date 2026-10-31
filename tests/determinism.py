"""Make Hypothesis's examples a function of the seed alone (D-056).

Hypothesis (6.170.13, pinned in uv.lock) draws about 5% of integers and strings
from a pool of literals it harvests from every local, non-test module imported
so far in the process (``hypothesis.internal.conjecture.providers``). The same
seed then generates different examples depending on which modules the process
has loaded: the mutant test for "extraction ignores control" caught its mutant
when every test module was collected and missed it when run alone (D-056). That
makes a "caught" result depend on what else ran.

``pin_generation`` replaces the harvested pool with a fixed empty one; the
global constants Hypothesis ships with still apply, and they are the same in
every process. This patches a private name, so ``tests/test_determinism.py``
fails if Hypothesis changes it.
"""

from typing import Any

from hypothesis.internal.conjecture import providers
from sortedcontainers import SortedSet

EMPTY: Any = providers.Constants(
    integers=SortedSet(),
    floats=SortedSet(key=providers.float_to_int),
    bytes=SortedSet(),
    strings=SortedSet(),
)


def _no_local_constants() -> Any:
    return EMPTY


def pin_generation() -> None:
    providers._get_local_constants = _no_local_constants
    providers.CONSTANTS_CACHE.cache.clear()


def pinned() -> bool:
    return providers._get_local_constants is _no_local_constants and len(EMPTY) == 0
