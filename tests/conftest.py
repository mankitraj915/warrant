"""Test-wide configuration: network blocking, Hypothesis profiles, marked mutants.

The network guard (evals/netguard.py) is installed when this conftest is
registered, before any test module is imported.

Hypothesis runs derandomized under the default ``check`` profile so
``scripts/tasks.py check`` is reproducible. ``HYPOTHESIS_PROFILE=fuzz`` (the
``fuzz`` target) runs long and randomized; ``WARRANT_FUZZ_EXAMPLES`` sets its
example count (default 20,000) so ``scripts/fuzz_chunks.py`` can run bounded chunks.

Neither profile uses an example database, so no run replays examples saved by an
earlier one, and generation is pinned to the seed alone (``tests/determinism.py``,
D-056): Hypothesis's pool of literals harvested from loaded modules is replaced by a
fixed empty one before any test runs.
"""

import os
import sys
from collections.abc import Iterator
from pathlib import Path

import pytest
from hypothesis import settings

from evals.netguard import NetworkAccessError, block_network
from tests.determinism import pin_generation

pin_generation()

__all__ = ["NetworkAccessError"]


def pytest_configure(config: pytest.Config) -> None:
    block_network()
    config.addinivalue_line(
        "markers",
        "harness_gap(mutant): covers already-correct code; must fail under the named"
        " mutant from tests/deterministic_mutants.py (D-063)",
    )


@pytest.fixture(autouse=True)
def _apply_marked_mutant(
    request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch
) -> Iterator[None]:
    """With ``WARRANT_MUTANT`` set, run each ``harness_gap`` test under its mutant
    (``*``: every marked test's own; a name: only tests marked with it, others skip)."""
    wanted = os.environ.get("WARRANT_MUTANT")
    marker = request.node.get_closest_marker("harness_gap")
    if wanted and marker is not None:
        from tests.deterministic_mutants import DETERMINISTIC_MUTANTS

        name = marker.args[0]
        if wanted not in ("*", name):
            pytest.skip(f"under mutant {wanted!r}; this test targets {name!r}")
        module, attribute, replacement = DETERMINISTIC_MUTANTS[name]
        monkeypatch.setattr(module, attribute, replacement)
    yield


def _peak_rss_mb() -> float:
    """Peak resident set of this process, in MB."""
    if sys.platform == "win32":
        import ctypes

        class Counters(ctypes.Structure):
            _fields_ = [("cb", ctypes.c_ulong), ("PageFaultCount", ctypes.c_ulong)] + [
                (name, ctypes.c_size_t)
                for name in (
                    "PeakWorkingSetSize",
                    "WorkingSetSize",
                    "QuotaPeakPagedPoolUsage",
                    "QuotaPagedPoolUsage",
                    "QuotaPeakNonPagedPoolUsage",
                    "QuotaNonPagedPoolUsage",
                    "PagefileUsage",
                    "PeakPagefileUsage",
                )
            ]

        counters = Counters()
        counters.cb = ctypes.sizeof(Counters)
        kernel32, psapi = ctypes.windll.kernel32, ctypes.windll.psapi
        kernel32.GetCurrentProcess.restype = ctypes.c_void_p  # a pointer-sized pseudo-handle
        psapi.GetProcessMemoryInfo.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_ulong]
        process = kernel32.GetCurrentProcess()
        if not psapi.GetProcessMemoryInfo(process, ctypes.byref(counters), counters.cb):
            return float("nan")
        return float(counters.PeakWorkingSetSize) / 2**20
    import resource

    return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024  # KB on Linux


def pytest_unconfigure() -> None:
    """Report peak RSS for scripts/fuzz_chunks.py when it asks for it."""
    path = os.environ.get("WARRANT_RSS_FILE")
    if path:
        Path(path).write_text(f"{_peak_rss_mb():.1f}")


settings.register_profile(
    "check", max_examples=200, derandomize=True, deadline=None, print_blob=True, database=None
)
settings.register_profile(
    "fuzz",
    max_examples=int(os.environ.get("WARRANT_FUZZ_EXAMPLES", "20000")),
    deadline=None,
    print_blob=True,
    database=None,
)
settings.load_profile(os.environ.get("HYPOTHESIS_PROFILE", "check"))
