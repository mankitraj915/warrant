"""Test-wide configuration: network blocking and Hypothesis profiles.

The network guard (evals/netguard.py) is installed when this conftest is
registered, before any test module is imported.

Hypothesis runs derandomized under the default ``check`` profile so
``scripts/tasks.py check`` is reproducible. ``HYPOTHESIS_PROFILE=fuzz`` (the
``fuzz`` target) runs long and randomized; ``WARRANT_FUZZ_EXAMPLES`` sets its
example count (default 20,000) so ``scripts/fuzz_chunks.py`` can run bounded chunks.
"""

import os
import sys
from pathlib import Path

from hypothesis import settings

from evals.netguard import NetworkAccessError, block_network

__all__ = ["NetworkAccessError"]


def pytest_configure() -> None:
    block_network()


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
    "check", max_examples=200, derandomize=True, deadline=None, print_blob=True
)
settings.register_profile(
    "fuzz",
    max_examples=int(os.environ.get("WARRANT_FUZZ_EXAMPLES", "20000")),
    deadline=None,
    print_blob=True,
)
settings.load_profile(os.environ.get("HYPOTHESIS_PROFILE", "check"))
