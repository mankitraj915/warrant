"""Test-wide configuration: network blocking and Hypothesis profiles.

The network guard (evals/netguard.py) is installed when this conftest is
registered, before any test module is imported.

Hypothesis runs derandomized under the default ``check`` profile so
``scripts/tasks.py check`` is reproducible. ``HYPOTHESIS_PROFILE=fuzz`` (the
``fuzz`` target) runs long and randomized.
"""

import os

from hypothesis import settings

from evals.netguard import NetworkAccessError, block_network

__all__ = ["NetworkAccessError"]


def pytest_configure() -> None:
    block_network()


settings.register_profile(
    "check", max_examples=200, derandomize=True, deadline=None, print_blob=True
)
settings.register_profile("fuzz", max_examples=20_000, deadline=None, print_blob=True)
settings.load_profile(os.environ.get("HYPOTHESIS_PROFILE", "check"))
