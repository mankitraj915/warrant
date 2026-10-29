"""Test-wide configuration: network blocking and Hypothesis profiles.

Network access is blocked by a ``sys.addaudithook`` installed when this
conftest is registered (before any test module is imported). Audit events are
raised by the C socket implementation, so the block also covers ``_socket``
and every Python wrapper. It cannot be uninstalled, and it does not reach
subprocesses.

Hypothesis runs derandomized under the default ``check`` profile so
``make check`` is reproducible. Set ``HYPOTHESIS_PROFILE=fuzz`` for long runs.
"""

import os
import sys

from hypothesis import settings

NETWORK_EVENTS = frozenset(
    {
        "socket.connect",  # also raised by connect_ex
        "socket.sendto",
        "socket.sendmsg",
        "socket.getaddrinfo",
        "socket.gethostbyname",
        "socket.gethostbyaddr",
        "socket.getnameinfo",
    }
)


class NetworkAccessError(RuntimeError):
    """Raised when code under test attempts network access."""


def _refuse_network(event: str, _args: tuple[object, ...]) -> None:
    if event in NETWORK_EVENTS:
        raise NetworkAccessError(f"network access is disabled during tests ({event})")


def pytest_configure() -> None:
    sys.addaudithook(_refuse_network)


settings.register_profile("check", derandomize=True, deadline=None, print_blob=True)
settings.register_profile("fuzz", max_examples=50_000, deadline=None, print_blob=True)
settings.load_profile(os.environ.get("HYPOTHESIS_PROFILE", "check"))
