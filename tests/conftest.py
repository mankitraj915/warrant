"""Test-wide configuration: network blocking and Hypothesis profiles.

Network access is blocked when this conftest is registered (before any test
module is imported), so neither imports nor tests can open outbound sockets.

Hypothesis runs derandomized under the default ``check`` profile so
``make check`` is reproducible. Set ``HYPOTHESIS_PROFILE=fuzz`` for long runs.
"""

import os
import socket
from typing import NoReturn

from hypothesis import settings


class NetworkAccessError(RuntimeError):
    """Raised when code under test attempts network access."""


def _refuse(*_args: object, **_kwargs: object) -> NoReturn:
    raise NetworkAccessError("network access is disabled during tests")


def _block_network() -> None:
    socket.socket.connect = _refuse  # type: ignore[method-assign,assignment]
    socket.socket.connect_ex = _refuse  # type: ignore[method-assign,assignment]
    socket.socket.sendto = _refuse  # type: ignore[method-assign,assignment]
    socket.create_connection = _refuse  # type: ignore[assignment]
    socket.getaddrinfo = _refuse  # type: ignore[assignment]


def pytest_configure() -> None:
    _block_network()


settings.register_profile("check", derandomize=True, deadline=None, print_blob=True)
settings.register_profile("fuzz", max_examples=50_000, deadline=None, print_blob=True)
settings.load_profile(os.environ.get("HYPOTHESIS_PROFILE", "check"))
