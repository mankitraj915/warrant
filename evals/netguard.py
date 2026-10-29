"""Process-wide network block via an audit hook (review finding 15).

Audit events are raised by the C socket layer, so the block covers ``_socket``
and every wrapper. It cannot be uninstalled and does not reach subprocesses.
Installed by tests/conftest.py and by the eval and fuzz entry points.
"""

import sys

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
    """Raised when code attempts network access while the guard is installed."""


def _refuse_network(event: str, _args: tuple[object, ...]) -> None:
    if event in NETWORK_EVENTS:
        raise NetworkAccessError(f"network access is disabled ({event})")


_installed = False


def block_network() -> None:
    """Install the guard once per process."""
    global _installed
    if not _installed:
        sys.addaudithook(_refuse_network)
        _installed = True
