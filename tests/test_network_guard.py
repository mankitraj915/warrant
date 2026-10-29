"""The test suite must not be able to open network connections (SPEC §11)."""

import _socket
import socket

import pytest
from conftest import NetworkAccessError


def test_create_connection_is_refused() -> None:
    with pytest.raises(NetworkAccessError):
        socket.create_connection(("127.0.0.1", 9), timeout=1)


def test_raw_socket_connect_is_refused() -> None:
    with (
        socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s,
        pytest.raises(NetworkAccessError),
    ):
        s.connect(("127.0.0.1", 9))


def test_udp_sendto_is_refused() -> None:
    with (
        socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s,
        pytest.raises(NetworkAccessError),
    ):
        s.sendto(b"x", ("127.0.0.1", 9))


def test_name_resolution_is_refused() -> None:
    with pytest.raises(NetworkAccessError):
        socket.getaddrinfo("example.com", 80)


def test_gethostbyname_is_refused() -> None:
    with pytest.raises(NetworkAccessError):
        socket.gethostbyname("localhost")


def test_c_level_socket_connect_is_refused() -> None:
    # Bypasses any patch on the Python-level socket.socket class.
    s = _socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        with pytest.raises(NetworkAccessError):
            s.connect_ex(("127.0.0.1", 9))
    finally:
        s.close()
