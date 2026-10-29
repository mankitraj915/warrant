"""The test suite must not be able to open network connections (SPEC §11)."""

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
