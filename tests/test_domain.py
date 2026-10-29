"""Seed determinism (SPEC §4.9, §11) and payment-mock semantics."""

from pathlib import Path

import pytest

from domain.payment_mock import PaymentMock, ProviderTimeout
from domain.seed import generate, materialize


def _db_bytes(tmp_path: Path, name: str, seed: int) -> bytes:
    path = tmp_path / name
    materialize(generate(seed), path).close()
    return path.read_bytes()


def test_same_seed_gives_byte_identical_database(tmp_path: Path) -> None:
    assert _db_bytes(tmp_path, "a.db", 7) == _db_bytes(tmp_path, "b.db", 7)


def test_different_seeds_give_different_worlds() -> None:
    assert generate(7) != generate(8)


def test_generated_world_has_tickets_and_orders() -> None:
    world = generate(7)
    assert world.orders and world.tickets and world.payments


def test_invalid_utf8_can_be_stored_in_untrusted_text() -> None:
    world = generate(1)
    ticket = world.tickets[0]
    conn = materialize(world.replace_text("tickets", ticket.id, "body", b"\xff\xfe bad"))
    (body,) = conn.execute("SELECT body FROM tickets WHERE id = ?", (ticket.id,)).fetchone()
    assert body == b"\xff\xfe bad"


def test_mock_is_idempotent_per_key() -> None:
    mock = PaymentMock()
    first = mock.refund("refund:1:2", 1, 500)
    assert mock.refund("refund:1:2", 1, 500) == first
    assert len(mock.effects) == 1


def test_timeout_commits_nothing() -> None:
    mock = PaymentMock()
    mock.inject("timeout")
    with pytest.raises(ProviderTimeout):
        mock.refund("k", 1, 500)
    assert mock.effects == [] and mock.status("k") is None


def test_failure_after_commit_is_visible_through_status() -> None:
    mock = PaymentMock()
    mock.inject("fail_after_commit")
    with pytest.raises(ProviderTimeout):
        mock.refund("k", 1, 500)
    assert mock.status("k") is not None
    assert len(mock.effects) == 1


def test_duplicate_response_does_not_duplicate_effect() -> None:
    mock = PaymentMock()
    mock.inject("duplicate_response")
    ref = mock.refund("k", 1, 500)
    assert mock.refund("k", 1, 500) == ref
    assert len(mock.effects) == 1
