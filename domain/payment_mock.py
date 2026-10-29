"""In-process payment provider mock.

Honours idempotency keys: a repeated key returns the original reference and
creates no new effect. Supports one-shot injected failures:

- ``"timeout"``: the call fails before anything is committed;
- ``"fail_after_commit"``: the refund is committed, then the call fails
  (the caller must query ``status`` before retrying);
- ``"duplicate_response"``: the refund is committed and the response is
  delivered twice (the second ``refund`` call with the same key replays it).

``effects`` is the ground-truth log of money actually moved.
"""

from dataclasses import dataclass, field
from typing import Literal

Failure = Literal["timeout", "fail_after_commit", "duplicate_response"]


class ProviderTimeout(Exception):
    """The provider did not confirm the call."""


@dataclass(frozen=True)
class ProviderEffect:
    idempotency_key: str
    order_id: int
    amount: int
    provider_ref: str


@dataclass
class PaymentMock:
    effects: list[ProviderEffect] = field(default_factory=list)
    _refs: dict[str, str] = field(default_factory=dict)
    _next_failure: Failure | None = None

    def inject(self, failure: Failure) -> None:
        self._next_failure = failure

    def status(self, idempotency_key: str) -> str | None:
        """Provider reference for a committed key, or None."""
        return self._refs.get(idempotency_key)

    def refund(self, idempotency_key: str, order_id: int, amount: int) -> str:
        failure, self._next_failure = self._next_failure, None
        if failure == "timeout":
            raise ProviderTimeout(idempotency_key)
        if idempotency_key in self._refs:
            return self._refs[idempotency_key]
        ref = f"pay-{len(self.effects) + 1}"
        self.effects.append(ProviderEffect(idempotency_key, order_id, amount, ref))
        self._refs[idempotency_key] = ref
        if failure == "fail_after_commit":
            raise ProviderTimeout(idempotency_key)
        return ref
