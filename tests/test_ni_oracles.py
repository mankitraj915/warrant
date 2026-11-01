"""The NI oracles themselves (tests/ni_properties.py) reject what they must.

An oracle that misses a violation makes every property that uses it vacuous for
that violation. These tests hand an oracle a run result that breaks one
postcondition and require it to raise.
"""

import pytest

from domain.seed import Ticket, materialize
from kernel.interpreter import ResolvedAction
from kernel.policy import Verdict
from kernel.run import OPERATOR, RunResult
from kernel.values import Scalar
from planners.fuzz import CASE_CUSTOMER, CASE_TICKET, _case_world
from tests.ni_properties import GOODWILL, GOODWILL_AMOUNT, NIViolation, check_ni4


def _goodwill_credit(site: int, ticket: int) -> ResolvedAction:
    args = {
        "ticket_id": ticket,
        "customer_id": CASE_CUSTOMER,
        "amount": GOODWILL_AMOUNT,
        "reason": "goodwill",
    }
    return ResolvedAction(
        (site,), "issue_credit", {n: Scalar(v, OPERATOR) for n, v in args.items()}, OPERATOR
    )


def test_ni4_goodwill_oracle_counts_credits_per_customer_within_a_run() -> None:
    """Gate 3 review #6: the oracle checked the per-customer bound only against the
    state before the run, so two admitted credits to one customer in one run (on
    two of their tickets) passed NI-4."""
    world = _case_world(1, "in_transit").extend(
        tickets=(Ticket(4005, CASE_CUSTOMER, "late", "late"),)
    )
    pre = materialize(world)
    admitted = Verdict("ALLOW", "standard goodwill credit", GOODWILL)
    one = RunResult(
        "one", "executed", "", actions=(_goodwill_credit(0, CASE_TICKET),), verdicts=(admitted,)
    )
    check_ni4(one, pre)  # control: one credit meets the postcondition
    two = RunResult(
        "two",
        "executed",
        "",
        actions=(_goodwill_credit(0, CASE_TICKET), _goodwill_credit(1, 4005)),
        verdicts=(admitted, admitted),
    )
    with pytest.raises(NIViolation, match="more than one credit for the customer"):
        check_ni4(two, pre)
