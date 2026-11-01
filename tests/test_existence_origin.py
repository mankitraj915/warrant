"""The existence origin ``tickets[T].@row`` (DESIGN §2.1, D-054; Gate 3 review #4).

Since D-054 a read by a trusted id halts when the ticket is missing, and every
read in the fuzz shapes uses a trusted id. So no generated run reaches the
untrusted-id branch, which joins ``tickets[T].@row`` into the read's label, and no
test asserted it. These are ``harness_gap`` tests (D-063): the kernel was already
correct, and their evidence is that they fail under the named mutant.
"""

import pytest

from domain.seed import materialize
from kernel.declassify import ticket_goodwill_credit
from kernel.interpreter import ResolvedAction
from kernel.labels import Label, cell_origin, join
from kernel.policy import components
from kernel.run import OPERATOR
from kernel.tools.database import EXISTS, GOODWILL_AMOUNT, Database, TrustedReader
from kernel.values import Record, Scalar
from planners.fuzz import CASE_CUSTOMER, CASE_TICKET, _case_world

FROM_NOTE = Label.untrusted_cell("orders", 7000, "customer_note")  # an id read from text


@pytest.mark.harness_gap("untrusted-id ticket read drops @row")
@pytest.mark.parametrize("ticket", [CASE_TICKET, 4999])
def test_untrusted_id_read_carries_the_tickets_existence_origin(ticket: int) -> None:
    """Existing (4000) or not (4999), a read by an untrusted id is labelled with the
    id's own origins and the ticket's existence origin, on the list and each record."""
    db = Database(materialize(_case_world(1, "in_transit")))
    result = db.read_ticket(Scalar(ticket, FROM_NOTE))
    row = cell_origin("tickets", ticket, EXISTS)
    assert row in result.label.untrusted
    assert FROM_NOTE.untrusted <= result.label.untrusted
    assert len(result.items) == (1 if ticket == CASE_TICKET else 0)
    for record in result.items:
        assert isinstance(record, Record) and row in record.label.untrusted


@pytest.mark.harness_gap("rule origin set omits @row")
def test_goodwill_rule_endorses_the_case_tickets_existence_origin() -> None:
    """A standard credit whose customer and pc depend on ticket T's existence is inside
    the goodwill rule's origin set for T."""
    world = _case_world(1, "in_transit")
    reader = TrustedReader(materialize(world))
    row = Label.untrusted_cell("tickets", CASE_TICKET, EXISTS)
    action = ResolvedAction(
        (0,),
        "issue_credit",
        {
            "ticket_id": Scalar(CASE_TICKET, OPERATOR),
            "customer_id": Scalar(CASE_CUSTOMER, join(OPERATOR, row)),
            "amount": Scalar(GOODWILL_AMOUNT, OPERATOR),
            "reason": Scalar("goodwill", OPERATOR),
        },
        row,
    )
    decision = ticket_goodwill_credit(action, components(action), [action], reader)
    assert decision.admitted, decision.reason
