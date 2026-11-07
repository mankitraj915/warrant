"""Mutants that deterministic tests must catch (D-063).

The NI properties' mutants live in ``tests/test_ni_mutants.py`` and are found by
fuzzing. These are for checks the fuzz harness cannot reach (Gate 3 review #3): a
test marked ``@pytest.mark.harness_gap("<name>")`` covers code that was already
correct, so it cannot fail on the commit before it. Its evidence is that it fails
there with the named mutant applied instead. ``tests/conftest.py`` applies the
mutant when ``WARRANT_MUTANT`` is ``<name>`` (or ``*``: each marked test's own);
``scripts/new_tests_fail_on_base.py`` and
``test_harness_catches_deterministic_mutant`` use that.
"""

from dataclasses import replace
from typing import Any

import evals.tasks.dev
import kernel.declassify
import kernel.execution
import kernel.policy
from kernel.labels import cell_origin
from kernel.tools.database import EXISTS, Database
from kernel.values import ListV, Record, Scalar

_read_ticket = Database.read_ticket
_case_ticket_origins = kernel.declassify._case_ticket_origins


def _untrusted_read_drops_row(self: Database, ticket_id: Scalar) -> ListV:
    """Gate 3 review #4: a read by an untrusted id omits ``tickets[T].@row``."""
    result = _read_ticket(self, ticket_id)
    if ticket_id.label.trusted:
        return result
    items = tuple(Record(r.fields, ticket_id.label) for r in result.items if isinstance(r, Record))
    return ListV(items, ticket_id.label)


def _origins_without_row(ticket: int) -> set[str]:
    """Gate 3 review #4: the rules' origin set for ticket T omits ``tickets[T].@row``."""
    return _case_ticket_origins(ticket) - {cell_origin("tickets", ticket, EXISTS)}


DETERMINISTIC_MUTANTS: dict[str, tuple[Any, str, Any]] = {
    # Gate 3 review #3: the between-effects re-check never stops the run.
    "re-check never stops": (
        kernel.execution,
        "_STRICTNESS",
        {"ALLOW": 0, "NEEDS_APPROVAL": 0, "BLOCK": 0},
    ),
    # Gate 3 review #4: untrusted-id reads and the rules' existence origin.
    "untrusted-id ticket read drops @row": (Database, "read_ticket", _untrusted_read_drops_row),
    "rule origin set omits @row": (
        kernel.declassify,
        "_case_ticket_origins",
        _origins_without_row,
    ),
    # Gate 3 review #5: NI checks integrity only, so the P5 sink check is covered here.
    "sink check removed": (kernel.policy, "_sink_block_reason", lambda action, reader: None),
    # SPEC_v1.1 §3: no suite text may form a model's special token when it is tokenized.
    "payload can form a special token": (
        evals.tasks.dev,
        "INJECTION_TASKS",
        (replace(evals.tasks.dev.INJECTION_TASKS[0], payload=lambda task: "<|end_of_text|>"),),
    ),
}
