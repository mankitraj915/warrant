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

from collections import Counter
from dataclasses import replace
from typing import Any

import evals.llm_score
import evals.tasks.dev
import evals.yardstick
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


_Accounted = evals.yardstick.Accounted


def _accounted_with(**changes: Any) -> Any:
    """``account`` builds its result last, so a mutant can change one field of it. Each value is
    a function of the fields ``account`` computed."""

    def build(**fields: Any) -> Any:
        return _Accounted(**{**fields, **{k: f(fields) for k, f in changes.items()}})

    return build


def _with_zero_amounts(after: Counter[Any], before: Counter[Any]) -> Counter[Any]:
    return after - before


def _ignoring_before(after: Counter[Any], before: Counter[Any]) -> Counter[Any]:
    return Counter({e: n for e, n in after.items() if e[0] == "closure" or e[3] != 0})


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
    # Gate B review, M1: accounting no calibration test noticed when it broke.
    "U ignores B": (
        evals.yardstick,
        "Accounted",
        _accounted_with(unauthorized=lambda f: f["strict"]),
    ),
    "rule-released ignores I and B": (
        evals.yardstick,
        "Accounted",
        _accounted_with(rule_released=lambda f: f["executed"] & f["released"]),
    ),
    "A is always empty": (
        evals.yardstick,
        "Accounted",
        _accounted_with(approved=lambda f: Counter()),
    ),
    "strict drops all-trusted effects": (
        evals.yardstick,
        "Accounted",
        _accounted_with(strict_trusted=lambda f: Counter()),
    ),
    "goodwill predicate always holds": (
        evals.yardstick,
        "_goodwill_holds",
        lambda pre, effect, run: True,
    ),
    "E keeps zero amounts": (evals.llm_score, "_added", _with_zero_amounts),
    "E ignores the initial state": (evals.llm_score, "_added", _ignoring_before),
    # Gate B review, M8: the pinned list of pairs whose attack plan is not Serving.
    "planned effects are empty": (evals.yardstick, "planned", lambda plan, world: Counter()),
}
