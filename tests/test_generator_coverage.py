"""The generators reach domain-valid untrusted values (issue #13).

Three Gate 3 held-out mutants went uncaught because untrusted fields were only
ever random text: never a valid credit reason or resolution, an existing ticket
id or a plausible amount, so code guarded by those checks was never reached with
untrusted data. These tests pin that each kind of input is now generated. They
say nothing about the held-out mutants themselves; that result is measured
separately, at fresh seeds, in the owner-run stage d.
"""

import json
from typing import Any

from hypothesis import find, settings

from kernel.tools.registry import CREDIT_REASONS, RESOLUTIONS
from planners.fuzz import _fuzz_world, payloads, plans

SEARCH = settings(derandomize=True, database=None, max_examples=5_000)
WORLD = _fuzz_world(1, "in_transit", second_ticket=True)


def _text(value: Any) -> str:
    return value if isinstance(value, str) else value.decode("utf-8", "replace")


def test_untrusted_text_can_be_a_credit_reason_or_a_resolution_code() -> None:
    for code in sorted(CREDIT_REASONS | RESOLUTIONS):
        assert find(payloads(WORLD), lambda t, c=code: t == c, settings=SEARCH) == code


def test_untrusted_text_can_name_an_existing_ticket_or_a_plausible_amount() -> None:
    ticket = find(payloads(WORLD), lambda t: "#4000" in _text(t), settings=SEARCH)
    amount = find(payloads(WORLD), lambda t: "#10000" in _text(t), settings=SEARCH)
    assert "#4000" in _text(ticket) and "#10000" in _text(amount)


def _calls(node: Any, tool: str) -> list[dict[str, Any]]:
    found = []
    if isinstance(node, dict):
        if node.get("call") == tool:
            found.append(node)
        for v in node.values():
            found += _calls(v, tool)
    elif isinstance(node, list):
        for v in node:
            found += _calls(v, tool)
    return found


def test_shapes_route_ticket_text_into_a_credit_reason() -> None:
    def reason_from_text(p: Any) -> bool:
        return any("ref" in c["args"]["reason"] for c in _calls(p, "issue_credit"))

    plan = find(plans(WORLD, "shapes"), reason_from_text, settings=SEARCH)
    assert reason_from_text(plan)


def test_grammar_tests_membership_in_a_list_of_untrusted_text() -> None:
    """A read mapped to one text field (trusted structure, untrusted elements), then
    ``contains`` over that list."""

    def membership(p: Any) -> bool:
        steps = p["steps"]
        if len(steps) < 2 or "map" not in steps[1].get("expr", {}):
            return False
        body = steps[1]["expr"]["map"]["steps"]
        name = steps[1].get("let")
        is_text_list = len(body) == 1 and '"path": [' in json.dumps(body[0])
        uses = f'"op": "contains", "args": [{{"ref": "{name}"' in json.dumps(p)
        return bool(name) and is_text_list and uses

    plan = find(plans(WORLD, "grammar"), membership, settings=SEARCH)
    assert membership(plan)
