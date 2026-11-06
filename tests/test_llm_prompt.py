"""The fixed planner prompt is pre-registered (docs/SPEC_v1.1.md §3): any edit to it must
change the pinned hash, and so becomes a recorded deviation, never a silent one.

The checks keep the prompt neutral between configurations: its examples are valid plans in
the key order the grammar forces, they use no id from an evaluation fixture and no evaluation
request, and it says nothing about injections, either to defend against them or to invite them.
"""

import hashlib
import json
import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from evals.tasks import ATTACKER_CUSTOMER, ATTACKER_INCIDENT, ATTACKER_ORDER, ATTACKER_TICKET
from evals.tasks.dev import INJECTION_TASKS as DEV
from evals.tasks.dev import USER_TASKS
from evals.tasks.holdout import INJECTION_TASKS as HOLDOUT
from kernel.plan_lang import check_plan, parse_plan
from kernel.tools.registry import TOOLS

ROOT = Path(__file__).resolve().parent.parent
PROMPT = ROOT / "planners" / "prompts" / "plan_v1.txt"
PROMPT_SHA256 = "59b62fc1c6ff5c16463439639ef0d39970b9ebf5c0d3cbd0517a93f4a2fcf6b5"

# The order pinned llama-cpp-python's converter forces: required keys in schema order, then
# optional ones. "let" is optional and so comes last, after "args" or "expr".
KEY_ORDER = (
    ("version", "steps"),
    ("call", "args"),
    ("call", "args", "let"),
    ("expr",),
    ("expr", "let"),
    ("lit",),
    ("ref",),
    ("ref", "path"),
    ("op", "args"),
    ("map",),
    ("filter",),
    ("over", "as", "steps"),
    ("over", "as", "where"),
)
ID_ARGUMENTS = {"ticket_id", "order_id", "customer_id", "incident_id"}


def _text() -> str:
    return PROMPT.read_bytes().decode("utf-8")


def _examples() -> list[tuple[str, dict[str, Any]]]:
    pairs = re.findall(r"^Request: (.+)\nPlan: (.+)$", _text(), flags=re.M)
    return [(request, json.loads(plan)) for request, plan in pairs]


def _nodes(value: Any) -> Iterator[Any]:
    yield value
    if isinstance(value, dict):
        for child in value.values():
            yield from _nodes(child)
    elif isinstance(value, list):
        for child in value:
            yield from _nodes(child)


def test_the_prompt_bytes_are_pinned_here_and_in_the_spec() -> None:
    digest = hashlib.sha256(PROMPT.read_bytes()).hexdigest()
    assert digest == PROMPT_SHA256, "a prompt change is a recorded deviation (SPEC_v1.1 §3)"
    assert digest in (ROOT / "docs" / "SPEC_v1.1.md").read_text(encoding="utf-8")


def test_the_prompt_has_one_place_for_the_tool_signatures_and_no_carriage_returns() -> None:
    assert _text().count("@@SIGNATURES@@") == 1
    assert "\r" not in _text()


def test_every_example_is_a_valid_plan_that_uses_known_tools() -> None:
    examples = _examples()
    assert len(examples) == 5
    for _request, plan in examples:
        check_plan(parse_plan(plan))
        calls = [n["call"] for n in _nodes(plan) if isinstance(n, dict) and "call" in n]
        assert calls and all(call in TOOLS for call in calls)


def test_every_example_uses_the_key_order_the_grammar_forces() -> None:
    for _request, plan in _examples():
        for node in _nodes(plan):
            if isinstance(node, dict) and _is_plan_node(node):
                assert tuple(node) in KEY_ORDER, tuple(node)


def _is_plan_node(node: dict[str, Any]) -> bool:
    """Plan-language objects, leaving out the free-form ``args`` map of a call."""
    return bool(node.keys() & {"version", "call", "expr", "lit", "ref", "op", "map", "filter"}) or (
        "over" in node
    )


def test_the_examples_share_no_id_with_any_evaluation_fixture() -> None:
    known = {ATTACKER_CUSTOMER, ATTACKER_INCIDENT, ATTACKER_ORDER, ATTACKER_TICKET}
    for task in USER_TASKS:
        known |= {task.case_ticket}
        known |= {o.id for o in task.fixture.orders} | {o.customer_id for o in task.fixture.orders}
    used = {
        value["lit"]
        for _request, plan in _examples()
        for node in _nodes(plan)
        if isinstance(node, dict) and "call" in node
        for name, value in node["args"].items()
        if name in ID_ARGUMENTS and "lit" in value
    }
    assert used, "no literal ids found: the test is not looking at the examples"
    assert not used & known


def test_no_example_copies_an_evaluation_request() -> None:
    requests = {request for request, _plan in _examples()}
    assert not requests & {task.prompt for task in USER_TASKS}


def test_the_prompt_says_nothing_about_injections_either_way() -> None:
    words = r"inject|untrust|malicious|attack|ignore|instruction|disregard|suspicious|obey"
    assert not re.search(words, _text(), flags=re.I)


def test_no_task_or_payload_text_can_form_a_special_token() -> None:
    for task in USER_TASKS:
        assert "<|" not in task.prompt
        assert all("<|" not in t.body for t in task.fixture.tickets)
        for injection in (*DEV, *HOLDOUT):
            assert "<|" not in (injection.payload(task) or "")
