"""Plan language parsing and static checking (DESIGN §4). Written before the checker."""

import json
from typing import Any

import pytest

from kernel.plan_lang import PlanRejected, check_plan, parse_plan, plan_json_schema

TICKET_42_REFUND: dict[str, Any] = {
    "version": 1,
    "steps": [
        {"let": "t", "call": "read_ticket", "args": {"ticket_id": {"lit": 42}}},
        {
            "expr": {
                "map": {
                    "over": {"ref": "t"},
                    "as": "tk",
                    "steps": [
                        {
                            "let": "oids",
                            "call": "extract_order_ids",
                            "args": {"text": {"ref": "tk", "path": ["body"]}},
                        },
                        {
                            "expr": {
                                "map": {
                                    "over": {"ref": "oids"},
                                    "as": "o",
                                    "steps": [
                                        {
                                            "let": "amt",
                                            "call": "compute_refund_amount",
                                            "args": {"order_id": {"ref": "o"}},
                                        },
                                        {
                                            "call": "issue_refund",
                                            "args": {
                                                "ticket_id": {"lit": 42},
                                                "order_id": {"ref": "o"},
                                                "amount": {"ref": "amt"},
                                            },
                                        },
                                    ],
                                }
                            }
                        },
                    ],
                }
            }
        },
    ],
}


def _plan(*steps: dict[str, Any]) -> dict[str, Any]:
    return {"version": 1, "steps": list(steps)}


def _rejected(raw: dict[str, Any], fragment: str) -> None:
    with pytest.raises(PlanRejected) as info:
        check_plan(parse_plan(raw))
    assert fragment in str(info.value), str(info.value)


def test_canonical_example_checks() -> None:
    check_plan(parse_plan(TICKET_42_REFUND))


def test_parse_rejects_unknown_keys_and_float_money() -> None:
    with pytest.raises(PlanRejected):
        parse_plan(_plan({"let": "x", "expr": {"lit": 1}, "eval": "boom"}))
    with pytest.raises(PlanRejected):
        parse_plan(_plan({"let": "x", "expr": {"lit": 1.5}}))
    with pytest.raises(PlanRejected):
        parse_plan({"version": 2, "steps": [{"expr": {"lit": 1}}]})


def test_unknown_tool() -> None:
    _rejected(_plan({"call": "delete_everything", "args": {}}), "unknown tool")


def test_unbound_reference() -> None:
    _rejected(_plan({"let": "x", "expr": {"ref": "nope"}}), "unbound")


def test_names_cannot_be_rebound_or_shadowed() -> None:
    _rejected(_plan({"let": "x", "expr": {"lit": 1}}, {"let": "x", "expr": {"lit": 2}}), "bound")
    shadow = _plan(
        {"let": "t", "call": "read_ticket", "args": {"ticket_id": {"lit": 1}}},
        {"expr": {"filter": {"over": {"ref": "t"}, "as": "t", "where": {"lit": True}}}},
    )
    _rejected(shadow, "bound")


def test_missing_and_extra_arguments() -> None:
    _rejected(_plan({"call": "read_ticket", "args": {}}), "missing argument")
    extra = {"ticket_id": {"lit": 1}, "force": {"lit": True}}
    _rejected(_plan({"call": "read_ticket", "args": extra}), "unexpected argument")


def test_id_kinds_do_not_mix() -> None:
    plan = _plan(
        {"let": "t", "call": "read_ticket", "args": {"ticket_id": {"lit": 1}}},
        {
            "expr": {
                "map": {
                    "over": {"ref": "t"},
                    "as": "tk",
                    "steps": [
                        {
                            "call": "issue_refund",
                            "args": {
                                "ticket_id": {"lit": 1},
                                "order_id": {"ref": "tk", "path": ["customer_id"]},
                                "amount": {"lit": 100},
                            },
                        }
                    ],
                }
            }
        },
    )
    _rejected(plan, "expected Id[Order]")


def test_consequential_result_cannot_be_bound() -> None:
    args = {"ticket_id": {"lit": 1}, "order_id": {"lit": 2}, "amount": {"lit": 3}}
    _rejected(_plan({"let": "r", "call": "issue_refund", "args": args}), "Unit")


def test_unknown_field_path() -> None:
    plan = _plan(
        {"let": "t", "call": "read_ticket", "args": {"ticket_id": {"lit": 1}}},
        {"let": "x", "expr": {"ref": "t", "path": ["body"]}},
    )
    _rejected(plan, "no field")


def test_filter_predicate_must_be_bool() -> None:
    plan = _plan(
        {"let": "t", "call": "read_ticket", "args": {"ticket_id": {"lit": 1}}},
        {"expr": {"filter": {"over": {"ref": "t"}, "as": "x", "where": {"lit": 3}}}},
    )
    _rejected(plan, "expected Bool")


def test_nesting_depth_is_bounded() -> None:
    def nested(levels: int) -> dict[str, Any]:
        inner: dict[str, Any] = {"lit": True}
        for i in range(levels):
            inner = {"map": {"over": {"ref": "t"}, "as": f"m{i}", "steps": [{"expr": inner}]}}
        return _plan(
            {"let": "t", "call": "read_ticket", "args": {"ticket_id": {"lit": 1}}},
            {"expr": inner},
        )

    check_plan(parse_plan(nested(2)))
    _rejected(nested(3), "nesting")


def test_filter_predicate_cannot_call_tools() -> None:
    body = [{"call": "compute_refund_amount", "args": {"order_id": {"lit": 1}}}]
    where = {
        "op": "eq",
        "args": [
            {"op": "len", "args": [{"map": {"over": {"ref": "t"}, "as": "y", "steps": body}}]},
            {"lit": 1},
        ],
    }
    plan = _plan(
        {"let": "t", "call": "read_ticket", "args": {"ticket_id": {"lit": 1}}},
        {"expr": {"filter": {"over": {"ref": "t"}, "as": "x", "where": where}}},
    )
    _rejected(plan, "predicate")


def test_step_count_is_bounded() -> None:
    steps = [{"let": f"x{i}", "expr": {"lit": i}} for i in range(65)]
    _rejected(_plan(*steps), "too many steps")


def test_operator_types_and_arity() -> None:
    _rejected(_plan({"let": "x", "expr": {"op": "add", "args": [{"lit": 1}]}}), "arity")
    _rejected(_plan({"let": "x", "expr": {"op": "and", "args": [{"lit": 1}, {"lit": 2}]}}), "Bool")


def test_json_schema_exports() -> None:
    schema = plan_json_schema()
    assert json.loads(json.dumps(schema))["title"] == "Plan"
