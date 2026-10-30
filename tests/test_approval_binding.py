"""NI-5, approval binding (DESIGN §7, §9.3). Written before approval execution.

With an approver that approves hash ``h``:
- the executed canonical set hashes to ``h``, or nothing executes;
- an approval issued in run ``r`` is rejected in any run ``r' != r`` and on a
  second use in ``r``.
Plus: a state change while the human is deciding aborts the run (re-check).
"""

from typing import Any

from hypothesis import event, given
from hypothesis import strategies as st

from domain.payment_mock import PaymentMock
from domain.seed import World, materialize
from kernel.approval import Approval, digest
from kernel.run import Environment, RunResult, run_plan
from planners.builders import Json, refund_from_ticket_text
from planners.fuzz import CASE_TICKET, _case_world, mutated, raw_extractor, sourced_plans, worlds
from tests.ni_properties import NIViolation, coverage_events, effects


class ApproveAll:
    """Approves whatever it is shown, and remembers what it approved."""

    def __init__(self) -> None:
        self.seen: list[tuple[dict[str, Any], str]] = []

    def review(self, request: dict[str, Any], hash_: str) -> Approval | None:
        self.seen.append((request, hash_))
        return Approval(request["run_id"], hash_)


class DenyAndRecord(ApproveAll):
    def review(self, request: dict[str, Any], hash_: str) -> Approval | None:
        super().review(request, hash_)
        return None


class Replay:
    """Presents a fixed approval, whatever it is shown."""

    def __init__(self, approval: Approval) -> None:
        self.approval = approval

    def review(self, request: dict[str, Any], hash_: str) -> Approval | None:
        return self.approval


def _two_eligible() -> World:  # the ownership rule does not admit: approval needed
    return _case_world(1, "delivered").replace_text("tickets", CASE_TICKET, "body", "Refund #7001")


def _env(world: World, approver: Any) -> Environment:
    return Environment(materialize(world), PaymentMock(), raw_extractor, approver=approver)


def _paid(env: Environment) -> list[tuple[int, int]]:
    provider = env.provider
    assert isinstance(provider, PaymentMock)
    return [(e.order_id, e.amount) for e in provider.effects]


def test_approved_set_executes_exactly() -> None:
    approver = ApproveAll()
    env = _env(_two_eligible(), approver)
    r = run_plan(refund_from_ticket_text(CASE_TICKET), env, run_id="r-1")
    assert r.outcome == "executed" and r.approval_hash == approver.seen[0][1]
    [request] = [req for req, _ in approver.seen]
    assert _paid(env) == [(a["args"]["order_id"], a["args"]["amount"]) for a in request["actions"]]


def test_approval_for_another_hash_executes_nothing() -> None:
    env = _env(_two_eligible(), Replay(Approval("r-1", "0" * 64)))
    r = run_plan(refund_from_ticket_text(CASE_TICKET), env, run_id="r-1")
    assert r.outcome == "approval_invalid" and _paid(env) == []


def test_approval_naming_another_run_executes_nothing() -> None:
    """Even with the correct hash for this run's set, an approval issued for a
    different run id is rejected."""
    shown = DenyAndRecord()
    run_plan(refund_from_ticket_text(CASE_TICKET), _env(_two_eligible(), shown), run_id="r-B")
    [(_, hash_b)] = shown.seen
    env = _env(_two_eligible(), Replay(Approval("r-A", hash_b)))
    r = run_plan(refund_from_ticket_text(CASE_TICKET), env, run_id="r-B")
    assert r.outcome == "approval_invalid" and _paid(env) == []


def test_identical_set_in_a_new_run_needs_a_new_approval() -> None:
    approver = ApproveAll()
    world = _two_eligible()
    env_a = _env(world, approver)
    run_plan(refund_from_ticket_text(CASE_TICKET), env_a, run_id="r-A")
    approval_a = Approval("r-A", approver.seen[0][1])
    env_b = _env(world, Replay(approval_a))  # same actions, same hash, different run
    r = run_plan(refund_from_ticket_text(CASE_TICKET), env_b, run_id="r-B")
    assert r.outcome == "approval_invalid" and _paid(env_b) == []


def test_run_id_is_single_use() -> None:
    approver = ApproveAll()
    env = _env(_two_eligible(), approver)
    run_plan(refund_from_ticket_text(CASE_TICKET), env, run_id="r-1")
    env.approver = Replay(Approval("r-1", approver.seen[0][1]))
    again = run_plan(refund_from_ticket_text(CASE_TICKET), env, run_id="r-1")
    assert again.outcome == "rejected" and "run_id" in again.reason
    assert len(_paid(env)) == 1


def test_state_change_while_deciding_aborts() -> None:
    class ChangesStateThenApproves(ApproveAll):
        def __init__(self, env_ref: list[Environment]) -> None:
            super().__init__()
            self.env_ref = env_ref

        def review(self, request: dict[str, Any], hash_: str) -> Approval | None:
            db = self.env_ref[0].db  # meanwhile, someone refunds the order elsewhere
            db.execute(
                "INSERT INTO refunds (order_id, ticket_id, amount, idempotency_key,"
                " provider_ref) VALUES (7001, 4000, 1, 'elsewhere', 'pay-x')"
            )
            db.commit()
            return super().review(request, hash_)

    ref: list[Environment] = []
    env = _env(_two_eligible(), ChangesStateThenApproves(ref))
    ref.append(env)
    r = run_plan(refund_from_ticket_text(CASE_TICKET), env, run_id="r-1")
    assert r.outcome == "aborted" and _paid(env) == []


def _as_effects(actions: list[dict[str, Any]]) -> list[tuple[Any, ...]]:
    """The effects an approved action list would have, in ``effects`` order."""
    by_tool: dict[str, list[tuple[Any, ...]]] = {"issue_refund": [], "issue_credit": []}
    closed = []
    for a in actions:
        x = a["args"]
        if a["tool"] == "issue_refund":
            key = f"refund:{x['order_id']}:{x['ticket_id']}"
            by_tool["issue_refund"].append((x["order_id"], x["amount"], key))
        elif a["tool"] == "issue_credit":
            row = ("credit", x["ticket_id"], x["customer_id"], x["amount"], x["reason"])
            by_tool["issue_credit"].append(row)
        else:
            closed.append(("close", x["ticket_id"], x["resolution"]))
    return by_tool["issue_refund"] + by_tool["issue_credit"] + sorted(closed)


def _ni5(plan: Json, world: World) -> RunResult:
    approver = ApproveAll()
    env = _env(world, approver)
    r = run_plan(plan, env, run_id="ni5")
    provider = env.provider
    assert isinstance(provider, PaymentMock)
    done = effects(provider, env.db)
    if not approver.seen:
        return r
    request, hash_ = approver.seen[0]
    approved = _as_effects(request["actions"])
    if done and (done != approved or digest(request) != hash_):
        raise NIViolation(f"NI-5 executed {done} but approved {approved}")
    return r


def ni5_property(data: Any) -> None:
    world = data.draw(worlds(), label="world")
    source, plan = data.draw(sourced_plans(world), label="plan")
    coverage_events(source, plan)
    r = _ni5(plan, data.draw(mutated(world), label="E"))
    event(f"[{source}] halted={r.outcome == 'halted'}")


@given(st.data())
def test_ni5_executed_set_is_the_approved_set(data: Any) -> None:
    ni5_property(data)
