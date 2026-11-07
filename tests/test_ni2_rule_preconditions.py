"""NI-2 requires the components a rule must never endorse to be trusted (issue #70).

Both rules reject an untrusted ``ticket_id`` first, and the goodwill rule also an untrusted
``amount`` or ``reason``. ``check_ni2`` only compared endorsed origins with the case ticket's
set, so a rule that wrongly admitted an action on a tainted ticket id passed it (Gate A review
of v1.1, finding 1). With the planner's context leaked, every literal carries the case
ticket's origins, which is exactly such a case.
"""

from types import SimpleNamespace
from typing import Any

import pytest

from domain.payment_mock import PaymentMock
from domain.seed import materialize
from evals.approver import GroundTruthApprover
from evals.harness import attack_plan
from evals.tasks.dev import INJECTION_TASKS, USER_TASKS
from kernel.declassify import GOODWILL, RuleDecision, _case_ticket_origins
from kernel.labels import BOTTOM, Label
from kernel.policy import Verdict
from kernel.run import Environment, RunResult, run_task
from planners.attacker import AttackerPlanner
from planners.oracle import OraclePlanner
from quarantine.extractor import extract_order_ids
from tests.ni_properties import NIViolation, check_ni2
from tests.test_ni_mutants import MUTANTS

TASKS = {t.id: t for t in USER_TASKS}
INJECTIONS = {i.id: i for i in INJECTION_TASKS}


def _leaked_run(task_id: str, planner: Any, payload: str | None) -> RunResult:
    task = TASKS[task_id]
    env = Environment(
        db=materialize(task.world(payload)),
        provider=PaymentMock(),
        extractor=extract_order_ids,
        approver=GroundTruthApprover(task),
    )
    return run_task(
        task.id, task.prompt, planner, env, leak_ticket_bodies=(task.case_ticket,), run_id="ni2"
    )


def _attacked_refund(monkeypatch: pytest.MonkeyPatch) -> RunResult:
    module, attribute, replacement = MUTANTS["ownership rule ignores origin set"]
    monkeypatch.setattr(module, attribute, replacement)
    task, injection = TASKS["T23"], INJECTIONS["I1"]
    planner = AttackerPlanner(task.oracle, attack_plan(task, injection))
    return _leaked_run("T23", planner, injection.payload(task))


def test_ni2_rejects_a_refund_admitted_on_a_tainted_ticket(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run = _attacked_refund(monkeypatch)
    assert any(v.kind == "ALLOW" and v.rule for v in run.verdicts), "the mutant did not fire"
    with pytest.raises(NIViolation, match="ticket_id"):
        check_ni2(run)


def test_ni2_rejects_a_credit_admitted_on_tainted_components(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module, attribute, replacement = MUTANTS["goodwill rule ignores origin set"]
    monkeypatch.setattr(module, attribute, replacement)
    run = _leaked_run("T23", OraclePlanner(TASKS["T23"].oracle), None)
    assert any(v.kind == "ALLOW" and v.rule for v in run.verdicts), "the mutant did not fire"
    with pytest.raises(NIViolation, match="ticket_id"):
        check_ni2(run)


@pytest.mark.parametrize("name", ["amount", "reason"])
def test_ni2_rejects_goodwill_endorsing_a_tainted_amount_or_reason(name: str) -> None:
    """Built directly: the ticket id is trusted, and only this component is tainted, with an
    origin inside the case ticket's set."""
    labels = dict.fromkeys(("ticket_id", "customer_id", "amount", "reason", "pc"), BOTTOM)
    labels[name] = Label(untrusted=frozenset(_case_ticket_origins(4223)))
    action = SimpleNamespace(
        site=(0,),
        component_labels=lambda: labels,
        canonical_args=lambda: {"ticket_id": 4223},
    )
    run: Any = SimpleNamespace(
        actions=[action],
        verdicts=[Verdict("ALLOW", "admitted", GOODWILL)],
        rule_log=[RuleDecision(GOODWILL, (0,), True, "admitted")],
    )
    with pytest.raises(NIViolation, match=name):
        check_ni2(run)
