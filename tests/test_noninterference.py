"""The headline test: non-interference under random and adversarial plans (SPEC §5).

For a plan P and two worlds that agree on every trusted cell and differ only in
attacker-controlled text, run P in both with a denying approver (Phase 1 has no
approval-execution path) and check NI-1..NI-4. Written before the interpreter.

Statistics (``--hypothesis-show-statistics``) report how often a rule was
consulted, how often projections were equal, and how often a run was suppressed,
so a vacuous pass is visible.
"""

from typing import Any

from hypothesis import event, given
from hypothesis import strategies as st

from planners.builders import Json
from planners.fuzz import mutated, plans, worlds
from tests.ni_properties import (
    check_ni1,
    check_ni2,
    check_ni3,
    check_ni4,
    effects,
    projection,
)
from tests.support import run_world


def ni_property(data: Any) -> None:
    world = data.draw(worlds(), label="world")
    plan: Json = data.draw(plans(world), label="plan")
    w1 = data.draw(mutated(world), label="E1")
    w2 = data.draw(mutated(world), label="E2")
    r1, p1, pre1 = run_world(plan, w1)
    r2, p2, pre2 = run_world(plan, w2)
    x1, x2 = effects(p1), effects(p2)

    consulted = bool(r1.rule_log or r2.rule_log)
    equal = projection(r1) == projection(r2)
    event(f"outcomes {r1.outcome}/{r2.outcome}")
    event(f"rule consulted={consulted} projection_equal={equal}")
    event(f"suppressed={bool(x1) != bool(x2)}")
    event(f"rule admitted={any(d.admitted for d in r1.rule_log + r2.rule_log)}")

    check_ni1(r1, r2)
    check_ni2(r1)
    check_ni2(r2)
    check_ni3(r1, x1, r2, x2)
    check_ni4(r1, pre1)
    check_ni4(r2, pre2)


@given(st.data())
def test_noninterference(data: Any) -> None:
    ni_property(data)
