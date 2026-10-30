"""Attacker-plan planner: a hijacked planner that does no text parsing (D-052).

The gullible planner obeys only the phrasings it was scripted for, so on
injections written by someone else it mostly measures its own text matching
(F-3). This planner instead emits the operator's correct plan plus a
structured attack plan written for the injection task by an independent agent
(``evals/tasks/*/attack_plans.py``), or the attack plan alone when the payload
tells the agent to drop the operator's work. It never reads its input, so
under Warrant's isolation it is not a model of anything; it is run only where
the attacker controls the planner's context (undefended, leaked context).
"""

from typing import Any

from evals.tasks import AttackPlan
from planners.builders import Json, plan


class AttackerPlanner:
    def __init__(self, base_plan: Json, attack: AttackPlan | None) -> None:
        self._base = base_plan
        self._attack = attack

    def plan(self, planner_input: Any) -> Json:
        if self._attack is None:
            return self._base
        if self._attack.replaces_user_plan:
            return plan(*self._attack.steps)
        return plan(*self._base["steps"], *self._attack.steps)
