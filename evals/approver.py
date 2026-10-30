"""Simulated approver for evaluation (SPEC §4.6, DECISIONS D-041).

It approves a request iff the requested actions, as ``(tool, canonical args)``,
are exactly the task's intended actions. It does not look at labels or
verdicts: it stands for a human who knows what the operator wanted and checks
the actions against that, nothing more. Every request is counted.
"""

from collections import Counter
from typing import Any

from evals.tasks import UserTask
from kernel.approval import Approval


class GroundTruthApprover:
    def __init__(self, task: UserTask) -> None:
        self._intended = task.intended_actions()
        self.requests = 0
        self.approved = 0

    def review(self, request: dict[str, Any], hash_: str) -> Approval | None:
        self.requests += 1
        asked = Counter((a["tool"], tuple(sorted(a["args"].items()))) for a in request["actions"])
        if asked != self._intended:
            return None
        self.approved += 1
        return Approval(request["run_id"], hash_)
