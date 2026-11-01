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

from typing import Any

import kernel.execution

DETERMINISTIC_MUTANTS: dict[str, tuple[Any, str, Any]] = {
    # Gate 3 review #3: the between-effects re-check never stops the run.
    "re-check never stops": (
        kernel.execution,
        "_STRICTNESS",
        {"ALLOW": 0, "NEEDS_APPROVAL": 0, "BLOCK": 0},
    ),
}
