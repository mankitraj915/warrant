"""The ``fuzz`` profile must not depend on whether it runs on a CI runner (issue #52).

On a CI runner Hypothesis 6.170.13 loads its built-in ``ci`` profile at import, and that
profile sets ``derandomize=True``. A ``fuzz`` profile that inherits from it ignores
``--hypothesis-seed``, so every ``scripts/fuzz_chunks.py`` chunk runs the same examples
(GitHub Actions run 41429151228). Each check runs in a fresh interpreter, because the CI
profile is chosen when Hypothesis is imported.
"""

import json
import os
import subprocess
import sys
from pathlib import Path

from hypothesis._settings import _CI_VARS

ROOT = Path(__file__).resolve().parent.parent

# Loads tests/conftest.py's profile, then draws with each seed through the same hook
# ``--hypothesis-seed`` uses (``hypothesis.core.global_force_seed``).
_PROBE = """
import json, sys
import tests.conftest
from hypothesis import core, given, settings, strategies as st

def draws(seed):
    core.global_force_seed = seed
    seen = []

    @given(st.integers(0, 2**32))
    def probe(x):
        seen.append(x)

    probe()
    return seen

print(json.dumps({
    "profile": settings.get_current_profile_name(),
    "settings": repr(settings.default),
    "derandomize": settings.default.derandomize,
    "draws": [draws(int(s)) for s in sys.argv[1:]],
}))
"""


def _probe(*, ci: bool, seeds: tuple[int, ...] = ()) -> dict[str, object]:
    env = {k: v for k, v in os.environ.items() if k not in _CI_VARS}
    if ci:
        env.update(CI="true", GITHUB_ACTIONS="true")
    env.update(HYPOTHESIS_PROFILE="fuzz", WARRANT_FUZZ_EXAMPLES="20")
    done = subprocess.run(
        [sys.executable, "-c", _PROBE, *map(str, seeds)],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=True,
    )
    result: dict[str, object] = json.loads(done.stdout)
    assert result["profile"] == "fuzz"
    return result


def test_fuzz_profile_honours_the_seed_on_ci() -> None:
    result = _probe(ci=True, seeds=(202620100, 202620101))
    first, second = result["draws"]  # type: ignore[misc]
    assert first != second, "two seeds drew the same examples on CI: the seed is ignored"
    assert result["derandomize"] is False


def test_fuzz_profile_is_the_same_on_and_off_ci() -> None:
    assert _probe(ci=True)["settings"] == _probe(ci=False)["settings"]
