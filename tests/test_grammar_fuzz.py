"""The grammar-based plan generator (D-053): every plan it produces is well
typed, and over many draws it covers every tool and construct of the grammar."""

from collections import Counter
from typing import Any

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from kernel.plan_lang import check_plan, parse_plan
from kernel.tools.registry import TOOLS
from planners.fuzz import PROBE_TICKET, SECOND_TICKET, _order_ids, worlds
from planners.grammar_fuzz import constructs, grammar_plan, pools

seen: Counter[str] = Counter()


@settings(max_examples=600, derandomize=True, suppress_health_check=list(HealthCheck))
@given(st.data())
def _generate(data: Any) -> None:
    world = data.draw(worlds())
    tickets = sorted({t.id for t in world.tickets} | {PROBE_TICKET, SECOND_TICKET})
    p = data.draw(st.composite(lambda d: grammar_plan(d, pools(_order_ids(world), tickets)))())
    check_plan(parse_plan(p))  # raises PlanRejected on any ill-typed plan
    seen.update(constructs(p["steps"]))


def test_grammar_plans_typecheck_and_cover_the_grammar() -> None:
    seen.clear()
    _generate()
    expected = {f"call {t}" for t in TOOLS}
    expected |= {f"op {o}" for o in ("add", "sub", "min", "max", "len", "at", "contains")}
    expected |= {f"op {o}" for o in ("eq", "ne", "lt", "le", "gt", "ge", "and", "or", "not")}
    expected |= {"map at depth 1", "map at depth 2", "filter at depth 1", "filter at depth 2"}
    expected |= {"field path", "bound expression", "consequential call under map"}
    assert expected <= set(seen), sorted(expected - set(seen))
