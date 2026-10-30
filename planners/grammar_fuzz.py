"""Grammar-based random plans for non-interference fuzzing (Phase 3, D-053).

The fixed shapes in ``planners.fuzz`` target known laundering patterns; this
generator instead derives arbitrary well-typed plans from the plan grammar
(DESIGN §4) and the tool registry, so the fuzzer also samples plans nobody
thought of. It is type-directed: every expression is generated for an expected
type from what is in scope (bound names, record fields), literals from small
per-type pools, and operators whose result has that type. Bounds: ``map``/
``filter`` nesting up to ``MAX_DEPTH``, at most ``STEP_BUDGET`` steps,
expressions at most ``EXPR_DEPTH`` operators deep. Every generated plan passes
the static checker (``tests/test_grammar_fuzz.py``).

``constructs(plan)`` names the grammar constructs a plan uses, for the
per-construct coverage counts in Hypothesis's statistics output.
"""

from collections.abc import Callable, Sequence
from itertools import count
from typing import Any

from hypothesis import strategies as st

from kernel.plan_lang import MAX_DEPTH
from kernel.tools.registry import (
    BOOL,
    CREDIT_REASONS,
    INT,
    MONEY,
    RECORDS,
    RESOLUTIONS,
    STR,
    TOOLS,
    TId,
    TList,
    TRec,
    Type,
    contains_unit,
    is_scalar,
)
from planners.builders import Json, call, expr, filter_, lit, map_, op, plan, ref

Draw = Callable[[st.SearchStrategy[Any]], Any]
Scope = dict[str, Type]

STEP_BUDGET = 40  # well under the checker's MAX_STEPS (64)
EXPR_DEPTH = 2
# Statement-level tool weights: consequential calls are frequent, so random plans
# often act on what they read.
TOOL_WEIGHTS = {
    "read_ticket": 3,
    "query_orders": 2,
    "compute_refund_amount": 2,
    "extract_order_ids": 2,
    "incident_orders": 1,
    "order_stats": 1,
    "issue_refund": 4,
    "issue_credit": 2,
    "close_ticket": 2,
}
_NUMERIC_OPS = ("add", "sub", "min", "max")
_COMPARISONS = ("lt", "le", "gt", "ge", "eq", "ne")


class _Generator:
    def __init__(self, draw: Draw, pools: dict[str, Sequence[Any]]) -> None:
        self.draw = draw
        self.pools = pools
        self.steps = 0
        self._names = count()

    def name(self) -> str:
        return f"g{next(self._names)}"

    def choose(self, options: Sequence[Any]) -> Any:
        return self.draw(st.sampled_from(list(options)))

    # --- blocks and steps ----------------------------------------------------------

    def block(self, scope: Scope, depth: int, size: int) -> tuple[list[Json], Type | None]:
        """Up to ``size`` steps in a new scope; returns them and the last step's type
        (None for Unit)."""
        scope = dict(scope)
        steps: list[Json] = []
        last: Type | None = None
        for _ in range(size):
            if self.steps >= STEP_BUDGET and steps:
                break
            self.steps += 1
            step, last = self.step(scope, depth)
            steps.append(step)
        return steps, last

    def step(self, scope: Scope, depth: int) -> tuple[Json, Type | None]:
        lists = self.lists(scope)
        kinds = ["call"] * 4
        if lists and depth < MAX_DEPTH and self.steps < STEP_BUDGET:
            kinds += ["map"] * 3 + ["filter"] * 2
        if lists:
            kinds += ["list_op"]
        kind = self.choose(kinds)
        if kind == "call":
            return self.call_step(scope, depth)
        if kind == "map":
            return self.map_step(scope, depth, lists)
        if kind == "filter":
            return self.filter_step(scope, depth, lists)
        return self.list_op_step(scope, lists)

    def bind(self, scope: Scope, t: Type, always: bool = False) -> str | None:
        if contains_unit(t) or not (always or self.draw(st.integers(0, 4)) > 0):
            return None
        name = self.name()
        scope[name] = t
        return name

    def call_step(self, scope: Scope, depth: int) -> tuple[Json, Type | None]:
        tools = [n for n, w in TOOL_WEIGHTS.items() for _ in range(w)]
        spec = TOOLS[self.choose(tools)]
        args = {p: self.arg(scope, p, t) for p, t in spec.params}
        if contains_unit(spec.result):
            return call(spec.name, **args), None
        return call(spec.name, self.bind(scope, spec.result), **args), spec.result

    def map_step(self, scope: Scope, depth: int, lists: list[tuple[Json, TList]]) -> Any:
        over, t = self.over(scope, lists)
        binder = self.name()
        body, last = self.block({**scope, binder: t.item}, depth + 1, self.choose([1, 2, 2, 3]))
        e = map_(over, binder, *body)
        if last is None:
            return expr(e), None
        result = TList(last)
        return expr(e, self.bind(scope, result)), result

    def filter_step(self, scope: Scope, depth: int, lists: list[tuple[Json, TList]]) -> Any:
        over, t = self.over(scope, lists)
        binder = self.name()
        where = self.expr({**scope, binder: t.item}, BOOL, 0)
        return expr(filter_(over, binder, where), self.bind(scope, t, always=True)), t

    def list_op_step(self, scope: Scope, lists: list[tuple[Json, TList]]) -> Any:
        xs, t = self.choose(lists)
        if self.draw(st.booleans()):
            return expr(op("len", xs), self.bind(scope, INT, always=True)), INT
        return expr(op("at", xs, self.expr(scope, INT, 1)), self.bind(scope, t, always=True)), t

    def over(self, scope: Scope, lists: list[tuple[Json, TList]]) -> tuple[Json, TList]:
        xs, t = self.choose(lists)
        if self.draw(st.integers(0, 3)) == 0:  # sometimes iterate over one picked element
            return op("at", xs, self.expr(scope, INT, 1)), t
        return xs, t

    # --- expressions ---------------------------------------------------------------

    def lists(self, scope: Scope) -> list[tuple[Json, TList]]:
        return [
            (ref(n), t)
            for n, t in scope.items()
            if isinstance(t, TList) and not contains_unit(t.item)
        ]

    def refs(self, scope: Scope, t: Type) -> list[Json]:
        found = [ref(n) for n, u in scope.items() if u == t]
        for n, u in scope.items():
            if isinstance(u, TRec):
                found += [ref(n, f) for f, ft in RECORDS[u.name].items() if ft == t]
        return found

    def arg(self, scope: Scope, param: str, t: Type) -> Json:
        if param in ("resolution", "reason") and self.draw(st.integers(0, 3)) > 0:
            return lit(
                self.choose(sorted(RESOLUTIONS if param == "resolution" else CREDIT_REASONS))
            )
        return self.expr(scope, t, 0)

    def expr(self, scope: Scope, t: Type, depth: int) -> Json:
        refs = self.refs(scope, t)
        kinds = ["lit"] + ["ref"] * (3 if refs else 0)
        if depth < EXPR_DEPTH and t in (MONEY, INT):
            kinds += ["op"]
        if depth < EXPR_DEPTH and t == BOOL:
            kinds += ["op"] * 4  # predicates: mostly comparisons and connectives
        kind = self.choose(kinds)
        if kind == "ref":
            return self.choose(refs)  # type: ignore[no-any-return]
        if kind == "lit":
            return lit(self.choose(self.pools[str(t)]))
        if t == BOOL:
            return self.bool_op(scope, depth)
        lists = self.lists(scope)
        if t == INT and lists and self.draw(st.booleans()):
            return op("len", self.choose(lists)[0])
        return op(
            self.choose(_NUMERIC_OPS),
            self.expr(scope, t, depth + 1),
            self.expr(scope, t, depth + 1),
        )

    def bool_op(self, scope: Scope, depth: int) -> Json:
        # Numeric comparisons weighted up: they are what amount checks look like.
        candidates = (MONEY,) * 3 + (INT,) * 2 + (STR, TId("Order"), TId("Customer"), TId("Ticket"))
        scalars = [t for t in candidates if self.refs(scope, t)]
        lists = [(xs, t) for xs, t in self.lists(scope) if is_scalar(t.item)]
        kinds = (
            ["logic"] + (["compare"] * 3 if scalars else []) + (["contains"] * 2 if lists else [])
        )
        kind = self.choose(kinds)
        if kind == "compare":
            t = self.choose(scalars)
            ops = _COMPARISONS if t in (MONEY, INT) else ("eq", "ne")
            left = self.choose(self.refs(scope, t))
            return op(self.choose(ops), left, self.expr(scope, t, depth + 1))
        if kind == "contains":
            xs, t = self.choose(lists)
            return op("contains", xs, self.expr(scope, t.item, depth + 1))
        name = self.choose(["and", "or", "not"])
        if name == "not":
            return op("not", self.expr(scope, BOOL, depth + 1))
        return op(name, self.expr(scope, BOOL, depth + 1), self.expr(scope, BOOL, depth + 1))


def pools(order_ids: Sequence[int], ticket_ids: Sequence[int]) -> dict[str, Sequence[Any]]:
    """Literal pools per type: the world's ids plus ids that name nothing."""
    return {
        "Id[Order]": [*order_ids, 999_999],
        "Id[Ticket]": [*ticket_ids, 4999],
        "Id[Customer]": [100, 101, 1, 999],
        "Id[Incident]": [90, 91],
        "Money": [0, 1, 100, 10_000, 120_000, 450_000, 10**15],
        "Int": [-1, 0, 1, 2],
        "Bool": [True, False],
        "Str": ["", "delivered", "open", "Please refund order #7000.", "7001 7000", "TRUE"],
    }


def grammar_plan(draw: Draw, literal_pools: dict[str, Sequence[Any]]) -> Json:
    """One random well-typed plan of 1 to 6 top-level steps."""
    gen = _Generator(draw, literal_pools)
    steps, _ = gen.block({}, 0, draw(st.integers(1, 6)))
    return plan(*steps)


def constructs(node: Any, depth: int = 0) -> set[str]:
    """The grammar constructs a plan uses (tools, iteration and its depth, operators,
    field paths, consequential calls under iteration)."""
    found: set[str] = set()
    if isinstance(node, list):
        for item in node:
            found |= constructs(item, depth)
        return found
    if not isinstance(node, dict):
        return found
    if "call" in node:
        found.add(f"call {node['call']}")
        if depth and TOOLS[node["call"]].consequential:
            found.add("consequential call under map")
    if "op" in node:
        found.add(f"op {node['op']}")
    if node.get("path"):
        found.add("field path")
    if "let" in node and "expr" in node:
        found.add("bound expression")
    for key in ("map", "filter"):
        if key in node:
            found.add(f"{key} at depth {depth + 1}")
            found |= constructs(node[key]["over"], depth)
            inner = node[key]["steps"] if key == "map" else node[key]["where"]
            found |= constructs(inner, depth + 1)
            return found
    for value in node.values():
        found |= constructs(value, depth)
    return found
