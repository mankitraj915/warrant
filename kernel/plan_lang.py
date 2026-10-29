"""Plan language: JSON AST, JSON Schema export, and static checker (DESIGN §4).

A plan is data. ``parse_plan`` validates its shape, ``check_plan`` validates
names, types, tool names and bounds. Nothing runs before both succeed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Annotated, Any, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictInt,
    StrictStr,
    StringConstraints,
    ValidationError,
)

from .tools.registry import (
    BOOL,
    INT,
    MONEY,
    RECORDS,
    STR,
    TOOLS,
    UNIT,
    TId,
    TList,
    TRec,
    Type,
    contains_unit,
    is_scalar,
)

MAX_STEPS = 64
MAX_DEPTH = 2
LIT_BOUND = 10**15

Name = Annotated[str, StringConstraints(pattern=r"^[a-z_][a-z0-9_]{0,31}$")]
OpName = Literal[
    "eq", "ne", "lt", "le", "gt", "ge", "and", "or", "not",
    "add", "sub", "min", "max", "len", "at", "contains",
]  # fmt: skip
IntLit = Annotated[StrictInt, Field(ge=-LIT_BOUND, le=LIT_BOUND)]
StrLit = Annotated[StrictStr, Field(max_length=500)]


class PlanRejected(Exception):
    """The plan failed parsing or static checking; nothing was executed."""


class _Node(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)


class Lit(_Node):
    lit: StrictBool | IntLit | StrLit


class Ref(_Node):
    ref: Name
    path: tuple[Name, ...] = ()


class Op(_Node):
    op: OpName
    args: tuple[Expr, ...]


class MapSpec(_Node):
    over: Expr
    as_: Name = Field(alias="as")
    steps: tuple[Step, ...] = Field(min_length=1)


class MapExpr(_Node):
    map: MapSpec


class FilterSpec(_Node):
    over: Expr
    as_: Name = Field(alias="as")
    where: Expr


class FilterExpr(_Node):
    filter: FilterSpec


Expr = Lit | Ref | Op | MapExpr | FilterExpr


class CallStep(_Node):
    let: Name | None = None
    call: Annotated[str, StringConstraints(max_length=64)]
    args: dict[Name, Expr]


class ExprStep(_Node):
    let: Name | None = None
    expr: Expr


Step = CallStep | ExprStep


class Plan(_Node):
    version: Literal[1]
    steps: tuple[Step, ...] = Field(min_length=1)


for _model in (Op, MapSpec, MapExpr, FilterSpec, FilterExpr, CallStep, ExprStep, Plan):
    _model.model_rebuild()


def parse_plan(raw: Any) -> Plan:
    """Validate the JSON shape of a plan."""
    try:
        return Plan.model_validate(raw)
    except ValidationError as exc:
        raise PlanRejected(f"malformed plan: {exc}") from exc


def plan_json_schema() -> dict[str, Any]:
    """JSON Schema for plans, for grammar-constrained decoding."""
    return Plan.model_json_schema(by_alias=True)


# --- static checker -------------------------------------------------------------

_UNARY = {"not", "len"}
_NUMERIC = (INT, MONEY)


@dataclass
class _Ctx:
    bound: set[str] = field(default_factory=set)
    steps: int = 0


def check_plan(plan: Plan) -> None:
    """Reject ill-typed or out-of-bounds plans (raises ``PlanRejected``)."""
    _check_block(plan.steps, {}, _Ctx(), depth=0)


def _check_block(steps: tuple[Step, ...], scope: dict[str, Type], ctx: _Ctx, depth: int) -> Type:
    scope = dict(scope)
    last: Type = UNIT
    for step in steps:
        ctx.steps += 1
        if ctx.steps > MAX_STEPS:
            raise PlanRejected(f"too many steps (max {MAX_STEPS})")
        if isinstance(step, CallStep):
            last = _check_call(step, scope, ctx, depth)
        else:
            last = _check_expr(step.expr, scope, ctx, depth, None, pure=False)
        if step.let is not None:
            if contains_unit(last):
                raise PlanRejected(f"cannot bind {step.let!r}: a Unit result cannot be bound")
            _bind(step.let, last, scope, ctx)
    return last


def _bind(name: str, t: Type, scope: dict[str, Type], ctx: _Ctx) -> None:
    if name in ctx.bound:
        raise PlanRejected(f"name {name!r} is already bound (no rebinding or shadowing)")
    ctx.bound.add(name)
    scope[name] = t


def _check_call(step: CallStep, scope: dict[str, Type], ctx: _Ctx, depth: int) -> Type:
    spec = TOOLS.get(step.call)
    if spec is None:
        raise PlanRejected(f"unknown tool {step.call!r}")
    params = dict(spec.params)
    for name in sorted(params.keys() - step.args.keys()):
        raise PlanRejected(f"missing argument {name!r} to {spec.name}")
    for name in sorted(step.args.keys() - params.keys()):
        raise PlanRejected(f"unexpected argument {name!r} to {spec.name}")
    for name, expected in params.items():
        _check_expr(step.args[name], scope, ctx, depth, expected, pure=False)
    return spec.result


def _expect(t: Type, expected: Type | None, what: str) -> Type:
    if expected is not None and t != expected:
        raise PlanRejected(f"{what}: expected {expected}, got {t}")
    return t


def _check_expr(
    e: Expr, scope: dict[str, Type], ctx: _Ctx, depth: int, expected: Type | None, *, pure: bool
) -> Type:
    if isinstance(e, Lit):
        return _expect(_lit_type(e, expected), expected, f"literal {e.lit!r}")
    if isinstance(e, Ref):
        return _expect(_ref_type(e, scope), expected, f"reference {e.ref!r}")
    if isinstance(e, Op):
        return _expect(_op_type(e, scope, ctx, depth, expected, pure), expected, f"op {e.op}")
    if depth + 1 > MAX_DEPTH:
        raise PlanRejected(f"map/filter nesting deeper than {MAX_DEPTH}")
    if isinstance(e, MapExpr):
        if pure:
            raise PlanRejected("map is not allowed inside a filter predicate")
        item = _list_item(_check_expr(e.map.over, scope, ctx, depth, None, pure=pure), "map")
        body_scope = dict(scope)
        _bind(e.map.as_, item, body_scope, ctx)
        result = TList(_check_block(e.map.steps, body_scope, ctx, depth + 1))
        return _expect(result, expected, "map")
    over = _check_expr(e.filter.over, scope, ctx, depth, None, pure=pure)
    item = _list_item(over, "filter")
    body_scope = dict(scope)
    _bind(e.filter.as_, item, body_scope, ctx)
    _check_expr(e.filter.where, body_scope, ctx, depth + 1, BOOL, pure=True)
    return _expect(over, expected, "filter")


def _list_item(t: Type, what: str) -> Type:
    if not isinstance(t, TList) or contains_unit(t.item):
        raise PlanRejected(f"{what} needs a list of values, got {t}")
    return t.item


def _lit_type(e: Lit, expected: Type | None) -> Type:
    if isinstance(e.lit, bool):
        return BOOL
    if isinstance(e.lit, int):
        ok = expected in _NUMERIC or isinstance(expected, TId)
        return expected if ok and expected is not None else INT
    return STR


def _ref_type(e: Ref, scope: dict[str, Type]) -> Type:
    if e.ref not in scope:
        raise PlanRejected(f"unbound reference {e.ref!r}")
    t = scope[e.ref]
    for name in e.path:
        fields = RECORDS[t.name] if isinstance(t, TRec) else {}
        if name not in fields:
            raise PlanRejected(f"{t} has no field {name!r}")
        t = fields[name]
    return t


def _op_type(
    e: Op, scope: dict[str, Type], ctx: _Ctx, depth: int, expected: Type | None, pure: bool
) -> Type:
    arity = 1 if e.op in _UNARY else 2
    if len(e.args) != arity:
        raise PlanRejected(f"operator {e.op} arity: expected {arity} arguments")

    def check(x: Expr, want: Type | None) -> Type:
        return _check_expr(x, scope, ctx, depth, want, pure=pure)

    if e.op == "not":
        check(e.args[0], BOOL)
        return BOOL
    if e.op in ("and", "or"):
        check(e.args[0], BOOL)
        check(e.args[1], BOOL)
        return BOOL
    if e.op == "len":
        _list_item(check(e.args[0], None), "len")
        return INT
    if e.op == "at":
        lst = check(e.args[0], None)
        _list_item(lst, "at")
        check(e.args[1], INT)
        return lst
    if e.op == "contains":
        item = _list_item(check(e.args[0], None), "contains")
        if not is_scalar(item):
            raise PlanRejected(f"contains needs a list of scalars, got List[{item}]")
        check(e.args[1], item)
        return BOOL
    a, b = e.args
    numeric_result = e.op in ("add", "sub", "min", "max")
    if isinstance(a, Lit) and not isinstance(b, Lit):
        tb = check(b, expected if numeric_result else None)
        ta = check(a, tb)
    else:
        ta = check(a, expected if numeric_result else None)
        tb = check(b, ta)
    if e.op in ("eq", "ne"):
        if not is_scalar(ta):
            raise PlanRejected(f"{e.op} needs scalars, got {ta}")
        return BOOL
    if ta not in _NUMERIC:
        raise PlanRejected(f"{e.op} needs Int or Money, got {ta}")
    return BOOL if not numeric_result else ta
