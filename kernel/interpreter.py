"""Plan interpreter: resolves a checked plan into labelled actions (DESIGN §3, §5).

Only read tools and the extractor run here. Each consequential call becomes a
``ResolvedAction`` carrying its labelled arguments and its program-counter
label; nothing consequential happens until the policy has seen the whole set.

The four label rules below are module-level functions so that the mutant tests
(tests/test_ni_mutants.py) can break each one and check the NI harness notices.
Evaluation is total for checked plans: absence is an empty list, arithmetic
saturates, extractor failures yield no ids.
"""

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from itertools import islice

from .labels import Label, join
from .plan_lang import (
    LIT_BOUND,
    CallStep,
    Expr,
    ExprStep,
    FilterExpr,
    Lit,
    MapExpr,
    Op,
    Plan,
    Ref,
    Step,
)
from .tools.database import MAX_LIST, Database
from .tools.registry import TOOLS
from .values import UNIT_VALUE, ListV, Py, Record, Scalar, Value, plain, whole_label

MAX_EXTRACT = 5
Site = tuple[int, ...]
Extractor = Callable[[str], list[object]]


# --- label rules (DESIGN §3, §3.1) -------------------------------------------------


def body_pc(pc: Label, structure: Label) -> Label:
    """pc inside a map body: the list's structure decides how often it runs."""
    return join(pc, structure)


def filter_structure_label(over: Label, predicates: list[Label]) -> Label:
    """Every predicate label joins the structure: one drop shifts every index."""
    return join(over, *predicates)


def at_structure_label(structure: Label, index: Label) -> Label:
    return join(structure, index)


def extraction_label(text: Label) -> Label:
    """The extractor's output is as untrusted as its input, whatever it returns."""
    return text


# --- resolved actions ----------------------------------------------------------------


@dataclass(frozen=True)
class ResolvedAction:
    site: Site
    tool: str
    args: Mapping[str, Value]
    pc: Label

    def component_labels(self) -> dict[str, Label]:
        labels = {name: whole_label(v) for name, v in self.args.items()}
        labels["pc"] = self.pc
        return labels

    def canonical_args(self) -> dict[str, Py]:
        return {name: plain(v) for name, v in self.args.items()}


def _saturate(n: int) -> int:
    return max(-LIT_BOUND, min(LIT_BOUND, n))


def validated_ids(raw: object) -> list[int]:
    """Exact positive ints within bounds, at most MAX_EXTRACT (review finding 5)."""
    if not isinstance(raw, list):
        return []
    valid = (x for x in islice(raw, 1000) if type(x) is int and 0 < x <= LIT_BOUND)
    return list(islice(valid, MAX_EXTRACT))


class Interpreter:
    def __init__(self, db: Database, extractor: Extractor, plan_label: Label) -> None:
        self._db = db
        self._extractor = extractor
        self._plan_label = plan_label
        self.actions: list[ResolvedAction] = []

    def resolve(self, plan: Plan) -> list[ResolvedAction]:
        self._block(plan.steps, {}, self._plan_label, ())
        return self.actions

    def _block(
        self, steps: tuple[Step, ...], scope: dict[str, Value], pc: Label, site: Site
    ) -> Value:
        scope = dict(scope)
        last: Value = UNIT_VALUE
        for index, step in enumerate(steps):
            here = (*site, index)
            if isinstance(step, CallStep):
                last = self._call(step, scope, pc, here)
            else:
                assert isinstance(step, ExprStep)
                last = self._expr(step.expr, scope, pc, here)
            if step.let is not None:
                scope[step.let] = last
        return last

    def _call(self, step: CallStep, scope: dict[str, Value], pc: Label, site: Site) -> Value:
        args = {name: self._expr(e, scope, pc, site) for name, e in step.args.items()}
        spec = TOOLS[step.call]
        if spec.consequential:
            self.actions.append(ResolvedAction(site, spec.name, args, pc))
            return UNIT_VALUE
        if spec.name == "read_ticket":
            return self._db.read_ticket(_scalar(args["ticket_id"]))
        if spec.name == "query_orders":
            return self._db.query_orders(_scalar(args["customer_id"]))
        if spec.name == "compute_refund_amount":
            return self._db.compute_refund_amount(_scalar(args["order_id"]))
        assert spec.name == "extract_order_ids"
        return self._extract(_scalar(args["text"]))

    def _extract(self, text: Scalar) -> ListV:
        label = extraction_label(text.label)
        try:
            ids = validated_ids(self._extractor(str(text.value)))
        except Exception:  # the extractor is untrusted and may fail arbitrarily
            ids = []
        return ListV(tuple(Scalar(i, label) for i in ids), label)

    def _expr(self, e: Expr, scope: dict[str, Value], pc: Label, site: Site) -> Value:
        if isinstance(e, Lit):
            return Scalar(e.lit, self._plan_label)
        if isinstance(e, Ref):
            value = scope[e.ref]
            for name in e.path:
                assert isinstance(value, Record), "checked plans only take fields of records"
                value = value.field(name)
            return value
        if isinstance(e, Op):
            return self._op(e, [self._expr(a, scope, pc, site) for a in e.args])
        if isinstance(e, MapExpr):
            over = _list(self._expr(e.map.over, scope, pc, site))
            inner_pc = body_pc(pc, over.label)
            results = tuple(
                self._block(
                    e.map.steps, {**scope, e.map.as_: over.element(k)}, inner_pc, (*site, k)
                )
                for k in range(min(len(over.items), MAX_LIST))
            )
            return ListV(results, over.label)
        assert isinstance(e, FilterExpr)
        over = _list(self._expr(e.filter.over, scope, pc, site))
        items = over.items[:MAX_LIST]
        predicates = [
            _scalar(self._expr(e.filter.where, {**scope, e.filter.as_: over.element(k)}, pc, site))
            for k in range(len(items))
        ]
        structure = filter_structure_label(over.label, [p.label for p in predicates])
        kept = tuple(item for item, p in zip(items, predicates, strict=True) if p.value is True)
        return ListV(kept, structure)

    def _op(self, e: Op, args: list[Value]) -> Value:
        if e.op == "len":
            xs = _list(args[0])
            return Scalar(len(xs.items), xs.label)
        if e.op == "at":
            xs, i = _list(args[0]), _scalar(args[1])
            structure = at_structure_label(xs.label, i.label)
            index = int(i.value)
            picked = (xs.items[index],) if 0 <= index < len(xs.items) else ()
            return ListV(picked, structure)
        if e.op == "contains":
            xs, x = _list(args[0]), _scalar(args[1])
            found = any(plain(item) == x.value for item in xs.items)
            return Scalar(found, join(whole_label(xs), x.label))
        scalars = [_scalar(a) for a in args]
        label = join(*(s.label for s in scalars))
        values = [s.value for s in scalars]
        if e.op == "not":
            return Scalar(not values[0], label)
        a, b = values
        result: Py
        if e.op == "and":
            result = bool(a) and bool(b)
        elif e.op == "or":
            result = bool(a) or bool(b)
        elif e.op == "eq":
            result = a == b
        elif e.op == "ne":
            result = a != b
        else:
            m, n = int(a), int(b)
            result = {
                "lt": m < n,
                "le": m <= n,
                "gt": m > n,
                "ge": m >= n,
                "add": _saturate(m + n),
                "sub": _saturate(m - n),
                "min": min(m, n),
                "max": max(m, n),
            }[e.op]
        return Scalar(result, label)


def _scalar(v: Value) -> Scalar:
    assert isinstance(v, Scalar), "checked plans only pass scalars here"
    return v


def _list(v: Value) -> ListV:
    assert isinstance(v, ListV), "checked plans only pass lists here"
    return v
