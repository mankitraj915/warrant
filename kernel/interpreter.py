"""Plan interpreter: resolves a checked plan into labelled actions (DESIGN §3, §5).

Only read tools and the extractor run here. Each consequential call becomes a
``ResolvedAction`` carrying its labelled arguments and its program-counter
label; nothing consequential happens until the policy has seen the whole set.

The four label rules below are module-level functions so that the mutant tests
(tests/test_ni_mutants.py) can break each one and check the NI harness notices.
Evaluation is total for checked plans: absence is an empty list, arithmetic
saturates, extractor failures yield no ids.
"""

import unicodedata
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from itertools import islice

from .labels import BOTTOM, Label, join
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
# Sites are paths: step indices and map iterations are >= 0; a negative entry
# -(i + 1) is the i-th argument of a call or op (or -1, a map/filter source), so
# two maps inside one expression never share a site (Gate 1 review #5).


# --- label rules (DESIGN §3, §3.1) -------------------------------------------------


def body_pc(pc: Label, structure: Label) -> Label:
    """pc inside a map body: the list's structure decides how often it runs."""
    return join(pc, structure)


def filter_structure_label(over: Label, predicates: list[Label]) -> Label:
    """Every predicate label joins the structure: one drop shifts every index."""
    return join(over, *predicates)


def at_structure_label(structure: Label, index: Label) -> Label:
    return join(structure, index)


def extraction_label(text: Label, seen: Label) -> Label:
    """The extractor's output is as untrusted as its input, whatever it returns,
    and as every earlier input of this run: an extractor with memory must not
    turn untrusted ids into trusted ones (Gate 1 review #4). ``seen`` joins the
    labels of all texts already passed to the extractor in this run, and the
    control context of every extraction call (Gate 2 review #1-2)."""
    return join(text, seen)


# Extension point for the mutant tests; always True in use. False restores the
# pre-Gate-2 behaviour: ``seen`` joins only text labels, and only for extractions
# that actually run, so its trust depended on data (NI-1) and an extractor that
# counts calls under a tainted pc could choose a "trusted" id (invariant).
EXTRACTION_FOLLOWS_CONTROL = True


def _extracts(steps: tuple[Step, ...]) -> bool:
    """Whether a block syntactically contains an extraction call (at any depth)."""
    return any(
        (isinstance(s, CallStep) and s.call == "extract_order_ids")
        or any(_expr_extracts(e) for e in (s.args.values() if isinstance(s, CallStep) else ()))
        or (isinstance(s, ExprStep) and _expr_extracts(s.expr))
        for s in steps
    )


def _expr_extracts(e: Expr) -> bool:
    if isinstance(e, MapExpr):
        return _expr_extracts(e.map.over) or _extracts(e.map.steps)
    if isinstance(e, FilterExpr):
        return _expr_extracts(e.filter.over) or _expr_extracts(e.filter.where)
    if isinstance(e, Op):
        return any(_expr_extracts(a) for a in e.args)
    return False


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
        self._extracted = BOTTOM
        self.actions: list[ResolvedAction] = []
        self.answer: Value = UNIT_VALUE  # the plan's final value, shown to the operator

    def resolve(self, plan: Plan) -> list[ResolvedAction]:
        self.answer = self._block(plan.steps, {}, self._plan_label, ())
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
        args = {
            name: self._expr(e, scope, pc, (*site, -(j + 1)))
            for j, (name, e) in enumerate(step.args.items())
        }
        spec = TOOLS[step.call]
        if spec.consequential:
            # Strings are NFC-normalised here, so the executed bytes are the hashed bytes.
            args = {
                name: Scalar(unicodedata.normalize("NFC", v.value), v.label)
                if isinstance(v, Scalar) and isinstance(v.value, str)
                else v
                for name, v in args.items()
            }
            self.actions.append(ResolvedAction(site, spec.name, args, pc))
            return UNIT_VALUE
        if spec.name == "read_ticket":
            return self._db.read_ticket(_scalar(args["ticket_id"]))
        if spec.name == "query_orders":
            return self._db.query_orders(_scalar(args["customer_id"]))
        if spec.name == "incident_orders":
            return self._db.incident_orders(_scalar(args["incident_id"]))
        if spec.name == "order_stats":
            return self._db.order_stats()
        if spec.name == "compute_refund_amount":
            return self._db.compute_refund_amount(_scalar(args["order_id"]))
        assert spec.name == "extract_order_ids"
        return self._extract(_scalar(args["text"]), pc)

    def _extract(self, text: Scalar, pc: Label) -> ListV:
        # The pc joins too: whether and how often the extractor is called is
        # state an extractor with memory can carry (Gate 2 review #1).
        context = join(text.label, pc) if EXTRACTION_FOLLOWS_CONTROL else text.label
        label = extraction_label(context, self._extracted)
        self._extracted = join(self._extracted, context)
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
            return self._op(
                e, [self._expr(a, scope, pc, (*site, -(i + 1))) for i, a in enumerate(e.args)]
            )
        if isinstance(e, MapExpr):
            over = _list(self._expr(e.map.over, scope, pc, (*site, -1)))
            inner_pc = body_pc(pc, over.label)
            if EXTRACTION_FOLLOWS_CONTROL and _extracts(e.map.steps):
                # Before iterating, even zero times: whether the body's extractions
                # run is decided by the list, so ``seen``'s trust is syntax-determined
                # (Gate 2 review #2, DESIGN §3.3).
                self._extracted = join(self._extracted, inner_pc)
            results = tuple(
                self._block(
                    e.map.steps, {**scope, e.map.as_: over.element(k)}, inner_pc, (*site, k)
                )
                for k in range(min(len(over.items), MAX_LIST))
            )
            return ListV(results, over.label)
        assert isinstance(e, FilterExpr)
        over = _list(self._expr(e.filter.over, scope, pc, (*site, -1)))
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
