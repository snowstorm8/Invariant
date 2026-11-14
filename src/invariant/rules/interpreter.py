"""Evaluation of rule expressions.

A tree-walking interpreter over the IR. It executes no user code: the only
operations are the operators and functions defined in this package, applied to
plain data. Evaluation is deterministic, has no side effects, and is bounded by
a step budget so a rule cannot stall a run.

Logic is three-valued. ``and``/``or``/``implies`` follow Kleene's rules, so an
undefined operand matters only when it could change the answer:
``false and <undefined>`` is false, ``true and <undefined>`` is undefined.
"""

from __future__ import annotations

from collections.abc import Mapping

from .functions import FUNCTIONS
from .ir import (
    Binary,
    Call,
    Comprehension,
    Expr,
    Index,
    ListExpr,
    Literal,
    Member,
    Quantifier,
    RecordExpr,
    Ref,
    Unary,
)
from .printer import format_expr
from .values import Undefined, Value, as_sequence, equal, is_list, is_map, is_number, kind_of

#: Expression nodes one rule may evaluate on one step.
DEFAULT_BUDGET = 200_000
_MISSING = object()


class BudgetExceededError(Exception):
    """The rule did more work than one step is allowed."""


class Interpreter:
    """Evaluates expressions of one rule against one context.

    Names resolve, in order, to: bound variables, ``let`` definitions (evaluated
    on first use, once), observations, then context roots.
    """

    def __init__(
        self,
        roots: Mapping[str, Value],
        lets: Mapping[str, Expr],
        observed: Mapping[str, Value],
        *,
        budget: int = DEFAULT_BUDGET,
    ) -> None:
        self.roots = roots
        self.lets = lets
        self.observed = observed
        self.budget = budget
        self._vars: dict[str, Value] = {}
        self._let_values: dict[str, Value] = {}

    def evaluate(self, expr: Expr) -> Value:
        self.budget -= 1
        if self.budget < 0:
            raise BudgetExceededError
        match expr:
            case Literal():
                return expr.value
            case Ref():
                return self._name(expr.name)
            case Member():
                target = self.evaluate(expr.target)
                if isinstance(target, Undefined):
                    return target
                return self._get(expr, target, expr.name)
            case Index():
                return self._index(expr)
            case ListExpr():
                items = []
                for item in expr.items:
                    value = self.evaluate(item)
                    if isinstance(value, Undefined):
                        return value
                    items.append(value)
                return items
            case RecordExpr():
                # A record keeps undefined fields out rather than poisoning the whole value.
                out = {}
                for key, field in expr.fields:
                    value = self.evaluate(field)
                    if not isinstance(value, Undefined):
                        out[key] = value
                return out
            case Unary():
                return self._unary(expr)
            case Binary():
                return self._binary(expr)
            case Call():
                return self._call(expr)
            case Quantifier():
                return self._quantifier(expr)
            case Comprehension():
                return self._comprehension(expr)
        raise TypeError(f"not an expression: {expr!r}")

    # -- names and access ----------------------------------------------------

    def _name(self, name: str) -> Value:
        if name in self._vars:
            return self._vars[name]
        if name in self.lets:
            if name not in self._let_values:
                saved, self._vars = self._vars, {}
                try:
                    self._let_values[name] = self.evaluate(self.lets[name])
                finally:
                    self._vars = saved
            return self._let_values[name]
        if name in self.observed:
            return self.observed[name]
        try:
            return self.roots[name]
        except KeyError:
            return Undefined(f"'{name}' is not available for this operation")

    @staticmethod
    def _get(expr: Member, target: Value, name: str) -> Value:
        if is_map(target):
            value = target.get(name, _MISSING)
            if value is _MISSING:
                return Undefined(f"{format_expr(expr)} is missing")
            return value
        return Undefined(
            f"{format_expr(expr.target)} is {kind_of(target)}, so it has no field '{name}'"
        )

    def _index(self, expr: Index) -> Value:
        target = self.evaluate(expr.target)
        if isinstance(target, Undefined):
            return target
        key = self.evaluate(expr.key)
        if isinstance(key, Undefined):
            return key
        if is_list(target):
            if not isinstance(key, int) or isinstance(key, bool):
                return Undefined(f"{format_expr(expr.target)} is a list; its index must be an integer")
            if -len(target) <= key < len(target):
                return target[key]
            return Undefined(f"{format_expr(expr)} is out of range")
        if is_map(target):
            if not isinstance(key, str):
                return Undefined(f"{format_expr(expr.target)} is a map; its key must be a string")
            value = target.get(key, _MISSING)
            if value is _MISSING:
                return Undefined(f"{format_expr(expr.target)} has no entry '{key}'")
            return value
        return Undefined(f"{format_expr(expr.target)} is {kind_of(target)} and cannot be indexed")

    # -- operators -----------------------------------------------------------

    def _truth(self, expr: Expr) -> bool | Undefined:
        value = self.evaluate(expr)
        if isinstance(value, (bool, Undefined)):
            return value
        return Undefined(f"{format_expr(expr)} is {kind_of(value)}, not true or false")

    def _unary(self, expr: Unary) -> Value:
        if expr.op == "not":
            truth = self._truth(expr.operand)
            return truth if isinstance(truth, Undefined) else not truth
        value = self.evaluate(expr.operand)
        if isinstance(value, Undefined):
            return value
        if not is_number(value):
            return Undefined(f"cannot negate {format_expr(expr.operand)}: it is {kind_of(value)}")
        return -value

    def _binary(self, expr: Binary) -> Value:
        op = expr.op
        if op in ("and", "or", "implies"):
            left = self._truth(expr.left)
            if op == "implies":
                left = left if isinstance(left, Undefined) else not left
            decisive = op != "and"  # the operand value that settles the result alone
            if left is decisive:
                return decisive
            right = self._truth(expr.right)
            if right is decisive:
                return decisive
            if isinstance(left, Undefined):
                return left
            return right if isinstance(right, Undefined) else not decisive

        left_value = self.evaluate(expr.left)
        if isinstance(left_value, Undefined):
            return left_value
        right_value = self.evaluate(expr.right)
        if isinstance(right_value, Undefined):
            return right_value
        a, b = left_value, right_value
        if op == "==":
            return equal(a, b)
        if op == "!=":
            return not equal(a, b)
        if op in ("<", "<=", ">", ">="):
            if not ((is_number(a) and is_number(b)) or (isinstance(a, str) and isinstance(b, str))):
                return Undefined(
                    f"cannot order {format_expr(expr.left)} ({kind_of(a)}) and "
                    f"{format_expr(expr.right)} ({kind_of(b)})"
                )
            return bool({"<": a < b, "<=": a <= b, ">": a > b, ">=": a >= b}[op])
        if op == "in":
            if is_list(b):
                return any(equal(a, item) for item in b)
            if isinstance(b, str) or is_map(b):
                if not isinstance(a, str):
                    return Undefined(f"{format_expr(expr.left)} is {kind_of(a)}, not a string")
                return a in b
            return Undefined(f"{format_expr(expr.right)} is {kind_of(b)}, not a list, map or string")
        if op == "+":
            if is_number(a) and is_number(b):
                return a + b
            if isinstance(a, str) and isinstance(b, str):
                return a + b
            if is_list(a) and is_list(b):
                return [*a, *b]
        elif is_number(a) and is_number(b):
            return a - b if op == "-" else a * b
        return Undefined(
            f"cannot apply '{op}' to {format_expr(expr.left)} ({kind_of(a)}) and "
            f"{format_expr(expr.right)} ({kind_of(b)})"
        )

    def _call(self, expr: Call) -> Value:
        fn = FUNCTIONS.get(expr.function)
        if fn is None:
            return Undefined(f"unknown function '{expr.function}'")
        args = [self.evaluate(a) for a in expr.args]
        if fn.strict:
            for arg in args:
                if isinstance(arg, Undefined):
                    return arg
        return fn.impl(args)

    # -- iteration -----------------------------------------------------------

    def _items(self, source: Expr) -> list[Value] | Undefined:
        value = self.evaluate(source)
        if isinstance(value, Undefined):
            return value
        items = as_sequence(value)
        if items is None:
            return Undefined(f"cannot iterate over {format_expr(source)}: it is {kind_of(value)}")
        return list(items)

    def _quantifier(self, expr: Quantifier) -> Value:
        items = self._items(expr.source)
        if isinstance(items, Undefined):
            return items
        # "some" looks for a true element, "every" for a false one; "none" is not-some.
        looking_for = expr.kind != "every"
        unknown: Undefined | None = None
        found = False
        saved = self._vars
        try:
            for item in items:
                self._vars = {**saved, expr.var: item}
                truth = self._truth(expr.condition)
                if isinstance(truth, Undefined):
                    unknown = unknown or truth
                elif truth is looking_for:
                    found = True
                    break
        finally:
            self._vars = saved
        if not found and unknown is not None:
            return unknown
        if expr.kind == "some":
            return found
        return not found

    def _comprehension(self, expr: Comprehension) -> Value:
        items = self._items(expr.source)
        if isinstance(items, Undefined):
            return items
        out: list[Value] = []
        saved = self._vars
        try:
            for item in items:
                self._vars = {**saved, expr.var: item}
                if expr.condition is not None:
                    keep = self._truth(expr.condition)
                    if isinstance(keep, Undefined):
                        return keep
                    if not keep:
                        continue
                value = self.evaluate(expr.value)
                if isinstance(value, Undefined):
                    return value
                out.append(value)
        finally:
            self._vars = saved
        return out
