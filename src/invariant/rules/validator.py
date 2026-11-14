"""Static checks of a rule against a context schema.

Catches, before anything runs: unknown fields and functions, comparisons that
can never be true, non-boolean conditions, conditions that use the response
where it is not yet known, unknown probes, name clashes and cyclic definitions.
"""

from __future__ import annotations

import difflib
import re

from .errors import Diagnostic
from .functions import FUNCTIONS
from .ir import (
    ASSERTION_KINDS,
    BINARY_OPS,
    QUANTIFIERS,
    SEVERITIES,
    Binary,
    Call,
    Comprehension,
    Expr,
    Index,
    Let,
    ListExpr,
    Literal,
    Loc,
    Member,
    Observe,
    Quantifier,
    RecordExpr,
    Ref,
    Rule,
    Template,
    Unary,
)
from .parser import RESERVED
from .printer import format_expr
from .types import (
    ANY,
    BOOL,
    INT,
    NULL,
    NUMBER,
    STRING,
    AnyType,
    BoolType,
    ContextSchema,
    Field,
    ListType,
    MapType,
    NullType,
    NumberType,
    RecordType,
    StringType,
    Type,
    record,
)

NAME_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
#: Ids the framework uses for its own evaluations.
RESERVED_IDS = frozenset({"EXEC"})
TAG_PATTERN = re.compile(r"[a-z0-9][a-z0-9._-]{0,31}")
MAX_TAGS = 12
MAX_BINDINGS = 64
MAX_ASSERTIONS = 32


def _suggest(word: str, options: list[str]) -> str:
    close = difflib.get_close_matches(word, options, n=1)
    return f"; did you mean '{close[0]}'?" if close else ""


def _group(t: Type) -> str | None:
    """Coarse kind used to decide whether two values can ever be equal."""
    if isinstance(t, (AnyType, NullType)):
        return None  # compatible with everything
    if isinstance(t, NumberType):
        return "number"
    if isinstance(t, StringType):
        return "string"
    if isinstance(t, BoolType):
        return "bool"
    if isinstance(t, ListType):
        return "list"
    return "object"


def _join(a: Type, b: Type) -> Type:
    if a == b:
        return a
    if isinstance(a, NumberType) and isinstance(b, NumberType):
        return NUMBER
    if isinstance(a, StringType) and isinstance(b, StringType):
        return STRING
    return ANY


class _RuleChecker:
    def __init__(self, rule: Rule, schema: ContextSchema) -> None:
        self.rule = rule
        self.schema = schema
        self.problems: list[Diagnostic] = []
        self.lets: dict[str, Let] = {}
        self.observes: dict[str, Observe] = {}
        self._let_types: dict[str, Type] = {}
        self._let_late: dict[str, bool] = {}
        self._resolving: list[str] = []

    # -- reporting -----------------------------------------------------------

    def error(self, message: str, loc: Loc | None) -> None:
        loc = loc or self.rule.loc
        self.problems.append(
            Diagnostic(
                message,
                line=loc.line if loc else None,
                col=loc.col if loc else None,
                path=loc.path if loc else None,
                rule=self.rule.name,
            )
        )

    # -- entry ---------------------------------------------------------------

    def check(self) -> list[Diagnostic]:
        rule = self.rule
        for label, value in (("name", rule.name), ("id", rule.id)):
            if not NAME_PATTERN.fullmatch(value):
                self.error(
                    f"rule {label} {value!r} is not valid: use 1-64 letters, digits, '.', '_' or "
                    "'-', starting with a letter or digit",
                    rule.loc,
                )
        if rule.policy is not None and not NAME_PATTERN.fullmatch(rule.policy):
            self.error(
                f"policy key {rule.policy!r} is not valid: use 1-64 letters, digits, '.', '_' "
                "or '-', starting with a letter or digit",
                rule.loc,
            )
        if len(rule.tags) > MAX_TAGS:
            self.error(f"a rule may have at most {MAX_TAGS} tags", rule.loc)
        for tag in rule.tags:
            if not TAG_PATTERN.fullmatch(tag):
                self.error(
                    f"tag {tag!r} is not valid: use 1-32 lower-case letters, digits, '_', '.' "
                    "or '-', starting with a letter or digit",
                    rule.loc,
                )
        if len(set(rule.tags)) != len(rule.tags):
            self.error("a tag is listed twice", rule.loc)
        if rule.id in RESERVED_IDS:
            self.error(f"rule id '{rule.id}' is reserved by Invariant", rule.loc)
        if rule.severity not in SEVERITIES:
            self.error(f"severity must be one of {', '.join(SEVERITIES)}", rule.loc)
        if len(rule.bindings) > MAX_BINDINGS:
            self.error(f"a rule may define at most {MAX_BINDINGS} let/observe names", rule.loc)
        if len(rule.assertions) > MAX_ASSERTIONS:
            self.error(f"a rule may hold at most {MAX_ASSERTIONS} assertions", rule.loc)

        for binding in rule.bindings:
            name = binding.name
            what = "let" if isinstance(binding, Let) else "observe"
            if name in self.schema.roots:
                self.error(f"{what} '{name}' hides the context field '{name}'", binding.loc)
            elif name in self.lets or name in self.observes:
                self.error(f"'{name}' is defined more than once", binding.loc)
            elif name in RESERVED or name in FUNCTIONS:
                self.error(f"'{name}' is a reserved word and cannot be used as a name", binding.loc)
            elif isinstance(binding, Let):
                self.lets[name] = binding
            else:
                self.observes[name] = binding

        for observe in self.observes.values():
            self._check_observe(observe)
        for name in self.lets:
            self._let_type(name, None)

        if rule.when is not None:
            self._boolean(rule.when, "the 'when' condition", {})
            late = self._late_cause(rule.when, frozenset())
            if late:
                self.error(
                    f"'when' is decided before the target responds, so it cannot use {late}; "
                    "move that condition into the assertion, e.g. "
                    "'always <response condition> implies <requirement>'",
                    _loc_of(rule.when),
                )
        if not rule.assertions:
            self.error(
                "the rule asserts nothing: add 'always <condition>' or 'never <condition>'",
                rule.loc,
            )
        for assertion in rule.assertions:
            if assertion.kind not in ASSERTION_KINDS:
                self.error(f"unknown assertion kind '{assertion.kind}'", assertion.loc)
            self._boolean(assertion.condition, f"the '{assertion.kind}' condition", {})
        for template in (rule.message, rule.pass_message):
            if template is not None:
                self._check_template(template)
        if rule.evidence is not None:
            for _, expr in rule.evidence:
                self.infer(expr, {})
        return self.problems

    def _check_template(self, template: Template) -> None:
        for part in template.parts:
            if not isinstance(part, str):
                self.infer(part, {})

    def _check_observe(self, observe: Observe) -> None:
        spec = self.schema.probes.get(observe.probe)
        if spec is None:
            known = sorted(self.schema.probes)
            listing = f"available: {', '.join(known)}" if known else "this target offers none"
            self.error(
                f"unknown probe '{observe.probe}'{_suggest(observe.probe, known)} ({listing})",
                observe.loc,
            )
            for arg in observe.args:
                self.infer(arg, {})
            return
        if len(observe.args) != len(spec.params):
            params = ", ".join(n for n, _ in spec.params)
            self.error(
                f"probe {observe.probe}({params}) takes {len(spec.params)} argument(s), "
                f"found {len(observe.args)}",
                observe.loc,
            )
        for arg, (param, expected) in zip(observe.args, spec.params, strict=False):
            actual = self.infer(arg, {})
            if _group(actual) and _group(expected) and _group(actual) != _group(expected):
                self.error(
                    f"probe {observe.probe}: argument '{param}' must be {expected.describe()}, "
                    f"but {format_expr(arg)} is {actual.describe()}",
                    _loc_of(arg),
                )
            late = self._late_cause(arg, frozenset())
            if late:
                self.error(
                    f"probe arguments are decided before the target responds, so "
                    f"'{observe.name}' cannot use {late}",
                    _loc_of(arg),
                )

    # -- names ---------------------------------------------------------------

    def _let_type(self, name: str, loc: Loc | None) -> Type:
        if name in self._let_types:
            return self._let_types[name]
        if name in self._resolving:
            cycle = " -> ".join([*self._resolving[self._resolving.index(name) :], name])
            self.error(f"let '{name}' is defined in terms of itself ({cycle})", loc)
            return ANY
        self._resolving.append(name)
        try:
            result = self.infer(self.lets[name].value, {})
        finally:
            self._resolving.pop()
        self._let_types[name] = result
        return result

    def _late_cause(self, expr: Expr, bound: frozenset[str], seen: frozenset[str] = frozenset()) -> str:
        """Why ``expr`` is only known after the response ('' if it is not)."""
        for node in _walk(expr):
            if not isinstance(node, Ref) or node.name in bound:
                continue
            name = node.name
            if name in self.observes:
                return f"the observation '{name}' (taken after the operation)"
            root = self.schema.roots.get(name)
            if root is not None and root.late:
                return f"'{name}'"
            if name in self.lets and name not in seen:
                inner = self._late_cause(self.lets[name].value, frozenset(), seen | {name})
                if inner:
                    return f"'{name}' (which depends on {inner})"
        return ""

    def _boolean(self, expr: Expr, what: str, scope: dict[str, Type]) -> None:
        t = self.infer(expr, scope)
        if not isinstance(t, (BoolType, AnyType)):
            self.error(
                f"{what} must be true or false, but {format_expr(expr)} is {t.describe()}",
                _loc_of(expr),
            )

    # -- expressions ---------------------------------------------------------

    def infer(self, expr: Expr, scope: dict[str, Type]) -> Type:
        match expr:
            case Literal():
                v = expr.value
                if v is None:
                    return NULL
                if isinstance(v, bool):
                    return BOOL
                if isinstance(v, int):
                    return INT
                if isinstance(v, float):
                    return NUMBER
                return STRING
            case Ref():
                return self._ref(expr, scope)
            case Member():
                target = self.infer(expr.target, scope)
                return self._field(expr, target, expr.name)
            case Index():
                return self._index(expr, scope)
            case ListExpr():
                item: Type | None = None
                for element in expr.items:
                    t = self.infer(element, scope)
                    item = t if item is None else _join(item, t)
                return ListType(item or ANY)
            case RecordExpr():
                return record(**{k: self.infer(v, scope) for k, v in expr.fields})
            case Unary():
                return self._unary(expr, scope)
            case Binary():
                return self._binary(expr, scope)
            case Call():
                return self._call(expr, scope)
            case Quantifier():
                if expr.kind not in QUANTIFIERS:
                    self.error(f"unknown quantifier '{expr.kind}'", expr.loc)
                inner = self._bind(expr.var, expr.source, scope, expr.loc)
                self._boolean(expr.condition, f"the condition of '{expr.kind}'", inner)
                return BOOL
            case Comprehension():
                inner = self._bind(expr.var, expr.source, scope, expr.loc)
                if expr.condition is not None:
                    self._boolean(expr.condition, "the 'where' condition", inner)
                return ListType(self.infer(expr.value, inner))
        raise TypeError(f"not an expression: {expr!r}")

    def _bind(self, var: str, source: Expr, scope: dict[str, Type], loc: Loc | None) -> dict[str, Type]:
        source_type = self.infer(source, scope)
        item: Type = ANY
        if isinstance(source_type, ListType):
            item = source_type.item
        elif isinstance(source_type, MapType):
            item = record(key=STRING, value=source_type.value)
        elif isinstance(source_type, RecordType):
            item = record(key=STRING, value=ANY)
        elif not isinstance(source_type, AnyType):
            self.error(
                f"cannot iterate over {format_expr(source)}: it is {source_type.describe()}, "
                "not a list or map",
                _loc_of(source),
            )
        if (
            var in scope
            or var in self.schema.roots
            or var in self.lets
            or var in self.observes
        ):
            self.error(f"variable '{var}' hides another name; choose a different one", loc)
        elif var in RESERVED or var in FUNCTIONS:
            self.error(f"'{var}' is a reserved word and cannot be used as a variable", loc)
        return {**scope, var: item}

    def _ref(self, expr: Ref, scope: dict[str, Type]) -> Type:
        name = expr.name
        if name in scope:
            return scope[name]
        if name in self.lets:
            return self._let_type(name, expr.loc)
        if name in self.observes:
            spec = self.schema.probes.get(self.observes[name].probe)
            return spec.returns if spec else ANY
        root = self.schema.roots.get(name)
        if root is not None:
            return root.type
        options = [*scope, *self.lets, *self.observes, *self.schema.roots]
        self.error(
            f"unknown name '{name}'{_suggest(name, options)} "
            f"(context fields: {', '.join(self.schema.roots)})",
            expr.loc,
        )
        return ANY

    def _field(self, expr: Member, target: Type, name: str) -> Type:
        if isinstance(target, AnyType):
            return ANY
        if isinstance(target, MapType):
            return target.value
        if isinstance(target, RecordType):
            found: Field | None = target.field(name)
            if found is not None:
                return found.type
            names = [n for n, _ in target.fields]
            self.error(
                f"{format_expr(expr.target)} has no field '{name}'{_suggest(name, names)} "
                f"(fields: {', '.join(names)})",
                expr.loc,
            )
            return ANY
        self.error(
            f"{format_expr(expr.target)} is {target.describe()} and has no field '{name}'",
            expr.loc,
        )
        return ANY

    def _index(self, expr: Index, scope: dict[str, Type]) -> Type:
        target = self.infer(expr.target, scope)
        key = self.infer(expr.key, scope)
        if isinstance(target, AnyType):
            return ANY
        if isinstance(target, ListType):
            if not isinstance(key, (NumberType, AnyType)):
                self.error(
                    f"a list is indexed by a number, but {format_expr(expr.key)} is "
                    f"{key.describe()}",
                    _loc_of(expr.key),
                )
            return target.item
        if isinstance(target, (MapType, RecordType)):
            if not isinstance(key, (StringType, AnyType)):
                self.error(
                    f"a map is indexed by a string, but {format_expr(expr.key)} is "
                    f"{key.describe()}",
                    _loc_of(expr.key),
                )
            if isinstance(target, MapType):
                return target.value
            if isinstance(expr.key, Literal) and isinstance(expr.key.value, str):
                return self._field(
                    Member(expr.target, expr.key.value, loc=expr.loc), target, expr.key.value
                )
            return ANY
        self.error(
            f"{format_expr(expr.target)} is {target.describe()} and cannot be indexed", expr.loc
        )
        return ANY

    def _unary(self, expr: Unary, scope: dict[str, Type]) -> Type:
        operand = self.infer(expr.operand, scope)
        if expr.op == "not":
            if not isinstance(operand, (BoolType, AnyType)):
                self.error(
                    f"'not' needs a true/false operand, but {format_expr(expr.operand)} is "
                    f"{operand.describe()}",
                    expr.loc,
                )
            return BOOL
        if not isinstance(operand, (NumberType, AnyType)):
            self.error(
                f"'-' needs a number, but {format_expr(expr.operand)} is {operand.describe()}",
                expr.loc,
            )
        return operand if isinstance(operand, NumberType) else NUMBER

    def _binary(self, expr: Binary, scope: dict[str, Type]) -> Type:
        op = expr.op
        if op not in BINARY_OPS:
            self.error(f"unknown operator '{op}'", expr.loc)
            return ANY
        left = self.infer(expr.left, scope)
        right = self.infer(expr.right, scope)
        if op in ("and", "or", "implies"):
            for side, t in ((expr.left, left), (expr.right, right)):
                if not isinstance(t, (BoolType, AnyType)):
                    self.error(
                        f"'{op}' needs true/false operands, but {format_expr(side)} is "
                        f"{t.describe()}",
                        _loc_of(side) or expr.loc,
                    )
            return BOOL
        if op in ("==", "!="):
            self._comparable(expr, left, right)
            self._enum_literal(expr.left, left, expr.right)
            self._enum_literal(expr.right, right, expr.left)
            return BOOL
        if op in ("<", "<=", ">", ">="):
            ok = (_group(left) in (None, "number") and _group(right) in (None, "number")) or (
                _group(left) in (None, "string") and _group(right) in (None, "string")
            )
            if not ok or isinstance(left, NullType) or isinstance(right, NullType):
                self.error(
                    f"'{op}' orders two numbers or two strings, but {format_expr(expr.left)} is "
                    f"{left.describe()} and {format_expr(expr.right)} is {right.describe()}",
                    expr.loc,
                )
            return BOOL
        if op == "in":
            if isinstance(right, ListType):
                if _group(left) and _group(right.item) and _group(left) != _group(right.item):
                    self.error(
                        f"{format_expr(expr.left)} is {left.describe()} and can never be in "
                        f"{format_expr(expr.right)}, a {right.describe()}",
                        expr.loc,
                    )
                if isinstance(expr.right, ListExpr):
                    for item in expr.right.items:
                        self._enum_literal(expr.left, left, item)
            elif isinstance(right, (StringType, MapType, RecordType)):
                if not isinstance(left, (StringType, AnyType)):
                    self.error(
                        f"only a string can be 'in' {right.describe()}, but "
                        f"{format_expr(expr.left)} is {left.describe()}",
                        expr.loc,
                    )
            elif not isinstance(right, AnyType):
                self.error(
                    f"'in' needs a list, map or string on the right, but "
                    f"{format_expr(expr.right)} is {right.describe()}",
                    expr.loc,
                )
            return BOOL
        if op == "+":
            if isinstance(left, AnyType) or isinstance(right, AnyType):
                return _plus_hint(left, right)
            if isinstance(left, NumberType) and isinstance(right, NumberType):
                return INT if left.integer and right.integer else NUMBER
            if isinstance(left, StringType) and isinstance(right, StringType):
                return STRING
            if isinstance(left, ListType) and isinstance(right, ListType):
                return ListType(_join(left.item, right.item))
            self.error(
                f"'+' adds two numbers, strings or lists, but {format_expr(expr.left)} is "
                f"{left.describe()} and {format_expr(expr.right)} is {right.describe()} "
                "(use str(x) to turn a value into text)",
                expr.loc,
            )
            return ANY
        for side, t in ((expr.left, left), (expr.right, right)):
            if not isinstance(t, (NumberType, AnyType)):
                self.error(
                    f"'{op}' needs numbers, but {format_expr(side)} is {t.describe()}", expr.loc
                )
        if isinstance(left, NumberType) and isinstance(right, NumberType):
            return INT if left.integer and right.integer else NUMBER
        return NUMBER

    def _comparable(self, expr: Binary, left: Type, right: Type) -> None:
        a, b = _group(left), _group(right)
        if a and b and a != b:
            self.error(
                f"{format_expr(expr.left)} is {left.describe()} and {format_expr(expr.right)} is "
                f"{right.describe()}; they can never be equal",
                expr.loc,
            )

    def _enum_literal(self, field_expr: Expr, field_type: Type, other: Expr) -> None:
        if (
            isinstance(field_type, StringType)
            and field_type.values
            and isinstance(other, Literal)
            and isinstance(other.value, str)
            and other.value not in field_type.values
        ):
            self.error(
                f'{format_expr(field_expr)} is never "{other.value}"'
                f"{_suggest(other.value, list(field_type.values))} "
                f"(possible values: {', '.join(field_type.values)})",
                _loc_of(other),
            )

    def _call(self, expr: Call, scope: dict[str, Type]) -> Type:
        arg_types = [self.infer(a, scope) for a in expr.args]
        fn = FUNCTIONS.get(expr.function)
        if fn is None:
            hint = _suggest(expr.function, list(FUNCTIONS))
            if expr.function in self.schema.probes:
                hint = f"; '{expr.function}' is a probe: use 'observe name = {expr.function}(...)'"
            self.error(f"unknown function '{expr.function}'{hint}", expr.loc)
            return ANY
        if len(expr.args) < fn.min_args or (
            fn.max_args is not None and len(expr.args) > fn.max_args
        ):
            self.error(
                f"{fn.signature} was called with {len(expr.args)} argument(s)", expr.loc
            )
            return ANY
        result = fn.check(arg_types)
        if isinstance(result, str):
            self.error(result, expr.loc)
            return ANY
        return result


def _plus_hint(left: Type, right: Type) -> Type:
    known = right if isinstance(left, AnyType) else left
    return known if isinstance(known, (NumberType, StringType, ListType)) else ANY


def _loc_of(expr: Expr) -> Loc | None:
    return expr.loc


def _walk(expr: Expr) -> list[Expr]:
    """``expr`` and every sub-expression."""
    out: list[Expr] = [expr]
    match expr:
        case Member():
            out += _walk(expr.target)
        case Index():
            out += _walk(expr.target) + _walk(expr.key)
        case ListExpr():
            for item in expr.items:
                out += _walk(item)
        case RecordExpr():
            for _, value in expr.fields:
                out += _walk(value)
        case Unary():
            out += _walk(expr.operand)
        case Binary():
            out += _walk(expr.left) + _walk(expr.right)
        case Call():
            for arg in expr.args:
                out += _walk(arg)
        case Quantifier():
            out += _walk(expr.source) + _walk(expr.condition)
        case Comprehension():
            out += _walk(expr.value) + _walk(expr.source)
            if expr.condition is not None:
                out += _walk(expr.condition)
    return out


def validate_rule(rule: Rule, schema: ContextSchema) -> list[Diagnostic]:
    """Every problem with ``rule`` for a target described by ``schema`` (empty if valid)."""
    return _RuleChecker(rule, schema).check()


def validate_rules(rules: tuple[Rule, ...] | list[Rule], schema: ContextSchema) -> list[Diagnostic]:
    """Validate each rule, and that ids are unique across the set."""
    problems: list[Diagnostic] = []
    seen: dict[str, str] = {}
    for rule in rules:
        problems += validate_rule(rule, schema)
        if rule.id in seen:
            loc = rule.loc
            problems.append(
                Diagnostic(
                    f"rule id '{rule.id}' is already used by rule \"{seen[rule.id]}\"; "
                    "ids must be unique",
                    line=loc.line if loc else None,
                    col=loc.col if loc else None,
                    path=loc.path if loc else None,
                    rule=rule.name,
                )
            )
        else:
            seen[rule.id] = rule.name
    return problems
