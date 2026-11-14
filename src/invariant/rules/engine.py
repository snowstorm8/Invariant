"""Compiled rules: judging one step, and sets of rules loaded at run time."""

from __future__ import annotations

from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass, field
from typing import Any

from invariant.evaluation.violations import Outcome

from . import jsonio
from .errors import Diagnostic, RuleValidationError
from .interpreter import DEFAULT_BUDGET, BudgetExceededError, Interpreter
from .ir import Assertion, Expr, Index, Let, Literal, Member, Observe, Ref, Rule, RuleDocument, Template
from .parser import parse_rules
from .printer import format_expr, format_rule
from .types import ContextSchema
from .validator import _walk, validate_rule, validate_rules
from .values import Undefined, Value, plain, render

_SHORT = 80
_MAX_EXPLAINED = 12


@dataclass(frozen=True)
class RuleVerdict:
    """What a rule concluded about one step.

    ``outcome`` is None when the step is outside the rule's ``when`` scope.
    """

    outcome: Outcome | None
    summary: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)


def _short(text: str) -> str:
    return text if len(text) <= _SHORT else text[: _SHORT - 1] + "…"


def _paths(expr: Expr, names: set[str]) -> list[Expr]:
    """The field paths and named values an expression reads: what a reader needs
    to see to understand why it came out as it did. Only whole paths are kept
    (``actor.org``, not also ``actor``), in order of appearance."""

    def is_path(node: Expr) -> bool:
        while isinstance(node, (Member, Index)):
            if isinstance(node, Index) and not isinstance(node.key, Literal):
                return False
            node = node.target
        return isinstance(node, Ref) and node.name in names

    candidates = [node for node in _walk(expr) if is_path(node)]
    prefixes: set[int] = set()
    for node in candidates:
        while isinstance(node, (Member, Index)):
            node = node.target
            prefixes.add(id(node))
    found: list[Expr] = []
    for node in candidates:
        if id(node) not in prefixes and node not in found:
            found.append(node)
    return found[:_MAX_EXPLAINED]


class CompiledRule:
    """A validated rule, ready to judge steps.

    Construction fails with ``RuleValidationError`` if the rule does not fit the
    schema, so a compiled rule never refers to something the integration does
    not provide.
    """

    def __init__(self, rule: Rule, schema: ContextSchema, *, budget: int = DEFAULT_BUDGET) -> None:
        problems = validate_rule(rule, schema)
        if problems:
            raise RuleValidationError(problems)
        self.rule = rule
        self.schema = schema
        self.budget = budget
        self._lets: dict[str, Expr] = {b.name: b.value for b in rule.bindings if isinstance(b, Let)}
        self.observes: tuple[Observe, ...] = rule.observes
        self._names = set(schema.roots) | set(self._lets) | {o.name for o in self.observes}

    @property
    def id(self) -> str:
        return self.rule.id

    @property
    def statement(self) -> str:
        """What the rule demands, in words if it has a description, else as written."""
        if self.rule.description:
            return self.rule.description
        return "; ".join(f"{a.kind} {format_expr(a.condition)}" for a in self.rule.assertions)

    # -- before the response -------------------------------------------------

    def in_scope(self, context: Mapping[str, Value]) -> bool | Undefined:
        """Does the rule apply to this step? Decided without the response."""
        if self.rule.when is None:
            return True
        try:
            result = Interpreter(context, self._lets, {}, budget=self.budget).evaluate(self.rule.when)
        except BudgetExceededError:
            return Undefined("the 'when' condition exceeded the evaluation budget")
        if isinstance(result, (bool, Undefined)):
            return result
        return Undefined("the 'when' condition is not true or false")

    def probe_arguments(self, context: Mapping[str, Value]) -> list[tuple[Observe, tuple[Value, ...] | Undefined]]:
        """Arguments of each ``observe`` clause, or why they cannot be computed."""
        interpreter = Interpreter(context, self._lets, {}, budget=self.budget)
        out: list[tuple[Observe, tuple[Value, ...] | Undefined]] = []
        for observe in self.observes:
            values: list[Value] = []
            problem: Undefined | None = None
            try:
                for arg in observe.args:
                    value = interpreter.evaluate(arg)
                    if isinstance(value, Undefined):
                        problem = value
                        break
                    values.append(value)
            except BudgetExceededError:
                problem = Undefined("probe arguments exceeded the evaluation budget")
            out.append((observe, problem if problem is not None else tuple(values)))
        return out

    # -- after the response --------------------------------------------------

    def judge(self, context: Mapping[str, Value], observed: Mapping[str, Value] | None = None) -> RuleVerdict:
        """Judge one step. ``context`` includes the response; ``observed`` holds
        the value of each ``observe`` clause that could be taken."""
        interpreter = Interpreter(context, self._lets, observed or {}, budget=self.budget)
        try:
            return self._judge(interpreter)
        except BudgetExceededError:
            return RuleVerdict(
                Outcome.INCONCLUSIVE,
                f"rule could not be evaluated: it exceeded the budget of {self.budget} steps",
            )

    def _judge(self, interpreter: Interpreter) -> RuleVerdict:
        rule = self.rule
        if rule.when is not None:
            scope = interpreter.evaluate(rule.when)
            if scope is False:
                return RuleVerdict(None)
            if scope is not True:
                reason = scope.reason if isinstance(scope, Undefined) else "it is not true or false"
                return RuleVerdict(
                    Outcome.INCONCLUSIVE,
                    f"cannot tell whether the rule applies: {reason}",
                    {"when": format_expr(rule.when), "reason": reason},
                )
        unknown: tuple[Assertion, str] | None = None
        for assertion in rule.assertions:
            value = interpreter.evaluate(assertion.condition)
            if isinstance(value, bool):
                if value is (assertion.kind == "never"):
                    return self._violation(interpreter, assertion)
                continue
            reason = value.reason if isinstance(value, Undefined) else "it is not true or false"
            unknown = unknown or (assertion, reason)
        if unknown is not None:
            assertion, reason = unknown
            text = f"{assertion.kind} {format_expr(assertion.condition)}"
            return RuleVerdict(
                Outcome.INCONCLUSIVE,
                f"rule could not be evaluated: {reason}",
                {"assertion": text, "reason": reason},
            )
        if rule.pass_message is not None:
            summary = self._render(interpreter, rule.pass_message)
        else:
            count = len(rule.assertions)
            summary = "assertion held" if count == 1 else f"all {count} assertions held"
        return RuleVerdict(Outcome.PASS, summary)

    def _violation(self, interpreter: Interpreter, assertion: Assertion) -> RuleVerdict:
        rule = self.rule
        text = f"{assertion.kind} {format_expr(assertion.condition)}"
        explained: dict[str, Any] = {}
        for path in _paths(assertion.condition, self._names):
            value = interpreter.evaluate(path)
            explained[format_expr(path)] = plain(value) if not isinstance(value, Undefined) else None
        if rule.message is not None:
            summary = self._render(interpreter, rule.message)
        else:
            values = ", ".join(f"{k} = {_short(render(v) if not isinstance(v, str) else repr(v))}" for k, v in explained.items())
            detail = f" ({values})" if values else ""
            if assertion.kind == "never":
                summary = f"forbidden condition held: {format_expr(assertion.condition)}{detail}"
            else:
                summary = f"required condition failed: {format_expr(assertion.condition)}{detail}"
        if rule.evidence is not None:
            evidence = {name: plain(interpreter.evaluate(expr)) for name, expr in rule.evidence}
        else:
            evidence = {"assertion": text, "values": explained}
        return RuleVerdict(Outcome.VIOLATION, summary, evidence)

    @staticmethod
    def _render(interpreter: Interpreter, template: Template) -> str:
        return "".join(
            part if isinstance(part, str) else render(interpreter.evaluate(part))
            for part in template.parts
        )


class RuleSet:
    """An ordered, validated collection of rules for one integration.

    Order is evaluation order; the first violation on a step decides how a
    failure is attributed.
    """

    def __init__(self, rules: Iterable[Rule], schema: ContextSchema) -> None:
        self.rules: tuple[Rule, ...] = tuple(rules)
        self.schema = schema
        problems = validate_rules(self.rules, schema)
        if problems:
            raise RuleValidationError(problems)
        self.compiled: tuple[CompiledRule, ...] = tuple(CompiledRule(r, schema) for r in self.rules)

    @classmethod
    def from_text(cls, source: str, schema: ContextSchema) -> RuleSet:
        return cls(parse_rules(source).rules, schema)

    @classmethod
    def from_json(cls, data: Any, schema: ContextSchema) -> RuleSet:
        """From decoded JSON; rules marked ``"enabled": false`` are left out."""
        document = jsonio.rules_from_json(data)
        return cls((r for r in document.rules if r.id not in document.disabled), schema)

    def to_json(self) -> dict[str, Any]:
        return jsonio.document_to_json(self.rules)

    def __iter__(self) -> Iterator[CompiledRule]:
        return iter(self.compiled)

    def __len__(self) -> int:
        return len(self.compiled)

    def ids(self) -> list[str]:
        return [r.id for r in self.rules]


@dataclass
class RegisteredRule:
    rule: Rule
    enabled: bool = True
    #: Where the rule came from: "builtin", "authored", "imported", ...
    origin: str = "authored"

    @property
    def source(self) -> str:
        return format_rule(self.rule)


class RuleRegistry:
    """Rules registered at run time, each individually switchable.

    Nothing here is fixed at import time: rules arrive as text, JSON or IR,
    are validated against the integration's schema on the way in, and
    :meth:`ruleset` yields whatever is enabled at that moment.
    """

    def __init__(self, schema: ContextSchema) -> None:
        self.schema = schema
        self._entries: dict[str, RegisteredRule] = {}

    def register(
        self,
        definition: str | Rule | RuleDocument | Mapping[str, Any] | list[Any],
        *,
        origin: str = "authored",
        enabled: bool = True,
        replace: bool = False,
    ) -> list[Rule]:
        """Add rules from text (``str``), decoded JSON (``dict``/``list``) or IR.

        All-or-nothing: if any rule is invalid, or its id is taken and
        ``replace`` is false, nothing is registered.
        """
        if isinstance(definition, str):
            document = parse_rules(definition)
        elif isinstance(definition, Rule):
            document = RuleDocument((definition,))
        elif isinstance(definition, RuleDocument):
            document = definition
        else:
            document = jsonio.rules_from_json(definition)
        problems = validate_rules(document.rules, self.schema)
        for rule in document.rules:
            if rule.id in self._entries and not replace:
                problems.append(
                    Diagnostic(f"a rule with id '{rule.id}' is already registered", rule=rule.name)
                )
        if problems:
            raise RuleValidationError(problems)
        for rule in document.rules:
            self._entries[rule.id] = RegisteredRule(
                rule, enabled and rule.id not in document.disabled, origin
            )
        return list(document.rules)

    def unregister(self, rule_id: str) -> None:
        del self._entries[self._require(rule_id)]

    def set_enabled(self, rule_id: str, enabled: bool) -> None:
        self._entries[self._require(rule_id)].enabled = enabled

    def _require(self, rule_id: str) -> str:
        if rule_id not in self._entries:
            raise KeyError(f"no rule with id '{rule_id}' is registered")
        return rule_id

    def __contains__(self, rule_id: object) -> bool:
        return rule_id in self._entries

    def __iter__(self) -> Iterator[RegisteredRule]:
        return iter(self._entries.values())

    def __len__(self) -> int:
        return len(self._entries)

    def get(self, rule_id: str) -> RegisteredRule:
        return self._entries[self._require(rule_id)]

    def ruleset(self) -> RuleSet:
        """The enabled rules, in registration order."""
        return RuleSet((e.rule for e in self._entries.values() if e.enabled), self.schema)
