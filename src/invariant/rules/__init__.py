"""User-defined security rules.

A small declarative language for stating what an application must always or
never do, with two interchangeable front ends (text and JSON) over one
intermediate representation, a static validator, and a sandboxed interpreter.

This package is application-agnostic. What a rule can refer to (``actor``,
``response``, ...) is defined by an integration's
:class:`~invariant.rules.types.ContextSchema` and supplied at run time through
a :class:`~invariant.rules.binding.RuleBinding`.
"""

from .binding import RuleBinding
from .engine import CompiledRule, RegisteredRule, RuleRegistry, RuleSet, RuleVerdict
from .errors import Diagnostic, RuleError, RuleSyntaxError, RuleValidationError
from .ir import Rule, RuleDocument
from .jsonio import document_to_json, loads, rule_to_json, rules_from_json
from .parser import parse_expression, parse_rules
from .printer import format_expr, format_rule, format_rules
from .types import ContextSchema
from .validator import validate_rule, validate_rules
from .values import LazyContext, Undefined

__all__ = [
    "CompiledRule",
    "ContextSchema",
    "Diagnostic",
    "LazyContext",
    "RegisteredRule",
    "Rule",
    "RuleBinding",
    "RuleDocument",
    "RuleError",
    "RuleRegistry",
    "RuleSet",
    "RuleSyntaxError",
    "RuleValidationError",
    "RuleVerdict",
    "Undefined",
    "document_to_json",
    "format_expr",
    "format_rule",
    "format_rules",
    "loads",
    "parse_expression",
    "parse_rules",
    "rule_to_json",
    "rules_from_json",
    "validate_rule",
    "validate_rules",
]
