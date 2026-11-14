"""Render the IR back to rule-language text.

``parse_rules(format_rule(rule))`` yields an equal rule, so the text form is a
lossless way to show, store and edit rules that arrived as JSON.
"""

from __future__ import annotations

import json

from .ir import (
    Binary,
    Call,
    Comprehension,
    Expr,
    Index,
    Let,
    ListExpr,
    Literal,
    Member,
    Quantifier,
    RecordExpr,
    Ref,
    Rule,
    Template,
    Unary,
)

_PREC = {
    "implies": 1, "or": 2, "and": 3,
    "==": 5, "!=": 5, "<": 5, "<=": 5, ">": 5, ">=": 5, "in": 5,
    "+": 6, "-": 6, "*": 7,
}  # fmt: skip
_NOT, _NEG, _ATOM = 4, 8, 9


def _precedence(expr: Expr) -> int:
    match expr:
        case Quantifier():
            return 0
        case Binary():
            return _PREC[expr.op]
        case Unary():
            return _NOT if expr.op == "not" else _NEG
        case Literal() if isinstance(expr.value, (int, float)) and not isinstance(
            expr.value, bool
        ) and expr.value < 0:
            return _NEG
    return _ATOM


def quote(text: str, mark: str = '"') -> str:
    """Quote text as a rule-language string literal."""
    if mark == "'":
        body = json.dumps(text, ensure_ascii=False)[1:-1].replace('\\"', '"').replace("'", "\\'")
        return f"'{body}'"
    return json.dumps(text, ensure_ascii=False)


def format_expr(expr: Expr, mark: str = '"') -> str:
    """Source text of ``expr``. ``mark`` is the quote character for string literals."""

    def wrap(child: Expr, minimum: int) -> str:
        text = fmt(child)
        return f"({text})" if _precedence(child) < minimum else text

    def fmt(e: Expr) -> str:
        match e:
            case Literal():
                if e.value is None:
                    return "null"
                if isinstance(e.value, bool):
                    return "true" if e.value else "false"
                if isinstance(e.value, str):
                    return quote(e.value, mark)
                return repr(e.value)
            case Ref():
                return e.name
            case Member():
                return f"{wrap(e.target, _ATOM)}.{e.name}"
            case Index():
                return f"{wrap(e.target, _ATOM)}[{fmt(e.key)}]"
            case ListExpr():
                return "[" + ", ".join(fmt(i) for i in e.items) + "]"
            case RecordExpr():
                return "{" + ", ".join(f"{_key(k, mark)}: {fmt(v)}" for k, v in e.fields) + "}"
            case Unary():
                if e.op == "not":
                    return f"not {wrap(e.operand, _NOT)}"
                return f"-{wrap(e.operand, _NEG)}"
            case Binary():
                p = _PREC[e.op]
                if e.op == "implies":  # right-associative
                    return f"{wrap(e.left, p + 1)} implies {wrap(e.right, p)}"
                if p == 5:  # comparisons do not chain
                    return f"{wrap(e.left, p + 1)} {e.op} {wrap(e.right, p + 1)}"
                return f"{wrap(e.left, p)} {e.op} {wrap(e.right, p + 1)}"
            case Call():
                return f"{e.function}(" + ", ".join(fmt(a) for a in e.args) + ")"
            case Quantifier():
                return f"{e.kind} {e.var} in {wrap(e.source, 6)} : {fmt(e.condition)}"
            case Comprehension():
                tail = f" where {fmt(e.condition)}" if e.condition is not None else ""
                return f"[{fmt(e.value)} for {e.var} in {wrap(e.source, 6)}{tail}]"
        raise TypeError(f"not an expression: {e!r}")

    return fmt(expr)


def _key(name: str, mark: str) -> str:
    return name if name.isidentifier() else quote(name, mark)


def format_template(template: Template) -> str:
    """The raw template text (before quoting), with ``{expr}`` holes."""
    out: list[str] = []
    for part in template.parts:
        if isinstance(part, str):
            out.append(part.replace("{", "{{").replace("}", "}}"))
        else:
            out.append("{" + format_expr(part, "'") + "}")
    return "".join(out)


def format_rule(rule: Rule) -> str:
    """A rule as canonical rule-language text."""
    lines = [f"rule {quote(rule.name)} {{"]
    if rule.id != rule.name:
        lines.append(f"    id {quote(rule.id)}")
    if rule.policy is not None:
        lines.append(f"    policy {quote(rule.policy)}")
    if rule.tags:
        lines.append("    tags " + ", ".join(quote(t) for t in rule.tags))
    if rule.description:
        lines.append(f"    description {quote(rule.description)}")
    lines.append(f"    severity {rule.severity}")
    if rule.when is not None:
        lines.append(f"    when {format_expr(rule.when)}")
    for binding in rule.bindings:
        if isinstance(binding, Let):
            lines.append(f"    let {binding.name} = {format_expr(binding.value)}")
        else:
            args = ", ".join(format_expr(a) for a in binding.args)
            lines.append(f"    observe {binding.name} = {binding.probe}({args})")
    for assertion in rule.assertions:
        lines.append(f"    {assertion.kind} {format_expr(assertion.condition)}")
    if rule.message is not None:
        lines.append(f"    message {quote(format_template(rule.message))}")
    if rule.pass_message is not None:
        lines.append(f"    pass_message {quote(format_template(rule.pass_message))}")
    if rule.evidence is not None:
        lines.append("    evidence {")
        for i, (name, expr) in enumerate(rule.evidence):
            comma = "," if i < len(rule.evidence) - 1 else ""
            lines.append(f"        {_key(name, chr(34))}: {format_expr(expr)}{comma}")
        lines.append("    }")
    lines.append("}")
    return "\n".join(lines)


def format_rules(rules: list[Rule] | tuple[Rule, ...]) -> str:
    """Several rules as canonical text separated by blank lines."""
    return "\n\n".join(format_rule(r) for r in rules) + "\n"
