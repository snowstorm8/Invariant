"""JSON form of rules.

A JSON rule file maps onto the same IR as the text language::

    {"version": 1, "rules": [{
        "name": "read-returns-own-tenant",
        "severity": "critical",
        "when": {"==": [{"ref": "operation.type"}, {"value": "read_document"}]},
        "assert": [{"always": {"implies": [
            {"call": "has", "args": [{"ref": "response.json.org_id"}]},
            {"==": [{"ref": "response.json.org_id"}, {"ref": "actor.org_id"}]}]}}],
        "message": "{actor.ref} was served a document of {response.json.org_id}"
    }]}

Expressions are objects with exactly one operator key (see ``_expr``). Numbers,
booleans and ``null`` stand for themselves. A *string* in an expression position
is rule-language source (``"actor.role == 'viewer'"``); a string literal is
written ``{"value": "viewer"}``.
"""

from __future__ import annotations

import difflib
import json
from typing import Any

from .errors import Diagnostic, RuleSyntaxError
from .ir import (
    DEFAULT_SEVERITY,
    QUANTIFIERS,
    SEVERITIES,
    Assertion,
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
    RuleDocument,
    Template,
    Unary,
)
from .lexer import MAX_SOURCE_CHARS
from .parser import MAX_DEPTH, RESERVED, parse_expression, parse_template
from .printer import format_template

FORMAT_VERSION = 1
RULE_KEYS = (
    "name", "id", "policy", "tags", "description", "severity", "enabled", "when", "bindings", "let", "observe",
    "assert", "always", "never", "message", "pass_message", "evidence",
)  # fmt: skip
_FOLDING = ("and", "or", "+", "*")
_PAIRS = ("implies", "==", "!=", "<", "<=", ">", ">=", "in", "-")
_OPERATORS = (
    "value", "ref", "field", "index", "list", "record", "not", "neg", "call", "collect",
    *_FOLDING, *_PAIRS, *QUANTIFIERS,
)  # fmt: skip


def _clean(path: str) -> str | None:
    """A lone rule object has no enclosing path, so its keys start the path."""
    return path.lstrip(".") or None


def _at(path: str) -> Loc:
    return Loc(path=_clean(path))


class _Fail(Exception):
    def __init__(self, message: str, path: str) -> None:
        super().__init__(message)
        self.diagnostic = Diagnostic(message, path=_clean(path))


def _suggest(word: str, options: tuple[str, ...] | list[str]) -> str:
    close = difflib.get_close_matches(word, options, n=1)
    return f"; did you mean '{close[0]}'?" if close else ""


def _kind(value: object) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "a boolean"
    if isinstance(value, (int, float)):
        return "a number"
    if isinstance(value, str):
        return "a string"
    if isinstance(value, list):
        return "a list"
    return "an object"


def _is_name(text: object) -> bool:
    return isinstance(text, str) and text.isidentifier() and text.isascii() and text not in RESERVED


# -- reading ----------------------------------------------------------------


def _expr(node: Any, path: str, depth: int = 0) -> Expr:
    if depth > MAX_DEPTH:
        raise _Fail(f"expression is nested more than {MAX_DEPTH} levels deep", path)
    loc = _at(path)
    if node is None or isinstance(node, (bool, int, float)):
        return Literal(node, loc=loc)
    if isinstance(node, str):
        try:
            return _relocate(parse_expression(node), path)
        except RuleSyntaxError as exc:
            raise _Fail(
                f"cannot parse expression {node!r}: {exc.diagnostics[0].message} "
                '(a string here is rule-language source; write {"value": ...} for a string literal)',
                path,
            ) from exc
    if isinstance(node, list):
        raise _Fail('a list is not an expression; write {"list": [...]}', path)
    if not isinstance(node, dict):
        raise _Fail(f"expected an expression, found {_kind(node)}", path)

    ops = [k for k in node if k in _OPERATORS]
    if "in" in ops and any(k in node for k in ("collect", *QUANTIFIERS)):
        ops.remove("in")  # there it names the source, not the membership operator
    if len(ops) != 1:
        unknown = [k for k in node if k not in _OPERATORS]
        if not ops and unknown:
            raise _Fail(
                f"unknown expression operator '{unknown[0]}'{_suggest(unknown[0], _OPERATORS)}",
                path,
            )
        if not ops:
            raise _Fail("empty object is not an expression", path)
        raise _Fail(f"an expression object needs exactly one operator, found {sorted(ops)}", path)
    op = ops[0]
    arg = node[op]
    here = f"{path}.{op}"

    def only(*allowed: str) -> None:
        extra = [k for k in node if k != op and k not in allowed]
        if extra:
            raise _Fail(f"unexpected key '{extra[0]}' next to '{op}'", path)

    def sub(value: Any, where: str) -> Expr:
        return _expr(value, where, depth + 1)

    def operands(minimum: int, exact: bool) -> list[Expr]:
        if not isinstance(arg, list):
            raise _Fail(f"'{op}' takes a list of operands, found {_kind(arg)}", here)
        if len(arg) < minimum or (exact and len(arg) != minimum):
            need = f"exactly {minimum}" if exact else f"at least {minimum}"
            raise _Fail(f"'{op}' takes {need} operands, found {len(arg)}", here)
        return [sub(a, f"{here}[{i}]") for i, a in enumerate(arg)]

    if op == "value":
        only()
        if arg is not None and not isinstance(arg, (bool, int, float, str)):
            raise _Fail(
                f'"value" holds a string, number, boolean or null, found {_kind(arg)}; '
                'use {"list": [...]} or {"record": {...}}',
                here,
            )
        return Literal(arg, loc=loc)
    if op == "ref":
        only()
        if not isinstance(arg, str) or not arg:
            raise _Fail(f'"ref" takes a dotted path such as "actor.org", found {_kind(arg)}', here)
        head, *rest = arg.split(".")
        if not _is_name(head) or not all(s.isidentifier() and s.isascii() for s in rest):
            raise _Fail(f"'{arg}' is not a valid field path", here)
        expr: Expr = Ref(head, loc=loc)
        for segment in rest:
            expr = Member(expr, segment, loc=loc)
        return expr
    if op == "field":
        only("of")
        if not isinstance(arg, str) or not arg.isidentifier():
            raise _Fail(f'"field" takes a field name, found {_kind(arg)}', here)
        if "of" not in node:
            raise _Fail('"field" needs "of" (the value to read the field from)', path)
        return Member(sub(node["of"], f"{path}.of"), arg, loc=loc)
    if op == "index":
        only()
        target, key = operands(2, True)
        return Index(target, key, loc=loc)
    if op == "list":
        only()
        if not isinstance(arg, list):
            raise _Fail(f'"list" takes a list, found {_kind(arg)}', here)
        return ListExpr(tuple(sub(a, f"{here}[{i}]") for i, a in enumerate(arg)), loc=loc)
    if op == "record":
        only()
        if not isinstance(arg, dict):
            raise _Fail(f'"record" takes an object, found {_kind(arg)}', here)
        return RecordExpr(tuple((k, sub(v, f"{here}.{k}")) for k, v in arg.items()), loc=loc)
    if op == "not":
        only()
        return Unary("not", sub(arg, here), loc=loc)
    if op == "neg":
        only()
        operand = sub(arg, here)
        if (
            isinstance(operand, Literal)
            and isinstance(operand.value, (int, float))
            and not isinstance(operand.value, bool)
        ):
            return Literal(-operand.value, loc=loc)
        return Unary("-", operand, loc=loc)
    if op == "call":
        only("args")
        if not _is_name(arg):
            raise _Fail(f'"call" takes a function name, found {_kind(arg)}', here)
        args = node.get("args", [])
        if not isinstance(args, list):
            raise _Fail(f'"args" must be a list, found {_kind(args)}', f"{path}.args")
        return Call(
            arg, tuple(sub(a, f"{path}.args[{i}]") for i, a in enumerate(args)), loc=loc
        )
    if op in QUANTIFIERS:
        only("in", "where")
        if not _is_name(arg):
            raise _Fail(f'"{op}" takes the variable name, found {_kind(arg)}', here)
        for needed in ("in", "where"):
            if needed not in node:
                raise _Fail(f'"{op}" needs "{needed}"', path)
        return Quantifier(
            op, arg, sub(node["in"], f"{path}.in"), sub(node["where"], f"{path}.where"), loc=loc
        )
    if op == "collect":
        only("for", "in", "where")
        for needed in ("for", "in"):
            if needed not in node:
                raise _Fail(f'"collect" needs "{needed}"', path)
        if not _is_name(node["for"]):
            raise _Fail('"for" takes the variable name', f"{path}.for")
        condition = sub(node["where"], f"{path}.where") if "where" in node else None
        return Comprehension(
            sub(arg, here), node["for"], sub(node["in"], f"{path}.in"), condition, loc=loc
        )
    only()
    if op in _FOLDING:
        first, *others = operands(2, False)
        for other in others:
            first = Binary(op, first, other, loc=loc)
        return first
    left, right = operands(2, True)
    return Binary(op, left, right, loc=loc)


def _relocate(expr: Expr, path: str) -> Expr:
    """Parsed-from-string nodes carry text positions that mean nothing in a JSON
    file; diagnostics should name the JSON path instead."""
    from dataclasses import fields, replace

    def walk(node: Any) -> Any:
        if isinstance(node, tuple):
            return tuple(walk(n) for n in node)
        if hasattr(node, "__dataclass_fields__") and not isinstance(node, Loc):
            changes = {
                f.name: walk(getattr(node, f.name)) for f in fields(node) if f.name != "loc"
            }
            return replace(node, loc=_at(path), **changes)
        return node

    result: Expr = walk(expr)
    return result


def _text(obj: dict[str, Any], key: str, path: str, default: str | None = None) -> str:
    if key not in obj:
        if default is None:
            raise _Fail(f'missing required key "{key}"', path)
        return default
    value = obj[key]
    if not isinstance(value, str):
        raise _Fail(f'"{key}" must be a string, found {_kind(value)}', f"{path}.{key}")
    return value


def _template(obj: dict[str, Any], key: str, path: str) -> Template | None:
    if key not in obj or obj[key] is None:
        return None
    where = f"{path}.{key}"
    text = _text(obj, key, path)
    try:
        template = parse_template(text, _at(where))
    except RuleSyntaxError as exc:
        raise _Fail(exc.diagnostics[0].message, where) from exc
    parts = tuple(p if isinstance(p, str) else _relocate(p, where) for p in template.parts)
    return Template(parts, loc=_at(where))


def _rule(obj: Any, path: str) -> tuple[Rule, bool]:
    if not isinstance(obj, dict):
        raise _Fail(f"a rule must be an object, found {_kind(obj)}", path)
    for key in obj:
        if key not in RULE_KEYS:
            raise _Fail(f"unknown rule key '{key}'{_suggest(key, RULE_KEYS)}", f"{path}.{key}")
    name = _text(obj, "name", path)
    rule_id = _text(obj, "id", path, name)
    description = _text(obj, "description", path, "")
    severity = _text(obj, "severity", path, DEFAULT_SEVERITY)
    if severity not in SEVERITIES:
        raise _Fail(
            f"severity must be one of {', '.join(SEVERITIES)}; found '{severity}'"
            + _suggest(severity, SEVERITIES),
            f"{path}.severity",
        )
    enabled = obj.get("enabled", True)
    if not isinstance(enabled, bool):
        raise _Fail(f'"enabled" must be true or false, found {_kind(enabled)}', f"{path}.enabled")
    when = _expr(obj["when"], f"{path}.when") if obj.get("when") is not None else None

    bindings: list[Let | Observe] = []
    if "bindings" in obj:
        if "let" in obj or "observe" in obj:
            raise _Fail('use either "bindings" or "let"/"observe", not both', path)
        if not isinstance(obj["bindings"], list):
            raise _Fail('"bindings" must be a list', f"{path}.bindings")
        for i, item in enumerate(obj["bindings"]):
            where = f"{path}.bindings[{i}]"
            if not isinstance(item, dict) or ("let" in item) == ("observe" in item):
                raise _Fail('a binding is {"let": name, "value": expr} or '
                            '{"observe": name, "probe": name, "args": [...]}', where)  # fmt: skip
            if "let" in item:
                bindings.append(_let(item["let"], item.get("value"), "value" in item, where))
            else:
                bindings.append(_observe(item["observe"], item, where))
    else:
        lets = obj.get("let", {})
        if not isinstance(lets, dict):
            raise _Fail('"let" must be an object of name: expression', f"{path}.let")
        for let_name, value in lets.items():
            bindings.append(_let(let_name, value, True, f"{path}.let.{let_name}", nested=False))
        observes = obj.get("observe", {})
        if not isinstance(observes, dict):
            raise _Fail('"observe" must be an object of name: {"probe", "args"}', f"{path}.observe")
        for obs_name, spec in observes.items():
            bindings.append(_observe(obs_name, spec, f"{path}.observe.{obs_name}"))

    assertions: list[Assertion] = []
    if "assert" in obj:
        if "always" in obj or "never" in obj:
            raise _Fail('use either "assert" or "always"/"never", not both', path)
        if not isinstance(obj["assert"], list):
            raise _Fail('"assert" must be a list', f"{path}.assert")
        for i, item in enumerate(obj["assert"]):
            where = f"{path}.assert[{i}]"
            if not isinstance(item, dict) or len(item) != 1 or next(iter(item)) not in (
                "always", "never"
            ):  # fmt: skip
                raise _Fail('an assertion is {"always": expr} or {"never": expr}', where)
            kind = next(iter(item))
            assertions.append(
                Assertion(kind, _expr(item[kind], f"{where}.{kind}"), loc=_at(where))
            )
    else:
        for kind in ("always", "never"):
            if kind not in obj:
                continue
            value = obj[kind]
            if isinstance(value, list):
                for i, item in enumerate(value):
                    where = f"{path}.{kind}[{i}]"
                    assertions.append(Assertion(kind, _expr(item, where), loc=_at(where)))
            else:
                where = f"{path}.{kind}"
                assertions.append(Assertion(kind, _expr(value, where), loc=_at(where)))

    evidence: tuple[tuple[str, Expr], ...] | None = None
    if obj.get("evidence") is not None:
        if not isinstance(obj["evidence"], dict):
            raise _Fail('"evidence" must be an object of name: expression', f"{path}.evidence")
        evidence = tuple(
            (k, _expr(v, f"{path}.evidence.{k}")) for k, v in obj["evidence"].items()
        )
    tags_value = obj.get("tags", [])
    if not isinstance(tags_value, list) or not all(isinstance(t, str) for t in tags_value):
        raise _Fail('"tags" must be a list of strings', f"{path}.tags")
    policy_key = _text(obj, "policy", path) if "policy" in obj else None
    rule = Rule(
        name=name,
        id=rule_id,
        tags=tuple(tags_value),
        policy=policy_key,
        description=description,
        severity=severity,
        when=when,
        bindings=tuple(bindings),
        assertions=tuple(assertions),
        message=_template(obj, "message", path),
        pass_message=_template(obj, "pass_message", path),
        evidence=evidence,
        loc=_at(path),
    )
    return rule, enabled


def _let(name: Any, value: Any, present: bool, path: str, *, nested: bool = True) -> Let:
    if not _is_name(name):
        raise _Fail(f"'{name}' is not a valid name for a let binding", path)
    if not present:
        raise _Fail(f'let "{name}" needs a "value"', path)
    return Let(name, _expr(value, f"{path}.value" if nested else path), loc=_at(path))


def _observe(name: Any, spec: Any, path: str) -> Observe:
    if not _is_name(name):
        raise _Fail(f"'{name}' is not a valid name for an observation", path)
    if not isinstance(spec, dict) or not _is_name(spec.get("probe")):
        raise _Fail(f'observation "{name}" needs a "probe" name', path)
    for key in spec:
        if key not in ("observe", "probe", "args"):
            raise _Fail(f"unknown key '{key}' in observation \"{name}\"", f"{path}.{key}")
    args = spec.get("args", [])
    if not isinstance(args, list):
        raise _Fail('"args" must be a list', f"{path}.args")
    return Observe(
        name,
        spec["probe"],
        tuple(_expr(a, f"{path}.args[{i}]") for i, a in enumerate(args)),
        loc=_at(path),
    )


def rules_from_json(data: Any) -> RuleDocument:
    """Build rules from decoded JSON: ``{"rules": [...]}``, a list of rules, or one rule.

    Raises ``RuleSyntaxError`` with one diagnostic per malformed rule.
    """
    if isinstance(data, dict) and "rules" in data:
        extra = [k for k in data if k not in ("rules", "version")]
        if extra:
            raise RuleSyntaxError(
                [Diagnostic(f"unknown top-level key '{extra[0]}'", path=extra[0])]
            )
        version = data.get("version", FORMAT_VERSION)
        if version != FORMAT_VERSION:
            raise RuleSyntaxError(
                [
                    Diagnostic(
                        f"unsupported rule file version {version!r}; "
                        f"this build reads version {FORMAT_VERSION}",
                        path="version",
                    )
                ]
            )
        items, prefix = data["rules"], "rules"
        if not isinstance(items, list):
            raise RuleSyntaxError(
                [Diagnostic(f'"rules" must be a list, found {_kind(items)}', path="rules")]
            )
    elif isinstance(data, list):
        items, prefix = data, ""
    elif isinstance(data, dict):
        items, prefix = [data], ""
    else:
        raise RuleSyntaxError(
            [Diagnostic(f'expected {{"rules": [...]}} or a rule object, found {_kind(data)}')]
        )
    if not items:
        raise RuleSyntaxError([Diagnostic("the file defines no rules", path=prefix or None)])

    rules: list[Rule] = []
    disabled: set[str] = set()
    problems: list[Diagnostic] = []
    for i, item in enumerate(items):
        path = f"{prefix}[{i}]" if (prefix or len(items) > 1 or isinstance(data, list)) else ""
        try:
            rule, enabled = _rule(item, path)
        except _Fail as fail:
            named = item.get("name") if isinstance(item, dict) else None
            d = fail.diagnostic
            problems.append(
                Diagnostic(d.message, path=d.path, rule=named if isinstance(named, str) else None)
            )
            continue
        rules.append(rule)
        if not enabled:
            disabled.add(rule.id)
    if problems:
        raise RuleSyntaxError(problems)
    return RuleDocument(tuple(rules), frozenset(disabled))


def loads(text: str) -> RuleDocument:
    """Parse the contents of a JSON rule file."""
    if len(text) > MAX_SOURCE_CHARS:
        raise RuleSyntaxError(
            [Diagnostic(f"rule file is larger than {MAX_SOURCE_CHARS} characters")]
        )
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise RuleSyntaxError(
            [Diagnostic(f"not valid JSON: {exc.msg}", line=exc.lineno, col=exc.colno)]
        ) from exc
    except RecursionError as exc:
        raise RuleSyntaxError([Diagnostic("JSON is nested too deeply")]) from exc
    return rules_from_json(data)


# -- writing ----------------------------------------------------------------


def expr_to_json(expr: Expr) -> Any:
    """Canonical structured form (never an expression string)."""
    match expr:
        case Literal():
            return {"value": expr.value} if isinstance(expr.value, str) else expr.value
        case Ref():
            return {"ref": expr.name}
        case Member():
            path = [expr.name]
            target = expr.target
            while isinstance(target, Member):
                path.append(target.name)
                target = target.target
            if isinstance(target, Ref) and all(p.isidentifier() and p.isascii() for p in path):
                return {"ref": ".".join([target.name, *reversed(path)])}
            return {"field": expr.name, "of": expr_to_json(expr.target)}
        case Index():
            return {"index": [expr_to_json(expr.target), expr_to_json(expr.key)]}
        case ListExpr():
            return {"list": [expr_to_json(i) for i in expr.items]}
        case RecordExpr():
            return {"record": {k: expr_to_json(v) for k, v in expr.fields}}
        case Unary():
            return {("not" if expr.op == "not" else "neg"): expr_to_json(expr.operand)}
        case Binary():
            return {expr.op: [expr_to_json(expr.left), expr_to_json(expr.right)]}
        case Call():
            return {"call": expr.function, "args": [expr_to_json(a) for a in expr.args]}
        case Quantifier():
            return {
                expr.kind: expr.var,
                "in": expr_to_json(expr.source),
                "where": expr_to_json(expr.condition),
            }
        case Comprehension():
            out = {
                "collect": expr_to_json(expr.value),
                "for": expr.var,
                "in": expr_to_json(expr.source),
            }
            if expr.condition is not None:
                out["where"] = expr_to_json(expr.condition)
            return out
    raise TypeError(f"not an expression: {expr!r}")


def rule_to_json(rule: Rule, *, enabled: bool = True) -> dict[str, Any]:
    """A rule in the JSON rule format."""
    out: dict[str, Any] = {"name": rule.name}
    if rule.id != rule.name:
        out["id"] = rule.id
    if rule.policy is not None:
        out["policy"] = rule.policy
    if rule.tags:
        out["tags"] = list(rule.tags)
    if rule.description:
        out["description"] = rule.description
    out["severity"] = rule.severity
    if not enabled:
        out["enabled"] = False
    if rule.when is not None:
        out["when"] = expr_to_json(rule.when)
    if rule.bindings:
        out["bindings"] = [
            {"let": b.name, "value": expr_to_json(b.value)}
            if isinstance(b, Let)
            else {"observe": b.name, "probe": b.probe, "args": [expr_to_json(a) for a in b.args]}
            for b in rule.bindings
        ]
    out["assert"] = [{a.kind: expr_to_json(a.condition)} for a in rule.assertions]
    if rule.message is not None:
        out["message"] = format_template(rule.message)
    if rule.pass_message is not None:
        out["pass_message"] = format_template(rule.pass_message)
    if rule.evidence is not None:
        out["evidence"] = {k: expr_to_json(v) for k, v in rule.evidence}
    return out


def document_to_json(
    rules: tuple[Rule, ...] | list[Rule], disabled: frozenset[str] | set[str] = frozenset()
) -> dict[str, Any]:
    """A whole document in the JSON rule format."""
    return {
        "version": FORMAT_VERSION,
        "rules": [rule_to_json(r, enabled=r.id not in disabled) for r in rules],
    }
