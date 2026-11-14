"""Recursive-descent parser for the rule language.

    rule "tenant-read-isolation" {
        id "TI-1"
        description "..."
        severity critical
        when operation.type == "read_document"
        let leaked = [d.ref for d in state.documents where d.org != actor.org]
        observe listing = org_documents(actor.org)
        always response.status == 200 implies response.json.org_id == actor.org_id
        never count(leaked) > 0
        message "{actor.ref} received {join(leaked, ', ')}"
        pass_message "nothing leaked"
        evidence { leaked: leaked, status: response.status }
    }

Expression precedence, loosest first: quantifier (``some x in xs : cond``),
``implies``, ``or``, ``and``, ``not``, comparison (``== != < <= > >= in``),
``+ -``, ``*``, unary ``-``, then ``.field``, ``[index]`` and calls.
"""

from __future__ import annotations

from .errors import Diagnostic, RuleSyntaxError
from .ir import (
    ASSERTION_KINDS,
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
from .lexer import Token, tokenize

#: Words that are operators or literals and can never be used as a name.
RESERVED = frozenset(
    {"and", "or", "not", "implies", "in", "for", "where", "true", "false", "null", *QUANTIFIERS}
)
#: Words that start a clause inside a rule body.
CLAUSES = (
    "id", "tags", "policy", "description", "severity", "when", "let", "observe",
    "always", "assert", "never", "message", "pass_message", "evidence",
)  # fmt: skip
COMPARISONS = ("==", "!=", "<", "<=", ">", ">=")
#: Deepest expression nesting accepted (bounds recursion on hostile input).
MAX_DEPTH = 64


class _Fail(Exception):
    def __init__(self, message: str, token: Token) -> None:
        super().__init__(message)
        self.diagnostic = Diagnostic(message, line=token.line, col=token.col)


class Parser:
    """Recursive-descent parser for the rule language."""
    def __init__(self, tokens: list[Token]) -> None:
        self.tokens = tokens
        self.pos = 0
        self.depth = 0

    # -- token helpers -------------------------------------------------------

    @property
    def tok(self) -> Token:
        """The current token."""
        return self.tokens[self.pos]

    def advance(self) -> Token:
        """Consume and return the current token."""
        token = self.tok
        if token.kind != "eof":
            self.pos += 1
        return token

    def at_punct(self, value: str) -> bool:
        """True if the current token is this punctuation."""
        return self.tok.kind == "punct" and self.tok.value == value

    def at_word(self, value: str) -> bool:
        """True if the current token is this keyword."""
        return self.tok.kind == "ident" and self.tok.value == value

    def eat_punct(self, value: str) -> bool:
        """Consume the punctuation if present; report whether it was."""
        if self.at_punct(value):
            self.pos += 1
            return True
        return False

    def eat_word(self, value: str) -> bool:
        """Consume the keyword if present; report whether it was."""
        if self.at_word(value):
            self.pos += 1
            return True
        return False

    def expect_punct(self, value: str, context: str) -> Token:
        """Consume the punctuation or raise a syntax error naming ``context``."""
        if not self.at_punct(value):
            raise _Fail(f"expected '{value}' {context}, found {self.tok.describe()}", self.tok)
        return self.advance()

    def expect_string(self, what: str) -> Token:
        """Consume a string literal or raise a syntax error."""
        if self.tok.kind != "string":
            raise _Fail(f"expected {what} in quotes, found {self.tok.describe()}", self.tok)
        return self.advance()

    def expect_name(self, what: str) -> Token:
        """Consume a name or raise a syntax error."""
        token = self.tok
        if token.kind != "ident":
            raise _Fail(f"expected {what}, found {token.describe()}", token)
        if token.value in RESERVED:
            raise _Fail(f"'{token.value}' is a reserved word and cannot be used as {what}", token)
        return self.advance()

    @staticmethod
    def loc(token: Token) -> Loc:
        """The source position of a token."""
        return Loc(line=token.line, col=token.col)

    # -- document ------------------------------------------------------------

    def document(self) -> RuleDocument:
        """Parse a whole document of rules."""
        rules: list[Rule] = []
        problems: list[Diagnostic] = []
        while self.tok.kind != "eof":
            try:
                rules.append(self.rule())
            except _Fail as fail:
                problems.append(fail.diagnostic)
                self._skip_to_next_rule()
        if problems:
            raise RuleSyntaxError(problems)
        if not rules:
            raise RuleSyntaxError(
                [Diagnostic('no rule found; a rule starts with: rule "name" {', line=1, col=1)]
            )
        return RuleDocument(tuple(rules))

    def _skip_to_next_rule(self) -> None:
        """Error recovery: resume at the next ``rule "name"`` so later rules are still checked."""
        self.advance()
        while self.tok.kind != "eof":
            nxt = self.tokens[self.pos + 1]
            if self.at_word("rule") and nxt.kind == "string":
                return
            self.pos += 1

    def rule(self) -> Rule:
        """Parse one ``rule "name" { ... }`` block."""
        start = self.tok
        if not self.eat_word("rule"):
            raise _Fail(f"expected 'rule', found {start.describe()}", start)
        name = str(self.expect_string("the rule name").value)
        self.expect_punct("{", "to open the rule body")
        rule_id: str | None = None
        policy: str | None = None
        tags: list[str] = []
        description: str | None = None
        severity: str | None = None
        when: Expr | None = None
        bindings: list[Let | Observe] = []
        assertions: list[Assertion] = []
        message: Template | None = None
        pass_message: Template | None = None
        evidence: tuple[tuple[str, Expr], ...] | None = None
        seen: set[str] = set()

        def once(token: Token, hint: str = "") -> None:
            word = str(token.value)
            if word in seen:
                raise _Fail(f"duplicate '{word}' clause{hint}", token)
            seen.add(word)

        while not self.at_punct("}"):
            token = self.tok
            if token.kind == "eof":
                raise _Fail(f"rule \"{name}\" is not closed: missing '}}'", token)
            if token.kind != "ident" or token.value not in CLAUSES:
                raise _Fail(
                    f"expected a clause ({', '.join(CLAUSES)}) or '}}', found {token.describe()}",
                    token,
                )
            self.advance()
            match token.value:
                case "id":
                    once(token)
                    rule_id = str(self.expect_string("the rule id").value)
                case "policy":
                    once(token)
                    policy = str(self.expect_string("the policy key").value)
                case "tags":
                    once(token)
                    tags.append(str(self.expect_string("a tag").value))
                    while self.eat_punct(","):
                        tags.append(str(self.expect_string("a tag").value))
                case "description":
                    once(token)
                    description = str(self.expect_string("the description").value)
                case "severity":
                    once(token)
                    level = self.tok
                    if level.kind not in ("ident", "string") or level.value not in SEVERITIES:
                        raise _Fail(
                            f"severity must be one of {', '.join(SEVERITIES)}; "
                            f"found {level.describe()}",
                            level,
                        )
                    self.advance()
                    severity = str(level.value)
                case "when":
                    once(token, " (combine conditions with 'and')")
                    when = self.expression()
                case "let":
                    name_tok = self.expect_name("a name after 'let'")
                    self.expect_punct("=", "after the let name")
                    bindings.append(
                        Let(str(name_tok.value), self.expression(), loc=self.loc(name_tok))
                    )
                case "observe":
                    name_tok = self.expect_name("a name after 'observe'")
                    self.expect_punct("=", "after the observation name")
                    probe = self.expect_name("a probe name")
                    self.expect_punct("(", "after the probe name")
                    args = self._arguments(")")
                    bindings.append(
                        Observe(
                            str(name_tok.value), str(probe.value), args, loc=self.loc(name_tok)
                        )
                    )
                case "always" | "assert" | "never":
                    kind = "never" if token.value == "never" else "always"
                    assertions.append(Assertion(kind, self.expression(), loc=self.loc(token)))
                case "message":
                    once(token)
                    message = self._template("the message")
                case "pass_message":
                    once(token)
                    pass_message = self._template("the pass message")
                case "evidence":
                    once(token)
                    self.expect_punct("{", "after 'evidence'")
                    evidence = self._fields()
        self.expect_punct("}", "to close the rule")
        return Rule(
            name=name,
            id=rule_id if rule_id is not None else name,
            description=description or "",
            severity=severity or DEFAULT_SEVERITY,
            when=when,
            bindings=tuple(bindings),
            assertions=tuple(assertions),
            message=message,
            pass_message=pass_message,
            evidence=evidence,
            tags=tuple(tags),
            policy=policy,
            loc=self.loc(start),
        )

    def _template(self, what: str) -> Template:
        token = self.expect_string(what)
        try:
            return parse_template(str(token.value), self.loc(token))
        except RuleSyntaxError as exc:
            raise _Fail(exc.diagnostics[0].message, token) from exc

    def _fields(self) -> tuple[tuple[str, Expr], ...]:
        """``name: expr, ...}`` (the opening brace is already consumed)."""
        fields: list[tuple[str, Expr]] = []
        names: set[str] = set()
        while not self.at_punct("}"):
            key = self.tok
            if key.kind not in ("ident", "string"):
                raise _Fail(f"expected a field name, found {key.describe()}", key)
            self.advance()
            if key.value in names:
                raise _Fail(f"duplicate field '{key.value}'", key)
            names.add(str(key.value))
            self.expect_punct(":", f"after field name '{key.value}'")
            fields.append((str(key.value), self.expression()))
            if not self.eat_punct(","):
                break
        self.expect_punct("}", "to close the field list")
        return tuple(fields)

    def _arguments(self, closer: str) -> tuple[Expr, ...]:
        args: list[Expr] = []
        while not self.at_punct(closer):
            args.append(self.expression())
            if not self.eat_punct(","):
                break
        self.expect_punct(closer, "to close the list")
        return tuple(args)

    # -- expressions ---------------------------------------------------------

    def expression(self) -> Expr:
        """Parse an expression (loosest to tightest: implies, or, and, not, comparison, arithmetic)."""
        self.depth += 1
        if self.depth > MAX_DEPTH:
            raise _Fail(f"expression is nested more than {MAX_DEPTH} levels deep", self.tok)
        try:
            return self._implies()
        finally:
            self.depth -= 1

    def _implies(self) -> Expr:
        left = self._or()
        token = self.tok
        if self.eat_word("implies"):
            return Binary("implies", left, self.expression(), loc=self.loc(token))
        return left

    def _or(self) -> Expr:
        left = self._and()
        while self.at_word("or"):
            token = self.advance()
            left = Binary("or", left, self._and(), loc=self.loc(token))
        return left

    def _and(self) -> Expr:
        left = self._not()
        while self.at_word("and"):
            token = self.advance()
            left = Binary("and", left, self._not(), loc=self.loc(token))
        return left

    def _not(self) -> Expr:
        token = self.tok
        if self.eat_word("not"):
            self.depth += 1
            if self.depth > MAX_DEPTH:
                raise _Fail(f"expression is nested more than {MAX_DEPTH} levels deep", token)
            try:
                return Unary("not", self._not(), loc=self.loc(token))
            finally:
                self.depth -= 1
        if token.kind == "ident" and token.value in QUANTIFIERS:
            self.advance()
            var = self.expect_name(f"a variable name after '{token.value}'")
            if not self.eat_word("in"):
                raise _Fail(
                    f"expected 'in' after '{token.value} {var.value}', found {self.tok.describe()}",
                    self.tok,
                )
            source = self._additive()
            self.expect_punct(":", f"before the condition of '{token.value}'")
            return Quantifier(
                str(token.value), str(var.value), source, self.expression(), loc=self.loc(token)
            )
        return self._comparison()

    def _comparison(self) -> Expr:
        left = self._additive()
        token = self.tok
        op: str | None = None
        negate = False
        if token.kind == "punct" and token.value in COMPARISONS:
            op = str(self.advance().value)
        elif self.at_word("in"):
            self.advance()
            op = "in"
        elif self.at_word("not") and self.tokens[self.pos + 1].value == "in":
            self.pos += 2
            op, negate = "in", True
        elif self.at_punct("="):
            raise _Fail("use '==' to compare ('=' is only used by let and observe)", token)
        if op is None:
            return left
        right = self._additive()
        after = self.tok
        if (after.kind == "punct" and after.value in COMPARISONS) or self.at_word("in"):
            raise _Fail("comparisons cannot be chained; join them with 'and'", after)
        result: Expr = Binary(op, left, right, loc=self.loc(token))
        return Unary("not", result, loc=self.loc(token)) if negate else result

    def _additive(self) -> Expr:
        left = self._multiplicative()
        while self.at_punct("+") or self.at_punct("-"):
            token = self.advance()
            left = Binary(str(token.value), left, self._multiplicative(), loc=self.loc(token))
        return left

    def _multiplicative(self) -> Expr:
        left = self._unary()
        while self.at_punct("*"):
            token = self.advance()
            left = Binary("*", left, self._unary(), loc=self.loc(token))
        return left

    def _unary(self) -> Expr:
        token = self.tok
        if self.eat_punct("-"):
            number = self.tok
            if number.kind == "number":
                self.advance()
                assert not isinstance(number.value, str)
                return self._postfix(Literal(-number.value, loc=self.loc(token)))
            self.depth += 1
            if self.depth > MAX_DEPTH:
                raise _Fail(f"expression is nested more than {MAX_DEPTH} levels deep", token)
            try:
                return Unary("-", self._unary(), loc=self.loc(token))
            finally:
                self.depth -= 1
        return self._postfix(self._primary())

    def _postfix(self, node: Expr) -> Expr:
        while True:
            token = self.tok
            if self.eat_punct("."):
                name = self.tok
                if name.kind != "ident":  # any word is a valid field name after '.'
                    raise _Fail(f"expected a field name after '.', found {name.describe()}", name)
                self.advance()
                node = Member(node, str(name.value), loc=self.loc(name))
            elif self.eat_punct("["):
                key = self.expression()
                self.expect_punct("]", "to close the index")
                node = Index(node, key, loc=self.loc(token))
            else:
                return node

    def _primary(self) -> Expr:
        token = self.tok
        loc = self.loc(token)
        if token.kind == "number":
            self.advance()
            assert not isinstance(token.value, str)
            return Literal(token.value, loc=loc)
        if token.kind == "string":
            self.advance()
            return Literal(str(token.value), loc=loc)
        if token.kind == "ident":
            word = str(token.value)
            if word in ("true", "false"):
                self.advance()
                return Literal(word == "true", loc=loc)
            if word == "null":
                self.advance()
                return Literal(None, loc=loc)
            if word in RESERVED:
                raise _Fail(f"unexpected '{word}'; expected a value", token)
            self.advance()
            if self.eat_punct("("):
                return Call(word, self._arguments(")"), loc=loc)
            return Ref(word, loc=loc)
        if self.eat_punct("("):
            inner = self.expression()
            self.expect_punct(")", "to close the parenthesis")
            return inner
        if self.eat_punct("["):
            if self.eat_punct("]"):
                return ListExpr((), loc=loc)
            first = self.expression()
            if self.eat_word("for"):
                var = self.expect_name("a variable name after 'for'")
                if not self.eat_word("in"):
                    raise _Fail(
                        f"expected 'in' after 'for {var.value}', found {self.tok.describe()}",
                        self.tok,
                    )
                source = self._additive()
                condition = self.expression() if self.eat_word("where") else None
                self.expect_punct("]", "to close the comprehension")
                return Comprehension(first, str(var.value), source, condition, loc=loc)
            items = [first]
            while self.eat_punct(","):
                if self.at_punct("]"):
                    break
                items.append(self.expression())
            self.expect_punct("]", "to close the list")
            return ListExpr(tuple(items), loc=loc)
        if self.eat_punct("{"):
            return RecordExpr(self._fields(), loc=loc)
        if token.kind == "eof":
            raise _Fail("unexpected end of input; expected a value", token)
        raise _Fail(f"unexpected {token.describe()}; expected a value", token)


def parse_rules(source: str) -> RuleDocument:
    """Parse rule-language text. Raises ``RuleSyntaxError`` listing every malformed rule."""
    return Parser(tokenize(source)).document()


def parse_expression(source: str, *, line: int = 1, col: int = 1) -> Expr:
    """Parse one expression (used for JSON expression strings and message templates)."""
    parser = Parser(tokenize(source, line=line, col=col))
    try:
        expr = parser.expression()
        if parser.tok.kind != "eof":
            raise _Fail(f"unexpected {parser.tok.describe()} after the expression", parser.tok)
    except _Fail as fail:
        raise RuleSyntaxError([fail.diagnostic]) from fail
    return expr


def parse_template(text: str, loc: Loc | None = None) -> Template:
    """Split message text into literal parts and ``{expression}`` holes.

    ``{{`` and ``}}`` stand for literal braces.
    """
    line = loc.line if loc and loc.line else 1
    col = loc.col if loc and loc.col else 1
    parts: list[str | Expr] = []
    buf: list[str] = []
    i, n = 0, len(text)

    def fail(message: str) -> RuleSyntaxError:
        return RuleSyntaxError([Diagnostic(message, line=line, col=col)])

    while i < n:
        ch = text[i]
        if text.startswith("{{", i) or text.startswith("}}", i):
            buf.append(ch)
            i += 2
        elif ch == "}":
            raise fail("unmatched '}' in message (write '}}' for a literal brace)")
        elif ch == "{":
            depth, j, quote = 1, i + 1, ""
            while j < n and depth:
                c = text[j]
                if quote:
                    if c == "\\":
                        j += 1
                    elif c == quote:
                        quote = ""
                elif c in "\"'":
                    quote = c
                elif c == "{":
                    depth += 1
                elif c == "}":
                    depth -= 1
                j += 1
            if depth:
                raise fail("unclosed '{' in message (write '{{' for a literal brace)")
            inner = text[i + 1 : j - 1]
            if not inner.strip():
                raise fail("empty '{}' in message")
            try:
                expr = parse_expression(inner, line=line, col=col)
            except RuleSyntaxError as exc:
                raise fail(
                    f"in message placeholder {{{inner}}}: {exc.diagnostics[0].message}"
                ) from exc
            if buf:
                parts.append("".join(buf))
                buf = []
            parts.append(expr)
            i = j
        else:
            buf.append(ch)
            i += 1
    if buf:
        parts.append("".join(buf))
    return Template(tuple(parts), loc=loc)


__all__ = ["ASSERTION_KINDS", "CLAUSES", "RESERVED", "parse_expression", "parse_rules", "parse_template"]
