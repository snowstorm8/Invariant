"""The text front end: tokens, grammar, error reporting and round-tripping."""

import pytest

from invariant.console.app import EXAMPLES
from invariant.integrations.builtin_rules import builtin_document
from invariant.rules import (
    RuleSyntaxError,
    format_expr,
    format_rule,
    format_rules,
    parse_expression,
    parse_rules,
)
from invariant.rules.ir import (
    Assertion,
    Binary,
    Call,
    Comprehension,
    Index,
    Let,
    ListExpr,
    Literal,
    Member,
    Observe,
    Quantifier,
    RecordExpr,
    Ref,
    Unary,
)

FULL = '''
# every clause, once
rule "full-example" {
    id "FE-1"
    description "Shows every clause."
    severity high
    when operation.type == "read_document" and actor.role in ["viewer", "member"]
    let foreign = [d.ref for d in state.documents where d.org != actor.org]   // comment
    observe listing = org_documents(actor.org)
    always count(listing) >= 0
    assert has(response.status)
    never contains(response.body, 'secret')
    message "{actor.ref} saw {count(foreign)} foreign docs: {join(foreign, ', ')} {{literal}}"
    pass_message "nothing leaked to {actor.ref}"
    evidence { foreign: foreign, "status code": response.status }
}
'''


def only(source):
    (rule,) = parse_rules(source).rules
    return rule


def test_every_clause_is_parsed_into_the_ir():
    rule = only(FULL)
    assert (rule.name, rule.id, rule.severity) == ("full-example", "FE-1", "high")
    assert rule.description == "Shows every clause."
    assert rule.when == Binary(
        "and",
        Binary("==", Member(Ref("operation"), "type"), Literal("read_document")),
        Binary("in", Member(Ref("actor"), "role"), ListExpr((Literal("viewer"), Literal("member")))),
    )
    assert rule.bindings == (
        Let(
            "foreign",
            Comprehension(
                Member(Ref("d"), "ref"),
                "d",
                Member(Ref("state"), "documents"),
                Binary("!=", Member(Ref("d"), "org"), Member(Ref("actor"), "org")),
            ),
        ),
        Observe("listing", "org_documents", (Member(Ref("actor"), "org"),)),
    )
    # 'assert' is an alias of 'always'; order is preserved.
    assert [a.kind for a in rule.assertions] == ["always", "always", "never"]
    assert rule.assertions[2] == Assertion(
        "never", Call("contains", (Member(Ref("response"), "body"), Literal("secret")))
    )
    assert rule.message.parts == (
        Member(Ref("actor"), "ref"),
        " saw ",
        Call("count", (Ref("foreign"),)),
        " foreign docs: ",
        Call("join", (Ref("foreign"), Literal(", "))),
        " {literal}",
    )
    assert rule.pass_message.parts == ("nothing leaked to ", Member(Ref("actor"), "ref"))
    assert rule.evidence == (("foreign", Ref("foreign")), ("status code", Member(Ref("response"), "status")))


def test_defaults_for_a_minimal_rule():
    rule = only('rule "tiny" { always true }')
    assert (rule.id, rule.severity, rule.description, rule.when) == ("tiny", "medium", "", None)
    assert rule.bindings == () and rule.message is None and rule.evidence is None


def test_several_rules_in_one_source_keep_their_order():
    doc = parse_rules('rule "a" { always true }\n\nrule "b" { never false }')
    assert [r.name for r in doc.rules] == ["a", "b"]


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        ("a or b and c", Binary("or", Ref("a"), Binary("and", Ref("b"), Ref("c")))),
        ("not a == b", Unary("not", Binary("==", Ref("a"), Ref("b")))),
        ("a implies b implies c", Binary("implies", Ref("a"), Binary("implies", Ref("b"), Ref("c")))),
        ("a and b implies c or d", Binary("implies", Binary("and", Ref("a"), Ref("b")), Binary("or", Ref("c"), Ref("d")))),
        ("1 + 2 * 3", Binary("+", Literal(1), Binary("*", Literal(2), Literal(3)))),
        ("(1 + 2) * 3", Binary("*", Binary("+", Literal(1), Literal(2)), Literal(3))),
        ("a - b - c", Binary("-", Binary("-", Ref("a"), Ref("b")), Ref("c"))),
        ("-1", Literal(-1)),
        ("-x.y", Unary("-", Member(Ref("x"), "y"))),
        ("x not in ys", Unary("not", Binary("in", Ref("x"), Ref("ys")))),
        ('m["k"].v[0]', Index(Member(Index(Ref("m"), Literal("k")), "v"), Literal(0))),
        ("a.id", Member(Ref("a"), "id")),  # clause words are fine as field names
        ("a.in", Member(Ref("a"), "in")),
        ("{a: 1, 'b c': x}", RecordExpr((("a", Literal(1)), ("b c", Ref("x"))))),
        ("[]", ListExpr(())),
        ("[1, 2.5, true, false, null]", ListExpr((Literal(1), Literal(2.5), Literal(True), Literal(False), Literal(None)))),
        ("some e in events : e.ok and x", Quantifier("some", "e", Ref("events"), Binary("and", Member(Ref("e"), "ok"), Ref("x")))),
        ("a and none e in events : e.ok", Binary("and", Ref("a"), Quantifier("none", "e", Ref("events"), Member(Ref("e"), "ok")))),
        ("[x * 2 for x in xs]", Comprehension(Binary("*", Ref("x"), Literal(2)), "x", Ref("xs"), None)),
        (r'"a\"b\nA"', Literal('a"b\nA')),
    ],
)
def test_expression_grammar(source, expected):
    assert parse_expression(source) == expected


def test_true_and_one_are_different_literals():
    assert parse_expression("true") != parse_expression("1")
    assert parse_expression("1") == parse_expression("1")


def test_locations_are_recorded_but_ignored_by_equality():
    a = parse_expression("actor.org")
    b = parse_expression("\n\n   actor.org")
    assert a == b and a.loc != b.loc
    assert (b.loc.line, b.loc.col) == (3, 10)


CORPUS = [FULL, *(e["source"] for e in EXAMPLES), format_rules(builtin_document().rules)]


@pytest.mark.parametrize("source", CORPUS)
def test_printing_a_rule_and_parsing_it_again_gives_the_same_rule(source):
    rules = parse_rules(source).rules
    printed = format_rules(rules)
    assert parse_rules(printed).rules == rules
    assert format_rules(parse_rules(printed).rules) == printed  # and printing is stable


@pytest.mark.parametrize(
    "source",
    [
        "(a or b) and c", "a or b and c", "not (a and b)", "(not a) == b", "a - (b - c)",
        "(a implies b) implies c", "(some x in xs : x) and y", "-(a + b)", "(a + b).c",
        "[y for y in (a + b) where some z in y : z]", "x in (a + b)", "a == (b in c)",
        '"quote \\" and \'single\'"', "1.5 * -2",
    ],
)  # fmt: skip
def test_printer_keeps_grouping(source):
    expr = parse_expression(source)
    assert parse_expression(format_expr(expr)) == expr
    assert parse_expression(format_expr(expr, "'")) == expr


# -- rejection ---------------------------------------------------------------

BAD = [
    ('rule "x" { always }', "expected a value", 1),
    ('rule "x" { always a = b }', "use '=='", 1),
    ('rule "x" { always a == b == c }', "cannot be chained", 1),
    ('rule "x" { always a && b }', "use 'and', 'or', 'not'", 1),
    ('rule "x" {\n  severity urgent\n  always true }', "severity must be one of critical, high, medium, low, info", 2),
    ('rule "x" {\n  wen true\n}', "expected a clause", 2),
    ('rule "x" {\n  when a\n  when b\n  always true }', "duplicate 'when' clause (combine conditions with 'and')", 3),
    ('rule "x" { always "unterminated }', "unterminated string", 1),
    ('rule "x" { always true', "missing '}'", 1),
    ('rule x { always true }', "expected the rule name in quotes", 1),
    ('always true', "expected 'rule'", 1),
    ('rule "x" { let in = 1 always true }', "'in' is a reserved word", 1),
    ('rule "x" { always some x xs : x }', "expected 'in' after 'some x'", 1),
    ('rule "x" { always [x for y] }', "expected 'in' after 'for y'", 1),
    ('rule "x" { always f(1, }', "expected a value", 1),
    ('rule "x" { always true message "{actor.}" }', "in message placeholder", 1),
    ('rule "x" { always true message "open { brace" }', "unclosed '{'", 1),
    ('rule "x" { always true message "stray } brace" }', "unmatched '}'", 1),
    ('rule "x" { always 12abc }', "malformed number", 1),
    ('rule "x" { always "\\q" }', "unknown escape", 1),
    ('rule "x" { evidence { a: 1, a: 2 } always true }', "duplicate field 'a'", 1),
    ("", "no rule found", 1),
    ("   # only a comment\n", "no rule found", 1),
]


@pytest.mark.parametrize(("source", "message", "line"), BAD)
def test_malformed_rules_are_rejected_with_a_located_message(source, message, line):
    with pytest.raises(RuleSyntaxError) as caught:
        parse_rules(source)
    (first, *_) = caught.value.diagnostics
    assert message in first.message
    assert first.line == line and first.col is not None


def test_every_malformed_rule_in_a_file_is_reported_and_good_ones_do_not_hide_them():
    source = 'rule "a" { always }\nrule "ok" { always true }\nrule "c" {\n never a = 1 }'
    with pytest.raises(RuleSyntaxError) as caught:
        parse_rules(source)
    assert [(d.line, d.message.split(";")[0][:20]) for d in caught.value.diagnostics] == [
        (1, "unexpected '}'"),
        (4, "use '==' to compare "),
    ]


def test_deeply_nested_input_is_refused_instead_of_overflowing_the_stack():
    with pytest.raises(RuleSyntaxError, match="nested more than"):
        parse_rules('rule "x" { always ' + "(" * 500 + "true" + ")" * 500 + " }")
    with pytest.raises(RuleSyntaxError, match="nested more than"):
        parse_rules('rule "x" { always ' + "not " * 500 + "true }")


def test_oversized_source_is_refused():
    with pytest.raises(RuleSyntaxError, match="larger than"):
        parse_rules("#" * 300_000)


def test_format_rule_omits_what_is_default():
    assert format_rule(only('rule "tiny" { always true }')) == (
        'rule "tiny" {\n    severity medium\n    always true\n}'
    )
