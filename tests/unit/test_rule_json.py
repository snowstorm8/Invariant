"""The JSON front end: it must produce the same IR as the text language."""

import json

import pytest

from invariant.console.app import EXAMPLES
from invariant.integrations.builtin_rules import builtin_document
from invariant.rules import (
    RuleSyntaxError,
    document_to_json,
    loads,
    parse_rules,
    rule_to_json,
    rules_from_json,
)
from invariant.rules.ir import Binary, Literal, Member, Ref

TEXT = '''
rule "read-returns-own-tenant" {
    id "CUSTOM-1"
    description "A read must return a document of the reader's organization."
    severity critical
    when operation.type == "read_document" and not (actor.role in ["admin"])
    let seen = [e.operation.target for e in events where e.policy.allowed]
    observe listing = org_documents(actor.org)
    always has(response.json.org_id) implies response.json.org_id == actor.org_id
    never count(listing) < 0 or (some e in events : e.response.status >= 500)
    message "{actor.ref} got {response.json.org_id} after {count(seen)} reads"
    pass_message "ok"
    evidence { seen: seen, first: first(seen), n: -1 }
}
'''

STRUCTURED = {
    "version": 1,
    "rules": [
        {
            "name": "read-returns-own-tenant",
            "id": "CUSTOM-1",
            "description": "A read must return a document of the reader's organization.",
            "severity": "critical",
            "when": {
                "and": [
                    {"==": [{"ref": "operation.type"}, {"value": "read_document"}]},
                    {"not": {"in": [{"ref": "actor.role"}, {"list": [{"value": "admin"}]}]}},
                ]
            },
            "bindings": [
                {
                    "let": "seen",
                    "value": {
                        "collect": {"ref": "e.operation.target"},
                        "for": "e",
                        "in": {"ref": "events"},
                        "where": {"ref": "e.policy.allowed"},
                    },
                },
                {"observe": "listing", "probe": "org_documents", "args": [{"ref": "actor.org"}]},
            ],
            "assert": [
                {
                    "always": {
                        "implies": [
                            {"call": "has", "args": [{"ref": "response.json.org_id"}]},
                            {"==": [{"ref": "response.json.org_id"}, {"ref": "actor.org_id"}]},
                        ]
                    }
                },
                {
                    "never": {
                        "or": [
                            {"<": [{"call": "count", "args": [{"ref": "listing"}]}, 0]},
                            {
                                "some": "e",
                                "in": {"ref": "events"},
                                "where": {">=": [{"ref": "e.response.status"}, 500]},
                            },
                        ]
                    }
                },
            ],
            "message": "{actor.ref} got {response.json.org_id} after {count(seen)} reads",
            "pass_message": "ok",
            "evidence": {
                "seen": {"ref": "seen"},
                "first": {"call": "first", "args": [{"ref": "seen"}]},
                "n": {"neg": 1},
            },
        }
    ],
}

#: The same rule again, using the conveniences: expression strings and the
#: let / observe / always / never shorthands.
SHORTHAND = {
    "name": "read-returns-own-tenant",
    "id": "CUSTOM-1",
    "description": "A read must return a document of the reader's organization.",
    "severity": "critical",
    "when": "operation.type == 'read_document' and not (actor.role in ['admin'])",
    "let": {"seen": "[e.operation.target for e in events where e.policy.allowed]"},
    "observe": {"listing": {"probe": "org_documents", "args": ["actor.org"]}},
    "always": "has(response.json.org_id) implies response.json.org_id == actor.org_id",
    "never": ["count(listing) < 0 or (some e in events : e.response.status >= 500)"],
    "message": "{actor.ref} got {response.json.org_id} after {count(seen)} reads",
    "pass_message": "ok",
    "evidence": {"seen": "seen", "first": "first(seen)", "n": -1},
}


def test_structured_json_builds_the_same_ir_as_text():
    assert rules_from_json(STRUCTURED).rules == parse_rules(TEXT).rules


def test_shorthand_json_builds_the_same_ir_as_text():
    assert rules_from_json(SHORTHAND).rules == parse_rules(TEXT).rules


def test_a_file_may_be_a_document_a_list_or_a_single_rule():
    rule = STRUCTURED["rules"][0]
    expected = parse_rules(TEXT).rules
    assert loads(json.dumps(STRUCTURED)).rules == expected
    assert loads(json.dumps([rule])).rules == expected
    assert loads(json.dumps(rule)).rules == expected


def test_bare_scalars_are_literals_and_strings_are_expressions():
    doc = rules_from_json({"name": "r", "always": {"==": [{"ref": "a.b"}, {"value": "a.b"}]}})
    assert doc.rules[0].assertions[0].condition == Binary(
        "==", Member(Ref("a"), "b"), Literal("a.b")
    )
    doc = rules_from_json({"name": "r", "always": {"==": ["a.b", 3]}})
    assert doc.rules[0].assertions[0].condition == Binary("==", Member(Ref("a"), "b"), Literal(3))


def test_and_or_take_any_number_of_operands():
    doc = rules_from_json({"name": "r", "always": {"and": ["a", "b", "c"]}})
    assert doc.rules[0].assertions[0].condition == parse_rules(
        'rule "r" { always a and b and c }'
    ).rules[0].assertions[0].condition


CORPUS = [TEXT, *(e["source"] for e in EXAMPLES)]


@pytest.mark.parametrize("source", CORPUS)
def test_exported_json_reads_back_as_the_same_rules(source):
    rules = parse_rules(source).rules
    exported = json.loads(json.dumps(document_to_json(rules)))  # through real JSON text
    assert rules_from_json(exported).rules == rules


def test_builtin_rules_survive_the_json_round_trip():
    rules = builtin_document().rules
    assert rules_from_json(json.loads(json.dumps(document_to_json(rules)))).rules == rules


def test_enabled_false_is_reported_as_disabled_and_exported_again():
    doc = rules_from_json(
        [{"name": "on", "always": True}, {"name": "off", "always": True, "enabled": False}]
    )
    assert [r.name for r in doc.rules] == ["on", "off"] and doc.disabled == {"off"}
    exported = document_to_json(doc.rules, doc.disabled)
    assert [r.get("enabled", True) for r in exported["rules"]] == [True, False]
    assert "enabled" not in rule_to_json(doc.rules[0])


# -- rejection ---------------------------------------------------------------

RULE = {"name": "r", "always": True}
BAD = [
    ("not json at all {", "not valid JSON", None),
    ("42", "expected", None),
    ("[]", "defines no rules", None),
    ('{"rules": {}}', '"rules" must be a list', "rules"),
    ('{"version": 2, "rules": []}', "unsupported rule file version 2", "version"),
    ('{"rules": [], "extra": 1}', "unknown top-level key 'extra'", "extra"),
    (json.dumps({"always": True}), 'missing required key "name"', None),
    (json.dumps({**RULE, "name": 5}), '"name" must be a string, found a number', "name"),
    (json.dumps({**RULE, "severty": "high"}), "unknown rule key 'severty'; did you mean 'severity'?", "severty"),
    (json.dumps({**RULE, "severity": "hgih"}), "severity must be one of critical, high, medium, low, info; found 'hgih'; did you mean 'high'?", "severity"),
    (json.dumps({**RULE, "enabled": "yes"}), '"enabled" must be true or false', "enabled"),
    (json.dumps({**RULE, "always": {"equals": [1, 1]}}), "unknown expression operator 'equals'", "always"),
    (json.dumps({**RULE, "always": {"==": [1]}}), "'==' takes exactly 2 operands, found 1", "always.=="),
    (json.dumps({**RULE, "always": {"==": [1, 2], "!=": [1, 2]}}), "exactly one operator", "always"),
    (json.dumps({**RULE, "always": {"and": ["a"]}}), "'and' takes at least 2 operands", "always.and"),
    (json.dumps({**RULE, "always": {"ref": "actor..org"}}), "'actor..org' is not a valid field path", "always.ref"),
    (json.dumps({**RULE, "always": {"value": [1, 2]}}), '"value" holds a string, number, boolean or null', "always.value"),
    (json.dumps({**RULE, "always": [1, 2]}), None, "always[0]"),  # a list of always-conditions: fine
    (json.dumps({**RULE, "always": {"list": 3}}), '"list" takes a list', "always.list"),
    (json.dumps({**RULE, "always": "actor.org =="}), "cannot parse expression 'actor.org =='", "always"),
    (json.dumps({**RULE, "always": {"some": "x", "in": "xs"}}), '"some" needs "where"', "always"),
    (json.dumps({**RULE, "always": {"call": "has", "args": 1}}), '"args" must be a list', "always.args"),
    (json.dumps({"name": "r", "assert": [{"sometimes": True}]}), 'an assertion is {"always": expr} or {"never": expr}', "assert[0]"),
    (json.dumps({**RULE, "assert": []}), 'use either "assert" or "always"/"never"', None),
    (json.dumps({"name": "r", "always": True, "let": {"x": 1}, "bindings": []}), 'use either "bindings" or "let"/"observe"', None),
    (json.dumps({**RULE, "bindings": [{"let": "x"}]}), 'let "x" needs a "value"', "bindings[0]"),
    (json.dumps({**RULE, "observe": {"o": {"args": []}}}), 'observation "o" needs a "probe" name', "observe.o"),
    (json.dumps({**RULE, "let": {"not a name": 1}}), "is not a valid name", "let.not a name"),
    (json.dumps({**RULE, "message": "{unclosed"}), "unclosed '{'", "message"),
    (json.dumps({**RULE, "evidence": [1]}), '"evidence" must be an object', "evidence"),
]


@pytest.mark.parametrize(("text", "message", "path"), [b for b in BAD if b[1] is not None])
def test_malformed_files_are_rejected_with_a_specific_message(text, message, path):
    with pytest.raises(RuleSyntaxError) as caught:
        loads(text)
    (first, *_) = caught.value.diagnostics
    assert message in first.message
    assert first.path == path


def test_a_list_under_always_is_several_assertions_not_an_error():
    doc = loads(json.dumps({**RULE, "always": [True, "a == b"]}))
    assert [a.kind for a in doc.rules[0].assertions] == ["always", "always"]


def test_each_bad_rule_in_a_file_is_reported_with_its_name_and_position():
    data = {"rules": [RULE, {"name": "second", "never": {"nope": 1}}, {"name": "third", "when": {"==": [1]}}]}
    with pytest.raises(RuleSyntaxError) as caught:
        rules_from_json(data)
    assert [(d.rule, d.path) for d in caught.value.diagnostics] == [
        ("second", "rules[1].never"),
        ("third", "rules[2].when.=="),
    ]


def test_json_nesting_is_bounded():
    deep: object = True
    for _ in range(200):
        deep = {"not": deep}
    with pytest.raises(RuleSyntaxError, match="nested more than"):
        rules_from_json({"name": "r", "always": deep})
