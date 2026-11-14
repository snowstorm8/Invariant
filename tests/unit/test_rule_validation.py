"""Semantic validation: a rule must make sense for the context it will run in."""

import pytest

from invariant.integrations.document_saas import SCHEMA
from invariant.rules import (
    RuleSet,
    RuleValidationError,
    parse_rules,
    rules_from_json,
    validate_rule,
    validate_rules,
)
from rule_support import BANK_SCHEMA


def problems(body, schema=SCHEMA, name="r"):
    (rule,) = parse_rules(f'rule "{name}" {{ {body} }}').rules
    return validate_rule(rule, schema)


def messages(body, schema=SCHEMA):
    return [d.message for d in problems(body, schema)]


VALID = [
    'always true',
    'when operation.type == "read_document" always response.status < 500',
    'when actor.role in ["viewer", "member"] and "delete" not in actor.permissions never response.status == 200 and operation.type == "delete_document"',
    'always has(response.json.org_id) implies response.json.org_id == actor.org_id',
    'never some d in state.documents : d.org != actor.org and contains(response.body, d.marker)',
    'observe l = org_documents(actor.org) always count(diff(state.expected_listing[actor.org], l)) == 0',
    'let n = count(events) always n >= 0 message "{n} earlier operations by {actor.ref}"',
    'always every e in events : e.response.status != null',
    'always policy.denials["TI-2"].reason != "" or not has(policy.denials["TI-2"])',
    'let org = coalesce(resource.org, actor.org) observe l = org_documents(org) always has(l)',
    'always response.json.items[0].owner.id == actor.id',  # below `json` anything goes
    'always sum([d.version for d in state.documents]) + 1 > 0',
    'evidence { who: actor, input: operation.input } always true',
]


@pytest.mark.parametrize("body", VALID)
def test_valid_rules_have_no_problems(body):
    assert messages(body) == []


INVALID = [
    ('always actor.rol == "viewer"', "actor has no field 'rol'; did you mean 'role'? (fields: ref, id, org, org_id, role, permissions)"),
    ('always actr.role == "viewer"', "unknown name 'actr'; did you mean 'actor'?"),
    ('always actor.role == "viewr"', 'actor.role is never "viewr"; did you mean \'viewer\'? (possible values: admin, member, viewer)'),
    ('always operation.type in ["read_document", "peek"]', 'operation.type is never "peek"'),
    ('always actor.role == 3', "actor.role is \"admin\" | \"member\" | \"viewer\" and 3 is int; they can never be equal"),
    ('always actor.ref > 3', "'>' orders two numbers or two strings"),
    ('always actor.ref', "the 'always' condition must be true or false, but actor.ref is string"),
    ('when actor.org always true', "the 'when' condition must be true or false"),
    ('always actor.ref and true', "'and' needs true/false operands, but actor.ref is string"),
    ('always not actor.ref', "'not' needs a true/false operand"),
    ('always actor.ref.length == 1', "actor.ref is string and has no field 'length'"),
    ('always actor.ref + 1 == 2', "'+' adds two numbers, strings or lists"),
    ('always resource.version * "2" == 2', "'*' needs numbers"),
    ('always count(actor.org_id, 1) == 1', "count(x) -> int was called with 2 argument(s)"),
    ('always count(resource.version) == 1', "count() expects a list, map or string as its first argument, found int"),
    ('always lenght(actor.ref) == 1', "unknown function 'lenght'"),
    ('always org_documents(actor.org) == 1', "'org_documents' is a probe: use 'observe name = org_documents(...)'"),
    ('observe l = documents(actor.org) always true', "unknown probe 'documents'; did you mean 'org_documents'? (available: org_documents)"),
    ('observe l = org_documents() always true', "probe org_documents(org) takes 1 argument(s), found 0"),
    ('observe l = org_documents(resource.version) always true', "argument 'org' must be string, but resource.version is int"),
    ('observe l = org_documents(response.body) always true', "probe arguments are decided before the target responds, so 'l' cannot use 'response'"),
    ('when response.status == 200 always true', "'when' is decided before the target responds, so it cannot use 'response'"),
    ('let ok = response.status == 200 when ok always true', "cannot use 'ok' (which depends on 'response')"),
    ('observe l = org_documents(actor.org) when count(l) > 0 always true', "cannot use the observation 'l' (taken after the operation)"),
    ('let a = b let b = a always a == 1', "let 'a' is defined in terms of itself (a -> b -> a)"),
    ('let actor = 1 always true', "let 'actor' hides the context field 'actor'"),
    ('let x = 1 let x = 2 always true', "'x' is defined more than once"),
    ('always some actor in events : true', "variable 'actor' hides another name"),
    ('always some e in actor.ref : true', "cannot iterate over actor.ref: it is string, not a list or map"),
    ('always some e in events : e.operation.kind == "x"', "e.operation has no field 'kind'"),
    ('always state.documents["doc0"].org == "x"', "a list is indexed by a number"),
    ('always "x" in resource.version', "'in' needs a list, map or string on the right"),
    ('when actor.role == "viewer"', "the rule asserts nothing: add 'always <condition>' or 'never <condition>'"),
    ('always true message "{actor.nme}"', "actor has no field 'nme'; did you mean 'name'?"),
    ('always true evidence { x: nope }', "unknown name 'nope'"),
]


@pytest.mark.parametrize(("body", "expected"), INVALID[:33] + INVALID[34:])
def test_invalid_rules_are_explained(body, expected):
    found = messages(body)
    assert any(expected in m for m in found), found


def test_a_typo_in_a_message_placeholder_is_caught_too():
    assert any("actor has no field 'nme'" in m for m in messages('always true message "{actor.nme}"'))


def test_diagnostics_carry_rule_name_and_position():
    source = 'rule "first" { always true }\nrule "second" {\n    always actor.rol == "x"\n}'
    found = validate_rules(parse_rules(source).rules, SCHEMA)
    assert [(d.rule, d.line, d.col) for d in found] == [("second", 3, 18)]
    assert str(found[0]).startswith('rule "second", line 3, col 18: actor has no field')


def test_json_rules_are_located_by_path():
    rules = rules_from_json({"rules": [{"name": "j", "always": {"==": [{"ref": "actor.rol"}, 1]}}]}).rules
    (found,) = validate_rules(rules, SCHEMA)
    assert (found.rule, found.path, found.line) == ("j", "rules[0].always.==[0]", None)


@pytest.mark.parametrize(
    ("name", "expected"),
    [("has space", "is not valid"), ("", "is not valid"), ("x" * 65, "is not valid"), ("EXEC", "is reserved")],
)
def test_names_and_ids_are_checked(name, expected):
    assert any(expected in d.message for d in problems("always true", name=name))


def test_ids_must_be_unique_within_a_set():
    source = 'rule "a" { id "X" always true }\nrule "b" { id "X" always true }'
    found = validate_rules(parse_rules(source).rules, SCHEMA)
    assert [d.message for d in found] == ["rule id 'X' is already used by rule \"a\"; ids must be unique"]
    with pytest.raises(RuleValidationError, match="ids must be unique"):
        RuleSet.from_text(source, SCHEMA)


def test_all_problems_of_a_rule_are_reported_together():
    found = messages('when response.status == 200 never actor.rol == "x" and operation.type == "raed"')
    assert len(found) == 3


# -- the schema, not the language, decides what exists -----------------------


def test_the_same_rule_is_valid_for_one_integration_and_invalid_for_another():
    body = 'when request.kind == "withdraw" never result.ok and request.amount > ledger.balances[request.source]'
    assert messages(body, BANK_SCHEMA) == []
    saas = messages(body, SCHEMA)
    assert any("unknown name 'request'" in m for m in saas)
    # ...and a document-SaaS rule means nothing to the bank.
    assert any("unknown name 'actor'" in m for m in messages('always actor.role == "viewer"', BANK_SCHEMA))


def test_late_roots_and_probes_come_from_the_schema():
    assert any("cannot use 'result'" in m for m in messages("when result.ok always true", BANK_SCHEMA))
    assert messages("observe b = balance(request.source) always b >= 0", BANK_SCHEMA) == []
    assert any("unknown probe 'org_documents'" in m for m in messages("observe b = org_documents(request.source) always true", BANK_SCHEMA))
    assert any('request.kind is never "refund"' in m for m in messages('always request.kind != "refund"', BANK_SCHEMA))


def test_the_rule_package_imports_nothing_application_specific():
    """The language must stay usable for any integration: no SaaS model inside it."""
    import re
    from pathlib import Path

    import invariant.rules

    forbidden = re.compile(r"invariant\.(core|properties|adapters|integrations|exploration|analysis|console)\b")
    for path in Path(invariant.rules.__file__).parent.glob("*.py"):
        imports = [line for line in path.read_text().splitlines() if line.startswith(("from ", "import "))]
        assert not [line for line in imports if forbidden.search(line)], path.name
