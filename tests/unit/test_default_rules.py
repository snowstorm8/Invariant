"""The default web-application rule library, rule by rule.

Every rule is shown a response that must violate it and one that must not, so a
rule that quietly never fires (a typo in a field name, a scope that matches
nothing) fails here instead of staying green in an exploration where the demo
app happens to have no such defect.
"""

import json
import re

import pytest

from invariant.adapters.base import Observation
from invariant.core.scenario import (
    CreateDocument,
    DeleteDocument,
    ListDocuments,
    ReadDocument,
    UpdateDocument,
)
from invariant.evaluation.violations import Outcome
from invariant.integrations.builtin_rules import (
    builtin_document,
    library_document,
    library_source,
    shipped_document,
)
from invariant.integrations.document_saas import DOCUMENT_SAAS, SCHEMA
from invariant.properties.authorization import decide
from invariant.properties.base import Step
from invariant.properties.checks import RuleCheck
from invariant.rules import RuleSet
from support import make_state

LIBRARY = RuleSet(library_document().rules, SCHEMA)
CHECKS = {c.id: RuleCheck(c, DOCUMENT_SAAS) for c in LIBRARY}

GOOD_HEADERS = {
    "x-content-type-options": "nosniff",
    "cache-control": "no-store",
    "x-frame-options": "DENY",
    "referrer-policy": "no-referrer",
    "content-security-policy": "default-src 'none'; frame-ancestors 'none'",
    "content-type": "application/json",
}
GROUPS = {"access-control", "data-exposure", "headers", "integrity"}
SKIP = "out of scope"

# make_state(): org0 (org_1){user0 admin, user2 viewer, doc0 = doc_6}, org1 (org_2){user1 member}
STATE = make_state()
READ_FOREIGN = ReadDocument(actor="user1", doc="doc0")
READ_OWN = ReadDocument(actor="user0", doc="doc0")
UPDATE_FOREIGN = UpdateDocument(actor="user1", doc="doc0", content="x")
UPDATE_OWN = UpdateDocument(actor="user0", doc="doc0", content="x")
DELETE_BY_VIEWER = DeleteDocument(actor="user2", doc="doc0")
LIST_OWN = ListDocuments(actor="user0")


def response(status=200, body=None, headers=None, cookies=(), method="GET", path="/documents"):
    text = body if isinstance(body, str) else json.dumps(body if body is not None else {})
    merged = dict(GOOD_HEADERS if headers is None else headers)
    return Observation(
        status=status, body=text, headers=merged, set_cookies=tuple(cookies), method=method, path=path
    )


def outcome_of(rule_id, op, observation, history=()):
    step = Step(op, STATE.user(op.actor), decide(STATE, op), STATE, tuple(history))
    check = CHECKS[rule_id]
    if not check.applies(step):
        return SKIP
    return check.evaluate(step, observation, {}).outcome


def event(kind, target, status=200, allowed=True):
    return {
        "index": 0,
        "operation": {"type": kind, "is_write": kind != "read_document", "target": target, "input": {}},
        "actor": {"ref": "user0", "id": "u", "org": "org0", "role": "admin", "permissions": []},
        "policy": {"allowed": allowed, "reason": "ok", "denials": {}},
        "response": {"status": status, "body": "", "excerpt": "", "headers": {}, "cookies": []},
    }


DOC = {"id": "doc_6", "org_id": "org_1", "content": "secret <<INV:3>>", "version": 1}
V, P = Outcome.VIOLATION, Outcome.PASS

# (rule, operation, observation, history, expected)
CASES = [
    # -- access control
    ("AC-1", READ_FOREIGN, response(200, DOC), (), V),
    ("AC-1", READ_FOREIGN, response(404, {"detail": "not found"}), (), P),
    ("AC-1", READ_OWN, response(200, DOC), (), SKIP),
    ("AC-2", UPDATE_FOREIGN, response(200, DOC), (), V),
    ("AC-2", DeleteDocument(actor="user1", doc="doc0"), response(200, {"deleted": True}), (), V),
    ("AC-2", UPDATE_FOREIGN, response(404, {"detail": "not found"}), (), P),
    ("AC-2", UPDATE_OWN, response(200, DOC), (), SKIP),
    ("AC-3", UpdateDocument(actor="user2", doc="doc0", content="x"), response(200, DOC), (), V),
    ("AC-3", CreateDocument(ref="d", actor="user2", content="x"), response(201, DOC), (), V),
    ("AC-3", UpdateDocument(actor="user2", doc="doc0", content="x"), response(403, {"detail": "no"}), (), P),
    ("AC-3", UPDATE_OWN, response(200, DOC), (), SKIP),
    ("AC-4", DELETE_BY_VIEWER, response(200, {"deleted": True}), (), V),
    ("AC-4", DELETE_BY_VIEWER, response(403, {"detail": "no"}), (), P),
    ("AC-4", DeleteDocument(actor="user0", doc="doc0"), response(200, {"deleted": True}), (), SKIP),
    ("AC-5", READ_OWN, response(200, {**DOC, "org_id": "org_2"}), (), V),
    ("AC-5", READ_OWN, response(200, DOC), (), P),
    ("AC-5", READ_OWN, response(404, {"detail": "not found"}), (), P),
    ("AC-6", LIST_OWN, response(200, [DOC, {**DOC, "id": "doc_9", "org_id": "org_2"}]), (), V),
    ("AC-6", LIST_OWN, response(200, [DOC]), (), P),
    ("AC-6", LIST_OWN, response(200, []), (), P),
    (
        "AC-7",
        READ_OWN,
        response(200, DOC),
        [event("delete_document", "doc0")],
        V,
    ),
    ("AC-7", READ_OWN, response(404, {"detail": "not found"}), [event("delete_document", "doc0")], P),
    ("AC-7", READ_OWN, response(200, DOC), [event("delete_document", "doc0", status=404)], SKIP),
    ("AC-7", READ_OWN, response(200, DOC), [event("delete_document", "doc9")], SKIP),
    ("AC-7", READ_OWN, response(200, DOC), (), SKIP),
    # -- data exposure
    ("DX-1", READ_OWN, response(200, {**DOC, "token": "tok-1"}), (), V),
    ("DX-1", READ_OWN, response(200, {"password": "hunter2"}), (), V),
    ("DX-1", READ_OWN, response(200, {"api_key": "k"}), (), V),
    ("DX-1", READ_OWN, response(200, DOC), (), P),
    ("DX-2", READ_OWN, response(500, "Traceback (most recent call last):\n  File ..."), (), V),
    ("DX-2", READ_OWN, response(400, 'File "/srv/app/main.py", line 3'), (), V),
    ("DX-2", READ_OWN, response(500, "SQLSTATE[23000] constraint"), (), V),
    ("DX-2", READ_OWN, response(404, {"detail": "not found"}), (), P),
    ("DX-2", READ_OWN, response(200, "a traceback is a stack of calls"), (), P),
    ("DX-3", READ_FOREIGN, response(403, {"detail": "forbidden"}), (), V),
    ("DX-3", READ_FOREIGN, response(404, {"detail": "belongs to org_1"}), (), V),
    ("DX-3", UPDATE_FOREIGN, response(403, {"detail": "no"}), (), V),
    ("DX-3", READ_FOREIGN, response(404, {"detail": "not found"}), (), P),
    ("DX-3", READ_OWN, response(403, {"detail": "no"}), (), SKIP),
    ("DX-3", CreateDocument(ref="d", actor="user1", content="x"), response(201, DOC), (), SKIP),
    # -- headers and cookies
    ("TH-1", READ_OWN, response(200, DOC, headers={}), (), V),
    ("TH-1", READ_OWN, response(200, DOC, headers={"x-content-type-options": "sniff"}), (), V),
    ("TH-1", READ_OWN, response(200, DOC, headers={"x-content-type-options": "NoSniff"}), (), P),
    ("TH-2", READ_OWN, response(200, DOC, headers={}), (), V),
    ("TH-2", READ_OWN, response(200, DOC, headers={"cache-control": "public, max-age=60"}), (), V),
    ("TH-2", READ_OWN, response(200, DOC, headers={"cache-control": "private, No-Store"}), (), P),
    ("TH-3", READ_OWN, response(200, DOC, headers={}), (), V),
    ("TH-3", READ_OWN, response(200, DOC, headers={"x-frame-options": "DENY"}), (), P),
    ("TH-3", READ_OWN, response(200, DOC, headers={"content-security-policy": "frame-ancestors 'self'"}), (), P),
    ("TH-3", READ_OWN, response(200, DOC, headers={"content-security-policy": "default-src 'none'"}), (), V),
    ("TH-4", READ_OWN, response(200, DOC, headers={}), (), V),
    ("TH-4", READ_OWN, response(200, DOC, headers={"referrer-policy": "no-referrer"}), (), P),
    ("TH-5", READ_OWN, response(200, DOC, headers={}), (), V),
    ("TH-5", READ_OWN, response(200, DOC), (), P),
    ("TH-6", READ_OWN, response(200, DOC, headers={**GOOD_HEADERS, "server": "nginx/1.25.3"}), (), V),
    ("TH-6", READ_OWN, response(200, DOC, headers={**GOOD_HEADERS, "x-powered-by": "Express"}), (), V),
    ("TH-6", READ_OWN, response(200, DOC, headers={**GOOD_HEADERS, "server": "nginx"}), (), P),
    ("TH-6", READ_OWN, response(200, DOC), (), P),
    (
        "TH-7",
        READ_OWN,
        response(200, DOC, headers={**GOOD_HEADERS, "access-control-allow-origin": "*",
                                    "access-control-allow-credentials": "true"}),
        (),
        V,
    ),
    ("TH-7", READ_OWN, response(200, DOC, headers={**GOOD_HEADERS, "access-control-allow-origin": "*"}), (), P),
    (
        "TH-7",
        READ_OWN,
        response(200, DOC, headers={**GOOD_HEADERS, "access-control-allow-origin": "https://app.example",
                                    "access-control-allow-credentials": "true"}),
        (),
        P,
    ),
    ("TH-8", READ_OWN, response(200, DOC, cookies=["sid=1; Secure; SameSite=Lax"]), (), V),
    ("TH-8", READ_OWN, response(200, DOC, cookies=["sid=1; HttpOnly; Secure"]), (), P),
    ("TH-8", READ_OWN, response(200, DOC, cookies=["a=1; HttpOnly", "b=2"]), (), V),
    ("TH-8", READ_OWN, response(200, DOC), (), P),
    ("TH-9", READ_OWN, response(200, DOC, cookies=["sid=1; HttpOnly"]), (), V),
    ("TH-9", READ_OWN, response(200, DOC, cookies=["sid=1; httponly; SECURE"]), (), P),
    ("TH-10", READ_OWN, response(200, DOC, cookies=["sid=1; HttpOnly; Secure"]), (), V),
    ("TH-10", READ_OWN, response(200, DOC, cookies=["sid=1; SameSite=None; Secure"]), (), V),
    ("TH-10", READ_OWN, response(200, DOC, cookies=["sid=1; SameSite=Strict"]), (), P),
    ("TH-10", READ_OWN, response(200, DOC, cookies=["sid=1; samesite=lax"]), (), P),
    ("TH-11", READ_OWN, response(200, DOC, headers={**GOOD_HEADERS, "content-type": "text/html"}), (), V),
    ("TH-11", READ_OWN, response(200, DOC, headers={k: v for k, v in GOOD_HEADERS.items() if k != "content-type"}), (), V),
    ("TH-11", READ_OWN, response(200, DOC, headers={**GOOD_HEADERS, "content-type": "application/json; charset=utf-8"}), (), P),
    ("TH-11", READ_OWN, response(500, "oops", headers={**GOOD_HEADERS, "content-type": "text/plain"}), (), P),
    # -- integrity and robustness
    ("IR-1", READ_OWN, response(500, "boom"), (), V),
    ("IR-1", READ_OWN, response(404, {"detail": "not found"}), (), P),
    ("IR-3", UPDATE_OWN, response(200, {**DOC, "version": 2}), (), P),
    ("IR-3", UPDATE_OWN, response(200, {**DOC, "version": 1}), (), V),
    ("IR-3", UPDATE_OWN, response(200, {**DOC, "version": 7}), (), V),
    ("IR-3", UPDATE_OWN, response(403, {"detail": "no"}), (), P),
    ("IR-3", UPDATE_FOREIGN, response(200, DOC), (), SKIP),
    ("IR-4", READ_OWN, response(200, DOC), (), P),
    ("IR-4", READ_OWN, response(200, {**DOC, "version": 2}), (), V),
    ("IR-4", READ_OWN, response(200, {**DOC, "content": "tampered"}), (), V),
    ("IR-4", READ_OWN, response(404, {"detail": "gone"}), (), P),
    ("IR-4", READ_FOREIGN, response(200, DOC), (), SKIP),
    ("IR-5", LIST_OWN, response(200, [DOC]), (), P),
    ("IR-5", LIST_OWN, response(200, []), (), V),
    ("IR-5", LIST_OWN, response(200, [DOC, {**DOC, "id": "doc_99"}]), (), V),
    ("IR-5", LIST_OWN, response(200, [{**DOC, "id": "doc_99"}]), (), V),
    ("IR-5", LIST_OWN, response(403, {"detail": "no"}), (), P),
]


@pytest.mark.parametrize(
    ("rule_id", "op", "observed", "history", "expected"),
    CASES,
    ids=[f"{c[0]}-{i}" for i, c in enumerate(CASES)],
)
def test_rule_judges_a_response(rule_id, op, observed, history, expected):
    got = outcome_of(rule_id, op, observed, history)
    assert got == expected, f"{rule_id}: expected {expected}, got {got}"


def test_every_rule_with_a_probe_is_covered_by_the_exploration_tests():
    # IR-2 needs a state probe, so it is exercised end to end in
    # tests/integration/test_default_rules_on_the_demo_app.py instead.
    probing = {r.id for r in library_document().rules if r.observes}
    assert probing == {"IR-2"}


def test_every_library_rule_is_exercised_both_ways_here_or_in_the_integration_tests():
    covered = {c[0] for c in CASES} | {"IR-2"}
    assert covered == {r.id for r in library_document().rules}
    # ... and each rule that can be judged here is seen both violated and held.
    for rule_id in covered - {"IR-2"}:
        seen = {c[4] for c in CASES if c[0] == rule_id}
        assert V in seen and P in seen, rule_id


# -- the library as a whole ----------------------------------------------------


def test_the_library_is_valid_and_its_ids_are_unique_and_do_not_clash_with_the_core():
    shipped = shipped_document().rules
    RuleSet(shipped, SCHEMA)  # validates every rule and every id
    assert len({r.id for r in shipped}) == len(shipped) == 29
    assert not {r.id for r in builtin_document().rules} & {r.id for r in library_document().rules}
    assert len({r.name for r in shipped}) == len(shipped)


def test_the_library_covers_four_groups_each_rule_in_one():
    rules = library_document().rules
    assert len(rules) == 26
    for rule in rules:
        assert rule.tags, rule.name
        assert rule.tags[0] in GROUPS, (rule.name, rule.tags)
    assert {r.tags[0] for r in rules} == GROUPS
    assert all(r.tags and r.tags[0] == "access-control" for r in builtin_document().rules)


def test_every_rule_documents_itself():
    for rule in shipped_document().rules:
        assert rule.description and rule.description.endswith("."), rule.name
        assert rule.message is not None, rule.name
        assert rule.severity in {"critical", "high", "medium", "low"}, rule.name
        assert re.fullmatch(r"[A-Z]{2}-\d{1,2}", rule.id), rule.id


def test_library_ids_follow_the_group_prefixes():
    prefixes = {"access-control": "AC", "data-exposure": "DX", "headers": "TH", "integrity": "IR"}
    for rule in library_document().rules:
        assert rule.id.startswith(prefixes[rule.tags[0]] + "-"), (rule.id, rule.tags)


def test_library_rules_do_not_depend_on_the_reference_policys_denial_labels():
    # Only the core rules read policy.denials; the library works for any policy.
    assert "policy.denials" not in library_source()
