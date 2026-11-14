"""User-defined rules through the real exploration engine and demo app."""

import json

from invariant.analysis.reproduction import replay
from invariant.evaluation.evaluator import Evaluator, evaluator_for_report
from invariant.evaluation.violations import Outcome
from invariant.exploration.runner import explore
from invariant.integrations.builtin_rules import builtin_document
from invariant.integrations.document_saas import SCHEMA
from invariant.rules import RuleRegistry, RuleSet, document_to_json, parse_rules
from vulnerable_saas.target import adapter_for, fixed_adapter, vulnerable_adapter

CUSTOM = '''
rule "read-returns-own-tenant" {
    severity critical
    when operation.type == "read_document"
    always response.status == 200 implies response.json.org_id == actor.org_id
}
'''
SEQUENCE = '''
rule "updated-docs-stay-private" {
    when operation.type == "read_document" and resource.org != actor.org
        and some e in events : e.operation.type == "update_document"
            and e.operation.target == operation.target
    never has(response.json.content)
}
'''


def test_existing_demo_with_builtin_rules_loaded_at_runtime():
    registry = RuleRegistry(SCHEMA)
    registry.register(builtin_document(), origin="builtin")
    rules = registry.ruleset()
    found = explore(vulnerable_adapter, seed=1, rules=rules)
    assert found.outcome is Outcome.VIOLATION
    assert found.report.finding.property_id == "TI-1" and found.report.reproduced is True
    evaluator = evaluator_for_report(found.report.rules)
    scenario = found.report.scenario
    assert replay(scenario, vulnerable_adapter, evaluator=evaluator).outcome is Outcome.VIOLATION
    assert replay(scenario, fixed_adapter, evaluator=evaluator).outcome is Outcome.PASS
    assert explore(fixed_adapter, seed=1, max_examples=40, rules=rules).outcome is Outcome.PASS


def test_a_new_rule_alone_detects_replays_and_passes_on_the_fixed_app():
    registry = RuleRegistry(SCHEMA)
    registry.register(CUSTOM)  # registered at run time; no built-in rule active
    rules = registry.ruleset()
    found = explore(vulnerable_adapter, seed=1, rules=rules)
    finding = found.report.finding
    assert found.outcome is Outcome.VIOLATION
    assert finding.property_id == "read-returns-own-tenant" and finding.severity == "critical"
    assert finding.evidence["values"]["response.status"] == 200
    assert found.report.reproduced is True
    evaluator = evaluator_for_report(json.loads(json.dumps(found.report.rules)))
    first = replay(found.report.scenario, vulnerable_adapter, evaluator=evaluator)
    again = replay(found.report.scenario, vulnerable_adapter, evaluator=evaluator)
    assert first.outcome is Outcome.VIOLATION and first.history == again.history
    assert replay(found.report.scenario, fixed_adapter, evaluator=evaluator).outcome is Outcome.PASS
    assert explore(fixed_adapter, seed=1, max_examples=40, rules=rules).outcome is Outcome.PASS


def test_text_and_json_forms_judge_identically():
    text = RuleSet.from_text(CUSTOM + SEQUENCE, SCHEMA)
    as_json = RuleSet.from_json(document_to_json(parse_rules(CUSTOM + SEQUENCE).rules), SCHEMA)
    scenario = explore(vulnerable_adapter, seed=1, rules=text).report.scenario
    a = replay(scenario, vulnerable_adapter, evaluator=Evaluator.for_rules(text))
    b = replay(scenario, vulnerable_adapter, evaluator=Evaluator.for_rules(as_json))
    assert a.outcome is b.outcome is Outcome.VIOLATION and a.history == b.history


def test_sequence_rule_and_several_rules_at_once():
    rules = RuleSet.from_text(SEQUENCE + CUSTOM, SCHEMA)
    found = explore(vulnerable_adapter, seed=1, rules=rules)
    assert found.outcome is Outcome.VIOLATION
    last = found.report.steps[-1]
    violated = [e.property_id for e in last.evaluations if e.outcome is Outcome.VIOLATION]
    assert violated == ["updated-docs-stay-private", "read-returns-own-tenant"]
    # The sequence rule needs the earlier update: without it, it is out of scope.
    kinds = [op.kind for op in found.report.scenario.operations]
    assert "update_document" in kinds
    assert explore(lambda: adapter_for(frozenset()), seed=1, max_examples=40, rules=rules).outcome is Outcome.PASS


# -- the three original rules, now data ---------------------------------------

import pytest  # noqa: E402

from invariant.adapters.base import Action  # noqa: E402
from invariant.core.engine import Engine, InconclusiveError, PropertyViolationError  # noqa: E402
from invariant.core.scenario import (  # noqa: E402
    CreateDocument,
    CreateOrg,
    CreateUser,
    DeleteDocument,
    ListDocuments,
    ReadDocument,
    Role,
    Scenario,
    UpdateDocument,
)
from invariant.properties.checks import CHECKS, RuleCheck, builtin_ruleset  # noqa: E402
from invariant.rules import RuleValidationError, rules_from_json  # noqa: E402
from support import ScriptedAdapter  # noqa: E402

SETUP = [
    CreateOrg(ref="org0", name="a"),
    CreateOrg(ref="org1", name="b"),
    CreateUser(ref="owner", org="org0", role=Role.ADMIN),
    CreateUser(ref="viewer", org="org0", role=Role.VIEWER),
    CreateUser(ref="outsider", org="org1", role=Role.ADMIN),
    CreateDocument(ref="doc0", actor="owner", content="top secret"),
]
ATTACKS = {
    "stale-cache-read": ("TI-1", [UpdateDocument(actor="owner", doc="doc0", content="v2"),
                                  ReadDocument(actor="outsider", doc="doc0")]),
    "update-missing-tenant-check": ("TI-2", [UpdateDocument(actor="outsider", doc="doc0", content="pwned")]),
    "viewer-can-update": ("AZ-1", [UpdateDocument(actor="viewer", doc="doc0", content="oops")]),
}  # fmt: skip
EVERYTHING = [
    ReadDocument(actor="outsider", doc="doc0"),
    UpdateDocument(actor="outsider", doc="doc0", content="x"),
    DeleteDocument(actor="outsider", doc="doc0"),
    UpdateDocument(actor="viewer", doc="doc0", content="x"),
    CreateDocument(ref="doc1", actor="viewer", content="x"),
    ListDocuments(actor="outsider"),
    UpdateDocument(actor="owner", doc="doc0", content="v2"),
    DeleteDocument(actor="owner", doc="doc0"),
    ReadDocument(actor="owner", doc="doc0"),
]


def scenario(*ops):
    return Scenario(operations=[*SETUP, *ops])


def test_the_default_checks_are_the_rule_file_and_nothing_else():
    assert all(type(check) is RuleCheck for check in CHECKS)
    assert [c.rule.rule for c in CHECKS] == list(builtin_document().rules)
    assert builtin_ruleset().ids() == ["TI-1", "TI-2", "AZ-1"]


@pytest.mark.parametrize("defect", [*ATTACKS, None])
def test_builtin_rules_judge_identically_however_they_are_loaded(defect):
    """Default evaluator, the rule file loaded at run time, and its JSON export
    must produce the same evaluations, summaries and evidence on every step."""
    ops = ATTACKS[defect][1] if defect else EVERYTHING
    factory = lambda: adapter_for(frozenset({defect} if defect else ()))  # noqa: E731
    from_json = RuleSet.from_json(json.loads(json.dumps(builtin_ruleset().to_json())), SCHEMA)
    runs = [
        replay(scenario(*ops), factory),
        replay(scenario(*ops), factory, evaluator=Evaluator.for_rules(builtin_ruleset())),
        replay(scenario(*ops), factory, evaluator=Evaluator.for_rules(from_json)),
    ]
    assert runs[0].history == runs[1].history == runs[2].history
    assert runs[0].outcome is (Outcome.VIOLATION if defect else Outcome.PASS)
    if defect:
        failing = runs[2].failure.record.evaluations
        assert [e.property_id for e in failing if e.outcome is Outcome.VIOLATION] == [ATTACKS[defect][0]]


# -- state, probes and sequences ----------------------------------------------

VERSION = '''
rule "read-shows-expected-version" {
    severity high
    when operation.type == "read_document" and resource.org == actor.org and not resource.deleted
    always has(response.json.version) implies response.json.version == resource.version
    message "{resource.ref} is at version {response.json.version}, expected {resource.version}"
}
'''
READ_ONLY = '''
rule "viewers-are-read-only" {
    when actor.role == "viewer"
    observe listing = org_documents(actor.org)
    let changes = diff(state.expected_listing[actor.org], listing)
    never count(changes) > 0
    message "viewer {actor.ref} changed {actor.org}: {join(changes, '; ')}"
}
'''


def test_a_rule_over_expected_state_catches_a_change_two_steps_later():
    """The viewer's forbidden update goes unjudged (no rule covers it); the
    defect surfaces only when a later read disagrees with the model."""
    evaluator = Evaluator.for_rules(RuleSet.from_text(VERSION, SCHEMA))
    ops = [UpdateDocument(actor="viewer", doc="doc0", content="oops"), ReadDocument(actor="owner", doc="doc0")]
    hit = replay(scenario(*ops), lambda: adapter_for(frozenset({"viewer-can-update"})), evaluator=evaluator)
    assert hit.outcome is Outcome.VIOLATION
    assert hit.failure.record.index == len(SETUP) + 1
    assert "doc0 is at version 2, expected 1" in str(hit.failure)
    assert replay(scenario(*ops), fixed_adapter, evaluator=evaluator).outcome is Outcome.PASS
    # Without the earlier update there is nothing to find, even on the defective build.
    alone = scenario(ReadDocument(actor="owner", doc="doc0"))
    assert replay(alone, lambda: adapter_for(frozenset({"viewer-can-update"})), evaluator=evaluator).outcome is Outcome.PASS


def test_a_probe_rule_is_found_by_exploration_and_minimised():
    rules = RuleSet.from_text(READ_ONLY, SCHEMA)
    found = explore(lambda: adapter_for(frozenset({"viewer-can-update"})), seed=1, rules=rules)
    assert found.outcome is Outcome.VIOLATION and found.report.reproduced is True
    assert found.report.finding.property_id == "viewers-are-read-only"
    assert "changed org" in found.report.finding.summary
    assert found.report.finding.evidence["values"]["changes"]
    # 1-minimal: every remaining operation is needed for this rule to fail.
    ops = found.report.scenario.operations
    evaluator = Evaluator.for_rules(rules)
    for i in range(len(ops)):
        shorter = Scenario(operations=ops[:i] + ops[i + 1 :])
        result = replay(shorter, lambda: adapter_for(frozenset({"viewer-can-update"})), evaluator=evaluator)
        assert not (result.valid and result.outcome is Outcome.VIOLATION)


def test_the_probe_a_rule_asks_for_is_taken_once_and_shared():
    calls = []

    class Counting(ScriptedAdapter):
        pass

    inner = adapter_for(frozenset())

    def handler(call):
        calls.append(call.action)
        return inner.execute(call)

    two = READ_ONLY + READ_ONLY.replace("viewers-are-read-only", "second-copy")
    engine = Engine(Counting(handler), Evaluator.for_rules(RuleSet.from_text(two, SCHEMA)))
    inner.reset()
    for op in SETUP:
        engine.apply(op)
    before = len(calls)
    record = engine.apply(ReadDocument(actor="viewer", doc="doc0"))
    assert calls[before:] == [Action.READ_DOCUMENT, Action.LIST_DOCUMENTS]  # one probe for both rules
    assert [(e.property_id, e.outcome) for e in record.evaluations] == [
        ("viewers-are-read-only", Outcome.PASS), ("second-copy", Outcome.PASS)]  # fmt: skip
    # Out of scope for a non-viewer: no evaluation and no probe.
    before = len(calls)
    assert engine.apply(ReadDocument(actor="owner", doc="doc0")).evaluations == []
    assert calls[before:] == [Action.READ_DOCUMENT]


def test_events_give_rules_the_history_of_the_run():
    source = '''
    rule "history" {
        when operation.type == "list_documents"
        always count(events) == 3 and events[0].operation.type == "create_document"
            and events[1].actor.ref == "outsider" and events[1].policy.allowed == false
            and events[1].response.status == 404 and events[1].resource.ref == "doc0"
            and events[2].operation.input.content == "v2" and events[2].resource.version == 1
            and (every e in events : e.index >= 0)
    }'''
    evaluator = Evaluator.for_rules(RuleSet.from_text(source, SCHEMA))
    ops = [ReadDocument(actor="outsider", doc="doc0"), UpdateDocument(actor="owner", doc="doc0", content="v2"),
           ListDocuments(actor="owner")]  # fmt: skip
    result = replay(scenario(*ops), fixed_adapter, evaluator=evaluator)
    assert result.outcome is Outcome.PASS
    assert [e.outcome for e in result.history[-1].evaluations] == [Outcome.PASS]


def test_replay_is_deterministic_and_resets_history_between_runs():
    evaluator = Evaluator.for_rules(RuleSet.from_text(SEQUENCE + CUSTOM + VERSION + READ_ONLY, SCHEMA))
    full = scenario(*ATTACKS["stale-cache-read"][1])
    runs = [replay(full, vulnerable_adapter, evaluator=evaluator) for _ in range(3)]
    assert runs[0].outcome is Outcome.VIOLATION
    assert runs[0].history == runs[1].history == runs[2].history
    engine = Engine(vulnerable_adapter(), evaluator)
    for _ in range(2):  # the same engine, reset: events from the first run must not leak
        engine.reset()
        for op in SETUP:
            engine.apply(op)
        with pytest.raises(PropertyViolationError, match="updated-docs-stay-private"):
            for op in ATTACKS["stale-cache-read"][1]:
                engine.apply(op)
    engine.close()


# -- undecidable rules and switched-off rules ----------------------------------


def test_a_rule_that_cannot_be_decided_stops_the_run_as_inconclusive():
    source = 'rule "needs-owner" { when operation.type == "read_document" always response.json.owner == actor.id }'
    evaluator = Evaluator.for_rules(RuleSet.from_text(source, SCHEMA))
    one = scenario(ReadDocument(actor="owner", doc="doc0"))
    strict = replay(one, fixed_adapter, evaluator=evaluator)
    assert strict.outcome is Outcome.INCONCLUSIVE and isinstance(strict.failure, InconclusiveError)
    (evaluation,) = strict.failure.record.evaluations
    assert evaluation.summary == "rule could not be evaluated: response.json.owner is missing"
    lenient = replay(one, fixed_adapter, evaluator=evaluator, strict=False)
    assert lenient.outcome is Outcome.INCONCLUSIVE and lenient.failure is None
    found = explore(fixed_adapter, seed=1, max_examples=30, rules=evaluator.rules)
    assert found.outcome is Outcome.INCONCLUSIVE  # never reported as PASS
    assert found.report.finding.property_id == "needs-owner"


def test_switching_a_builtin_rule_off_is_not_an_error_when_the_policy_denies_under_it():
    only_ti1 = RuleSet((builtin_document().rules[0],), SCHEMA)
    ops = [UpdateDocument(actor="outsider", doc="doc0", content="x"), DeleteDocument(actor="viewer", doc="doc0")]
    result = replay(scenario(*ops), fixed_adapter, evaluator=Evaluator.for_rules(only_ti1))
    assert result.outcome is Outcome.PASS
    assert [[e.property_id for e in r.evaluations] for r in result.history[-2:]] == [["TI-1"], ["TI-1"]]


def test_rule_order_decides_attribution():
    a_then_b = RuleSet.from_text(CUSTOM + SEQUENCE, SCHEMA)
    b_then_a = RuleSet.from_text(SEQUENCE + CUSTOM, SCHEMA)
    full = scenario(*ATTACKS["stale-cache-read"][1])
    first = replay(full, vulnerable_adapter, evaluator=Evaluator.for_rules(a_then_b)).failure
    second = replay(full, vulnerable_adapter, evaluator=Evaluator.for_rules(b_then_a)).failure
    assert str(first).startswith("read-returns-own-tenant violated")
    assert str(second).startswith("updated-docs-stay-private violated")


def test_a_user_rule_next_to_the_builtins_is_judged_on_the_same_step():
    rules = RuleSet((*builtin_document().rules, *parse_rules(CUSTOM).rules), SCHEMA)
    result = replay(scenario(*ATTACKS["stale-cache-read"][1]), vulnerable_adapter, evaluator=Evaluator.for_rules(rules))
    violated = [e.property_id for e in result.failure.record.evaluations if e.outcome is Outcome.VIOLATION]
    assert violated == ["TI-1", "read-returns-own-tenant"]
    assert str(result.failure).startswith("TI-1 violated")  # built-ins come first


def test_reports_embed_their_rules_and_stale_ones_are_refused():
    rules = RuleSet.from_text(CUSTOM, SCHEMA)
    report = explore(vulnerable_adapter, seed=1, rules=rules).report
    assert rules_from_json({"rules": report.rules}).rules == rules.rules
    assert explore(fixed_adapter, seed=1, max_examples=5).report.rules is None  # default: built-ins
    broken = [{**report.rules[0], "always": "actor.gone == 1"}]
    broken[0].pop("assert", None)
    with pytest.raises(RuleValidationError, match="actor has no field 'gone'"):
        evaluator_for_report(broken)


def test_the_pinned_regression_scenario_also_trips_the_user_rule():
    from pathlib import Path

    pinned = Path(__file__).parents[1] / "regression" / "scenarios" / "stale_cache_read.json"
    saved = Scenario.model_validate_json(pinned.read_text())
    evaluator = Evaluator.for_rules(RuleSet.from_text(CUSTOM, SCHEMA))
    assert replay(saved, vulnerable_adapter, evaluator=evaluator).outcome is Outcome.VIOLATION
    assert replay(saved, fixed_adapter, evaluator=evaluator).outcome is Outcome.PASS
