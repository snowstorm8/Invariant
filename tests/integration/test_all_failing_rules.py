"""Every rule that fails is reported, not just the first one."""

import json

from vulnerable_saas.target import adapter_for, fixed_adapter

from invariant.analysis.reproduction import replay
from invariant.core.engine import Engine
from invariant.core.scenario import (
    CreateDocument,
    CreateOrg,
    CreateUser,
    ReadDocument,
    Role,
    UpdateDocument,
)
from invariant.evaluation.evaluator import Evaluator, evaluator_for_report
from invariant.evaluation.violations import Outcome
from invariant.exploration.runner import explore
from invariant.integrations.document_saas import SCHEMA
from invariant.reporting.models import Report
from invariant.reporting.reporter import render_html, render_text
from invariant.rules import RuleSet

STALE = frozenset({"stale-cache-read"})
VIEWER = frozenset({"viewer-can-update"})

#: Fails on exactly the step where TI-1 does (a cross-tenant read that succeeds).
SAME_STEP = '''
rule "read-returns-own-tenant" {
    severity critical
    when operation.type == "read_document" and has(resource) and resource.org != actor.org
    never response.status == 200
}
'''

#: Fails in a different kind of sequence from TI-1: a viewer's write succeeding.
OTHER_SEQUENCE = '''
rule "viewer-write-is-rejected" {
    severity high
    when operation.is_write and actor.role == "viewer"
    never response.status < 300
}
'''

#: Reads, so it can only ever fail in sequences that contain a stale read.
LISTS_ARE_FINE = '''
rule "list-has-no-foreign-documents" {
    when operation.type == "list_documents"
    never contains(response.body, "no such marker anywhere")
}
'''


def builtin_plus(text: str) -> RuleSet:
    from invariant.integrations.builtin_rules import builtin_document
    from invariant.rules import parse_rules

    return RuleSet(
        [*builtin_document().rules, *parse_rules(text).rules], SCHEMA
    )


def ids(report: Report) -> list[str]:
    return [f.property_id for f in report.findings]


def test_two_rules_failing_on_the_same_step_are_both_reported():
    found = explore(lambda: adapter_for(STALE), seed=1, rules=builtin_plus(SAME_STEP))
    report = found.report
    assert found.outcome is Outcome.VIOLATION
    assert set(ids(report)) == {"TI-1", "read-returns-own-tenant"}
    assert all(f.outcome is Outcome.VIOLATION for f in report.findings)
    assert all(f.reproduced is True for f in report.findings)
    # The first finding is the one the report has always headlined.
    assert report.finding == report.findings[0]
    assert report.scenario == report.findings[0].scenario
    assert report.steps == report.findings[0].steps


def test_each_finding_has_its_own_minimal_scenario_that_replays_alone():
    rules = builtin_plus(SAME_STEP)
    report = explore(lambda: adapter_for(STALE), seed=1, rules=rules).report
    evaluator = evaluator_for_report(report.rules)
    everything = {p.id for p in evaluator.properties}
    for finding in report.findings:
        assert finding.scenario is not None
        alone = replay(
            finding.scenario,
            lambda: adapter_for(STALE),
            evaluator=evaluator.muting(everything - {finding.property_id}),
        )
        assert alone.outcome is Outcome.VIOLATION
        assert alone.failure is not None and alone.failure.record.index == finding.step_index
        # ... and the fixed build is clean for it.
        clean = replay(
            finding.scenario,
            fixed_adapter,
            evaluator=evaluator.muting(everything - {finding.property_id}),
        )
        assert clean.outcome is Outcome.PASS


def test_rules_that_fail_in_different_sequences_are_all_reported():
    # TI-1 needs a stale cross-tenant read; the viewer rule needs a viewer write.
    # A single search stops at whichever it meets first.
    rules = builtin_plus(OTHER_SEQUENCE)
    found = explore(lambda: adapter_for(STALE | VIEWER), seed=1, rules=rules)
    assert found.outcome is Outcome.VIOLATION
    assert {"TI-1", "AZ-1", "viewer-write-is-rejected"} <= set(ids(found.report))
    assert all(f.reproduced for f in found.report.findings)
    # Distinct counterexamples, each ending on its own failing step.
    by_rule = {f.property_id: f for f in found.report.findings}
    assert by_rule["TI-1"].scenario != by_rule["viewer-write-is-rejected"].scenario
    assert found.report.executions > 200  # it kept searching after the first failure


def test_a_rule_that_never_fails_is_not_reported_alongside_the_failing_ones():
    rules = builtin_plus(SAME_STEP + LISTS_ARE_FINE)
    report = explore(lambda: adapter_for(STALE), seed=1, rules=rules).report
    assert "list-has-no-foreign-documents" not in ids(report)
    assert "TI-1" in ids(report)


def test_passing_run_has_no_findings():
    report = explore(fixed_adapter, seed=1, max_examples=30, rules=builtin_plus(SAME_STEP)).report
    assert report.outcome is Outcome.PASS
    assert report.finding is None and report.findings == []


def test_the_search_is_repeatable():
    rules = builtin_plus(SAME_STEP + OTHER_SEQUENCE)
    one = explore(lambda: adapter_for(STALE | VIEWER), seed=3, max_examples=120, rules=rules).report
    two = explore(lambda: adapter_for(STALE | VIEWER), seed=3, max_examples=120, rules=rules).report
    assert one.model_dump() == two.model_dump()


# -- muting: the mechanism behind the repeated search --------------------------


def _attack() -> list[object]:
    return [
        CreateOrg(ref="org0", name="org0"),
        CreateOrg(ref="org1", name="org1"),
        CreateUser(ref="user0", org="org0", role=Role.ADMIN),
        CreateUser(ref="user1", org="org1", role=Role.VIEWER),
        CreateDocument(ref="doc0", actor="user0", content="a"),
        UpdateDocument(actor="user0", doc="doc0", content="b"),
        ReadDocument(actor="user1", doc="doc0"),
    ]


def test_a_muted_rule_is_still_evaluated_but_does_not_fail_the_run():
    evaluator = Evaluator().muting({"TI-1"})
    engine = Engine(adapter_for(STALE), evaluator)
    engine.reset()
    try:
        for op in _attack():
            engine.apply(op)  # type: ignore[arg-type]
    finally:
        engine.close()
    last = engine.history[-1]
    assert [e.outcome for e in last.evaluations if e.property_id == "TI-1"] == [Outcome.VIOLATION]
    assert engine.muted_violation is True


def test_without_muting_the_same_step_raises():
    engine = Engine(adapter_for(STALE), Evaluator())
    engine.reset()
    try:
        for op in _attack()[:-1]:
            engine.apply(op)  # type: ignore[arg-type]
        raised = False
        try:
            engine.apply(_attack()[-1])  # type: ignore[arg-type]
        except AssertionError:
            raised = True
    finally:
        engine.close()
    assert raised and engine.muted_violation is False


def test_muting_does_not_change_the_original_evaluator():
    base = Evaluator()
    muted = base.muting({"TI-1"})
    assert base.muted == frozenset() and muted.muted == {"TI-1"}
    assert muted.properties == base.properties


# -- reports ------------------------------------------------------------------


def test_report_round_trips_and_old_reports_still_load():
    report = explore(lambda: adapter_for(STALE), seed=1, rules=builtin_plus(SAME_STEP)).report
    again = Report.model_validate_json(report.model_dump_json())
    assert again == report
    old = json.loads(report.model_dump_json())
    for key in ("findings",):
        old.pop(key)
    for finding in (old["finding"],):
        for key in ("scenario", "steps", "reproduced"):
            finding.pop(key)
    loaded = Report.model_validate(old)
    assert loaded.finding is not None and loaded.findings == []
    assert "Finding" in render_text(loaded) or "VIOLATION" in render_text(loaded)
    assert render_html(loaded)


def test_text_report_lists_every_failed_rule():
    report = explore(lambda: adapter_for(STALE), seed=1, rules=builtin_plus(SAME_STEP)).report
    text = render_text(report)
    assert "2 rules violated: TI-1, read-returns-own-tenant" in text
    assert "=== Finding 1 of 2 ===" in text and "=== Finding 2 of 2 ===" in text
    assert text.count("VIOLATION: ") == 2


def test_a_single_failure_keeps_the_original_text_layout():
    report = explore(lambda: adapter_for(STALE), seed=1).report
    text = render_text(report)
    assert "rules violated" not in text and "=== Finding" not in text
    assert len(report.findings) == 1
