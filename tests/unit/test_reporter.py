import json

from invariant.core.engine import PropertyViolationError, StepRecord
from invariant.core.scenario import ReadDocument
from invariant.evaluation.violations import Evaluation, Outcome
from invariant.reporting.models import Report
from invariant.reporting.reporter import build_report, load_report, render_text, save_report


def failure():
    op = ReadDocument(actor="user1", doc="doc0")
    ev = Evaluation(
        property_id="TI-1",
        outcome=Outcome.VIOLATION,
        summary="user1 received data of doc0",
        evidence={"leaked": [{"doc": "doc0"}]},
    )
    rec = StepRecord(index=0, operation=op, allowed_by_policy=False, policy_reason="cross-tenant read",
                     status=200, evaluations=[ev])
    return PropertyViolationError("TI-1 violated", rec, [rec])


def test_pass_report_has_no_finding_and_states_limits():
    r = build_report(target="t", failure=None, executions=10, seed=1, reproduced=None)
    assert r.outcome is Outcome.PASS and r.finding is None and r.scenario is None
    assert "not a proof" in render_text(r)


def test_violation_report_identifies_property_and_sequence(tmp_path):
    r = build_report(target="t", failure=failure(), executions=5, seed=7, reproduced=True)
    assert r.outcome is Outcome.VIOLATION
    assert (r.finding.property_id, r.finding.property_name) == ("TI-1", "tenant-read-isolation")
    assert "another organization" in r.finding.statement
    assert r.scenario.operations == [ReadDocument(actor="user1", doc="doc0")]
    text = render_text(r)
    assert "user1 reads doc0" in text and "<-- VIOLATION" in text and "Reproduced" in text

    path = tmp_path / "r.json"
    save_report(r, path)
    assert json.loads(path.read_text())["finding"]["property_id"] == "TI-1"
    assert load_report(path) == r


def test_unreproduced_finding_is_called_out():
    r = build_report(target="t", failure=failure(), executions=5, seed=None, reproduced=False)
    assert "NO" in render_text(r)


def test_report_roundtrips_through_json():
    r = build_report(target="t", failure=failure(), executions=5, seed=7, reproduced=True)
    assert Report.model_validate_json(r.model_dump_json()) == r
