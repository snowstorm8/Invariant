"""Behavioural tests for ``web_bridge.py`` (one JSON request on stdin, one JSON reply on stdout).

Protocol-level tests run the script as a subprocess. Tests that need to control
exploration or replay import the module and monkeypatch those two calls, so they do
not depend on Hypothesis' randomness.
"""

import importlib.util
import io
import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

from invariant.analysis.reproduction import ReplayResult
from invariant.core.scenario import CreateDocument, CreateOrg, Scenario
from invariant.evaluation.violations import Outcome
from invariant.exploration.runner import ExplorationResult
from invariant.properties.registry import CATALOG
from invariant.reporting.models import Finding, Report
from vulnerable_saas.app.models import KNOWN_DEFECTS

ROOT = Path(__file__).parents[2]
BRIDGE = ROOT / "web_bridge.py"
ALL_DEFECTS = sorted(KNOWN_DEFECTS)

EMBEDDED = re.compile(
    r'<script id="invariant-report" type="application/json">(.*?)</script>', re.DOTALL
)


def run_bridge(request, *, raw=None):
    """Run the bridge as a subprocess; returns (exit_code, stdout, stderr)."""
    stdin = raw if raw is not None else json.dumps(request)
    proc = subprocess.run(
        [sys.executable, str(BRIDGE)],
        input=stdin,
        capture_output=True,
        text=True,
        cwd=ROOT,  # the bridge adds the relative path "examples" to sys.path
        timeout=120,
    )
    return proc.returncode, proc.stdout, proc.stderr


def ok(request):
    code, out, _ = run_bridge(request)
    assert code == 0, out
    return json.loads(out)


def err(request=None, *, raw=None):
    code, out, _ = run_bridge(request, raw=raw)
    assert code == 1, out
    body = json.loads(out)  # stdout is exactly one JSON document
    assert set(body) == {"error"}
    assert isinstance(body["error"], str) and body["error"]
    return body["error"]


def make_report(**kw):
    base = {"tool_version": "0", "target": "t", "outcome": Outcome.PASS, "executions": 0, "seed": None}
    base.update(kw)
    return Report(**base)


def dump(report):
    return json.loads(report.model_dump_json())


SCENARIO = Scenario(operations=[CreateOrg(ref="org0", name="org0")])


# ---------------------------------------------------------------- protocol


def test_success_writes_exactly_one_json_document_and_exits_zero():
    code, out, _ = run_bridge({"action": "catalog"})
    assert code == 0
    # json.loads rejects trailing data, so this proves a single document.
    assert isinstance(json.loads(out), dict)
    assert out.count("\n") <= 1


def test_malformed_json_is_a_structured_error():
    assert "JSONDecodeError" in err(raw="{not json")


def test_empty_stdin_is_a_structured_error():
    assert "JSONDecodeError" in err(raw="")


def test_non_object_request_is_a_structured_error():
    assert "TypeError" in err(raw="[1, 2]")


def test_missing_action_is_a_structured_error():
    assert "action" in err({})


def test_unknown_action_is_a_structured_error():
    assert "unknown action: bogus" in err({"action": "bogus"})


# ----------------------------------------------------------------- catalog


def test_catalog_schema():
    body = ok({"action": "catalog"})
    assert set(body) == {"defects", "properties"}
    for d in body["defects"]:
        assert set(d) == {"id", "title", "description", "property"}
        assert all(isinstance(v, str) and v for v in d.values())
    for p in body["properties"]:
        assert set(p) == {"id", "name", "statement"}
        assert all(isinstance(v, str) and v for v in p.values())


def test_catalog_lists_every_known_defect_once():
    ids = [d["id"] for d in ok({"action": "catalog"})["defects"]]
    assert sorted(ids) == ALL_DEFECTS


def test_catalog_properties_match_registry():
    props = ok({"action": "catalog"})["properties"]
    assert {p["id"] for p in props} == set(CATALOG)
    for p in props:
        registered = CATALOG[p["id"]]
        assert (p["name"], p["statement"]) == (registered.name, registered.statement)


def test_catalog_defects_reference_registered_properties():
    body = ok({"action": "catalog"})
    registered = {p["id"] for p in body["properties"]}
    assert {d["property"] for d in body["defects"]} <= registered


# -------------------------------------------------------------------- html


def test_html_renders_report_data():
    report = make_report(target="vulnerable_saas[fixed]", executions=7, seed=3)
    body = ok({"action": "html", "report": dump(report)})
    assert set(body) == {"html"}
    html = body["html"]
    assert html.lstrip().lower().startswith("<!doctype html>")
    assert "<!-- invariant:report -->" not in html
    match = EMBEDDED.search(html)
    assert match is not None
    assert Report.model_validate_json(match.group(1)) == report


def test_html_missing_report_is_a_structured_error():
    assert "report" in err({"action": "html"})


def test_html_invalid_report_is_a_structured_error():
    assert "ValidationError" in err({"action": "html", "report": {"hello": "world"}})


def test_html_report_controlled_fields_cannot_break_out_of_script_element():
    attack = "</script><script>alert(1)</script><!--"
    report = make_report(
        target=attack,
        outcome=Outcome.VIOLATION,
        finding=Finding(
            property_id="TI-1",
            property_name=attack,
            statement=attack,
            outcome=Outcome.VIOLATION,
            summary=attack,
            step_index=0,
            evidence={"response_excerpt": attack, "nested": [{"x": attack}]},
        ),
        scenario=Scenario(
            operations=[
                CreateOrg(ref="org0", name=attack),
                CreateDocument(ref="doc0", actor="user0", content=attack),
            ]
        ),
        note=attack,
    )
    html = ok({"action": "html", "report": dump(report)})["html"]
    assert "alert(1)</script>" not in html
    assert "<script>alert(1)" not in html
    match = EMBEDDED.search(html)
    assert match is not None
    assert "</script" not in match.group(1).lower()
    assert Report.model_validate_json(match.group(1)) == report


# ------------------------------------------------------------------ replay


@pytest.fixture(scope="module")
def vulnerable_report():
    """A real report from a seeded scan of one defect (also used by scan tests)."""
    return ok({"action": "scan", "defects": ["viewer-can-update"], "seed": 1,
               "max_examples": 50})


def test_replay_without_scenario_is_a_structured_error():
    msg = err({"action": "replay", "report": dump(make_report())})
    assert "no scenario" in msg


def test_replay_missing_report_is_a_structured_error():
    assert "report" in err({"action": "replay"})


def test_replay_invalid_report_is_a_structured_error():
    assert "ValidationError" in err({"action": "replay", "report": {"hello": "world"}})


def test_replay_unknown_defect_is_a_structured_error():
    report = make_report(scenario=SCENARIO)
    assert "unknown defects" in err(
        {"action": "replay", "defects": ["nope"], "report": dump(report)}
    )


def test_replay_reproduces_real_violation_and_passes_on_fixed_target(vulnerable_report):
    report = vulnerable_report["report"]
    assert report["outcome"] == "VIOLATION"
    hit = ok({"action": "replay", "defects": ["viewer-can-update"], "report": report})
    assert hit["outcome"] == "VIOLATION" and hit["valid"] is True
    assert hit["steps"] == len(report["scenario"]["operations"])
    assert "AZ-1" in hit["message"]
    fixed = ok({"action": "replay", "defects": [], "report": report})
    assert fixed["outcome"] == "PASS" and fixed["valid"] is True and fixed["message"] == ""


def test_replay_response_schema_and_arguments(load_bridge, run_inprocess, monkeypatch):
    seen = {}

    def fake_replay(scenario, factory, **kw):
        seen["scenario"], seen["factory"] = scenario, factory
        return ReplayResult(Outcome.VIOLATION, ["a", "b", "c"], RuntimeError("boom"))

    monkeypatch.setattr(load_bridge, "replay", fake_replay)
    monkeypatch.setattr(load_bridge, "adapter_for", lambda defects: ("adapter", defects))
    report = make_report(scenario=SCENARIO)
    out = run_inprocess({"action": "replay", "defects": ["stale-cache-read"],
                         "report": dump(report)})
    assert set(out) == {"outcome", "valid", "message", "steps", "duration_ms"}
    assert out["outcome"] == "VIOLATION"
    assert out["valid"] is True
    assert out["message"] == "boom"
    assert out["steps"] == 3
    assert isinstance(out["duration_ms"], int) and out["duration_ms"] >= 0
    assert seen["scenario"] == SCENARIO
    assert seen["factory"]() == ("adapter", frozenset({"stale-cache-read"}))


def test_replay_invalid_scenario_has_empty_message(load_bridge, run_inprocess, monkeypatch):
    monkeypatch.setattr(
        load_bridge, "replay",
        lambda scenario, factory, **kw: ReplayResult(Outcome.INCONCLUSIVE, [], valid=False),
    )
    out = run_inprocess({"action": "replay", "report": dump(make_report(scenario=SCENARIO))})
    assert (out["outcome"], out["valid"], out["message"], out["steps"]) == (
        "INCONCLUSIVE", False, "", 0)


# -------------------------------------------------------------------- scan


@pytest.fixture(scope="module")
def load_bridge():
    """Import web_bridge.py without leaking its import-time global side effects."""
    import warnings

    saved_path = list(sys.path)
    with warnings.catch_warnings():  # the module installs a blanket "ignore" filter
        spec = importlib.util.spec_from_file_location("web_bridge_under_test", BRIDGE)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    sys.path[:] = saved_path
    return module


@pytest.fixture
def run_inprocess(load_bridge, monkeypatch, capsys):
    def run(request):
        monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(request)))
        load_bridge.main()
        return json.loads(capsys.readouterr().out)

    return run


def fake_explore(calls, outcome=Outcome.PASS):
    def explore(factory, **kw):
        calls.append({"factory": factory, **kw})
        return ExplorationResult(outcome, make_report(target=kw["target"], outcome=outcome,
                                                      seed=kw.get("seed")))

    return explore


def test_scan_passes_defects_seed_and_max_examples_to_exploration(
    load_bridge, run_inprocess, monkeypatch
):
    calls, built = [], []
    monkeypatch.setattr(load_bridge, "explore", fake_explore(calls))
    monkeypatch.setattr(load_bridge, "adapter_for", lambda d: built.append(d) or "adapter")
    out = run_inprocess({"action": "scan", "defects": ["viewer-can-update", "stale-cache-read"],
                         "seed": 42, "max_examples": 7})
    (call,) = calls
    assert call["seed"] == 42 and call["max_examples"] == 7
    assert call["target"] == "vulnerable_saas[stale-cache-read,viewer-can-update]"
    assert call["factory"]() == "adapter"
    assert built == [frozenset({"viewer-can-update", "stale-cache-read"})]
    assert set(out) == {"report", "duration_ms"}
    assert Report.model_validate(out["report"]).target == call["target"]
    assert isinstance(out["duration_ms"], int) and out["duration_ms"] >= 0


def test_scan_defaults(load_bridge, run_inprocess, monkeypatch):
    calls = []
    monkeypatch.setattr(load_bridge, "explore", fake_explore(calls))
    out = run_inprocess({"action": "scan"})
    (call,) = calls
    assert call["seed"] is None and call["max_examples"] == 200
    assert call["target"] == "vulnerable_saas[fixed]"
    assert out["report"]["outcome"] == "PASS"


def test_scan_rejects_unknown_defects_before_exploring(load_bridge, run_inprocess, monkeypatch):
    calls = []
    monkeypatch.setattr(load_bridge, "explore", fake_explore(calls))
    with pytest.raises(ValueError, match="unknown defects"):
        run_inprocess({"action": "scan", "defects": ["viewer-can-update", "bogus"]})
    assert calls == []


def test_scan_unknown_defect_over_the_wire():
    assert "unknown defects" in err({"action": "scan", "defects": ["bogus"]})


BAD_DEFECTS = ["viewer-can-update", 5, None, 1.5, True, {"a": 1}, ["ok", 3], [None], [["x"]]]
BAD_MAX_EXAMPLES = ["10", "abc", 3.7, 10.0, True, False, None, [3], {}, 0, -5]
BAD_SEEDS = ["1", "x", 1.5, 1.0, True, False, [1], {}]


def never_explore(*args, **kwargs):
    raise AssertionError("explore() must not be called for invalid input")


@pytest.mark.parametrize("bad", BAD_DEFECTS)
def test_scan_malformed_defects_is_rejected_as_malformed(bad):
    # Not merely "unknown defects": a bare string must not be split into characters.
    assert "defects must be a list of strings" in err({"action": "scan", "defects": bad})


@pytest.mark.parametrize("bad", BAD_DEFECTS)
def test_replay_malformed_defects_is_rejected_as_malformed(bad):
    report = dump(make_report(scenario=SCENARIO))
    assert "defects must be a list of strings" in err(
        {"action": "replay", "defects": bad, "report": report}
    )


@pytest.mark.parametrize("bad", BAD_MAX_EXAMPLES)
def test_scan_invalid_max_examples_is_rejected(bad):
    assert "max_examples must be" in err({"action": "scan", "max_examples": bad})


@pytest.mark.parametrize("bad", BAD_SEEDS)
def test_scan_invalid_seed_is_rejected(bad):
    assert "seed must be an integer or null" in err({"action": "scan", "seed": bad})


@pytest.mark.parametrize(
    "request_",
    [
        {"defects": "viewer-can-update"},
        {"defects": [1]},
        {"max_examples": 3.7},
        {"max_examples": True},
        {"max_examples": "5"},
        {"max_examples": None},
        {"max_examples": 0},
        {"max_examples": -1},
        {"seed": "1"},
        {"seed": 1.5},
        {"seed": True},
        {"seed": [1]},
    ],
)
def test_scan_never_explores_for_invalid_input(load_bridge, run_inprocess, monkeypatch, request_):
    monkeypatch.setattr(load_bridge, "explore", never_explore)
    with pytest.raises(ValueError):
        run_inprocess({"action": "scan", **request_})


def test_scan_accepts_empty_defect_list(load_bridge, run_inprocess, monkeypatch):
    calls = []
    monkeypatch.setattr(load_bridge, "explore", fake_explore(calls))
    run_inprocess({"action": "scan", "defects": []})
    assert calls[0]["target"] == "vulnerable_saas[fixed]"


@pytest.mark.parametrize("value", [1, 7, 200, 10**6])
def test_scan_accepts_positive_integer_max_examples(load_bridge, run_inprocess, monkeypatch, value):
    calls = []
    monkeypatch.setattr(load_bridge, "explore", fake_explore(calls))
    run_inprocess({"action": "scan", "max_examples": value})
    assert calls[0]["max_examples"] == value and type(calls[0]["max_examples"]) is int


@pytest.mark.parametrize("value", [None, 0, 1, -3, 2**40])
def test_scan_accepts_null_or_integer_seed(load_bridge, run_inprocess, monkeypatch, value):
    calls = []
    monkeypatch.setattr(load_bridge, "explore", fake_explore(calls))
    run_inprocess({"action": "scan", "seed": value})
    assert calls[0]["seed"] == value


def test_scan_real_exploration_finds_the_seeded_defect(vulnerable_report):
    assert set(vulnerable_report) == {"report", "duration_ms"}
    assert isinstance(vulnerable_report["duration_ms"], int)
    assert vulnerable_report["duration_ms"] >= 0
    report = Report.model_validate(vulnerable_report["report"])
    assert report.target == "vulnerable_saas[viewer-can-update]"
    assert report.outcome == Outcome.VIOLATION
    assert report.finding is not None and report.finding.property_id == "AZ-1"
    assert report.seed == 1


def test_scan_real_exploration_of_fixed_target_passes():
    body = ok({"action": "scan", "defects": [], "seed": 1, "max_examples": 10})
    report = Report.model_validate(body["report"])
    assert report.target == "vulnerable_saas[fixed]"
    assert report.outcome == Outcome.PASS and report.finding is None
