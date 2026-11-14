"""The console: rule management and exploration, as the browser drives it."""

import http.client
import json
import threading

import pytest
from vulnerable_saas.target import console_target

from invariant.console.app import EXAMPLES, ConsoleApp, ConsoleError
from invariant.console.server import make_server
from invariant.console.store import RuleStore
from invariant.reporting.models import Report

CUSTOM = EXAMPLES[0]["source"]  # read-returns-own-tenant
RULE_FILE = {
    "version": 1,
    "rules": [
        {
            "name": "no-foreign-org-id",
            "severity": "high",
            "when": {"==": [{"ref": "operation.type"}, {"value": "read_document"}]},
            "always": "has(response.json.org_id) implies response.json.org_id == actor.org_id",
        },
        {"name": "answers", "enabled": False, "never": {"==": [{"ref": "response.status"}, 418]}},
    ],
}


@pytest.fixture
def app(tmp_path):
    return ConsoleApp(console_target(), RuleStore(tmp_path / "store" / "rules.json"))


def by_name(rules, name):
    return next(r for r in rules if r["name"] == name)


# -- reference and validation -------------------------------------------------


def test_bootstrap_describes_target_language_and_builtin_rules(app):
    boot = app.bootstrap()
    assert boot["target"]["name"] == "vulnerable_saas"
    assert {o["id"] for o in boot["target"]["options"]} == {
        "stale-cache-read", "update-missing-tenant-check", "viewer-can-update"}  # fmt: skip
    schema = boot["language"]["schema"]
    assert schema["name"] == "document-saas"
    assert [r["name"] for r in schema["roots"]] == [
        "operation", "actor", "resource", "policy", "state", "events", "response"]  # fmt: skip
    assert by_name(schema["roots"], "response")["late"] is True
    assert [p["name"] for p in schema["probes"]] == ["org_documents"]
    assert "diff" in {f["name"] for f in boot["language"]["functions"]}
    builtin = [r for r in boot["rules"] if r["origin"] == "builtin"]
    assert [(r["id"], r["enabled"], r["editable"], r["valid"]) for r in builtin] == [
        ("TI-1", True, False, True), ("TI-2", True, False, True), ("AZ-1", True, False, True)]  # fmt: skip
    json.dumps(boot)  # everything the page receives is plain JSON


def test_every_shipped_example_and_the_new_rule_template_validate(app):
    boot = app.bootstrap()
    for source in [boot["language"]["template"], *(e["source"] for e in EXAMPLES)]:
        result = app.validate({"source": source})
        assert result["ok"], result["diagnostics"]
        assert result["rules"][0]["json"]["name"] == result["rules"][0]["name"]


def test_validate_reports_syntax_and_semantic_problems_with_positions(app):
    syntax = app.validate({"source": 'rule "x" {\n  never a = 1\n}'})
    assert not syntax["ok"] and syntax["rules"] == []
    assert [(d["line"], d["col"]) for d in syntax["diagnostics"]] == [(2, 11)]
    semantic = app.validate({"source": 'rule "x" {\n  never actor.rol == "v"\n}'})
    assert not semantic["ok"]
    (d,) = semantic["diagnostics"]
    assert (d["rule"], d["line"]) == ("x", 2) and "did you mean 'role'" in d["message"]
    as_json = app.validate({"source": json.dumps({"name": "j", "always": {"nope": 1}}), "format": "json"})
    assert as_json["diagnostics"][0]["path"] == "always"


def test_validate_flags_an_id_that_is_already_taken(app):
    taken = app.validate({"source": 'rule "mine" { id "TI-1" always true }'})
    assert not taken["ok"] and "already used by a built-in rule" in taken["diagnostics"][0]["message"]
    key = app.save_rule({"source": CUSTOM})["saved"][0]
    assert not app.validate({"source": CUSTOM})["ok"]  # a second rule with the same id
    assert app.validate({"source": CUSTOM, "key": key})["ok"]  # editing the rule itself


@pytest.mark.parametrize("request_", [{}, {"source": 5}, {"source": "x", "format": "yaml"}])
def test_validate_rejects_malformed_requests(app, request_):
    with pytest.raises(ConsoleError):
        app.validate(request_)


# -- create, edit, enable, delete ---------------------------------------------


def test_create_edit_disable_and_delete_a_rule(app):
    out = app.save_rule({"source": CUSTOM})
    (key,) = out["saved"]
    rule = by_name(out["rules"], "read-returns-own-tenant")
    assert (rule["key"], rule["origin"], rule["enabled"], rule["valid"], rule["editable"]) == (
        key, "authored", True, True, True)  # fmt: skip
    assert rule["severity"] == "critical" and rule["source"] == CUSTOM

    edited = app.save_rule({"key": key, "source": CUSTOM.replace("critical", "low")})
    assert edited["saved"] == [key] and len(edited["rules"]) == 4
    assert by_name(edited["rules"], "read-returns-own-tenant")["severity"] == "low"

    off = app.set_enabled({"key": key, "enabled": False})["rules"]
    assert by_name(off, "read-returns-own-tenant")["enabled"] is False
    off = app.set_enabled({"key": "builtin:TI-2", "enabled": False})["rules"]
    assert by_name(off, "tenant-write-isolation")["enabled"] is False
    assert app.active_ruleset().ids() == ["TI-1", "AZ-1"]

    left = app.delete_rule({"key": key})["rules"]
    assert [r["origin"] for r in left] == ["builtin"] * 3
    with pytest.raises(ConsoleError, match="cannot be deleted"):
        app.delete_rule({"key": "builtin:TI-1"})
    with pytest.raises(KeyError):
        app.delete_rule({"key": key})


def test_a_source_with_several_rules_becomes_several_entries(app):
    out = app.save_rule({"source": EXAMPLES[1]["source"] + "\n" + EXAMPLES[2]["source"]})
    assert len(out["saved"]) == 2
    names = [r["name"] for r in out["rules"] if r["origin"] == "authored"]
    assert names == ["no-read-after-delete", "read-shows-expected-version"]


def test_an_invalid_rule_is_kept_as_a_draft_but_cannot_run(app):
    out = app.save_rule({"source": 'rule "wip" {\n    always actor.rol == "x"\n}'})
    draft = by_name(out["rules"], "wip")
    assert draft["valid"] is False and draft["json"] is None and draft["diagnostics"]
    with pytest.raises(ConsoleError, match='fix or switch off the rules that do not validate: "wip"') as caught:
        app.scan({"options": [], "max_examples": 1})
    assert caught.value.diagnostics[0]["line"] == 2
    app.set_enabled({"key": draft["key"], "enabled": False})
    assert app.active_ruleset().ids() == ["TI-1", "TI-2", "AZ-1"]
    unparsable = app.save_rule({"source": 'rule "half'})
    assert by_name(unparsable["rules"], "half")["valid"] is False


def test_rules_and_switches_survive_a_restart(tmp_path):
    path = tmp_path / "rules.json"
    first = ConsoleApp(console_target(), RuleStore(path))
    key = first.save_rule({"source": CUSTOM})["saved"][0]
    first.set_enabled({"key": "builtin:AZ-1", "enabled": False})
    second = ConsoleApp(console_target(), RuleStore(path))
    assert by_name(second.list_rules(), "read-returns-own-tenant")["key"] == key
    assert second.active_ruleset().ids() == ["TI-1", "TI-2", "read-returns-own-tenant"]
    assert second.save_rule({"source": EXAMPLES[1]["source"]})["saved"] != [key]  # keys are not reused
    path.write_text("{broken")
    with pytest.raises(ValueError, match="cannot read rule store"):
        RuleStore(path)


# -- JSON upload --------------------------------------------------------------


def test_upload_json_adds_rules_shown_in_the_rule_language(app):
    out = app.import_json({"filename": "team.json", "content": json.dumps(RULE_FILE)})
    assert len(out["imported"]) == 2
    rule = by_name(out["rules"], "no-foreign-org-id")
    assert (rule["origin"], rule["filename"], rule["enabled"], rule["valid"]) == (
        "imported", "team.json", True, True)  # fmt: skip
    assert rule["source"].startswith('rule "no-foreign-org-id" {\n    severity high\n')
    assert by_name(out["rules"], "answers")["enabled"] is False  # "enabled": false is honoured
    assert app.active_ruleset().ids() == ["TI-1", "TI-2", "AZ-1", "no-foreign-org-id"]


@pytest.mark.parametrize(
    ("content", "message", "path"),
    [
        ("{not json", "not valid JSON", None),
        (json.dumps({"rules": [{"name": "a", "always": {"equals": [1, 2]}}]}), "unknown expression operator 'equals'", "rules[0].always"),
        (json.dumps({"name": "a", "always": "actor.rol == 'x'"}), "actor has no field 'rol'", "always"),
        (json.dumps({"name": "a", "id": "TI-1", "always": True}), "belongs to a built-in rule", None),
        (json.dumps([{"name": "a", "always": True}, {"name": "a", "always": True}]), "defined twice", None),
    ],
)
def test_a_bad_upload_is_rejected_whole_with_specific_diagnostics(app, content, message, path):
    with pytest.raises(ConsoleError, match="bad.json was not imported") as caught:
        app.import_json({"filename": "bad.json", "content": content})
    diagnostics = caught.value.diagnostics
    assert any(message in d["message"] for d in diagnostics), diagnostics
    assert path is None or diagnostics[0]["path"] == path
    assert [r["origin"] for r in app.list_rules()] == ["builtin"] * 3  # nothing was stored


def test_uploading_an_existing_id_needs_replace(app):
    app.import_json({"filename": "v1.json", "content": json.dumps(RULE_FILE)})
    with pytest.raises(ConsoleError) as caught:
        app.import_json({"filename": "v2.json", "content": json.dumps(RULE_FILE)})
    assert "already exists" in caught.value.diagnostics[0]["message"]
    changed = json.loads(json.dumps(RULE_FILE))
    changed["rules"][0]["severity"] = "low"
    out = app.import_json({"filename": "v2.json", "content": json.dumps(changed), "replace": True})
    custom = [r for r in out["rules"] if r["origin"] != "builtin"]
    assert len(custom) == 2
    assert (custom[0]["severity"], custom[0]["filename"]) == ("low", "v2.json")


def test_export_can_be_uploaded_into_another_console(app, tmp_path):
    app.save_rule({"source": CUSTOM})
    app.import_json({"filename": "team.json", "content": json.dumps(RULE_FILE)})
    app.save_rule({"source": 'rule "draft" { always nope }'})  # invalid drafts are not exported
    exported = app.export()
    assert [r["name"] for r in exported["rules"]] == ["read-returns-own-tenant", "no-foreign-org-id", "answers"]
    other = ConsoleApp(console_target(), RuleStore(tmp_path / "other.json"))
    other.import_json({"filename": "export.json", "content": json.dumps(exported)})
    mine = {r["name"]: r["json"] for r in app.list_rules() if r["json"] and r["origin"] != "builtin"}
    theirs = {r["name"]: r["json"] for r in other.list_rules() if r["origin"] != "builtin"}
    assert mine == theirs


# -- running ------------------------------------------------------------------


def test_run_with_only_a_user_rule_then_replay_on_both_builds(app):
    app.save_rule({"source": CUSTOM})
    for rule_id in ("TI-1", "TI-2", "AZ-1"):
        app.set_enabled({"key": f"builtin:{rule_id}", "enabled": False})
    out = app.scan({"options": ["stale-cache-read"], "seed": 1})
    report = Report.model_validate(out["report"])
    assert out["rules_used"] == [{"id": "read-returns-own-tenant", "name": "read-returns-own-tenant", "severity": "critical"}]
    assert report.outcome == "VIOLATION" and report.finding.property_id == "read-returns-own-tenant"
    assert report.finding.severity == "critical" and report.reproduced is True
    assert report.target == "vulnerable_saas[stale-cache-read]"
    assert len(out["steps_text"]) == len(report.steps) and out["steps_text"][-1].endswith("reads doc0")
    assert [r["name"] for r in report.rules] == ["read-returns-own-tenant"]

    # The report carries its rules: replay judges with them even after the rule is gone.
    app.delete_rule({"key": by_name(app.list_rules(), "read-returns-own-tenant")["key"]})
    hit = app.replay({"options": ["stale-cache-read"], "report": out["report"]})
    assert (hit["outcome"], hit["valid"], hit["violated"]) == ("VIOLATION", True, ["read-returns-own-tenant"])
    fixed = app.replay({"options": [], "report": out["report"]})
    assert (fixed["outcome"], fixed["message"], fixed["target"]) == ("PASS", "", "vulnerable_saas[fixed]")
    assert "invariant-report" in app.report_html({"report": out["report"]})["html"]


def test_default_selection_reproduces_the_builtin_demo(app):
    out = app.scan({"options": ["stale-cache-read"], "seed": 1})
    assert out["report"]["finding"]["property_id"] == "TI-1"
    assert [r["id"] for r in out["rules_used"]] == ["TI-1", "TI-2", "AZ-1"]
    assert app.replay({"options": [], "report": out["report"]})["outcome"] == "PASS"
    assert app.scan({"options": [], "seed": 1, "max_examples": 25})["report"]["outcome"] == "PASS"


def test_a_disabled_rule_is_not_checked(app):
    app.set_enabled({"key": "builtin:AZ-1", "enabled": False})
    app.set_enabled({"key": "builtin:TI-2", "enabled": False})
    out = app.scan({"options": ["viewer-can-update"], "seed": 1, "max_examples": 40})
    assert out["report"]["outcome"] != "VIOLATION"  # only AZ-1 would have attributed it
    app.set_enabled({"key": "builtin:AZ-1", "enabled": True})
    out = app.scan({"options": ["viewer-can-update"], "seed": 1, "max_examples": 40})
    assert out["report"]["finding"]["property_id"] == "AZ-1"


@pytest.mark.parametrize(
    ("request_", "message"),
    [
        ({"options": "stale-cache-read"}, "options must be a list of strings"),
        ({"options": ["nope"]}, "unknown options"),
        ({"seed": "1"}, "seed must be an integer or null"),
        ({"max_examples": 0}, "max_examples must be at least 1"),
        ({"max_examples": True}, "max_examples must be an integer"),
    ],
)
def test_scan_rejects_bad_input_before_running(app, monkeypatch, request_, message):
    monkeypatch.setattr("invariant.console.app.explore", lambda *a, **k: pytest.fail("explored"))
    with pytest.raises(ValueError, match=message):
        app.scan(request_)


def test_scan_refuses_to_run_with_nothing_enabled(app):
    for rule_id in ("TI-1", "TI-2", "AZ-1"):
        app.set_enabled({"key": f"builtin:{rule_id}", "enabled": False})
    with pytest.raises(ConsoleError, match="no rule is enabled"):
        app.scan({"options": []})


# -- over HTTP ----------------------------------------------------------------


@pytest.fixture
def server(app):
    srv = make_server(app, port=0)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    yield srv.server_address[1]
    srv.shutdown()
    srv.server_close()


def call(port, method, path, body=None, headers=None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=60)
    send = {"Content-Type": "application/json"} if body is not None else {}
    send.update(headers or {})
    conn.request(method, path, json.dumps(body) if body is not None else None, send)
    response = conn.getresponse()
    raw = response.read()
    conn.close()
    kind = response.getheader("Content-Type", "")
    return response.status, (json.loads(raw) if kind.startswith("application/json") else raw.decode())


def test_the_page_and_the_whole_workflow_over_http(server):
    status, page = call(server, "GET", "/")
    assert status == 200 and "<title>Invariant — Console</title>" in page
    for control in ('id="new-rule"', 'id="upload-input"', 'id="validate-btn"', 'id="save-btn"', 'id="run-btn"'):
        assert control in page

    status, boot = call(server, "GET", "/api/bootstrap")
    assert status == 200 and len(boot["rules"]) == 3

    status, bad = call(server, "POST", "/api/validate", {"source": 'rule "x" { always actor.rol }'})
    assert status == 200 and bad["ok"] is False

    status, saved = call(server, "POST", "/api/rules", {"source": CUSTOM})
    assert status == 200 and len(saved["rules"]) == 4
    status, imported = call(server, "POST", "/api/rules/import", {"filename": "t.json", "content": json.dumps(RULE_FILE)})
    assert status == 200 and len(imported["imported"]) == 2
    for rule_id in ("TI-1", "TI-2", "AZ-1"):
        assert call(server, "POST", "/api/rules/enabled", {"key": f"builtin:{rule_id}", "enabled": False})[0] == 200

    status, scan = call(server, "POST", "/api/scan", {"options": ["stale-cache-read"], "seed": 1})
    assert status == 200 and scan["report"]["outcome"] == "VIOLATION"
    assert scan["report"]["finding"]["property_id"] in ("read-returns-own-tenant", "no-foreign-org-id")
    status, fixed = call(server, "POST", "/api/replay", {"options": [], "report": scan["report"]})
    assert status == 200 and fixed["outcome"] == "PASS"
    status, html = call(server, "POST", "/api/report-html", {"report": scan["report"]})
    assert status == 200 and html["html"].lstrip().lower().startswith("<!doctype html>")
    status, exported = call(server, "GET", "/api/rules/export")
    assert status == 200 and len(exported["rules"]) == 3
    status, _ = call(server, "POST", "/api/rules/delete", {"key": saved["saved"][0]})
    assert status == 200


def test_errors_are_json_with_diagnostics(server):
    status, body = call(server, "POST", "/api/rules/import", {"filename": "b.json", "content": "{"})
    assert status == 400 and "was not imported" in body["error"] and body["diagnostics"]
    assert call(server, "POST", "/api/replay", {"report": {"nope": 1}})[0] == 400
    assert call(server, "POST", "/api/rules/delete", {"key": "r999"})[0] == 400
    assert call(server, "POST", "/api/nope", {})[0] == 404
    assert call(server, "GET", "/etc/passwd")[0] == 404


def test_the_server_only_answers_same_origin_json_on_its_own_address(server):
    # DNS rebinding: a page on another name resolving to this address.
    assert call(server, "GET", "/api/bootstrap", headers={"Host": "evil.example"})[0] == 403
    # A cross-site form post cannot use application/json without a preflight.
    conn = http.client.HTTPConnection("127.0.0.1", server, timeout=10)
    conn.request("POST", "/api/rules/delete", "key=r1", {"Content-Type": "application/x-www-form-urlencoded"})
    assert conn.getresponse().status == 415
    conn.close()
    status, _ = call(server, "POST", "/api/validate", {"source": "x"}, {"Origin": "https://evil.example"})
    assert status == 403
    status, _ = call(server, "POST", "/api/validate", {"source": "x"}, {"Origin": f"http://localhost:{server}"})
    assert status == 200
    conn = http.client.HTTPConnection("127.0.0.1", server, timeout=10)
    conn.request("POST", "/api/validate", "[1]", {"Content-Type": "application/json"})
    assert conn.getresponse().status == 400
    conn.close()
