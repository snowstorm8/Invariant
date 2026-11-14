"""The console's project workflow: pick a folder, inspect it, start it, run the rules, read reports.

The application under test here is the Meridian Docs example, started as a real local process
from its ``invariant.toml`` and exercised over real HTTP.
"""

import http.client
import json
import threading

import pytest

from invariant.console import dialogs
from invariant.console.app import ConsoleApp, ConsoleError
from invariant.console.project import MANIFEST_NAME, RunningProject, load_manifest
from invariant.console.server import make_server
from invariant.console.store import RuleStore
from meridian_support import DEFECTS, MERIDIAN, copy_project


@pytest.fixture
def app(tmp_path):
    console = ConsoleApp(None, RuleStore(tmp_path / "rules.json"), start_dir=MERIDIAN.parent)
    yield console
    console.close()


def test_without_a_project_rules_can_be_written_but_nothing_can_run(app):
    boot = app.bootstrap()
    assert boot["target"] is None and boot["project"]["open"] is False
    assert len(boot["rules"]) == 29  # the default library is there before any folder is chosen
    with pytest.raises(ConsoleError, match="open a project folder first"):
        app.scan({})
    with pytest.raises(ConsoleError, match="open a project folder first"):
        app.replay({"report": {}})


def test_inspecting_a_folder_reads_the_manifest_and_runs_nothing(app):
    got = app.project_inspect({"path": str(MERIDIAN)})
    assert got["error"] == "" and got["manifest"]["name"] == "Meridian Docs"
    assert got["manifest"]["command"].startswith("python server.py")
    assert app.project_state()["open"] is False


def test_a_folder_that_is_not_a_project_is_explained_not_raised(app, tmp_path):
    got = app.project_inspect({"path": str(tmp_path)})
    assert got["manifest"] is None and MANIFEST_NAME in got["error"]
    with pytest.raises(ConsoleError, match="path must be a folder path"):
        app.project_inspect({"path": " "})
    with pytest.raises(ConsoleError, match=MANIFEST_NAME):
        app.project_open({"path": str(tmp_path)})


def test_the_folder_dialog_result_is_described(app, monkeypatch):
    monkeypatch.setattr(dialogs, "choose_folder", lambda start: dialogs.Choice(MERIDIAN))
    got = app.project_pick({})
    assert got["supported"] and got["manifest"]["name"] == "Meridian Docs" and got["path"] == str(MERIDIAN)

    monkeypatch.setattr(dialogs, "choose_folder", lambda start: dialogs.Choice(None))
    assert app.project_pick({})["path"] is None

    monkeypatch.setattr(dialogs, "choose_folder", lambda start: dialogs.Choice(None, supported=False))
    assert app.project_pick({})["supported"] is False

    monkeypatch.setattr(dialogs, "choose_folder", lambda start: dialogs.Choice(None, error="no display"))
    with pytest.raises(ConsoleError, match="no display"):
        app.project_pick({})


def test_the_dialog_opens_where_the_examples_are(app, monkeypatch):
    seen = []
    monkeypatch.setattr(dialogs, "choose_folder", lambda start: seen.append(start) or dialogs.Choice(None))
    app.project_pick({})
    assert seen == [MERIDIAN.parent]


def test_open_starts_the_application_and_close_stops_it(app):
    out = app.project_open({"path": str(MERIDIAN)})
    project = out["project"]["project"]
    assert out["target"]["name"] == "Meridian Docs" and out["target"]["options"] == []
    assert project["running"] and project["url"].startswith("http://127.0.0.1:")
    assert len(out["rules"]) == 29
    running = app._project
    assert running is not None and running.running

    closed = app.project_close({})
    assert closed["target"] is None and closed["project"]["open"] is False
    assert not running.running


def test_opening_another_project_stops_the_previous_one(app, tmp_path):
    app.project_open({"path": str(MERIDIAN)})
    first = app._project
    app.project_open({"path": str(copy_project(tmp_path, flags="none"))})
    assert first is not None and not first.running and app._project is not first
    assert app._project is not None and app._project.running


def test_an_application_that_exits_at_start_up_is_reported_with_its_output(app, tmp_path):
    (tmp_path / MANIFEST_NAME).write_text(
        '[run]\ncommand = ["python", "-c", "print(\'config error: no database\'); raise SystemExit(3)", "{port}"]\n'
        "start_timeout = 10\n"
    )
    with pytest.raises(ConsoleError, match=r"exited with status 3[\s\S]*no database"):
        app.project_open({"path": str(tmp_path)})
    assert app.project_state()["open"] is False


def test_an_application_that_never_answers_is_reported_and_stopped(tmp_path):
    (tmp_path / MANIFEST_NAME).write_text(
        '[run]\ncommand = ["python", "-c", "import time; time.sleep(30)", "{port}"]\nstart_timeout = 1\n'
    )
    running = RunningProject(load_manifest(tmp_path))
    with pytest.raises(Exception, match="did not answer /"):
        running.start()
    assert not running.running


def test_the_application_gets_only_a_small_environment(tmp_path, monkeypatch):
    monkeypatch.setenv("SOME_API_KEY", "must-not-leak")
    (tmp_path / "probe.py").write_text(
        "import os, sys\nfrom http.server import BaseHTTPRequestHandler, HTTPServer\n"
        "class H(BaseHTTPRequestHandler):\n"
        "    def do_GET(self):\n"
        "        body = ('leak' if 'SOME_API_KEY' in os.environ else 'clean').encode()\n"
        "        self.send_response(200); self.send_header('Content-Length', str(len(body))); self.end_headers(); self.wfile.write(body)\n"
        "    def log_message(self, *a): pass\n"
        "HTTPServer(('127.0.0.1', int(sys.argv[1])), H).serve_forever()\n"
    )
    (tmp_path / MANIFEST_NAME).write_text('[run]\ncommand = ["python", "probe.py", "{port}"]\nhealth = "/"\n')
    running = RunningProject(load_manifest(tmp_path))
    running.start()
    try:
        import httpx

        assert httpx.get(running.url, trust_env=False).text == "clean"
    finally:
        running.stop()


def test_the_default_rules_find_the_hidden_defects_of_the_running_application(app):
    """The demo flow: open the folder, run every active rule, read the report."""
    app.project_open({"path": str(MERIDIAN)})
    scan = app.scan({"seed": 1, "max_examples": 200})
    report = scan["report"]
    assert report["outcome"] == "VIOLATION" and report["target"] == "Meridian Docs"
    found = {f["property_id"] for f in report["findings"] if f["outcome"] == "VIOLATION"}
    assert set(DEFECTS.values()) <= found, sorted(set(DEFECTS.values()) - found)
    assert len(found) >= 20
    assert all(f["scenario"] and len(f["scenario"]["operations"]) <= 12 for f in report["findings"])

    replay = app.replay({"report": report})
    assert replay["outcome"] == "VIOLATION"
    assert all(f["reproduced"] for f in replay["findings"]), replay["findings"]


def test_the_fixed_application_passes_every_default_rule(app, tmp_path):
    app.project_open({"path": str(copy_project(tmp_path, flags="none"))})
    report = app.scan({"seed": 1, "max_examples": 150})["report"]
    assert report["outcome"] == "PASS" and report["findings"] == []


# -- over HTTP ----------------------------------------------------------------


@pytest.fixture
def server(app):
    srv = make_server(app, port=0)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    yield srv.server_address[1]
    srv.shutdown()
    srv.server_close()


def call(port, method, path, body=None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=120)
    headers = {"Content-Type": "application/json"} if body is not None else {}
    conn.request(method, path, json.dumps(body) if body is not None else None, headers)
    response = conn.getresponse()
    return response.status, json.loads(response.read())


def test_the_workflow_over_http(server):
    status, boot = call(server, "GET", "/api/bootstrap")
    assert status == 200 and boot["target"] is None and boot["project"]["dialog"] in (True, False)

    status, got = call(server, "POST", "/api/project/inspect", {"path": str(MERIDIAN)})
    assert status == 200 and got["manifest"]["name"] == "Meridian Docs"

    status, opened = call(server, "POST", "/api/project/open", {"path": str(MERIDIAN)})
    assert status == 200 and opened["project"]["project"]["running"]
    assert call(server, "GET", "/api/project")[1]["open"] is True

    status, scan = call(server, "POST", "/api/scan", {"seed": 1, "max_examples": 60})
    assert status == 200 and scan["report"]["outcome"] == "VIOLATION"

    status, closed = call(server, "POST", "/api/project/close", {})
    assert status == 200 and closed["target"] is None
    status, err = call(server, "POST", "/api/scan", {})
    assert status == 400 and "open a project folder" in err["error"]
