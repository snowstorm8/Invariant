"""Rule selection through the web bridge and the command line."""

import json
import subprocess
import sys
from pathlib import Path

from typer.testing import CliRunner

from invariant.cli.main import app
from invariant.console.app import EXAMPLES

ROOT = Path(__file__).parents[2]
EXAMPLES_DIR = str(ROOT / "examples")
VULN = "vulnerable_saas.target:vulnerable_adapter"
FIXED = "vulnerable_saas.target:fixed_adapter"
CUSTOM = EXAMPLES[0]["source"]
runner = CliRunner()


def bridge(request):
    proc = subprocess.run(
        [sys.executable, str(ROOT / "web_bridge.py")],
        input=json.dumps(request), capture_output=True, text=True, cwd=ROOT, timeout=180,
    )  # fmt: skip
    return proc.returncode, json.loads(proc.stdout)


def test_bridge_describes_the_language_and_validates_rules():
    code, language = bridge({"action": "language"})
    assert code == 0 and language["schema"]["name"] == "document-saas"
    code, good = bridge({"action": "validate", "source": CUSTOM})
    assert code == 0 and good["ok"] is True and good["rules"][0]["name"] == "read-returns-own-tenant"
    code, bad = bridge({"action": "validate", "source": 'rule "x" { always actor.rol }'})
    assert code == 0 and bad["ok"] is False and "did you mean 'role'" in bad["diagnostics"][0]["message"]


def test_bridge_scan_with_a_user_rule_only_then_replay_from_the_report():
    code, out = bridge({"action": "scan", "defects": ["stale-cache-read"], "seed": 1,
                        "builtin_rules": False, "rules": [CUSTOM]})  # fmt: skip
    assert code == 0, out
    report = out["report"]
    assert report["outcome"] == "VIOLATION"
    assert report["finding"]["property_id"] == "read-returns-own-tenant"
    assert [r["name"] for r in report["rules"]] == ["read-returns-own-tenant"]
    code, hit = bridge({"action": "replay", "defects": ["stale-cache-read"], "report": report})
    assert code == 0 and hit["outcome"] == "VIOLATION" and "read-returns-own-tenant" in hit["message"]
    code, fixed = bridge({"action": "replay", "defects": [], "report": report})
    assert code == 0 and fixed["outcome"] == "PASS"


def test_bridge_accepts_json_rules_next_to_selected_builtins():
    rule = {"name": "json-rule", "never": {"==": [{"ref": "response.status"}, 418]}}
    code, out = bridge({"action": "scan", "defects": [], "seed": 1, "max_examples": 5,
                        "builtin_rules": ["TI-1"], "rules": [rule]})  # fmt: skip
    assert code == 0 and out["report"]["outcome"] == "PASS"
    assert [r.get("id", r["name"]) for r in out["report"]["rules"]] == ["TI-1", "json-rule"]


def test_bridge_rejects_bad_rule_selections_with_the_reason():
    for request, message in [
        ({"rules": ['rule "x" { always actor.rol }']}, "actor has no field 'rol'"),
        ({"rules": ["rule oops"]}, "expected the rule name in quotes"),
        ({"rules": "not a list"}, "rules must be a list"),
        ({"builtin_rules": ["TI-9"]}, "unknown built-in rules: ['TI-9']"),
        ({"builtin_rules": False}, "no rules selected"),
        ({"rules": ['rule "a" { id "TI-1" always true }']}, "ids must be unique"),
    ]:
        code, out = bridge({"action": "scan", "defects": [], "max_examples": 1, **request})
        assert code == 1 and message in out["error"], out


def test_cli_explore_with_a_rule_file_and_replay_from_the_report(tmp_path):
    rules = tmp_path / "mine.rules"
    rules.write_text(CUSTOM)
    report = tmp_path / "r.json"
    found = runner.invoke(app, ["explore", VULN, "--app-dir", EXAMPLES_DIR, "--seed", "1",
                                "--rules", str(rules), "--no-builtin", "--report", str(report)])  # fmt: skip
    assert found.exit_code == 1, found.output
    assert "VIOLATION: read-returns-own-tenant" in found.output and "[severity: critical]" in found.output
    assert runner.invoke(app, ["replay", str(report), VULN, "--app-dir", EXAMPLES_DIR]).exit_code == 1
    assert runner.invoke(app, ["replay", str(report), FIXED, "--app-dir", EXAMPLES_DIR]).exit_code == 0


def test_cli_accepts_json_rule_files_alongside_the_builtins(tmp_path):
    rules = tmp_path / "mine.json"
    rules.write_text(json.dumps({"name": "json-rule", "never": "response.status == 418"}))
    report = tmp_path / "r.json"
    out = runner.invoke(app, ["explore", FIXED, "--app-dir", EXAMPLES_DIR, "--seed", "1",
                              "--max-examples", "5", "--rules", str(rules), "--report", str(report)])  # fmt: skip
    assert out.exit_code == 0, out.output
    used = json.loads(report.read_text())["rules"]
    assert [r.get("id", r["name"]) for r in used] == ["TI-1", "TI-2", "AZ-1", "json-rule"]


def test_cli_reports_invalid_rule_files_as_usage_errors(tmp_path):
    rules = tmp_path / "bad.rules"
    rules.write_text('rule "x" {\n  always actor.rol == "v"\n}')
    out = runner.invoke(app, ["explore", FIXED, "--app-dir", EXAMPLES_DIR, "--rules", str(rules)])
    assert out.exit_code == 2
    assert "line 2" in out.output and "did you mean" in out.output


def test_cli_console_rejects_a_target_that_is_not_a_console_target():
    out = runner.invoke(app, ["console", FIXED, "--app-dir", EXAMPLES_DIR, "--no-open"])
    assert out.exit_code == 2 and "ConsoleTarget" in out.output
