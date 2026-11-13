import json
import re
from pathlib import Path

from typer.testing import CliRunner

from invariant.cli.main import app
from invariant.reporting.models import Report
from invariant.reporting.reporter import load_report, render_html

EXAMPLES = str(Path(__file__).parents[2] / "examples")
VULN = "vulnerable_saas.target:vulnerable_adapter"
FIXED = "vulnerable_saas.target:fixed_adapter"
runner = CliRunner()

EMBEDDED = re.compile(
    r'<script id="invariant-report" type="application/json">(.*?)</script>', re.DOTALL
)


def embedded_report(html: str) -> Report:
    match = EMBEDDED.search(html)
    assert match is not None, "report payload not embedded"
    return Report.model_validate_json(match.group(1))


def test_explore_writes_html_with_embedded_report(tmp_path):
    report, page = tmp_path / "r.json", tmp_path / "r.html"
    r = runner.invoke(
        app,
        [
            "explore",
            VULN,
            "--app-dir",
            EXAMPLES,
            "--seed",
            "1",
            "--report",
            str(report),
            "--html",
            str(page),
        ],
    )
    assert r.exit_code == 1, r.output
    html = page.read_text()
    assert "<!-- invariant:report -->" not in html
    assert embedded_report(html) == load_report(report)


def test_view_renders_saved_report_next_to_json(tmp_path):
    report = tmp_path / "pass.json"
    runner.invoke(
        app,
        [
            "explore",
            FIXED,
            "--app-dir",
            EXAMPLES,
            "--seed",
            "1",
            "--max-examples",
            "10",
            "--report",
            str(report),
        ],
    )
    r = runner.invoke(app, ["view", str(report), "--no-open"])
    assert r.exit_code == 0, r.output
    assert embedded_report((tmp_path / "pass.html").read_text()).outcome == "PASS"


def test_view_rejects_invalid_report(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"hello": "world"}))
    r = runner.invoke(app, ["view", str(bad), "--no-open"])
    assert r.exit_code == 2


def test_report_content_cannot_break_out_of_script_element():
    report = Report(
        tool_version="0",
        target="</script><script>alert(1)</script>",
        outcome="PASS",
        executions=0,
        seed=None,
    )
    html = render_html(report)
    assert "alert(1)</script>" not in html
    assert embedded_report(html).target == report.target
