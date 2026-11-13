import json
from pathlib import Path

from typer.testing import CliRunner

from invariant.cli.main import app

EXAMPLES = str(Path(__file__).parents[2] / "examples")
VULN = "vulnerable_saas.target:vulnerable_adapter"
FIXED = "vulnerable_saas.target:fixed_adapter"
runner = CliRunner()


def test_explore_vulnerable_exits_1_writes_report_and_replays(tmp_path):
    report = tmp_path / "r.json"
    r = runner.invoke(app, ["explore", VULN, "--app-dir", EXAMPLES, "--seed", "1",
                            "--report", str(report)])
    assert r.exit_code == 1, r.output
    assert "VIOLATION: TI-1" in r.output
    assert json.loads(report.read_text())["reproduced"] is True

    again = runner.invoke(app, ["replay", str(report), VULN, "--app-dir", EXAMPLES])
    assert again.exit_code == 1 and "VIOLATION" in again.output

    fixed = runner.invoke(app, ["replay", str(report), FIXED, "--app-dir", EXAMPLES])
    assert fixed.exit_code == 0 and "PASS" in fixed.output


def test_explore_fixed_exits_0():
    r = runner.invoke(app, ["explore", FIXED, "--app-dir", EXAMPLES, "--seed", "1",
                            "--max-examples", "30"])
    assert r.exit_code == 0 and "Result: PASS" in r.output


def test_bad_target_spec_is_a_usage_error():
    for spec in ("nocolon", "no_such_module:thing", "vulnerable_saas.target:missing"):
        r = runner.invoke(app, ["explore", spec, "--app-dir", EXAMPLES])
        assert r.exit_code == 2, spec


def test_replay_report_without_scenario_exits_2(tmp_path):
    p = tmp_path / "pass.json"
    r = runner.invoke(app, ["explore", FIXED, "--app-dir", EXAMPLES, "--seed", "1",
                            "--max-examples", "10", "--report", str(p)])
    assert r.exit_code == 0
    out = runner.invoke(app, ["replay", str(p), FIXED, "--app-dir", EXAMPLES])
    assert out.exit_code == 2
