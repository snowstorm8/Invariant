"""Build, persist and render reports."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from importlib import resources
from pathlib import Path

from invariant import __version__
from invariant.core.engine import RunFailure, StepRecord
from invariant.core.scenario import describe_op
from invariant.evaluation.violations import Evaluation, Outcome
from invariant.properties.base import Property
from invariant.properties.registry import EXECUTION, PROPERTIES
from invariant.rules.engine import RuleSet

from .models import Finding, Report


@dataclass(frozen=True)
class Confirmed:
    """One failed rule with the minimal run that shows it and its replay result."""

    failure: RunFailure
    property_id: str
    reproduced: bool | None


def primary_evaluation(record: StepRecord) -> Evaluation:
    """The evaluation a failing step is headlined by: its first violation, or
    else its first inconclusive result."""
    return next(
        e
        for e in record.evaluations
        if e.outcome in (Outcome.VIOLATION, Outcome.INCONCLUSIVE)
        and (e.outcome is Outcome.VIOLATION or record.outcome is not Outcome.VIOLATION)
    )


def _finding(entry: Confirmed, catalog: Mapping[str, Property]) -> Finding:
    record = entry.failure.record
    evaluation = next(e for e in record.evaluations if e.property_id == entry.property_id)
    prop = catalog.get(evaluation.property_id, EXECUTION)
    return Finding(
        property_id=prop.id,
        property_name=prop.name,
        statement=prop.statement,
        outcome=evaluation.outcome,
        summary=evaluation.summary,
        step_index=record.index,
        evidence=evaluation.evidence,
        severity=prop.severity,
        scenario=entry.failure.scenario,
        steps=entry.failure.history,
        reproduced=entry.reproduced,
    )


def build_report(
    *,
    target: str,
    failure: RunFailure | None,
    executions: int,
    seed: int | None,
    reproduced: bool | None,
    properties: Mapping[str, Property] | None = None,
    rules: RuleSet | None = None,
    confirmed: Sequence[Confirmed] | None = None,
    held: Mapping[str, int] | None = None,
) -> Report:
    """``properties`` is the metadata of the rules the run was judged with
    (default: the built-in ones); ``rules`` is embedded so the report replays
    with the same rule set. ``confirmed`` lists every failed rule, first one
    first; without it the report has the single failure ``failure``."""
    catalog = PROPERTIES if properties is None else properties
    embedded = rules.to_json()["rules"] if rules is not None else None
    if failure is None and not confirmed:
        return Report(
            tool_version=__version__,
            target=target,
            outcome=Outcome.PASS,
            executions=executions,
            seed=seed,
            rules=embedded,
            held=dict(held or {}),
        )
    if not confirmed:
        assert failure is not None
        confirmed = [Confirmed(failure, primary_evaluation(failure.record).property_id, reproduced)]
    findings = [_finding(entry, catalog) for entry in confirmed]
    first = findings[0]
    return Report(
        tool_version=__version__,
        target=target,
        outcome=first.outcome,
        executions=executions,
        seed=seed,
        finding=first,
        findings=findings,
        scenario=first.scenario,
        steps=first.steps,
        reproduced=first.reproduced,
        rules=embedded,
        held=dict(held or {}),
    )


def save_report(report: Report, path: Path) -> None:
    path.write_text(report.model_dump_json(indent=2) + "\n")


def load_report(path: Path) -> Report:
    return Report.model_validate_json(path.read_text())


_REPORT_SLOT = "<!-- invariant:report -->"
# Escaped so report content (e.g. a leaked "</script>" in a response excerpt) cannot
# terminate the embedding <script> element; the result is still valid JSON.
_SCRIPT_SAFE = str.maketrans({"<": "\\u003c", ">": "\\u003e", "&": "\\u0026"})


def render_html(report: Report) -> str:
    """Render REPORT as a self-contained HTML page (no network, no external assets)."""
    template = (
        resources.files("invariant.reporting")
        .joinpath("viewer.html")
        .read_text("utf-8")
    )
    payload = report.model_dump_json().translate(_SCRIPT_SAFE)
    tag = f'<script id="invariant-report" type="application/json">{payload}</script>'
    return template.replace(_REPORT_SLOT, tag, 1)


def save_html(report: Report, path: Path) -> None:
    path.write_text(render_html(report), encoding="utf-8")


def render_text(report: Report) -> str:
    lines = [f"Invariant {report.tool_version} — target: {report.target}"]
    lines.append(f"Result: {report.outcome} ({report.executions} executions explored)")
    if report.finding is None:
        lines.append(report.note)
        return "\n".join(lines)
    findings = report.findings or [report.finding]
    violated = [f for f in findings if f.outcome is Outcome.VIOLATION]
    if len(violated) > 1:
        lines.append(f"{len(violated)} rules violated: " + ", ".join(f.property_id for f in violated))
    for number, f in enumerate(findings, 1):
        if len(findings) > 1:
            lines += ["", f"=== Finding {number} of {len(findings)} ==="]
        lines += _render_finding(report, f)
    lines += ["", report.note]
    return "\n".join(lines)


def _render_finding(report: Report, f: Finding) -> list[str]:
    steps = f.steps or report.steps
    reproduced = f.reproduced if f.scenario is not None else report.reproduced
    lines = [
        "",
        f"{f.outcome}: {f.property_id} {f.property_name}"
        + (f"  [severity: {f.severity}]" if f.severity else ""),
        f"  Property: {f.statement}",
        f"  Finding : {f.summary}",
        "",
        "Operation sequence:",
    ]
    for step in steps:
        marker = "  <-- " + f.outcome if step.index == f.step_index else ""
        status = step.status if step.status is not None else "no response"
        lines.append(
            f"  {step.index}. {describe_op(step.operation)}  [HTTP {status}]{marker}"
        )
    if f.evidence:
        lines += ["", "Evidence:"]
        for key, value in f.evidence.items():
            lines.append(f"  {key}: {value}")
    if reproduced is not None:
        lines += [
            "",
            "Reproduced by deterministic replay on a fresh target: "
            + ("yes" if reproduced else "NO (flaky or non-deterministic target)"),
        ]
    return lines
