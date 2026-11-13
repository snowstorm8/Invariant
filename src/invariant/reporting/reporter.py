"""Build, persist and render reports."""

from __future__ import annotations

from pathlib import Path

from invariant import __version__
from invariant.core.engine import RunFailure
from invariant.core.scenario import describe_op
from invariant.evaluation.violations import Outcome
from invariant.properties.registry import EXECUTION, PROPERTIES

from .models import Finding, Report


def build_report(
    *,
    target: str,
    failure: RunFailure | None,
    executions: int,
    seed: int | None,
    reproduced: bool | None,
) -> Report:
    if failure is None:
        return Report(
            tool_version=__version__,
            target=target,
            outcome=Outcome.PASS,
            executions=executions,
            seed=seed,
        )
    record = failure.record
    evaluation = next(
        e
        for e in record.evaluations
        if e.outcome in (Outcome.VIOLATION, Outcome.INCONCLUSIVE)
        and (e.outcome is Outcome.VIOLATION or record.outcome is not Outcome.VIOLATION)
    )
    prop = PROPERTIES.get(evaluation.property_id, EXECUTION)
    return Report(
        tool_version=__version__,
        target=target,
        outcome=evaluation.outcome,
        executions=executions,
        seed=seed,
        finding=Finding(
            property_id=prop.id,
            property_name=prop.name,
            statement=prop.statement,
            outcome=evaluation.outcome,
            summary=evaluation.summary,
            step_index=record.index,
            evidence=evaluation.evidence,
        ),
        scenario=failure.scenario,
        steps=failure.history,
        reproduced=reproduced,
    )


def save_report(report: Report, path: Path) -> None:
    path.write_text(report.model_dump_json(indent=2) + "\n")


def load_report(path: Path) -> Report:
    return Report.model_validate_json(path.read_text())


def render_text(report: Report) -> str:
    lines = [f"Invariant {report.tool_version} — target: {report.target}"]
    lines.append(f"Result: {report.outcome} ({report.executions} executions explored)")
    if report.finding is None:
        lines.append(report.note)
        return "\n".join(lines)
    f = report.finding
    lines += [
        "",
        f"{f.outcome}: {f.property_id} {f.property_name}",
        f"  Property: {f.statement}",
        f"  Finding : {f.summary}",
        "",
        "Operation sequence:",
    ]
    for step in report.steps:
        marker = "  <-- " + f.outcome if step.index == f.step_index else ""
        status = step.status if step.status is not None else "no response"
        lines.append(
            f"  {step.index}. {describe_op(step.operation)}  [HTTP {status}]{marker}"
        )
    if f.evidence:
        lines += ["", "Evidence:"]
        for key, value in f.evidence.items():
            lines.append(f"  {key}: {value}")
    if report.reproduced is not None:
        lines += [
            "",
            "Reproduced by deterministic replay on a fresh target: "
            + ("yes" if report.reproduced else "NO (flaky or non-deterministic target)"),
        ]
    lines += ["", report.note]
    return "\n".join(lines)
