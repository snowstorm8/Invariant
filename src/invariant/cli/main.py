"""Developer-facing command line interface.

    invariant explore vulnerable_saas.target:vulnerable_adapter --app-dir examples
    invariant replay report.json vulnerable_saas.target:vulnerable_adapter --app-dir examples
    invariant view report.json


Exit codes: 0 = PASS, 1 = VIOLATION, 2 = INCONCLUSIVE or usage error.
"""

from __future__ import annotations

import importlib
import sys
import webbrowser
from collections.abc import Callable
from pathlib import Path
from typing import Annotated

import typer
from pydantic import ValidationError

from invariant.adapters.base import Adapter
from invariant.analysis.reproduction import replay
from invariant.evaluation.violations import Outcome
from invariant.exploration.runner import explore
from invariant.reporting.reporter import (
    load_report,
    render_text,
    save_html,
    save_report,
)

app = typer.Typer(add_completion=False, no_args_is_help=True, help=__doc__)

EXIT = {Outcome.PASS: 0, Outcome.VIOLATION: 1, Outcome.INCONCLUSIVE: 2}

TargetArg = Annotated[str, typer.Argument(help="Adapter factory as 'module:callable'.")]
AppDirOpt = Annotated[Path, typer.Option(help="Directory added to sys.path before importing.")]


def load_factory(spec: str, app_dir: Path) -> Callable[[], Adapter]:
    module_name, sep, attr = spec.partition(":")
    if not sep or not module_name or not attr:
        raise typer.BadParameter("expected 'module:callable'")
    sys.path.insert(0, str(app_dir.resolve()))
    try:
        factory = getattr(importlib.import_module(module_name), attr)
    except (ImportError, AttributeError) as exc:
        raise typer.BadParameter(f"cannot load {spec!r}: {exc}") from exc
    if not callable(factory):
        raise typer.BadParameter(f"{spec!r} is not callable")
    return factory  # type: ignore[no-any-return]


@app.command("explore")
def explore_cmd(
    target: TargetArg,
    app_dir: AppDirOpt = Path("."),
    seed: Annotated[int | None, typer.Option(help="Seed for a repeatable search.")] = None,
    max_examples: Annotated[int, typer.Option(min=1)] = 200,
    report: Annotated[Path | None, typer.Option(help="Write the JSON report here.")] = None,
    html: Annotated[
        Path | None, typer.Option(help="Write a self-contained HTML report here.")
    ] = None,
) -> None:
    """Search for security-property violations against TARGET (local targets only)."""
    factory = load_factory(target, app_dir)
    result = explore(factory, target=target, seed=seed, max_examples=max_examples)
    typer.echo(render_text(result.report))
    if report is not None:
        save_report(result.report, report)
        typer.echo(f"\nReport written to {report}")
    if html is not None:
        save_html(result.report, html)
        typer.echo(f"HTML report written to {html}")
    raise typer.Exit(EXIT[result.outcome])


@app.command("view")
def view_cmd(
    report: Annotated[Path, typer.Argument(exists=True, dir_okay=False)],
    out: Annotated[
        Path | None, typer.Option(help="HTML output path (default: REPORT with .html).")
    ] = None,
    open_browser: Annotated[
        bool, typer.Option("--open/--no-open", help="Open the page in a browser.")
    ] = True,
) -> None:
    """Render a saved JSON REPORT as an interactive HTML page."""
    try:
        saved = load_report(report)
    except ValidationError as exc:
        typer.echo(f"{report} is not a valid Invariant report: {exc.error_count()} error(s)")
        raise typer.Exit(2) from exc
    target = out if out is not None else report.with_suffix(".html")
    save_html(saved, target)
    typer.echo(f"HTML report written to {target}")
    if open_browser:
        webbrowser.open(target.resolve().as_uri())


@app.command("replay")
def replay_cmd(
    report: Annotated[Path, typer.Argument(exists=True, dir_okay=False)],
    target: TargetArg,
    app_dir: AppDirOpt = Path("."),
) -> None:
    """Re-run the scenario stored in REPORT against TARGET on a fresh instance."""
    saved = load_report(report)
    if saved.scenario is None:
        typer.echo("report contains no scenario to replay")
        raise typer.Exit(2)
    result = replay(saved.scenario, load_factory(target, app_dir))
    if not result.valid:
        typer.echo("scenario is invalid for this target (unknown references)")
        raise typer.Exit(2)
    typer.echo(f"Replay of {len(saved.scenario.operations)} operations: {result.outcome}")
    if result.failure is not None:
        typer.echo(str(result.failure))
    raise typer.Exit(EXIT[result.outcome])


if __name__ == "__main__":
    app()
