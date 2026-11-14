"""Developer-facing command line interface.

    invariant explore vulnerable_saas.target:vulnerable_adapter --app-dir examples
    invariant replay report.json vulnerable_saas.target:vulnerable_adapter --app-dir examples
    invariant view report.json
    invariant console                      # rule management and exploration in the browser


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
from invariant.evaluation.evaluator import evaluator_for_report
from invariant.evaluation.violations import Outcome
from invariant.exploration.runner import explore
from invariant.integrations.builtin_rules import builtin_document, library_document
from invariant.integrations.document_saas import SCHEMA
from invariant.rules import jsonio
from invariant.rules.engine import RuleSet
from invariant.rules.errors import RuleError
from invariant.rules.ir import Rule
from invariant.rules.parser import parse_rules
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


def load_rules(paths: list[Path], *, builtin: bool, library: bool = False) -> RuleSet | None:
    """Rules from files (``.json``: the JSON format; anything else: rule-language text).

    None when nothing was asked for, which selects the built-in rules.
    ``library`` adds the default web-application rule library.
    """
    if not paths and builtin and not library:
        return None
    rules: list[Rule] = list(builtin_document().rules) if builtin else []
    if library:
        rules += library_document().rules
    try:
        for path in paths:
            text = path.read_text("utf-8")
            if path.suffix.lower() == ".json":
                document = jsonio.loads(text)
                rules += [r for r in document.rules if r.id not in document.disabled]
            else:
                rules += parse_rules(text).rules
        if not rules:
            raise typer.BadParameter("no rules selected")
        return RuleSet(rules, SCHEMA)
    except RuleError as exc:
        lines = "\n".join(f"  {d}" for d in exc.diagnostics)
        raise typer.BadParameter(f"invalid rules:\n{lines}") from exc


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
    rules: Annotated[
        list[Path] | None,
        typer.Option(
            "--rules", exists=True, dir_okay=False,
            help="Rule file to add (.json, or rule-language text). Repeatable.",
        ),
    ] = None,  # fmt: skip
    builtin: Annotated[
        bool, typer.Option("--builtin/--no-builtin", help="Include the built-in rules.")
    ] = True,
    library: Annotated[
        bool,
        typer.Option(
            "--library/--no-library",
            help="Also check the default web-application rule library (the console enables it).",
        ),
    ] = False,
) -> None:
    """Search for security-property violations against TARGET (local targets only)."""
    factory = load_factory(target, app_dir)
    result = explore(
        factory,
        target=target,
        seed=seed,
        max_examples=max_examples,
        rules=load_rules(rules or [], builtin=builtin, library=library),
    )
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
    try:
        # Judge with the rules the report was produced with.
        evaluator = evaluator_for_report(saved.rules)
    except RuleError as exc:
        typer.echo(f"the rules stored in the report are not valid: {exc}")
        raise typer.Exit(2) from exc
    result = replay(saved.scenario, load_factory(target, app_dir), evaluator=evaluator)
    if not result.valid:
        typer.echo("scenario is invalid for this target (unknown references)")
        raise typer.Exit(2)
    typer.echo(f"Replay of {len(saved.scenario.operations)} operations: {result.outcome}")
    if result.failure is not None:
        typer.echo(str(result.failure))
    raise typer.Exit(EXIT[result.outcome])


@app.command("console")
def console_cmd(
    target: Annotated[
        str | None,
        typer.Argument(
            help="Optional: open this console target ('module:callable' returning a ConsoleTarget) "
            "instead of choosing a project folder."
        ),
    ] = None,
    demo: Annotated[
        bool, typer.Option("--demo", help="Open the built-in vulnerable demo application.")
    ] = False,
    app_dir: AppDirOpt = Path("examples"),
    host: Annotated[str, typer.Option(help="Address to listen on.")] = "127.0.0.1",
    port: Annotated[int, typer.Option(min=0, max=65535)] = 8765,
    store: Annotated[
        Path, typer.Option(help="File that keeps the rules you create or import.")
    ] = Path(".invariant/rules.json"),
    open_browser: Annotated[
        bool, typer.Option("--open/--no-open", help="Open the console in a browser.")
    ] = True,
) -> None:
    """Open the Invariant console: choose an application folder, manage rules, run the exploration."""
    from invariant.console.app import ConsoleApp
    from invariant.console.server import make_server
    from invariant.console.store import RuleStore
    from invariant.console.target import ConsoleTarget

    described: ConsoleTarget | None = None
    if demo and target is None:
        target = "vulnerable_saas.target:console_target"
    if target is not None:
        loaded = load_factory(target, app_dir)()
        if not isinstance(loaded, ConsoleTarget):
            raise typer.BadParameter(f"{target!r} did not return a ConsoleTarget")
        described = loaded
    try:
        rule_store = RuleStore(store)
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc
    console = ConsoleApp(described, rule_store, start_dir=app_dir.resolve() if app_dir.is_dir() else None)
    server = make_server(console, host, port)
    shown = "localhost" if host in ("127.0.0.1", "::1") else host
    url = f"http://{shown}:{server.server_address[1]}/"
    typer.echo(f"Invariant console: {url}  (Ctrl+C to stop)")
    if open_browser:
        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        typer.echo("\nstopped")
    finally:
        server.server_close()
        console.close()


if __name__ == "__main__":
    app()
