"""JSON bridge used by the Invariant web console.

Reads one request from stdin, writes one JSON document to stdout.

    {"action": "scan",   "defects": [...], "seed": 1, "max_examples": 200}
    {"action": "replay", "defects": [...], "report": {...}}
    {"action": "html",   "report": {...}}
    {"action": "catalog"}
    {"action": "language"}
    {"action": "validate", "source": "rule ...", "format": "text" | "json"}

A scan may select its rules: ``"builtin_rules"`` (true, false or a list of
ids) and ``"rules"`` (a list of rule definitions, each rule-language text or a
JSON rule object). Without either, the built-in rules are used. The report
records the rules it was judged with, and ``replay`` re-applies them.
"""

from __future__ import annotations

import json
import sys
import time
import warnings

warnings.filterwarnings("ignore")
sys.path.insert(0, "examples")

from invariant.analysis.reproduction import replay  # noqa: E402
from invariant.console.app import ConsoleApp, ruleset_from_request  # noqa: E402
from invariant.evaluation.evaluator import evaluator_for_report  # noqa: E402
from invariant.integrations.document_saas import SCHEMA  # noqa: E402
from invariant.exploration.runner import explore  # noqa: E402
from invariant.properties.registry import PROPERTIES  # noqa: E402
from invariant.reporting.models import Report  # noqa: E402
from invariant.reporting.reporter import render_html  # noqa: E402
from vulnerable_saas.app.models import KNOWN_DEFECTS  # noqa: E402
from vulnerable_saas.target import DEFECTS, adapter_for, console_target  # noqa: E402

def target_name(defects: frozenset[str]) -> str:
    return "vulnerable_saas[" + (",".join(sorted(defects)) or "fixed") + "]"


def parse_defects(raw: object) -> frozenset[str]:
    if not isinstance(raw, list) or not all(isinstance(d, str) for d in raw):
        raise ValueError("defects must be a list of strings")
    defects = frozenset(raw)
    unknown = defects - KNOWN_DEFECTS
    if unknown:
        raise ValueError(f"unknown defects: {sorted(unknown)}")
    return defects


def parse_max_examples(raw: object) -> int:
    # bool is a subclass of int, so it must be rejected explicitly.
    if isinstance(raw, bool) or not isinstance(raw, int):
        raise ValueError("max_examples must be an integer")
    if raw <= 0:
        raise ValueError("max_examples must be greater than zero")
    return raw


def parse_seed(raw: object) -> int | None:
    if raw is None:
        return None
    if isinstance(raw, bool) or not isinstance(raw, int):
        raise ValueError("seed must be an integer or null")
    return raw


def main() -> None:
    req = json.load(sys.stdin)
    action = req["action"]
    if action == "catalog":
        out = {
            "defects": [{"id": k, **v} for k, v in DEFECTS.items()],
            "properties": [
                {"id": p.id, "name": p.name, "statement": p.statement}
                for p in PROPERTIES.values()
            ],
        }
    elif action == "scan":
        defects = parse_defects(req.get("defects", []))
        seed = parse_seed(req.get("seed"))
        max_examples = parse_max_examples(req.get("max_examples", 200))
        rules = ruleset_from_request(req.get("rules"), req.get("builtin_rules"), SCHEMA)
        started = time.perf_counter()
        result = explore(
            lambda: adapter_for(defects),
            target=target_name(defects),
            seed=seed,
            max_examples=max_examples,
            **({} if rules is None else {"rules": rules}),
        )
        out = {
            "report": json.loads(result.report.model_dump_json()),
            "duration_ms": int((time.perf_counter() - started) * 1000),
        }
    elif action == "replay":
        defects = parse_defects(req.get("defects", []))
        report = Report.model_validate(req["report"])
        if report.scenario is None:
            raise ValueError("report has no scenario to replay")
        evaluator = evaluator_for_report(report.rules)
        started = time.perf_counter()
        result = replay(report.scenario, lambda: adapter_for(defects), evaluator=evaluator)
        out = {
            "outcome": str(result.outcome),
            "valid": result.valid,
            "message": str(result.failure) if result.failure else "",
            "steps": len(result.history),
            "duration_ms": int((time.perf_counter() - started) * 1000),
        }
    elif action == "language":
        out = ConsoleApp(console_target()).bootstrap()["language"]
    elif action == "validate":
        out = ConsoleApp(console_target()).validate(req)
    elif action == "html":
        out = {"html": render_html(Report.model_validate(req["report"]))}
    else:
        raise ValueError(f"unknown action: {action}")
    json.dump(out, sys.stdout)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:  # noqa: BLE001
        json.dump({"error": f"{type(exc).__name__}: {exc}"}, sys.stdout)
        sys.exit(1)
