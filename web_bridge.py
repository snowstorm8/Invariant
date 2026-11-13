"""JSON bridge used by the Invariant web console.

Reads one request from stdin, writes one JSON document to stdout.

    {"action": "scan",   "defects": [...], "seed": 1, "max_examples": 200}
    {"action": "replay", "defects": [...], "report": {...}}
    {"action": "html",   "report": {...}}
    {"action": "catalog"}
"""

from __future__ import annotations

import json
import sys
import time
import warnings

warnings.filterwarnings("ignore")
sys.path.insert(0, "examples")

from invariant.analysis.reproduction import replay  # noqa: E402
from invariant.exploration.runner import explore  # noqa: E402
from invariant.properties.registry import PROPERTIES  # noqa: E402
from invariant.reporting.models import Report  # noqa: E402
from invariant.reporting.reporter import render_html  # noqa: E402
from vulnerable_saas.app.models import KNOWN_DEFECTS  # noqa: E402
from vulnerable_saas.target import adapter_for  # noqa: E402

DEFECTS = {
    "stale-cache-read": {
        "title": "Stale cache read",
        "description": "GET /documents/{id} serves recently updated documents from a cache keyed by id only, skipping the tenant check.",
        "property": "TI-1",
    },
    "update-missing-tenant-check": {
        "title": "Update missing tenant check",
        "description": "PUT /documents/{id} checks the caller's role but not that the document belongs to the caller's organization.",
        "property": "TI-2",
    },
    "viewer-can-update": {
        "title": "Viewer can update",
        "description": "PUT /documents/{id} does not enforce the role check, so read-only viewers can modify documents.",
        "property": "AZ-1",
    },
}


def target_name(defects: frozenset[str]) -> str:
    return "vulnerable_saas[" + (",".join(sorted(defects)) or "fixed") + "]"


def parse_defects(raw: list[str]) -> frozenset[str]:
    defects = frozenset(raw)
    unknown = defects - KNOWN_DEFECTS
    if unknown:
        raise ValueError(f"unknown defects: {sorted(unknown)}")
    return defects


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
        started = time.perf_counter()
        result = explore(
            lambda: adapter_for(defects),
            target=target_name(defects),
            seed=req.get("seed"),
            max_examples=int(req.get("max_examples", 200)),
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
        started = time.perf_counter()
        result = replay(report.scenario, lambda: adapter_for(defects))
        out = {
            "outcome": str(result.outcome),
            "valid": result.valid,
            "message": str(result.failure) if result.failure else "",
            "steps": len(result.history),
            "duration_ms": int((time.perf_counter() - started) * 1000),
        }
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
