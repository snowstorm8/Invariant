"""The console's behaviour, independent of HTTP.

Every method takes and returns plain JSON-compatible data, so the same code
serves the browser (``server.py``) and is directly testable. Rule definitions
are data all the way through: they arrive as text or JSON, are validated
against the target integration's schema, and are handed to the exploration
engine as a ``RuleSet``.
"""

from __future__ import annotations

import json
import re
import threading
import time
from typing import Any

from invariant import __version__
from invariant.analysis.reproduction import replay
from invariant.core.scenario import describe_op
from invariant.evaluation.evaluator import evaluator_for_report
from invariant.exploration.runner import explore
from invariant.integrations.builtin_rules import builtin_document
from invariant.properties.base import Property
from invariant.reporting.models import Report
from invariant.reporting.reporter import render_html
from invariant.rules import jsonio
from invariant.rules.engine import RuleSet
from invariant.rules.errors import Diagnostic, RuleError
from invariant.rules.functions import describe_functions
from invariant.rules.ir import SEVERITIES, Rule, RuleDocument
from invariant.rules.parser import CLAUSES, parse_rules
from invariant.rules.printer import format_rule
from invariant.rules.types import ContextSchema
from invariant.rules.validator import validate_rule

from .store import RuleStore, StoredRule
from .target import ConsoleTarget

BUILTIN_PREFIX = "builtin:"
_NAME_GUESS = re.compile(r'rule\s+["\']([^"\'\n{]+)')

NEW_RULE_TEMPLATE = '''rule "my-new-rule" {
    description "Describe what the application must never allow."
    severity medium

    when operation.type == "read_document"

    always response.status == 200 implies response.json.org_id == actor.org_id

    message "{actor.ref} ({actor.org}) was served a document owned by {response.json.org_id}"
}
'''

EXAMPLES = [
    {
        "title": "Response field must match the actor's tenant",
        "description": "A structural check on the response, independent of content markers.",
        "source": NEW_RULE_TEMPLATE.replace("my-new-rule", "read-returns-own-tenant")
        .replace(
            "Describe what the application must never allow.",
            "A successful read must return a document of the reader's own organization.",
        )
        .replace("severity medium", "severity critical"),
    },
    {
        "title": "Deleted documents stay deleted (sequence rule)",
        "description": "Relates this operation to an earlier one in the same run.",
        "source": '''rule "no-read-after-delete" {
    description "Once a document was deleted, no later read may return its content."
    severity high

    when operation.type == "read_document"
        and some e in events :
            e.operation.type == "delete_document"
            and e.operation.target == operation.target
            and e.policy.allowed and e.response.status < 300

    never contains(response.body, resource.marker)
}
''',
    },
    {
        "title": "Reads must show the version the model expects (state rule)",
        "description": "Compares the response with Invariant's expected application state.",
        "source": '''rule "read-shows-expected-version" {
    description "A same-tenant read must return the version produced by authorised writes only."
    severity high

    when operation.type == "read_document" and resource.org == actor.org and not resource.deleted

    always has(response.json.version) implies response.json.version == resource.version

    message "{resource.ref} is at version {response.json.version}, but only authorised writes up to version {resource.version} happened"
}
''',
    },
    {
        "title": "Viewers never change state (probe rule)",
        "description": "Observes the organization after the operation and compares with the model.",
        "source": '''rule "viewers-are-read-only" {
    description "Nothing a viewer does may change its organization's documents."
    severity high

    when actor.role == "viewer"
    observe listing = org_documents(actor.org)
    let changes = diff(state.expected_listing[actor.org], listing)

    never count(changes) > 0

    message "viewer {actor.ref} changed {actor.org}: {join(changes, '; ')}"
}
''',
    },
]


def ruleset_from_request(
    sources: object, builtin: object, schema: ContextSchema
) -> RuleSet | None:
    """The rule set a scan request asks for, or None for the default.

    ``sources`` is a list whose items are rule-language text or decoded JSON
    rules; ``builtin`` selects built-in rules: true/absent for all, false for
    none, or a list of ids. Raises ``RuleError``/``ValueError`` with specifics.
    """
    if sources is None and builtin is None:
        return None
    available = builtin_document().rules
    rules: list[Rule] = []
    if builtin is None or builtin is True:
        rules += available
    elif isinstance(builtin, list) and all(isinstance(i, str) for i in builtin):
        unknown = set(builtin) - {r.id for r in available}
        if unknown:
            raise ValueError(f"unknown built-in rules: {sorted(unknown)}")
        rules += [r for r in available if r.id in builtin]
    elif builtin is not False:
        raise ValueError("builtin_rules must be true, false or a list of rule ids")
    if sources is not None and not isinstance(sources, list):
        raise ValueError("rules must be a list of rule definitions (text or JSON)")
    for source in sources or []:
        if isinstance(source, str):
            rules += parse_rules(source).rules
        else:
            document = jsonio.rules_from_json(source)
            rules += [r for r in document.rules if r.id not in document.disabled]
    if not rules:
        raise ValueError("no rules selected: enable a built-in rule or supply one")
    return RuleSet(rules, schema)


class ConsoleError(ValueError):
    """A request the console refuses, with an explanation for the developer."""

    def __init__(self, message: str, diagnostics: list[dict[str, Any]] | None = None) -> None:
        super().__init__(message)
        self.diagnostics = diagnostics or []


def _rule_info(rule: Rule) -> dict[str, Any]:
    prop = Property.from_rule(rule)
    return {
        "id": rule.id,
        "name": rule.name,
        "description": rule.description,
        "severity": rule.severity,
        "statement": prop.statement,
    }


def _int(raw: object, name: str, *, minimum: int | None = None, optional: bool = False) -> int | None:
    if raw is None and optional:
        return None
    # bool is a subclass of int, so it must be rejected explicitly.
    if isinstance(raw, bool) or not isinstance(raw, int):
        raise ConsoleError(f"{name} must be an integer" + (" or null" if optional else ""))
    if minimum is not None and raw < minimum:
        raise ConsoleError(f"{name} must be at least {minimum}")
    return raw


class ConsoleApp:
    def __init__(self, target: ConsoleTarget, store: RuleStore | None = None) -> None:
        self.target = target
        self.schema = target.binding.schema
        self.store = store or RuleStore()
        self.builtin: tuple[Rule, ...] = builtin_document().rules
        #: One exploration at a time; rule edits are serialised too.
        self._lock = threading.RLock()

    # -- reference -----------------------------------------------------------

    def bootstrap(self) -> dict[str, Any]:
        return {
            "version": __version__,
            "target": {
                "name": self.target.name,
                "description": self.target.description,
                "options": [
                    {"id": o.id, "title": o.title, "description": o.description,
                     "property": o.property}
                    for o in self.target.options
                ],  # fmt: skip
            },
            "language": {
                "schema": self.schema.describe(),
                "functions": describe_functions(),
                "clauses": list(CLAUSES),
                "severities": list(SEVERITIES),
                "template": NEW_RULE_TEMPLATE,
                "examples": EXAMPLES,
            },
            "rules": self.list_rules(),
        }

    # -- validation ----------------------------------------------------------

    def _parse(self, source: str, fmt: str) -> RuleDocument:
        if fmt == "json":
            return jsonio.loads(source)
        if fmt != "text":
            raise ConsoleError(f"unknown rule format '{fmt}' (use 'text' or 'json')")
        return parse_rules(source)

    def _check(self, source: str, fmt: str = "text") -> tuple[RuleDocument | None, list[Diagnostic]]:
        try:
            document = self._parse(source, fmt)
        except RuleError as exc:
            return None, exc.diagnostics
        problems: list[Diagnostic] = []
        seen: set[str] = set()
        for rule in document.rules:
            problems += validate_rule(rule, self.schema)
            if rule.id in seen:
                problems.append(Diagnostic(f"rule id '{rule.id}' is defined twice", rule=rule.name))
            seen.add(rule.id)
        return document, problems

    def _other_ids(self, except_key: str | None) -> dict[str, str]:
        """Rule id -> who defines it, for everything except one stored entry."""
        taken = {rule.id: "a built-in rule" for rule in self.builtin}
        for stored in self.store.data.rules:
            if stored.key == except_key:
                continue
            document, problems = self._check(stored.source)
            if document is not None and not problems:
                for rule in document.rules:
                    taken.setdefault(rule.id, f'your rule "{rule.name}"')
        return taken

    def validate(self, request: dict[str, Any]) -> dict[str, Any]:
        """Check a definition without saving or running anything."""
        source = request.get("source")
        if not isinstance(source, str):
            raise ConsoleError("source must be a string")
        fmt = request.get("format", "text")
        key = request.get("key")
        document, problems = self._check(source, str(fmt))
        if document is not None:
            taken = self._other_ids(key if isinstance(key, str) else None)
            for rule in document.rules:
                if rule.id in taken:
                    loc = rule.loc
                    problems.append(
                        Diagnostic(
                            f"rule id '{rule.id}' is already used by {taken[rule.id]}; "
                            "choose another name or add an 'id' clause",
                            line=loc.line if loc else None,
                            col=loc.col if loc else None,
                            path=loc.path if loc else None,
                            rule=rule.name,
                        )
                    )
        rules = document.rules if document is not None else ()
        return {
            "ok": not problems,
            "diagnostics": [d.to_json() for d in problems],
            "rules": [
                {**_rule_info(r), "source": format_rule(r), "json": jsonio.rule_to_json(r)}
                for r in rules
            ]
            if not problems
            else [_rule_info(r) for r in rules],
        }

    # -- rule management -----------------------------------------------------

    def _entry(self, stored: StoredRule, taken: dict[str, str]) -> dict[str, Any]:
        document, problems = self._check(stored.source)
        info: dict[str, Any]
        if document is not None and document.rules:
            rule = document.rules[0]
            info = _rule_info(rule)
            if not problems and rule.id in taken:
                problems = [
                    Diagnostic(f"rule id '{rule.id}' is already used by {taken[rule.id]}", rule=rule.name)
                ]
            as_json = jsonio.rule_to_json(rule) if not problems else None
        else:
            guess = _NAME_GUESS.search(stored.source)
            info = {
                "id": "", "name": guess.group(1).strip() if guess else "untitled draft",
                "description": "", "severity": "", "statement": "",
            }  # fmt: skip
            as_json = None
        return {
            **info,
            "key": stored.key,
            "origin": stored.origin,
            "filename": stored.filename,
            "enabled": stored.enabled,
            "editable": True,
            "source": stored.source,
            "json": as_json,
            "valid": not problems,
            "diagnostics": [d.to_json() for d in problems],
        }

    def list_rules(self) -> list[dict[str, Any]]:
        with self._lock:
            disabled = set(self.store.data.disabled_builtin)
            out: list[dict[str, Any]] = [
                {
                    **_rule_info(rule),
                    "key": BUILTIN_PREFIX + rule.id,
                    "origin": "builtin",
                    "filename": "",
                    "enabled": rule.id not in disabled,
                    "editable": False,
                    "source": format_rule(rule),
                    "json": jsonio.rule_to_json(rule),
                    "valid": True,
                    "diagnostics": [],
                }
                for rule in self.builtin
            ]
            taken = {rule.id: "a built-in rule" for rule in self.builtin}
            for stored in self.store.data.rules:
                entry = self._entry(stored, taken)
                if entry["valid"]:
                    taken[entry["id"]] = f'your rule "{entry["name"]}"'
                out.append(entry)
            return out

    def save_rule(self, request: dict[str, Any]) -> dict[str, Any]:
        """Create a rule, or replace the one stored under ``key``.

        A source that defines several rules becomes several entries. A source
        that does not validate is kept as a draft.
        """
        source = request.get("source")
        if not isinstance(source, str) or not source.strip():
            raise ConsoleError("the rule definition is empty")
        key = request.get("key")
        with self._lock:
            existing = self.store.find(key) if isinstance(key, str) and key else None
            document, problems = self._check(source)
            pieces = (
                [format_rule(r) + "\n" for r in document.rules]
                if document is not None and not problems and len(document.rules) > 1
                else [source]
            )
            saved: list[str] = []
            for i, piece in enumerate(pieces):
                if i == 0 and existing is not None:
                    existing.source = piece
                    saved.append(existing.key)
                    continue
                entry = StoredRule(
                    key=self.store.new_key(),
                    source=piece,
                    enabled=bool(request.get("enabled", True)),
                    origin=existing.origin if existing else "authored",
                    filename=existing.filename if existing else "",
                )
                self.store.data.rules.append(entry)
                saved.append(entry.key)
            self.store.save()
            return {"saved": saved, "rules": self.list_rules()}

    def import_json(self, request: dict[str, Any]) -> dict[str, Any]:
        """Import a JSON rule file. Nothing is stored unless every rule is valid."""
        content = request.get("content")
        filename = str(request.get("filename") or "rules.json")
        if not isinstance(content, str):
            raise ConsoleError("content must be the text of a JSON rule file")
        replace = request.get("replace") is True
        with self._lock:
            document, problems = self._check(content, "json")
            if document is not None and not problems:
                owners: dict[str, StoredRule] = {}
                for stored in self.store.data.rules:
                    parsed, bad = self._check(stored.source)
                    if parsed is not None and not bad:
                        owners.update({r.id: stored for r in parsed.rules})
                builtin_ids = {r.id for r in self.builtin}
                for rule in document.rules:
                    if rule.id in builtin_ids:
                        problems.append(
                            Diagnostic(
                                f"rule id '{rule.id}' belongs to a built-in rule; "
                                "rename the imported rule",
                                path=rule.loc.path if rule.loc else None,
                                rule=rule.name,
                            )
                        )
                    elif rule.id in owners and not replace:
                        problems.append(
                            Diagnostic(
                                f"a rule with id '{rule.id}' already exists; "
                                "import with 'replace existing' to overwrite it",
                                path=rule.loc.path if rule.loc else None,
                                rule=rule.name,
                            )
                        )
            if document is None or problems:
                raise ConsoleError(
                    f"{filename} was not imported: {len(problems)} problem(s)",
                    [d.to_json() for d in problems],
                )
            imported: list[str] = []
            for rule in document.rules:
                text = format_rule(rule) + "\n"
                enabled = rule.id not in document.disabled
                if rule.id in owners:
                    target = owners[rule.id]
                    target.source, target.enabled = text, enabled
                    target.origin, target.filename = "imported", filename
                    imported.append(target.key)
                else:
                    entry = StoredRule(self.store.new_key(), text, enabled, "imported", filename)
                    self.store.data.rules.append(entry)
                    imported.append(entry.key)
            self.store.save()
            return {"imported": imported, "rules": self.list_rules()}

    def set_enabled(self, request: dict[str, Any]) -> dict[str, Any]:
        key, enabled = request.get("key"), request.get("enabled")
        if not isinstance(key, str) or not isinstance(enabled, bool):
            raise ConsoleError("expected {key: string, enabled: boolean}")
        with self._lock:
            if key.startswith(BUILTIN_PREFIX):
                rule_id = key.removeprefix(BUILTIN_PREFIX)
                if rule_id not in {r.id for r in self.builtin}:
                    raise ConsoleError(f"no built-in rule '{rule_id}'")
                off = set(self.store.data.disabled_builtin)
                off.discard(rule_id) if enabled else off.add(rule_id)
                self.store.data.disabled_builtin = sorted(off)
            else:
                self.store.find(key).enabled = enabled
            self.store.save()
            return {"rules": self.list_rules()}

    def delete_rule(self, request: dict[str, Any]) -> dict[str, Any]:
        key = request.get("key")
        if not isinstance(key, str):
            raise ConsoleError("expected {key: string}")
        if key.startswith(BUILTIN_PREFIX):
            raise ConsoleError("built-in rules cannot be deleted; switch them off instead")
        with self._lock:
            self.store.data.rules.remove(self.store.find(key))
            self.store.save()
            return {"rules": self.list_rules()}

    def export(self) -> dict[str, Any]:
        """Every valid authored/imported rule, as a JSON rule file."""
        with self._lock:
            rules: list[Rule] = []
            disabled: set[str] = set()
            for stored in self.store.data.rules:
                document, problems = self._check(stored.source)
                if document is None or problems:
                    continue
                rules += document.rules
                if not stored.enabled:
                    disabled.update(r.id for r in document.rules)
            return jsonio.document_to_json(rules, disabled)

    # -- running -------------------------------------------------------------

    def active_ruleset(self) -> RuleSet:
        """Every enabled rule: built-ins first (their order is fixed), then the
        developer's rules in the order they are listed."""
        entries = self.list_rules()
        enabled = [e for e in entries if e["enabled"]]
        broken = [e for e in enabled if not e["valid"]]
        if broken:
            names = ", ".join(f'"{e["name"]}"' for e in broken)
            raise ConsoleError(
                f"fix or switch off the rules that do not validate: {names}",
                [d for e in broken for d in e["diagnostics"]],
            )
        if not enabled:
            raise ConsoleError("no rule is enabled; switch on at least one rule to run")
        try:
            return RuleSet.from_json({"rules": [e["json"] for e in enabled]}, self.schema)
        except RuleError as exc:
            raise ConsoleError(str(exc), [d.to_json() for d in exc.diagnostics]) from exc

    def scan(self, request: dict[str, Any]) -> dict[str, Any]:
        """Explore the target with the enabled rules."""
        options = self.target.parse_options(request.get("options", []))
        seed = _int(request.get("seed"), "seed", optional=True)
        max_examples = _int(request.get("max_examples", 200), "max_examples", minimum=1)
        assert max_examples is not None
        with self._lock:
            rules = self.active_ruleset()
            started = time.perf_counter()
            result = explore(
                lambda: self.target.adapter_for(options),
                target=self.target.label(options),
                seed=seed,
                max_examples=max_examples,
                rules=rules,
            )
        report = result.report
        return {
            "report": json.loads(report.model_dump_json()),
            "steps_text": [describe_op(s.operation) for s in report.steps],
            "rules_used": [{"id": r.id, "name": r.name, "severity": r.severity} for r in rules.rules],
            "options": sorted(options),
            "duration_ms": int((time.perf_counter() - started) * 1000),
        }

    def replay(self, request: dict[str, Any]) -> dict[str, Any]:
        """Re-run a report's scenario, judged by the rules stored in the report."""
        options = self.target.parse_options(request.get("options", []))
        report = Report.model_validate(request.get("report"))
        if report.scenario is None:
            raise ConsoleError("report has no scenario to replay")
        try:
            evaluator = evaluator_for_report(report.rules, self.target.binding)
        except RuleError as exc:
            raise ConsoleError(
                f"the rules stored in the report are not valid: {exc}",
                [d.to_json() for d in exc.diagnostics],
            ) from exc
        with self._lock:
            started = time.perf_counter()
            result = replay(
                report.scenario, lambda: self.target.adapter_for(options), evaluator=evaluator
            )
        violated = [
            e.property_id
            for e in (result.failure.record.evaluations if result.failure else [])
            if e.outcome.value == "VIOLATION"
        ]
        return {
            "outcome": str(result.outcome),
            "valid": result.valid,
            "message": str(result.failure) if result.failure else "",
            "violated": violated,
            "steps": len(result.history),
            "target": self.target.label(options),
            "duration_ms": int((time.perf_counter() - started) * 1000),
        }

    def report_html(self, request: dict[str, Any]) -> dict[str, Any]:
        return {"html": render_html(Report.model_validate(request.get("report")))}
