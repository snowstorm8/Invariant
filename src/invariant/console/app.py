"""The console's behaviour, independent of HTTP.

Every method takes and returns plain JSON-compatible data, so the same code
serves the browser (``server.py``) and is directly testable. Rule definitions
are data all the way through: they arrive as text or JSON, are validated
against the target integration's schema, and are handed to the exploration
engine as a ``RuleSet``.
"""

from __future__ import annotations

import dataclasses
import json
import re
import threading
import time
from pathlib import Path
from typing import Any

from invariant import __version__
from invariant.analysis.minimizer import violates
from invariant.analysis.reproduction import replay
from invariant.core.scenario import describe_op
from invariant.evaluation.evaluator import evaluator_for_report
from invariant.exploration.runner import explore
from invariant.integrations.builtin_rules import builtin_document, shipped_document
from invariant.integrations.document_saas import DOCUMENT_SAAS
from invariant.properties.base import Property
from invariant.reporting.models import Report
from invariant.reporting.reporter import render_html
from invariant.rules import ids as rule_ids
from invariant.rules import jsonio
from invariant.rules.engine import RuleSet
from invariant.rules.errors import Diagnostic, RuleError
from invariant.rules.functions import describe_functions
from invariant.rules.ir import SEVERITIES, Rule, RuleDocument
from invariant.rules.parser import CLAUSES, parse_rules
from invariant.rules.printer import format_rule, format_rules, quote
from invariant.rules.types import ContextSchema
from invariant.rules.validator import validate_rule

from . import dialogs
from .project import Manifest, ProjectError, RunningProject, load_manifest
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


_STRING = r"""(?:"(?:[^"\\\n]|\\.)*"|'(?:[^'\\\n]|\\.)*')"""
_COMMENT = r"(?:[ \t]*(?:\#|//)[^\n]*)?"
_RULE_HEADER = re.compile(rf"^([ \t]*rule[ \t]+{_STRING}[ \t]*\{{){_COMMENT}$", re.MULTILINE)
_ID_LINE = re.compile(rf"^([ \t]*)id[ \t]+{_STRING}{_COMMENT}$", re.MULTILINE)


def with_id(source: str, rules: tuple[Rule, ...], new_id: str) -> str:
    """``source`` with the id of its first rule set to ``new_id``.

    Edits the text, so comments and layout survive; if that cannot be done
    safely (several rules, an unusual layout) the rule is printed instead.
    """
    wanted = tuple(dataclasses.replace(rules[0], id=new_id) if i == 0 else r
                   for i, r in enumerate(rules))  # fmt: skip
    if len(rules) == 1:
        found = _ID_LINE.search(source)
        edited: str | None = None
        if found is not None:
            edited = source[: found.start()] + f"{found.group(1)}id {quote(new_id)}" + source[found.end() :]
        else:
            head = _RULE_HEADER.search(source)
            if head is not None:
                edited = source[: head.end()] + f"\n    id {quote(new_id)}" + source[head.end() :]
        if edited is not None:
            try:
                if parse_rules(edited).rules == wanted:
                    return edited
            except RuleError:
                pass
    return format_rules(list(wanted))


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
        "tags": list(rule.tags),
        "policy": rule.policy,
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
    def __init__(
        self,
        target: ConsoleTarget | None = None,
        store: RuleStore | None = None,
        *,
        library: bool = True,
        start_dir: Path | None = None,
    ) -> None:
        #: The application under test. None until a project folder (or a target the
        #: console was started with) is opened; rules can be written without one.
        self.target: ConsoleTarget | None = target
        self.schema = (target.binding if target else DOCUMENT_SAAS).schema
        #: Where the folder dialog opens.
        self.start_dir = start_dir
        self._project: RunningProject | None = None
        self.store = store or RuleStore()
        #: Every rule that ships (core + default library), with the ids it was written with.
        #: ``library=False`` offers only the three core rules.
        self.shipped: tuple[Rule, ...] = (
            shipped_document() if library else builtin_document()
        ).rules
        #: One exploration at a time; rule edits are serialised too.
        self._lock = threading.RLock()

    @property
    def builtin(self) -> tuple[Rule, ...]:
        """The shipped rules as they are shown and run: with the display id the
        developer's id algorithm gave them. The shipped id stays as the rule's
        policy key, so renaming never changes what the reference policy denies."""
        chosen = self.store.data.builtin_ids
        out: list[Rule] = []
        for rule in self.shipped:
            new = chosen.get(rule.id)
            if new is None or new == rule.id:
                out.append(rule)
            else:
                out.append(dataclasses.replace(rule, id=new, policy=rule.policy or rule.id))
        return tuple(out)

    def _builtin_pairs(self) -> list[tuple[str, Rule]]:
        """(shipped id, effective rule) for every shipped rule."""
        return list(zip((r.id for r in self.shipped), self.builtin, strict=True))

    # -- reference -----------------------------------------------------------

    def bootstrap(self) -> dict[str, Any]:
        return {
            "version": __version__,
            "target": self._target_json(),
            "project": self.project_state(),
            "language": {
                "schema": self.schema.describe(),
                "functions": describe_functions(),
                "clauses": list(CLAUSES),
                "severities": list(SEVERITIES),
                "template": NEW_RULE_TEMPLATE,
                "examples": EXAMPLES,
            },
            "rules": self.list_rules(),
            "settings": self.get_settings(),
        }

    def _target_json(self) -> dict[str, Any] | None:
        target = self.target
        if target is None:
            return None
        return {
            "name": target.name,
            "description": target.description,
            "options": [
                {"id": o.id, "title": o.title, "description": o.description, "property": o.property}
                for o in target.options
            ],
        }

    def _need_target(self) -> ConsoleTarget:
        if self.target is None:
            raise ConsoleError("open a project folder first (the Project tab)")
        return self.target

    # -- project (the application under test) -------------------------------------------

    def project_state(self) -> dict[str, Any]:
        running = self._project
        return {
            "open": running is not None,
            "project": running.state() if running else None,
            "dialog": dialogs.available(),
            "start_dir": str(self.start_dir) if self.start_dir else "",
        }

    def project_pick(self, request: dict[str, Any]) -> dict[str, Any]:
        """Open the system's folder dialog, then describe the chosen folder (nothing is run)."""
        choice = dialogs.choose_folder(self.start_dir)
        if not choice.supported:
            return {"supported": False, "path": None, "manifest": None, "error": ""}
        if choice.error:
            raise ConsoleError(choice.error)
        if choice.path is None:
            return {"supported": True, "path": None, "manifest": None, "error": ""}
        return {"supported": True, **self._inspect(choice.path)}

    def project_inspect(self, request: dict[str, Any]) -> dict[str, Any]:
        raw = request.get("path")
        if not isinstance(raw, str) or not raw.strip():
            raise ConsoleError("path must be a folder path")
        return self._inspect(Path(raw.strip()))

    @staticmethod
    def _inspect(folder: Path) -> dict[str, Any]:
        try:
            manifest: Manifest = load_manifest(folder)
        except ProjectError as exc:
            return {"path": str(folder), "manifest": None, "error": str(exc)}
        return {"path": str(manifest.folder), "manifest": manifest.describe(), "error": ""}

    def project_open(self, request: dict[str, Any]) -> dict[str, Any]:
        """Start the project in the folder and make it the application under test."""
        raw = request.get("path")
        if not isinstance(raw, str) or not raw.strip():
            raise ConsoleError("path must be a folder path")
        try:
            manifest = load_manifest(Path(raw.strip()))
        except ProjectError as exc:
            raise ConsoleError(str(exc)) from exc
        with self._lock:
            self._close_project()
            running = RunningProject(manifest)
            try:
                running.start()
            except ProjectError as exc:
                raise ConsoleError(str(exc)) from exc
            self._project = running
            self.target = running.console_target()
            self.schema = self.target.binding.schema
        return {"project": self.project_state(), "target": self._target_json(), "rules": self.list_rules()}

    def project_close(self, request: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            self._close_project()
        return {"project": self.project_state(), "target": self._target_json()}

    def _close_project(self) -> None:
        if self._project is not None:
            self._project.stop()
            self._project = None
            self.target = None

    def close(self) -> None:
        """Stop anything the console started."""
        with self._lock:
            self._close_project()

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
        # What rules written without an id will be called once saved.
        assigned: dict[str, str] = {}
        if document is not None and not problems:
            _, with_ids = self._with_assigned_ids(source, document, key if isinstance(key, str) else None)
            assigned = {
                before.name: after.id
                for before, after in zip(document.rules, with_ids.rules, strict=True)
                if before.id != after.id
            }
        return {
            "ok": not problems,
            "assigned_ids": assigned,
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
                "description": "", "severity": "", "statement": "", "tags": [], "policy": None,
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
            pairs = self._builtin_pairs()
            out: list[dict[str, Any]] = [
                {
                    **_rule_info(rule),
                    "key": BUILTIN_PREFIX + shipped_id,
                    "shipped_id": shipped_id,
                    "origin": "builtin",
                    "filename": "",
                    "enabled": shipped_id not in disabled,
                    "editable": False,
                    "source": format_rule(rule),
                    "json": jsonio.rule_to_json(rule),
                    "valid": True,
                    "diagnostics": [],
                }
                for shipped_id, rule in pairs
            ]
            taken = {rule.id: "a built-in rule" for _, rule in pairs}
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
            if document is not None and not problems:
                source, document = self._with_assigned_ids(
                    source, document, existing.key if existing else None
                )
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

    def _with_assigned_ids(
        self, source: str, document: RuleDocument, except_key: str | None
    ) -> tuple[str, RuleDocument]:
        """Give every rule that was written without an ``id`` the one the chosen
        algorithm derives from its name. A rule whose id equals its name has none."""
        missing = [r for r in document.rules if r.id == r.name]
        if not missing:
            return source, document
        taken = set(self._other_ids(except_key)) | {
            r.id for r in document.rules if r.id != r.name
        }
        chosen: dict[str, str] = {}
        for rule in missing:
            chosen[rule.name] = rule_ids.assign(self.store.data.id_algorithm, rule.name, taken)
            taken.add(chosen[rule.name])
        rules = tuple(
            dataclasses.replace(r, id=chosen[r.name]) if r.id == r.name else r
            for r in document.rules
        )
        if len(document.rules) == 1:
            source = with_id(source, document.rules, chosen[document.rules[0].name])
        else:
            source = format_rules(list(rules))
        return source, dataclasses.replace(document, rules=rules)

    # -- settings ------------------------------------------------------------

    def get_settings(self) -> dict[str, Any]:
        return {
            "id_algorithm": self.store.data.id_algorithm,
            "default_id_algorithm": rule_ids.DEFAULT_ALGORITHM,
            "id_algorithms": rule_ids.describe(),
        }

    def _id_plan(self, algorithm: str) -> list[dict[str, Any]]:
        """What ``algorithm`` would call every rule, and which of them change."""
        if algorithm not in rule_ids.ALGORITHMS:
            raise ConsoleError(
                f"unknown id algorithm '{algorithm}' (choose one of: {', '.join(rule_ids.ALGORITHMS)})"
            )
        items: list[tuple[str, str, str]] = []
        origin: dict[str, str] = {}
        for shipped_id, rule in self._builtin_pairs():
            key = BUILTIN_PREFIX + shipped_id
            items.append((key, rule.name, rule.id))
            origin[key] = "builtin"
        for stored in self.store.data.rules:
            document, problems = self._check(stored.source)
            if document is None or problems:
                continue  # a draft has no id to rewrite
            for index, rule in enumerate(document.rules):
                key = f"{stored.key}#{index}"
                items.append((key, rule.name, rule.id))
                origin[key] = stored.origin
        new = rule_ids.assign_all(algorithm, items)
        names = {key: name for key, name, _ in items}
        return [
            {"key": key, "name": names[key], "origin": origin[key], "from": current, "to": new[key]}
            for key, _, current in items
        ]

    def preview_settings(self, request: dict[str, Any]) -> dict[str, Any]:
        """The id changes saving ``id_algorithm`` would make. Changes nothing."""
        algorithm = request.get("id_algorithm")
        if not isinstance(algorithm, str):
            raise ConsoleError("id_algorithm must be a string")
        with self._lock:
            plan = self._id_plan(algorithm)
            return {
                "id_algorithm": algorithm,
                "changes": [c for c in plan if c["from"] != c["to"]],
                "unchanged": sum(1 for c in plan if c["from"] == c["to"]),
            }

    def save_settings(self, request: dict[str, Any]) -> dict[str, Any]:
        """Choose the id algorithm and rename every rule to match it, built-in
        rules included. Drafts that do not validate are left as they are."""
        algorithm = request.get("id_algorithm")
        if not isinstance(algorithm, str):
            raise ConsoleError("id_algorithm must be a string")
        with self._lock:
            plan = self._id_plan(algorithm)
            new_ids = {c["key"]: c["to"] for c in plan}
            data = self.store.data
            for shipped in self.shipped:
                wanted = new_ids[BUILTIN_PREFIX + shipped.id]
                if wanted == shipped.id:
                    data.builtin_ids.pop(shipped.id, None)
                else:
                    data.builtin_ids[shipped.id] = wanted
            for stored in data.rules:
                document, problems = self._check(stored.source)
                if document is None or problems:
                    continue
                wanted_ids = [new_ids[f"{stored.key}#{i}"] for i in range(len(document.rules))]
                if wanted_ids == [r.id for r in document.rules]:
                    continue
                if len(document.rules) == 1:
                    stored.source = with_id(stored.source, document.rules, wanted_ids[0])
                else:
                    stored.source = format_rules(
                        [dataclasses.replace(r, id=i) for r, i in zip(document.rules, wanted_ids, strict=True)]
                    )
            data.id_algorithm = algorithm
            self.store.save()
            return {
                "settings": self.get_settings(),
                "changed": [c for c in plan if c["from"] != c["to"]],
                "rules": self.list_rules(),
            }

    def set_enabled_many(self, request: dict[str, Any]) -> dict[str, Any]:
        """Switch many rules on or off in one request (every key or none)."""
        keys, enabled = request.get("keys"), request.get("enabled")
        if not isinstance(keys, list) or not all(isinstance(k, str) for k in keys):
            raise ConsoleError("expected {keys: [string], enabled: boolean}")
        if not isinstance(enabled, bool):
            raise ConsoleError("expected {keys: [string], enabled: boolean}")
        with self._lock:
            known = {r.id for r in self.shipped}
            for key in keys:
                if key.startswith(BUILTIN_PREFIX):
                    if key.removeprefix(BUILTIN_PREFIX) not in known:
                        raise ConsoleError(f"no built-in rule '{key.removeprefix(BUILTIN_PREFIX)}'")
                else:
                    self.store.find(key)  # raises KeyError for an unknown key
            off = set(self.store.data.disabled_builtin)
            for key in keys:
                if key.startswith(BUILTIN_PREFIX):
                    shipped_id = key.removeprefix(BUILTIN_PREFIX)
                    off.discard(shipped_id) if enabled else off.add(shipped_id)
                else:
                    self.store.find(key).enabled = enabled
            self.store.data.disabled_builtin = sorted(off)
            self.store.save()
            return {"rules": self.list_rules()}

    def _with_import_ids(
        self, document: RuleDocument, owned_by_name: dict[str, str]
    ) -> RuleDocument:
        """Ids for imported rules that came without one. A rule named like one the
        developer already has takes that rule's id (so 'replace existing' works on
        re-import); any other gets the id the chosen algorithm derives."""
        taken = set(self._other_ids(None)) | {r.id for r in document.rules if r.id != r.name}
        rules: list[Rule] = []
        disabled = set(document.disabled)
        for rule in document.rules:
            if rule.id == rule.name:
                new = owned_by_name.get(rule.name) or rule_ids.assign(
                    self.store.data.id_algorithm, rule.name, taken
                )
                taken.add(new)
                if rule.id in disabled:
                    disabled.discard(rule.id)
                    disabled.add(new)
                rule = dataclasses.replace(rule, id=new)
            rules.append(rule)
        return RuleDocument(rules=tuple(rules), disabled=frozenset(disabled))

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
                owned_by_name: dict[str, str] = {}
                for stored in self.store.data.rules:
                    parsed, bad = self._check(stored.source)
                    if parsed is not None and not bad:
                        owners.update({r.id: stored for r in parsed.rules})
                        owned_by_name.update({r.name: r.id for r in parsed.rules})
                document = self._with_import_ids(document, owned_by_name)
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
                if rule_id not in {r.id for r in self.shipped}:
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
        target = self._need_target()
        options = target.parse_options(request.get("options", []))
        seed = _int(request.get("seed"), "seed", optional=True)
        max_examples = _int(request.get("max_examples", 200), "max_examples", minimum=1)
        assert max_examples is not None
        with self._lock:
            rules = self.active_ruleset()
            started = time.perf_counter()
            result = explore(
                lambda: target.adapter_for(options),
                target=target.label(options),
                seed=seed,
                max_examples=max_examples,
                rules=rules,
            )
        report = result.report
        return {
            "report": json.loads(report.model_dump_json()),
            "steps_text": [describe_op(s.operation) for s in report.steps],
            # One entry per finding: its operation sequence, described.
            "findings_steps_text": [
                [describe_op(s.operation) for s in f.steps] for f in report.findings
            ],
            "rules_used": [{"id": r.id, "name": r.name, "severity": r.severity} for r in rules.rules],
            "options": sorted(options),
            "duration_ms": int((time.perf_counter() - started) * 1000),
        }

    def replay(self, request: dict[str, Any]) -> dict[str, Any]:
        """Re-run a report's scenario, judged by the rules stored in the report."""
        target = self._need_target()
        options = target.parse_options(request.get("options", []))
        report = Report.model_validate(request.get("report"))
        if report.scenario is None:
            raise ConsoleError("report has no scenario to replay")
        try:
            evaluator = evaluator_for_report(report.rules, target.binding)
        except RuleError as exc:
            raise ConsoleError(
                f"the rules stored in the report are not valid: {exc}",
                [d.to_json() for d in exc.diagnostics],
            ) from exc
        with self._lock:
            started = time.perf_counter()
            result = replay(
                report.scenario, lambda: target.adapter_for(options), evaluator=evaluator
            )
            # Each finding has its own minimal scenario. Replay it with every
            # other rule muted, so the answer is "does this rule alone still fail".
            every_rule = {p.id for p in evaluator.properties}
            findings = []
            for finding in report.findings:
                if finding.scenario is None:
                    continue
                again = replay(
                    finding.scenario,
                    lambda: target.adapter_for(options),
                    evaluator=evaluator.muting(every_rule - {finding.property_id}),
                )
                findings.append(
                    {
                        "property_id": finding.property_id,
                        "outcome": str(again.outcome),
                        "valid": again.valid,
                        "reproduced": violates(again, finding.property_id),
                        "message": str(again.failure) if again.failure else "",
                        "steps": len(again.history),
                    }
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
            "findings": findings,
            "target": target.label(options),
            "duration_ms": int((time.perf_counter() - started) * 1000),
        }

    def report_html(self, request: dict[str, Any]) -> dict[str, Any]:
        return {"html": render_html(Report.model_validate(request.get("report")))}
