"""Persistence for the rules a developer manages in the console.

One JSON file holds every authored or imported rule (as rule-language text,
which is lossless for JSON imports too) with its on/off switch, plus the ids of
built-in rules that were switched off. Drafts that do not validate are kept, so
work in progress is not lost; they simply cannot be run.
"""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import asdict, dataclass, field
from pathlib import Path

STORE_VERSION = 1


@dataclass
class StoredRule:
    key: str
    source: str
    enabled: bool = True
    origin: str = "authored"  # "authored" | "imported"
    filename: str = ""


@dataclass
class StoreData:
    rules: list[StoredRule] = field(default_factory=list)
    disabled_builtin: list[str] = field(default_factory=list)
    next_key: int = 1


class RuleStore:
    """Load/save ``StoreData``. ``path=None`` keeps everything in memory."""

    def __init__(self, path: Path | None = None) -> None:
        self.path = path
        self.data = self._load()

    def _load(self) -> StoreData:
        if self.path is None or not self.path.exists():
            return StoreData()
        try:
            raw = json.loads(self.path.read_text("utf-8"))
            rules = [
                StoredRule(
                    key=str(r["key"]),
                    source=str(r["source"]),
                    enabled=bool(r.get("enabled", True)),
                    origin=str(r.get("origin", "authored")),
                    filename=str(r.get("filename", "")),
                )
                for r in raw.get("rules", [])
            ]
            return StoreData(
                rules=rules,
                disabled_builtin=[str(i) for i in raw.get("disabled_builtin", [])],
                next_key=int(raw.get("next_key", len(rules) + 1)),
            )
        except (OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
            raise ValueError(f"cannot read rule store {self.path}: {exc}") from exc

    def save(self) -> None:
        if self.path is None:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {"version": STORE_VERSION, **asdict(self.data)}
        # Write-then-rename so an interrupted save never leaves a truncated store.
        fd, tmp = tempfile.mkstemp(dir=self.path.parent, prefix=".rules-", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, indent=2)
                handle.write("\n")
            os.replace(tmp, self.path)
        except BaseException:
            Path(tmp).unlink(missing_ok=True)
            raise

    def new_key(self) -> str:
        key = f"r{self.data.next_key}"
        self.data.next_key += 1
        return key

    def find(self, key: str) -> StoredRule:
        for rule in self.data.rules:
            if rule.key == key:
                return rule
        raise KeyError(f"no rule with key '{key}'")
