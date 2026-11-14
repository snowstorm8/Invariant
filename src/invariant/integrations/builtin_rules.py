"""The rules that ship with the document SaaS integration.

They live in ``document_saas.rules``, in the rule language. This module only
reads and parses that file; it imports nothing application-specific, so the
property metadata (``properties/isolation.py``) can be derived from it.
"""

from __future__ import annotations

from functools import cache
from importlib import resources

from invariant.rules.ir import Rule, RuleDocument
from invariant.rules.parser import parse_rules

RULE_FILE = "document_saas.rules"
#: The default rule library for web applications (access control, data exposure,
#: headers and cookies, integrity). Shipped alongside the core rules; it is a
#: separate file so the core rule set, and what is pinned on it, stays small.
LIBRARY_FILE = "web_defaults.rules"


def builtin_source() -> str:
    return resources.files("invariant.integrations").joinpath(RULE_FILE).read_text("utf-8")


@cache
def builtin_document() -> RuleDocument:
    return parse_rules(builtin_source())


def builtin_rule(rule_id: str) -> Rule:
    return next(r for r in builtin_document().rules if r.id == rule_id)


def library_source() -> str:
    return resources.files("invariant.integrations").joinpath(LIBRARY_FILE).read_text("utf-8")


@cache
def library_document() -> RuleDocument:
    return parse_rules(library_source())


@cache
def shipped_document() -> RuleDocument:
    """Every rule that ships: the core rules first, then the default library."""
    core, library = builtin_document(), library_document()
    return RuleDocument(rules=(*core.rules, *library.rules), disabled=core.disabled | library.disabled)
