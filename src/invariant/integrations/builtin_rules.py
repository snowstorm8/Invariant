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


def builtin_source() -> str:
    return resources.files("invariant.integrations").joinpath(RULE_FILE).read_text("utf-8")


@cache
def builtin_document() -> RuleDocument:
    return parse_rules(builtin_source())


def builtin_rule(rule_id: str) -> Rule:
    return next(r for r in builtin_document().rules if r.id == rule_id)
