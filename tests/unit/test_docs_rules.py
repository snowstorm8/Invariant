"""Every complete rule in the documentation validates, and none gives a false alarm.

Fenced blocks tagged ``rule`` in docs/*.md are complete rules. They are checked against the
document-service schema and then explored on the fixed Meridian build, where every rule that is
written as a promise about a correct application must hold.
"""

import re
from pathlib import Path

from meridian_support import MeridianAdapter

from invariant.exploration.runner import explore
from invariant.integrations.document_saas import DOCUMENT_SAAS
from invariant.rules.engine import RuleSet
from invariant.rules.parser import parse_rules
from invariant.rules.validator import validate_rule

DOCS = Path(__file__).resolve().parent.parent.parent / "docs"
BLOCK = re.compile(r"^```rule\n(.*?)^```", re.S | re.M)


def doc_rules() -> list[tuple[str, str]]:
    found = []
    for path in sorted(DOCS.glob("*.md")):
        for match in BLOCK.finditer(path.read_text()):
            found.append((path.name, match.group(1)))
    return found


def test_the_tutorial_has_rules_to_check():
    names = {name for name, _ in doc_rules()}
    assert "tutorial-rules.md" in names
    assert len([1 for name, _ in doc_rules() if name == "tutorial-rules.md"]) >= 15


def test_every_documented_rule_is_valid():
    for name, source in doc_rules():
        document = parse_rules(source)
        for rule in document.rules:
            problems = validate_rule(rule, DOCUMENT_SAAS.schema)
            assert not problems, f"{name}: {rule.name}: {[p.message for p in problems]}"


def test_documented_rules_hold_on_the_fixed_build():
    # Rules are collected by name so that a rule shown twice is checked once.
    seen: dict[str, str] = {}
    for _, source in doc_rules():
        for rule in parse_rules(source).rules:
            seen.setdefault(rule.name, source)
    # Exercise rules and the tutorial's rules all state promises a correct application keeps.
    rules = RuleSet.from_text("\n".join(seen.values()), DOCUMENT_SAAS.schema)
    result = explore(
        lambda: MeridianAdapter(frozenset()), target="docs", seed=1, max_examples=60, rules=rules
    )
    assert result.report.outcome.value == "PASS", [
        (f.property_id, f.summary) for f in result.report.findings
    ]
