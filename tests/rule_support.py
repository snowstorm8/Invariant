"""A second, unrelated integration for the rule engine: a toy bank.

It shares nothing with the document SaaS model (no orgs, documents, roles or
HTTP). Tests use it to show that the rule language is driven entirely by the
schema and values an integration supplies.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from invariant.rules import ContextSchema, RuleBinding, RuleSet
from invariant.rules.types import (
    ANY,
    BOOL,
    INT,
    NUMBER,
    STRING,
    Field,
    ListType,
    MapType,
    ProbeSpec,
    enum,
    record,
)

_TRANSFER = record(
    kind=enum("deposit", "withdraw", "transfer"),
    amount=NUMBER,
    source=Field(STRING, optional=True),
    destination=Field(STRING, optional=True),
)
_CUSTOMER = record(id=STRING, tier=enum("basic", "gold"), frozen=BOOL, limits=MapType(NUMBER))

BANK_SCHEMA = ContextSchema(
    name="toy-bank",
    description="Accounts and money movements.",
    roots={
        "request": Field(_TRANSFER, "The movement being judged."),
        "customer": Field(_CUSTOMER, "Who asked for it."),
        "ledger": Field(
            record(balances=MapType(NUMBER), accounts=ListType(record(id=STRING, owner=STRING))),
            "Expected balances before the movement.",
        ),
        "journal": Field(
            ListType(record(request=_TRANSFER, customer=_CUSTOMER, result=record(ok=BOOL))),
            "Earlier movements, oldest first.",
        ),
        "result": Field(
            record(ok=BOOL, code=INT, receipt=Field(ANY, optional=True)),
            "What the bank answered.",
            late=True,
        ),
    },
    probes={
        "balance": ProbeSpec(
            (("account", STRING),), NUMBER, "Balance of one account after the movement."
        )
    },
)


class BankBinding(RuleBinding):
    """Steps are plain dicts; the 'response' is the bank's result dict."""

    @property
    def schema(self) -> ContextSchema:
        return BANK_SCHEMA

    def context(self, step: Any, response: Any | None) -> Mapping[str, Any]:
        roots = dict(step)
        if response is not None:
            roots["result"] = response
        return roots

    def probe_request(self, probe: str, args: Any) -> tuple[str, str]:
        return (probe, args[0])

    def probe_value(self, probe: str, raw: Any) -> Any:
        return raw


def bank_step(**overrides: Any) -> dict[str, Any]:
    step: dict[str, Any] = {
        "request": {"kind": "transfer", "amount": 50, "source": "acc-a", "destination": "acc-b"},
        "customer": {"id": "c1", "tier": "basic", "frozen": False, "limits": {"transfer": 100}},
        "ledger": {
            "balances": {"acc-a": 80, "acc-b": 10},
            "accounts": [{"id": "acc-a", "owner": "c1"}, {"id": "acc-b", "owner": "c2"}],
        },
        "journal": [],
    }
    step.update(overrides)
    return step


def bank_rules(source: str) -> RuleSet:
    return RuleSet.from_text(source, BANK_SCHEMA)


def judge(source: str, step: Mapping[str, Any], result: Any, observed: Mapping[str, Any] | None = None):
    """Judge ``step`` with the single rule in ``source``; returns its RuleVerdict."""
    (rule,) = bank_rules(source).compiled
    binding = BankBinding()
    return rule.judge(binding.context(step, result), observed or {})
