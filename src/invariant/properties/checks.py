"""How security properties are judged: by interpreting rules.

There is one implementation of :class:`SecurityProperty`, :class:`RuleCheck`. It
judges a step by evaluating a rule written in Invariant's rule language against
the context the integration builds for that step. The built-in properties
(TI-1, TI-2, AZ-1) are rules too, loaded from ``integrations/document_saas.rules``;
rules a developer writes are turned into checks by the same function.
"""

from __future__ import annotations

from invariant.adapters.base import Observation
from invariant.evaluation.violations import Outcome
from invariant.integrations.builtin_rules import builtin_document
from invariant.integrations.document_saas import DOCUMENT_SAAS
from invariant.rules.binding import RuleBinding
from invariant.rules.engine import CompiledRule, RuleSet
from invariant.rules.values import Undefined

from .base import Evidence, ProbeRequest, Property, SecurityProperty, Step, Verdict


class RuleCheck(SecurityProperty):
    """A rule, presented to the evaluation framework as a property.

    Pure: no I/O, no state between steps. ``applies`` is the rule's ``when``,
    ``requires`` its ``observe`` clauses, ``evaluate`` its assertions.
    """

    def __init__(self, rule: CompiledRule, binding: RuleBinding = DOCUMENT_SAAS) -> None:
        super().__init__(Property.from_rule(rule.rule))
        self.rule = rule
        self.binding = binding

    def applies(self, step: Step) -> bool:
        # An undecidable scope still applies: evaluate() then reports it as
        # INCONCLUSIVE instead of silently skipping the rule.
        return self.rule.in_scope(self.binding.context(step, None)) is not False

    def requires(self, step: Step) -> tuple[ProbeRequest, ...]:
        requests: list[ProbeRequest] = []
        for observe, args in self.rule.probe_arguments(self.binding.context(step, None)):
            if isinstance(args, Undefined):
                continue  # cannot be asked for; evaluate() finds the name undefined
            request: ProbeRequest = self.binding.probe_request(observe.probe, args)  # type: ignore[assignment]
            if request not in requests:
                requests.append(request)
        return tuple(requests)

    def evaluate(self, step: Step, response: Observation, evidence: Evidence) -> Verdict:
        context = self.binding.context(step, response)
        observed = {}
        for observe, args in self.rule.probe_arguments(self.binding.context(step, None)):
            if isinstance(args, Undefined):
                continue
            request: ProbeRequest = self.binding.probe_request(observe.probe, args)  # type: ignore[assignment]
            if request in evidence:
                observed[observe.name] = self.binding.probe_value(observe.probe, evidence[request])
        verdict = self.rule.judge(context, observed)
        if verdict.outcome is None:  # only reachable if called without applies()
            return Verdict(Outcome.PASS, "rule does not apply to this operation")
        return Verdict(verdict.outcome, verdict.summary, verdict.evidence)


def checks_for(rules: RuleSet, binding: RuleBinding = DOCUMENT_SAAS) -> tuple[RuleCheck, ...]:
    """One check per rule, in the rule set's order."""
    return tuple(RuleCheck(rule, binding) for rule in rules)


def builtin_ruleset() -> RuleSet:
    """The rules that ship with the document SaaS integration, freshly compiled."""
    return RuleSet(builtin_document().rules, DOCUMENT_SAAS.schema)


#: Default evaluation order. The first violation on a step determines how a
#: failure is attributed, so this order is part of observable behaviour.
CHECKS: tuple[SecurityProperty, ...] = checks_for(builtin_ruleset())

_BY_ID = {check.id: check for check in CHECKS}
TENANT_READ_ISOLATION_CHECK = _BY_ID["TI-1"]
TENANT_WRITE_ISOLATION_CHECK = _BY_ID["TI-2"]
ROLE_WRITE_PERMISSION_CHECK = _BY_ID["AZ-1"]
