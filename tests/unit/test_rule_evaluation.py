"""Evaluating rules, on an integration that has nothing to do with the demo SaaS."""

import pytest

from invariant.evaluation.violations import Outcome
from invariant.rules import (
    CompiledRule,
    RuleRegistry,
    RuleSet,
    RuleValidationError,
    document_to_json,
    parse_expression,
    parse_rules,
)
from invariant.rules.interpreter import Interpreter
from invariant.rules.values import LazyContext, Undefined
from rule_support import BANK_SCHEMA, BankBinding, bank_rules, bank_step, judge

OK = {"ok": True, "code": 200, "receipt": {"id": "r1", "amount": 50}}
REFUSED = {"ok": False, "code": 403}


def value(source, roots=None, lets=None):
    interpreter = Interpreter(roots or {}, {k: parse_expression(v) for k, v in (lets or {}).items()}, {})
    return interpreter.evaluate(parse_expression(source))


# -- expressions -------------------------------------------------------------

ROOTS = {
    "n": 3,
    "s": "hello",
    "xs": [1, 2, 3],
    "m": {"a": 1, "b": None},
    "people": [{"name": "ann", "age": 30}, {"name": "bob"}],
    "flag": True,
}


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        ("n + 1 * 2", 5), ("n - 1 - 1", 1), ("-n", -3), ("s + '!'", "hello!"), ("xs + [4]", [1, 2, 3, 4]),
        ("n == 3.0", True), ("n == '3'", False), ("flag == 1", False), ("m.b == null", True),
        ("xs == [1, 2, 3]", True), ("{a: 1} == {a: 1}", True), ("{a: 1} != {a: 2}", True),
        ("n < 4 and s >= 'h'", True), ("2 in xs", True), ("'ell' in s", True), ("'a' in m", True),
        ("5 not in xs", True), ("xs[0]", 1), ("xs[-1]", 3), ("m['a']", 1), ("people[0].name", "ann"),
        ("count(xs)", 3), ("count(s)", 5), ("count(m)", 2), ("contains(s, 'ell')", True),
        ("contains(xs, 2)", True), ("startswith(s, 'he')", True), ("endswith(s, 'x')", False),
        ("upper(s)", "HELLO"), ("lower('AbC')", "abc"), ("str(n) + str(flag) + str(null)", "3truenull"),
        ("join(xs, '-')", "1-2-3"), ("first(xs)", 1), ("last(xs)", 3), ("keys(m)", ["a", "b"]),
        ("values(m)", [1, None]), ("sum(xs)", 6), ("sum([])", 0), ("min(xs)", 1), ("max(xs)", 3),
        ("distinct([1, 1, 2, 1.0])", [1, 2]),
        ("[x * 2 for x in xs where x > 1]", [4, 6]),
        ("[e.key for e in m]", ["a", "b"]),
        ("some x in xs : x > 2", True), ("every x in xs : x > 2", False), ("none x in xs : x > 5", True),
        ("some x in [] : true", False), ("every x in [] : false", True),
        ("[[x, y] for x in [1, 2] where some y in xs : y == x + 2]", None),  # y is not in scope outside
        ("diff({a: 1, b: 2, c: {v: 1}}, {b: 3, c: {v: 1}, d: 4})",
         ["a expected but missing", "d present but not expected", "b expected (2) observed (3)"]),
        ("diff({k: {content: 'x', version: 1}}, {k: {content: 'y', version: 2}})",
         ["k expected (content='x', version=1) observed (content='y', version=2)"]),
    ],
)  # fmt: skip
def test_expression_values(source, expected):
    result = value(source, ROOTS)
    if expected is None:
        assert isinstance(result, Undefined)
    else:
        assert result == expected and type(result) is type(expected)


@pytest.mark.parametrize(
    ("source", "reason"),
    [
        ("missing", "'missing' is not available for this operation"),
        ("m.zzz", "m.zzz is missing"),
        ("s.length", "s is a string, so it has no field 'length'"),
        ("m.b.c", "m.b is null, so it has no field 'c'"),
        ("xs[9]", "xs[9] is out of range"),
        ("m['zzz']", "m has no entry 'zzz'"),
        ("n < s", "cannot order n (a number) and s (a string)"),
        ("n + s", "cannot apply '+'"),
        ("not n", "n is a number, not true or false"),
        ("first([])", "first() of an empty list"),
        ("count(n)", "count() expects a list, map or string, got a number"),
        ("some p in people : p.age > 40", "p.age is missing"),
        ("[p.age for p in people]", "p.age is missing"),
        ("some x in n : true", "cannot iterate over n"),
    ],
)
def test_what_cannot_be_computed_is_undefined_with_a_reason(source, reason):
    result = value(source, ROOTS)
    assert isinstance(result, Undefined) and reason in result.reason


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        # Kleene logic: undefined matters only when it could change the answer.
        ("false and missing", False), ("missing and false", False), ("true and missing", None),
        ("true or missing", True), ("missing or true", True), ("false or missing", None),
        ("false implies missing", True), ("missing implies true", True), ("true implies missing", None),
        ("not missing", None), ("missing == 1", None),
        ("some p in people : p.age == 30", True),   # decided by ann; bob's missing age is irrelevant
        ("every p in people : p.age == 99", False),
        ("every p in people : p.age == 30", None),  # bob could falsify it
        ("none p in people : p.age == 99", None),
        ("has(missing)", False), ("has(m.b)", True), ("has(people[1].age)", False),
        ("coalesce(missing, m.zzz, 7)", 7), ("coalesce(n, missing)", 3),
        ("{a: n, b: missing}", {"a": 3}),
    ],
)
def test_three_valued_logic(source, expected):
    result = value(source, ROOTS)
    if expected is None:
        assert isinstance(result, Undefined)
    else:
        assert result == expected


def test_lets_are_evaluated_lazily_once_and_outside_any_loop_variable():
    calls = []

    def expensive():
        calls.append(1)
        return [1, 2, 3]

    roots = LazyContext({"xs": expensive, "never_used": lambda: 1 / 0})
    assert value("some x in xs : x == total - 3", roots, {"total": "sum(xs)"}) is True
    assert calls == [1]


def test_runaway_rules_are_stopped_by_the_step_budget():
    big = "[[[a + b + c for c in xs] for b in xs] for a in xs]"
    (rule,) = RuleSet.from_text(
        f'rule "r" {{ always count({big.replace("xs", "ledger.accounts")}) >= 0 }}'.replace("a + b + c", "1"),
        BANK_SCHEMA,
    ).compiled
    step = bank_step(ledger={"balances": {}, "accounts": [{"id": str(i), "owner": "c"} for i in range(80)]})
    verdict = CompiledRule(rule.rule, BANK_SCHEMA, budget=5_000).judge(BankBinding().context(step, OK))
    assert verdict.outcome is Outcome.INCONCLUSIVE and "exceeded the budget" in verdict.summary
    assert rule.judge(BankBinding().context(bank_step(), OK)).outcome is Outcome.PASS


def test_rules_cannot_reach_python():
    for source in ("__import__('os')", "actor.__class__", "open('x')", "eval('1')"):
        result = value(source, {"actor": {"ref": "u"}})
        assert isinstance(result, Undefined)
    with pytest.raises(RuleValidationError, match="unknown function '__import__'"):
        bank_rules('rule "r" { always __import__("os") == 1 }')


# -- verdicts ----------------------------------------------------------------

OVERDRAFT = '''
rule "no-overdraft" {
    severity critical
    when request.kind in ["withdraw", "transfer"]
    never result.ok and request.amount > ledger.balances[request.source]
}
'''


def test_pass_violation_and_out_of_scope():
    assert judge(OVERDRAFT, bank_step(), OK).outcome is Outcome.PASS
    rich = bank_step(request={"kind": "transfer", "amount": 500, "source": "acc-a", "destination": "acc-b"})
    refused = judge(OVERDRAFT, rich, REFUSED)
    assert (refused.outcome, refused.summary) == (Outcome.PASS, "assertion held")
    violated = judge(OVERDRAFT, rich, OK)
    assert violated.outcome is Outcome.VIOLATION
    deposit = bank_step(request={"kind": "deposit", "amount": 5})
    assert judge(OVERDRAFT, deposit, OK).outcome is None  # not in scope: no verdict at all


def test_a_violation_without_a_message_explains_itself_from_the_values_it_read():
    step = bank_step(request={"kind": "transfer", "amount": 500, "source": "acc-a", "destination": "acc-b"})
    verdict = judge(OVERDRAFT, step, OK)
    assert verdict.summary == (
        "forbidden condition held: result.ok and request.amount > ledger.balances[request.source] "
        "(result.ok = true, request.amount = 500, ledger.balances = "
        '{"acc-a": 80, "acc-b": 10}, request.source = \'acc-a\')'
    )
    assert verdict.evidence == {
        "assertion": "never result.ok and request.amount > ledger.balances[request.source]",
        "values": {
            "result.ok": True,
            "request.amount": 500,
            "ledger.balances": {"acc-a": 80, "acc-b": 10},
            "request.source": "acc-a",
        },
    }


def test_message_and_evidence_clauses_are_used_verbatim():
    source = '''
    rule "limit" {
        let limit = customer.limits[request.kind]
        always result.ok implies request.amount <= limit
        message "{customer.id} moved {request.amount} over a limit of {limit} {{sic}}"
        pass_message "{request.amount} is within {limit}"
        evidence { limit: limit, receipt: result.receipt.id, absent: result.receipt.nope }
    }'''
    assert judge(source, bank_step(), OK).summary == "50 is within 100"
    step = bank_step(request={"kind": "transfer", "amount": 150, "source": "acc-a"})
    verdict = judge(source, step, OK)
    assert verdict.summary == "c1 moved 150 over a limit of 100 {sic}"
    assert verdict.evidence == {"limit": 100, "receipt": "r1", "absent": None}


def test_a_verdict_that_depends_on_missing_data_is_inconclusive_never_pass():
    source = 'rule "receipt" { always result.receipt.amount == request.amount }'
    assert judge(source, bank_step(), OK).outcome is Outcome.PASS
    verdict = judge(source, bank_step(), REFUSED)
    assert verdict.outcome is Outcome.INCONCLUSIVE
    assert verdict.summary == "rule could not be evaluated: result.receipt is missing"
    assert verdict.evidence["assertion"] == "always result.receipt.amount == request.amount"
    # Saying when the field is expected removes the ambiguity.
    guarded = 'rule "receipt" { always result.ok implies result.receipt.amount == request.amount }'
    assert judge(guarded, bank_step(), REFUSED).outcome is Outcome.PASS


def test_a_definite_violation_outranks_an_undecidable_assertion():
    source = 'rule "two" { always result.receipt.id == "r1" never result.code == 403 }'
    assert judge(source, bank_step(), REFUSED).outcome is Outcome.VIOLATION
    assert judge(source, bank_step(), {"ok": False, "code": 500}).outcome is Outcome.INCONCLUSIVE
    assert judge(source, bank_step(), OK).summary == "all 2 assertions held"


def test_an_undecidable_scope_is_inconclusive():
    source = 'rule "r" { when customer.limits["wire"] > 0 always result.ok }'
    (rule,) = bank_rules(source).compiled
    context = BankBinding().context(bank_step(), None)
    assert isinstance(rule.in_scope(context), Undefined)
    verdict = judge(source, bank_step(), OK)
    assert verdict.outcome is Outcome.INCONCLUSIVE and "cannot tell whether the rule applies" in verdict.summary


def test_observations_are_requested_before_the_response_and_used_after():
    source = '''
    rule "balance-after" {
        when request.kind == "withdraw"
        observe after = balance(request.source)
        always result.ok implies after == ledger.balances[request.source] - request.amount
    }'''
    (rule,) = bank_rules(source).compiled
    binding = BankBinding()
    step = bank_step(request={"kind": "withdraw", "amount": 30, "source": "acc-a"})
    ((observe, args),) = rule.probe_arguments(binding.context(step, None))
    assert (observe.name, observe.probe, args) == ("after", "balance", ("acc-a",))
    assert binding.probe_request(observe.probe, args) == ("balance", "acc-a")
    assert judge(source, step, OK, {"after": 50}).outcome is Outcome.PASS
    assert judge(source, step, OK, {"after": 80}).outcome is Outcome.VIOLATION
    missing = judge(source, step, OK, {})  # the probe could not be taken
    assert missing.outcome is Outcome.INCONCLUSIVE and "'after' is not available" in missing.summary


def test_rules_relate_the_current_step_to_earlier_ones():
    source = '''
    rule "frozen-after-fraud" {
        description "After a refused transfer over 1000, the customer's next withdrawal must be refused."
        when request.kind == "withdraw"
            and some j in journal : j.request.kind == "transfer" and j.request.amount > 1000
                and not j.result.ok and j.customer.id == customer.id
        never result.ok
    }'''
    withdraw = {"kind": "withdraw", "amount": 10, "source": "acc-a"}
    customer = bank_step()["customer"]
    fraud = {"request": {"kind": "transfer", "amount": 5000}, "customer": customer, "result": {"ok": False}}
    other = {"request": {"kind": "transfer", "amount": 5000}, "customer": {**customer, "id": "c9"}, "result": {"ok": False}}
    assert judge(source, bank_step(request=withdraw), OK).outcome is None
    assert judge(source, bank_step(request=withdraw, journal=[other]), OK).outcome is None
    assert judge(source, bank_step(request=withdraw, journal=[other, fraud]), OK).outcome is Outcome.VIOLATION
    assert judge(source, bank_step(request=withdraw, journal=[fraud]), REFUSED).outcome is Outcome.PASS


def test_text_and_json_rules_give_identical_verdicts():
    source = OVERDRAFT + '''
    rule "gold-only-large" {
        let big = request.amount >= 100
        always big and result.ok implies customer.tier == "gold"
        message "{customer.id} ({customer.tier}) moved {request.amount}"
        evidence { tier: customer.tier, amount: request.amount }
    }'''
    from_text = bank_rules(source)
    from_json = RuleSet.from_json(document_to_json(parse_rules(source).rules), BANK_SCHEMA)
    assert from_json.rules == from_text.rules
    binding = BankBinding()
    for amount in (10, 90, 100, 500):
        for result in (OK, REFUSED):
            step = bank_step(request={"kind": "transfer", "amount": amount, "source": "acc-a"})
            context = binding.context(step, result)
            assert [r.judge(context) for r in from_text] == [r.judge(context) for r in from_json]


# -- runtime registration ----------------------------------------------------


def test_rules_are_registered_enabled_disabled_and_removed_at_run_time():
    registry = RuleRegistry(BANK_SCHEMA)
    assert len(registry) == 0 and registry.ruleset().ids() == []
    registry.register(OVERDRAFT)  # text
    registry.register({"name": "always-answers", "always": {"call": "has", "args": [{"ref": "result.code"}]}})  # JSON
    registry.register(parse_rules('rule "third" { always true }').rules[0], origin="imported")  # IR
    assert registry.ruleset().ids() == ["no-overdraft", "always-answers", "third"]
    assert "third" in registry and registry.get("third").origin == "imported"

    registry.set_enabled("no-overdraft", False)
    assert registry.ruleset().ids() == ["always-answers", "third"]
    registry.set_enabled("no-overdraft", True)
    registry.unregister("third")
    assert registry.ruleset().ids() == ["no-overdraft", "always-answers"]
    assert registry.get("no-overdraft").source.startswith('rule "no-overdraft" {')
    with pytest.raises(KeyError):
        registry.set_enabled("third", True)


def test_registration_is_all_or_nothing_and_ids_are_unique():
    registry = RuleRegistry(BANK_SCHEMA)
    registry.register(OVERDRAFT)
    with pytest.raises(RuleValidationError, match="already registered"):
        registry.register(OVERDRAFT)
    both = 'rule "good" { always true }\nrule "bad" { always custmer.id == "x" }'
    with pytest.raises(RuleValidationError, match="unknown name 'custmer'"):
        registry.register(both)
    assert registry.ruleset().ids() == ["no-overdraft"]  # "good" was not half-registered
    registry.register(OVERDRAFT.replace("critical", "low"), replace=True)
    assert registry.get("no-overdraft").rule.severity == "low"


def test_json_disabled_flag_is_respected_on_registration():
    registry = RuleRegistry(BANK_SCHEMA)
    registry.register([{"name": "a", "always": True}, {"name": "b", "always": True, "enabled": False}])
    assert registry.ruleset().ids() == ["a"] and len(registry) == 2
