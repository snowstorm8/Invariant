"""End to end: Invariant against the demo app, vulnerable and fixed."""

import pytest

from invariant.adapters.base import Action, Adapter, Observation
from invariant.analysis.minimizer import minimize, violates
from invariant.analysis.reproduction import replay
from invariant.core.engine import InconclusiveError
from invariant.core.scenario import (
    CreateDocument,
    CreateOrg,
    CreateUser,
    DeleteDocument,
    ReadDocument,
    Role,
    Scenario,
    UpdateDocument,
)
from invariant.evaluation.violations import Outcome
from invariant.exploration.runner import explore
from invariant.exploration.state_machine import ExplorationSink, build_state_machine
from vulnerable_saas.target import adapter_for, fixed_adapter, vulnerable_adapter

SETUP = [
    CreateOrg(ref="org0", name="a"),
    CreateOrg(ref="org1", name="b"),
    CreateUser(ref="owner", org="org0", role=Role.ADMIN),
    CreateUser(ref="viewer", org="org0", role=Role.VIEWER),
    CreateUser(ref="outsider", org="org1", role=Role.ADMIN),
    CreateDocument(ref="doc0", actor="owner", content="top secret"),
]

ATTACKS = {
    "stale-cache-read": (
        "TI-1",
        [UpdateDocument(actor="owner", doc="doc0", content="v2"),
         ReadDocument(actor="outsider", doc="doc0")],
    ),
    "update-missing-tenant-check": (
        "TI-2",
        [UpdateDocument(actor="outsider", doc="doc0", content="pwned")],
    ),
    "viewer-can-update": (
        "AZ-1",
        [UpdateDocument(actor="viewer", doc="doc0", content="oops")],
    ),
}


def scenario(*ops):
    return Scenario(operations=[*SETUP, *ops])


@pytest.mark.parametrize("defect", ATTACKS)
def test_each_defect_is_detected_with_the_right_property(defect):
    prop, ops = ATTACKS[defect]
    result = replay(scenario(*ops), lambda: adapter_for(frozenset({defect})))
    assert result.outcome is Outcome.VIOLATION
    assert violates(result, prop)
    assert result.failure.record.index == len(SETUP) + len(ops) - 1


@pytest.mark.parametrize("defect", ATTACKS)
def test_same_attack_passes_against_the_fixed_app(defect):
    _, ops = ATTACKS[defect]
    result = replay(scenario(*ops), fixed_adapter)
    assert result.outcome is Outcome.PASS and result.failure is None


def test_attack_does_not_trigger_other_defects():
    # Each defect is independent: the cache bug scenario is clean when only the
    # viewer bug is enabled.
    _, ops = ATTACKS["stale-cache-read"]
    result = replay(scenario(*ops), lambda: adapter_for(frozenset({"viewer-can-update"})))
    assert result.outcome is Outcome.PASS


def test_forbidden_actions_on_fixed_app_all_pass():
    ops = [
        ReadDocument(actor="outsider", doc="doc0"),
        UpdateDocument(actor="outsider", doc="doc0", content="x"),
        DeleteDocument(actor="outsider", doc="doc0"),
        UpdateDocument(actor="viewer", doc="doc0", content="x"),
        DeleteDocument(actor="viewer", doc="doc0"),
        CreateDocument(ref="doc1", actor="viewer", content="x"),
    ]
    result = replay(scenario(*ops), fixed_adapter)
    assert result.outcome is Outcome.PASS
    assert all(r.outcome is Outcome.PASS for r in result.history)


def test_explore_finds_the_controlled_defect_reliably():
    # Several independent search seeds: discovery must not depend on luck.
    for seed in range(5):
        result = explore(vulnerable_adapter, target="demo", seed=seed)
        report = result.report
        assert result.outcome is Outcome.VIOLATION, f"seed {seed} missed the defect"
        assert report.finding.property_id == "TI-1"
        assert report.reproduced is True
        ops = report.scenario.operations
        assert isinstance(ops[-1], ReadDocument)
        assert any(isinstance(o, UpdateDocument) for o in ops)  # the cache needs an update
        assert len(ops) <= 9  # minimised


def test_explore_is_repeatable_for_a_seed():
    a = explore(vulnerable_adapter, seed=3).report.scenario
    b = explore(vulnerable_adapter, seed=3).report.scenario
    assert a == b


def test_explored_scenario_replays_on_fresh_instance_and_passes_once_fixed():
    report = explore(vulnerable_adapter, seed=0).report
    assert replay(report.scenario, vulnerable_adapter).outcome is Outcome.VIOLATION
    assert replay(report.scenario, fixed_adapter).outcome is Outcome.PASS


def test_explore_fixed_app_reports_pass_without_a_finding():
    result = explore(fixed_adapter, seed=0, max_examples=60)
    assert result.outcome is Outcome.PASS
    assert result.report.finding is None and result.report.executions >= 60


def test_explore_finds_other_defects_too():
    for defect, prop in [("update-missing-tenant-check", "TI-2"), ("viewer-can-update", "AZ-1")]:
        result = explore(lambda d=defect: adapter_for(frozenset({d})), seed=0)
        assert result.outcome is Outcome.VIOLATION
        assert result.report.finding.property_id == prop


def test_minimizer_removes_irrelevant_operations_and_keeps_the_cause():
    _, ops = ATTACKS["stale-cache-read"]
    noisy = scenario(
        ReadDocument(actor="owner", doc="doc0"),
        CreateDocument(ref="doc1", actor="owner", content="noise"),
        *ops,
        ReadDocument(actor="viewer", doc="doc0"),
    )
    # trailing op after the violation is never executed; minimize drops the noise
    small, result = minimize(noisy, vulnerable_adapter, property_id="TI-1")
    assert len(small.operations) < len(noisy.operations)
    assert violates(result, "TI-1")
    kinds = [type(o) for o in small.operations]
    assert UpdateDocument in kinds and kinds[-1] is ReadDocument
    # 1-minimal: removing any single op breaks the reproduction
    for i in range(len(small.operations)):
        candidate = Scenario(operations=small.operations[:i] + small.operations[i + 1 :])
        assert not violates(replay(candidate, vulnerable_adapter), "TI-1")


def test_minimizer_returns_non_reproducing_scenario_unchanged():
    benign = scenario()
    out, result = minimize(benign, fixed_adapter, property_id="TI-1")
    assert out == benign and not violates(result, "TI-1")


def test_replay_of_scenario_with_dangling_refs_is_invalid_not_pass():
    result = replay(Scenario(operations=[ReadDocument(actor="ghost", doc="doc0")]), fixed_adapter)
    assert result.valid is False and result.outcome is Outcome.INCONCLUSIVE


def test_runs_are_isolated_state_does_not_leak_between_replays():
    s = scenario(*ATTACKS["stale-cache-read"][1])
    first = replay(s, vulnerable_adapter)
    second = replay(s, vulnerable_adapter)
    assert first.outcome is second.outcome is Outcome.VIOLATION
    assert [r.status for r in first.history] == [r.status for r in second.history]


# -- non-strict exploration must not turn INCONCLUSIVE into PASS -------------


class BrokenReads(Adapter):
    """A working target whose single-document reads always answer 500.

    Reads are not used to verify writes, so a non-strict engine records the
    step as INCONCLUSIVE and carries on instead of stopping the run.
    """

    def __init__(self, defects=frozenset()):
        self.inner = adapter_for(defects)
        #: Every call this instance received, in order, with the status it answered.
        self.log: list[tuple[Action, int | None]] = []

    def reset(self):
        self.inner.reset()

    def execute(self, call):
        if call.action is Action.READ_DOCUMENT:
            observation = Observation(status=500, body="boom")
        else:
            observation = self.inner.execute(call)
        self.log.append((call.action, observation.status))
        return observation

    def close(self):
        self.inner.close()


@pytest.mark.parametrize("strict", [True, False])
def test_inconclusive_steps_never_yield_pass_regardless_of_strict(strict):
    result = explore(BrokenReads, seed=1, max_examples=20, strict=strict)
    assert result.outcome is Outcome.INCONCLUSIVE
    assert result.report.finding.property_id == "EXEC"
    assert result.report.finding.outcome is Outcome.INCONCLUSIVE
    assert result.report.reproduced is True
    assert isinstance(result.report.scenario.operations[-1], ReadDocument)


def drive_until_failed_read(strict):
    """One exploration execution, driven by hand up to its first failing read.

    The rules are called directly, in a fixed order, on the same state machine
    class ``explore()`` hands to Hypothesis, so nothing here depends on what
    Hypothesis happens to generate. Exactly one adapter instance is involved.
    """
    adapter, sink = BrokenReads(), ExplorationSink()
    machine_cls = build_state_machine(lambda: adapter, sink=sink, strict=strict)
    machine = machine_cls()
    machine.provision_orgs()
    user = machine.create_user(org="org0", role=Role.ADMIN)
    doc = machine.create_document(actor=user, content="abc")
    assert doc == "doc0" and sink.failures == []  # healthy until the read
    return machine, adapter, sink, user, doc


def test_non_strict_execution_continues_on_the_same_adapter_after_an_inconclusive_read():
    machine, adapter, sink, user, doc = drive_until_failed_read(strict=False)

    machine.read_document(actor=user, doc=doc)  # INCONCLUSIVE, must not raise
    calls_at_failure = len(adapter.log)
    assert adapter.log[-1] == (Action.READ_DOCUMENT, 500)
    read_step = machine.engine.history[-1]
    assert read_step.outcome is Outcome.INCONCLUSIVE

    # The INCONCLUSIVE step is reported to the sink although nothing was raised.
    assert len(sink.failures) == 1
    failure = sink.failures[0]
    assert isinstance(failure, InconclusiveError)
    assert failure.record is read_step
    assert isinstance(failure.scenario.operations[-1], ReadDocument)

    # The very same adapter instance then serves further operations, which are
    # judged normally and change the target: the execution really continued.
    machine.list_documents(actor=user)
    machine.update_document(actor=user, doc=doc, content="xyz")
    later = adapter.log[calls_at_failure:]
    assert (Action.LIST_DOCUMENTS, 200) in later
    assert (Action.UPDATE_DOCUMENT, 200) in later
    assert [r.outcome for r in machine.engine.history[read_step.index + 1 :]] == [
        Outcome.PASS,
        Outcome.PASS,
    ]
    assert machine.engine.state.doc(doc).version == 2

    # A second failing read is still executed, but the execution is reported once.
    machine.read_document(actor=user, doc=doc)
    assert adapter.log[-1] == (Action.READ_DOCUMENT, 500)
    assert len(sink.failures) == 1
    machine.teardown()


def test_strict_execution_stops_at_the_inconclusive_read():
    machine, adapter, sink, user, doc = drive_until_failed_read(strict=True)
    with pytest.raises(InconclusiveError) as raised:
        machine.read_document(actor=user, doc=doc)
    assert adapter.log[-1] == (Action.READ_DOCUMENT, 500)
    assert sink.failures == [raised.value]
    machine.teardown()


def test_non_strict_violation_still_outranks_inconclusive():
    result = explore(
        lambda: BrokenReads(frozenset({"viewer-can-update"})), seed=0, strict=False
    )
    assert result.outcome is Outcome.VIOLATION
    assert result.report.finding.property_id == "AZ-1"


def test_non_strict_clean_target_still_passes():
    result = explore(fixed_adapter, seed=0, max_examples=30, strict=False)
    assert result.outcome is Outcome.PASS and result.report.finding is None


def test_a_report_counts_the_steps_each_passing_rule_held_on() -> None:
    result = explore(fixed_adapter, seed=1, max_examples=15)
    assert result.outcome is Outcome.PASS
    held = result.report.held
    assert held and all(count > 0 for count in held.values())
    assert {"TI-1", "TI-2", "AZ-1"} <= set(held)

    broken = explore(vulnerable_adapter, seed=1, max_examples=200).report
    failed = {f.property_id for f in broken.findings}
    assert "TI-1" in failed
    assert all(n > 0 for n in broken.held.values())
