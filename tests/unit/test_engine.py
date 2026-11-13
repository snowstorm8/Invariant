import pytest
from support import ScriptedAdapter, obs

from invariant.adapters.base import Action, Call
from invariant.core.engine import Engine, InconclusiveError, PropertyViolationError
from invariant.core.scenario import (
    CreateDocument,
    CreateOrg,
    CreateUser,
    DeleteDocument,
    ListDocuments,
    ReadDocument,
    Role,
    UpdateDocument,
)
from invariant.core.state import UnknownRefError
from invariant.evaluation.violations import Outcome


class World:
    """A tiny scriptable target: hands out ids, serves canned document responses."""

    def __init__(self):
        self.n = 0
        self.overrides: dict[Action, object] = {}

    def __call__(self, call: Call):
        if call.action in self.overrides:
            return self.overrides[call.action]
        self.n += 1
        match call.action:
            case Action.CREATE_ORG:
                return obs(201, {"id": f"o{self.n}"})
            case Action.CREATE_USER:
                return obs(201, {"id": f"u{self.n}", "token": f"t{self.n}"})
            case Action.CREATE_DOCUMENT:
                return obs(201, {"id": f"d{self.n}"})
            case Action.LIST_DOCUMENTS:
                return obs(200, [])
            case _:
                return obs(404, {"detail": "not found"})


@pytest.fixture
def world():
    return World()


@pytest.fixture
def engine(world):
    e = Engine(ScriptedAdapter(world))
    e.reset()
    e.apply(CreateOrg(ref="org0", name="a"))
    e.apply(CreateOrg(ref="org1", name="b"))
    e.apply(CreateUser(ref="user0", org="org0", role=Role.ADMIN))
    e.apply(CreateUser(ref="user1", org="org1", role=Role.MEMBER))
    e.apply(CreateUser(ref="user2", org="org0", role=Role.VIEWER))
    return e


def test_reset_resets_adapter_and_forgets_model(engine):
    engine.apply(CreateDocument(ref="doc0", actor="user0", content="c"))
    assert engine.state.docs and engine.history
    engine.reset()
    assert engine.adapter.resets == 2
    assert not engine.state.docs and not engine.state.users and not engine.history
    assert engine.new_ref("doc") == "doc0"


def test_new_ref_is_per_prefix_and_sequential(engine):
    assert [engine.new_ref("x"), engine.new_ref("x"), engine.new_ref("y")] == ["x0", "x1", "y0"]


def test_calls_use_real_credentials_and_ids_not_symbolic_refs(engine):
    engine.apply(CreateDocument(ref="doc0", actor="user0", content="c"))
    call = engine.adapter.calls[-1]
    assert call.credential == engine.state.user("user0").token != "user0"
    engine.apply(ReadDocument(actor="user0", doc="doc0"))
    assert engine.adapter.calls[-1].resource_id == engine.state.doc("doc0").external_id


def test_authorised_create_is_mirrored_with_unique_marker(engine):
    engine.apply(CreateDocument(ref="doc0", actor="user0", content="same"))
    engine.apply(CreateDocument(ref="doc1", actor="user0", content="same"))
    d0, d1 = engine.state.doc("doc0"), engine.state.doc("doc1")
    assert d0.org == "org0" and d0.version == 1
    assert d0.marker != d1.marker and d0.content.endswith(d0.marker)


def test_failed_authorised_create_leaves_model_unchanged(engine, world):
    world.overrides[Action.CREATE_DOCUMENT] = obs(400, {"detail": "bad"})
    rec = engine.apply(CreateDocument(ref="doc0", actor="user0", content="c"))
    assert "doc0" not in engine.state.docs and rec.outcome is Outcome.PASS


def test_authorised_update_and_delete_update_model(engine, world):
    engine.apply(CreateDocument(ref="doc0", actor="user0", content="c"))
    world.overrides[Action.UPDATE_DOCUMENT] = obs(200, {"ok": 1})
    engine.apply(UpdateDocument(actor="user0", doc="doc0", content="new"))
    doc = engine.state.doc("doc0")
    assert doc.version == 2 and doc.content.startswith("new ")
    world.overrides[Action.DELETE_DOCUMENT] = obs(200, {"deleted": True})
    engine.apply(DeleteDocument(actor="user0", doc="doc0"))
    assert doc.deleted


def test_update_rejected_by_target_does_not_change_model(engine):
    engine.apply(CreateDocument(ref="doc0", actor="user0", content="c"))
    before = engine.state.doc("doc0").content
    engine.apply(UpdateDocument(actor="user0", doc="doc0", content="new"))  # default 404
    assert engine.state.doc("doc0").content == before


def test_forbidden_write_triggers_probe_as_member_of_affected_org(engine, world):
    engine.apply(CreateDocument(ref="doc0", actor="user0", content="c"))
    ext = engine.state.doc("doc0").external_id
    marker_content = engine.state.doc("doc0").content
    world.overrides[Action.LIST_DOCUMENTS] = obs(
        200, [{"id": ext, "content": marker_content, "version": 1}]
    )
    rec = engine.apply(UpdateDocument(actor="user1", doc="doc0", content="evil"))
    probe_call = engine.adapter.calls[-1]
    assert probe_call.action is Action.LIST_DOCUMENTS
    assert probe_call.credential == engine.state.user("user0").token  # org0 member, not attacker
    assert not rec.allowed_by_policy and rec.outcome is Outcome.PASS
    assert engine.state.doc("doc0").version == 1


def test_forbidden_write_that_changed_state_raises_violation_with_evidence(engine, world):
    engine.apply(CreateDocument(ref="doc0", actor="user0", content="c"))
    ext = engine.state.doc("doc0").external_id
    world.overrides[Action.UPDATE_DOCUMENT] = obs(403, {"detail": "forbidden"})
    world.overrides[Action.LIST_DOCUMENTS] = obs(
        200, [{"id": ext, "content": "tampered", "version": 2}]
    )
    with pytest.raises(PropertyViolationError) as exc:
        engine.apply(UpdateDocument(actor="user1", doc="doc0", content="evil"))
    err = exc.value
    assert err.record.status == 403
    assert err.record.evaluations[-1].property_id == "TI-2"
    assert [type(o).__name__ for o in err.scenario.operations][-1] == "UpdateDocument"
    assert len(err.history) == len(engine.history)


def test_setup_failure_is_inconclusive_even_when_not_strict(world):
    e = Engine(ScriptedAdapter(world), strict=False)
    e.reset()
    world.overrides[Action.CREATE_ORG] = obs(500, "boom")
    with pytest.raises(InconclusiveError):
        e.apply(CreateOrg(ref="org0", name="a"))
    assert e.history[-1].evaluations[0].property_id == "EXEC"


def test_server_error_strict_raises_non_strict_records(engine, world):
    engine.apply(CreateDocument(ref="doc0", actor="user0", content="c"))
    world.overrides[Action.READ_DOCUMENT] = obs(500, "boom")
    with pytest.raises(InconclusiveError):
        engine.apply(ReadDocument(actor="user0", doc="doc0"))
    engine.strict = False
    rec = engine.apply(ReadDocument(actor="user0", doc="doc0"))
    assert rec.outcome is Outcome.INCONCLUSIVE  # recorded, never reported as PASS


def test_transport_error_is_inconclusive(engine, world):
    world.overrides[Action.LIST_DOCUMENTS] = obs(None, "", error="ConnectError")
    with pytest.raises(InconclusiveError):
        engine.apply(ListDocuments(actor="user0"))


def test_unknown_ref_is_rejected(engine):
    with pytest.raises(UnknownRefError):
        engine.apply(ReadDocument(actor="user0", doc="doc99"))


def test_close_closes_adapter(engine):
    engine.close()
    assert engine.adapter.closed


def test_scenario_is_the_executed_operations(engine):
    engine.apply(ListDocuments(actor="user0"))
    ops = engine.scenario.operations
    assert len(ops) == 6 and isinstance(ops[-1], ListDocuments)
