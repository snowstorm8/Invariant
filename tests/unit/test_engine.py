import pytest

from invariant.adapters.base import Action, AdapterError, Call, Observation
from invariant.core.engine import (
    Engine,
    EngineInvalidatedError,
    InconclusiveError,
    PropertyViolationError,
)
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
from support import ScriptedAdapter, obs

WRITERS = {"admin", "member"}


class World:
    """A small, correct multi-tenant document service with switchable faults.

    * ``skip_persist``: these actions answer success but change nothing.
    * ``apply_on_deny``: forbidden writes answer 403 yet still modify state.
    * ``overrides``: canned observation per action (checked first).
    * ``mangle``: function applied to stored content on create/update.
    """

    def __init__(self):
        self.n = 0
        self.orgs: set[str] = set()
        self.users: dict[str, tuple[str, str]] = {}  # token -> (org, role)
        self.docs: dict[str, dict] = {}
        self.skip_persist: set[Action] = set()
        self.apply_on_deny = False
        self.overrides: dict[Action, Observation] = {}
        self.mangle = lambda c: c

    def _id(self, prefix):
        self.n += 1
        return f"{prefix}{self.n}"

    def __call__(self, call: Call) -> Observation:
        if call.action in self.overrides:
            return self.overrides[call.action]
        a = call.action
        if a is Action.CREATE_ORG:
            org = self._id("o")
            self.orgs.add(org)
            return obs(201, {"id": org})
        if a is Action.CREATE_USER:
            uid, token = self._id("u"), self._id("t")
            self.users[token] = (call.org_id, call.data["role"])
            return obs(201, {"id": uid, "token": token})
        org, role = self.users[call.credential]
        if a is Action.LIST_DOCUMENTS:
            return obs(200, [self._view(d) for d in self.docs.values() if d["org"] == org])
        if a is Action.CREATE_DOCUMENT:
            if role not in WRITERS:
                return obs(403, {"detail": "role"})
            doc_id = self._id("d")
            doc = {"id": doc_id, "org": org, "content": self.mangle(call.data["content"]), "version": 1}
            if a not in self.skip_persist:
                self.docs[doc_id] = doc
            return obs(201, self._view(doc))
        doc = self.docs.get(call.resource_id)
        if doc is None:
            return obs(404, {"detail": "not found"})
        if a is Action.READ_DOCUMENT:
            return obs(200, self._view(doc)) if doc["org"] == org else obs(404)
        allowed = doc["org"] == org and (role in WRITERS if a is Action.UPDATE_DOCUMENT else role == "admin")
        if not allowed and not self.apply_on_deny:
            return obs(403 if doc["org"] == org else 404, {"detail": "denied"})
        if a is Action.UPDATE_DOCUMENT:
            if a not in self.skip_persist:
                doc["content"] = self.mangle(call.data["content"])
                doc["version"] += 1
            return obs(200 if allowed else 403, self._view(doc))
        if a is Action.DELETE_DOCUMENT:
            if a not in self.skip_persist:
                del self.docs[call.resource_id]
            return obs(200 if allowed else 403, {"id": call.resource_id, "deleted": True})
        raise AssertionError(a)

    @staticmethod
    def _view(d):
        return {"id": d["id"], "org_id": d["org"], "content": d["content"], "version": d["version"]}


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


@pytest.fixture
def seeded(engine):
    engine.apply(CreateDocument(ref="doc0", actor="user0", content="c"))
    return engine


def assert_inconclusive_and_model_untouched(engine, op, before):
    """Stops INCONCLUSIVE (never a violation) and leaves the model as it was."""
    with pytest.raises(InconclusiveError) as exc:
        engine.apply(op)
    assert not isinstance(exc.value, PropertyViolationError)
    assert exc.value.record.outcome is Outcome.INCONCLUSIVE
    assert exc.value.record.evaluations[-1].property_id == "EXEC"
    assert {r: (d.content, d.version, d.deleted) for r, d in engine.state.docs.items()} == before
    return exc.value


def model_view(engine):
    return {r: (d.content, d.version, d.deleted) for r, d in engine.state.docs.items()}


# -- lifecycle / plumbing -------------------------------------------------


def test_reset_resets_adapter_and_forgets_model(seeded):
    assert seeded.state.docs and seeded.history
    seeded.reset()
    assert seeded.adapter.resets == 2
    assert not seeded.state.docs and not seeded.state.users and not seeded.history
    assert seeded.new_ref("doc") == "doc0"


def test_new_ref_is_per_prefix_and_sequential(engine):
    assert [engine.new_ref("x"), engine.new_ref("x"), engine.new_ref("y")] == ["x0", "x1", "y0"]


def test_calls_use_real_credentials_and_ids_not_symbolic_refs(seeded):
    create_call = next(c for c in seeded.adapter.calls if c.action is Action.CREATE_DOCUMENT)
    assert create_call.credential == seeded.state.user("user0").token != "user0"
    seeded.apply(ReadDocument(actor="user0", doc="doc0"))
    assert seeded.adapter.calls[-1].resource_id == seeded.state.doc("doc0").external_id


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


# -- valid authorised operations are verified, then committed --------------


def test_valid_create_is_verified_and_mirrored_with_unique_marker(engine):
    engine.apply(CreateDocument(ref="doc0", actor="user0", content="same"))
    engine.apply(CreateDocument(ref="doc1", actor="user0", content="same"))
    d0, d1 = engine.state.doc("doc0"), engine.state.doc("doc1")
    assert d0.org == "org0" and d0.version == 1 and d0.content.endswith(d0.marker)
    assert d0.marker != d1.marker


def test_valid_update_and_delete_are_verified_and_committed(seeded):
    seeded.apply(UpdateDocument(actor="user0", doc="doc0", content="new"))
    doc = seeded.state.doc("doc0")
    assert doc.version == 2 and doc.content.startswith("new ")
    assert doc.marker in doc.content
    seeded.apply(DeleteDocument(actor="user0", doc="doc0"))
    assert doc.deleted and not seeded.state.expected_snapshot("org0")


def test_valid_operation_issues_a_probe_as_the_actor(seeded):
    seeded.apply(UpdateDocument(actor="user0", doc="doc0", content="n"))
    probe = seeded.adapter.calls[-1]
    assert probe.action is Action.LIST_DOCUMENTS
    assert probe.credential == seeded.state.user("user0").token


def test_authorised_rejection_with_unchanged_state_is_not_an_error(seeded, world):
    seeded.apply(DeleteDocument(actor="user0", doc="doc0"))
    before = model_view(seeded)
    rec = seeded.apply(UpdateDocument(actor="user0", doc="doc0", content="x"))  # 404: gone
    assert rec.outcome is Outcome.PASS and model_view(seeded) == before


def test_update_of_deleted_doc_that_falsely_succeeds_is_unverified(seeded, world):
    seeded.apply(DeleteDocument(actor="user0", doc="doc0"))
    world.overrides[Action.UPDATE_DOCUMENT] = obs(200, {"ok": True})
    ext = seeded.state.doc("doc0").external_id
    world.docs[ext] = {"id": ext, "org": "o1", "content": "zombie", "version": 1}
    assert_inconclusive_and_model_untouched(
        seeded, UpdateDocument(actor="user0", doc="doc0", content="x"), model_view(seeded)
    )


# -- HTTP success without the promised state change ------------------------


def test_200_without_persisted_create_is_inconclusive(engine, world):
    world.skip_persist.add(Action.CREATE_DOCUMENT)
    err = assert_inconclusive_and_model_untouched(
        engine, CreateDocument(ref="doc0", actor="user0", content="c"), {}
    )
    assert err.record.status == 201 and "expected but missing" in err.record.evaluations[-1].summary
    assert "doc0" not in engine.state.docs


def test_200_without_persisted_update_is_inconclusive(seeded, world):
    world.skip_persist.add(Action.UPDATE_DOCUMENT)
    assert_inconclusive_and_model_untouched(
        seeded, UpdateDocument(actor="user0", doc="doc0", content="new"), model_view(seeded)
    )


def test_200_without_persisted_delete_is_inconclusive(seeded, world):
    world.skip_persist.add(Action.DELETE_DOCUMENT)
    assert_inconclusive_and_model_untouched(
        seeded, DeleteDocument(actor="user0", doc="doc0"), model_view(seeded)
    )
    assert not seeded.state.doc("doc0").deleted


def test_unverified_transition_halts_even_when_not_strict(seeded, world):
    seeded.strict = False
    world.skip_persist.add(Action.UPDATE_DOCUMENT)
    with pytest.raises(InconclusiveError):
        seeded.apply(UpdateDocument(actor="user0", doc="doc0", content="new"))


def test_persisted_content_differing_from_sent_content_is_inconclusive(engine, world):
    world.mangle = lambda c: c.upper()
    assert_inconclusive_and_model_untouched(
        engine, CreateDocument(ref="doc0", actor="user0", content="c"), {}
    )


def test_wrong_version_after_update_is_inconclusive(seeded, world):
    ext = seeded.state.doc("doc0").external_id
    world.docs[ext]["version"] = 5  # app disagrees about the version counter
    assert_inconclusive_and_model_untouched(
        seeded, UpdateDocument(actor="user0", doc="doc0", content="n"), model_view(seeded)
    )


def test_create_success_without_document_id_is_inconclusive(engine, world):
    world.overrides[Action.CREATE_DOCUMENT] = obs(201, {"ok": True})
    assert_inconclusive_and_model_untouched(
        engine, CreateDocument(ref="doc0", actor="user0", content="c"), {}
    )


def test_error_response_that_nevertheless_changed_state_is_inconclusive_not_violation(seeded, world):
    ext = seeded.state.doc("doc0").external_id
    world.overrides[Action.UPDATE_DOCUMENT] = obs(400, {"detail": "bad"})
    world.docs[ext]["content"] = "changed anyway"  # applied despite the 400
    assert_inconclusive_and_model_untouched(
        seeded, UpdateDocument(actor="user0", doc="doc0", content="n"), model_view(seeded)
    )


# -- the state probe itself must be trustworthy -----------------------------

BAD_PROBES = [
    obs(None, "", error="ConnectError"),
    obs(500, "boom"),
    obs(404, "gone"),
    obs(200, "not json"),
    obs(200, {"docs": []}),
    obs(200, [1]),
    obs(200, [{"id": "d1", "content": "x"}]),  # no version
]


@pytest.mark.parametrize("probe", BAD_PROBES)
@pytest.mark.parametrize(
    "op",
    [
        UpdateDocument(actor="user0", doc="doc0", content="new"),
        DeleteDocument(actor="user0", doc="doc0"),
    ],
)
def test_unavailable_or_malformed_probe_blocks_authorised_commit(seeded, world, probe, op):
    world.overrides[Action.LIST_DOCUMENTS] = probe
    err = assert_inconclusive_and_model_untouched(seeded, op, model_view(seeded))
    assert "probe unusable" in err.record.evaluations[-1].summary


@pytest.mark.parametrize("probe", BAD_PROBES)
def test_unavailable_or_malformed_probe_on_authorised_create(engine, world, probe):
    world.overrides[Action.LIST_DOCUMENTS] = probe
    assert_inconclusive_and_model_untouched(
        engine, CreateDocument(ref="doc0", actor="user0", content="c"), {}
    )


@pytest.mark.parametrize("probe", BAD_PROBES)
def test_unavailable_or_malformed_probe_after_forbidden_write_is_inconclusive(seeded, world, probe):
    world.overrides[Action.LIST_DOCUMENTS] = probe
    before = model_view(seeded)
    with pytest.raises(InconclusiveError) as exc:
        seeded.apply(UpdateDocument(actor="user1", doc="doc0", content="evil"))
    assert not isinstance(exc.value, PropertyViolationError)
    assert model_view(seeded) == before


# -- unauthorised writes: existing detection preserved ----------------------


def test_forbidden_write_with_unchanged_state_passes_and_leaves_model(seeded):
    before = model_view(seeded)
    rec = seeded.apply(UpdateDocument(actor="user1", doc="doc0", content="evil"))
    assert not rec.allowed_by_policy and rec.outcome is Outcome.PASS
    probe = seeded.adapter.calls[-1]
    assert probe.credential == seeded.state.user("user0").token  # org0 member, not attacker
    assert model_view(seeded) == before


def test_403_that_still_modified_state_is_a_violation(seeded, world):
    world.apply_on_deny = True
    with pytest.raises(PropertyViolationError) as exc:
        seeded.apply(UpdateDocument(actor="user1", doc="doc0", content="evil"))
    rec = exc.value.record
    assert rec.status == 403 and rec.evaluations[-1].property_id == "TI-2"
    assert rec.evaluations[-1].outcome is Outcome.VIOLATION
    assert seeded.state.doc("doc0").version == 1  # model was not corrupted by the attack


def test_forbidden_delete_that_removed_doc_is_a_violation(seeded, world):
    world.apply_on_deny = True
    with pytest.raises(PropertyViolationError) as exc:
        seeded.apply(DeleteDocument(actor="user2", doc="doc0"))  # viewer
    assert exc.value.record.evaluations[-1].property_id == "AZ-1"
    assert not seeded.state.doc("doc0").deleted


# -- failures unrelated to verification --------------------------------------


def test_setup_failure_is_inconclusive_even_when_not_strict(world):
    e = Engine(ScriptedAdapter(world), strict=False)
    e.reset()
    world.overrides[Action.CREATE_ORG] = obs(500, "boom")
    with pytest.raises(InconclusiveError):
        e.apply(CreateOrg(ref="org0", name="a"))
    assert e.history[-1].evaluations[0].property_id == "EXEC"


def test_server_error_strict_raises_non_strict_records(seeded, world):
    world.overrides[Action.READ_DOCUMENT] = obs(500, "boom")
    with pytest.raises(InconclusiveError):
        seeded.apply(ReadDocument(actor="user0", doc="doc0"))
    seeded.strict = False
    rec = seeded.apply(ReadDocument(actor="user0", doc="doc0"))
    assert rec.outcome is Outcome.INCONCLUSIVE


def test_server_error_on_authorised_write_halts_and_leaves_model(seeded, world):
    seeded.strict = False
    world.overrides[Action.UPDATE_DOCUMENT] = obs(500, "boom")
    before = model_view(seeded)
    with pytest.raises(InconclusiveError):
        seeded.apply(UpdateDocument(actor="user0", doc="doc0", content="n"))
    assert model_view(seeded) == before


def test_transport_error_is_inconclusive(engine, world):
    world.overrides[Action.LIST_DOCUMENTS] = obs(None, "", error="ConnectError")
    with pytest.raises(InconclusiveError):
        engine.apply(ListDocuments(actor="user0"))


# -- an unverified transition is terminal until a successful reset ------------


def invalidate(engine, world):
    """Make an authorised write unverifiable and swallow the resulting error."""
    world.skip_persist.add(Action.UPDATE_DOCUMENT)
    with pytest.raises(InconclusiveError):
        engine.apply(UpdateDocument(actor="user0", doc="doc0", content="new"))
    world.skip_persist.clear()


def test_apply_after_unverified_write_is_rejected_before_any_adapter_call(seeded, world):
    invalidate(seeded, world)
    calls, history, model = len(seeded.adapter.calls), list(seeded.history), model_view(seeded)
    users = dict(seeded.state.users)
    for op in (
        ListDocuments(actor="user0"),  # harmless read
        UpdateDocument(actor="user0", doc="doc0", content="again"),
        CreateOrg(ref="org9", name="x"),  # setup ops too
    ):
        with pytest.raises(EngineInvalidatedError, match="reset"):
            seeded.apply(op)
    assert len(seeded.adapter.calls) == calls
    assert seeded.history == history and model_view(seeded) == model
    assert seeded.state.users == users and "org9" not in seeded.state.orgs


@pytest.mark.parametrize("strict", [True, False])
def test_every_unverified_cause_invalidates(seeded, world, strict):
    seeded.strict = strict
    world.overrides[Action.LIST_DOCUMENTS] = obs(200, "not json")  # unusable probe
    with pytest.raises(InconclusiveError):
        seeded.apply(UpdateDocument(actor="user0", doc="doc0", content="n"))
    with pytest.raises(EngineInvalidatedError):
        seeded.apply(ListDocuments(actor="user0"))


def test_missing_create_id_and_server_error_also_invalidate(engine, world):
    world.overrides[Action.CREATE_DOCUMENT] = obs(201, {"ok": True})
    with pytest.raises(InconclusiveError):
        engine.apply(CreateDocument(ref="doc0", actor="user0", content="c"))
    with pytest.raises(EngineInvalidatedError):
        engine.apply(ListDocuments(actor="user0"))

    engine.reset()
    world.overrides.clear()
    engine.apply(CreateOrg(ref="org0", name="a"))
    engine.apply(CreateUser(ref="user0", org="org0", role=Role.ADMIN))
    world.overrides[Action.CREATE_DOCUMENT] = obs(500, "boom")
    engine.strict = False
    with pytest.raises(InconclusiveError):
        engine.apply(CreateDocument(ref="doc0", actor="user0", content="c"))
    with pytest.raises(EngineInvalidatedError):
        engine.apply(ListDocuments(actor="user0"))


def test_successful_reset_restores_normal_operation(seeded, world):
    invalidate(seeded, world)
    seeded.reset()
    assert not seeded.history and not seeded.state.docs
    seeded.apply(CreateOrg(ref="org0", name="a"))
    seeded.apply(CreateUser(ref="user0", org="org0", role=Role.ADMIN))
    rec = seeded.apply(CreateDocument(ref="doc0", actor="user0", content="c"))
    assert rec.outcome is Outcome.PASS and "doc0" in seeded.state.docs


def test_failed_reset_does_not_clear_the_terminal_state(seeded, world):
    invalidate(seeded, world)
    adapter = seeded.adapter

    def failing_reset():
        raise AdapterError("cannot reset")

    adapter.reset = failing_reset
    calls, history = len(adapter.calls), list(seeded.history)
    with pytest.raises(AdapterError):
        seeded.reset()
    with pytest.raises(EngineInvalidatedError):
        seeded.apply(ListDocuments(actor="user0"))
    assert len(adapter.calls) == calls and seeded.history == history  # nothing was cleared
    del adapter.reset  # target recovers; a later successful reset works
    seeded.reset()
    seeded.apply(CreateOrg(ref="org0", name="a"))


def test_ordinary_violation_does_not_invalidate_the_engine(seeded, world):
    world.apply_on_deny = True
    with pytest.raises(PropertyViolationError):
        seeded.apply(UpdateDocument(actor="user1", doc="doc0", content="evil"))
    world.apply_on_deny = False
    seeded.apply(ListDocuments(actor="user0"))  # still usable, as before


def test_unrelated_inconclusive_observation_does_not_invalidate(seeded, world):
    seeded.strict = False
    world.overrides[Action.READ_DOCUMENT] = obs(500, "boom")
    assert seeded.apply(ReadDocument(actor="user0", doc="doc0")).outcome is Outcome.INCONCLUSIVE
    seeded.apply(ListDocuments(actor="user0"))  # non-strict continues, as before


def test_failed_reset_on_a_valid_engine_makes_it_unusable(seeded, world):
    adapter = seeded.adapter
    boom = AdapterError("cannot reset")

    def failing_reset():
        raise boom

    adapter.reset = failing_reset
    calls, history, model = len(adapter.calls), list(seeded.history), model_view(seeded)
    refs = dict(seeded._ref_counts)
    with pytest.raises(AdapterError) as exc:
        seeded.reset()
    assert exc.value is boom  # original exception propagates unchanged
    for op in (ListDocuments(actor="user0"), CreateOrg(ref="org9", name="x")):
        with pytest.raises(EngineInvalidatedError):
            seeded.apply(op)
    assert len(adapter.calls) == calls  # rejected before contacting the adapter
    assert seeded.history == history and model_view(seeded) == model
    assert seeded.state.users and seeded._ref_counts == refs  # nothing was cleared

    del adapter.reset  # target recovers
    seeded.reset()
    assert not seeded.history and not seeded.state.users
    seeded.apply(CreateOrg(ref="org0", name="a"))
    seeded.apply(CreateUser(ref="user0", org="org0", role=Role.ADMIN))
    assert seeded.apply(ListDocuments(actor="user0")).outcome is Outcome.PASS
