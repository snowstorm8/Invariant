import pytest
from support import make_state

from invariant.core.scenario import (
    CreateDocument,
    CreateOrg,
    DeleteDocument,
    ListDocuments,
    ReadDocument,
    UpdateDocument,
)
from invariant.properties.authorization import decide
from invariant.properties.registry import PROPERTIES


@pytest.mark.parametrize(
    ("op", "allowed", "prop"),
    [
        (ReadDocument(actor="user0", doc="doc0"), True, None),
        (ReadDocument(actor="user2", doc="doc0"), True, None),  # viewer may read own org
        (ReadDocument(actor="user1", doc="doc0"), False, "TI-1"),
        (UpdateDocument(actor="user0", doc="doc0", content="x"), True, None),
        (UpdateDocument(actor="user1", doc="doc0", content="x"), False, "TI-2"),
        (UpdateDocument(actor="user2", doc="doc0", content="x"), False, "AZ-1"),
        (DeleteDocument(actor="user0", doc="doc0"), True, None),
        (DeleteDocument(actor="user1", doc="doc0"), False, "TI-2"),
        (DeleteDocument(actor="user2", doc="doc0"), False, "AZ-1"),
        (CreateDocument(ref="doc1", actor="user1", content="x"), True, None),
        (CreateDocument(ref="doc1", actor="user2", content="x"), False, "AZ-1"),
        (ListDocuments(actor="user1"), True, None),
        (CreateOrg(ref="org2", name="n"), True, None),
    ],
)
def test_policy_decisions(op, allowed, prop):
    decision = decide(make_state(), op)
    assert decision.allowed is allowed
    assert decision.property_id == prop


def test_member_cannot_delete_own_org_doc():
    s = make_state()
    s.users["user1"].org = "org0"  # member of the owning org
    d = decide(s, DeleteDocument(actor="user1", doc="doc0"))
    assert (d.allowed, d.property_id) == (False, "AZ-1")


def test_decision_property_ids_are_registered_and_stated():
    for pid in ("TI-1", "TI-2", "AZ-1"):
        assert PROPERTIES[pid].statement
        assert PROPERTIES[pid].name
