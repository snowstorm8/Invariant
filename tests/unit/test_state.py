import pytest
from support import make_state

from invariant.core.state import ModelState, UnknownRefError


def test_lookup_unknown_refs_raise():
    s = ModelState()
    for fn in (s.user, s.doc, s.org):
        with pytest.raises(UnknownRefError):
            fn("nope")


def test_member_of_and_foreign_docs():
    s = make_state()
    assert s.member_of("org0").ref == "user0"
    assert s.member_of("org1").ref == "user1"
    assert s.member_of("missing") is None
    assert [d.ref for d in s.foreign_docs("org1")] == ["doc0"]
    assert s.foreign_docs("org0") == []


def test_expected_snapshot_excludes_deleted_and_other_orgs():
    s = make_state()
    assert s.expected_snapshot("org0") == {"doc_6": ("secret <<INV:3>>", 1)}
    assert s.expected_snapshot("org1") == {}
    s.docs["doc0"].deleted = True
    assert s.expected_snapshot("org0") == {}


def test_foreign_docs_include_deleted_docs():
    s = make_state()
    s.docs["doc0"].deleted = True
    assert [d.ref for d in s.foreign_docs("org1")] == ["doc0"]
