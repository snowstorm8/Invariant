"""Snapshot parsing and comparison: None is 'unusable', never 'empty'."""

import pytest

from invariant.adapters.base import Observation
from invariant.evaluation.evaluator import Evaluator
from invariant.evaluation.snapshots import diff_snapshots, parse_snapshot
from support import obs

DOC = {"id": "doc_6", "content": "secret <<INV:3>>", "version": 1}

UNUSABLE = [
    Observation(error="ReadTimeout: slow"),  # no response
    obs(500, [DOC]),  # a well-formed listing is still unusable unless the status is 200
    obs(201, [DOC]),
    obs(403, []),
    obs(200, ""),
    obs(200, "not json"),
    obs(200, {"docs": [DOC]}),  # not a list
    obs(200, "null"),
    obs(200, [1, 2]),  # items are not objects
    obs(200, [DOC, "x"]),  # one bad item spoils the whole listing
    obs(200, [{"content": "c", "version": 1}]),  # missing id
    obs(200, [{"id": "d", "version": 1}]),  # missing content
    obs(200, [{"id": "d", "content": "c"}]),  # missing version
    obs(200, [{"id": 7, "content": "c", "version": 1}]),  # id not a string
    obs(200, [{"id": "d", "content": None, "version": 1}]),  # content not a string
    obs(200, [{"id": "d", "content": "c", "version": "1"}]),  # version not an integer
    obs(200, [{"id": "d", "content": "c", "version": 1.0}]),
    obs(200, [{"id": "d", "content": "c", "version": None}]),
]


# -- parse_snapshot ---------------------------------------------------------


@pytest.mark.parametrize("probe", UNUSABLE)
def test_unusable_probe_parses_to_none(probe):
    assert parse_snapshot(probe) is None


def test_empty_listing_is_an_empty_snapshot_not_unusable():
    assert parse_snapshot(obs(200, [])) == {}


def test_listing_is_reduced_to_content_and_version_by_id():
    other = {"id": "doc_9", "content": "", "version": 4}
    assert parse_snapshot(obs(200, [DOC, other])) == {
        "doc_6": ("secret <<INV:3>>", 1),
        "doc_9": ("", 4),
    }


def test_fields_the_model_does_not_predict_are_ignored():
    item = {**DOC, "org_id": "org_1", "updated_at": "now"}
    assert parse_snapshot(obs(200, [item])) == {"doc_6": ("secret <<INV:3>>", 1)}


def test_a_repeated_id_keeps_the_last_entry():
    # Current behaviour: duplicates are not rejected.
    later = {**DOC, "content": "later", "version": 2}
    assert parse_snapshot(obs(200, [DOC, later])) == {"doc_6": ("later", 2)}


def test_a_boolean_version_is_accepted_as_an_integer():
    # Current behaviour: the check is isinstance(version, int), and bool is an int.
    snapshot = parse_snapshot(obs(200, [{"id": "d", "content": "c", "version": True}]))
    assert snapshot == {"d": ("c", True)}


# -- diff_snapshots ---------------------------------------------------------


def test_equal_snapshots_have_no_differences():
    assert diff_snapshots({}, {}) == []
    assert diff_snapshots({"a": ("x", 1)}, {"a": ("x", 1)}) == []


def test_each_kind_of_difference_has_its_exact_wording():
    assert diff_snapshots({"a": ("x", 1)}, {}) == ["a expected but missing"]
    assert diff_snapshots({}, {"a": ("x", 1)}) == ["a present but not expected"]
    assert diff_snapshots({"a": ("x", 1)}, {"a": ("y", 1)}) == [
        "a expected (content='x', version=1) observed (content='y', version=1)"
    ]
    assert diff_snapshots({"a": ("x", 1)}, {"a": ("x", 2)}) == [
        "a expected (content='x', version=1) observed (content='x', version=2)"
    ]


def test_content_is_shown_with_repr_so_quotes_and_whitespace_are_visible():
    assert diff_snapshots({"a": ("it's", 1)}, {"a": ("x \n", 1)}) == [
        "a expected (content=\"it's\", version=1) observed (content='x \\n', version=1)"
    ]


def test_differences_are_grouped_missing_then_unexpected_then_changed_each_sorted_by_id():
    expected = {"m2": ("x", 1), "c2": ("x", 1), "m1": ("x", 1), "c1": ("x", 1), "same": ("x", 1)}
    observed = {"u2": ("x", 1), "c1": ("y", 1), "same": ("x", 1), "u1": ("x", 1), "c2": ("x", 3)}
    assert diff_snapshots(expected, observed) == [
        "m1 expected but missing",
        "m2 expected but missing",
        "u1 present but not expected",
        "u2 present but not expected",
        "c1 expected (content='x', version=1) observed (content='y', version=1)",
        "c2 expected (content='x', version=1) observed (content='x', version=3)",
    ]


def test_diff_does_not_modify_its_arguments():
    expected, observed = {"a": ("x", 1)}, {"b": ("y", 2)}
    diff_snapshots(expected, observed)
    assert (expected, observed) == ({"a": ("x", 1)}, {"b": ("y", 2)})


# -- Evaluator.snapshot_diff stays a thin, compatible wrapper ----------------

EXPECTED = {"doc_6": ("secret <<INV:3>>", 1)}


@pytest.mark.parametrize("probe", UNUSABLE)
def test_snapshot_diff_returns_none_for_an_unusable_probe(probe):
    assert Evaluator().snapshot_diff(probe, EXPECTED) is None


@pytest.mark.parametrize(
    "probe",
    [
        obs(200, [DOC]),  # equal -> []
        obs(200, []),  # missing
        obs(200, [DOC, {"id": "doc_7", "content": "x", "version": 1}]),  # unexpected
        obs(200, [{**DOC, "content": "evil", "version": 2}]),  # changed
    ],
)
def test_snapshot_diff_is_parse_then_diff(probe):
    observed = parse_snapshot(probe)
    assert observed is not None
    result = Evaluator().snapshot_diff(probe, EXPECTED)
    assert result == diff_snapshots(EXPECTED, observed)
    assert isinstance(result, list)


def test_snapshot_diff_distinguishes_no_difference_from_unusable():
    evaluator = Evaluator()
    assert evaluator.snapshot_diff(obs(200, [DOC]), EXPECTED) == []
    assert evaluator.snapshot_diff(obs(200, "not json"), EXPECTED) is None


def test_the_private_helpers_are_gone():
    assert not hasattr(Evaluator, "_parse_snapshot")
    assert not hasattr(Evaluator, "_diff")
