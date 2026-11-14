import pytest
from meridian.app import create_app
from meridian.flags import ALL_FLAGS, flags_from_env


def test_flags_default_to_the_build_deployed_to_staging():
    assert flags_from_env({}) == ALL_FLAGS
    assert flags_from_env({"MERIDIAN_FLAGS": "ALL"}) == ALL_FLAGS


def test_none_selects_the_stable_paths():
    assert flags_from_env({"MERIDIAN_FLAGS": "none"}) == frozenset()


def test_a_list_selects_exactly_those_flags():
    assert flags_from_env({"MERIDIAN_FLAGS": " bulk-render, undo-toast "}) == {"bulk-render", "undo-toast"}


def test_unknown_flags_are_refused():
    with pytest.raises(ValueError, match="unknown flags"):
        flags_from_env({"MERIDIAN_FLAGS": "bulk-render,nope"})
    with pytest.raises(ValueError, match="unknown flags"):
        create_app(frozenset({"nope"}))
