"""Deterministic AA-11 rule ids."""

import itertools
import re
from pathlib import Path

import pytest

from invariant.rules import ids

NAMES = [
    "tenant-read-isolation",
    "viewer-write-is-rejected",
    "cookies-are-http-only",
    "read-returns-own-tenant",
    "x",
    "a-b",
    "123",
    "",
    "ünïcode-näme",
    "camelCaseRuleName",
]


def test_there_are_five_algorithms_and_a_default():
    assert len(ids.ALGORITHMS) == 5
    assert ids.DEFAULT_ALGORITHM in ids.ALGORITHMS
    assert {a["id"] for a in ids.describe()} == set(ids.ALGORITHMS)
    assert all(a["label"] and a["description"] and "->" in a["example"] for a in ids.describe())


@pytest.mark.parametrize("algorithm", list(ids.ALGORITHMS))
@pytest.mark.parametrize("name", NAMES)
def test_every_algorithm_gives_two_letters_a_dash_and_two_digits(algorithm, name):
    assert ids.ID_PATTERN.fullmatch(ids.candidate(algorithm, name))


@pytest.mark.parametrize("algorithm", list(ids.ALGORITHMS))
def test_the_same_name_always_gives_the_same_id(algorithm):
    for name in NAMES:
        assert ids.candidate(algorithm, name) == ids.candidate(algorithm, name)


def test_known_values_are_pinned():
    # A change here renames every user's rules, so it must be deliberate.
    assert ids.candidate("initials", "tenant-read-isolation") == "TR-19"
    assert ids.candidate("consonants", "tenant-read-isolation") == "TN-16"
    assert ids.candidate("edges", "tenant-read-isolation") == "TI-55"
    assert ids.candidate("crc32", "tenant-read-isolation") == "BS-94"
    assert ids.candidate("sha256", "tenant-read-isolation") == "LR-29"


def test_the_algorithms_are_genuinely_different():
    names = [n for n in NAMES if n]
    for first, second in itertools.combinations(ids.ALGORITHMS, 2):
        differing = sum(ids.candidate(first, n) != ids.candidate(second, n) for n in names)
        assert differing >= len(names) // 2, (first, second)


def test_separators_and_case_do_not_change_the_id():
    for algorithm in ids.ALGORITHMS:
        assert ids.candidate(algorithm, "tenant-read-isolation") == ids.candidate(
            algorithm, "Tenant Read_Isolation"
        )


def test_short_names_are_padded_not_rejected():
    assert ids.candidate("initials", "x").startswith("XX")
    assert ids.candidate("initials", "").startswith("XX")
    assert ids.candidate("edges", "a-b").startswith("AB")


@pytest.mark.parametrize("algorithm", list(ids.ALGORITHMS))
def test_a_taken_id_moves_to_the_next_free_one(algorithm):
    first = ids.candidate(algorithm, "tenant-read-isolation")
    second = ids.assign(algorithm, "tenant-read-isolation", {first})
    third = ids.assign(algorithm, "tenant-read-isolation", {first, second})
    assert len({first, second, third}) == 3
    assert all(ids.ID_PATTERN.fullmatch(i) for i in (second, third))
    assert ids.assign(algorithm, "tenant-read-isolation", set()) == first


def test_probing_wraps_through_digits_then_letters():
    assert ids.render(ids.SPACE - 1) == "ZZ-99"
    assert ids.render(ids.SPACE) == "AA-00"
    taken = {f"TR-{n:02d}" for n in range(100)}
    assert ids.assign("initials", "tenant-read-isolation", taken) == "TS-00"


def test_running_out_of_ids_is_an_error():
    everything = {ids.render(i) for i in range(ids.SPACE)}
    with pytest.raises(ValueError, match="every AA-11 id"):
        ids.assign("initials", "x", everything)


def test_unknown_algorithm_names_the_choices():
    with pytest.raises(ValueError, match="unknown id algorithm 'nope'.*initials"):
        ids.candidate("nope", "x")


RULES = [
    ("k1", "tenant-read-isolation", "TI-1"),
    ("k2", "tenant-write-isolation", "TI-2"),
    ("k3", "role-write-permission", "AZ-1"),
    ("k4", "tenant-read-isolation", "mine"),  # same name as k1
]


@pytest.mark.parametrize("algorithm", list(ids.ALGORITHMS))
def test_assign_all_gives_every_rule_a_distinct_valid_id(algorithm):
    result = ids.assign_all(algorithm, RULES)
    assert set(result) == {"k1", "k2", "k3", "k4"}
    assert len(set(result.values())) == 4
    assert all(ids.ID_PATTERN.fullmatch(i) for i in result.values())


@pytest.mark.parametrize("algorithm", list(ids.ALGORITHMS))
def test_assign_all_does_not_depend_on_the_order_given(algorithm):
    forward = ids.assign_all(algorithm, RULES)
    assert ids.assign_all(algorithm, list(reversed(RULES))) == forward
    assert ids.assign_all(algorithm, RULES[2:] + RULES[:2]) == forward


@pytest.mark.parametrize("algorithm", list(ids.ALGORITHMS))
def test_applying_the_same_algorithm_twice_changes_nothing(algorithm):
    once = ids.assign_all(algorithm, RULES)
    again = ids.assign_all(algorithm, [(k, n, once[k]) for k, n, _ in RULES])
    assert again == once


def test_a_rule_that_already_has_its_candidate_keeps_it_over_a_namesake():
    wanted = ids.candidate("initials", "tenant-read-isolation")
    result = ids.assign_all(
        "initials",
        [("a", "tenant-read-isolation", "zz"), ("b", "tenant-read-isolation", wanted)],
    )
    assert result["b"] == wanted and result["a"] != wanted


def test_reserved_ids_are_never_handed_out():
    wanted = ids.candidate("initials", "tenant-read-isolation")
    result = ids.assign_all("initials", [("a", "tenant-read-isolation", "x")], reserved={wanted})
    assert result["a"] != wanted


def test_the_module_stands_alone():
    source = Path(ids.__file__).read_text(encoding="utf-8")
    imports = re.findall(r"^(?:from|import) (\S+)", source, re.MULTILINE)
    assert not [i for i in imports if i.startswith("invariant")], imports
