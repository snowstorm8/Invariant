"""The console with the default rule library: groups, bulk switching, ids and settings."""

import json

import pytest
from vulnerable_saas.target import DEFECTS, console_target

from invariant.console.app import ConsoleApp, ConsoleError
from invariant.console.store import RuleStore
from invariant.evaluation.violations import Outcome
from invariant.rules import ids as rule_ids

SIMPLE = '''# keep this comment
rule "no-teapots" {
    description "A read must never answer 418."
    severity low
    when operation.type == "read_document"
    never response.status == 418
}
'''
EXPLICIT = SIMPLE.replace('rule "no-teapots" {', 'rule "no-teapots" {\n    id "MY-ID"')


@pytest.fixture
def app(tmp_path):
    return ConsoleApp(console_target(), RuleStore(tmp_path / "rules.json"))


def builtin(app):
    return [r for r in app.list_rules() if r["origin"] == "builtin"]


def mine(app):
    return [r for r in app.list_rules() if r["origin"] != "builtin"]


# -- the library is on by default, grouped by tag ---------------------------------


def test_the_core_rules_and_the_library_are_all_listed_and_on(app):
    rules = builtin(app)
    assert len(rules) == 29
    assert [r["id"] for r in rules[:3]] == ["TI-1", "TI-2", "AZ-1"]  # attribution order
    assert all(r["enabled"] and r["valid"] and not r["editable"] for r in rules)
    assert all(r["tags"] for r in rules)
    assert {r["tags"][0] for r in rules} == {"access-control", "data-exposure", "headers", "integrity"}
    assert len({r["key"] for r in rules}) == 29
    json.dumps(app.bootstrap())


def test_the_active_rule_set_is_everything_enabled(app):
    assert [r.id for r in app.active_ruleset().rules] == [r["id"] for r in app.list_rules()]


# -- switching many rules at once --------------------------------------------------


def test_switch_a_whole_group_off_and_back_on_in_one_request(app):
    headers = [r["key"] for r in builtin(app) if r["tags"][0] == "headers"]
    assert len(headers) == 11
    out = app.set_enabled_many({"keys": headers, "enabled": False})
    assert sum(1 for r in out["rules"] if r["enabled"]) == 29 - 11
    assert len(app.active_ruleset().rules) == 18
    app.set_enabled_many({"keys": headers, "enabled": True})
    assert all(r["enabled"] for r in app.list_rules())


def test_bulk_switching_covers_your_own_rules_too(app):
    app.save_rule({"source": SIMPLE})
    keys = [r["key"] for r in app.list_rules()]
    app.set_enabled_many({"keys": keys, "enabled": False})
    assert not any(r["enabled"] for r in app.list_rules())
    with pytest.raises(ConsoleError, match="no rule is enabled"):
        app.active_ruleset()


def test_a_bad_key_changes_nothing(app):
    keys = [builtin(app)[0]["key"], "builtin:NOPE"]
    with pytest.raises(ConsoleError, match="no built-in rule 'NOPE'"):
        app.set_enabled_many({"keys": keys, "enabled": False})
    assert all(r["enabled"] for r in app.list_rules())
    with pytest.raises(KeyError):
        app.set_enabled_many({"keys": ["r999"], "enabled": False})
    assert all(r["enabled"] for r in app.list_rules())


@pytest.mark.parametrize(
    "request_",
    [{}, {"keys": "x", "enabled": True}, {"keys": [1], "enabled": True}, {"keys": [], "enabled": "yes"}],
)
def test_bulk_switching_rejects_malformed_requests(app, request_):
    with pytest.raises(ConsoleError, match="expected"):
        app.set_enabled_many(request_)


def test_bulk_switches_survive_a_restart(tmp_path):
    path = tmp_path / "rules.json"
    first = ConsoleApp(console_target(), RuleStore(path))
    keys = [r["key"] for r in builtin(first) if r["tags"][0] == "integrity"]
    first.set_enabled_many({"keys": keys, "enabled": False})
    second = ConsoleApp(console_target(), RuleStore(path))
    assert {r["key"] for r in second.list_rules() if not r["enabled"]} == set(keys)


# -- a rule written without an id gets one from its name ----------------------------


def test_a_new_rule_without_an_id_gets_the_chosen_algorithms_id(app):
    out = app.save_rule({"source": SIMPLE})
    (rule,) = [r for r in out["rules"] if r["origin"] != "builtin"]
    assert rule["id"] == rule_ids.candidate("initials", "no-teapots") == "NT-09"
    assert 'id "NT-09"' in rule["source"]
    assert "# keep this comment" in rule["source"]  # the text was edited, not reprinted
    assert rule["valid"]


def test_an_explicit_id_is_kept(app):
    app.save_rule({"source": EXPLICIT})
    assert mine(app)[0]["id"] == "MY-ID"


def test_validate_says_what_id_will_be_assigned_and_saves_nothing(app):
    check = app.validate({"source": SIMPLE})
    assert check["ok"] and check["assigned_ids"] == {"no-teapots": "NT-09"}
    assert app.validate({"source": EXPLICIT})["assigned_ids"] == {}
    assert mine(app) == []


def test_ids_are_unique_when_names_collide(app):
    first = app.save_rule({"source": SIMPLE})["saved"][0]
    second = app.save_rule({"source": SIMPLE.replace("no-teapots", "no-teapots")})["saved"][0]
    ids = [r["id"] for r in mine(app)]
    assert len(set(ids)) == 2 and all(rule_ids.ID_PATTERN.fullmatch(i) for i in ids)
    assert first != second


def test_a_source_with_several_rules_gets_an_id_for_each(app):
    both = SIMPLE + SIMPLE.replace("no-teapots", "no-kettles")
    app.save_rule({"source": both})
    assert sorted(r["name"] for r in mine(app)) == ["no-kettles", "no-teapots"]
    assert all(rule_ids.ID_PATTERN.fullmatch(r["id"]) for r in mine(app))
    assert len({r["id"] for r in mine(app)}) == 2


def test_a_draft_that_does_not_validate_is_saved_untouched(app):
    broken = 'rule "half-written" { never response.status =='
    app.save_rule({"source": broken})
    (draft,) = mine(app)
    assert draft["source"] == broken and not draft["valid"]


def test_editing_a_rule_does_not_change_its_id(app):
    key = app.save_rule({"source": SIMPLE})["saved"][0]
    source = mine(app)[0]["source"].replace("418", "419")
    app.save_rule({"source": source, "key": key})
    assert mine(app)[0]["id"] == "NT-09" and "419" in mine(app)[0]["source"]


def test_the_algorithm_in_force_decides(app):
    app.save_settings({"id_algorithm": "crc32"})
    app.save_rule({"source": SIMPLE})
    assert mine(app)[0]["id"] == rule_ids.candidate("crc32", "no-teapots")


# -- settings: choose an algorithm, every rule follows ------------------------------


def test_settings_list_the_five_algorithms_and_the_current_choice(app):
    settings = app.bootstrap()["settings"]
    assert settings["id_algorithm"] == settings["default_id_algorithm"] == "initials"
    assert [a["id"] for a in settings["id_algorithms"]] == list(rule_ids.ALGORITHMS)


def test_preview_changes_nothing_and_matches_what_saving_does(app):
    app.save_rule({"source": SIMPLE})
    before = app.list_rules()
    preview = app.preview_settings({"id_algorithm": "sha256"})
    assert app.list_rules() == before
    assert app.get_settings()["id_algorithm"] == "initials"
    saved = app.save_settings({"id_algorithm": "sha256"})
    assert saved["changed"] == preview["changes"]
    assert len(preview["changes"]) + preview["unchanged"] == 30


@pytest.mark.parametrize("algorithm", list(rule_ids.ALGORITHMS))
def test_saving_an_algorithm_renames_every_rule_built_in_ones_included(app, algorithm):
    app.save_rule({"source": EXPLICIT})
    app.save_settings({"id_algorithm": algorithm})
    rules = app.list_rules()
    assert all(rule_ids.ID_PATTERN.fullmatch(r["id"]) for r in rules)
    assert len({r["id"] for r in rules}) == len(rules) == 30
    expected = rule_ids.assign_all(
        algorithm, [(r["key"], r["name"], r["id"]) for r in rules]
    )
    assert {r["key"]: r["id"] for r in rules} == expected
    assert app.get_settings()["id_algorithm"] == algorithm
    # ... in the source the editor shows, too.
    for rule in rules:
        assert f'"{rule["id"]}"' in rule["source"] or rule["origin"] == "builtin"


def test_renaming_keeps_keys_policy_keys_and_switches(app):
    app.set_enabled({"key": "builtin:TI-2", "enabled": False})
    app.save_settings({"id_algorithm": "initials"})
    ti2 = next(r for r in builtin(app) if r["key"] == "builtin:TI-2")
    assert ti2["id"] == "TW-20" and ti2["shipped_id"] == "TI-2"
    assert ti2["policy"] == "TI-2" and not ti2["enabled"]
    assert 'policy "TI-2"' in ti2["source"] and 'id "TW-20"' in ti2["source"]
    # Every renamed built-in remembers the id it shipped with as its policy key.
    cross = next(r for r in builtin(app) if r["key"] == "builtin:AC-1")
    assert cross["policy"] == "AC-1" and cross["id"] != "AC-1"


def test_applying_the_same_algorithm_again_changes_nothing(app):
    app.save_settings({"id_algorithm": "edges"})
    before = [(r["key"], r["id"], r["source"]) for r in app.list_rules()]
    again = app.save_settings({"id_algorithm": "edges"})
    assert again["changed"] == []
    assert [(r["key"], r["id"], r["source"]) for r in again["rules"]] == before


def test_switching_algorithm_back_restores_the_shipped_ids(app):
    # The shipped ids are not AA-11, so there is no way back to them through an
    # algorithm; what must hold is that the chosen ids are stable and distinct.
    app.save_settings({"id_algorithm": "crc32"})
    first = {r["key"]: r["id"] for r in app.list_rules()}
    app.save_settings({"id_algorithm": "initials"})
    app.save_settings({"id_algorithm": "crc32"})
    assert {r["key"]: r["id"] for r in app.list_rules()} == first


def test_your_rules_are_rewritten_comments_and_all_but_drafts_are_left_alone(app):
    app.save_rule({"source": SIMPLE})
    app.save_rule({"source": 'rule "half" { never response.status =='})
    app.save_settings({"id_algorithm": "crc32"})
    valid = next(r for r in mine(app) if r["valid"])
    assert valid["id"] == rule_ids.candidate("crc32", "no-teapots")
    assert "# keep this comment" in valid["source"]
    draft = next(r for r in mine(app) if not r["valid"])
    assert draft["source"] == 'rule "half" { never response.status =='


def test_unknown_algorithms_and_bad_requests_are_refused_without_changes(app):
    before = app.list_rules()
    for call in (app.save_settings, app.preview_settings):
        with pytest.raises(ConsoleError, match="unknown id algorithm 'rot13'"):
            call({"id_algorithm": "rot13"})
        with pytest.raises(ConsoleError, match="must be a string"):
            call({"id_algorithm": 5})
        with pytest.raises(ConsoleError, match="must be a string"):
            call({})
    assert app.list_rules() == before and app.get_settings()["id_algorithm"] == "initials"


def test_the_choice_and_the_renamed_built_ins_survive_a_restart(tmp_path):
    path = tmp_path / "rules.json"
    first = ConsoleApp(console_target(), RuleStore(path))
    first.save_rule({"source": SIMPLE})
    first.save_settings({"id_algorithm": "sha256"})
    second = ConsoleApp(console_target(), RuleStore(path))
    assert second.get_settings()["id_algorithm"] == "sha256"
    assert [(r["key"], r["id"]) for r in second.list_rules()] == [
        (r["key"], r["id"]) for r in first.list_rules()
    ]


def test_an_import_may_not_reuse_a_built_in_rules_new_id(app):
    app.save_settings({"id_algorithm": "initials"})
    clash = {"version": 1, "rules": [{"name": "imposter", "id": "TR-19", "never": "response.status == 1"}]}
    with pytest.raises(ConsoleError, match="was not imported") as caught:
        app.import_json({"content": json.dumps(clash)})
    assert "belongs to a built-in rule" in caught.value.diagnostics[0]["message"]


# -- renamed rules still run and are attributed correctly ---------------------------


def test_a_renamed_policy_rule_still_judges_forbidden_writes(app):
    app.save_settings({"id_algorithm": "sha256"})
    shown = {r["shipped_id"]: r["id"] for r in builtin(app) if "shipped_id" in r}
    out = app.scan({"options": ["update-missing-tenant-check"], "seed": 1, "max_examples": 60})
    ids = {f["property_id"] for f in out["report"]["findings"]}
    assert shown["TI-2"] in ids
    assert "TI-2" not in ids  # reports speak the id the developer chose
    assert all(f["reproduced"] for f in out["report"]["findings"])
    replayed = app.replay({"options": ["update-missing-tenant-check"], "report": out["report"]})
    assert replayed["outcome"] == "VIOLATION"
    assert all(f["reproduced"] for f in replayed["findings"])
    fixed = app.replay({"options": [], "report": out["report"]})
    assert fixed["outcome"] == "PASS"


# -- the library against the demo builds --------------------------------------------


def test_the_fixed_build_passes_every_default_rule(app):
    out = app.scan({"options": [], "seed": 1, "max_examples": 60})
    assert out["report"]["outcome"] == Outcome.PASS and out["report"]["findings"] == []
    assert len(out["rules_used"]) == 29


@pytest.mark.parametrize("defect", sorted(DEFECTS))
def test_each_seeded_defect_is_caught_by_the_rule_it_is_labelled_with(app, defect):
    out = app.scan({"options": [defect], "seed": 1, "max_examples": 120})
    found = {f["property_id"] for f in out["report"]["findings"]}
    assert DEFECTS[defect]["property"] in found, (defect, found)
    assert all(f["reproduced"] for f in out["report"]["findings"])
