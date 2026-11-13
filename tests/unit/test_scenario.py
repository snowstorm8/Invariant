import pytest

from invariant.core.scenario import (
    CreateDocument,
    CreateOrg,
    CreateUser,
    ReadDocument,
    Role,
    Scenario,
    describe_op,
)


def test_scenario_json_roundtrip_preserves_operation_types():
    s = Scenario(
        operations=[
            CreateOrg(ref="org0", name="a"),
            CreateUser(ref="user0", org="org0", role=Role.VIEWER),
            CreateDocument(ref="doc0", actor="user0", content="c"),
            ReadDocument(actor="user0", doc="doc0"),
        ]
    )
    back = Scenario.model_validate_json(s.model_dump_json())
    assert back == s
    assert [type(o) for o in back.operations] == [type(o) for o in s.operations]


def test_unknown_kind_is_rejected():
    with pytest.raises(ValueError):
        Scenario.model_validate({"operations": [{"kind": "drop_tables"}]})


def test_describe_is_human_readable():
    s = Scenario(operations=[ReadDocument(actor="user1", doc="doc0")])
    assert s.describe() == ["0. user1 reads doc0"]
    with pytest.raises(TypeError):
        describe_op(object())
