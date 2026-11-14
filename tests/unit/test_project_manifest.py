"""invariant.toml: what makes a folder a project, and what the console shows before running it."""

import sys

import pytest

from invariant.console.project import MANIFEST_NAME, ProjectError, load_manifest

VALID = """
[project]
name = "Acme"
description = "Docs"

[run]
command = ["python", "app.py", "--port", "{port}"]
health = "/up"
start_timeout = 5
env = { MODE = "demo" }

[contract]
integration = "document-saas"
reset = "/reset"
"""


def write(tmp_path, text):
    (tmp_path / MANIFEST_NAME).write_text(text)
    return tmp_path


def test_a_valid_manifest_is_read_without_running_anything(tmp_path):
    m = load_manifest(write(tmp_path, VALID))
    assert (m.name, m.description, m.health, m.reset, m.start_timeout) == ("Acme", "Docs", "/up", "/reset", 5.0)
    assert m.env == {"MODE": "demo"} and m.folder == tmp_path.resolve()


def test_port_is_filled_in_and_python_means_this_interpreter(tmp_path):
    argv = load_manifest(write(tmp_path, VALID)).argv(4321)
    assert argv == [sys.executable, "app.py", "--port", "4321"]


def test_describe_shows_the_command_unexpanded(tmp_path):
    shown = load_manifest(write(tmp_path, VALID)).describe()
    assert shown["command"] == "python app.py --port {port}" and shown["integration"] == "document-saas"


def test_defaults(tmp_path):
    m = load_manifest(write(tmp_path, '[run]\ncommand = ["node", "s.js", "{port}"]\n'))
    assert (m.name, m.health, m.reset, m.integration, m.start_timeout) == (
        tmp_path.name, "/", "/_admin/reset", "document-saas", 20.0)  # fmt: skip
    assert m.argv(1)[0] == "node"


def test_not_a_folder(tmp_path):
    with pytest.raises(ProjectError, match="is not a folder"):
        load_manifest(tmp_path / "missing")


def test_a_folder_without_a_manifest_says_so(tmp_path):
    with pytest.raises(ProjectError, match="has no invariant.toml"):
        load_manifest(tmp_path)


def test_unreadable_toml(tmp_path):
    with pytest.raises(ProjectError, match="could not be read"):
        load_manifest(write(tmp_path, "[run\n"))


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("[run]\n", "command must be a list"),
        ('[run]\ncommand = "python app.py"\n', "command must be a list"),
        ('[run]\ncommand = []\n', "command must be a list"),
        ('[run]\ncommand = ["a", 1]\n', "command must be a list"),
        ('[run]\ncommand = ["python", "app.py"]\n', "must pass the port"),
        ('[run]\ncommand = ["a", "{port}"]\nstart_timeout = 0\n', "start_timeout"),
        ('[run]\ncommand = ["a", "{port}"]\nstart_timeout = 500\n', "start_timeout"),
        ('[run]\ncommand = ["a", "{port}"]\nstart_timeout = true\n', "start_timeout"),
        ('[run]\ncommand = ["a", "{port}"]\nenv = { A = 1 }\n', "env must be a table of strings"),
        ('[run]\ncommand = ["a", "{port}"]\nhealth = "healthz"\n', "must be a path"),
        ('[run]\ncommand = ["a", "{port}"]\nhealth = "/a b"\n', "must be a path"),
        ('[run]\ncommand = ["a", "{port}"]\n[contract]\nintegration = "graphql"\n', "not supported"),
        ('[run]\ncommand = ["a", "{port}"]\n[contract]\nreset = "reset"\n', "must be a path"),
        ('run = 1\n', "must be a table"),
        ('[project]\nname = 3\n[run]\ncommand = ["a", "{port}"]\n', "must be strings"),
    ],
)
def test_invalid_manifests_are_rejected_with_a_reason(tmp_path, text, message):
    with pytest.raises(ProjectError, match=message):
        load_manifest(write(tmp_path, text))
