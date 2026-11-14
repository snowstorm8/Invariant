"""The native folder dialog: what the console does with each way it can end."""

import subprocess
from pathlib import Path

from invariant.console import dialogs


def fake_run(monkeypatch, *, code=0, out="", err="", raises=None):
    monkeypatch.setattr(dialogs, "_command", lambda start: ["dialog"])

    def run(argv, **kwargs):
        if raises:
            raise raises
        return subprocess.CompletedProcess(argv, code, out, err)

    monkeypatch.setattr(dialogs.subprocess, "run", run)


def test_the_chosen_folder_is_returned(monkeypatch):
    fake_run(monkeypatch, out="/work/app/\n")
    choice = dialogs.choose_folder()
    assert choice.path == Path("/work/app") and choice.supported and not choice.error


def test_cancelling_is_not_an_error(monkeypatch):
    fake_run(monkeypatch, code=1, err="execution error: User canceled. (-128)")
    choice = dialogs.choose_folder()
    assert choice.path is None and choice.supported and not choice.error
    fake_run(monkeypatch, code=1)  # zenity/kdialog/powershell: nothing printed
    assert dialogs.choose_folder().path is None


def test_a_failing_dialog_reports_why(monkeypatch):
    fake_run(monkeypatch, code=1, err="boom\nno display available")
    assert dialogs.choose_folder().error == "no display available"
    fake_run(monkeypatch, raises=OSError("gone"))
    assert "could not be shown" in dialogs.choose_folder().error


def test_without_a_dialog_the_console_falls_back_to_the_path_field(monkeypatch):
    monkeypatch.setattr(dialogs, "_command", lambda start: None)
    choice = dialogs.choose_folder()
    assert not choice.supported and choice.path is None
    assert dialogs.available() is False


def test_the_dialog_opens_in_the_start_folder(monkeypatch, tmp_path):
    seen = []
    monkeypatch.setattr(dialogs, "_command", lambda start: seen.append(start) or None)
    dialogs.choose_folder(tmp_path)
    dialogs.choose_folder(tmp_path / "missing")
    assert seen == [tmp_path, None]


def test_the_macos_command_quotes_the_start_folder(monkeypatch):
    monkeypatch.setattr(dialogs.sys, "platform", "darwin")
    monkeypatch.setattr(dialogs.shutil, "which", lambda name: "/usr/bin/osascript")
    argv = dialogs._command(Path('/tmp/a "b"'))
    assert argv[0] == "osascript" and 'default location (POSIX file "/tmp/a \\"b\\"")' in argv[-1]
