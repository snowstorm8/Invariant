"""The operating system's own folder chooser (Finder, File Explorer, a desktop's file dialog).

A web page cannot hand a server the path of a folder, but the console runs on the developer's own
machine, so the console server opens the real dialog and reports what was chosen. Where no dialog
is available the console falls back to a path field.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

PROMPT = "Choose the folder of the application to test"
#: A person choosing a folder can take a while.
TIMEOUT = 600


@dataclass(frozen=True)
class Choice:
    #: What the person picked; None when they cancelled.
    """Outcome of a folder dialog: a path, or a cancellation."""
    path: Path | None
    #: False when this machine has no folder dialog to open (use the path field).
    supported: bool = True
    error: str = ""


def available() -> bool:
    """True if this machine has a native folder chooser the console can open."""
    return _command(None) is not None


def _applescript_quote(text: str) -> str:
    return text.replace("\\", "\\\\").replace('"', '\\"')


def _command(start: Path | None) -> list[str] | None:
    if sys.platform == "darwin" and shutil.which("osascript"):
        where = f' default location (POSIX file "{_applescript_quote(str(start))}")' if start else ""
        return [
            "osascript",
            "-e", 'tell application "Finder" to activate',
            "-e", f'POSIX path of (choose folder with prompt "{PROMPT}"{where})',
        ]  # fmt: skip
    if sys.platform == "win32":
        start_line = f"$d.SelectedPath = '{str(start).replace(chr(39), chr(39) * 2)}';" if start else ""
        script = (
            "Add-Type -AssemblyName System.Windows.Forms;"
            "$d = New-Object System.Windows.Forms.FolderBrowserDialog;"
            f"$d.Description = '{PROMPT}'; {start_line}"
            "$f = New-Object System.Windows.Forms.Form; $f.TopMost = $true;"
            "if ($d.ShowDialog($f) -eq 'OK') { Write-Output $d.SelectedPath }"
        )
        return ["powershell", "-NoProfile", "-STA", "-Command", script]
    if shutil.which("zenity"):
        argv = ["zenity", "--file-selection", "--directory", f"--title={PROMPT}"]
        return argv + ([f"--filename={start}/"] if start else [])
    if shutil.which("kdialog"):
        return ["kdialog", "--getexistingdirectory", str(start or Path.home()), "--title", PROMPT]
    return None


def choose_folder(start: Path | None = None) -> Choice:
    """Open the system folder dialog and wait for the person's answer."""
    argv = _command(start if start is not None and start.is_dir() else None)
    if argv is None:
        return Choice(None, supported=False)
    try:
        done = subprocess.run(
            argv, capture_output=True, text=True, timeout=TIMEOUT, check=False
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return Choice(None, error=f"the folder dialog could not be shown: {exc}")
    chosen = done.stdout.strip()
    if done.returncode != 0 or not chosen:
        # macOS reports a cancelled dialog as error -128 on stderr; other platforms print nothing.
        if done.returncode != 0 and "-128" not in done.stderr and done.stderr.strip():
            return Choice(None, error=done.stderr.strip().splitlines()[-1])
        return Choice(None)
    return Choice(Path(chosen))
