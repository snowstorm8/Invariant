"""Projects: an application in a folder that Invariant can start and test.

A project folder holds an ``invariant.toml`` that says how to run the application and how to
reset it between tests. Invariant starts it as a local process on a free loopback port, tests it
over real HTTP and stops it afterwards::

    [project]
    name = "Meridian Docs"
    description = "..."

    [run]
    command = ["python", "server.py", "--port", "{port}"]   # "python" is this interpreter
    health = "/healthz"                                      # answers 200 when the app is ready
    start_timeout = 20                                       # seconds
    env = { SOME_SETTING = "value" }                         # optional

    [contract]
    integration = "document-saas"
    reset = "/_admin/reset"

Nothing is run until the person has seen the command and started the project. The application is
only ever contacted on 127.0.0.1.
"""

from __future__ import annotations

import contextlib
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import tomllib
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx

from invariant.adapters.base import Adapter
from invariant.adapters.http import HttpAdapter
from invariant.integrations.document_saas import DOCUMENT_SAAS

from .target import ConsoleTarget

MANIFEST_NAME = "invariant.toml"
INTEGRATIONS = {"document-saas": DOCUMENT_SAAS}
MAX_TIMEOUT = 120.0


class ProjectError(ValueError):
    """The folder is not a usable project, or the application would not start."""


@dataclass(frozen=True)
class Manifest:
    folder: Path
    name: str
    description: str
    command: tuple[str, ...]
    health: str
    start_timeout: float
    reset: str
    integration: str
    env: Mapping[str, str] = field(default_factory=dict)

    def argv(self, port: int) -> list[str]:
        """The command to run, with ``{port}`` filled in and ``python`` meaning this interpreter."""
        argv = [part.replace("{port}", str(port)) for part in self.command]
        if argv[0] in ("python", "python3"):
            argv[0] = sys.executable
        return argv

    def describe(self) -> dict[str, Any]:
        return {
            "folder": str(self.folder),
            "name": self.name,
            "description": self.description,
            "command": " ".join(self.command),
            "health": self.health,
            "reset": self.reset,
            "integration": self.integration,
            "env": dict(self.env),
        }


def _table(data: Mapping[str, Any], key: str) -> Mapping[str, Any]:
    value = data.get(key, {})
    if not isinstance(value, dict):
        raise ProjectError(f"[{key}] in {MANIFEST_NAME} must be a table")
    return value


def _path(value: object, where: str) -> str:
    if not isinstance(value, str) or not value.startswith("/") or any(c.isspace() for c in value):
        raise ProjectError(f"{where} must be a path starting with '/', for example \"/healthz\"")
    return value


def load_manifest(folder: Path | str) -> Manifest:
    """Read and validate ``invariant.toml`` in ``folder``. Runs nothing."""
    root = Path(folder).expanduser()
    if not root.is_dir():
        raise ProjectError(f"{root} is not a folder")
    root = root.resolve()
    file = root / MANIFEST_NAME
    if not file.is_file():
        raise ProjectError(
            f"{root.name or str(root)} has no {MANIFEST_NAME}. "
            "Choose the folder of an application that has one (see docs/projects.md)."
        )
    try:
        data = tomllib.loads(file.read_text("utf-8"))
    except (tomllib.TOMLDecodeError, UnicodeDecodeError) as exc:
        raise ProjectError(f"{MANIFEST_NAME} could not be read: {exc}") from exc

    project, run, contract = _table(data, "project"), _table(data, "run"), _table(data, "contract")
    command = run.get("command")
    if (
        not isinstance(command, list)
        or not command
        or not all(isinstance(part, str) and part for part in command)
    ):
        raise ProjectError('[run] command must be a list of strings, for example ["python", "server.py"]')
    if not any("{port}" in part for part in command):
        raise ProjectError('[run] command must pass the port to the application as "{port}"')
    timeout = run.get("start_timeout", 20)
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not 1 <= timeout <= MAX_TIMEOUT:
        raise ProjectError(f"[run] start_timeout must be between 1 and {MAX_TIMEOUT:g} seconds")
    env = run.get("env", {})
    if not isinstance(env, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in env.items()):
        raise ProjectError("[run] env must be a table of strings")
    integration = contract.get("integration", "document-saas")
    if integration not in INTEGRATIONS:
        raise ProjectError(
            f"[contract] integration '{integration}' is not supported; use one of: "
            + ", ".join(sorted(INTEGRATIONS))
        )
    name = project.get("name", root.name)
    description = project.get("description", "")
    if not isinstance(name, str) or not isinstance(description, str):
        raise ProjectError("[project] name and description must be strings")
    return Manifest(
        folder=root,
        name=name or root.name,
        description=description,
        command=tuple(command),
        health=_path(run.get("health", "/"), "[run] health"),
        start_timeout=float(timeout),
        reset=_path(contract.get("reset", "/_admin/reset"), "[contract] reset"),
        integration=integration,
        env=dict(env),
    )


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port: int = sock.getsockname()[1]
    return port


#: What the application is given of this process's environment.
_INHERITED = ("PATH", "HOME", "LANG", "LC_ALL", "TMPDIR", "SYSTEMROOT", "TEMP", "TMP", "VIRTUAL_ENV")


class _SharedAdapter(HttpAdapter):
    """An adapter over the project's one running process; closing it leaves the process up."""

    def close(self) -> None:
        pass


class RunningProject:
    """The application of a project, running as a local process."""

    def __init__(self, manifest: Manifest) -> None:
        self.manifest = manifest
        self.port = 0
        self._process: subprocess.Popen[bytes] | None = None
        self._client: httpx.Client | None = None
        self._log = tempfile.TemporaryFile()  # noqa: SIM115 - lives as long as the process
        self._lock = threading.RLock()

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    @property
    def running(self) -> bool:
        return self._process is not None and self._process.poll() is None

    def log_tail(self, limit: int = 2000) -> str:
        self._log.flush()
        self._log.seek(0)
        text = self._log.read().decode("utf-8", "replace")
        return text[-limit:]

    def start(self) -> None:
        with self._lock:
            if self.running:
                return
            self.port = _free_port()
            env = {k: os.environ[k] for k in _INHERITED if k in os.environ}
            env["PYTHONUNBUFFERED"] = "1"
            env.update(self.manifest.env)
            argv = self.manifest.argv(self.port)
            try:
                self._process = subprocess.Popen(  # noqa: S603 - the person confirmed this command
                    argv,
                    cwd=self.manifest.folder,
                    env=env,
                    stdin=subprocess.DEVNULL,
                    stdout=self._log,
                    stderr=subprocess.STDOUT,
                )
            except OSError as exc:
                raise ProjectError(f"could not start {argv[0]!r}: {exc}") from exc
            # Connections are reused (a connection per request exhausts the machine's
            # ephemeral ports over a long exploration).
            self._client = httpx.Client(
                base_url=self.url,
                timeout=10.0,
                trust_env=False,
                follow_redirects=False,
                limits=httpx.Limits(keepalive_expiry=5.0),
            )
            try:
                self._wait_until_ready()
            except ProjectError:
                self.stop()
                raise

    def _wait_until_ready(self) -> None:
        assert self._client is not None and self._process is not None
        deadline = time.monotonic() + self.manifest.start_timeout
        while time.monotonic() < deadline:
            code = self._process.poll()
            if code is not None:
                raise ProjectError(
                    f"the application exited with status {code} before it was ready.\n"
                    + self.log_tail()
                )
            with contextlib.suppress(httpx.HTTPError):
                if self._client.get(self.manifest.health).status_code == 200:
                    return
            time.sleep(0.1)
        raise ProjectError(
            f"the application did not answer {self.manifest.health} within "
            f"{self.manifest.start_timeout:g} seconds.\n" + self.log_tail()
        )

    def stop(self) -> None:
        with self._lock:
            if self._client is not None:
                self._client.close()
                self._client = None
            process, self._process = self._process, None
            if process is not None and process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)

    def adapter(self) -> Adapter:
        if not self.running or self._client is None:
            raise ProjectError("the application is not running; open the project again")
        return _SharedAdapter(self._client, reset_path=self.manifest.reset)

    def state(self) -> dict[str, Any]:
        return {
            **self.manifest.describe(),
            "running": self.running,
            "url": self.url if self.running else "",
            "log": self.log_tail(1200),
        }

    def console_target(self) -> ConsoleTarget:
        return ConsoleTarget(
            name=self.manifest.name,
            description=self.manifest.description,
            adapter_for=lambda _options: self.adapter(),
            binding=INTEGRATIONS[self.manifest.integration],
            close=self.stop,
        )
