"""Local HTTP server for the Invariant console.

Serves one page (``console.html``) and a small JSON API backed by
:class:`~invariant.console.app.ConsoleApp`. Standard library only.

The server is for a developer's own machine. It binds to loopback by default,
answers only requests addressed to a loopback host name (so a web page cannot
reach it through DNS rebinding), and accepts state-changing requests only as
same-origin JSON.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import resources
from typing import Any
from urllib.parse import urlsplit

from pydantic import ValidationError

from .app import ConsoleApp, ConsoleError

MAX_BODY_BYTES = 2_000_000
LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "[::1]", "::1"})


def console_page() -> bytes:
    return resources.files("invariant.console").joinpath("console.html").read_bytes()


def _host_name(header: str) -> str:
    host = header.strip().lower()
    if host.startswith("["):
        return host[: host.find("]") + 1]
    return host.rsplit(":", 1)[0] if ":" in host else host


def make_handler(app: ConsoleApp, allowed_hosts: frozenset[str]) -> type[BaseHTTPRequestHandler]:
    posts: dict[str, Callable[[dict[str, Any]], dict[str, Any]]] = {
        "/api/validate": app.validate,
        "/api/rules": app.save_rule,
        "/api/rules/import": app.import_json,
        "/api/rules/enabled": app.set_enabled,
        "/api/rules/enabled-many": app.set_enabled_many,
        "/api/settings/preview": app.preview_settings,
        "/api/settings": app.save_settings,
        "/api/rules/delete": app.delete_rule,
        "/api/scan": app.scan,
        "/api/replay": app.replay,
        "/api/report-html": app.report_html,
        "/api/project/pick": app.project_pick,
        "/api/project/inspect": app.project_inspect,
        "/api/project/open": app.project_open,
        "/api/project/close": app.project_close,
    }
    gets: dict[str, Callable[[], dict[str, Any]]] = {
        "/api/bootstrap": app.bootstrap,
        "/api/rules/export": app.export,
        "/api/settings": app.get_settings,
        "/api/project": app.project_state,
    }

    class Handler(BaseHTTPRequestHandler):
        server_version = "InvariantConsole"
        protocol_version = "HTTP/1.1"

        def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
            pass  # the console is interactive; request logs are noise

        # -- helpers ---------------------------------------------------------

        def _send(self, status: int, body: bytes, content_type: str) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.end_headers()
            self.wfile.write(body)

        def _json(self, status: int, payload: dict[str, Any]) -> None:
            self._send(status, json.dumps(payload).encode("utf-8"), "application/json")

        def _error(self, status: int, message: str, diagnostics: list[Any] | None = None) -> None:
            self._json(status, {"error": message, "diagnostics": diagnostics or []})

        def _local(self) -> bool:
            if _host_name(self.headers.get("Host", "")) not in allowed_hosts:
                self._error(HTTPStatus.FORBIDDEN, "this console only answers on its own address")
                return False
            return True

        # -- routes ----------------------------------------------------------

        def do_GET(self) -> None:  # noqa: N802
            if not self._local():
                return
            path = urlsplit(self.path).path
            if path in ("/", "/index.html"):
                self._send(HTTPStatus.OK, console_page(), "text/html; charset=utf-8")
            elif path in gets:
                self._json(HTTPStatus.OK, gets[path]())
            else:
                self._error(HTTPStatus.NOT_FOUND, f"no such page: {path}")

        def do_POST(self) -> None:  # noqa: N802
            if not self._local():
                return
            path = urlsplit(self.path).path
            handler = posts.get(path)
            if handler is None:
                self._error(HTTPStatus.NOT_FOUND, f"no such endpoint: {path}")
                return
            # A cross-site form cannot send this content type without a CORS
            # preflight, which this server never approves.
            if self.headers.get("Content-Type", "").split(";")[0].strip() != "application/json":
                self._error(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, "send application/json")
                return
            origin = self.headers.get("Origin")
            if origin and _host_name(urlsplit(origin).netloc) not in allowed_hosts:
                self._error(HTTPStatus.FORBIDDEN, "cross-origin requests are not accepted")
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                length = -1
            if length < 0 or length > MAX_BODY_BYTES:
                self._error(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "request body is too large")
                return
            try:
                request = json.loads(self.rfile.read(length) or b"{}")
            except ValueError:
                self._error(HTTPStatus.BAD_REQUEST, "request body is not valid JSON")
                return
            if not isinstance(request, dict):
                self._error(HTTPStatus.BAD_REQUEST, "request body must be a JSON object")
                return
            try:
                self._json(HTTPStatus.OK, handler(request))
            except ConsoleError as exc:
                self._error(HTTPStatus.BAD_REQUEST, str(exc), exc.diagnostics)
            except ValidationError as exc:
                self._error(HTTPStatus.BAD_REQUEST, f"invalid report: {exc.error_count()} error(s)")
            except (ValueError, KeyError) as exc:
                self._error(HTTPStatus.BAD_REQUEST, str(exc.args[0]) if exc.args else str(exc))
            except Exception as exc:  # noqa: BLE001 - report, do not drop the connection
                self._error(HTTPStatus.INTERNAL_SERVER_ERROR, f"{type(exc).__name__}: {exc}")

    return Handler


def make_server(app: ConsoleApp, host: str = "127.0.0.1", port: int = 8765) -> ThreadingHTTPServer:
    """Create (but do not start) the console server. ``port=0`` picks a free port."""
    allowed = LOOPBACK_HOSTS | {host.lower()}
    server = ThreadingHTTPServer((host, port), make_handler(app, frozenset(allowed)))
    server.daemon_threads = True
    return server
