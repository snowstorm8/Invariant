# Projects: testing an application from a folder

The console tests an application you point it at. Choose the application's folder; Invariant reads
its `invariant.toml`, shows you the command it would run, and, once you confirm, starts it as a local
process, tests it over HTTP and stops it afterwards.

```
.venv/bin/invariant console      # Project tab -> Choose folder... -> Open -> Rules -> Run exploration
```

`Choose folder…` opens the operating system's own dialog (Finder, File Explorer, a desktop file
dialog). Where none exists, type the path instead. The dialog starts in `examples/`, where
`meridian_docs` lives.

## `invariant.toml`

```toml
[project]
name = "Meridian Docs"
description = "Multi-tenant enterprise document platform."

[run]
command = ["python", "server.py", "--host", "127.0.0.1", "--port", "{port}"]
health = "/healthz"        # answers 200 when the application is ready
start_timeout = 20         # seconds, 1-120
env = { SOME_SETTING = "value" }   # optional

[contract]
integration = "document-saas"
reset = "/_admin/reset"
```

- `command` is run from the project folder. `{port}` is a free loopback port; `python` means the
  interpreter running Invariant.
- The application receives only `PATH`, `HOME`, locale and temp variables plus `env`; none of the
  console's other environment.
- `reset` must return `{"orgs": 0, "users": 0, "documents": 0}`; it is called before every sequence.
- The application speaks the document contract in `adapters/http.py`.
- Nothing runs until you press *Open project*. Only 127.0.0.1 is contacted.

## Meridian Docs (`examples/meridian_docs`)

An enterprise document platform: workspaces, roles, revisions, trash, search, edge cache, read
replica, audit log, session cookies. It is **intentionally insecure** and carries 13 defects, each
behind a release flag (`MERIDIAN_FLAGS`: `all` by default, `none` for the fixed build, or a list).
Each needs a multi-step sequence; none is visible in a single request.

| Flag | What happens | Default rule |
|---|---|---|
| `edge-cache-v2` | the edge cache is keyed by document id only, so another workspace is served a hot document | AC-1, AC-5, TI-1 |
| `recent-viewers` | a refused read still records the caller as a viewer, and viewers may save | AC-2, TI-2 |
| `coediting-lease` | a co-editing lease after an edit skips the role check for the next writes | AC-3, AZ-1 |
| `owner-follows-editor` | the last editor becomes owner, and owners may delete | AC-4 |
| `read-replica` | deleting a document does not purge the read replica | AC-7 |
| `collab-sessions` | with two editors, updates echo the caller's API token | DX-1 |
| `history-rotation` | off-by-one when the revision history rotates: a crash whose page shows a stack trace | IR-1, DX-2 |
| `friendly-refusals` | admins of another workspace get a 403 naming the owner | DX-3 |
| `merge-revisions` | an update after someone else read the document bumps the version twice | IR-3 |
| `draft-autosave` | a refused write by a viewer who opened the document saves the draft | IR-2, AZ-1 |
| `lean-error-pages` | error responses skip the hardening headers | TH-1..TH-5 |
| `bulk-render` | listings of 3+ documents add `X-Powered-By` and are served as `text/html` | TH-6, TH-11 |
| `undo-toast` | a delete sets an unprotected cookie | TH-8, TH-9, TH-10 |

At the default 200 sequences and seed 1 the default rules report 25 violated rules in well under a
minute. Minimal counterexamples are pinned in `tests/regression/scenarios/meridian/`.
