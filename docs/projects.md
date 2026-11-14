# Projects: testing an application from a folder

The console tests an application you point it at. Choose the application's folder; Invariant reads
its `invariant.toml`, shows you the command it would run and, once you confirm, starts it as a
local process, tests it over real HTTP and stops it afterwards.

```bash
.venv/bin/invariant console      # Project -> Choose folder... -> Open -> Rules -> Run exploration
```

*Choose folder…* opens the operating system's own dialog (Finder, File Explorer, a desktop's file
dialog) and starts in the `examples/` folder, where `meridian_docs` lives. Where the machine has
no dialog the console says so and you type the path instead; *Inspect* then does the same thing.
A folder without a valid `invariant.toml` is explained, not started.

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

| Key | Meaning |
|---|---|
| `project.name`, `project.description` | Shown in the console and in reports. Default: the folder name. |
| `run.command` | The program and arguments, run from the project folder. Must contain `{port}`, replaced by a free loopback port. `python` means the interpreter running Invariant. |
| `run.health` | Path polled with `GET` until it answers 200 (default `/`). |
| `run.start_timeout` | How long to wait for that, in seconds (1-120, default 20). |
| `run.env` | Extra environment variables (strings). |
| `contract.integration` | What rules can see. Only `document-saas` today. |
| `contract.reset` | Path that discards all data (default `/_admin/reset`). |

What Invariant guarantees:

- **Nothing runs until you press *Open project*.** The command is shown first.
- The application receives only `PATH`, `HOME`, locale and temp variables plus `run.env`, not the
  rest of your environment.
- Only `127.0.0.1` is contacted. The application's own output is kept and shown if it fails to start.
- Opening another project, closing the project or quitting the console stops the process.

## The application contract

Invariant drives the application through the *document contract* (`adapters/http.py`). Bearer tokens
authenticate users; the engine creates tenants and users through provisioning endpoints.

| Request | Purpose |
|---|---|
| `POST {reset}` | Discard all data; respond `{"orgs": 0, "users": 0, "documents": 0}`. Called before every sequence and verified. |
| `POST /_admin/orgs` `{"name"}` | Create a tenant; respond with `{"id"}`. |
| `POST /_admin/orgs/{org}/users` `{"name", "role"}` | Create a user (`admin`, `member`, `viewer`); respond with `{"id", "token"}`. |
| `POST /documents` `{"content"}` | Create; respond with `{"id", ...}`. |
| `GET /documents` | List the caller's tenant's documents (`id`, `content`, `version`). |
| `GET/PUT/DELETE /documents/{id}` | Read, update (`{"content"}`), delete. |

Documents carry `org_id` and `version`; version starts at 1 and an update adds one. The reference
policy is: everyone may read and list inside their own tenant, `admin` and `member` may create and
update, only `admin` may delete, nobody may touch another tenant's documents
([security-properties.md](security-properties.md)). Provisioning endpoints are test-harness
surface, not part of what is judged.

## Meridian Docs (`examples/meridian_docs`)

An enterprise document platform: workspaces, roles, revisions, trash, search, an edge cache, a read
replica, an audit log and session cookies, written as a normal FastAPI service
(`meridian/documents.py` holds the rules of the platform, `security.py` authentication and headers,
`api.py` the routes). It is **intentionally insecure** and carries 13 defects. Each is behind a
release flag and none shows in a single request.

`MERIDIAN_FLAGS` selects which are on: `all` (the default, the build as deployed to staging),
`none` (the fixed build), or a comma-separated list. To test the fixed build, put
`env = { MERIDIAN_FLAGS = "none" }` under `[run]`.

| Flag | What happens | Default rules that catch it |
|---|---|---|
| `edge-cache-v2` | The edge cache is keyed by document id only, so an edited document is served to another workspace. | AC-1, AC-5, TI-1 |
| `recent-viewers` | A refused read still records the caller as a viewer, and viewers may save. | AC-2, TI-2 |
| `coediting-lease` | An edit opens a co-editing window that skips the role check for the next writers. | AC-3, AZ-1 |
| `owner-follows-editor` | The last editor becomes the owner, and owners may delete. | AC-4, AZ-1 |
| `read-replica` | Deleting a document does not purge its read-replica copy. | AC-7 |
| `collab-sessions` | With two editors, updates echo the caller's API token. | DX-1 |
| `history-rotation` | Off-by-one when the revision history rotates: a crash whose error page shows a stack trace. | IR-1, DX-2 |
| `friendly-refusals` | Admins of another workspace get a 403 naming the owner. | DX-3 |
| `merge-revisions` | An update after someone else read the document advances the version by two. | IR-3 |
| `draft-autosave` | A refused write by a viewer who opened the document saves the draft. | IR-2, AZ-1 |
| `lean-error-pages` | Error responses skip the hardening headers. | TH-1 to TH-5 |
| `bulk-render` | Listings of three or more documents add `X-Powered-By` and are served as `text/html`. | TH-6, TH-11 |
| `undo-toast` | A delete sets an unprotected cookie. | TH-8, TH-9, TH-10 |

With the default rules, seed 1 and 200 sequences, Invariant reports about 25 violated rules over
real HTTP in under a minute. Counts vary a little between runs; the thirteen defects are all found.
Minimal counterexamples are pinned in `tests/regression/scenarios/meridian/`.

## Making your own application testable

1. Expose the contract above (the demo's `meridian/api.py` is a compact example).
2. Add an `invariant.toml` to its folder.
3. Start with the default rules on a build you believe is correct. They must pass; if one fires
   it is either a real finding or a sign your application differs from the contract.
4. Add rules for your own promises ([tutorial](tutorial-rules.md)).

Applications that cannot follow the document contract need their own integration (a
`RuleBinding` and schema, see [architecture.md](architecture.md)).
