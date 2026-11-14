# vulnerable_saas

**Deliberately insecure. Local testing only; never deploy.**

A small multi-tenant document API (orgs, users with `admin` / `member` / `viewer` roles,
org-owned documents), run in-process through Starlette's `TestClient`. It is the quick demo behind
`scripts/demo.sh` and most of the test suite. For a realistic application and the full
folder-to-report workflow see `../meridian_docs` and [docs/projects.md](../../docs/projects.md).

`create_app(defects=...)` switches on named defects (see `app/models.py`); with none, the app is
the fixed version.

| Defect | Behaviour | Caught by |
|---|---|---|
| `stale-cache-read` | `GET /documents/{id}` serves a recently *updated* document from a cache keyed by id only (needs create, update, then a read from another org) | TI-1, AC-1, AC-5 |
| `update-missing-tenant-check` | `PUT` checks the role but not the tenant | TI-2, AC-2 |
| `viewer-can-update` | `PUT` does not enforce the role | AZ-1, AC-3 |
| `missing-security-headers` | responses omit the hardening headers and announce the server version | TH-1 to TH-6 |
| `verbose-errors` | another org's document gets a 403 naming the owner instead of a plain 404 | DX-3 |

`target.py` provides `vulnerable_adapter` / `fixed_adapter` factories for the command line and
`console_target()` for the console (`invariant console --demo`, which offers one switch per defect).
