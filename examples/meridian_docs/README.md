# Meridian Docs

**Deliberately insecure. Local testing only; never deploy.**

A multi-tenant enterprise document platform used to demonstrate Invariant on something realistic:
workspaces and roles, revisions, trash, search, an edge cache, a read replica, an audit log and
session cookies. It is a normal FastAPI service started from its own folder:

```
meridian/state.py       domain objects and the in-memory platform state
meridian/documents.py   the service layer: the rules of the platform
meridian/security.py    authentication, session cookies, hardening headers, the crash page
meridian/api.py         HTTP routes (documents, search, revisions) and provisioning endpoints
meridian/flags.py       release flags
server.py               python server.py --port 8080
invariant.toml          how Invariant starts, health-checks and resets it
```

Thirteen defects are hidden behind release flags (`MERIDIAN_FLAGS`: `all` by default, `none` for the
fixed build, or a comma-separated list). Each needs a multi-step sequence to trigger, and the code
does not label them. The list, with the rules that catch each, is in
[docs/projects.md](../../docs/projects.md); how to show them is in
[docs/demo-walkthrough.md](../../docs/demo-walkthrough.md).

Use it from the console: `invariant console` → **Project** → *Choose folder…* → this folder.
