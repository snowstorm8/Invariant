# Getting started

## Install

Python 3.12 or newer.

```bash
python -m venv .venv
.venv/bin/pip install -e '.[dev]'
.venv/bin/pytest tests/unit      # sub-second sanity check
```

The `demo` extra (`pip install -e '.[demo]'`) installs just what the demo applications need
(FastAPI and uvicorn); `dev` includes it plus pytest and mypy.

## The console

```bash
.venv/bin/invariant console            # http://localhost:8765, no application loaded
.venv/bin/invariant console --demo     # start with the built-in vulnerable demo as the target
```

The console has four tabs.

| Tab | What you do there |
|---|---|
| **Project** | Choose the folder of an application. *Choose folder…* opens the operating system's dialog (type a path instead where there is none). Invariant reads `invariant.toml`, shows the command it would run and, when you confirm, starts the application on a free local port. |
| **Rules** | The rules that will be checked. 29 default rules are on, grouped by tag. Search, filter by tag, switch groups or single rules on and off, create rules, upload or export JSON. |
| **Run exploration** | Choose a seed (blank for a random search) and the number of sequences, then run. Results list every violated rule. |
| **Settings** | Choose how rules written without an `id` are named (`AA-11`, five algorithms). Saving renames every rule to match. |

### A first run with the Meridian Docs demo

1. **Project** → *Choose folder…* → `examples/meridian_docs` → *Open project and start the application*.
2. **Rules**: leave everything on.
3. **Run exploration**: seed `1`, `200` sequences → *Run exploration*.

About a minute later the result reads "N rules violated". Below the failed rules, **Passed rules**
lists every enabled rule that held, with the number of steps it was checked on; rules that never
applied to a generated step are listed separately as *never exercised* (their passing says nothing,
so run more sequences). Select a failed rule to see the minimal
operation sequence that broke it and the evidence; *Open full report* gives the full page, and
*Replay on this build* confirms each finding on a fresh instance. The walkthrough
[demo-walkthrough.md](demo-walkthrough.md) explains what you are looking at.

### Your first rule

1. On the **Rules** tab choose **+ New rule** and replace the template with:

   ```
   rule "viewers-cannot-write" {
       description "A viewer must never be able to change a document."
       severity high
       when operation.is_write and actor.role == "viewer"
       never response.status < 300
       message "{actor.ref} (viewer) got HTTP {response.status} for {operation.type}"
   }
   ```

   Press **Ctrl+Space** for suggestions. The status line under the editor says *valid* once the
   rule can run.
2. **Save**. The rule is on and kept in `.invariant/rules.json` (not committed).
3. Open **Run exploration** and run. On a build where a viewer can write, the rule reports a
   `VIOLATION` with the shortest sequence in which a viewer changes a document.

The [tutorial](tutorial-rules.md) takes it from here.

## Command line

```bash
# explore the built-in demo (a Python target: module:callable returning an adapter)
.venv/bin/invariant explore vulnerable_saas.target:vulnerable_adapter --app-dir examples --seed 1 --report r.json
.venv/bin/invariant replay r.json vulnerable_saas.target:vulnerable_adapter --app-dir examples   # VIOLATION
.venv/bin/invariant replay r.json vulnerable_saas.target:fixed_adapter --app-dir examples        # PASS
.venv/bin/invariant view r.json                                                                  # HTML report
./scripts/demo.sh                                                                                # all of the above
```

`explore` options: `--seed`, `--max-examples` (default 200), `--report FILE`, `--html FILE`,
`--rules FILE` (repeatable; `.json` or rule-language text), `--no-builtin` (drop the three core
rules) and `--library` (also check the 26 default web-application rules; the console enables them).

Exit codes: 0 PASS, 1 VIOLATION, 2 INCONCLUSIVE or usage error.

`explore` and `replay` take a *target*: `module:callable` returning a fresh `Adapter` each call
(see `examples/vulnerable_saas/target.py`). Applications that run as their own process are tested
through the console, with an `invariant.toml` ([projects.md](projects.md)).

## Tests and type checking

```bash
.venv/bin/pytest                 # everything; the exploration tests take ~10 minutes
.venv/bin/pytest tests/unit      # sub-second
.venv/bin/mypy                   # strict; must stay clean
```

## Where to go next

- [tutorial-rules.md](tutorial-rules.md): write rules.
- [projects.md](projects.md): make your own application testable.
- [architecture.md](architecture.md): how it works.
