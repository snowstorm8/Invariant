# Getting started

```bash
.venv/bin/pip install -e '.[dev]'
.venv/bin/invariant explore vulnerable_saas.target:vulnerable_adapter --app-dir examples --seed 1 --report r.json
.venv/bin/invariant replay r.json vulnerable_saas.target:vulnerable_adapter --app-dir examples   # VIOLATION
.venv/bin/invariant replay r.json vulnerable_saas.target:fixed_adapter --app-dir examples        # PASS
```

The console is the main interface for writing and managing rules:

```bash
.venv/bin/invariant console            # http://localhost:8765, demo app as the target
```

Rule files also work from the command line: `invariant explore ... --rules my.rules [--no-builtin]`
(`.json` files use the JSON format). See [rules.md](rules.md).

Exit codes: 0 PASS, 1 VIOLATION, 2 INCONCLUSIVE/usage error. A target is `module:callable`
returning a fresh `Adapter` each call.

## Your first rule (in the console)

1. Run `.venv/bin/invariant console` and open http://localhost:8765.
2. On the **Rules** tab choose **+ New rule** and replace the template with:

   ```
   rule "viewers-cannot-write" {
       description "A viewer must never be able to change a document."
       severity high
       when operation.is_write and actor.role == "viewer"
       always not (response.status >= 200 and response.status < 300)
       message "{actor.ref} (viewer) got HTTP {response.status} for {operation.type}"
   }
   ```

   While you type, press **Ctrl+Space** for suggestions (fields such as `actor.role`, functions,
   clauses). The status line under the editor says *valid* once the rule can run.
3. **Save**. The rule is enabled and kept in `.invariant/rules.json`.
4. Open **Run exploration**, switch on the `viewer-can-update` defect, and run. The rule should
   report a VIOLATION with a minimal operation sequence in which a viewer updates a document.
   Run again with every defect off (the fixed build): no violation is found.
5. Use **Replay on the fixed build** on the result to confirm the same sequence passes there.

See [rules.md](rules.md) for the full language.
