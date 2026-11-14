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
