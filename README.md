# Invariant

**Define what your software must never allow. Invariant tests whether those promises hold.**

Invariant is a property-testing tool for security invariants. Instead of matching vulnerability
signatures, it explores long sequences of operations by many users, roles and tenants against a
running web application, and a deterministic evaluator decides after every step whether a stated
rule was broken. Each broken rule comes back with the shortest sequence that breaks it, replayable
on a fresh instance.

The current target is **authorization, tenant isolation, data exposure, browser hardening and state
integrity** in multi-tenant document-style web applications. It is a prototype: it tests only
applications on your own machine.

## The workflow

```bash
python -m venv .venv && .venv/bin/pip install -e '.[dev]'
.venv/bin/invariant console
```

1. **Project**: choose the folder of an application (the console opens your operating system's own
   folder dialog). The folder holds an `invariant.toml` that says how to start it. Invariant shows
   the command, and starts the application on a local port only after you confirm.
2. **Rules**: 29 default rules are on, grouped by tag (access control, data exposure, headers,
   integrity). Search, filter, switch groups on and off, write your own, or import JSON.
3. **Run exploration**: pick a seed and the number of sequences and run. Every enabled rule is
   judged on every step.
4. **Read the report**: each violated rule lists its minimal counterexample, evidence, severity and
   whether it reproduced on replay. **Open full report** shows the rule, the timeline and the
   evidence; **Replay** re-checks every finding on a fresh instance.

`examples/meridian_docs` is a full demo application for exactly this flow: an enterprise document
platform with 13 deliberately hidden defects that each need a multi-step sequence. With the default
rules, seed 1 and 200 sequences, Invariant reports about 25 violated rules in under a minute. See
[docs/demo-walkthrough.md](docs/demo-walkthrough.md).

## Your own rules

Security rules are data, not code. Write them in the console or upload a JSON file; Invariant
validates them and checks them on every step.

```
rule "viewers-cannot-write" {
    description "A viewer must never be able to change a document."
    severity high
    when operation.is_write and actor.role == "viewer"
    never response.status < 300
}
```

New to the language? Start with the [tutorial](docs/tutorial-rules.md); the
[reference](docs/rules.md) is the full specification. The three core rules (TI-1, TI-2, AZ-1) and the
26 default web-application rules are written in the same language and ship as rule files under
`src/invariant/integrations/`.

## Command line

```bash
.venv/bin/invariant console                 # the browser console (choose a folder)
.venv/bin/invariant console --demo          # open the built-in vulnerable demo instead
.venv/bin/invariant explore vulnerable_saas.target:vulnerable_adapter --app-dir examples --seed 1 --report r.json
.venv/bin/invariant replay r.json vulnerable_saas.target:fixed_adapter --app-dir examples
.venv/bin/invariant view r.json             # HTML report from a saved JSON report
./scripts/demo.sh                           # violation -> replay -> fixed app passes
```

Exit codes: 0 PASS, 1 VIOLATION, 2 INCONCLUSIVE or usage error. See
[docs/getting-started.md](docs/getting-started.md).

## Repository map

| Path | What it is |
|---|---|
| `src/invariant/exploration/` | Hypothesis `RuleBasedStateMachine` that picks operations and arguments. Knows nothing about security. Multi-round search so every failing rule is reported. |
| `src/invariant/core/engine.py` | Executes one operation via the adapter, runs the planned probes, keeps the expected-state model. |
| `src/invariant/rules/` | The rule language: parser, JSON format, validator, interpreter, id algorithms. Knows no application. |
| `src/invariant/integrations/` | What rules can see for an application (`RuleBinding`, schema) and the shipped rule files. |
| `src/invariant/properties/` | The reference authorization policy, and `RuleCheck`, which presents a rule as a `SecurityProperty`. |
| `src/invariant/evaluation/` | Plans probes, judges every rule in scope, owns `INCONCLUSIVE`. Deterministic; no LLM. |
| `src/invariant/adapters/` | `reset()` / `execute()` / `close()` contract; `HttpAdapter` for REST targets. |
| `src/invariant/analysis/` | Replay of a symbolic scenario and 1-minimal reduction. |
| `src/invariant/reporting/` | JSON report, text rendering, the HTML report viewer. |
| `src/invariant/console/` | The browser console: project launcher and folder dialog, rule management, exploration. |
| `examples/vulnerable_saas/` | Small in-process demo with five switchable defects. |
| `examples/meridian_docs/` | The enterprise demo application, started from its `invariant.toml`. |
| `docs/` | Documentation (below). |

## Documentation

| Document | Contents |
|---|---|
| [getting-started.md](docs/getting-started.md) | Install, first run, console, command line. |
| [demo-walkthrough.md](docs/demo-walkthrough.md) | The demo flow, step by step, with what to say and what to expect. |
| [projects.md](docs/projects.md) | Pointing Invariant at an application: `invariant.toml`, the Meridian Docs demo and its defects. |
| [tutorial-rules.md](docs/tutorial-rules.md) | Learn the rule language by writing rules. |
| [rules.md](docs/rules.md) | Rule language reference, JSON format, ids, the default library. |
| [security-properties.md](docs/security-properties.md) | The reference policy and every shipped rule. |
| [architecture.md](docs/architecture.md) | How exploration, the engine, evaluation, replay and the console fit together. |
| [design-decisions.md](docs/design-decisions.md) | Decisions, trade-offs and known limitations. |

## Safety

Invariant only tests applications on your own machine. The console and any application it starts
listen on loopback; the application gets a small environment (no secrets from yours) and is stopped
afterwards. `examples/vulnerable_saas` and `examples/meridian_docs` are intentionally insecure:
never deploy them. Do not point Invariant at systems you do not own.

## Limitations

Invariant performs bounded, randomized testing. `PASS` means *no violation found in the explored
scenarios*; it is not formal verification and gives no security guarantee. Deep defects need more
sequences: raise **Sequences to try** (or `--max-examples`) if a rule you expect is missing. Details
in [docs/design-decisions.md](docs/design-decisions.md).

## License

MIT, see [LICENSE](LICENSE).
