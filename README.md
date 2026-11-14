# Invariant

**Define what your software must never allow. Invariant tests whether those promises hold.**

Invariant is an open-source property-testing framework for security invariants. Instead of
matching vulnerability signatures, it uses [Hypothesis](https://hypothesis.readthedocs.io)
stateful testing to explore sequences of operations by many users, roles and tenants, and a
deterministic evaluator to decide whether an explicit security property was violated.

The first target is **authorization and multi-tenant isolation** in web applications.
This is a prototype: it tests only the local demo app that ships in `examples/`.

## Quick start

```bash
python -m venv .venv && .venv/bin/pip install -e '.[dev]'
.venv/bin/pytest            # ~2 minutes; exploration tests dominate
./scripts/demo.sh           # violation -> replay -> fixed app passes
.venv/bin/invariant console # choose an app folder, manage rules, run explorations, in the browser
```

## Your own rules

Security rules are data, not code. Write them in the console or upload a JSON file; Invariant
validates them and checks them on every step of every operation sequence it explores.

```
rule "read-returns-own-tenant" {
    severity critical
    when operation.type == "read_document"
    always response.status == 200 implies response.json.org_id == actor.org_id
}
```

The three core rules (TI-1, TI-2, AZ-1) are written in the same language
(`src/invariant/integrations/document_saas.rules`), and 26 default rules for web applications
(access control, data exposure, headers and cookies, integrity) ship next to them in
`web_defaults.rules`. In the console they are grouped by tag, searchable, and can be switched on and
off one by one or a group at a time; the Settings tab chooses how rules without an `id` are named
(`AA-11`, five algorithms) and renames every rule to match. See [docs/rules.md](docs/rules.md).

## What the demo shows

`examples/vulnerable_saas` is a deliberately vulnerable FastAPI multi-tenant app. Its
`stale-cache-read` defect lets `GET /documents/{id}` serve a recently *updated* document from a
cache keyed by id only, skipping the tenant check. Reaching it needs a sequence:
create document → update it → read it as a user of another organization.

```
VIOLATION: TI-1 tenant-read-isolation
  0. provision org org0          3. user0 creates doc0
  1. provision org org1          4. user0 updates doc0
  2. provision member user0 in org1   5. provision viewer user5 in org0
                                 6. user5 reads doc0  [HTTP 200]  <-- VIOLATION
Evidence: leaked doc0 (owned by org1) to user5 (org0)
Reproduced by deterministic replay on a fresh target: yes
```

## How it works

| Layer | Responsibility |
|---|---|
| `exploration/` | Hypothesis `RuleBasedStateMachine` picks operations and arguments. Knows nothing about security. |
| `core/engine.py` | Executes one operation via the adapter, takes the probes the evaluator plans, keeps the expected-state model. |
| `rules/` | The rule language: parser, JSON format, validator, interpreter. Knows no application. |
| `integrations/` | What rules can refer to for a given application (`RuleBinding`, schema), and its built-in rule file. |
| `properties/` | The reference authorization policy, and `RuleCheck`, which presents a rule to the evaluator as a `SecurityProperty`. |
| `evaluation/` | Framework around the properties: plans probes, runs each property in scope, owns `INCONCLUSIVE`. Deterministic; no LLM, no status-code trust. |
| `adapters/` | `reset()` / `execute()` / `close()` contract; `HttpAdapter` for REST targets. |
| `analysis/` | Replay of a symbolic scenario and 1-minimal reduction. |
| `reporting/` | Structured JSON report, text rendering and the HTML report viewer. |
| `console/` | The browser console: rule management and exploration (`invariant console`). |

See [docs/architecture.md](docs/architecture.md) and [docs/security-properties.md](docs/security-properties.md).

## Limitations

Invariant performs bounded, randomized testing. `PASS` means *no violation found in the explored
scenarios*; it is not formal verification and gives no security guarantee. Details in
[docs/design-decisions.md](docs/design-decisions.md).
