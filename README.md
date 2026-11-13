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
.venv/bin/pytest            # ~1 minute; exploration tests dominate
./scripts/demo.sh           # violation -> replay -> fixed app passes
```

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
| `core/engine.py` | Executes one operation via the adapter, keeps the expected-state model, calls the evaluator. |
| `properties/` | Property statements (TI-1, TI-2, AZ-1) and the reference authorization policy. |
| `evaluation/` | Deterministic verdicts: `PASS` / `VIOLATION` / `INCONCLUSIVE`. No LLM, no status-code trust. |
| `adapters/` | `reset()` / `execute()` / `close()` contract; `HttpAdapter` for REST targets. |
| `analysis/` | Replay of a symbolic scenario and 1-minimal reduction. |
| `reporting/` | Structured JSON report and text rendering. |

See [docs/architecture.md](docs/architecture.md) and [docs/security-properties.md](docs/security-properties.md).

## Limitations

Invariant performs bounded, randomized testing. `PASS` means *no violation found in the explored
scenarios*; it is not formal verification and gives no security guarantee. Details in
[docs/design-decisions.md](docs/design-decisions.md).
