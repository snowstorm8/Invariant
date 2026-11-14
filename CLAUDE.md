# Invariant — notes for contributors and agents

Property-based testing of security invariants (authorization / tenant isolation). Python 3.12+,
`src/` layout, Hypothesis + FastAPI + HTTPX + Pydantic + pytest.

## Commands
- `.venv/bin/pip install -e '.[dev]'` — install
- `.venv/bin/pytest` — all tests (~1 min); `pytest tests/unit` is sub-second
- `.venv/bin/mypy` — strict type check (must stay clean)
- `./scripts/demo.sh` — end-to-end demo against the local vulnerable app
- `.venv/bin/invariant console` — browser console (rules + exploration) on localhost:8765

## Rules
- Hypothesis chooses operations only. Security verdicts come from `SecurityProperty.evaluate`
  (`properties/checks.py`), run by `evaluation/`, and must be deterministic and pure: properties do
  no I/O and declare the probes they need via `requires`. No LLM in the evaluation path.
- Every property is a rule in the rule language (`docs/rules.md`), interpreted by `rules/`. The
  built-ins live in `integrations/document_saas.rules`; do not add Python property classes.
- `rules/` is application-agnostic: it must not import `core/`, `properties/`, `adapters/` or
  `integrations/`. What rules can see comes from a `RuleBinding` + `ContextSchema` in `integrations/`.
- Never `eval`/`exec` rule content. New rule functions go in the closed table `rules/functions.py`.
- A rule value that is missing is undefined, and a verdict that depends on it is `INCONCLUSIVE`.
- Never decide a verdict from an HTTP status alone. Missing observations, 5xx and transport
  errors are `INCONCLUSIVE`, never `PASS`.
- Scenarios use symbolic refs (`org0`, `user1`, `doc2`), never app IDs or tokens, so they replay.
- Only update the expected-state model for operations the policy authorised.
- Test only the local demo app. Do not point Invariant at third-party systems.
- `examples/vulnerable_saas` is intentionally insecure; never deploy it.
- Each component needs tests; new defects need a pinned scenario in `tests/regression/scenarios`.
- Empty scaffold files (`core/config.py`, `core/context.py`, `exploration/strategies.py`,
  `evaluation/assertions.py`, `reporting/formats.py`) are intentionally unimplemented.
