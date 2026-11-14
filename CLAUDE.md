# Invariant — notes for contributors and agents

Property-based testing of security invariants (authorization, tenant isolation, data exposure,
headers, integrity) in web applications. Python 3.12+, `src/` layout, Hypothesis + FastAPI + HTTPX +
Pydantic + uvicorn + pytest. User docs are in `docs/` (start at `README.md`).

## Commands
- `.venv/bin/pip install -e '.[dev]'` — install
- `.venv/bin/pytest` — all tests (~12 min; the exploration tests dominate); `pytest tests/unit` is sub-second
- `.venv/bin/mypy` — strict type check (must stay clean; covers `src/invariant` and both examples)
- `./scripts/demo.sh` — end-to-end demo against the in-process vulnerable app
- `.venv/bin/invariant console` — browser console on localhost:8765: Project (choose a folder with an
  `invariant.toml`, e.g. `examples/meridian_docs`) → Rules → Run exploration. `--demo` preloads the
  built-in demo. See `docs/projects.md` and `docs/demo-walkthrough.md`.

## Rules
- Hypothesis chooses operations only. Security verdicts come from `SecurityProperty.evaluate`
  (`properties/checks.py`), run by `evaluation/`, and must be deterministic and pure: properties do
  no I/O and declare the probes they need via `requires`. No LLM in the evaluation path.
- Every property is a rule in the rule language (`docs/rules.md`, `docs/tutorial-rules.md`),
  interpreted by `rules/`. The core built-ins live in `integrations/document_saas.rules`, the default
  web-application library in `integrations/web_defaults.rules`; do not add Python property classes.
  A rule's `id` is what reports show; the policy's name for it is its `policy` key (`rules/ids.py`
  derives `AA-11` ids from names).
- `rules/` is application-agnostic: it must not import `core/`, `properties/`, `adapters/` or
  `integrations/`. What rules can see comes from a `RuleBinding` + `ContextSchema` in `integrations/`.
- Never `eval`/`exec` rule content. New rule functions go in the closed table `rules/functions.py`.
- A rule value that is missing is undefined, and a verdict that depends on it is `INCONCLUSIVE`.
- Never decide a verdict from an HTTP status alone. Missing observations, 5xx and transport
  errors are `INCONCLUSIVE`, never `PASS`.
- Scenarios use symbolic refs (`org0`, `user1`, `doc2`), never app IDs or tokens, so they replay.
- Only update the expected-state model for operations the policy authorised.
- A muted rule's violation ends a generated sequence only if it may have desynchronised model and
  target (`Engine._may_diverge`); header, cookie and status violations do not.
- Test only applications on the local machine. Do not point Invariant at third-party systems. A
  project is started only by an explicit action in the console, with a minimal environment.
- `examples/vulnerable_saas` and `examples/meridian_docs` are intentionally insecure; never deploy them.
- Each component needs tests; new defects need a pinned scenario in `tests/regression/scenarios`
  (`meridian/` for the enterprise demo, one file per release flag).
- Complete rules in `docs/*.md` are fenced as ```` ```rule ````; `tests/unit/test_docs_rules.py`
  validates them and checks they hold on the fixed Meridian build. Keep docs and tests in step.
- Empty scaffold files (`core/config.py`, `core/context.py`, `exploration/strategies.py`,
  `evaluation/assertions.py`, `reporting/formats.py`) are intentionally unimplemented.
