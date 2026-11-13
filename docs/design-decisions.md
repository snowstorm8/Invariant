# Design decisions and known limitations

- **Hypothesis shrinking is disabled** (`Phase.generate` only). Stateful shrinking is heuristic and
  slow; `analysis/minimizer.py` does deterministic, property-aware deletion instead. The result is
  1-minimal, not globally minimal.
- **Model sync uses status codes** for *authorised* operations (2xx ⇒ the target accepted it). That
  only keeps the model aligned; verdicts never depend on status. If the target misbehaves on an
  authorised operation (e.g. returns 4xx but applied it), the model can drift and a later probe may
  report a false positive.
- **Confidentiality detection relies on markers** the engine writes into content. It cannot see
  leaks of data it did not plant (IDs, metadata, user names) or leaks via side channels.
- **Fixed topology**: two orgs, any number of users with random roles, documents. No sharing,
  invitations, role changes or token revocation yet.
- **In-process target**: the demo uses `TestClient`; Starlette warns that it prefers `httpx2`
  (suppressed in pytest config). `HttpAdapter` accepts any `httpx.Client`.
- **Seeded runs** use `hypothesis.stateful.get_state_machine_test`, which is not a documented API.
- `LICENSE` is still empty; choose one before publishing.
