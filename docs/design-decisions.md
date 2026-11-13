# Design decisions and known limitations

- **Hypothesis shrinking is disabled** (`Phase.generate` only). Stateful shrinking is heuristic and
  slow; `analysis/minimizer.py` does deterministic, property-aware deletion instead. The result is
  1-minimal, not globally minimal.
- **Verified state transitions.** After an authorised write the engine lists the actor's own org and
  compares it with the snapshot the model predicts after the change (2xx: the change; otherwise:
  no change). Only a match updates the model. A mismatch or unusable probe stops the run as
  INCONCLUSIVE, never as a violation. Cost: one extra request per authorised write. Residual risk:
  the verification trusts the listing endpoint; a target whose listing and storage disagree
  consistently would pass, and unauthorised-write detection shares the same probe mechanism.
- **Confidentiality detection relies on markers** the engine writes into content. It cannot see
  leaks of data it did not plant (IDs, metadata, user names) or leaks via side channels.
- **Fixed topology**: two orgs, any number of users with random roles, documents. No sharing,
  invitations, role changes or token revocation yet.
- **In-process target**: the demo uses `TestClient`; Starlette warns that it prefers `httpx2`
  (suppressed in pytest config). `HttpAdapter` accepts any `httpx.Client`.
- **Seeded runs** use `hypothesis.stateful.get_state_machine_test`, which is not a documented API.
- `LICENSE` is still empty; choose one before publishing.
