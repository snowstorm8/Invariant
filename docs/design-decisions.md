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
- **Rules are interpreted, never executed.** A rule is parsed into an IR and walked by
  `rules/interpreter.py`; there is no `eval`, no attribute access on Python objects, and a closed
  function table. Evaluation has a step budget per rule per step (exceeding it is INCONCLUSIVE).
- **`when` cannot see the response.** Scope and probe arguments are decided before the target
  answers, so the calls a scenario makes do not depend on the response being judged. They may depend
  on earlier responses through `events`. Response conditions go in the assertion (`implies`).
- **An `observe` clause takes one probe with arguments known up front**; a rule cannot probe once per
  element of a list.
- **The console is single-user and local.** It binds to loopback, refuses other Host names and
  cross-origin requests, and runs one exploration at a time.
- **Confidentiality detection relies on markers** the engine writes into content. It cannot see
  leaks of data it did not plant (IDs, metadata, user names) or leaks via side channels.
- **Fixed topology**: two orgs, any number of users with random roles, documents. No sharing,
  invitations, role changes or token revocation yet.
- **In-process target**: the demo uses `TestClient`; Starlette warns that it prefers `httpx2`
  (suppressed in pytest config). `HttpAdapter` accepts any `httpx.Client`.
- **Seeded runs** use `hypothesis.stateful.get_state_machine_test`, which is not a documented API.
- `LICENSE` is still empty; choose one before publishing.
