# Architecture

```
Hypothesis state machine ──▶ Engine.apply(op) ──▶ Adapter.execute(Call) ──▶ target app
   (exploration/)              │  ▲                                          
                               │  └── ModelState (expected state, core/state.py)
                               ▼
                       Evaluator (evaluation/) ──▶ Evaluation{PASS|VIOLATION|INCONCLUSIVE}
                               │
              violation ──▶ RunFailure ──▶ minimize ──▶ replay ──▶ Report (JSON/text)
```

**Operations** (`core/scenario.py`) are symbolic and serialisable. The engine resolves refs to
real credentials/IDs and builds an adapter `Call`.

**Expected state** (`ModelState`) holds orgs, users (org, role), documents (owner org, content,
version, deleted). It is updated only from operations the reference policy authorised, so it
represents what the target *should* contain. Every write embeds a marker `<<INV:n>>`, unique per
step, in the stored content; seeing a foreign document's marker in a response means that data was
disclosed, whatever the status code or response shape.

**Evaluation**
- *TI-1 confidentiality*: scan every response body for markers of other orgs' documents.
- *TI-2 / AZ-1 integrity*: after an operation the policy forbids, take a *state probe* (list the
  affected org as a legitimate member) and diff it against the model.
- No response / 5xx / unusable probe → `INCONCLUSIVE`. By default (`strict`) these stop the run.

**Reset and isolation.** Hypothesis runs one state-machine instance per example; each builds a
fresh adapter via the factory, then `Engine.reset()` calls `Adapter.reset()`, which must verify
the target is empty (the HTTP adapter checks `POST /_admin/reset` reports zero entities).

**Reproduction.** `explore()` takes the shortest violating run Hypothesis produced, minimises it
by deleting operations that are not needed for the same property to fail, then replays the result
on a fresh target and records whether it reproduced.
