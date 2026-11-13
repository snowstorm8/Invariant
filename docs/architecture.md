# Architecture

```
Hypothesis state machine ──▶ Engine.apply(op) ──▶ Adapter.execute(Call) ──▶ target app
   (exploration/)              │  ▲                    ▲
                               │  │                    └── probes the evaluator planned
                               │  └── ModelState (expected state, core/state.py)
                               ▼
                       Evaluator (evaluation/) ──▶ Evaluation{PASS|VIOLATION|INCONCLUSIVE}
                         plan ─▶ judge              ▲
                               │                    └── SecurityProperty (properties/checks.py)
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

**Evaluation** is *plan, probe, judge*. Each property is a `SecurityProperty`
(`properties/base.py`) with three pure methods: `applies(step)` (is this step in scope?),
`requires(step)` (which probes are needed?) and `evaluate(step, response, evidence)` (the verdict).

1. *Plan*: `Evaluator.plan` collects the probe requests of every property in scope, each once. It
   does not see the response, so the calls a scenario makes depend only on the scenario and the model.
2. *Probe*: the engine executes each request (today only `OrgSnapshot`: list an org as one of its
   members). Properties never perform I/O.
3. *Judge*: `Evaluator.judge` runs each property in scope and stamps its id on the result.

The properties (`properties/checks.py`), in evaluation order:
- *TI-1 confidentiality*: on every responded actor operation, scan the response body for markers of
  other orgs' documents. Needs no probe.
- *TI-2 / AZ-1 integrity*: for a write the policy denied, diff a snapshot of the affected org against
  the model. One implementation, two instances; which one applies is taken from the policy decision,
  never recomputed.

The framework owns missing evidence: no response, a 5xx, or a probe that was not taken or cannot be
parsed is `INCONCLUSIVE`, and a property is never asked to judge without the evidence it required.
By default (`strict`) these stop the run. Out of scope means no evaluation, not a `PASS`. The first
violation on a step determines how a failure is attributed, so evaluation order is observable.

Verifying *authorised* writes before committing them to the model is separate from property
evaluation and stays in the engine (see design-decisions.md).

**Reset and isolation.** Hypothesis runs one state-machine instance per example; each builds a
fresh adapter via the factory, then `Engine.reset()` calls `Adapter.reset()`, which must verify
the target is empty (the HTTP adapter checks `POST /_admin/reset` reports zero entities).

**Reproduction.** `explore()` takes the shortest violating run Hypothesis produced, minimises it
by deleting operations that are not needed for the same property to fail, then replays the result
on a fresh target and records whether it reproduced.
