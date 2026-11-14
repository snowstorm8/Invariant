# Architecture

```
Hypothesis state machine ──▶ Engine.apply(op) ──▶ Adapter.execute(Call) ──▶ target app
   (exploration/)              │  ▲                    ▲
                               │  │                    └── probes the evaluator planned
                               │  └── ModelState (expected state, core/state.py)
                               ▼
                       Evaluator (evaluation/) ──▶ Evaluation{PASS|VIOLATION|INCONCLUSIVE}
                         plan ─▶ judge              ▲
                               │                    └── RuleCheck (properties/checks.py)
                               │                          └── rule interpreter (rules/) over the
                               │                              context a RuleBinding builds (integrations/)
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

**Rules.** What is judged is a set of rules chosen at run time (`RuleSet`), written in the rule
language as text or JSON ([rules.md](rules.md)). `rules/` parses both into one IR, validates it
against the integration's `ContextSchema`, and interprets it; it executes no user code and imports
nothing application-specific. `integrations/document_saas.py` is the `RuleBinding` for the demo's
model: it turns a step (operation, actor, policy decision, expected state, history, response) into
the values rules read. Another application supplies its own binding and schema.

**Evaluation** is *plan, probe, judge*. Each rule is presented as a `SecurityProperty`
(`properties/base.py`) by `RuleCheck`, with three pure methods: `applies(step)` (the rule's
`when`), `requires(step)` (its `observe` clauses) and `evaluate(step, response, evidence)` (its
assertions). `Evaluator()` uses the built-in rule file; `Evaluator.for_rules(ruleset)` any other set.

1. *Plan*: `Evaluator.plan` collects the probe requests of every property in scope, each once. It
   does not see the response, so the calls a scenario makes depend only on the scenario and the model.
2. *Probe*: the engine executes each request (today only `OrgSnapshot`: list an org as one of its
   members). Properties never perform I/O.
3. *Judge*: `Evaluator.judge` runs each property in scope and stamps its id on the result.

The engine also records each finished actor operation (via the binding) and passes the list to
later steps as `events`, so a rule can relate operations across a sequence.

The built-in rules (`integrations/document_saas.rules`), in evaluation order:
- *TI-1 confidentiality*: on every responded actor operation, scan the response body for markers of
  other orgs' documents. Needs no probe.
- *TI-2 / AZ-1 integrity*: for a write the policy denied, diff a snapshot of the affected org against
  the model. Two rules of the same shape; each applies when the policy decision holds a denial
  for it (an operation can be denied under both) and reports that denial's reason. Both ask for the
  same snapshot, which is taken once.

The framework owns missing evidence: no response, a 5xx, or a probe that was not taken or cannot be
parsed is `INCONCLUSIVE`, and a property is never asked to judge without the evidence it required.
A rule whose verdict depends on an undefined value (a field that is not there) is `INCONCLUSIVE` too.
By default (`strict`) these stop the run. Out of scope means no evaluation, not a `PASS`. The first
violation on a step determines how a failure is attributed, so evaluation order is observable.

Verifying *authorised* writes before committing them to the model is separate from property
evaluation and stays in the engine (see design-decisions.md).

**Reset and isolation.** Hypothesis runs one state-machine instance per example; each builds a
fresh adapter via the factory, then `Engine.reset()` calls `Adapter.reset()`, which must verify
the target is empty (the HTTP adapter checks `POST /_admin/reset` reports zero entities).

**Reproduction.** `explore()` takes the shortest violating run Hypothesis produced, minimises it
by deleting operations that are not needed for the same property to fail, then replays the result
on a fresh target and records whether it reproduced. All three steps use the same rule set, which
the report embeds (`Report.rules`) when it was chosen explicitly, so a later replay judges with it.

**Console.** `console/app.py` holds the behaviour (validate, save, import, enable, scan, replay) over
plain JSON; `console/server.py` serves it and `console.html` on loopback with the standard library.
`web_bridge.py` exposes the same operations over stdin/stdout.
