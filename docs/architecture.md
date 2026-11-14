# Architecture

```
console (browser) ──▶ console/app.py ──▶ explore() ─────────────────────────────────────┐
  Project · Rules · Run · Settings          │                                              │
        │                                   ▼                                              │
        └─ project.py ─ starts app    Hypothesis state machine ──▶ Engine.apply(op)        │
           (invariant.toml), dialogs.py   (exploration/)               │  ▲                │
                                                                       │  └ ModelState     │
                                          Adapter.execute(Call) ◀──────┘    (core/state.py)│
                                                 │                                          │
                                       target application (real HTTP)                      │
                                                 │                                          │
                          Evaluator (evaluation/) ◀── response + probes                    │
                            plan ─▶ probe ─▶ judge ──▶ Evaluation{PASS|VIOLATION|INCONCLUSIVE}
                                 │                                                          │
                 RuleCheck (properties/checks.py) ─ rule interpreter (rules/)               │
                   over the context a RuleBinding builds (integrations/)                    │
                                                                                            │
   violation ──▶ RunFailure ──▶ minimize ──▶ replay ──▶ Report (JSON / text / HTML) ◀───────┘
```

## Operations and the expected-state model

**Operations** (`core/scenario.py`) are symbolic and serialisable: `org0`, `user1`, `doc2`, never
real ids or tokens, so a scenario replays on any instance. The engine resolves refs to credentials
and ids and builds an adapter `Call`. The operations are *create org*, *create user* (setup), and
*create / read / update / delete / list document* by an actor.

**Expected state** (`ModelState`) holds orgs, users (org, role) and documents (owner org, content,
version, deleted). It is updated only from operations the reference policy authorised, so it
represents what the target *should* contain. Every write embeds a marker `<<INV:n>>`, unique per
step, in the stored content; seeing a foreign document's marker in a response proves that data was
disclosed, whatever the status code or response shape.

**Verified commits.** After an authorised write the engine lists the actor's own organization and
compares it with the snapshot the model predicts. Only a match updates the model; a mismatch stops
the run as `INCONCLUSIVE`, never as a violation (see [design-decisions.md](design-decisions.md)).

## Exploration

`exploration/state_machine.py` is a Hypothesis `RuleBasedStateMachine` with bundles of orgs, users
and documents. It chooses *which operation with which arguments*; it never looks at a response.
Hypothesis' own shrinking is disabled (`Phase.generate`); `analysis/minimizer.py` does deterministic,
property-aware reduction afterwards. A seed makes the search repeatable.

Each Hypothesis example builds a fresh adapter from the factory and calls `Engine.reset()`, which
calls `Adapter.reset()`; the HTTP adapter verifies the reset endpoint reports zero entities. For a
project the adapter is a thin view of the one running process (reset between examples), so closing
an adapter never stops the application.

## Rules and evaluation

What is judged is a set of rules chosen at run time (`RuleSet`), written in the rule language as
text or JSON ([rules.md](rules.md)). `rules/` parses both into one immutable IR, validates it
against the integration's `ContextSchema`, and interprets it with a three-valued (Kleene) logic. It
executes no user code and imports nothing application-specific. `integrations/document_saas.py` is
the `RuleBinding` for the document contract: it turns a step (operation, actor, policy decision,
expected state, history, response with headers and cookies) into the values rules read. Another
application type supplies its own binding and schema.

Evaluation is *plan, probe, judge*. `RuleCheck` presents each rule as a `SecurityProperty` with
three pure methods: `applies(step)` (the rule's `when`), `requires(step)` (its `observe` clauses)
and `evaluate(step, response, evidence)` (its assertions). `Evaluator.for_rules(ruleset)` judges
any set.

1. *Plan*: collect the probe requests of every rule in scope, each once. Planning never sees the
   response, so the calls a scenario makes depend only on the scenario and the model.
2. *Probe*: the engine performs each request (today `org_documents`: list an org as one of its
   members). Properties never perform I/O.
3. *Judge*: run each rule in scope and stamp its id on the result.

The engine records each finished actor operation (through the binding) and hands the list to later
steps as `events`, so a rule can relate operations across a sequence.

The framework owns missing evidence: no response, a 5xx, a transport error, a probe that was not
taken or cannot be parsed is `INCONCLUSIVE`, and a rule whose verdict depends on an undefined value
is `INCONCLUSIVE` too. Out of scope means no evaluation, not a `PASS`. By default (`strict`) an
inconclusive step stops the run.

## Reporting every failing rule

A step is judged by all rules in scope, and a run stops at the first failing step, so one search
can only see the rules that fail there. `explore` therefore repeats the search. After a round
fails, every rule that failed is *muted* (`Evaluator.muting`): still evaluated, so probes and
denial coverage do not change, but no longer failing the run. Rounds repeat, with the same seed,
until one finds nothing new or every rule has been reported.

Whether a muted violation also ends the generated sequence (`Engine.muted_violation`) depends on
whether it may have left the model and the target disagreeing (`Engine._may_diverge`):

| Muted violation on... | Sequence continues? |
|---|---|
| a read, a listing, or any step, about a header, a cookie, a status or a body | yes: state is untouched |
| a rule that probes state (`observe`) | no: the model may be wrong now |
| a write the policy forbids that went through | no |
| a write that failed with a server error, or could not be verified | no |

This is what lets the search keep going past, for instance, missing headers on every error
response and still reach a defect that needs ten more steps. Each failed rule is minimised and
replayed on its own (every other rule muted) and appears in `Report.findings` with its own
`scenario`, `steps` and `reproduced`; `finding`, `scenario` and `steps` repeat the first. The cost is
one more search per round, and a rule that fails only in long sequences needs a larger
`--max-examples`.

Every step also counts, per rule, the `PASS` evaluations (`ExplorationSink.held`); `explore` keeps
the largest count across rounds and the report carries it as `Report.held`. The console's *Passed
rules* card is the enabled rules that did not fail, split into those that held on at least one step
and those that were never in scope.

## Reproduction and reports

`explore()` takes the shortest violating run for each rule, minimises it by deleting operations
that are not needed for the same rule to fail, then replays the result on a fresh target and
records whether it reproduced. All three steps use the same rule set, which the report embeds
(`Report.rules`) so that a later `replay` judges with exactly those rules. Reports are
JSON (`reporting/models.py`), text, or a self-contained HTML page (`reporting/viewer.html`) that
shows the selected rule, its timeline, evidence and the replay command.

## Console and projects

`console/app.py` holds all behaviour over plain JSON; `console/server.py` serves it and
`console.html` on loopback with the standard library (it answers only loopback host names and
same-origin JSON). The pieces:

- **Rule store** (`store.py`): rules you create or import, kept in `.invariant/rules.json` with
  their enabled switches and the id algorithm. The shipped rules are offered next to them, keyed
  `builtin:<shipped id>`; their displayed id follows the chosen algorithm while their `policy`
  key stays fixed.
- **Projects** (`project.py`): `load_manifest` reads and validates `invariant.toml` (running
  nothing); `RunningProject` starts the command from the project folder on a free loopback port with
  a minimal environment, waits for the health path, offers a shared `HttpAdapter` for it and stops it
  on close. Applications are always started by an explicit action in the console.
- **Folder dialog** (`dialogs.py`): the console server opens the operating system's own folder
  chooser (AppleScript on macOS, PowerShell on Windows, zenity or kdialog elsewhere). Without one,
  the console falls back to a path field.
- **Targets** (`target.py`): `ConsoleTarget` is what the console needs from an application (name,
  adapter factory, optional switchable builds, binding, close hook). The built-in demo and every
  project produce one.
- **Endpoints**: `/api/bootstrap`, rules (`/api/rules`, import, export, enabled, enabled-many,
  delete), `/api/validate`, `/api/settings` (+ preview), `/api/project` (+ pick, inspect, open,
  close), `/api/scan`, `/api/replay`, `/api/report-html`.
- One exploration runs at a time; rule edits are serialised.

`web_bridge.py` exposes the same operations over stdin/stdout for other front ends.

## The demo applications

`examples/vulnerable_saas` is a small in-process FastAPI service with five switchable defects,
used by the tests and `scripts/demo.sh`. `examples/meridian_docs` is a larger service with a normal
package structure (state, service layer, security, routes) and thirteen release-flagged defects; it
runs as its own process, started from its `invariant.toml`. Both speak the document contract.
