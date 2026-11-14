# Demo walkthrough

A script for showing Invariant end to end on a realistic application. It takes about five minutes.

## Before you start

```bash
.venv/bin/pip install -e '.[dev]'
.venv/bin/invariant console
```

The console opens on the **Project** tab with no application loaded.

## 1. Pick the application (Project)

Click **Choose folder…**. The operating system's folder dialog opens in `examples/`; choose
`meridian_docs`. (If the dialog is hidden behind the browser window, look for Finder or File
Explorer in the task switcher. Typing the path and pressing **Inspect** does the same.)

Invariant shows what it found in the folder's `invariant.toml`: the application's name, the exact
command it will run, how it knows the application is ready and how it resets between tests.
Nothing has run yet. Click **Open project and start the application**; the console starts it on a
free local port and moves to the Rules tab.

*What to say:* Invariant does not need the source, only a way to start the application and speak
HTTP to it. It never contacts anything but this local process.

## 2. Review the rules (Rules)

All 29 default rules are on, grouped by tag:

- **access control** (AC): cross-tenant reads and writes refused, viewers cannot write, only admins
  delete, listings and reads stay in the caller's tenant, deleted documents stay gone;
- **data exposure** (DX): no credentials in responses, no stack traces, refusals do not reveal that a
  document exists;
- **headers** (TH): nosniff, no-store, framing, referrer policy, CSP, no technology banner, no
  wildcard CORS, cookie flags, JSON served as JSON;
- **integrity** (IR): no server errors, refused writes change nothing, versions advance by one,
  reads and listings match what the model expects.

Click a rule to read it. They are written in the same language you can use to add your own
([tutorial](tutorial-rules.md)). Search, tag filters and group switches make large rule sets
manageable.

## 3. Run (Run exploration)

Keep seed `1` and `200` sequences and click **Run exploration**.

Invariant resets the application, creates two tenants and users with random roles, then performs
random sequences of creates, reads, updates, deletes and listings, judging every enabled rule after
every step. When a rule fails it finds the shortest sequence that shows it, then searches again with
that rule muted so the *other* failing rules surface too. This takes about a minute.

## 4. Read the report

The result reads "N rules violated" (about 25). Each row is a rule with severity and a *reproduced*
tag. Select one:

- **Operation sequence**: the minimal steps, in plain words, with the HTTP status of each and the
  step that broke the rule highlighted. For example the `coediting-lease` finding:

  ```
  provision org org0 · provision viewer user1 in org0 · provision member user2 in org0
  provision admin user3 in org0
  user2 creates doc4 · user3 updates doc4 · user1 updates doc4   <-- HTTP 200  (AC-3)
  ```

  A viewer changed a document, but only because an admin had just edited it: no single request
  shows this.
- **Evidence**: the data behind the verdict.
- **Replay on this build**: each finding is re-run on a fresh instance and marked reproduced.
- **Open full report**: the whole page for the selected rule, with the timeline, the evidence and
  the replay command. **Download report JSON** keeps the run.

## What to point out

- The defects are in realistic places: a cache keyed by id, a replica that is not purged, a
  collaboration window, an error page that is too helpful, a cookie without flags.
- Every finding is a minimal, deterministic sequence, not a log line.
- The verdict comes from the rules, not from the status code alone and not from an LLM.
- `PASS` would only mean "not found in the explored sequences": it is not a proof. If a rule you
  expect is missing, raise **Sequences to try**.

## Showing that the fixed build passes

Copy `examples/meridian_docs`, add `env = { MERIDIAN_FLAGS = "none" }` under `[run]` in the copy's
`invariant.toml`, and open the copy. The same rules, seed and sequence count report `PASS`.

## Troubleshooting

| Symptom | Fix |
|---|---|
| No folder dialog appears | Look for it behind the browser window, or type the path and click **Inspect**. |
| "has no invariant.toml" | You chose a parent or child folder; choose the one containing the file. |
| "did not answer /healthz" | The application failed to start; the console shows its output. Check its dependencies (`pip install -e '.[demo]'`). |
| Fewer rules than expected | Raise **Sequences to try**; deep defects need more search. Use the same seed to compare runs. |
| A rule you wrote is `INCONCLUSIVE` | It reads a value that is sometimes absent; see [tutorial, section 6](tutorial-rules.md#6-undefined-values-and-inconclusive). |
