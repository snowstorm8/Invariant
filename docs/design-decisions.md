# Design decisions and known limitations

## Decisions

- **Hypothesis chooses operations; rules decide verdicts.** Hypothesis only picks which operation to
  try and with which arguments. Every security verdict comes from `SecurityProperty.evaluate`,
  run by `evaluation/`, and is deterministic and pure: a property does no I/O and declares the probes
  it needs. There is no LLM in the evaluation path, and a verdict is never decided from an HTTP
  status alone.
- **Hypothesis shrinking is disabled** (`Phase.generate` only). Stateful shrinking is heuristic and
  slow; `analysis/minimizer.py` does deterministic, property-aware deletion instead. The result is
  1-minimal, not globally minimal.
- **Verified state transitions.** After an authorised write the engine lists the actor's own org and
  compares it with the snapshot the model predicts after the change (2xx: the change; otherwise: no
  change). Only a match updates the model. A mismatch or unusable probe stops the run as
  `INCONCLUSIVE`, never as a violation. Cost: one extra request per authorised write. Residual risk:
  the verification trusts the listing endpoint; a target whose listing and storage disagree
  consistently would pass.
- **Rules are interpreted, never executed.** A rule is parsed into an IR and walked by
  `rules/interpreter.py`: no `eval`, no attribute access on Python objects, a closed function table,
  and a step budget per rule per step (exceeding it is `INCONCLUSIVE`). `rules/` is
  application-agnostic and imports nothing from the engine, properties, adapters or integrations.
- **Missing is not false.** A value a rule needs but cannot find is *undefined*, and a verdict that
  depends on it is `INCONCLUSIVE`. Missing observations, 5xx responses and transport errors are
  `INCONCLUSIVE`, never `PASS`.
- **`when` cannot see the response.** Scope and probe arguments are decided before the target
  answers, so the calls a scenario makes do not depend on the response being judged. They may
  depend on earlier responses through `events`. Response conditions go in the assertion (`implies`).
- **An `observe` clause takes one probe with arguments known up front**; a rule cannot probe once
  per element of a list.
- **Every failing rule is reported.** A search stops at the first failing step, so `explore`
  repeats it with already-reported rules muted. Muting keeps a rule evaluated; whether a muted
  violation ends the generated sequence depends on whether it may have desynchronised model and
  target (`Engine._may_diverge`, [architecture.md](architecture.md)). Header or status violations
  do not end it, so the search can reach deeper defects past them.
- **Only authorised operations update the model.** The expected-state model represents what the
  application *should* contain, never what it happened to do.
- **Scenarios are symbolic** (`org0`, `user1`, `doc2`), never app ids or tokens, so they replay.
- **Applications are tested as processes.** A project's application is started from its
  `invariant.toml` as a local process with a minimal environment and tested over real HTTP; it is
  reset before every sequence. Nothing starts without an explicit action, and only `127.0.0.1` is
  contacted. One connection pool serves the whole run, with idle connections dropped before a
  server's keep-alive timeout.
- **The console is single-user and local.** It binds to loopback, refuses other Host names and
  cross-origin requests, accepts only JSON, and runs one exploration at a time. The folder dialog is
  opened by the console server because a web page cannot read a folder path.
- **Rule ids are deterministic.** A rule without an `id` gets `AA-11` from its name by a chosen
  algorithm; renaming rules to match is explicit (Settings). A built-in rule keeps its shipped id as
  its key and policy key, so the reference policy is unaffected.

## Known limitations

- **Bounded, randomized search.** `PASS` means no violation was found in the explored sequences;
  it is not a proof. Deep defects need more sequences. At the default 200 the enterprise demo
  reports about 25 of its rules; the exact count varies a little between runs.
- **Confidentiality detection relies on markers** the engine writes into content. It cannot see
  leaks of data it did not plant (ids, metadata, user names) except through rules that look for them
  explicitly (for example `DX-1` for credential fields).
- **Fixed topology**: two organizations, any number of users with random roles, documents. No
  sharing, invitations, role changes or token revocation operations yet; defects in those layers are
  reachable only through the five document operations.
- **One integration.** Only the document contract (`document-saas`) is supported. A different
  application type needs its own `RuleBinding`, schema and operations.
- **Integrity checks cover denied writes.** Properties see the model as it was before the
  operation, which is the right expectation only when nothing should have changed.
- **The folder dialog needs a desktop.** macOS, Windows, and Linux with zenity or kdialog; otherwise
  the path field is used.
- **Seeded runs** use `hypothesis.stateful.get_state_machine_test`, which is not a documented API.
- **The in-process demo** uses Starlette's `TestClient`, which warns that it prefers `httpx2`
  (suppressed in the pytest config). `HttpAdapter` accepts any `httpx.Client`.
- **The examples are insecure on purpose.** Never deploy `vulnerable_saas` or `meridian_docs`.
