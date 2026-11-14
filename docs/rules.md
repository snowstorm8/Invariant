# Writing rules

A rule states what the application must always or never do. Rules are data: they are written in
the console (or uploaded as JSON), validated, and handed to the exploration engine at run time.
No Python is written or executed for a rule.

```
rule "read-returns-own-tenant" {
    description "A successful read must return a document of the reader's organization."
    severity critical

    when operation.type == "read_document"

    always response.status == 200 implies response.json.org_id == actor.org_id

    message "{actor.ref} ({actor.org}) was served a document owned by {response.json.org_id}"
}
```

## Clauses

| Clause | Meaning |
|---|---|
| `rule "name" { ... }` | Name: 1-64 letters, digits, `.`, `_`, `-`. |
| `id "X"` | Id used in reports. Must be unique. Without it the console assigns one of the form `AA-11` derived from the name (see [Rule ids](#rule-ids)); the command line uses the name. |
| `tags "a", "b"` | Labels (lower-case letters, digits, `_ . -`; up to 12). The console groups, filters and bulk-switches rules by tag; the first tag is the group. They never affect a verdict. |
| `policy "KEY"` | The reference policy's name for this rule, when it differs from `id`. The core rules read `policy.denials["TI-2"]`; that key stays put when the rule's id is renamed. Omit it unless the policy names the rule. |
| `description "..."` | What must never happen, in words. Shown in reports. |
| `severity critical\|high\|medium\|low\|info` | Default `medium`. |
| `when <condition>` | Which operations the rule covers. Decided *before* the response, so it cannot use `response` or an observation. Omit it to cover every operation. |
| `let name = <expression>` | A named value. Evaluated on first use. |
| `observe name = probe(args)` | Application state after the operation, taken by the integration. |
| `always <condition>` (alias `assert`) | Must hold. |
| `never <condition>` | Must not hold. |
| `message "..."`, `pass_message "..."` | Text of the finding / of a pass. `{expression}` is interpolated; `{{` is a literal brace. |
| `evidence { key: <expression>, ... }` | Evidence attached to a violation. |

Without `message`/`evidence`, a violation explains itself: the failed assertion and the value of
every field it read.

## Expressions

- Operators, loosest first: `implies`, `or`, `and`, `not`, `== != < <= > >= in` (and `not in`),
  `+ -`, `*`, unary `-`.
- Access: `actor.role`, `policy.denials["TI-2"]`, `events[0]`.
- Quantifiers: `some x in xs : cond`, `every x in xs : cond`, `none x in xs : cond`.
- Comprehension: `[d.ref for d in state.documents where d.org != actor.org]`.
- Literals: `"text"`, `'text'`, `42`, `1.5`, `true`, `false`, `null`, `[1, 2]`, `{key: value}`.
- Functions: `has coalesce count contains startswith endswith lower upper str join first last
  distinct keys values sum min max diff`. The list is closed.
- Comments: `#` or `//` to end of line.

**Undefined.** Reading something that is not there (a field the response does not carry, the
`resource` of a create) is *undefined*, not false. `and`/`or`/`implies` ignore an undefined operand
when it cannot change the result; otherwise the rule is `INCONCLUSIVE`, never `PASS`. Say when a
field is expected with `has(x)`, `coalesce(a, b)` or `<condition> implies <requirement>`.

## What rules can refer to

That is decided by the integration, not the language. Each integration publishes a
`ContextSchema` (`rules/types.py`) and builds the values through a `RuleBinding`
(`rules/binding.py`). The console shows the schema of the current target under *Reference*.

For the document SaaS (`integrations/document_saas.py`): `operation` (type, inputs), `actor`
(identity, role, permissions), `resource` (the targeted document as the model expects it),
`policy` (the reference policy's ruling), `state` (expected application state), `events` (earlier
operations of the run with their responses), `response` (status, body, decoded JSON, **headers**,
**cookies**, and the **request** it answers), and the probe `org_documents(org)`.

`response.headers` is a map by lower-case name; a header that was not sent is undefined, so test it
with `has(...)` or `coalesce(...)`:

```
always lower(coalesce(response.headers["x-content-type-options"], "")) == "nosniff"
always every c in response.cookies : c.http_only and c.secure
```

Each cookie has `name`, `secure`, `http_only`, `same_site` (lower-case, empty if absent), `path`,
`domain`, `persistent` and `raw`.

Sequences are expressed over `events`:

```
when operation.type == "read_document"
    and some e in events : e.operation.type == "delete_document"
        and e.operation.target == operation.target and e.policy.allowed
never contains(response.body, resource.marker)
```

## JSON

A JSON file is `{"version": 1, "rules": [...]}`, a list of rules, or one rule. It builds the same
internal representation as the text, so both behave identically.

```json
{"name": "read-returns-own-tenant", "severity": "critical",
 "when": {"==": [{"ref": "operation.type"}, {"value": "read_document"}]},
 "assert": [{"always": {"implies": [
     {"==": [{"ref": "response.status"}, 200]},
     {"==": [{"ref": "response.json.org_id"}, {"ref": "actor.org_id"}]}]}}],
 "message": "{actor.ref} was served a document owned by {response.json.org_id}"}
```

Expression objects have one operator key: `value`, `ref`, `field`+`of`, `index`, `list`, `record`,
`not`, `neg`, `and`, `or`, `implies`, the comparison and arithmetic operators, `call`+`args`,
`some|every|none`+`in`+`where`, `collect`+`for`+`in`+`where`. Numbers, booleans and `null` stand
for themselves. A **string** in an expression position is rule-language source
(`"actor.role == 'viewer'"`); a string literal is `{"value": "viewer"}`. Shorthands: `"let"`,
`"observe"`, `"always"`, `"never"` instead of `"bindings"` / `"assert"`; `"enabled": false`.
The console's *JSON* view shows any valid rule in this format.

## Where rules run

- **Console** (`invariant console`): create, edit, validate, upload, enable/disable, run, replay.
  Rules are kept in `.invariant/rules.json`.
- **CLI**: `invariant explore TARGET --rules my.rules --rules team.json [--no-builtin]`.
- **Web bridge**: `{"action": "scan", "rules": [...], "builtin_rules": [...]}`.
- **Python**: `explore(factory, rules=RuleSet.from_text(source, SCHEMA))`.

A report records the rule set it was judged with; `replay` re-applies exactly those rules.

## Rule ids

A rule written without an `id` is given one in the form `AA-11` (two letters, a dash, two digits)
derived from its **name** alone, so the same name always gives the same id. The console's
**Settings** tab chooses the algorithm, with a preview of what each would rename:

| Algorithm | Letters | Digits | `tenant-read-isolation` |
|---|---|---|---|
| `initials` (default) | first letters of the first two words | letter count of the name | `TR-19` |
| `consonants` | first two consonants | sum of letter values | `TN-16` |
| `edges` | first letter of the first and last word | position-weighted checksum | `TI-55` |
| `crc32` | from a CRC-32 of the name | from the same CRC-32 | `BS-94` |
| `sha256` | from a SHA-256 of the name | from the same SHA-256 | `LR-29` |

If the id is taken, the next free one after it is used (counting through the digits, then the
letters). **Saving** a choice renames *every* rule to match, built-in ones included: the console
shows the old and the new id first. Applying the same algorithm again changes nothing. A built-in
rule keeps its shipped id as its key and as its `policy` key, so the reference policy, saved
switches and replay are unaffected; only the id shown in findings changes. Reports saved earlier
keep the ids they were made with. The code is `rules/ids.py`.

## The default rule library

`integrations/web_defaults.rules` ships 26 rules for web applications next to the three core ones,
all enabled in the console and grouped by their first tag:

| Group | Ids | What they check |
|---|---|---|
| `access-control` | AC-1 to AC-7 | cross-tenant reads and writes are refused, viewers cannot write, only admins delete, reads and listings stay in the caller's tenant, deleted documents stay gone |
| `data-exposure` | DX-1 to DX-3 | no credentials in responses, no stack traces or database detail in errors, refusals do not reveal that a document exists or who owns it |
| `headers` | TH-1 to TH-11 | nosniff, no-store, framing, referrer policy, CSP, no technology banner, no wildcard CORS with credentials, cookies are HttpOnly / Secure / SameSite, JSON is served as JSON |
| `integrity` | IR-1 to IR-5 | no server errors, refused writes change nothing, update bumps the version by one, reads and listings match the model |

Each must hold on the fixed demo build, so a failure means the application is wrong. The demo
app's `missing-security-headers` and `verbose-errors` switches exist to show the header and
data-exposure rules firing. From the command line the library is opt-in: `--library` (the console
turns it on).
