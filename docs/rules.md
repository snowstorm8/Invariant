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
| `id "X"` | Id used in reports. Defaults to the name. Must be unique. |
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
operations of the run with their responses), `response` (status, body, decoded JSON), and the probe
`org_documents(org)`.

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
