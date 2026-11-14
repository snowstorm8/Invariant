# Tutorial: writing rules

This tutorial teaches the rule language by building rules, from a three-line check to rules that
look across a whole sequence of operations. It assumes nothing except that you can read code. The
[rules reference](rules.md) is the complete specification; this is the guided route.

Every complete rule in a `rule` block below is validated against the document-service schema by the
test suite (`tests/unit/test_docs_rules.py`), so what you read here is what runs.

Contents: [1 What a rule is](#1-what-a-rule-is) · [2 Your first rule](#2-your-first-rule) ·
[3 Scoping with `when`](#3-scoping-with-when) · [4 `always`, `never` and `implies`](#4-always-never-and-implies) ·
[5 What a rule can see](#5-what-a-rule-can-see) · [6 Undefined values](#6-undefined-values-and-inconclusive) ·
[7 Lists, `let` and functions](#7-lists-let-and-functions) · [8 Messages and evidence](#8-messages-and-evidence) ·
[9 State: `observe`](#9-state-after-the-operation-observe) · [10 Sequences: `events`](#10-sequences-events) ·
[11 Headers and cookies](#11-headers-and-cookies) · [12 Testing a rule](#12-testing-your-rule) ·
[13 JSON, ids, tags](#13-json-ids-tags-and-severity) · [14 Exercises](#14-exercises) · [15 Cheat sheet](#15-cheat-sheet)

## 1 What a rule is

A rule states something your application must **always** or **never** do. Invariant does not run
your rule once. It generates many sequences of operations (users of different roles in different
organizations creating, reading, updating, deleting and listing documents) and, after **every
step** of every sequence, asks each rule: *did the application just break you?*

For one step the rule gives one of three answers:

| Verdict | Meaning |
|---|---|
| `PASS` | The rule applied to this step and held. |
| `VIOLATION` | The rule applied and was broken. This is a finding. |
| `INCONCLUSIVE` | The rule applied but could not be decided (a value it needed was missing, the server crashed, ...). Never counted as a pass. |

A step the rule does not cover (its `when` is false) is simply out of scope.

Rules are **data**. They are parsed and interpreted, never executed as code, so a rule cannot
touch your machine, and the same rule behaves the same way every time.

## 2 Your first rule

Start Invariant's console, open a project (see [projects.md](projects.md)) and go to the **Rules**
tab. Choose **+ New rule** and replace the template with:

```rule
rule "viewers-cannot-write" {
    description "A viewer must never be able to change a document."
    severity high

    when operation.is_write and actor.role == "viewer"
    never response.status < 300

    message "{actor.ref} is a viewer but got HTTP {response.status} for {operation.type}"
}
```

Read it aloud: *for every write by a viewer, the response status must never be below 300.*

- `rule "name" { ... }` wraps everything. The name is 1-64 letters, digits, `.`, `_`, `-`.
- `description` and `severity` (`critical`, `high`, `medium`, `low`, `info`) are shown in reports.
- `when` picks the steps the rule is about.
- `never` is the requirement, here that the condition is **false**.
- `message` is the text of a finding. `{...}` inserts the value of an expression.

While you type, **Ctrl+Space** suggests fields, functions and clauses, and the status line under
the editor says *valid* once the rule can run (or points at the line that is wrong). **Save**,
then open **Run exploration** and run. On an application where viewers can write, you get a
`VIOLATION` with the shortest operation sequence that shows it, for example:

```
provision org org0
provision viewer user user1 in org0
provision member user user2 in org0
provision admin user user3 in org0
user2 creates doc4
user3 updates doc4
user1 updates doc4       <-- HTTP 200
```

(This is what Invariant reports for the `coediting-lease` defect of the Meridian Docs demo: an edit
by a writer opens a co-editing window in which the next writer's role is not checked.)

Those lines are a *scenario*. It is symbolic (`org0`, `user1`, `doc0`: never real ids or tokens),
so Invariant can replay it on a fresh instance to confirm the finding.

## 3 Scoping with `when`

Without `when` a rule covers every operation. With it, the rule only looks at steps where the
condition holds. `when` is decided **before** the application answers, so it can use the
operation, the actor, the targeted resource, the policy and the history, but not `response`.

```rule
rule "only-admins-delete" {
    description "Only an admin may delete a document."
    severity high
    when operation.type == "delete_document" and actor.role != "admin"
    never response.status < 300
    message "{actor.role} {actor.ref} deleted {operation.target} (HTTP {response.status})"
}
```

Operations are `create_document`, `read_document`, `update_document`, `delete_document` and
`list_documents`; `operation.is_write` is true for the first, third and fourth. Roles are `admin`,
`member`, `viewer`.

Why can't `when` see the response? The calls Invariant makes for a scenario must depend only on the
scenario, not on how the application happened to answer. Put conditions about the answer in the
assertion, using `implies` (next section).

## 4 `always`, `never` and `implies`

- `always C`: the condition `C` must be **true**.
- `never C`: the condition `C` must be **false**. `never C` is the same as `always not C`.
- `A implies B`: if `A` is true, `B` must be true; if `A` is false the whole thing holds.

`implies` is how you say "if it succeeded, then it must have ...":

```rule
rule "read-returns-own-tenant" {
    description "A successful read returns a document of the reader's organization."
    severity critical
    when operation.type == "read_document"
    always response.status == 200 implies response.json.org_id == actor.org_id
    message "{actor.ref} ({actor.org}) was served a document owned by {response.json.org_id}"
}
```

Conditions combine with `and`, `or`, `not` and compare with `== != < <= > >=`; `in` / `not in`
test membership. Precedence, loosest first: `implies`, `or`, `and`, `not`, comparisons, `+ -`,
`*`, unary `-`. Use parentheses when in doubt. A rule may have several `always`/`never` lines; all
must hold.

**Never decide on the status code alone.** `response.status < 300` says an operation was
*accepted*, which is only a violation when the policy said it should be refused. That is why the
rules above first narrow the scope (`when`) to cases that must be refused. A bare "status is 200"
check is a weak rule; look at what came back.

## 5 What a rule can see

Everything a rule can name comes from a few roots. The console lists them with types under
**Reference** (with fields you can click to insert).

| Root | What it is | Fields |
|---|---|---|
| `operation` | the step | `type`, `is_write`, `target` (the document ref), `input.content` |
| `actor` | who performed it | `ref`, `id`, `org`, `org_id`, `role`, `permissions` |
| `resource` | the targeted document as the model expects it | `ref`, `id`, `org`, `org_id`, `content`, `marker`, `version`, `deleted` |
| `policy` | what the reference policy says | `allowed`, `reason`, `denials[...]` |
| `state` | the whole expected state | `orgs`, `users`, `documents`, `expected_listing` |
| `events` | earlier steps of this run, with their responses | see [section 10](#10-sequences-events) |
| `response` | what the application answered | `status`, `body`, `excerpt`, `json`, `headers`, `cookies`, `request` |

Notes:

- `actor.org` / `resource.org` are the symbolic org refs (`org0`); `org_id` is the application's id.
  Compare refs with refs and ids with ids.
- `resource.marker` is a unique token the engine writes into every document's content. Finding
  another tenant's marker in a response proves data was disclosed, whatever the response looks like.
- `response.json` is the decoded body; it is undefined when the body is not JSON.
- `response.headers` is a map keyed by lower-case header name.
- Use `policy.allowed` to ask "should this have been permitted?" instead of re-implementing the
  authorization rules.
- Nested access uses dots and brackets: `response.json.org_id`, `policy.denials["TI-2"]`,
  `events[0]`.

## 6 Undefined values and `INCONCLUSIVE`

Reading something that is not there (a JSON field a 404 body does not have, `resource` on a
`create_document`) gives **undefined**, not `false`. Undefined is contagious: if a rule's verdict
depends on an undefined value, the verdict is `INCONCLUSIVE`, never `PASS`. (`and`, `or` and
`implies` ignore an undefined operand when the other operand already decides the result.)

This rule has a bug:

```text
always response.json.version > 0
```

On a `404` there is no `json.version`, so the rule is `INCONCLUSIVE` on every error response.
Say when the field is expected:

```rule
rule "versions-start-at-one" {
    description "A returned document has a positive version."
    severity low
    when operation.type == "read_document"
    always response.status == 200 implies response.json.version >= 1
}
```

Three tools handle absence:

| Tool | Use |
|---|---|
| `has(x)` | true if `x` exists: `has(response.headers["server"])` |
| `coalesce(a, b, ...)` | the first value that exists: `coalesce(response.headers["server"], "")` |
| `A implies B` | only require `B` when `A` says it should be there |

Missing evidence in the wider sense (no response, a 5xx, a failed transport) is also
`INCONCLUSIVE`. A run that hits it stops and says so rather than guess.

## 7 Lists, `let` and functions

**Quantifiers** test every element of a list: `some x in xs : cond`, `every x in xs : cond`,
`none x in xs : cond`.

```rule
rule "listing-is-tenant-scoped" {
    description "A listing contains only the caller's own organization's documents."
    severity critical
    when operation.type == "list_documents"
    always response.status == 200 implies
        none d in response.json : d.org_id != actor.org_id
}
```

**Comprehensions** build a list: `[expression for x in xs where condition]`. **`let`** names a
value so you can reuse it. It is evaluated when first used:

```rule
rule "listing-shows-no-foreign-documents" {
    description "Same check as above, but reporting which documents leaked."
    severity critical
    when operation.type == "list_documents"
    let foreign = [d.id for d in response.json where d.org_id != actor.org_id]
    always response.status == 200 implies count(foreign) == 0
    message "{actor.ref} saw documents of other organizations: {join(foreign, ', ')}"
}
```

**Functions** form a closed list (a rule can never call anything else):

| Function | Result |
|---|---|
| `has(x)`, `coalesce(a, b, ...)` | presence (section 6) |
| `count(x)` | number of items / characters / keys |
| `contains(haystack, needle)` | substring, list item or map key |
| `startswith(t, p)`, `endswith(t, s)` | text tests |
| `lower(t)`, `upper(t)`, `str(x)` | text conversion |
| `join(list, sep)` | text from a list |
| `first(list)`, `last(list)`, `distinct(list)` | list helpers |
| `keys(map)`, `values(map)` | map helpers |
| `sum(list)`, `min(list)`, `max(list)` | numbers |
| `diff(expected, observed)` | the differences between two listings, as text |

Literals: `"text"` or `'text'`, `42`, `1.5`, `true`, `false`, `null`, `[1, 2]`, `{key: value}`.
Comments start with `#` or `//`.

A rule for secrets that must never be echoed back:

```rule
rule "no-credentials-in-responses" {
    description "Responses never carry tokens, passwords or secrets."
    severity critical
    never has(response.json.token) or has(response.json.password)
        or has(response.json.secret) or has(response.json.api_key)
    message "a response carried a credential-like field"
}
```

## 8 Messages and evidence

Without `message`, a violation explains itself: the failed assertion and the value of every field
it read. Write your own when you can say it better:

- `message "..."` is the finding text; `pass_message "..."` is the text of a pass.
- `{expression}` inserts a value; write `{{` for a literal brace.
- `evidence { name: expression, ... }` attaches data to a violation (shown in the report's
  *Evidence* panel):

```rule
rule "marker-never-leaves-its-tenant" {
    description "Another organization's data never appears in a response."
    severity critical
    let leaked = [
        {doc: d.ref, owner: d.org}
        for d in state.documents
        where d.org != actor.org and contains(response.body, d.marker)
    ]
    never count(leaked) > 0
    message "{actor.ref} ({actor.org}) received data of {count(leaked)} foreign document(s)"
    evidence { leaked: leaked, status: response.status, excerpt: response.excerpt }
}
```

This rule is independent of status codes and response shape: it finds the data itself.

## 9 State after the operation: `observe`

Some promises are about what the operation **did**, not what it answered: a refused write must
leave everything unchanged. `observe` asks the integration for the application's state after the
step (a *probe*), which the rule can compare with what the model expects.

```rule
rule "refused-writes-change-nothing" {
    description "A write the policy forbids leaves the affected organization as expected."
    severity critical
    when operation.is_write and not policy.allowed
    let org = coalesce(resource.org, actor.org)
    observe listing = org_documents(org)
    let differences = diff(state.expected_listing[org], listing)
    never count(differences) > 0
    message "a refused {operation.type} changed {org}: {join(differences, '; ')}"
    pass_message "state of {org} unchanged after a refused {operation.type}"
}
```

- `org_documents(org)` lists the organization's documents (content and version) as one of its own
  members, after the operation.
- `state.expected_listing[org]` is what the model says that listing should be.
- `diff(...)` returns the differences as text; none means the application did nothing.

A probe is requested before the response is seen, so its arguments must be known up front (an
`observe` cannot probe once per element of a list), and `when` cannot use its result.

## 10 Sequences: `events`

`events` is the list of earlier steps of the current sequence, each with `operation`, `actor`,
`resource`, `policy` and `response`. It lets a rule relate steps, which is how bugs that need a
history are caught:

```rule
rule "deleted-documents-stay-gone" {
    description "After a document was deleted, no later read of it succeeds."
    severity high
    when operation.type == "read_document"
        and some e in events :
            e.operation.type == "delete_document"
            and e.operation.target == operation.target
            and e.policy.allowed and e.response.status < 300
    never response.status < 300 or contains(response.body, resource.marker)
    message "{operation.target} was deleted earlier, yet a read answered {response.status}"
}
```

`events` only holds steps that happened **before** this one, so `when` may use it (it is already
known). The rule above fires on a read after a successful, permitted delete of the same document.
Such a defect (a cache or replica that outlives its source) cannot be found by testing single
requests.

## 11 Headers and cookies

`response.headers` maps lower-case header names to text. A header that was not sent is undefined,
so use `has` or `coalesce`:

```rule
rule "content-type-sniffing-disabled" {
    description "Responses send X-Content-Type-Options: nosniff."
    severity medium
    tags "headers"
    always lower(coalesce(response.headers["x-content-type-options"], "")) == "nosniff"
}
```

`response.cookies` lists the cookies the response sets. Each has `name`, `secure`, `http_only`,
`same_site` (lower-case, empty when absent), `path`, `domain`, `persistent` and `raw`:

```rule
rule "cookies-are-http-only" {
    description "Every cookie a response sets is HttpOnly."
    severity high
    tags "headers", "cookies"
    always every c in response.cookies : c.http_only
    message "cookies without HttpOnly: {join([c.name for c in response.cookies where not c.http_only], ', ')}"
}
```

Over an empty list `every` holds, so a response that sets no cookie passes.

## 12 Testing your rule

A rule can be wrong in two ways, and you should check both:

1. **False alarms.** Run it against a build you believe is correct (for the demo apps, the fixed
   build: `MERIDIAN_FLAGS=none` in the manifest, or every defect switched off). It must `PASS`. A
   violation there means the rule is wrong, not the application.
2. **Missed bugs.** Run it against a build with a defect it should catch. If it passes, widen the
   `when`, or run more sequences (`Sequences to try`): deep bugs need more search.

Habits that help:

- Start with `when` narrow and `message` precise, so a finding is understandable at a glance.
- Remember `INCONCLUSIVE` is information: it tells you a field you used is sometimes absent.
- Read the **Evidence** panel and the replay: the reported sequence is minimal; each step is needed.
- Disable rules you are not working on (search, filter by tag, or switch a whole group off) to
  keep runs short.
- Common mistakes: comparing a ref to an id (`actor.org == resource.org_id`), using `response` in
  `when`, forgetting `implies` before reading a field that only exists on success, and treating
  a 2xx as a violation without first scoping to operations that must be refused.

## 13 JSON, ids, tags and severity

Everything above also exists as JSON, so rules can be generated or shared as files. Upload it from
the **Rules** tab, or pass it with `--rules`. The console's *JSON* view shows any valid rule in this
format. See [rules.md](rules.md#json).

Optional clauses:

```rule
rule "cross-tenant-read-denied" {
    id "AC-1"
    tags "access-control", "tenancy"
    policy "TI-1"
    description "Reading another organization's document must be refused."
    severity critical
    when operation.type == "read_document" and has(resource) and resource.org != actor.org
    never response.status < 300
}
```

- `id` is what reports show. Leave it out and the console assigns one of the form `AA-11` from
  the name (algorithm chosen under **Settings**, see [rules.md](rules.md#rule-ids)).
- `tags` group and filter rules in the console; the first tag is the group. They never change a
  verdict.
- `policy` links the rule to a denial key of the reference policy; you rarely need it.

## 14 Exercises

Try each before opening the solution. Test it on a build with the matching defect and on a fixed
build.

**A.** A document's version must never go backwards: after an update, the returned version is
greater than the one the model expects before it.

<details><summary>Solution</summary>

```rule
rule "version-increases-on-update" {
    description "An accepted update returns a version above the previous one."
    severity medium
    when operation.type == "update_document" and policy.allowed and has(resource) and not resource.deleted
    always response.status == 200 implies response.json.version > resource.version
}
```
</details>

**B.** Error responses must be JSON, never HTML.

<details><summary>Solution</summary>

```rule
rule "errors-are-json" {
    description "Error responses are served as JSON."
    severity low
    always response.status >= 400 implies
        startswith(lower(coalesce(response.headers["content-type"], "")), "application/json")
}
```
</details>

**C.** A refusal must not tell the caller which organization owns a document: the owner's id must
not appear in the body of an error response.

<details><summary>Solution</summary>

```rule
rule "refusals-do-not-name-owners" {
    description "A refusal never names the organization that owns the document."
    severity medium
    when has(resource) and resource.org != actor.org and operation.type != "create_document"
    never response.status >= 400 and contains(response.body, coalesce(resource.org_id, "-"))
}
```
</details>

**D.** Reading or listing must never change anything. (Hint: this needs `observe` and
`state.expected_listing`.)

<details><summary>Solution</summary>

```rule
rule "reads-do-not-modify" {
    description "A read or listing leaves the organization as the model expects."
    severity high
    when operation.type == "read_document" or operation.type == "list_documents"
    let org = actor.org
    observe listing = org_documents(org)
    let differences = diff(state.expected_listing[org], listing)
    never count(differences) > 0
    message "a {operation.type} changed {org}: {join(differences, '; ')}"
}
```
</details>

## 15 Cheat sheet

```
rule "name" {
    id "AA-11"                      # optional, unique; assigned from the name if absent
    tags "group", "other"           # optional; first tag is the console group
    description "what must hold"
    severity critical|high|medium|low|info

    when <condition>                # scope; no `response`, no observations
    let x = <expression>            # named value, evaluated when used
    observe p = org_documents(org)  # application state after the step
    always <condition>              # must be true   (alias: assert)
    never  <condition>              # must be false

    message "text with {expression}"
    pass_message "text"
    evidence { key: <expression> }
}
```

| Want to say | Write |
|---|---|
| if A then B | `A implies B` |
| a field might be absent | `has(x)`, `coalesce(x, default)`, or put it behind `implies` |
| every / some / no element | `every x in xs : c`, `some ...`, `none ...` |
| list of things | `[x.id for x in xs where c]` |
| what the policy said | `policy.allowed`, `policy.denials["KEY"]` |
| what happened earlier | `some e in events : e.operation.type == "..."` |
| application state after | `observe l = org_documents(org)`, `diff(state.expected_listing[org], l)` |
| a header | `lower(coalesce(response.headers["name"], ""))` |
