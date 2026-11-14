# Security properties

Everything Invariant judges is a **rule** in the [rule language](rules.md). Twenty-nine rules ship:
three core rules and twenty-six in the default web-application library. They are ordinary rules in
two files, `src/invariant/integrations/document_saas.rules` and `web_defaults.rules`; nothing about
them is special-cased in Python. In the console they are grouped by their first tag and can be
switched on and off singly or by group.

## Core rules

| ID | Name | Severity | Must hold |
|---|---|---|---|
| TI-1 | `tenant-read-isolation` | critical | A principal must never receive data belonging to a resource owned by another organization. |
| TI-2 | `tenant-write-isolation` | critical | A principal must never modify or delete a resource owned by another organization. |
| AZ-1 | `role-write-permission` | high | A principal must not perform a write operation that its role does not permit. |

These three are scoped by the **reference policy** (below) and judge state: a write the policy
denied must leave the affected organization exactly as the model expects (TI-2, AZ-1), and no
response may contain the marker of another organization's document (TI-1).

## Default library

### Access control (`AC`)

| ID | Name | Severity | Must hold |
|---|---|---|---|
| AC-1 | `cross-tenant-read-denied` | critical | Reading another organization's document must be refused. |
| AC-2 | `cross-tenant-write-denied` | critical | Updating or deleting another organization's document must be refused. |
| AC-3 | `viewer-cannot-write` | high | A viewer must not create, update or delete documents. |
| AC-4 | `only-admins-delete` | high | Only an admin may delete a document, even in the member's own organization. |
| AC-5 | `read-returns-own-tenant` | critical | A successful read returns a document of the reader's own organization. |
| AC-6 | `listing-is-tenant-scoped` | critical | A listing contains only documents of the caller's organization. |
| AC-7 | `deleted-documents-stay-gone` | high | Once a document was deleted, no later read of it may succeed. |

### Data exposure (`DX`)

| ID | Name | Severity | Must hold |
|---|---|---|---|
| DX-1 | `no-credentials-in-responses` | critical | Responses to a user's requests never carry tokens, passwords or secrets. |
| DX-2 | `errors-reveal-no-internals` | medium | Error responses carry no stack trace, source path or database detail. |
| DX-3 | `refusals-do-not-reveal-existence` | medium | Asking for another organization's document is answered like asking for one that does not exist, without naming its owner. |

### Headers and cookies (`TH`)

| ID | Name | Severity | Must hold |
|---|---|---|---|
| TH-1 | `content-type-sniffing-disabled` | medium | Responses send X-Content-Type-Options: nosniff. |
| TH-2 | `responses-are-not-cached` | medium | Authenticated responses are not stored by browsers or shared caches (Cache-Control: no-store). |
| TH-3 | `framing-is-restricted` | medium | Responses forbid being framed by other sites (X-Frame-Options or CSP frame-ancestors). |
| TH-4 | `referrer-policy-set` | low | Responses set a Referrer-Policy. |
| TH-5 | `content-security-policy-set` | medium | Responses send a Content-Security-Policy. |
| TH-6 | `no-technology-banner` | low | Responses do not announce server software and versions (Server with a version, X-Powered-By). |
| TH-7 | `cors-never-wildcard-with-credentials` | high | CORS never allows any origin together with credentials. |
| TH-8 | `cookies-are-http-only` | high | Every cookie a response sets is HttpOnly, out of reach of page scripts. |
| TH-9 | `cookies-are-secure` | high | Every cookie a response sets is Secure, so it is never sent over plain HTTP. |
| TH-10 | `cookies-have-samesite` | medium | Every cookie a response sets declares SameSite=Lax or Strict. |
| TH-11 | `json-declares-its-content-type` | medium | A JSON body is served as application/json, never as something a browser may render. |

### Integrity (`IR`)

| ID | Name | Severity | Must hold |
|---|---|---|---|
| IR-1 | `requests-never-crash-the-server` | high | Well-formed requests from a legitimate user never cause a server error. |
| IR-2 | `refused-writes-change-nothing` | critical | A write the policy forbids leaves every document of the affected organization as the model expects it. |
| IR-3 | `update-advances-the-version-by-one` | medium | An authorised update returns the document at the next version. |
| IR-4 | `read-returns-the-expected-document` | high | A read in the owner's organization returns the content and version that authorised writes produced. |
| IR-5 | `listing-matches-expected-state` | high | A listing contains exactly the documents authorised writes left in the organization. |

Each library rule must hold on a correct build, so a failure means the application is wrong. They
were checked against the fixed builds of both demo applications (no violation) and against builds
with the matching defects (each detected).

## Reference policy

`properties/authorization.py` says what *should* be allowed, independently of the application:
all roles may read and list within their own organization; `admin` and `member` may create and
update; only `admin` may delete; nobody may touch another organization's documents.

`decide()` evaluates every policy rule, so one operation can be denied under several keys, each
keeping its own reason. A cross-tenant viewer update is denied under TI-2 (tenant) and AZ-1 (role);
a same-organization viewer update under AZ-1 only; a cross-tenant member update under TI-2 only.
Roles are the actor's role in its own organization. An operation kind the policy has no rule for
raises `UnsupportedOperationError`; it is never allowed by default. Rules read the outcome as
`policy.allowed`, `policy.reason` and `policy.denials["KEY"]` instead of recomputing authorization.

The policy's name for a rule is its `policy` key. A rule's `id` is what reports show and can be
renamed (Settings tab); the key stays, so renaming never changes what the policy denies.

## Adding rules

- **Your own rules**: write them in the console, upload JSON, or pass `--rules`. No Python change.
  See the [tutorial](tutorial-rules.md) and the [reference](rules.md).
- **Shipping a rule by default**: append it to `web_defaults.rules` (or `document_saas.rules`),
  give it an `id`, `tags` and a description, and add it to the tests. Append rather than insert: the
  first violation on a step headlines the report (every failing rule is still reported).
- **Exposing something new to rules**: add the field to the integration's schema and values
  (`integrations/document_saas.py`); the validator and the console's reference pick it up.
- **A new kind of probe** is new application I/O and a deliberate engine change.

Limits that follow from the design: integrity can only be expressed for *denied* writes today
(properties see the model as it was before the operation, which is the right expectation only when
nothing should have changed); with integrity rules switched off, an undetected forbidden write
leaves the model and the target disagreeing, and the next authorised write then fails verification
and the run ends `INCONCLUSIVE`.
