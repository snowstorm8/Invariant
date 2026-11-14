# Security properties

| ID | Name | Must never happen |
|---|---|---|
| TI-1 | tenant-read-isolation | A principal receives data belonging to a resource owned by another organization. |
| TI-2 | tenant-write-isolation | A principal modifies or deletes a resource owned by another organization. |
| AZ-1 | role-write-permission | A principal performs a write its role does not permit. |

Reference policy (`properties/authorization.py`): all roles may read/list within their own org;
`admin` and `member` may create and update; only `admin` may delete; no cross-org access.

`decide()` evaluates every rule, so one operation can be denied under several properties, each denial
keeping its own property id and reason. A cross-tenant viewer update is denied under TI-2 (tenant) and
AZ-1 (role); a same-org viewer update under AZ-1 only; a cross-tenant member update under TI-2 only.
Roles are the actor's role in its own org, so they are checked even when the target is another tenant's.
An operation kind the policy has no rule for raises `UnsupportedOperationError`; it is never allowed by default.

How each is judged is described in [architecture.md](architecture.md). All three are rules in
`integrations/document_saas.rules`, written in the language described in [rules.md](rules.md).

## Adding a rule

Write it in the console, upload JSON, or pass a rule file (`--rules`). No Python change is needed:
see [rules.md](rules.md). The rest of this page is about extending what rules can *see*.

## Extending the built-in set or the context

1. To ship a rule by default, append it to `integrations/document_saas.rules`. Append rather than
   insert: the first violation on a step headlines the report (all failing rules are still reported).
2. To expose a new field, add it to the schema and to the values in
   `integrations/document_saas.py`; the validator and the console's reference pick it up.
3. Test with `RuleSet.from_text(...)` and `Evaluator.for_rules(...)`; rule evaluation is pure.

No engine or evaluator change is needed if a rule only uses existing operations, model
fields and the `org_documents` probe. Otherwise:

- A property that changes what is *allowed* also needs a rule in the reference policy (`decide`).
  Built-in rules take scope from the resulting decision (`policy.denials["ID"]`) rather than
  recomputing authorization.
- A new kind of probe is new application I/O and is a deliberate engine change.
- With integrity rules switched off, an undetected forbidden write leaves the model and the target
  disagreeing; the next authorised write then fails verification and the run ends `INCONCLUSIVE`.
- Integrity can only be expressed for *denied* writes today: properties see the model as it was
  before the operation, which is the right expectation only when nothing should have changed.
