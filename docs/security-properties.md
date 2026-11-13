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

How each is judged is described in [architecture.md](architecture.md); the implementations are in
`properties/checks.py`.

## Adding a property

1. Add its `Property` metadata (stable id, name, statement) and register it in `properties/registry.py`.
2. Implement a `SecurityProperty` in `properties/checks.py` and append the instance to `CHECKS`.
   Append rather than insert: the first violation on a step decides how a failure is attributed.
3. Unit-test `applies`, `requires` and `evaluate` directly; they are pure functions.

No engine or evaluator change is needed if the property only uses existing operations, model
fields and the `OrgSnapshot` probe. Otherwise:

- A property that changes what is *allowed* also needs a rule in the reference policy (`decide`).
  Take scope from the resulting `Decision` (`decision.denial_for(self.id)`); do not recompute
  authorization inside the property.
- A new kind of probe is new application I/O and is a deliberate engine change.
- Integrity can only be expressed for *denied* writes today: properties see the model as it was
  before the operation, which is the right expectation only when nothing should have changed.
