# Security properties

| ID | Name | Must never happen |
|---|---|---|
| TI-1 | tenant-read-isolation | A principal receives data belonging to a resource owned by another organization. |
| TI-2 | tenant-write-isolation | A principal modifies or deletes a resource owned by another organization. |
| AZ-1 | role-write-permission | A principal performs a write its role does not permit. |

Reference policy (`properties/authorization.py`): all roles may read/list within their own org;
`admin` and `member` may create and update; only `admin` may delete; no cross-org access.

How each is judged is described in [architecture.md](architecture.md).
