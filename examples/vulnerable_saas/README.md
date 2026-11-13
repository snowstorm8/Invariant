# vulnerable_saas

**Deliberately insecure. Local testing only; never deploy.**

Multi-tenant document API (orgs, users with `admin`/`member`/`viewer` roles, org-owned documents).
`create_app(defects=...)` enables named defects (see `app/models.py`): `stale-cache-read`
(the milestone defect), `update-missing-tenant-check`, `viewer-can-update`. With no defects the
app is the fixed version. `target.py` provides `vulnerable_adapter` / `fixed_adapter` factories.
