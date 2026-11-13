"""All known properties, by id."""

from __future__ import annotations

from .authorization import ROLE_WRITE_PERMISSION
from .base import Property
from .isolation import TENANT_READ_ISOLATION, TENANT_WRITE_ISOLATION

PROPERTIES: dict[str, Property] = {
    p.id: p for p in (TENANT_READ_ISOLATION, TENANT_WRITE_ISOLATION, ROLE_WRITE_PERMISSION)
}
EXECUTION = Property(
    id="EXEC",
    name="execution-health",
    statement="Operations must yield a usable observation for the outcome to be judged.",
)
