"""Tenant-isolation properties."""

from __future__ import annotations

from .base import Property

TENANT_READ_ISOLATION = Property(
    id="TI-1",
    name="tenant-read-isolation",
    statement=(
        "A principal must never receive data belonging to a resource owned by "
        "another organization."
    ),
)

TENANT_WRITE_ISOLATION = Property(
    id="TI-2",
    name="tenant-write-isolation",
    statement=(
        "A principal must never modify or delete a resource owned by another organization."
    ),
)
