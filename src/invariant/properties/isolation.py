"""Tenant-isolation properties.

The definitions live in the rule language (``integrations/document_saas.rules``);
these constants are that metadata, kept as names for the reference policy and
for code that refers to a property by identity.
"""

from __future__ import annotations

from invariant.integrations.builtin_rules import builtin_rule

from .base import Property

TENANT_READ_ISOLATION = Property.from_rule(builtin_rule("TI-1"))
TENANT_WRITE_ISOLATION = Property.from_rule(builtin_rule("TI-2"))
