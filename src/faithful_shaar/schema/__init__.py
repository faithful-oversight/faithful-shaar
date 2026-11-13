# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""The JSON Schemas shaar publishes, shipped as package data.

The report schemas are generated from the section registry in
``faithful_shaar.outputs.columns``; a test keeps the committed files equal to what the
generator writes.
"""

from __future__ import annotations

from importlib import resources

from faithful_shaar.errors import UsageError

SCHEMA_NAMES = ("campaign-report-v1", "decisions-report-v1", "verify-report-v1", "manifest-v1")


def schema_text(name: str) -> str:
    """Return the text of the schema called ``name``, as ``shaar schema NAME`` prints it.

    Raises:
        UsageError: ``name`` is not one of :data:`SCHEMA_NAMES`.
    """
    if name not in SCHEMA_NAMES:
        msg = f"unknown schema {name!r}; choose from {', '.join(SCHEMA_NAMES)}"
        raise UsageError(msg)
    return (resources.files("faithful_shaar.schema") / f"{name}.schema.json").read_text(
        encoding="utf-8"
    )
