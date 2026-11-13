# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""The columns of every report section, in one place.

The JSON schemas, the renderers and the commands all read this registry, so the
published schema cannot drift from the report. A report section whose key or columns
differ from the registry is refused when the JSON report is written.
"""

from __future__ import annotations

from faithful_shaar.outputs.document import Column


def _c(*pairs: tuple[str, str]) -> tuple[Column, ...]:
    return tuple(Column(key, title) for key, title in pairs)


SECTION_COLUMNS: dict[str, dict[str, tuple[Column, ...]]] = {
    "campaign": {
        "reviewers": _c(
            ("reviewer", "Reviewer"),
            ("email", "Email"),
            ("rows", "Entries"),
            ("packet", "Packet file"),
        ),
        "rows": _c(
            ("row_id", "Row ID"),
            ("reviewer", "Reviewer"),
            ("principal", "User"),
            ("account", "Account"),
            ("status", "Status"),
            ("resource", "Access to"),
            ("resource_kind", "Type"),
            ("access", "Access"),
            ("via", "Granted through"),
            ("source", "Source"),
        ),
        "unassigned": _c(
            ("principal", "User"),
            ("account", "Account"),
            ("resource", "Access to"),
            ("access", "Access"),
            ("reason", "Why there is no reviewer"),
            ("source", "Source"),
        ),
    },
    "decisions": {
        "decisions": _c(
            ("row_id", "Row ID"),
            ("reviewer", "Reviewer"),
            ("principal", "User"),
            ("resource", "Access to"),
            ("access", "Access"),
            ("decision", "Decision"),
            ("comment", "Comment"),
            ("state", "Outcome"),
            ("packet", "Packet"),
            ("citation", "Source"),
        ),
        "removals": _c(
            ("row_id", "Row ID"),
            ("principal", "User"),
            ("account", "Account"),
            ("resource", "Access to"),
            ("access", "Access"),
            ("reviewer", "Reviewer"),
            ("comment", "Comment"),
        ),
        "attention": _c(
            ("row_id", "Row ID"),
            ("reviewer", "Reviewer"),
            ("principal", "User"),
            ("resource", "Access to"),
            ("state", "Outcome"),
            ("reason", "Why it needs attention"),
            ("citation", "Source"),
        ),
    },
    "verify": {
        "removals": _c(
            ("row_id", "Row ID"),
            ("principal", "User"),
            ("resource", "Access to"),
            ("access", "Access"),
            ("result", "Result"),
            ("reason", "Reason"),
            ("citation", "Source"),
        ),
        "kept_but_gone": _c(
            ("row_id", "Row ID"),
            ("principal", "User"),
            ("resource", "Access to"),
            ("access", "Access"),
            ("citation", "Source"),
        ),
        "new_since_review": _c(
            ("principal", "User"),
            ("resource", "Access to"),
            ("access", "Access"),
            ("citation", "Source"),
        ),
    },
}
"""Report kind -> section key -> columns, in the order sections appear."""
