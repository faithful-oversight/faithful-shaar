# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""The packaged PowerShell exporter."""

from __future__ import annotations

from faithful_core.collect.script import ScriptResource

NAME = "Export-ShaarAccess.ps1"
_EXPORTER = ScriptResource("faithful_shaar", NAME, "exporter")

text = _EXPORTER.text
"""Return the exporter script. It is pure ASCII."""
version = _EXPORTER.version
"""Return the exporter's own version, as it writes it into each file."""
