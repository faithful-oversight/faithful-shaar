# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""Generate the JSON Schemas of the reports and the manifest.

The report schemas are built from :data:`~faithful_shaar.outputs.columns.SECTION_COLUMNS`,
so a section's columns are written once. A test compares the committed files in
``faithful_shaar/schema`` with this module's output, so they cannot drift.
"""

from __future__ import annotations

import json
from typing import Any

from faithful_shaar.outputs.columns import SECTION_COLUMNS

BASE_URL = "https://faithful-oversight.github.io/faithful-shaar/schema"
REPORT_NAMES = tuple(f"{kind}-report-v1" for kind in SECTION_COLUMNS)
MANIFEST_NAME = "manifest-v1"
SCHEMA_NAMES = (*REPORT_NAMES, MANIFEST_NAME)
DIALECT = "https://json-schema.org/draft/2020-12/schema"
TIME_PATTERN = "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"
SHA256_PATTERN = "^[0-9a-f]{64}$"
FILE_NAME_PATTERN = "^[A-Za-z0-9][A-Za-z0-9._-]*$"


def schema_id(name: str) -> str:
    """The ``$id`` of a schema, which is also the URL the reports name it by."""
    return f"{BASE_URL}/{name}.schema.json"


def _strings(*, minimum: int = 0) -> dict[str, Any]:
    return {"type": "array", "items": {"type": "string"}, "minItems": minimum}


def _input_item() -> dict[str, Any]:
    properties: dict[str, Any] = {
        "name": {"type": "string"},
        "kind": {"type": "string"},
        "size": {"type": "integer", "minimum": 0},
        "sha256": {"$ref": "#/$defs/sha256"},
    }
    return {
        "type": "object",
        "additionalProperties": False,
        "required": sorted(properties),
        "properties": dict(sorted(properties.items())),
    }


_DEFS: dict[str, Any] = {
    "time": {
        "type": "string",
        "pattern": TIME_PATTERN,
        "description": "RFC 3339, UTC, to the second, with a trailing Z.",
    },
    "sha256": {"type": "string", "pattern": SHA256_PATTERN},
}
_CELL: dict[str, Any] = {
    "anyOf": [
        {"type": ["string", "integer", "null"]},
        {"type": "array", "items": {"type": "string"}},
    ],
    "description": "Text, a whole number, nothing (null), or a list of text.",
}


def _tool() -> dict[str, Any]:
    return {
        "type": "object",
        "additionalProperties": False,
        "required": ["name", "version"],
        "properties": {"name": {"const": "shaar"}, "version": {"type": "string"}},
    }


def _section(kind: str, key: str) -> dict[str, Any]:
    columns = SECTION_COLUMNS[kind][key]
    return {
        "type": "array",
        "items": {
            "type": "object",
            "additionalProperties": False,
            "required": [c.key for c in columns],
            "properties": {c.key: {"$ref": "#/$defs/cell", "title": c.title} for c in columns},
        },
    }


def _report(kind: str) -> dict[str, Any]:
    name = f"{kind}-report-v1"
    sections = SECTION_COLUMNS[kind]
    properties: dict[str, Any] = {
        "schema": {"const": schema_id(name)},
        "kind": {"const": kind},
        "title": {"type": "string"},
        "headline": {"type": "string"},
        "generated_at": {"$ref": "#/$defs/time"},
        "tool": _tool(),
        "facts": {"type": "object", "additionalProperties": {"type": "string"}},
        "counts": {
            "type": "object",
            "additionalProperties": {"type": "integer", "minimum": 0},
        },
        "sections": {
            "type": "object",
            "additionalProperties": False,
            "required": list(sections),
            "properties": {key: _section(kind, key) for key in sections},
        },
        "problems": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["source", "reason"],
                "properties": {
                    "source": {
                        "type": "object",
                        "additionalProperties": False,
                        "required": ["file", "detail"],
                        "properties": {"file": {"type": "string"}, "detail": {"type": "string"}},
                    },
                    "reason": {"type": "string"},
                },
            },
        },
        "not_shown": _strings(),
        "inputs": {"type": "array", "items": _input_item()},
        "data": {"type": "object"},
    }
    return {
        "$schema": DIALECT,
        "$id": schema_id(name),
        "title": f"shaar {kind} report",
        "description": (
            f"Version 1 of the JSON report that shaar {kind} writes. Every section row is "
            "an object with exactly the columns listed here."
        ),
        "type": "object",
        "additionalProperties": False,
        "required": sorted(properties),
        "properties": dict(sorted(properties.items())),
        "$defs": {**_DEFS, "cell": _CELL},
    }


def _manifest() -> dict[str, Any]:
    properties: dict[str, Any] = {
        "schema": {"const": schema_id(MANIFEST_NAME)},
        "tool": _tool(),
        "generated_at": {"$ref": "#/$defs/time"},
        "files": {
            "type": "array",
            "minItems": 1,
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["name", "sha256", "size"],
                "properties": {
                    "name": {"type": "string", "pattern": FILE_NAME_PATTERN},
                    "size": {"type": "integer", "minimum": 0},
                    "sha256": {"$ref": "#/$defs/sha256"},
                },
            },
        },
        "inputs": {"type": "array", "items": _input_item()},
        "limits": {
            "description": (
                "The size limits the run used, by name (see the --limit option). Present "
                "when the command reads files. A value above the built-in default was "
                "chosen by whoever ran the command."
            ),
            "type": "object",
            "additionalProperties": {"type": "integer", "minimum": 1},
        },
    }
    return {
        "$schema": DIALECT,
        "$id": schema_id(MANIFEST_NAME),
        "title": "shaar run manifest",
        "description": (
            "Version 1 of the manifest shaar writes with every command. It lists each "
            "output file with its size and SHA-256, and each input, so a reader can "
            "confirm that a set of files is complete and unchanged. It is written last."
        ),
        "type": "object",
        "additionalProperties": False,
        "required": sorted(set(properties) - {"limits"}),
        "properties": dict(sorted(properties.items())),
        "$defs": dict(_DEFS),
    }


def generate_schema(name: str) -> str:
    """The text of the schema called ``name`` (one of :data:`SCHEMA_NAMES`).

    Raises:
        KeyError: ``name`` is not a schema name.
    """
    if name == MANIFEST_NAME:
        document = _manifest()
    elif name in REPORT_NAMES:
        document = _report(name.removesuffix("-report-v1"))
    else:
        raise KeyError(name)
    return json.dumps(document, indent=2, ensure_ascii=False) + "\n"
