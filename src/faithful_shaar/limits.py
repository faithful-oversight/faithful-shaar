# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""Size limits, their defaults, and the ``--limit NAME=VALUE`` option that raises them.

Every limit exists to keep a damaged or hostile file from using all of a machine's memory.
Hitting one is never silent: the command stops with an error that names the limit and how
to raise it, and exits with code 3. The defaults sit well above realistic enterprise
sizes. A run that raises a limit records every limit it used in ``manifest.json``.

The default of each limit is the constant in the module that enforces it, so this module
holds only the names and where each default lives.
"""

from __future__ import annotations

import importlib
from typing import Final

from faithful_shaar.errors import UsageError

MAX_VALUE: Final = 1 << 40

# name -> (module, constant, what it limits)
_SOURCES: Final = {
    "csv-bytes": ("faithful_shaar.inputs.csvread", "MAX_CSV_BYTES", "the size of one CSV input"),
    "csv-rows": ("faithful_shaar.inputs.csvread", "MAX_ROWS", "the data rows in one CSV input"),
    "export-bytes": (
        "faithful_shaar.inputs.export",
        "MAX_FILE_BYTES",
        "the size of one shaar export (JSON Lines)",
    ),
    "map-bytes": (
        "faithful_shaar.assign",
        "MAX_MAP_BYTES",
        "the size of a reviewer map",
    ),
    "campaign-bytes": (
        "faithful_shaar.campaign",
        "MAX_CAMPAIGN_BYTES",
        "the size of campaign.json",
    ),
    "decisions-bytes": (
        "faithful_shaar.decide",
        "MAX_DECISIONS_BYTES",
        "the size of decisions.json",
    ),
    "packet-bytes": ("faithful_shaar.cli", "MAX_PACKET_BYTES", "the size of one returned packet"),
    "column-map-bytes": (
        "faithful_shaar.inputs.csvmap",
        "MAX_MAP_BYTES",
        "the size of a column map",
    ),
    "line-bytes": (
        "faithful_shaar.inputs.export",
        "MAX_LINE_BYTES",
        "the length of one line of a shaar export",
    ),
    "xlsx-rows": ("faithful_shaar.formats.xlsx", "MAX_ROWS", "the rows on a packet's sheet"),
    "xlsx-cells": (
        "faithful_shaar.formats.xlsx",
        "MAX_CELLS",
        "the cells with content in a packet",
    ),
    "xlsx-bytes": (
        "faithful_shaar.formats.xlsx",
        "MAX_UNCOMPRESSED_BYTES",
        "the size of a packet once unzipped",
    ),
    "xml-elements": (
        "faithful_shaar.formats.xlsx",
        "MAX_XML_ELEMENTS",
        "the XML elements in one part of a packet",
    ),
}
NAMES: Final = tuple(_SOURCES)
# A limit not given follows the limit it grows with, so raising the rows is enough.
_FOLLOWS: Final = {"xlsx-cells": ("xlsx-rows", 16), "xml-elements": ("xlsx-rows", 64)}

_active: dict[str, int] = {}


def default(name: str) -> int:
    """Return the built-in value of limit ``name``."""
    module, constant, _what = _SOURCES[name]
    value = getattr(importlib.import_module(module), constant)
    assert isinstance(value, int)  # noqa: S101 - every source is an integer constant
    return value


def get(name: str) -> int:
    """Return the limit in force for ``name``: the ``--limit`` value, else the default."""
    if name in _active:
        return _active[name]
    base, factor = _FOLLOWS.get(name, ("", 0))
    if base in _active:
        return _active[base] * factor
    return default(name)


def raised(name: str) -> bool:
    """Whether ``--limit`` set ``name`` for this run."""
    return name in _active


def hint(name: str) -> str:
    """Return the sentence that tells a reader how to raise limit ``name``."""
    return f"to read it anyway, raise the limit with --limit {name}=NUMBER (now {get(name)})"


def effective() -> dict[str, int]:
    """Return every limit in force, by name, for the manifest."""
    return {name: get(name) for name in sorted(_SOURCES)}


def parse(text: str) -> tuple[str, int]:
    """Parse one ``NAME=VALUE`` argument.

    Raises:
        ValueError: The name is unknown or the value is not a positive whole number.
    """
    name, sign, number = text.partition("=")
    name = name.strip()
    if not sign or name not in _SOURCES:
        msg = f"{text!r} is not NAME=VALUE with a NAME from: {', '.join(NAMES)}"
        raise ValueError(msg)
    number = number.strip().replace("_", "")
    if not (number.isascii() and number.isdigit()) or not 0 < int(number) <= MAX_VALUE:
        msg = f"the value for {name} must be a whole number from 1 to {MAX_VALUE}, not {number!r}"
        raise ValueError(msg)
    return name, int(number)


def configure(overrides: list[str] | None) -> None:
    """Set the limits for this run from ``--limit`` arguments, replacing any earlier set.

    Raises:
        UsageError: An argument is not valid.
    """
    chosen: dict[str, int] = {}
    for text in overrides or []:
        try:
            name, value = parse(text)
        except ValueError as exc:
            raise UsageError(str(exc)) from None
        chosen[name] = value
    _active.clear()
    _active.update(chosen)


def reset() -> None:
    """Go back to the defaults."""
    _active.clear()
