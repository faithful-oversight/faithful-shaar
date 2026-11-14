# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""The report document every renderer reads.

A command fills a :class:`Document`; :mod:`faithful_shaar.outputs.render` turns it into
JSON, Markdown, HTML and CSV. Renderers read nothing else, so all formats agree. Values
are untrusted text from the inputs: this module holds them as they are, and each
renderer makes them safe for its own format.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from faithful_shaar.clock import date_and_time

if TYPE_CHECKING:
    from faithful_shaar.model import InputFile, Problem

Cell = str | int | None
"""One table cell. A list of text is allowed in a row and is shown ``; ``-joined."""
Row = dict[str, Cell | list[str]]
KINDS = ("campaign", "decisions", "verify")


@dataclass(frozen=True)
class Column:
    """A table column: ``key`` is the JSON field name, ``title`` the heading people read."""

    key: str
    title: str


@dataclass(frozen=True)
class Section:
    """A titled table of rows.

    ``empty`` is the text shown when there are no rows, so an empty table is never
    silent. ``citations`` names the row field that holds the ``file, detail`` text of
    each row's source; HTML marks that column. Use ``""`` when rows have no such field.
    """

    key: str
    title: str
    intro: str
    columns: tuple[Column, ...]
    rows: list[Row]
    empty: str
    citations: str = "source"


@dataclass(frozen=True)
class Document:
    """A whole report: headline, facts, counts, sections, problems and limits."""

    kind: str
    title: str
    headline: str
    facts: list[tuple[str, str]]
    counts: list[tuple[str, int]]
    sections: list[Section]
    problems: list[Problem]
    not_shown: list[str]
    generated_at: str
    tool_version: str
    inputs: list[InputFile] = field(default_factory=list)
    data: dict[str, Any] = field(default_factory=dict)


def cell_text(value: Cell | list[str]) -> str:
    """Write a cell as plain text: nothing for ``None``, ``; ``-joined for a list."""
    if value is None:
        return ""
    if isinstance(value, list):
        return "; ".join(value)
    return str(value)


def format_time(moment: datetime) -> str:
    """Write a time as RFC 3339 in UTC with a trailing ``Z``, to the second."""
    moment = moment.replace(tzinfo=UTC) if moment.tzinfo is None else moment.astimezone(UTC)
    return date_and_time(moment) + "Z"


def generated_now() -> str:
    """The report time: the clock, or ``SOURCE_DATE_EPOCH`` for a repeatable report.

    Raises:
        ValueError: ``SOURCE_DATE_EPOCH`` is set but is not a whole number of seconds
            that names a time.
    """
    fixed = os.environ.get("SOURCE_DATE_EPOCH", "")
    if not fixed:
        return format_time(datetime.now(UTC))
    try:
        return format_time(datetime.fromtimestamp(int(fixed), UTC))
    except (ValueError, OverflowError, OSError) as exc:
        msg = f"SOURCE_DATE_EPOCH must be whole seconds since 1970, not {fixed!r}"
        raise ValueError(msg) from exc
