# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""Read access data (shaar exports and CSV files) into a :class:`Snapshot`.

Inputs are recognised by content, never by extension: a file whose first line is a JSON
object with ``shaar_export`` is a shaar export; any other file is read as a CSV, which
needs a column map or a preset.
"""

from __future__ import annotations

import json
import stat
from typing import TYPE_CHECKING

from faithful_shaar.errors import InputError
from faithful_shaar.inputs import csvread, export
from faithful_shaar.inputs.csvmap import PRESETS, CsvMap, load_map
from faithful_shaar.inputs.merge import merge

if TYPE_CHECKING:
    from pathlib import Path

    from faithful_shaar.model import Snapshot

__all__ = ["PRESETS", "CsvMap", "load_map", "read_inputs"]


def is_export(first_line: bytes) -> bool:
    """Return whether a file's first line is the header of a shaar export."""
    try:
        head = json.loads(first_line)
    except (ValueError, RecursionError):
        return False
    return isinstance(head, dict) and "shaar_export" in head


def _read_one(path: Path, cmap: CsvMap | None) -> Snapshot:
    name = path.name
    try:
        info = path.stat()
    except OSError as exc:
        msg = f"cannot read {name}: {exc.strerror}"
        raise InputError(msg) from exc
    if not stat.S_ISREG(info.st_mode):
        msg = f"{name} is not a regular file"
        raise InputError(msg)
    if info.st_size > export.MAX_FILE_BYTES:
        msg = f"{name} is larger than the limit of {export.MAX_FILE_BYTES} bytes"
        raise InputError(msg)
    try:
        with path.open("rb") as stream:
            first = stream.readline(export.MAX_LINE_BYTES + 1)
            stream.seek(0)
            if is_export(first):
                return export.read_export(stream, name)[0]
            if cmap is None:
                msg = (
                    f"{name} is not a shaar export; to read a CSV, name its columns "
                    "with a map file or a preset"
                )
                raise InputError(msg)
            return csvread.read_csv(stream, name, cmap)[0]
    except OSError as exc:
        msg = f"cannot read {name}: {exc.strerror}"
        raise InputError(msg) from exc


def read_inputs(
    paths: list[Path],
    *,
    label: str,
    csv_map: Path | None = None,
    preset: str | None = None,
    resource: str | None = None,
) -> Snapshot:
    """Read every input and return one merged snapshot named ``label``.

    ``csv_map`` (a TOML file) and ``preset`` describe CSV inputs; ``resource`` fixes the
    one resource of a CSV that has no resource column. Raises :class:`InputError` for an
    input that cannot be read at all (not a regular file, too large, undecodable, no
    header, bad map); anything less becomes a problem on the snapshot. Each input is
    fingerprinted (size and SHA-256 of its bytes) under its file name only.
    """
    if not paths:
        msg = "no input files given"
        raise InputError(msg)
    cmap = load_map(csv_map, preset, resource)
    return merge(label, [_read_one(path, cmap) for path in paths])
