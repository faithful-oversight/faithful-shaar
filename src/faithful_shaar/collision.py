# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""Find an input that a run would overwrite or remove by publishing its own output.

``--force`` lets a run replace the files an earlier run wrote. It must never let a run replace
a file the run was told to read: an access export, a column map, a reviewer map, a returned
packet, a certificate, a secret file. Two paths are the same file when their resolved paths
are equal (this covers a symbolic link on either side, and an output folder reached through
a link, even before the target exists) or when ``os.path.samefile`` says they share a device
and inode (this covers hard links).
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterable


def same_file(source: Path, target: Path) -> bool:
    """Return whether ``source`` and ``target`` are, or would be, one file.

    ``target`` need not exist: its folder is resolved, so a link to the folder of ``source``
    is seen through.

    Raises:
        OSError: A path cannot be examined (for example a folder that cannot be searched).
    """
    real_source = Path(os.path.realpath(source))
    planned = Path(os.path.realpath(target.parent)) / target.name
    if real_source in (planned, Path(os.path.realpath(target))):
        return True
    try:
        return source.samefile(target)
    except (FileNotFoundError, NotADirectoryError):
        return False


def first_collision(sources: Iterable[Path], targets: Iterable[Path]) -> tuple[Path, Path] | None:
    """Return the first ``(input, target)`` pair that are one file, or ``None``.

    Raises:
        OSError: A path cannot be examined; the caller reports it and stops, because a run
            that cannot tell whether it would overwrite an input must not publish.
    """
    planned = list(targets)
    for source in sources:
        for target in planned:
            if same_file(source, target):
                return source, target
    return None


def secret_file(reference: str | None) -> Path | None:
    """Return the file a ``file:PATH`` secret reference reads, or ``None`` for any other."""
    provider, _, location = (reference or "").partition(":")
    return Path(location) if provider == "file" and location else None


def collection_collision(sources: Iterable[Path | None], output: Path) -> str | None:
    """Return the error text when a collection's output file is a file it was told to use.

    The files are a CA file, a certificate, or a ``file:`` secret: never a place to publish.
    Returns ``None`` when there is no collision. An unexaminable path is a collision too,
    because the run cannot show that it is safe to publish.
    """
    used = [path for path in sources if path is not None]
    try:
        found = first_collision(used, [output])
    except OSError as exc:
        return f"cannot compare {output} with the files this collection uses: {exc.strerror}"
    if found is None:
        return None
    return (
        f"the output file {output} is {found[0]}, which this collection reads; "
        "choose another output file (even --force never replaces it)"
    )
