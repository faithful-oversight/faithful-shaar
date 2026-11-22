# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""Publish a set of report files together, privately, and without clobbering.

faithful-core does the work; its ``faithful_core.files`` module states every guarantee.
This module only names shaar's temporary files: ``.shaar-*.tmp`` while writing, and
``.shaar-old-*.bak`` while a forced replace can still be undone. shaar puts the manifest
last, so a manifest means every other file is in place.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from faithful_core import files as core

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping
    from pathlib import Path

SLUG = "shaar"


def write_files(
    directory: Path,
    files: Mapping[str, bytes],
    *,
    force: bool,
    remove: Iterable[str] = (),
) -> list[Path]:
    """Write every file, or leave ``directory`` as it was; see ``faithful_core.files``.

    With ``force``, the plain files named in ``remove`` (an earlier run's files that this
    run does not write) are taken away in the same all-or-nothing swap.

    Raises:
        OutputError: A target exists and ``force`` is false, a target is a directory, or
            writing fails.
    """
    return core.write_files(directory, files, force=force, slug=SLUG, remove=remove)
