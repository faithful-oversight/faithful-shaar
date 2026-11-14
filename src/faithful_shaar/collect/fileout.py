# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""Write one collected file privately, and never replace a file without ``--force``."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

from faithful_shaar.errors import CollectionError

_PRIVATE = 0o600


def write_private(path: Path, data: bytes, *, force: bool) -> None:
    """Write ``data`` to ``path``, readable only by the current user.

    Without ``force`` the file is created exclusively, so an existing file or a
    symbolic link at that name is never written through. With ``force`` the data
    goes to a private temporary file in the same directory, which then replaces
    the target (a symbolic link is replaced, never followed).

    Raises:
        CollectionError: The target is a directory, exists without ``force``, or
            cannot be written.
    """
    if path.is_dir() and not path.is_symlink():
        msg = f"{path} is a directory; give a file name"
        raise CollectionError(msg)
    try:
        if force:
            _replace(path, data)
        else:
            _create(path, data)
    except FileExistsError as exc:
        msg = f"{path} already exists; use --force to replace it"
        raise CollectionError(msg) from exc
    except OSError as exc:
        msg = f"cannot write {path}: {exc.strerror}"
        raise CollectionError(msg) from exc


def _create(path: Path, data: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, _PRIVATE)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def _replace(path: Path, data: bytes) -> None:
    fd, temp = tempfile.mkstemp(dir=path.parent, prefix=".shaar-", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        Path(temp).replace(path)
    except BaseException:
        Path(temp).unlink(missing_ok=True)
        raise
