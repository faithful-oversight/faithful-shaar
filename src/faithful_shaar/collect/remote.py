# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""Run the exporter on a domain controller over PowerShell remoting.

The packaged script is sent to the controller and run there with ``-ToPipeline``.
Its lines stream back and are written to a file next to the destination, and the
file is published only after its end line checks out: the record count and the
SHA-256 the script computed over everything it sent before the end line must match
what arrived. A partial file is never left behind.

faithful-core runs the connection, the transport rules, the secret handling, and the
rule that every failure discards the private file; see ``faithful_core.collect.winrm``.
This module holds what is shaar's own: the checks on each line, the end line, the
script's parameters, and the result.

Rights: the account must be allowed to open a PowerShell remoting session on the
controller (by default, members of Administrators or Remote Management Users) and to
read the groups it exports. Whether a just-enough-administration endpoint can be
narrowed further for this script has not been tested.

Lines are checked as they arrive: the first must be a shaar export header for system
``ad``, every other line before the end line must be a JSON object holding exactly one
of ``principal``, ``resource``, ``grant`` and ``gap``, and nothing may follow the end
line. The gaps and the resources marked incomplete are returned to the caller.
"""

from __future__ import annotations

import contextlib
import functools
import hashlib
import json
import os
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from faithful_core.collect import names, winrm

from faithful_shaar.errors import CollectionError

if TYPE_CHECKING:
    from collections.abc import Callable

install_hint = functools.partial(names.install_hint, "faithful-shaar")
"""Say how to install shaar with extras, for the messages faithful-core writes."""

MAX_LINE = 1024 * 1024
"""The longest line an export may hold, in bytes."""
MAX_FILE = 512 * 1024 * 1024
"""The largest export shaar accepts, in bytes."""
_RECORDS = ("principal", "resource", "grant", "gap")


@dataclass(frozen=True)
class Result:
    """What a collection wrote.

    Attributes:
        path: The published file.
        records: How many record lines it holds.
        gaps: What the exporter could not read, as ``what: reason`` sentences.
        incomplete: Names of the groups whose membership was cut short.
    """

    path: Path
    records: int
    gaps: tuple[str, ...]
    incomplete: tuple[str, ...] = ()


def secret_file(reference: str | None) -> Path | None:
    """Return the file a ``file:PATH`` secret reference reads, or ``None`` for any other."""
    provider, _, location = (reference or "").partition(":")
    return Path(location) if provider == "file" and location else None


def parameters(
    *,
    groups: list[str] | None = None,
    search_base: str | None = None,
    privileged: bool = False,
    server: str | None = None,
) -> dict[str, Any]:
    """Return the script's parameters for a remote run.

    The script reads from ``server`` (the controller the session is on) so that its
    directory reads are not a second hop.

    Raises:
        CollectionError: No scope was given.
    """
    if not (groups or search_base or privileged):
        msg = "give at least one of --group, --search-base and --privileged"
        raise CollectionError(msg)
    values: dict[str, Any] = {"ToPipeline": True}
    if groups:
        values["Group"] = list(groups)
    if search_base:
        values["SearchBase"] = search_base
    if privileged:
        values["Privileged"] = True
    if server:
        values["Server"] = server
    return values


def write_private(destination: Path, data: bytes, *, force: bool) -> None:
    """Write ``data`` to ``destination`` owner-only, never overwriting without ``force``.

    Raises:
        CollectionError: The destination exists (and ``force`` is off) or cannot be written.
    """
    temp = destination.parent / f".{destination.name}.{uuid.uuid4().hex}.part"
    try:
        descriptor = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
    except OSError as exc:
        with contextlib.suppress(OSError):
            temp.unlink()
        msg = f"cannot write to {destination.parent}: {exc.strerror or exc}"
        raise CollectionError(msg) from None
    try:
        winrm.publish_file(temp, destination, force=force)
    except CollectionError:
        with contextlib.suppress(OSError):
            temp.unlink()
        raise


class _Sink:
    """Write streamed lines to a private file and check them as they come."""

    def __init__(self, destination: Path) -> None:
        self.destination = destination
        self.temp = destination.parent / f".{destination.name}.{uuid.uuid4().hex}.part"
        descriptor = os.open(self.temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        self.handle = os.fdopen(descriptor, "wb")
        self.digest = hashlib.sha256()
        self.records = 0
        self.size = 0
        self.ended = False
        self.trailer: dict[str, Any] = {}
        self.gaps: list[str] = []
        self.incomplete: list[str] = []
        self.lines = 0

    def take(self, item: object) -> None:
        if self.ended:
            msg = "the exporter sent output after its end line"
            raise CollectionError(msg)
        number = self.lines + 1
        if not isinstance(item, str) or not item.isascii() or "\n" in item or "\r" in item:
            msg = f"the exporter sent something that is not one line of text (line {number})"
            raise CollectionError(msg)
        raw = item.encode("ascii") + b"\n"
        if len(raw) > MAX_LINE:
            msg = f"line {number} from the exporter is too long"
            raise CollectionError(msg)
        self.size += len(raw)
        if self.size > MAX_FILE:
            msg = f"the export is larger than {MAX_FILE // (1024 * 1024)} MiB"
            raise CollectionError(msg)
        body = self._parse(raw, number)
        if number == 1:
            self._header(body)
        elif "end" in body:
            self._end(body)
        else:
            self._record(body, number)
        self.lines = number
        self.handle.write(raw)
        if not self.ended:
            self.digest.update(raw)

    @staticmethod
    def _parse(raw: bytes, number: int) -> dict[str, Any]:
        try:
            body = json.loads(raw)
        except ValueError:
            msg = f"line {number} from the exporter is not JSON"
            raise CollectionError(msg) from None
        if not isinstance(body, dict):
            msg = f"line {number} from the exporter is not a JSON object"
            raise CollectionError(msg)
        return body

    @staticmethod
    def _header(body: dict[str, Any]) -> None:
        if body.get("shaar_export") != 1 or body.get("system") != "ad":
            msg = "the exporter's first line is not a shaar export header for Active Directory"
            raise CollectionError(msg)

    def _end(self, body: dict[str, Any]) -> None:
        records, sha256 = body.get("records"), body.get("sha256")
        if (
            body.get("end") is not True
            or isinstance(records, bool)
            or not isinstance(records, int)
            or not isinstance(sha256, str)
        ):
            msg = "the exporter's end line is not valid"
            raise CollectionError(msg)
        self.trailer = body
        self.ended = True

    def _record(self, body: dict[str, Any], number: int) -> None:
        kinds = [key for key in _RECORDS if key in body]
        content = body[kinds[0]] if len(kinds) == 1 and len(body) == 1 else None
        if not isinstance(content, dict):
            msg = f"the exporter sent a line of an unknown kind (line {number})"
            raise CollectionError(msg)
        self.records += 1
        if kinds[0] == "gap":
            self.gaps.append(f"{content.get('what')}: {content.get('reason')}")
        elif kinds[0] == "resource" and content.get("complete") is not True:
            self.incomplete.append(str(content.get("name") or content.get("id")))

    def finish(self) -> Result:
        """Check the end line against what arrived."""
        self.handle.close()
        if not self.ended:
            msg = "the export ended without its end line, so it did not finish"
            raise CollectionError(msg)
        if (
            self.trailer["records"] != self.records
            or self.trailer["sha256"] != self.digest.hexdigest()
        ):
            msg = (
                f"the export's end line does not match what arrived ({self.records} records "
                "received); the transfer was damaged"
            )
            raise CollectionError(msg)
        return Result(self.destination, self.records, tuple(self.gaps), tuple(self.incomplete))

    def publish(self, *, force: bool) -> None:
        """Put the checked file in place without following a link or clobbering."""
        winrm.publish_file(self.temp, self.destination, force=force)

    def discard(self) -> None:
        with contextlib.suppress(OSError):
            self.handle.close()
        with contextlib.suppress(OSError):
            self.temp.unlink()


def collect(  # noqa: PLR0913 - one argument per collection choice
    target: winrm.Target,
    script: str,
    script_parameters: dict[str, Any],
    destination: Path,
    *,
    force: bool,
    clock: Callable[[], float] = time.monotonic,
) -> Result:
    """Run the exporter on the target and write its file to ``destination``.

    Raises:
        CollectionError: The connection, authentication, or export failed, or
            what arrived does not match the exporter's end line. Every message has
            the secret removed, and no partial file is left.
    """
    try:
        sink = _Sink(destination)
    except OSError as exc:
        msg = f"cannot write to {destination.parent}: {exc.strerror or exc}"
        raise CollectionError(msg) from None
    return winrm.collect(
        target,
        script,
        script_parameters,
        destination,
        sink=sink,
        noun="exporter",
        hint=install_hint("ad"),
        force=force,
        clock=clock,
    )
