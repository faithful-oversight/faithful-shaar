# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""Run the exporter on a domain controller over PowerShell remoting.

The packaged script is sent to the controller and run there with ``-ToPipeline``.
Its lines stream back and are written to a file next to the destination, and the
file is published only after its end line checks out: the record count and the
SHA-256 the script computed over everything it sent before the end line must match
what arrived. A partial file is never left behind.

Transport security is not optional. HTTPS (port 5986) always verifies the server's
certificate against the system's roots or ``--ca-file``. Plain HTTP (port 5985) is
accepted only with Kerberos, Negotiate, or NTLM message encryption required, which
pypsrp then enforces. Basic and CredSSP authentication are not offered.

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
import hashlib
import importlib
import json
import os
import shutil
import time
import uuid
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from faithful_shaar.collect.names import install_hint
from faithful_shaar.collect.secrets import redact, remember
from faithful_shaar.errors import CollectionError

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

AUTHS = ("kerberos", "negotiate", "ntlm")
TRANSPORTS = ("https", "http")
POLL_SECONDS = 5
"""How long one wait for output lasts before shaar checks the idle timeout."""
MAX_LINE = 1024 * 1024
"""The longest line an export may hold, in bytes."""
MAX_FILE = 512 * 1024 * 1024
"""The largest export shaar accepts, in bytes."""
_RECORDS = ("principal", "resource", "grant", "gap")
_INSTALL = f"remote collection needs pypsrp; install it with: {install_hint('ad')}"


@dataclass(frozen=True)
class Target:
    r"""Where and how to connect.

    Attributes:
        server: The controller's fully qualified DNS name.
        auth: One of :data:`AUTHS`.
        username: ``DOMAIN\\user``, or ``None`` to use the current Kerberos ticket.
        secret: The password, already resolved, or ``None``.
        transport: ``https`` or ``http`` (with message encryption).
        port: The port, or ``None`` for 5986 or 5985.
        ca_file: A PEM file of certificate authorities to trust for HTTPS.
        connect_timeout: Seconds to wait for the connection.
        idle_timeout: Seconds without output after which collection stops.
    """

    server: str
    auth: str
    username: str | None = None
    secret: str | None = field(default=None, repr=False)
    transport: str = "https"
    port: int | None = None
    ca_file: Path | None = None
    connect_timeout: int = 30
    idle_timeout: int = 600


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


def settings(target: Target) -> dict[str, Any]:
    """Return the WSMan settings for a target, refusing any insecure combination.

    Raises:
        CollectionError: The authentication or transport is not one shaar offers.
    """
    if target.auth not in AUTHS or target.transport not in TRANSPORTS:
        msg = f"--auth must be one of {', '.join(AUTHS)} over https or encrypted http"
        raise CollectionError(msg)
    https = target.transport == "https"
    if target.ca_file is not None and not https:
        msg = "--ca-file applies to https only"
        raise CollectionError(msg)
    return {
        "server": target.server,
        "port": target.port or (5986 if https else 5985),
        "ssl": https,
        "auth": target.auth,
        "username": target.username,
        "password": target.secret,
        # A path is a CA bundle to verify against; True uses the system's roots.
        # There is no setting that turns verification off.
        "cert_validation": str(target.ca_file) if target.ca_file else True,
        "encryption": "auto" if https else "always",
        "connection_timeout": target.connect_timeout,
        "operation_timeout": POLL_SECONDS,
        "read_timeout": POLL_SECONDS + 30,
    }


def _client() -> tuple[Any, Any, Any, int]:
    """Import pypsrp's WSMan, RunspacePool, and PowerShell, and its running state."""
    try:
        wsman = importlib.import_module("pypsrp.wsman")
        powershell = importlib.import_module("pypsrp.powershell")
        objects = importlib.import_module("pypsrp.complex_objects")
    except ImportError:
        raise CollectionError(_INSTALL) from None
    running: int = objects.PSInvocationState.RUNNING
    return wsman.WSMan, powershell.RunspacePool, powershell.PowerShell, running


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


def _copy_new(source: Path, destination: Path) -> None:
    """Copy to a name created exclusively, owner-only; a failed copy removes it."""
    descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as target, source.open("rb") as origin:
            shutil.copyfileobj(origin, target)
    except BaseException:
        with contextlib.suppress(OSError):
            destination.unlink()
        raise


def publish(temp: Path, destination: Path, *, force: bool) -> None:
    """Put a finished private file in place without following a link or clobbering.

    The temporary file is consumed. Without ``force`` an existing name, even a
    dangling link, is never replaced.

    Raises:
        CollectionError: The destination exists (and ``force`` is off) or cannot be written.
    """
    if force:
        try:
            temp.replace(destination)
        except OSError as exc:
            msg = f"cannot write {destination}: {exc.strerror or exc}"
            raise CollectionError(msg) from exc
        return
    exists = f"{destination} already exists; pass --force to replace it"
    try:
        try:
            os.link(temp, destination)
        except FileExistsError:
            raise
        except OSError:
            # No hard links here (FAT, exFAT, some network shares): create the name
            # exclusively and copy.
            _copy_new(temp, destination)
    except FileExistsError:
        raise CollectionError(exists) from None
    except OSError as exc:
        msg = f"cannot write {destination}: {exc.strerror or exc}"
        raise CollectionError(msg) from exc
    temp.unlink()


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
        publish(temp, destination, force=force)
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

    def finish(self) -> None:
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

    def publish(self, *, force: bool) -> None:
        """Put the checked file in place without following a link or clobbering."""
        publish(self.temp, self.destination, force=force)

    def discard(self) -> None:
        with contextlib.suppress(OSError):
            self.handle.close()
        with contextlib.suppress(OSError):
            self.temp.unlink()


def collect(  # noqa: PLR0913 - one argument per collection choice
    target: Target,
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
    if target.secret:
        remember(target.secret)
    if os.path.lexists(destination) and not force:
        msg = f"{destination} already exists; pass --force to replace it"
        raise CollectionError(msg)
    wsman_class, pool_class, powershell_class, running = _client()
    try:
        sink = _Sink(destination)
    except OSError as exc:
        msg = f"cannot write to {destination.parent}: {exc.strerror or exc}"
        raise CollectionError(msg) from None
    try:
        with wsman_class(**settings(target)) as wsman, pool_class(wsman) as pool:
            shell = powershell_class(pool)
            shell.add_script(script)
            shell.add_parameters(script_parameters)
            shell.begin_invoke()
            _drain(shell, sink, running, target.idle_timeout, clock)
            _check_failed(shell, sink, target.server)
        sink.finish()
        sink.publish(force=force)
    except CollectionError as exc:
        sink.discard()
        raise CollectionError(redact(str(exc))) from None
    except Exception as exc:  # noqa: BLE001 - any library error, made safe to show
        sink.discard()
        text = redact(str(exc)) or type(exc).__name__
        msg = f"remote collection from {target.server} failed: {text}"
        raise CollectionError(msg) from None
    return Result(destination, sink.records, tuple(sink.gaps), tuple(sink.incomplete))


def _check_failed(shell: Any, sink: _Sink, server: str) -> None:
    """Report the script's own error when it stopped before its end line."""
    if not sink.ended and shell.had_errors:
        errors = [str(error) for error in getattr(shell.streams, "error", [])]
        reason = errors[0] if errors else "the script stopped with an error"
        msg = f"the exporter failed on {server}: {reason}"
        raise CollectionError(msg)


def _drain(
    shell: Any, sink: _Sink, running_state: int, idle_timeout: int, clock: Callable[[], float]
) -> None:
    """Take output as it arrives until the script ends, or stop it when it stalls."""
    last = clock()
    while True:
        running = shell.state == running_state
        if running:
            shell.poll_invoke(timeout=POLL_SECONDS)
        output = shell.output
        if output:
            for item in output:
                sink.take(item)
            output.clear()
            last = clock()
        if not running:
            return
        if clock() - last > idle_timeout:
            with contextlib.suppress(Exception):
                shell.stop()
            msg = f"the exporter sent nothing for {idle_timeout} seconds and was stopped"
            raise CollectionError(msg)
