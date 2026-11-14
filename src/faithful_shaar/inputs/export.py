# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""Read a shaar export (JSON Lines) as the collectors write it.

Rules this reader applies, in addition to the format in the design:

- The header must be the first line and valid, or the file is refused (``InputError``).
- The trailer must be the last line. Its ``records`` is the number of lines between the
  header and the trailer (blank and unreadable lines included) and its ``sha256`` covers
  every byte before the trailer line. If any of that fails, the export is not trusted to
  be whole and **no resource is complete**.
- A line that is not a JSON object, is too long, or a record that is dropped without
  knowing which resource it belonged to, also leaves no resource complete.
- A grant dropped for a bad field marks only its resource as not complete.
- A grant whose principal or resource record is missing is **kept** with a stub (kind
  ``unknown`` or ``other``, the id as its name, ``extra["stub"] == "true"``) and a
  problem: the access exists in the source, and hiding it would be worse than showing it
  without details. A stub resource is never complete.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from faithful_shaar import keys
from faithful_shaar.errors import InputError
from faithful_shaar.inputs.combine import add_grant, parse_time
from faithful_shaar.model import (
    PRINCIPAL_KINDS,
    RESOURCE_KINDS,
    Grant,
    InputFile,
    Principal,
    Problem,
    Resource,
    Snapshot,
    Source,
)

if TYPE_CHECKING:
    from typing import BinaryIO

MAX_LINE_BYTES = 1 << 20
MAX_FILE_BYTES = 512 << 20
EXPORT_VERSION = 1
SYSTEMS = ("ad", "entra")
KIND = "shaar-export"
_RECORD_TYPES = ("principal", "resource", "grant", "gap")


def _text(value: object) -> str:
    return value if isinstance(value, str) else json.dumps(value, sort_keys=True)


@dataclass
class _PendingGrant:
    source: Source
    principal_key: str
    principal_id: str
    resource_id: str
    entitlement: str
    via: tuple[str, ...]
    extra: dict[str, str]


@dataclass
class _Reader:
    """State of one export while it is read."""

    name: str
    system: str = ""
    lineno: int = 0
    size: int = 0
    records: int = 0
    loss: bool = False
    tenant: str = ""
    domain: str = ""
    trailer_seen: bool = False
    trailer_ok: bool = False
    everything: Any = field(default_factory=hashlib.sha256)
    body: Any = field(default_factory=hashlib.sha256)
    snapshot: Snapshot = field(default_factory=lambda: Snapshot(label=""))
    resource_keys: dict[str, str] = field(default_factory=dict)
    complete: set[str] = field(default_factory=set)
    incomplete_ids: set[str] = field(default_factory=set)
    ambiguous: set[str] = field(default_factory=set)
    pending: list[_PendingGrant] = field(default_factory=list)

    # -- plumbing -------------------------------------------------------------------

    def source(self, lineno: int | None = None) -> Source:
        return Source(self.name, f"line {self.lineno if lineno is None else lineno}")

    def problem(self, source: Source, reason: str) -> None:
        self.snapshot.problems.append(Problem(source, reason))

    def read_line(self, stream: BinaryIO) -> bytes | None:
        """Return the next line (``b""`` at the end), or ``None`` when it is too long.

        Every byte read goes into the whole-file hash. A too-long line is also added to
        the body hash here, because it cannot be the trailer.
        """
        chunk = stream.readline(MAX_LINE_BYTES + 1)
        if not chunk:
            return b""
        self.lineno += 1
        self.take(chunk)
        if len(chunk) <= MAX_LINE_BYTES or chunk.endswith(b"\n"):
            return chunk
        self.body.update(chunk)
        while True:
            chunk = stream.readline(MAX_LINE_BYTES)
            self.take(chunk)
            self.body.update(chunk)
            if not chunk or chunk.endswith(b"\n"):
                return None

    def take(self, chunk: bytes) -> None:
        self.size += len(chunk)
        if self.size > MAX_FILE_BYTES:
            msg = f"{self.name} is larger than the limit of {MAX_FILE_BYTES} bytes"
            raise InputError(msg)
        self.everything.update(chunk)

    # -- fields ---------------------------------------------------------------------

    def string(self, record: dict[str, Any], name: str, source: Source, what: str) -> str:
        value = record.get(name)
        if value is None:
            return ""
        if isinstance(value, str):
            return value.strip()
        self.problem(source, f"{what} field {name!r} is not text; ignored")
        return ""

    def strings(self, record: dict[str, Any], name: str, source: Source, what: str) -> list[str]:
        value = record.get(name)
        if value is None:
            return []
        if not isinstance(value, list):
            self.problem(source, f"{what} field {name!r} is not a list; ignored")
            return []
        out = [v.strip() for v in value if isinstance(v, str) and v.strip()]
        if len(out) != len(value):
            self.problem(source, f"{what} field {name!r} has entries that are not text; skipped")
        return out

    def extras(self, record: dict[str, Any], source: Source, what: str) -> dict[str, str]:
        value = record.get("extra")
        if value is None:
            return {}
        if not isinstance(value, dict):
            self.problem(source, f"{what} field 'extra' is not an object; ignored")
            return {}
        return {str(k): _text(v) for k, v in value.items()}

    def kind(
        self, record: dict[str, Any], allowed: tuple[str, ...], default: str, source: Source
    ) -> str:
        value = self.string(record, "kind", source, "record")
        if value.casefold() in allowed:
            return value.casefold()
        if value:
            self.problem(source, f"unknown kind {value[:40]!r}; recorded as {default!r}")
        return default

    def identity(self, raw: str, *, role: bool = False) -> tuple[str, str]:
        """Return the key for a raw source id and a note when the key is weaker."""
        if self.system == "entra":
            make = keys.entra_role if role else keys.entra
            return make(self.tenant, raw), ""
        try:
            return keys.sid(raw, self.domain), ""
        except ValueError:
            return keys.dn(raw), "has no SID, so it is matched by distinguished name"

    # -- records --------------------------------------------------------------------

    def handle_principal(self, record: object, source: Source) -> None:
        if not isinstance(record, dict):
            self.problem(source, "principal record is not an object; skipped")
            return
        raw = self.string(record, "id", source, "principal")
        if not raw:
            self.problem(source, "principal record has no id; skipped")
            return
        key, note = self.identity(raw)
        if note:
            self.problem(source, f"principal {raw!r} {note}")
        manager = self.string(record, "manager_id", source, "principal")
        enabled = record.get("enabled")
        if enabled is not None and not isinstance(enabled, bool):
            self.problem(source, "principal field 'enabled' is not true or false; ignored")
            enabled = None
        principal = Principal(
            key=key,
            system=self.system,
            id=raw,
            name=self.string(record, "name", source, "principal") or raw,
            kind=self.kind(record, PRINCIPAL_KINDS, "unknown", source),
            enabled=enabled,
            email=self.string(record, "email", source, "principal"),
            upn=self.string(record, "upn", source, "principal"),
            manager_key=self.identity(manager)[0] if manager else "",
            last_sign_in=self.string(record, "last_sign_in", source, "principal"),
            source=source,
            extra=self.extras(record, source, "principal"),
        )
        if key in self.snapshot.principals:
            first = self.snapshot.principals[key].source
            self.problem(source, f"duplicate principal id {raw!r}; kept the one at {first}")
            return
        self.snapshot.principals[key] = principal

    def handle_resource(self, record: object, source: Source) -> None:
        if not isinstance(record, dict):
            self.problem(source, "resource record is not an object; skipped")
            return
        raw = self.string(record, "id", source, "resource")
        if not raw:
            self.problem(source, "resource record has no id; skipped")
            return
        kind = self.kind(record, RESOURCE_KINDS, "other", source)
        key, note = self.identity(raw, role=kind == "role")
        if note:
            self.problem(source, f"resource {raw!r} {note}")
        owners = [
            self.identity(o)[0] for o in self.strings(record, "owner_ids", source, "resource")
        ]
        complete = record.get("complete")
        if not isinstance(complete, bool):
            self.problem(source, "resource field 'complete' is not true or false; not complete")
            complete = False
        resource = Resource(
            key=key,
            system=self.system,
            id=raw,
            name=self.string(record, "name", source, "resource") or raw,
            kind=kind,
            owner_keys=tuple(dict.fromkeys(owners)),
            source=source,
            extra=self.extras(record, source, "resource"),
        )
        earlier = self.resource_keys.setdefault(keys.fold(raw), key)
        if earlier != key:
            # One raw id as two resources (a group and a role, say): a grant naming that id
            # could belong to either, so neither is read in full.
            self.problem(
                source,
                f"resource id {raw!r} is also given as another resource ({earlier}); "
                "its grants cannot be placed, so neither is treated as complete",
            )
            self.ambiguous.update({earlier, key})
        if key in self.snapshot.resources:
            first = self.snapshot.resources[key].source
            self.problem(source, f"duplicate resource id {raw!r}; kept the one at {first}")
            complete = False
        else:
            self.snapshot.resources[key] = resource
        if complete:
            self.complete.add(key)
        else:
            self.complete.discard(key)
            self.incomplete_ids.add(keys.fold(raw))

    def drop_grant(self, source: Source, reason: str, resource_id: str) -> None:
        self.problem(source, f"grant skipped: {reason}")
        if resource_id:
            self.incomplete_ids.add(keys.fold(resource_id))
        else:
            self.loss = True

    def handle_grant(self, record: object, source: Source) -> None:
        if not isinstance(record, dict):
            self.problem(source, "grant record is not an object; skipped")
            self.loss = True
            return
        pid = self.string(record, "principal_id", source, "grant")
        rid = self.string(record, "resource_id", source, "grant")
        entitlement = self.string(record, "entitlement", source, "grant")
        via_raw = record.get("via")
        if not (pid and rid and entitlement):
            self.drop_grant(source, "principal_id, resource_id or entitlement is missing", rid)
        elif via_raw is not None and not (
            isinstance(via_raw, list) and all(isinstance(v, str) for v in via_raw)
        ):
            self.drop_grant(source, "'via' is not a list of names", rid)
        else:
            via = tuple(v.strip() for v in via_raw or [] if v.strip())
            self.pending.append(
                _PendingGrant(
                    source,
                    self.identity(pid)[0],
                    pid,
                    rid,
                    entitlement,
                    via,
                    self.extras(record, source, "grant"),
                )
            )

    def handle_gap(self, record: object, source: Source) -> None:
        if not isinstance(record, dict):
            self.problem(source, "gap record is not an object; skipped")
            return
        what = self.string(record, "what", source, "gap") or "something"
        reason = self.string(record, "reason", source, "gap") or "no reason given"
        self.problem(source, f"not read: {what}: {reason}")

    # -- structure ------------------------------------------------------------------

    def header(self, stream: BinaryIO) -> None:
        line = self.read_line(stream)
        if not line:
            msg = f"{self.name} is empty or its first line is too long to be a shaar export"
            raise InputError(msg)
        try:
            head = json.loads(line)
        except ValueError as exc:
            msg = f"{self.name}, line 1 is not JSON, so this is not a shaar export"
            raise InputError(msg) from exc
        if not isinstance(head, dict) or head.get("shaar_export") != EXPORT_VERSION:
            msg = f"{self.name} has no shaar_export {EXPORT_VERSION} header on line 1"
            raise InputError(msg)
        if head.get("system") not in SYSTEMS:
            shown = _text(head.get("system"))[:40]
            msg = f"{self.name} header names system {shown!r}; expected ad or entra"
            raise InputError(msg)
        self.system = head["system"]
        self.snapshot.systems.add(self.system)
        self.header_fields(head)
        self.body.update(line)

    def header_fields(self, head: dict[str, Any]) -> None:
        source = self.source(1)
        stamp = head.get("collected_at")
        if isinstance(stamp, str) and parse_time(stamp) is not None:
            self.snapshot.collected_at = stamp.strip()
        else:
            self.problem(source, "header has no valid collected_at (ISO 8601 with Z or offset)")
        context = self.snapshot.context
        for name in ("scope", "collector"):
            if name in head:
                context[f"{name}[{self.name}]"] = _text(head[name])
        for name in ("tenant", "domain", "cloud"):
            if name in head:
                context[f"{name}[{self.name}]"] = _text(head[name])
        # Keys are tied to their directory: the tenant for Entra ID, the domain for the
        # well-known SIDs every domain shares. Without it, nothing here is read in full.
        self.tenant = _text(head.get("tenant", "")) if self.system == "entra" else ""
        self.domain = _text(head.get("domain", "")) if self.system == "ad" else ""
        if self.system == "entra" and keys.tenant(self.tenant) == keys.UNKNOWN:
            self.problem(
                source, "header names no tenant id, so this export proves no complete read"
            )
            self.loss = True
        if self.system == "ad" and not self.domain.strip():
            self.problem(
                source, "header names no domain, so well-known groups cannot be tied to one"
            )

    def classify(self, line: bytes | None) -> None:
        """Handle one body line (everything after the header)."""
        source = self.source()
        if line is None:
            self.problem(source, f"line is longer than {MAX_LINE_BYTES} bytes; skipped")
            self.loss = True
            return
        if self.trailer_seen:
            if line.strip():
                self.problem(source, "data after the trailer; the export is not trusted")
                self.trailer_ok = False
            self.body.update(line)
            return
        if not line.strip():
            self.problem(source, "empty line")
        else:
            self.dispatch(line, source)

    def dispatch(self, line: bytes, source: Source) -> None:
        try:
            obj = json.loads(line)
        except (ValueError, RecursionError):
            obj = None
        if not isinstance(obj, dict):
            self.problem(source, "line is not a JSON object; skipped")
            self.loss = True
            return
        if "end" in obj:
            self.trailer(obj, source)
            return
        kinds = [k for k in obj if k in _RECORD_TYPES]
        if len(obj) == 1 and kinds:
            getattr(self, f"handle_{kinds[0]}")(obj[kinds[0]], source)
        elif kinds:
            self.problem(source, "record has more than one member; skipped")
            self.loss = True
        else:
            # A record this reader does not know may have held access, so a skipped one
            # means no membership here can be shown to be complete.
            self.problem(source, f"unknown record type {next(iter(obj), '')[:40]!r}; skipped")
            self.loss = True

    def trailer(self, obj: dict[str, Any], source: Source) -> None:
        self.trailer_seen = True
        count = obj.get("records")
        digest = obj.get("sha256")
        found = self.body.hexdigest()
        reasons = []
        if obj.get("end") is not True:
            reasons.append("the trailer's 'end' is not true")
        if isinstance(count, bool) or count != self.records:
            reasons.append(f"the trailer counts {_text(count)[:20]} records, {self.records} read")
        if not isinstance(digest, str) or digest.strip().casefold() != found:
            reasons.append("the trailer's sha256 does not match the bytes read")
        self.trailer_ok = not reasons
        if reasons:
            self.problem(source, "; ".join(reasons) + "; the export may be cut short or altered")

    def run(self, stream: BinaryIO) -> None:
        self.header(stream)
        while True:
            line = self.read_line(stream)
            if line == b"":
                break
            before = self.trailer_seen
            self.classify(line)
            if not before and not self.trailer_seen:
                self.records += 1
            if line is not None and not (self.trailer_seen and self.trailer_ok):
                self.body.update(line)
        if not self.trailer_seen:
            self.problem(self.source(), "no trailer at the end of the file; it may be cut short")

    # -- result ---------------------------------------------------------------------

    def stub_principal(self, pending: _PendingGrant) -> None:
        snap = self.snapshot
        known = snap.principals.get(pending.principal_key)
        if known is None:
            snap.principals[pending.principal_key] = Principal(
                key=pending.principal_key,
                system=self.system,
                id=pending.principal_id,
                name=pending.principal_id,
                source=pending.source,
                extra={"stub": "true"},
            )
        elif "stub" not in known.extra:
            return
        self.problem(pending.source, "grant names a principal with no record; kept with a stub")

    def resolve_resource(self, pending: _PendingGrant) -> str:
        snap = self.snapshot
        key = self.resource_keys.get(keys.fold(pending.resource_id))
        if key is None:
            key, _ = self.identity(pending.resource_id)
            self.resource_keys[keys.fold(pending.resource_id)] = key
            snap.resources[key] = Resource(
                key=key,
                system=self.system,
                id=pending.resource_id,
                name=pending.resource_id,
                kind="other",
                source=pending.source,
                extra={"stub": "true"},
            )
        elif "stub" not in snap.resources[key].extra:
            return key
        self.problem(pending.source, "grant names a resource with no record; kept with a stub")
        return key

    def finish(self) -> None:
        snap = self.snapshot
        for pending in self.pending:
            self.stub_principal(pending)
            rkey = self.resolve_resource(pending)
            add_grant(
                snap.grants,
                Grant(
                    key=keys.grant(rkey, pending.principal_key, pending.entitlement),
                    system=self.system,
                    principal_key=pending.principal_key,
                    resource_key=rkey,
                    entitlement=pending.entitlement,
                    via=pending.via,
                    source=pending.source,
                    extra=pending.extra,
                ),
            )
        if self.loss:
            self.problem(
                Source(self.name),
                "some lines could not be read, so no resource is treated as complete",
            )
        if self.trailer_ok and not self.loss:
            lost = {self.resource_keys.get(i) for i in self.incomplete_ids} | self.ambiguous
            snap.complete_resources = {k for k in self.complete if k not in lost}


def read_export(stream: BinaryIO, name: str) -> tuple[Snapshot, InputFile]:
    """Read a shaar export from ``stream``; ``name`` is its display name.

    Returns the snapshot and the file's fingerprint (size and SHA-256 of every byte).
    Raises :class:`InputError` when the header is missing or invalid, or the file is
    larger than :data:`MAX_FILE_BYTES`. Everything else becomes a problem.
    """
    reader = _Reader(name)
    reader.run(stream)
    reader.finish()
    reader.snapshot.label = name
    info = InputFile(name, KIND, reader.size, reader.everything.hexdigest())
    reader.snapshot.inputs.append(info)
    return reader.snapshot, info
