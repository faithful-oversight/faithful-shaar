# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""Synthetic access data for tests: shaar export bytes and CSV bytes.

Everything here is made up: the domain is ``corp.example``, people are "Avery Example",
SIDs are ``S-1-5-21-1000-1000-1000-<rid>`` and object ids end in a counter.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence
    from pathlib import Path

DOMAIN_SID = "S-1-5-21-1000-1000-1000"
COLLECTED_AT = "2026-11-01T12:00:00Z"
GENERIC_HEADERS = (
    "principal_id",
    "principal_name",
    "principal_kind",
    "enabled",
    "email",
    "upn",
    "manager_id",
    "last_sign_in",
    "resource_id",
    "resource_name",
    "resource_kind",
    "owner_ids",
    "entitlement",
    "via",
    "system",
)


def sid(rid: int) -> str:
    """Return a synthetic domain SID with relative id ``rid``."""
    return f"{DOMAIN_SID}-{rid}"


def guid(number: int) -> str:
    """Return a synthetic object id ending in ``number``."""
    return f"00000000-0000-4000-8000-{number:012d}"


def principal(ident: str, name: Any = "Avery Example", **fields: Any) -> dict[str, Any]:
    """Return a ``principal`` export record."""
    body: dict[str, Any] = {"id": ident, "name": name, "kind": "user", "enabled": True}
    body.update(fields)
    return {"principal": body}


def resource(ident: str, name: str = "Tier0 Admins", **fields: Any) -> dict[str, Any]:
    """Return a ``resource`` export record (complete unless told otherwise)."""
    body: dict[str, Any] = {"id": ident, "name": name, "kind": "group", "complete": True}
    body.update(fields)
    return {"resource": body}


def grant(
    principal_id: str, resource_id: str, entitlement: str = "member", **fields: Any
) -> dict[str, Any]:
    """Return a ``grant`` export record."""
    body: dict[str, Any] = {
        "principal_id": principal_id,
        "resource_id": resource_id,
        "entitlement": entitlement,
    }
    body.update(fields)
    return {"grant": body}


def line(record: dict[str, Any]) -> bytes:
    """Return one JSON Lines line (compact, UTF-8, LF)."""
    return json.dumps(record, separators=(",", ":"), ensure_ascii=False).encode() + b"\n"


def export_bytes(
    records: Iterable[dict[str, Any] | bytes],
    *,
    system: str = "ad",
    header: dict[str, Any] | None = None,
    trailer: bool | dict[str, Any] = True,
) -> bytes:
    """Build a shaar export.

    ``records`` are dicts (written as lines) or raw bytes (written as they are, so a
    test can add a malformed line). ``header`` replaces header fields (a ``None`` value
    removes one). ``trailer`` is ``True`` for a correct trailer, ``False`` for none, or a
    dict of fields that replace the correct ones (a ``None`` value removes one).
    """
    head: dict[str, Any] = {
        "shaar_export": 1,
        "system": system,
        "collector": {"name": "test", "version": "0"},
        "collected_at": COLLECTED_AT,
        "scope": {"groups": ["Tier0 Admins"]},
    }
    head["domain" if system == "ad" else "tenant"] = "corp.example" if system == "ad" else guid(0)
    for key, value in (header or {}).items():
        if value is None:
            head.pop(key, None)
        else:
            head[key] = value
    parts = [line(head)]
    count = 0
    for record in records:
        parts.append(record if isinstance(record, bytes) else line(record))
        count += 1
    body = b"".join(parts)
    if trailer is False:
        return body
    end: dict[str, Any] = {
        "end": True,
        "records": count,
        "sha256": hashlib.sha256(body).hexdigest(),
    }
    if isinstance(trailer, dict):
        for key, value in trailer.items():
            if value is None:
                end.pop(key, None)
            else:
                end[key] = value
    return body + line(end)


def csv_bytes(
    headers: Sequence[str],
    rows: Iterable[Sequence[str]],
    *,
    delimiter: str = ",",
    encoding: str = "utf-8",
    bom: bool = False,
) -> bytes:
    """Build a CSV file; ``bom`` writes a byte order mark for UTF-8 and UTF-16."""
    buffer = io.StringIO(newline="")
    writer = csv.writer(buffer, delimiter=delimiter, lineterminator="\r\n")
    writer.writerow(headers)
    writer.writerows(rows)
    text = buffer.getvalue()
    if encoding.casefold().replace("-", "").replace("_", "") in {"utf16", "utf16le", "utf16be"}:
        if encoding.casefold().endswith("be"):
            return (b"\xfe\xff" if bom else b"") + text.encode("utf-16-be")
        return (b"\xff\xfe" if bom else b"") + text.encode("utf-16-le")
    prefix = b"\xef\xbb\xbf" if bom else b""
    return prefix + text.encode(encoding)


def generic_row(**fields: str) -> list[str]:
    """Return a row for :data:`GENERIC_HEADERS`; unnamed columns are empty."""
    return [fields.get(name, "") for name in GENERIC_HEADERS]


def write(directory: Path, name: str, data: bytes) -> Path:
    """Write ``data`` to ``directory / name`` and return the path."""
    path = directory / name
    path.write_bytes(data)
    return path
