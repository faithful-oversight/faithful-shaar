# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""Read a CSV of access into model objects, using a column map.

shaar cannot know whether a CSV holds everything. Every resource a CSV mentions is
treated as complete unless the map says ``complete = false``, a row had to be skipped,
or the file could not be read to its end. Cells are text: nothing in them is evaluated,
whatever it looks like (``=SUM(...)``, ``@x``, ``+1``).

A blank (or unmapped) entitlement means ``member``.

Row numbers are 1-based file line numbers, the header counting as row 1 (a row that
spans several lines is cited by its first line).
"""

from __future__ import annotations

import codecs
import csv
import hashlib
import io
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, TypeVar

from faithful_shaar import keys
from faithful_shaar.errors import InputError
from faithful_shaar.inputs.combine import (
    add_grant,
    differing_principal_fields,
    differing_resource_fields,
)
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
    from collections.abc import Callable, Iterator, Mapping
    from typing import BinaryIO

    from faithful_shaar.inputs.csvmap import CsvMap

MAX_CSV_BYTES = 256 << 20
MAX_ROWS = 2_000_000
KIND = "csv"
DELIMITERS = (",", ";", "\t", "|")

_T = TypeVar("_T", Principal, Resource)


class _Skip(Exception):  # noqa: N818 - control flow inside this module only
    """The row cannot be used; the message says why."""


def decode(raw: bytes, forced: str, name: str) -> str:
    """Decode a CSV: ``forced`` encoding, else by byte order mark, else strict UTF-8."""
    if forced:
        encoding = forced
    elif raw.startswith(codecs.BOM_UTF8):
        encoding = "utf-8-sig"
    elif raw.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)):
        encoding = "utf-16"
    else:
        encoding = "utf-8"
    try:
        text = raw.decode(encoding)
    except UnicodeDecodeError as exc:
        msg = (
            f"{name} cannot be decoded as {encoding} (byte {exc.start}); "
            "set `encoding` in the column map"
        )
        raise InputError(msg) from exc
    if "\x00" in text:
        msg = f"{name} contains NUL characters, so it is not a text CSV"
        raise InputError(msg)
    return text.removeprefix("﻿")


def sniff(text: str, forced: str, name: str) -> str:
    """Return the delimiter: ``forced``, else the one that splits the header line most."""
    first = next((line for line in text.split("\n") if line.strip()), "")
    if not first:
        msg = f"{name} has no header row"
        raise InputError(msg)
    if forced:
        return forced
    try:
        counts = {d: len(next(csv.reader([first], delimiter=d))) for d in DELIMITERS}
    except csv.Error as exc:
        msg = f"{name} header cannot be read: {exc}"
        raise InputError(msg) from exc
    return max(DELIMITERS, key=lambda d: counts[d])


def _records(reader: Any) -> Iterator[tuple[int, list[str] | csv.Error]]:
    while True:
        start = reader.line_num + 1
        try:
            row = next(reader)
        except StopIteration:
            return
        except csv.Error as exc:
            yield start, exc
            continue
        yield start, row


@dataclass
class _Row:
    values: dict[str, str]
    extras: dict[str, dict[str, str]]


@dataclass
class _Ident:
    key: str
    id: str
    name: str
    system: str


@dataclass
class _Tally:
    first: Source
    count: int = 0


@dataclass
class _Reader:
    """State of one CSV while it is read."""

    name: str
    cmap: CsvMap
    snapshot: Snapshot = field(default_factory=lambda: Snapshot(label=""))
    cols: dict[str, int] = field(default_factory=dict)
    extra_cols: dict[str, dict[str, int]] = field(default_factory=dict)
    width: int = 0
    loss: bool = False
    incomplete: set[str] = field(default_factory=set)
    tallies: dict[tuple[str, str], _Tally] = field(default_factory=dict)

    # -- header ---------------------------------------------------------------------

    def resolve(self, header: list[str], number: int) -> None:
        index: dict[str, int] = {}
        repeated: set[str] = set()
        for position, cell in enumerate(header):
            key = cell.strip().casefold()
            if key in index:
                repeated.add(key)
            elif key:
                index[key] = position
        self.width = len(header)
        cmap = self.cmap
        self.cols = self.find(cmap.columns, index, repeated)
        if cmap.resource:
            self.cols.pop("resource_id", None)
            self.cols.pop("resource_name", None)
        for group, names in (
            ("principal", cmap.extra_principal),
            ("resource", cmap.extra_resource),
            ("grant", cmap.extra_grant),
        ):
            self.extra_cols[group] = self.find({n: n for n in names}, index, repeated)
        self.check_columns(number)

    def find(
        self, wanted: Mapping[str, str], index: dict[str, int], repeated: set[str]
    ) -> dict[str, int]:
        found: dict[str, int] = {}
        for label, header in wanted.items():
            key = header.casefold()
            if key in repeated:
                msg = f"{self.name} has more than one column named {header!r}"
                raise InputError(msg)
            if key in index:
                found[label] = index[key]
            elif not self.cmap.optional:
                msg = f"{self.name} has no column {header!r} (mapped to {label})"
                raise InputError(msg)
        return found

    def check_columns(self, number: int) -> None:
        cols, cmap = self.cols, self.cmap
        if "principal_id" not in cols and "principal_name" not in cols:
            msg = f"{self.name}: the map names no principal_id or principal_name column in the file"
            raise InputError(msg)
        if not (cmap.resource or "resource_id" in cols or "resource_name" in cols):
            msg = f"{self.name}: no resource column, and no fixed resource (--resource or map)"
            raise InputError(msg)
        if not cmap.system and "system" not in cols:
            msg = (
                f"{self.name}: name the system with a `system` column or `system = ...` in the map"
            )
            raise InputError(msg)
        source = Source(self.name, f"row {number}")
        if "principal_id" not in cols:
            reason = "no principal_id column: principals are matched by name, which is weaker"
            self.snapshot.problems.append(Problem(source, reason))
        # A resource the map or --resource names is fixed by whoever runs shaar, so the
        # same name is used for every export of it; only a name read from rows is weaker.
        if not cmap.resource and "resource_id" not in cols:
            reason = "no resource id: the resource is matched by name, which is weaker"
            self.snapshot.problems.append(Problem(source, reason))

    # -- rows -----------------------------------------------------------------------

    def tally(self, label: str, value: str, source: Source) -> None:
        self.tallies.setdefault((label, value), _Tally(source)).count += 1

    def drop(self, source: Source, reason: str, resource_key: str | None) -> None:
        self.snapshot.problems.append(Problem(source, f"row skipped: {reason}"))
        if resource_key is None:
            self.loss = True
        else:
            self.incomplete.add(resource_key)

    def row(self, number: int, cells: list[str]) -> None:
        source = Source(self.name, f"row {number}")
        try:
            row = self.split(cells)
            system = self.system(row)
            resource = self.resource_ident(row, system)
        except _Skip as skip:
            self.drop(source, str(skip), None)
            return
        try:
            principal_ident = self.principal_ident(row, system)
            principal = self.make_principal(row, principal_ident, system, source)
            resource_rec = self.make_resource(row, resource, system, source)
            grant = self.make_grant(row, principal, resource_rec, source)
        except _Skip as skip:
            self.drop(source, str(skip), resource.key)
            return
        self.keep(self.snapshot.principals, principal, differing_principal_fields)
        self.keep(self.snapshot.resources, resource_rec, differing_resource_fields)
        add_grant(self.snapshot.grants, grant)

    def keep(self, known: dict[str, _T], item: _T, compare: Callable[[_T, _T], list[str]]) -> None:
        first = known.setdefault(item.key, item)
        differing = compare(first, item) if first is not item else []
        if differing:
            reason = f"{item.id!r} differs from the record at {first.source} in: " + ", ".join(
                differing
            )
            self.snapshot.problems.append(Problem(item.source, reason + "; kept the first"))

    def split(self, cells: list[str]) -> _Row:
        if len(cells) > self.width:
            msg = f"it has {len(cells)} cells but the header has {self.width}"
            raise _Skip(msg)
        values = {f: cells[i].strip() if i < len(cells) else "" for f, i in self.cols.items()}
        extras = {
            group: {
                n: cells[i].strip() for n, i in cols.items() if i < len(cells) and cells[i].strip()
            }
            for group, cols in self.extra_cols.items()
        }
        return _Row(values, extras)

    def system(self, row: _Row) -> str:
        value = row.values.get("system", "") or self.cmap.system
        try:
            return keys.system_name(value)
        except ValueError as exc:
            raise _Skip(str(exc)) from exc

    def ident(self, raw: str, name: str, system: str, *, by_id: bool) -> _Ident:
        style = self.cmap.id_style
        try:
            if by_id and style == "sid":
                return _Ident(keys.sid(raw), raw, name or raw, "ad")
            if by_id and style == "entra":
                return _Ident(keys.entra(raw), raw, name or raw, "entra")
            if by_id:
                return _Ident(keys.csv(system, raw), raw, name or raw, f"csv:{system}")
            return _Ident(keys.csv(system, name), name, name, f"csv:{system}")
        except ValueError as exc:
            raise _Skip(str(exc)) from exc

    def resource_ident(self, row: _Row, system: str) -> _Ident:
        values = row.values
        if self.cmap.resource:
            return self.ident("", self.cmap.resource, system, by_id=False)
        if "resource_id" in self.cols:
            if not values["resource_id"]:
                msg = "resource_id is empty"
                raise _Skip(msg)
            return self.ident(
                values["resource_id"], values.get("resource_name", ""), system, by_id=True
            )
        if not values["resource_name"]:
            msg = "resource_name is empty"
            raise _Skip(msg)
        return self.ident("", values["resource_name"], system, by_id=False)

    def principal_ident(self, row: _Row, system: str) -> _Ident:
        values = row.values
        if "principal_id" in self.cols:
            if not values["principal_id"]:
                msg = "principal_id is empty"
                raise _Skip(msg)
            return self.ident(
                values["principal_id"], values.get("principal_name", ""), system, by_id=True
            )
        if not values["principal_name"]:
            msg = "principal_name is empty"
            raise _Skip(msg)
        return self.ident("", values["principal_name"], system, by_id=False)

    def person_key(self, raw: str, system: str) -> str:
        """Return the key of a manager or owner, written the way principals are."""
        return self.ident(raw, raw, system, by_id="principal_id" in self.cols).key

    def kind(self, raw: str, source: Source) -> str:
        text = raw.casefold()
        if not text:
            return "unknown"
        if text in self.cmap.principal_kinds:
            return self.cmap.principal_kinds[text]
        if text in PRINCIPAL_KINDS:
            return text
        self.tally("principal kind", raw, source)
        return "unknown"

    def enabled(self, raw: str, source: Source) -> bool | None:
        text = raw.casefold()
        if not text:
            return None
        if text in self.cmap.enabled_true:
            return True
        if text in self.cmap.enabled_false:
            return False
        self.tally("enabled value", raw, source)
        return None

    def manager(self, raw: str, system: str, source: Source) -> str:
        if not raw:
            return ""
        try:
            return self.person_key(raw, system)
        except _Skip as skip:
            self.snapshot.problems.append(Problem(source, f"manager ignored: {skip}"))
            return ""

    def make_principal(self, row: _Row, ident: _Ident, system: str, source: Source) -> Principal:
        values = row.values
        return Principal(
            key=ident.key,
            system=ident.system,
            id=ident.id,
            name=ident.name,
            kind=self.kind(values.get("principal_kind", ""), source),
            enabled=self.enabled(values.get("enabled", ""), source),
            email=values.get("email", ""),
            upn=values.get("upn", ""),
            manager_key=self.manager(values.get("manager_id", ""), system, source),
            last_sign_in=values.get("last_sign_in", ""),
            source=source,
            extra=row.extras["principal"],
        )

    def owners(self, raw: str, system: str, source: Source) -> tuple[str, ...]:
        found: list[str] = []
        for part in raw.split(self.cmap.owner_separator):
            if not part.strip():
                continue
            try:
                found.append(self.person_key(part.strip(), system))
            except _Skip as skip:
                self.snapshot.problems.append(Problem(source, f"owner ignored: {skip}"))
        return tuple(dict.fromkeys(found))

    def make_resource(self, row: _Row, ident: _Ident, system: str, source: Source) -> Resource:
        values = row.values
        raw_kind = values.get("resource_kind", "").casefold()
        default = self.cmap.resource_kind or "other"
        if raw_kind in RESOURCE_KINDS:
            kind = raw_kind
        else:
            kind = default
            if raw_kind:
                self.tally("resource kind", values["resource_kind"], source)
        return Resource(
            key=ident.key,
            system=ident.system,
            id=ident.id,
            name=ident.name,
            kind=kind,
            owner_keys=self.owners(values.get("owner_ids", ""), system, source),
            source=source,
            extra=row.extras["resource"],
        )

    def make_grant(
        self, row: _Row, principal: Principal, resource: Resource, source: Source
    ) -> Grant:
        values = row.values
        entitlement = values.get("entitlement", "") or "member"
        via = tuple(
            part.strip()
            for part in values.get("via", "").split(self.cmap.via_separator)
            if part.strip()
        )
        return Grant(
            key=keys.grant(resource.key, principal.key, entitlement),
            system=resource.system,
            principal_key=principal.key,
            resource_key=resource.key,
            entitlement=entitlement,
            via=via,
            source=source,
            extra=row.extras["grant"],
        )

    # -- whole file -----------------------------------------------------------------

    def run(self, text: str, delimiter: str) -> None:
        reader = csv.reader(io.StringIO(text, newline=""), delimiter=delimiter)
        records = _records(reader)
        header: list[str] | None = None
        data_rows = 0
        for number, record in records:
            if isinstance(record, csv.Error):
                self.fail_row(number, record, in_header=header is None)
            elif header is None:
                if any(cell.strip() for cell in record):
                    header = record
                    self.resolve(header, number)
            elif any(cell.strip() for cell in record):
                data_rows += 1
                if data_rows > MAX_ROWS:
                    msg = f"{self.name} has more than {MAX_ROWS} rows"
                    raise InputError(msg)
                self.row(number, record)
        if header is None:
            msg = f"{self.name} has no header row"
            raise InputError(msg)

    def fail_row(self, number: int, error: csv.Error, *, in_header: bool) -> None:
        if in_header:
            msg = f"{self.name} header cannot be read: {error}"
            raise InputError(msg)
        self.snapshot.problems.append(
            Problem(Source(self.name, f"row {number}"), f"row cannot be read: {error}")
        )
        self.loss = True

    def finish(self) -> None:
        snap = self.snapshot
        for (label, value), tally in sorted(self.tallies.items()):
            reason = f"{label} {value!r} not recognised ({tally.count} rows); recorded as unknown"
            snap.problems.append(Problem(tally.first, reason))
        if self.loss:
            snap.problems.append(
                Problem(
                    Source(self.name),
                    "some rows could not be read, so no resource is treated as complete",
                )
            )
        snap.collected_at = self.cmap.collected_at
        snap.systems.update(p.system for p in snap.principals.values())
        snap.systems.update(r.system for r in snap.resources.values())
        if self.cmap.complete and not self.loss:
            snap.complete_resources = set(snap.resources) - self.incomplete


def read_csv(stream: BinaryIO, name: str, cmap: CsvMap) -> tuple[Snapshot, InputFile]:
    """Read a CSV from ``stream`` using ``cmap``; ``name`` is its display name.

    Raises :class:`InputError` when the file cannot be decoded, has no header, lacks a
    mapped column, or is larger than :data:`MAX_CSV_BYTES` or :data:`MAX_ROWS`. A bad row
    becomes a problem and is skipped.
    """
    raw = stream.read(MAX_CSV_BYTES + 1)
    if len(raw) > MAX_CSV_BYTES:
        msg = f"{name} is larger than the limit of {MAX_CSV_BYTES} bytes"
        raise InputError(msg)
    text = decode(raw, cmap.encoding, name)
    delimiter = sniff(text, cmap.delimiter, name)
    reader = _Reader(name, cmap)
    reader.snapshot.label = name
    reader.run(text, delimiter)
    reader.finish()
    info = InputFile(name, KIND, len(raw), hashlib.sha256(raw).hexdigest())
    reader.snapshot.inputs.append(info)
    return reader.snapshot, info
