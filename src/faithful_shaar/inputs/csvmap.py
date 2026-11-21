# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""The column map that tells shaar what the columns of a CSV mean.

A map is a TOML file (read with the standard library) and/or a built-in preset.
Both are plain data; a map can start from a preset with ``preset = "NAME"`` and
override any part of it. All keys:

```toml
preset = "generic"            # optional starting point
system = "hr-app"             # system name used in keys (letters, digits, . _ -)
resource = "Ledger Admins"    # one fixed resource for the whole file
resource_kind = "application" # default kind when there is no resource_kind column
encoding = "utf-8"            # default: by byte order mark, else strict UTF-8
delimiter = ","               # default: sniffed among , ; tab |  ("tab" is accepted)
owner_separator = ";"
via_separator = ">"
complete = true               # false: no resource in this file counts as complete
collected_at = "2026-11-01T00:00:00Z"   # when the CSV was exported, if known
optional = false              # true: a mapped column missing from the file is not an error;
                              # one this file lists under [columns] is a recorded problem
id_style = "csv"              # csv | sid | entra: how an id column becomes a key
domain = "corp.example"       # id_style sid: the domain well-known SIDs belong to
tenant = "00000000-0000-4000-8000-000000000000"  # id_style entra: the tenant id

[columns]                     # field = "header in the file"
principal_id = "SamAccountName"

[values]
enabled_true = ["true", "yes", "1", "enabled"]
enabled_false = ["false", "no", "0", "disabled"]

[principal_kinds]             # header value (case-insensitive) = shaar kind
inetorgperson = "user"

[extra]                       # columns kept as extra text on the record
principal = ["Department"]
```
"""

from __future__ import annotations

import codecs
import tomllib
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from faithful_shaar import keys, limits
from faithful_shaar.errors import InputError
from faithful_shaar.inputs.combine import parse_time
from faithful_shaar.model import PRINCIPAL_KINDS, RESOURCE_KINDS

if TYPE_CHECKING:
    from collections.abc import Mapping
    from pathlib import Path

MAX_MAP_BYTES = 1 << 20

FIELDS = (
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
ID_STYLES = ("csv", "sid", "entra")
DEFAULT_TRUE = ("true", "yes", "1", "enabled")
DEFAULT_FALSE = ("false", "no", "0", "disabled")

_TOP_KEYS = frozenset(
    {
        "preset",
        "system",
        "resource",
        "resource_kind",
        "encoding",
        "delimiter",
        "owner_separator",
        "via_separator",
        "complete",
        "collected_at",
        "optional",
        "id_style",
        "domain",
        "tenant",
        "columns",
        "values",
        "principal_kinds",
        "extra",
    }
)
_TABLES = ("columns", "values", "principal_kinds", "extra")

PRESETS: dict[str, dict[str, Any]] = {
    "generic": {
        "optional": True,
        "columns": {name: name for name in FIELDS},
    },
    "ad-users-groups": {
        "optional": True,
        "system": "ad-users-groups",
        "id_style": "sid",
        "resource_kind": "group",
        "columns": {
            "principal_id": "SID",
            "principal_name": "Name",
            "principal_kind": "objectClass",
            "resource_id": "GroupSID",
            "resource_name": "GroupName",
        },
        "extra": {"principal": ["SamAccountName"]},
        "principal_kinds": {
            "user": "user",
            "inetorgperson": "user",
            "group": "group",
            "computer": "device",
            "msds-groupmanagedserviceaccount": "service",
            "msds-managedserviceaccount": "service",
        },
    },
    "entra-members": {
        "optional": True,
        "system": "entra-members",
        "id_style": "entra",
        "resource_kind": "group",
        "columns": {
            "principal_id": "id",
            "principal_name": "displayName",
            "upn": "userPrincipalName",
            "enabled": "accountEnabled",
        },
        "extra": {"principal": ["userType"]},
        "principal_kinds": {},
    },
}


@dataclass(frozen=True)
class CsvMap:
    """A validated column map; see the module documentation for every setting."""

    columns: Mapping[str, str] = field(default_factory=dict)
    system: str = ""
    resource: str = ""
    resource_kind: str = ""
    id_style: str = "csv"
    domain: str = ""
    tenant: str = ""
    encoding: str = ""
    delimiter: str = ""
    owner_separator: str = ";"
    via_separator: str = ">"
    enabled_true: tuple[str, ...] = DEFAULT_TRUE
    enabled_false: tuple[str, ...] = DEFAULT_FALSE
    principal_kinds: Mapping[str, str] = field(default_factory=dict)
    extra_principal: tuple[str, ...] = ()
    extra_resource: tuple[str, ...] = ()
    extra_grant: tuple[str, ...] = ()
    complete: bool = True
    collected_at: str = ""
    optional: bool = False
    explicit: frozenset[str] = frozenset()
    """The fields the map file itself names under ``[columns]``, as opposed to the ones a
    preset supplies. A preset's column that a file lacks is ordinary; a column the person
    who wrote the map asked for, and the file lacks, is a problem."""


def _fail(message: str) -> InputError:
    return InputError(f"column map: {message}")


def _typed(data: Mapping[str, Any], key: str, kind: type, default: Any) -> Any:
    value = data.get(key, default)
    if not isinstance(value, kind):
        msg = f"{key!r} must be a {kind.__name__}"
        raise _fail(msg)
    return value


def _flag(data: Mapping[str, Any], key: str, *, default: bool) -> bool:
    value: bool = _typed(data, key, bool, default)
    return value


def _words(data: Mapping[str, Any], key: str, default: tuple[str, ...]) -> tuple[str, ...]:
    value = data.get(key)
    if value is None:
        return default
    if not isinstance(value, list) or not all(isinstance(v, str) and v.strip() for v in value):
        msg = f"{key!r} must be a list of non-empty text"
        raise _fail(msg)
    return tuple(keys.fold(v.strip()) for v in value)


def _columns(data: Mapping[str, Any]) -> dict[str, str]:
    table = _typed(data, "columns", dict, {})
    for name, header in table.items():
        if name not in FIELDS:
            msg = f"unknown column field {name!r}; known: {', '.join(FIELDS)}"
            raise _fail(msg)
        if not isinstance(header, str) or not header.strip():
            msg = f"column {name!r} must name a header"
            raise _fail(msg)
    return {name: header.strip() for name, header in table.items()}


def _kinds(data: Mapping[str, Any]) -> dict[str, str]:
    table = _typed(data, "principal_kinds", dict, {})
    for alias, kind in table.items():
        if kind not in PRINCIPAL_KINDS:
            msg = f"principal_kinds {alias!r} must map to one of {', '.join(PRINCIPAL_KINDS)}"
            raise _fail(msg)
    return {keys.fold(str(alias).strip()): kind for alias, kind in table.items()}


def _extras(data: Mapping[str, Any]) -> dict[str, tuple[str, ...]]:
    table = _typed(data, "extra", dict, {})
    unknown = set(table) - {"principal", "resource", "grant"}
    if unknown:
        msg = f"unknown [extra] entries: {', '.join(sorted(map(str, unknown)))}"
        raise _fail(msg)
    out = {}
    for name in ("principal", "resource", "grant"):
        value = table.get(name, [])
        if not isinstance(value, list) or not all(isinstance(v, str) and v.strip() for v in value):
            msg = f"[extra] {name} must be a list of header names"
            raise _fail(msg)
        out[name] = tuple(v.strip() for v in value)
    return out


def _delimiter(data: Mapping[str, Any]) -> str:
    value: str = _typed(data, "delimiter", str, "")
    if value.casefold() == "tab":
        return "\t"
    if len(value) > 1:
        msg = "'delimiter' must be one character (or the word tab)"
        raise _fail(msg)
    return value


def _encoding(data: Mapping[str, Any]) -> str:
    value: str = _typed(data, "encoding", str, "")
    try:
        if value:
            codecs.lookup(value)
            b"".decode(value)  # refuses codecs that are not text encodings (base64_codec)
    except LookupError as exc:
        msg = f"unknown encoding {value[:40]!r}"
        raise _fail(msg) from exc
    return value


def _system(data: Mapping[str, Any]) -> str:
    value: str = _typed(data, "system", str, "")
    try:
        return keys.system_name(value) if value.strip() else ""
    except ValueError as exc:
        raise _fail(str(exc)) from exc


def _scalars(data: Mapping[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {
        "system": _system(data),
        "resource": _typed(data, "resource", str, "").strip(),
        "encoding": _encoding(data),
        "delimiter": _delimiter(data),
        "complete": _flag(data, "complete", default=True),
        "optional": _flag(data, "optional", default=False),
    }
    for key in ("owner_separator", "via_separator"):
        out[key] = _typed(data, key, str, ";" if key.startswith("owner") else ">")
        if not out[key]:
            msg = f"{key!r} must not be empty"
            raise _fail(msg)
    return out


def _choices(data: Mapping[str, Any]) -> dict[str, Any]:
    style = _typed(data, "id_style", str, "csv")
    if style not in ID_STYLES:
        msg = f"'id_style' must be one of {', '.join(ID_STYLES)}"
        raise _fail(msg)
    kind = _typed(data, "resource_kind", str, "")
    if kind and kind not in RESOURCE_KINDS:
        msg = f"'resource_kind' must be one of {', '.join(RESOURCE_KINDS)}"
        raise _fail(msg)
    stamp = _typed(data, "collected_at", str, "").strip()
    if stamp and parse_time(stamp) is None:
        msg = "'collected_at' must be ISO 8601 with Z or an offset"
        raise _fail(msg)
    domain = _typed(data, "domain", str, "").strip()
    tenant = _typed(data, "tenant", str, "").strip()
    if tenant and keys.tenant(tenant) == keys.UNKNOWN:
        msg = "'tenant' must be the tenant id (a GUID), not a domain name"
        raise _fail(msg)
    return {
        "id_style": style,
        "resource_kind": kind,
        "collected_at": stamp,
        "domain": domain,
        "tenant": tenant,
    }


def build_map(data: Mapping[str, Any], explicit: frozenset[str] = frozenset()) -> CsvMap:
    """Validate map data (from TOML or a preset) and return the map.

    ``explicit`` names the column fields the map file itself lists (see :class:`CsvMap`).
    """
    unknown = set(data) - _TOP_KEYS
    if unknown:
        msg = f"unknown setting(s): {', '.join(sorted(map(str, unknown)))}"
        raise _fail(msg)
    values = _typed(data, "values", dict, {})
    stray = set(values) - {"enabled_true", "enabled_false"}
    if stray:
        msg = f"unknown [values] entries: {', '.join(sorted(map(str, stray)))}"
        raise _fail(msg)
    extras = _extras(data)
    return CsvMap(
        columns=_columns(data),
        enabled_true=_words(values, "enabled_true", DEFAULT_TRUE),
        enabled_false=_words(values, "enabled_false", DEFAULT_FALSE),
        principal_kinds=_kinds(data),
        extra_principal=extras["principal"],
        extra_resource=extras["resource"],
        extra_grant=extras["grant"],
        explicit=explicit,
        **_scalars(data),
        **_choices(data),
    )


def _read_toml(path: Path) -> dict[str, Any]:
    try:
        with path.open("rb") as handle:
            raw = handle.read(limits.get("column-map-bytes") + 1)
    except OSError as exc:
        msg = f"cannot read the column map {path}: {exc.strerror}"
        raise InputError(msg) from exc
    if len(raw) > limits.get("column-map-bytes"):
        msg = (
            f"the column map {path} is larger than {limits.get('column-map-bytes')} bytes; "
            f"{limits.hint('column-map-bytes')}"
        )
        raise InputError(msg)
    try:
        return tomllib.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        msg = f"the column map {path} is not valid TOML: {exc}"
        raise InputError(msg) from exc


def _preset(name: str) -> dict[str, Any]:
    if name not in PRESETS:
        msg = f"unknown preset {name[:40]!r}; choose one of {', '.join(sorted(PRESETS))}"
        raise InputError(msg)
    base = PRESETS[name]
    return {k: (dict(v) if isinstance(v, dict) else v) for k, v in base.items()}


def load_map(path: Path | None, preset: str | None, resource: str | None) -> CsvMap | None:
    """Return the map made from ``path`` and/or ``preset``, or ``None`` when neither is given.

    The file's settings override the preset's; its tables are merged key by key. An
    explicit ``preset`` argument wins over a ``preset`` key in the file. ``resource``
    (the command's ``--resource``) fixes one resource for the whole file.
    """
    if path is None and preset is None:
        return None
    file_data = _read_toml(path) if path is not None else {}
    name = preset if preset is not None else file_data.get("preset")
    data: dict[str, Any] = {}
    if name is not None:
        if not isinstance(name, str):
            msg = "column map: 'preset' must be text"
            raise InputError(msg)
        data = _preset(name)
    for key, value in file_data.items():
        if key == "preset":
            continue
        if key in _TABLES and isinstance(value, dict) and isinstance(data.get(key), dict):
            data[key].update(value)
        else:
            data[key] = value
    if resource:
        data["resource"] = resource
    listed = file_data.get("columns")
    explicit = frozenset(str(k) for k in listed) if isinstance(listed, dict) else frozenset()
    return build_map(data, explicit)
