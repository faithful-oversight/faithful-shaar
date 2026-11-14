# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""Rules shared by every reader for combining records that describe the same thing."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from faithful_shaar.model import Grant, Principal, Resource

PRINCIPAL_FIELDS = (
    "system",
    "id",
    "name",
    "kind",
    "enabled",
    "email",
    "upn",
    "manager_key",
    "last_sign_in",
)
RESOURCE_FIELDS = ("system", "id", "name", "kind", "owner_keys")

PATH_JOIN = " > "
PATH_LIST_JOIN = "; "
DIRECT = "direct"


def parse_time(text: str) -> datetime | None:
    """Return the time in ``text`` (ISO 8601 with an offset or ``Z``), or ``None``."""
    try:
        moment = datetime.fromisoformat(text.strip())
    except ValueError:
        return None
    return moment if moment.tzinfo is not None else None


def differing_principal_fields(first: Principal, other: Principal) -> list[str]:
    """Return the names of the fields in which two principals with one key differ."""
    return [f for f in PRINCIPAL_FIELDS if getattr(first, f) != getattr(other, f)]


def differing_resource_fields(first: Resource, other: Resource) -> list[str]:
    """Return the names of the fields in which two resources with one key differ."""
    return [f for f in RESOURCE_FIELDS if getattr(first, f) != getattr(other, f)]


def path_text(via: tuple[str, ...]) -> str:
    """Return one access path as text: the chain joined with ``>``, or ``direct``."""
    return PATH_JOIN.join(via) if via else DIRECT


def paths_of(grant: Grant) -> list[str]:
    """Return every path a grant is known by (its own when it has not been merged)."""
    joined = grant.extra.get("paths")
    if joined is None:
        return [path_text(grant.via)]
    return joined.split(PATH_LIST_JOIN)


def add_grant(grants: dict[str, Grant], grant: Grant) -> None:
    """Add ``grant``; when its key is known, merge the paths into the existing grant.

    The merged grant keeps the first grant's source and fields. ``via`` becomes the
    shortest path (the first one on a tie). ``extra["paths"]`` is set when more than one
    distinct path is known and lists them all, joined with ``"; "`` (each path is its
    names joined with ``" > "``, or ``direct``).
    """
    existing = grants.get(grant.key)
    if existing is None:
        grants[grant.key] = grant
        return
    paths = paths_of(existing)
    paths.extend(p for p in paths_of(grant) if p not in paths)
    via = grant.via if len(grant.via) < len(existing.via) else existing.via
    extra = dict(existing.extra)
    if len(paths) > 1:
        extra["paths"] = PATH_LIST_JOIN.join(paths)
    grants[grant.key] = replace(existing, via=via, extra=extra)
