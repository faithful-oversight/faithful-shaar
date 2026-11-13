# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""Choosing who reviews each grant.

Three rules, chosen per campaign:

- ``manager``: the principal's manager, as the input records it.
- ``owner``: an owner of the resource. When a resource has several owners, the first by
  name reviews and the others are named as co-owners in the packet, so every grant has
  exactly one reviewer. An owner never reviews their own access: the next owner does.
- ``map``: a CSV that names a reviewer for a resource or for a principal.

A grant no rule can place is *unassigned*, with the reason. Unassigned grants are always
reported; they are never dropped.

One person often appears in several systems (Active Directory, Entra ID, an application),
each with its own key. A reviewer with an email address is therefore identified by that
address, so one person gets one packet, and nobody reviews their own access in another
system either.
"""

from __future__ import annotations

import csv
import io
from dataclasses import dataclass
from typing import TYPE_CHECKING

from faithful_shaar.errors import InputError

if TYPE_CHECKING:
    from pathlib import Path

    from faithful_shaar.model import Grant, Principal, Resource, Snapshot

RULES = ("manager", "owner", "map")
MAX_MAP_BYTES = 16 * 1024 * 1024


@dataclass(frozen=True)
class Reviewer:
    """Who reviews a grant.

    ``key`` is ``mail:<address>`` for a reviewer with an email address, the principal key
    for one without, or ``map:<id>`` for a mapped reviewer.
    """

    key: str
    name: str
    email: str = ""


@dataclass(frozen=True)
class Assignment:
    """The result for one grant: a reviewer and the co-owners, or the reason there is none."""

    reviewer: Reviewer | None
    reason: str = ""
    co_owners: tuple[str, ...] = ()


@dataclass(frozen=True)
class MapEntry:
    """One line of a reviewer map: what it matches, and who reviews it."""

    resource: str
    principal: str
    reviewer: Reviewer
    line: int


def _reviewer(principal: Principal) -> Reviewer:
    email = principal.email.strip()
    key = f"mail:{email.casefold()}" if email else principal.key
    return Reviewer(key, principal.name or principal.id, email)


def _same_person(one: Principal, other: Principal | None) -> bool:
    """Whether two principals are one person: the same key, or the same email address."""
    if other is None:
        return False
    if one.key == other.key:
        return True
    return (
        bool(one.email.strip()) and one.email.strip().casefold() == other.email.strip().casefold()
    )


def _names(principal: Principal) -> set[str]:
    """Every text that may name a principal in a reviewer map, case-folded."""
    found = {principal.key, principal.id, principal.name, principal.upn, principal.email}
    return {value.strip().casefold() for value in found if value.strip()}


def _resource_names(resource: Resource) -> set[str]:
    found = {resource.key, resource.id, resource.name}
    return {value.strip().casefold() for value in found if value.strip()}


def by_manager(grant: Grant, snapshot: Snapshot) -> Assignment:
    """Assign a grant to the principal's manager."""
    principal = snapshot.principals.get(grant.principal_key)
    if principal is None or not principal.manager_key:
        return Assignment(None, "the input names no manager for this principal")
    manager = snapshot.principals.get(principal.manager_key)
    if manager is None:
        return Assignment(None, "the manager is not in the input, so they cannot be named")
    if _same_person(manager, principal):
        return Assignment(None, "the input names the principal as their own manager")
    return Assignment(_reviewer(manager))


def by_owner(grant: Grant, snapshot: Snapshot) -> Assignment:
    """Assign a grant to the first owner of its resource who is not the principal."""
    resource = snapshot.resources.get(grant.resource_key)
    if resource is None or not resource.owner_keys:
        return Assignment(None, "the input names no owner for this resource")
    owners = sorted(
        (
            snapshot.principals[key]
            for key in set(resource.owner_keys)
            if key in snapshot.principals
        ),
        key=lambda p: ((p.name or p.id).casefold(), p.key),
    )
    if not owners:
        return Assignment(
            None, "the resource's owners are not in the input, so they cannot be named"
        )
    holder = snapshot.principals.get(grant.principal_key)
    others = [
        owner
        for owner in owners
        if owner.key != grant.principal_key and not _same_person(owner, holder)
    ]
    if not others:
        return Assignment(
            None, "the only owner is the principal, who cannot review their own access"
        )
    chosen = others[0]
    co_owners = tuple(owner.name or owner.id for owner in owners if owner.key != chosen.key)
    return Assignment(_reviewer(chosen), co_owners=co_owners)


def read_map(path: Path) -> list[MapEntry]:
    """Read a reviewer map: ``resource`` or ``principal``, then the reviewer's id, name, email.

    Raises:
        InputError: The file cannot be read, is not UTF-8 CSV, or lacks a needed column.
    """
    try:
        data = path.read_bytes()
    except OSError as exc:
        msg = f"cannot read the reviewer map {path.name}: {exc.strerror}"
        raise InputError(msg) from None
    if len(data) > MAX_MAP_BYTES:
        msg = f"the reviewer map {path.name} is larger than {MAX_MAP_BYTES} bytes"
        raise InputError(msg)
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError:
        msg = f"the reviewer map {path.name} is not UTF-8 text"
        raise InputError(msg) from None
    reader = csv.DictReader(io.StringIO(text, newline=""))
    fields = {name.strip().casefold() for name in reader.fieldnames or []}
    missing = {"reviewer_id", "reviewer_name"} - fields
    if missing or not fields & {"resource", "principal"}:
        msg = (
            f"the reviewer map {path.name} needs the columns reviewer_id, reviewer_name, "
            "and resource or principal (reviewer_email is optional)"
        )
        raise InputError(msg)
    entries = []
    for line, row in enumerate(reader, start=2):
        values = {(k or "").strip().casefold(): (v or "").strip() for k, v in row.items() if k}
        reviewer_id = values.get("reviewer_id", "")
        if not reviewer_id or not (values.get("resource") or values.get("principal")):
            msg = (
                f"the reviewer map {path.name}, row {line}: needs reviewer_id and a "
                "resource or principal"
            )
            raise InputError(msg)
        reviewer = Reviewer(
            f"map:{reviewer_id.casefold()}",
            values.get("reviewer_name") or reviewer_id,
            values.get("reviewer_email", ""),
        )
        entries.append(
            MapEntry(
                values.get("resource", "").casefold(),
                values.get("principal", "").casefold(),
                reviewer,
                line,
            )
        )
    return entries


def by_map(grant: Grant, snapshot: Snapshot, entries: list[MapEntry]) -> Assignment:
    """Assign a grant by the reviewer map: a resource match first, then a principal match."""
    resource = snapshot.resources.get(grant.resource_key)
    principal = snapshot.principals.get(grant.principal_key)
    resource_names = _resource_names(resource) if resource else {grant.resource_key}
    principal_names = _names(principal) if principal else {grant.principal_key}
    for wanted, names in (("resource", resource_names), ("principal", principal_names)):
        matches = [e for e in entries if getattr(e, wanted) and getattr(e, wanted) in names]
        reviewers = {e.reviewer for e in matches}
        if len(reviewers) > 1:
            lines = ", ".join(str(e.line) for e in matches)
            return Assignment(
                None, f"the reviewer map names different reviewers for this {wanted} (rows {lines})"
            )
        if reviewers:
            reviewer = reviewers.pop()
            mine = {reviewer.key.removeprefix("map:"), reviewer.email.strip().casefold()} - {""}
            if mine & principal_names:
                return Assignment(
                    None, "the mapped reviewer is the principal, who cannot review their own access"
                )
            return Assignment(reviewer)
    return Assignment(None, "the reviewer map names no reviewer for this resource or principal")


def assign(
    grant: Grant, snapshot: Snapshot, rule: str, entries: list[MapEntry] | None = None
) -> Assignment:
    """Assign one grant by ``rule`` (one of :data:`RULES`)."""
    if rule == "manager":
        return by_manager(grant, snapshot)
    if rule == "owner":
        return by_owner(grant, snapshot)
    if rule == "map":
        return by_map(grant, snapshot, entries or [])
    msg = f"unknown reviewer rule {rule!r}; use one of {', '.join(RULES)}"
    raise ValueError(msg)
