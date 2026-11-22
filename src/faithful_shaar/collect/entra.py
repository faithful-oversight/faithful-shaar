# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""Read who holds access in Microsoft Entra ID, with GET requests only.

``shaar collect entra`` signs in with azure-identity (a certificate, a client
secret, or a device code), reads group membership, owners, managers, directory
role assignments and eligible (PIM) role assignments from Microsoft Graph v1.0,
and writes one shaar export (JSON Lines) for ``shaar campaign``.

Application permissions needed, all read-only, with admin consent:

- ``GroupMember.Read.All``: groups, members and owners.
- ``User.Read.All``: users' details and managers.
- ``RoleManagement.Read.Directory``: ``--roles`` and ``--pim``.

Whatever cannot be read becomes a ``gap`` record, and a group whose membership
was cut short is written with ``"complete": false``.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import importlib
import json
import os
import re
from collections import deque
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from faithful_core.clock import date_and_time
from faithful_core.collect import secrets
from faithful_core.console import say
from faithful_core.files import refuse_aliases

from faithful_shaar import __version__
from faithful_shaar.collect.fileout import write_private
from faithful_shaar.collect.graph import (
    CLOUDS,
    Cloud,
    Credential,
    GraphClient,
    GraphGap,
    Pages,
    odata_string,
)
from faithful_shaar.collect.remote import install_hint, secret_file
from faithful_shaar.errors import CollectionError, ShaarError, UsageError

if TYPE_CHECKING:
    from collections.abc import Iterable

COLLECTOR_NAME = "shaar collect entra"
EXPORT_VERSION = 1
MAX_NESTED_GROUPS = 1000
MAX_MANAGER_LOOKUPS = 20000
MAX_MANAGER_FAILURES = 20

PERM_GROUPS = "GroupMember.Read.All"
PERM_USERS = "User.Read.All"
PERM_ROLES = "RoleManagement.Read.Directory"

_GUID = re.compile(r"[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}")
_DOMAIN = re.compile(r"(?=.{1,253}$)([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}")
_USER_FIELDS = "id,displayName,userPrincipalName,mail,accountEnabled,userType"
_KINDS = {
    "user": "user",
    "servicePrincipal": "service",
    "group": "group",
    "device": "device",
    "orgContact": "other",
}
_INSTALL = install_hint("entra")


# --- sign-in ------------------------------------------------------------------------


@dataclass(frozen=True)
class SignIn:
    """How to sign in. Secrets are already resolved; none of this is ever written."""

    tenant: str
    client_id: str
    cloud: Cloud
    certificate: Path | None = None
    certificate_password: str | None = None
    client_secret: str | None = None
    device_code: bool = False


def _identity() -> Any:
    try:
        return importlib.import_module("azure.identity")
    except ImportError as exc:
        msg = f"reading Entra ID needs azure-identity; install it with: {_INSTALL}"
        raise CollectionError(msg) from exc


def _device_prompt(verification_uri: str, user_code: str, expires_on: datetime) -> None:
    say(
        f"To sign in, open {verification_uri} and enter the code {user_code}. "
        f"The code expires at {date_and_time(expires_on, ' ')} UTC.",
        error=True,
    )


def build_credential(sign_in: SignIn) -> Credential:
    """Create the azure-identity credential for ``sign_in``.

    Raises:
        CollectionError: azure-identity is not installed.
    """
    identity = _identity()
    authority = getattr(identity.AzureAuthorityHosts, sign_in.cloud.authority)
    common: dict[str, Any] = {"authority": authority}
    if sign_in.certificate is not None:
        return identity.CertificateCredential(  # type: ignore[no-any-return]
            sign_in.tenant,
            sign_in.client_id,
            certificate_path=str(sign_in.certificate),
            password=sign_in.certificate_password,
            **common,
        )
    if sign_in.client_secret is not None:
        return identity.ClientSecretCredential(  # type: ignore[no-any-return]
            sign_in.tenant, sign_in.client_id, sign_in.client_secret, **common
        )
    return identity.DeviceCodeCredential(  # type: ignore[no-any-return]
        client_id=sign_in.client_id,
        tenant_id=sign_in.tenant,
        prompt_callback=_device_prompt,
        **common,
    )


# --- what was read ------------------------------------------------------------------


@dataclass(frozen=True)
class Scope:
    """What the operator asked to read."""

    groups: tuple[str, ...] = ()
    all_security_groups: bool = False
    roles: bool = False
    pim: bool = False

    def empty(self) -> bool:
        """True when nothing was asked for."""
        return not (self.groups or self.all_security_groups or self.roles or self.pim)


@dataclass
class Export:
    """Everything collected, before it is written."""

    tenant: str
    cloud: Cloud
    scope: Scope
    collected_at: str
    principals: dict[str, dict[str, Any]] = field(default_factory=dict)
    resources: dict[str, dict[str, Any]] = field(default_factory=dict)
    grants: dict[tuple[str, str, str], dict[str, Any]] = field(default_factory=dict)
    gaps: set[tuple[str, str]] = field(default_factory=set)


def _text(obj: dict[str, Any], key: str) -> str:
    value = obj.get(key)
    return value if isinstance(value, str) else ""


def _scope(item: dict[str, Any]) -> str:
    """Return a role assignment's ``directoryScopeId``, or "" if it is not usable.

    A blank scope, or one with spaces around it, names no scope Graph uses. Read as text it
    would become the entitlement ``scope`` and stand for a scope it is not, so it is unusable.
    """
    value = _text(item, "directoryScopeId")
    return value if value and value == value.strip() else ""


def _lost(pages: Pages) -> int:
    """How many records of a listing could not be used: not objects, or without an id."""
    return pages.dropped + sum(1 for item in pages.items if not _text(item, "id"))


def _lost_reason(pages: Pages) -> str:
    return f"{_lost(pages)} records without an id (or that were not objects) were skipped"


def _moment(text: str) -> datetime | None:
    """An ISO 8601 time with a zone (``Z`` allowed) in UTC; None when it cannot be read."""
    try:
        when = datetime.fromisoformat(text)
    except ValueError:
        return None
    return when.astimezone(UTC) if when.tzinfo is not None else None


def _kind(obj: dict[str, Any]) -> str:
    return _KINDS.get(_text(obj, "@odata.type").rpartition(".")[2], "unknown")


def _principal(obj: dict[str, Any]) -> dict[str, Any] | None:
    ident = _text(obj, "id")
    if not ident:
        return None
    enabled = obj.get("accountEnabled")
    extra = {"user_type": "Guest"} if _text(obj, "userType").casefold() == "guest" else {}
    return {
        "id": ident,
        "name": _text(obj, "displayName"),
        "kind": _kind(obj),
        "enabled": enabled if isinstance(enabled, bool) else None,
        "email": _text(obj, "mail"),
        "upn": _text(obj, "userPrincipalName"),
        "manager_id": "",
        "last_sign_in": "",
        "extra": extra,
    }


@dataclass
class _RoleReview:
    """What one role listing could not account for."""

    seen: set[str] = field(default_factory=set)
    incomplete: set[str] = field(default_factory=set)
    everything: bool = False  # a record could not be tied to a role: no role is complete


# A schedule in one of these states is not access now. Revoked, canceled, denied and
# failed schedules never took effect or have ended.
_NOT_CURRENT = frozenset({"revoked", "canceled", "denied", "failed"})


def _window(info: dict[str, Any]) -> tuple[datetime | None, datetime | None] | None:
    """The start and end of a schedule's window (None: open); None when unreadable."""
    start = info.get("startDateTime")
    began = _moment(start) if isinstance(start, str) else None
    expiration = info.get("expiration")
    if (start is not None and began is None) or not isinstance(expiration, dict):
        return None
    end_text, kind = expiration.get("endDateTime"), expiration.get("type")
    ends = _moment(end_text) if isinstance(end_text, str) else None
    if kind == "noExpiration":
        readable = end_text is None
    else:
        readable = kind in {"afterDateTime", "afterDuration"} and ends is not None
    if not readable or (ends is not None and began is not None and ends <= began):
        return None
    return began, ends


def _eligibility(item: dict[str, Any], now: datetime) -> bool | None:
    """Is this PIM eligibility schedule in force at ``now``?

    True: provisioned, started, not ended. False: known not to be access now (a final
    status, or a window that ended or has not begun). None: cannot be told.
    """
    status = _text(item, "status").casefold()
    if status in _NOT_CURRENT:
        return False
    info = item.get("scheduleInfo")
    window = _window(info) if status == "provisioned" and isinstance(info, dict) else None
    if window is None:
        return None
    began, ends = window
    return (began is None or began <= now) and (ends is None or ends > now)


class _Collector:
    def __init__(self, client: GraphClient, export: Export) -> None:
        self.client = client
        self.out = export
        self._direct_cache: dict[str, Pages] = {}
        self._group_names: dict[str, str] = {}

    # records

    def gap(self, what: str, reason: str) -> None:
        self.out.gaps.add((what, reason))

    def add_principal(self, obj: dict[str, Any]) -> str:
        """Record a principal, filling blanks from later sightings; return its id."""
        new = _principal(obj)
        if new is None:
            return ""
        old = self.out.principals.get(new["id"])
        if old is None:
            self.out.principals[new["id"]] = new
            return str(new["id"])
        for key in ("name", "email", "upn"):
            old[key] = old[key] or new[key]
        if old["kind"] == "unknown":
            old["kind"] = new["kind"]
        if old["enabled"] is None:
            old["enabled"] = new["enabled"]
        old["extra"] = {**new["extra"], **old["extra"]}
        return str(new["id"])

    def add_grant(
        self,
        resource_id: str,
        principal_id: str,
        entitlement: str,
        via: Iterable[str] = (),
        extra: dict[str, str] | None = None,
    ) -> None:
        key = (resource_id, principal_id, entitlement.casefold())
        self.out.grants[key] = {
            "principal_id": principal_id,
            "resource_id": resource_id,
            "entitlement": entitlement,
            "via": list(via),
            "extra": extra or {},
        }

    # groups

    def groups(self, scope: Scope) -> None:
        found: dict[str, dict[str, Any]] = {}
        for reference in scope.groups:
            group = self._find_group(reference)
            if group is not None:
                found[group["id"]] = group
        if scope.all_security_groups:
            listing = self._security_groups()
            for group in listing:
                found.setdefault(group["id"], group)
        for ident in sorted(found, key=str.casefold):
            self._group(found[ident])

    def _security_groups(self) -> list[dict[str, Any]]:
        listing = self.client.pages(
            "/groups",
            {"$filter": "securityEnabled eq true", "$select": "id,displayName,securityEnabled"},
            needs=PERM_GROUPS,
        )
        if listing.error:
            self.gap("security groups", f"the list could not be read completely: {listing.error}")
        if _lost(listing):
            self.gap("security groups", _lost_reason(listing))
        return [g for g in listing.items if _text(g, "id")]

    def _find_group(self, reference: str) -> dict[str, Any] | None:
        what = f"group {reference}"
        select = {"$select": "id,displayName,securityEnabled"}
        if _GUID.fullmatch(reference):
            try:
                group = self.client.get(f"/groups/{reference}", select, needs=PERM_GROUPS)
            except GraphGap as gap:
                self.gap(what, gap.reason)
                return None
            if not _text(group, "id"):
                self.gap(what, "the response holds no group id")
                return None
            return group
        listing = self.client.pages(
            "/groups",
            {"$filter": f"displayName eq {odata_string(reference)}", **select},
            needs=PERM_GROUPS,
        )
        matches = [g for g in listing.items if _text(g, "id")]
        if listing.error:
            self.gap(what, f"the name could not be looked up: {listing.error}")
        elif not matches:
            self.gap(what, "no group has this display name")
        elif len(matches) > 1:
            ids = ", ".join(sorted(_text(g, "id") for g in matches))
            self.gap(what, f"{len(matches)} groups have this display name ({ids}); use an id")
        else:
            return matches[0]
        return None

    def _group(self, group: dict[str, Any]) -> None:
        ident = _text(group, "id")
        name = _text(group, "displayName") or ident
        self._group_names[ident] = name
        label = f"group {name} ({ident})"
        secure = group.get("securityEnabled")
        extra = {"security_enabled": str(secure).lower()} if isinstance(secure, bool) else {}
        complete = True

        owners = self.client.pages(
            f"/groups/{ident}/owners", {"$select": _USER_FIELDS}, needs=PERM_GROUPS
        )
        if owners.error:
            self.gap(f"owners of {label}", owners.error)
        if _lost(owners):
            complete = False
            self.gap(f"owners of {label}", _lost_reason(owners))
        owner_ids = sorted({self.add_principal(o) for o in owners.items} - {""})

        transitive = self.client.pages(
            f"/groups/{ident}/transitiveMembers", {"$select": _USER_FIELDS}, needs=PERM_GROUPS
        )
        if transitive.error:
            complete = False
            self.gap(f"members of {label}", transitive.error)
        if _lost(transitive):
            complete = False
            self.gap(f"members of {label}", _lost_reason(transitive))
        direct = self._direct(ident, label)
        if direct.error or _lost(direct):
            complete = False
        direct_ids = {_text(m, "id") for m in direct.items}
        paths = self._nested_paths(ident, name, direct)

        everyone = {_text(m, "id"): m for m in [*direct.items, *transitive.items] if _text(m, "id")}
        for member_id in sorted(everyone, key=str.casefold):
            self.add_principal(everyone[member_id])
            self._member_grant(ident, name, member_id, direct_ids, paths)
        self.out.resources[ident] = {
            "id": ident,
            "name": name,
            "kind": "group",
            "owner_ids": owner_ids,
            "complete": complete,
            "extra": extra,
        }

    def _member_grant(
        self,
        group_id: str,
        group_name: str,
        member_id: str,
        direct_ids: set[str],
        paths: dict[str, tuple[str, ...]],
    ) -> None:
        if member_id in direct_ids:
            self.add_grant(group_id, member_id, "member")
        elif member_id in paths:
            self.add_grant(group_id, member_id, "member", paths[member_id])
        else:
            self.add_grant(
                group_id,
                member_id,
                "member",
                (group_name,),
                {"path_unknown": "the nested group that holds this member could not be read"},
            )

    def _direct(self, ident: str, label: str = "") -> Pages:
        """Direct members of a group, read once however many times it is needed."""
        if ident not in self._direct_cache:
            name = label or f"group {self._group_names.get(ident, ident)} ({ident})"
            listing = self.client.pages(
                f"/groups/{ident}/members", {"$select": _USER_FIELDS}, needs=PERM_GROUPS
            )
            if listing.error:
                self.gap(f"direct members of {name}", listing.error)
            if _lost(listing):
                self.gap(f"direct members of {name}", _lost_reason(listing))
            self._direct_cache[ident] = listing
        return self._direct_cache[ident]

    def _nested_paths(
        self, root_id: str, root_name: str, direct: Pages
    ) -> dict[str, tuple[str, ...]]:
        """Shortest chain of group names to every member below the direct nested groups."""
        paths: dict[str, tuple[str, ...]] = {}
        visited = {root_id}
        queue: deque[tuple[str, tuple[str, ...]]] = deque()

        def enqueue(members: list[dict[str, Any]], chain: tuple[str, ...]) -> None:
            for member in members:
                ident = _text(member, "id")
                if not ident:
                    continue
                if chain:
                    paths.setdefault(ident, chain)
                if _kind(member) == "group" and ident not in visited:
                    visited.add(ident)
                    name = _text(member, "displayName") or ident
                    self._group_names.setdefault(ident, name)
                    queue.append((ident, (*(chain or (root_name,)), name)))

        enqueue(direct.items, ())
        expanded = 0
        while queue:
            if expanded == MAX_NESTED_GROUPS:
                self.gap(
                    f"nested groups of group {root_name} ({root_id})",
                    f"stopped after expanding {MAX_NESTED_GROUPS} nested groups",
                )
                break
            ident, chain = queue.popleft()
            expanded += 1
            enqueue(self._direct(ident).items, chain)
        return paths

    # roles

    def roles(self, scope: Scope, now: datetime) -> None:
        """Read active and eligible directory role assignments.

        Active and eligible (PIM) assignments of a role are separate resources, ``<role
        id>`` and ``<role id>:eligible``, each complete only when its own listing was read
        in full. A later export that read one listing and not the other therefore can never
        make an assignment of the other kind look removed.

        A grant is one role, one principal and one scope. Neither its resource id nor its
        entitlement holds the role's name, which can change or fail to be read; the name
        is only in the resource record.
        """
        names, definitions = self._role_definitions()
        listings: list[tuple[str, str, Pages]] = []
        if scope.roles:
            listings.append(("", "active", self._assignments("roleAssignments")))
        if scope.pim:
            listings.append(
                (":eligible", "eligible", self._assignments("roleEligibilitySchedules"))
            )
        group_holders: dict[str, str] = {}
        for suffix, label, pages in listings:
            if pages.error:
                self.gap(f"{label} directory role assignments", pages.error)
            review = _RoleReview()
            if pages.dropped:
                review.everything = True
                self.gap(
                    f"{label} role assignments",
                    f"{pages.dropped} list entries that were not objects were skipped",
                )
            self._role_items(pages.items, suffix, now, review, group_holders)
            for role_id in set(definitions) | review.seen:
                name = names.get(role_id, role_id)
                lost = pages.error or review.everything or role_id in review.incomplete
                self.out.resources[role_id + suffix] = {
                    "id": role_id + suffix,
                    "name": f"{name} (eligible)" if suffix else name,
                    "kind": "role",
                    "owner_ids": [],
                    "complete": not lost,
                    "extra": {"assignment": label, "role_id": role_id},
                }
        for ident, name in group_holders.items():
            self.gap(
                f"members of group {name} ({ident}) who hold a role through it",
                "a role is assigned to this group; its members are not expanded here, "
                "so collect the group with --group",
            )

    def _role_definitions(self) -> tuple[dict[str, str], set[str]]:
        listing = self.client.pages(
            "/roleManagement/directory/roleDefinitions",
            {"$select": "id,displayName"},
            needs=PERM_ROLES,
            top=False,
        )
        if listing.error:
            self.gap(
                "role names",
                f"roles are shown by their id where the name was not read: {listing.error}",
            )
        names = {_text(d, "id"): _text(d, "displayName") or _text(d, "id") for d in listing.items}
        names.pop("", None)
        return names, set(names)

    def _assignments(self, collection: str) -> Pages:
        return self.client.pages(
            f"/roleManagement/directory/{collection}",
            {"$expand": "principal"},
            needs=PERM_ROLES,
            top=False,
        )

    def _role_items(
        self,
        items: list[dict[str, Any]],
        suffix: str,
        now: datetime,
        review: _RoleReview,
        group_holders: dict[str, str],
    ) -> None:
        """Record each assignment as grants, one per scope; note what could not be used."""
        eligible = bool(suffix)
        lost = {"unusable": 0, "unscoped": 0, "unevaluated": 0}
        for item in items:
            principal_id, role_id = _text(item, "principalId"), _text(item, "roleDefinitionId")
            if not role_id:
                lost["unusable"] += 1
                review.everything = True  # which role it was for is unknown
                continue
            review.seen.add(role_id)
            problem = self._role_problem(item, principal_id, now if eligible else None)
            if problem == "current":
                self._role_grant(item, principal_id, role_id + suffix, group_holders)
            elif problem:
                lost[problem] += 1
                review.incomplete.add(role_id)
        what = "eligible role assignments" if eligible else "active role assignments"
        reasons = {
            "unusable": "assignments without a principal or role id were skipped",
            "unscoped": "assignments without a directory scope were skipped",
            "unevaluated": "eligibility schedules whose status or validity window could "
            "not be evaluated were not treated as eligible",
        }
        for key, count in lost.items():
            if count:
                self.gap(what, f"{count} {reasons[key]}")

    @staticmethod
    def _role_problem(item: dict[str, Any], principal_id: str, now: datetime | None) -> str:
        """``current`` for a usable assignment in force, ``""`` if known not to be, else why not.

        ``now`` is given for eligibility schedules only, which have a lifecycle.
        """
        if not principal_id:
            return "unusable"
        if now is not None:
            state = _eligibility(item, now)
            if state is None:
                return "unevaluated"
            if not state:
                return ""
        return "current" if _scope(item) else "unscoped"

    def _role_grant(
        self,
        item: dict[str, Any],
        principal_id: str,
        resource_id: str,
        group_holders: dict[str, str],
    ) -> None:
        holder = item.get("principal")
        obj = dict(holder) if isinstance(holder, dict) else {}
        obj["id"] = principal_id
        self.add_principal(obj)
        if self.out.principals[principal_id]["kind"] == "group":
            group_holders[principal_id] = self.out.principals[principal_id]["name"] or principal_id
        scope_id = _scope(item)
        self.add_grant(
            resource_id, principal_id, "whole directory" if scope_id == "/" else f"scope {scope_id}"
        )

    # managers

    def managers(self) -> None:
        users = sorted(
            (p for p in self.out.principals.values() if p["kind"] == "user"),
            key=lambda p: str(p["id"]).casefold(),
        )
        failures = 0
        for position, user in enumerate(users):
            if position == MAX_MANAGER_LOOKUPS or failures == MAX_MANAGER_FAILURES:
                self.gap(
                    "managers",
                    f"managers of the last {len(users) - position} users were not read "
                    "(too many lookups or failures)",
                )
                return
            try:
                payload = self.client.get(
                    f"/users/{user['id']}",
                    {"$select": "id", "$expand": f"manager($select={_USER_FIELDS})"},
                    needs=PERM_USERS,
                )
            except GraphGap as gap:
                failures += 1
                self.gap(f"manager of user {user['name'] or user['id']} ({user['id']})", gap.reason)
                continue
            manager = payload.get("manager")
            if isinstance(manager, dict):
                user["manager_id"] = self.add_principal(manager)


# --- the export ---------------------------------------------------------------------


def collect(client: GraphClient, tenant: str, scope: Scope, collected_at: str) -> Export:
    """Read everything ``scope`` asks for. Only a rejected token stops this early.

    ``tenant`` is what the operator asked for: a GUID or a domain name. The export
    records the canonical tenant id from the access token's ``tid`` claim, which says
    which tenant actually answered.

    Raises:
        CollectionError: The token names no tenant, or another one than the GUID asked
            for, or ``collected_at`` is not a time.
    """
    now = _moment(collected_at)
    if now is None:
        msg = f"{collected_at!r} is not a time with a zone"
        raise CollectionError(msg)
    actual = client.tenant_id()
    if _GUID.fullmatch(tenant) and tenant.lower() != actual:
        msg = f"the access token is for tenant {actual}, not the requested tenant {tenant.lower()}"
        raise CollectionError(msg)
    export = Export(actual, client.cloud, scope, collected_at)
    collector = _Collector(client, export)
    collector.groups(scope)
    if scope.roles or scope.pim:
        collector.roles(scope, now)
    collector.managers()
    return export


def _line(record: dict[str, Any]) -> bytes:
    return json.dumps(record, ensure_ascii=False, separators=(",", ":")).encode("utf-8") + b"\n"


def render(export: Export) -> bytes:
    """The shaar export: JSON Lines, UTF-8, LF, in an order that depends only on the data.

    ``records`` in the trailer counts the principal, resource, grant and gap
    lines. ``sha256`` covers every byte before the trailer line.
    """
    scope = export.scope
    lines = [
        _line(
            {
                "shaar_export": EXPORT_VERSION,
                "system": "entra",
                "collector": {"name": COLLECTOR_NAME, "version": __version__},
                "collected_at": export.collected_at,
                "scope": {
                    "cloud": export.cloud.name,
                    "graph_host": export.cloud.graph_host,
                    "groups": sorted(scope.groups),
                    "all_security_groups": scope.all_security_groups,
                    "roles": scope.roles,
                    "pim": scope.pim,
                },
                "tenant": export.tenant,
                "cloud": export.cloud.name,
            }
        )
    ]
    records: list[dict[str, Any]] = []
    records += [
        {"principal": export.principals[k]}
        for k in sorted(export.principals, key=lambda k: (k.casefold(), k))
    ]
    records += [
        {"resource": export.resources[k]}
        for k in sorted(
            export.resources, key=lambda k: (export.resources[k]["kind"], k.casefold(), k)
        )
    ]
    records += [{"grant": export.grants[k]} for k in sorted(export.grants, key=_grant_order)]
    records += [{"gap": {"what": what, "reason": reason}} for what, reason in sorted(export.gaps)]
    lines += [_line(r) for r in records]
    body = b"".join(lines)
    trailer = {"end": True, "records": len(records), "sha256": hashlib.sha256(body).hexdigest()}
    return body + _line(trailer)


def _grant_order(key: tuple[str, str, str]) -> tuple[str, str, str, tuple[str, str, str]]:
    return (key[0].casefold(), key[1].casefold(), key[2], key)


def collected_at(now: datetime | None = None) -> str:
    """UTC time as ``YYYY-MM-DDTHH:MM:SSZ``; ``SOURCE_DATE_EPOCH`` fixes it when set."""
    moment = (now or datetime.now(UTC)).astimezone(UTC)
    epoch = os.environ.get("SOURCE_DATE_EPOCH", "")
    if epoch.isascii() and epoch.isdigit():
        # An impossible time is ignored, as for any other unreadable value.
        with contextlib.suppress(OverflowError, OSError, ValueError):
            moment = datetime.fromtimestamp(int(epoch), UTC)
    return date_and_time(moment) + "Z"


# --- command line -------------------------------------------------------------------


def _tenant(text: str) -> str:
    if _GUID.fullmatch(text) or _DOMAIN.fullmatch(text):
        return text.lower()
    msg = f"{text!r} is not a tenant id (GUID) or a verified domain name"
    raise argparse.ArgumentTypeError(msg)


def _guid(text: str) -> str:
    if _GUID.fullmatch(text):
        return text.lower()
    msg = f"{text!r} is not a GUID"
    raise argparse.ArgumentTypeError(msg)


def add_collect_entra_arguments(collect_subparsers: Any) -> None:
    """Register ``entra`` under ``shaar collect``."""
    entra = collect_subparsers.add_parser(
        "entra",
        help="read group members, owners, managers and roles from Entra ID",
        description=(
            "Read who holds access in Microsoft Entra ID through Microsoft Graph (GET "
            "requests only) and write a shaar export. The application needs these "
            f"read-only application permissions with admin consent: {PERM_GROUPS}, "
            f"{PERM_USERS}, and {PERM_ROLES} for --roles and --pim. To verify a later "
            "removal of a directory role, collect with the same --roles and --pim "
            "choices both times."
        ),
    )
    entra.add_argument("--tenant", required=True, type=_tenant, help="tenant id or domain")
    entra.add_argument("--client-id", required=True, type=_guid, help="application (client) id")
    auth = entra.add_mutually_exclusive_group(required=True)
    auth.add_argument("--certificate", type=Path, metavar="PATH", help="PEM or PFX file")
    auth.add_argument("--client-secret", metavar="REF", help="secret reference, e.g. env:NAME")
    auth.add_argument(
        "--device-code", action="store_true", help="sign in as yourself with a device code"
    )
    entra.add_argument(
        "--certificate-password", metavar="REF", help="secret reference for the certificate"
    )
    entra.add_argument("--cloud", choices=sorted(CLOUDS), default="global")
    entra.add_argument(
        "--group", nargs="+", action="extend", default=[], metavar="ID|NAME",
        help="read these groups (an object id, or a display name that matches one group)",
    )  # fmt: skip
    entra.add_argument(
        "--all-security-groups", action="store_true", help="read every security-enabled group"
    )
    entra.add_argument("--roles", action="store_true", help="read directory role assignments")
    entra.add_argument("--pim", action="store_true", help="read eligible role assignments")
    entra.add_argument("-o", "--output", required=True, type=Path, metavar="FILE")
    entra.add_argument("--force", action="store_true", help="replace an existing file")
    entra.set_defaults(run=run_collect_entra)


def _sign_in(args: argparse.Namespace) -> SignIn:
    if args.certificate_password and not args.certificate:
        msg = "--certificate-password needs --certificate"
        raise UsageError(msg)
    certificate: Path | None = args.certificate
    if certificate is not None and not certificate.is_file():
        msg = f"the certificate file {certificate} cannot be read"
        raise CollectionError(msg)
    password = secret = None
    if args.certificate_password:
        password = secrets.resolve(args.certificate_password, hint=install_hint, keep=("entra",))
        secrets.remember(password)
    if args.client_secret:
        secret = secrets.resolve(args.client_secret, hint=install_hint, keep=("entra",))
        secrets.remember(secret)
    return SignIn(
        tenant=args.tenant,
        client_id=args.client_id,
        cloud=CLOUDS[args.cloud],
        certificate=certificate,
        certificate_password=password,
        client_secret=secret,
        device_code=bool(args.device_code),
    )


def _read_files(args: argparse.Namespace) -> list[tuple[str, Path]]:
    """The files ``collect entra`` reads, by role: the certificate and any ``file:`` secret."""
    found: list[tuple[str, Path]] = []
    if args.certificate:
        found.append(("certificate", args.certificate))
    for role, reference in (
        ("client secret file", args.client_secret),
        ("certificate password file", args.certificate_password),
    ):
        if (path := secret_file(reference)) is not None:
            found.append((role, path))
    return found


def _terminal(text: str) -> str:
    """Escape control characters, so a group name cannot rewrite the terminal."""
    return "".join(c if c.isprintable() else c.encode("unicode_escape").decode() for c in text)


def run_collect_entra(args: argparse.Namespace) -> int:
    """Run ``shaar collect entra``. Returns 0, 2 for bad options, or 3 when collection fails."""
    try:
        _run(args)
    except UsageError as exc:
        say(f"shaar: error: {_terminal(secrets.redact(str(exc)))}", error=True)
        return 2
    except ShaarError as exc:
        say(f"shaar: error: {_terminal(secrets.redact(str(exc)))}", error=True)
        return 3
    return 0


def _run(args: argparse.Namespace) -> None:
    scope = Scope(
        groups=tuple(args.group),
        all_security_groups=args.all_security_groups,
        roles=args.roles,
        pim=args.pim,
    )
    if scope.empty():
        msg = "choose what to read: --group, --all-security-groups, --roles, or --pim"
        raise UsageError(msg)
    output: Path = args.output
    # The files this command reads are never the file it writes, even with --force. This
    # runs before any secret is read or any connection is made.
    refuse_aliases([output], _read_files(args))
    if (output.exists() or output.is_symlink()) and not args.force:
        msg = f"{output} already exists; use --force to replace it"
        raise CollectionError(msg)
    _identity()  # a missing extra is reported before any secret is read
    sign_in = _sign_in(args)
    client = GraphClient(sign_in.cloud, build_credential(sign_in))
    export = collect(client, args.tenant, scope, collected_at())
    write_private(output, render(export), force=args.force)
    say(
        f"Read {len(export.principals)} principals, {len(export.resources)} resources and "
        f"{len(export.grants)} grants from tenant {export.tenant} into {_terminal(str(output))}."
    )
    for what, reason in sorted(export.gaps):
        say(f"  not read: {_terminal(what)}: {_terminal(reason)}")
