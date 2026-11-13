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
import sys
from collections import deque
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from faithful_shaar import __version__
from faithful_shaar.clock import date_and_time
from faithful_shaar.collect import secrets
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
_INSTALL = "pip install 'faithful-shaar[entra]'"


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
    sys.stderr.write(
        f"To sign in, open {verification_uri} and enter the code {user_code}. "
        f"The code expires at {date_and_time(expires_on, ' ')} UTC.\n"
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
        owner_ids = sorted({self.add_principal(o) for o in owners.items} - {""})

        transitive = self.client.pages(
            f"/groups/{ident}/transitiveMembers", {"$select": _USER_FIELDS}, needs=PERM_GROUPS
        )
        if transitive.error:
            complete = False
            self.gap(f"members of {label}", transitive.error)
        direct = self._direct(ident, label)
        if direct.error:
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

    def roles(self, scope: Scope) -> None:
        """Read active and eligible directory role assignments.

        Active and eligible (PIM) assignments of a role are separate resources, ``<role
        id>`` and ``<role id>:eligible``, each complete only when its own listing was read
        in full. A later export that read one listing and not the other therefore can never
        make an assignment of the other kind look removed.
        """
        names, definitions = self._role_definitions()
        listings: list[tuple[str, str, Pages]] = []
        if scope.roles:
            listings.append(("", "active", self._assignments("roleAssignments")))
        if scope.pim:
            listings.append(
                (":eligible", "eligible", self._assignments("roleEligibilitySchedules"))
            )
        scopes: dict[tuple[str, str, str], set[str]] = {}
        group_holders: dict[str, str] = {}
        for suffix, label, pages in listings:
            if pages.error:
                self.gap(f"{label} directory role assignments", pages.error)
            seen = self._role_items(pages.items, names, suffix, scopes, group_holders)
            role_ids = set(definitions) | seen
            for role_id in role_ids:
                name = names.get(role_id, role_id)
                self.out.resources[role_id + suffix] = {
                    "id": role_id + suffix,
                    "name": f"{name} (eligible)" if suffix else name,
                    "kind": "role",
                    "owner_ids": [],
                    "complete": not pages.error,
                    "extra": {"assignment": label, "role_id": role_id},
                }
        for (resource_id, principal_id, entitlement), where in scopes.items():
            extra = {"directory_scope": "; ".join(sorted(where))} if where else {}
            self.add_grant(resource_id, principal_id, entitlement, (), extra)
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
        names: dict[str, str],
        suffix: str,
        scopes: dict[tuple[str, str, str], set[str]],
        group_holders: dict[str, str],
    ) -> set[str]:
        """Record each assignment; return the ids of the roles they name."""
        skipped = 0
        seen: set[str] = set()
        for item in items:
            principal_id, role_id = _text(item, "principalId"), _text(item, "roleDefinitionId")
            if not principal_id or not role_id:
                skipped += 1
                continue
            holder = item.get("principal")
            obj = dict(holder) if isinstance(holder, dict) else {}
            obj["id"] = principal_id
            self.add_principal(obj)
            if self.out.principals[principal_id]["kind"] == "group":
                group_holders[principal_id] = (
                    self.out.principals[principal_id]["name"] or principal_id
                )
            seen.add(role_id)
            entitlement = names.get(role_id, role_id) + (" (eligible)" if suffix else "")
            where = scopes.setdefault((role_id + suffix, principal_id, entitlement), set())
            if _text(item, "directoryScopeId"):
                where.add(_text(item, "directoryScopeId"))
        if skipped:
            self.gap(
                "role assignments",
                f"{skipped} assignments without a principal or role id were skipped",
            )
        return seen

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
    """Read everything ``scope`` asks for. Only a rejected token stops this early."""
    export = Export(tenant, client.cloud, scope, collected_at)
    collector = _Collector(client, export)
    collector.groups(scope)
    if scope.roles or scope.pim:
        collector.roles(scope)
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
    entra.add_argument("--all-security-groups", action="store_true", help="read every group")
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
        password = secrets.resolve(args.certificate_password)
        secrets.remember(password)
    if args.client_secret:
        secret = secrets.resolve(args.client_secret)
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


def _terminal(text: str) -> str:
    """Escape control characters, so a group name cannot rewrite the terminal."""
    return "".join(c if c.isprintable() else c.encode("unicode_escape").decode() for c in text)


def run_collect_entra(args: argparse.Namespace) -> int:
    """Run ``shaar collect entra``. Returns 0, 2 for bad options, or 3 when collection fails."""
    try:
        _run(args)
    except UsageError as exc:
        sys.stderr.write(f"shaar: error: {_terminal(secrets.redact(str(exc)))}\n")
        return 2
    except ShaarError as exc:
        sys.stderr.write(f"shaar: error: {_terminal(secrets.redact(str(exc)))}\n")
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
    if (output.exists() or output.is_symlink()) and not args.force:
        msg = f"{output} already exists; use --force to replace it"
        raise CollectionError(msg)
    _identity()  # a missing extra is reported before any secret is read
    sign_in = _sign_in(args)
    client = GraphClient(sign_in.cloud, build_credential(sign_in))
    export = collect(client, args.tenant, scope, collected_at())
    write_private(output, render(export), force=args.force)
    sys.stdout.write(
        f"Read {len(export.principals)} principals, {len(export.resources)} resources and "
        f"{len(export.grants)} grants from tenant {args.tenant} into {_terminal(str(output))}.\n"
    )
    for what, reason in sorted(export.gaps):
        sys.stdout.write(f"  not read: {_terminal(what)}: {_terminal(reason)}\n")
