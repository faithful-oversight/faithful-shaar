# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
r"""Stable keys that identify principals, resources and grants across exports.

A key is ``system:kind:value``. The system and kind are lower case; the value is
normalized for its kind so that two exports of the same thing give the same key:

- ``ad:sid:S-1-5-21-...``: a domain's security identifier, upper case (SIDs ignore case).
  A domain SID is unique everywhere. A well-known SID such as ``S-1-5-32-544``
  (BUILTIN\Administrators) is the same in every domain, so its key names the domain:
  ``ad:sid:S-1-5-32-544@corp.example``.
- ``ad:dn:cn=...``: a distinguished name, case-folded. Used only when no SID is known.
- ``entra:<tenant>:id:<object id>`` and ``entra:<tenant>:role:<role definition id>``: an
  Entra ID object or directory role, in its tenant. Built-in role ids are the same in
  every tenant, so a key without its tenant would let one tenant's evidence stand for
  another's.
- ``csv:<system>:<id>``: an identifier from a CSV, case-folded and trimmed.

When the domain or tenant is not known, the key says ``?`` in its place
(:data:`UNKNOWN`), and :func:`unscoped` reports it: such a resource is never treated as
read in full, because its evidence cannot be tied to one directory.

Matching across exports uses keys only, never display names, unless a CSV offers nothing
else (then the CSV reader records that the match is by name).
"""

from __future__ import annotations

import re
import unicodedata

_SID = re.compile(r"S-1-\d+(-\d+)+", re.IGNORECASE)
_DOMAIN_SID = re.compile(r"S-1-5-21-\d+-\d+-\d+(-\d+)?", re.IGNORECASE)
_GUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
UNKNOWN = "?"
_SYSTEM = re.compile(r"[a-z0-9][a-z0-9._-]{0,39}")


def fold(text: str) -> str:
    """Return text the way identity matching compares it.

    Text that looks the same can be written in different ways: ``é`` as one character or
    as ``e`` plus a combining accent (macOS and some directory exports use the second),
    full-width letters, ligatures. Matching normalizes with NFKC, folds case, and
    normalizes again (case folding can leave text unnormalized). Only the comparison text
    changes: names and ids are shown and written exactly as the input gave them.

    Characters that merely resemble each other, such as Cyrillic a (U+0430) and Latin a, are
    different letters and stay different.
    """
    if text.isascii():
        return text.casefold()
    return unicodedata.normalize("NFKC", unicodedata.normalize("NFKC", text).casefold())


def sid(value: str, domain: str = "") -> str:
    """Return the key of a Windows SID, or raise :class:`ValueError` when it is not one.

    ``domain`` names the domain the SID was read in. It is part of the key only for a SID
    that is not a domain SID, such as ``S-1-5-32-544``, which every domain has.
    """
    text = value.strip()
    if not _SID.fullmatch(text):
        msg = f"{value[:80]!r} is not a SID"
        raise ValueError(msg)
    if _DOMAIN_SID.fullmatch(text):
        return f"ad:sid:{text.upper()}"
    return f"ad:sid:{text.upper()}@{fold(domain.strip()) or UNKNOWN}"


def dn(value: str) -> str:
    """Return the key of an Active Directory distinguished name."""
    return f"ad:dn:{fold(value.strip())}"


def tenant(value: str) -> str:
    """Return a tenant as keys use it: its id in lower case, or :data:`UNKNOWN`.

    Only a tenant id (a GUID) identifies a tenant; a domain name can move between tenants.
    """
    text = value.strip().lower()
    return text if _GUID.fullmatch(text) else UNKNOWN


def entra(tenant_id: str, value: str) -> str:
    """Return the key of an Entra ID object id in a tenant."""
    return f"entra:{tenant(tenant_id)}:id:{value.strip().lower()}"


def entra_role(tenant_id: str, value: str) -> str:
    """Return the key of an Entra ID directory role definition in a tenant."""
    return f"entra:{tenant(tenant_id)}:role:{value.strip().lower()}"


def unscoped(key: str) -> bool:
    """Say whether a key could not be tied to its domain or tenant."""
    return key.endswith(f"@{UNKNOWN}") or key.startswith(f"entra:{UNKNOWN}:")


def system_name(value: str) -> str:
    """Return a CSV system name as keys use it, or raise :class:`ValueError`.

    A system name is 1 to 40 characters: lower-case letters, digits, ``.``, ``_`` and
    ``-``, starting with a letter or digit. ``ad`` and ``entra`` are reserved for the
    collectors' exports.
    """
    text = fold(value.strip())
    if not _SYSTEM.fullmatch(text):
        msg = f"{value[:80]!r} is not a system name (letters, digits, '.', '_' or '-')"
        raise ValueError(msg)
    if text in {"ad", "entra"}:
        msg = f"{text!r} is reserved for shaar's own exports; name the CSV's system"
        raise ValueError(msg)
    return text


def csv(system: str, value: str) -> str:
    """Return the key of an identifier from a CSV of ``system`` (see :func:`system_name`)."""
    return f"csv:{system_name(system)}:{fold(value.strip())}"


def _part(text: str) -> str:
    return text.replace("%", "%25").replace("|", "%7C")


def grant(resource_key: str, principal_key: str, entitlement: str) -> str:
    """Return a grant's key: its resource, its principal and its entitlement.

    Each part has ``%`` and ``|`` escaped, so two different grants never share a key,
    whatever their identifiers hold.
    """
    parts = (resource_key, principal_key, fold(entitlement.strip()))
    return "|".join(_part(p) for p in parts)


def entitlement_of(grant_key: str) -> str:
    """Return the entitlement part of a grant key, as :func:`grant` wrote it."""
    return grant_key.rsplit("|", 1)[-1]


def system_of(key: str) -> str:
    """Return the system part of a key (``ad``, ``entra`` or ``csv:<system>``)."""
    head, _, rest = key.partition(":")
    if head == "csv":
        return f"csv:{rest.partition(':')[0]}"
    return head
