# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""Stable keys that identify principals, resources and grants across exports.

A key is ``system:kind:value``. The system and kind are lower case; the value is
normalized for its kind so that two exports of the same thing give the same key:

- ``ad:sid:S-1-5-21-...``: a Windows security identifier, upper case (SIDs ignore case).
- ``ad:dn:cn=...``: a distinguished name, case-folded. Used only when no SID is known.
- ``entra:id:<object id>``: an Entra ID object id, lower case.
- ``entra:role:<role definition id>``: an Entra ID directory role, lower case.
- ``csv:<system>:<id>``: an identifier from a CSV, case-folded and trimmed.

Matching across exports uses keys only, never display names, unless a CSV offers nothing
else (then the CSV reader records that the match is by name).
"""

from __future__ import annotations

import re

_SID = re.compile(r"S-1-\d+(-\d+)+", re.IGNORECASE)
_SYSTEM = re.compile(r"[a-z0-9][a-z0-9._-]{0,39}")


def sid(value: str) -> str:
    """Return the key of a Windows SID, or raise :class:`ValueError` when it is not one."""
    text = value.strip()
    if not _SID.fullmatch(text):
        msg = f"{value[:80]!r} is not a SID"
        raise ValueError(msg)
    return f"ad:sid:{text.upper()}"


def dn(value: str) -> str:
    """Return the key of an Active Directory distinguished name."""
    return f"ad:dn:{value.strip().casefold()}"


def entra(value: str) -> str:
    """Return the key of an Entra ID object id."""
    return f"entra:id:{value.strip().lower()}"


def entra_role(value: str) -> str:
    """Return the key of an Entra ID directory role definition."""
    return f"entra:role:{value.strip().lower()}"


def system_name(value: str) -> str:
    """Return a CSV system name as keys use it, or raise :class:`ValueError`.

    A system name is 1 to 40 characters: lower-case letters, digits, ``.``, ``_`` and
    ``-``, starting with a letter or digit. ``ad`` and ``entra`` are reserved for the
    collectors' exports.
    """
    text = value.strip().casefold()
    if not _SYSTEM.fullmatch(text):
        msg = f"{value[:80]!r} is not a system name (letters, digits, '.', '_' or '-')"
        raise ValueError(msg)
    if text in {"ad", "entra"}:
        msg = f"{text!r} is reserved for shaar's own exports; name the CSV's system"
        raise ValueError(msg)
    return text


def csv(system: str, value: str) -> str:
    """Return the key of an identifier from a CSV of ``system`` (see :func:`system_name`)."""
    return f"csv:{system_name(system)}:{value.strip().casefold()}"


def grant(resource_key: str, principal_key: str, entitlement: str) -> str:
    """Return a grant's key: its resource, its principal and its entitlement."""
    return f"{resource_key}|{principal_key}|{entitlement.strip().casefold()}"


def system_of(key: str) -> str:
    """Return the system part of a key (``ad``, ``entra`` or ``csv:<system>``)."""
    head, _, rest = key.partition(":")
    if head == "csv":
        return f"csv:{rest.partition(':')[0]}"
    return head
