# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""The records shaar works with, whatever system they came from.

An access review is about *grants*: a principal (a user, a group, a service account)
holds an entitlement on a resource (a group, a role, an application). Every record keeps
a :class:`Source` so that a report can say exactly where each fact came from, and every
input keeps the :class:`Problem` list of what could not be read, so that a report never
claims more than its inputs show.
"""

from __future__ import annotations

from dataclasses import dataclass, field

PRINCIPAL_KINDS = ("user", "group", "service", "device", "other", "unknown")
RESOURCE_KINDS = ("group", "role", "application", "other")


@dataclass(frozen=True)
class Source:
    """Where a fact came from: an input's display name and a detail such as ``row 12``."""

    file: str
    detail: str = ""

    def __str__(self) -> str:
        """Return ``file`` or ``file, detail``."""
        return f"{self.file}, {self.detail}" if self.detail else self.file


@dataclass(frozen=True)
class Problem:
    """Something in an input that could not be read or trusted, and why."""

    source: Source
    reason: str


@dataclass(frozen=True)
class Principal:
    """Someone or something that holds access.

    ``key`` identifies the principal across exports (see :mod:`faithful_shaar.keys`).
    ``enabled`` is ``None`` when the input does not say. ``manager_key`` is ``""`` when
    the input names no manager. ``last_sign_in`` is the text the source gave, or ``""``.
    """

    key: str
    system: str
    id: str
    name: str
    kind: str = "unknown"
    enabled: bool | None = None
    email: str = ""
    upn: str = ""
    manager_key: str = ""
    last_sign_in: str = ""
    source: Source = field(default_factory=lambda: Source(""))
    extra: dict[str, str] = field(default_factory=dict, compare=False, hash=False)


@dataclass(frozen=True)
class Resource:
    """Something access is granted on: a group, a role, an application."""

    key: str
    system: str
    id: str
    name: str
    kind: str = "group"
    owner_keys: tuple[str, ...] = ()
    source: Source = field(default_factory=lambda: Source(""))
    extra: dict[str, str] = field(default_factory=dict, compare=False, hash=False)


@dataclass(frozen=True)
class Grant:
    """One principal's entitlement on one resource.

    ``via`` is ``()`` for direct access. For access through nested groups it is the chain
    of group names from the resource down to the principal's own group. When an input
    shows several paths to the same access, they are one grant: ``via`` is the shortest
    path and ``extra["paths"]`` lists every path.
    """

    key: str
    system: str
    principal_key: str
    resource_key: str
    entitlement: str
    via: tuple[str, ...] = ()
    source: Source = field(default_factory=lambda: Source(""))
    extra: dict[str, str] = field(default_factory=dict, compare=False, hash=False)


@dataclass(frozen=True)
class InputFile:
    """An input as the manifest records it: display name, kind, size and SHA-256."""

    name: str
    kind: str
    size: int
    sha256: str


@dataclass
class Snapshot:
    """Everything read from one or more inputs of one review.

    ``complete_resources`` holds the keys of resources whose whole membership was read.
    Only for those can the absence of a grant be taken as evidence that it does not exist.
    ``systems`` names each system read the way :func:`faithful_shaar.keys.system_of` does:
    ``ad``, ``entra`` or ``csv:<system>``. ``resource_times`` says when each resource was
    read: the earliest time of the inputs that hold it, or ``""`` when any of them does
    not say. Evidence about a resource is only as recent as the inputs that read it.
    ``entitlement_blind`` names the systems (as for ``systems``) of resources read from a CSV
    whose map has an entitlement column that the file does not have: every grant there reads
    as ``member``, so the absence of any other entitlement shows nothing.
    """

    label: str
    collected_at: str = ""
    systems: set[str] = field(default_factory=set)
    principals: dict[str, Principal] = field(default_factory=dict)
    resources: dict[str, Resource] = field(default_factory=dict)
    grants: dict[str, Grant] = field(default_factory=dict)
    complete_resources: set[str] = field(default_factory=set)
    resource_times: dict[str, str] = field(default_factory=dict)
    problems: list[Problem] = field(default_factory=list)
    inputs: list[InputFile] = field(default_factory=list)
    context: dict[str, str] = field(default_factory=dict)
    entitlement_blind: set[str] = field(default_factory=set)
