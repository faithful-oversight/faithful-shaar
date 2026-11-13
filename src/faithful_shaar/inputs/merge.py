# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""Merge the snapshots of several inputs into one."""

from __future__ import annotations

from datetime import UTC, datetime

from faithful_shaar.inputs.combine import (
    add_grant,
    differing_principal_fields,
    differing_resource_fields,
    parse_time,
)
from faithful_shaar.model import Problem, Snapshot

_FLOOR = datetime.min.replace(tzinfo=UTC)


def earliest(snapshots: list[Snapshot]) -> str:
    """Return the earliest ``collected_at`` of the inputs, or ``""`` when one is unknown.

    The earliest, not the latest: a later verification may only claim evidence as recent
    as the oldest input it rests on. An export without a valid time makes the answer
    unknown (``""``). A CSV without a time (the map gave none) makes no claim and is
    left out.
    """
    stamps = []
    for snapshot in snapshots:
        if snapshot.collected_at:
            stamps.append(snapshot.collected_at)
        elif snapshot.inputs[0].kind != "csv":
            return ""
    return min(stamps, key=lambda s: parse_time(s) or _FLOOR, default="")


def merge(label: str, snapshots: list[Snapshot]) -> Snapshot:
    """Combine snapshots, in order, into one named ``label``.

    - Equal principals and resources are kept once. When two with one key differ in any
      recorded field, the first is kept and a problem names the fields and both sources.
    - Grants with one key merge their paths (see ``add_grant``).
    - A resource is complete only if every input that mentions it says so: one input
      that read it only in part, or not trustworthily, withdraws the claim.
    - ``collected_at`` is :func:`earliest`.
    """
    out = Snapshot(label=label)
    for snap in snapshots:
        out.inputs.extend(snap.inputs)
        out.systems |= snap.systems
        out.context.update(snap.context)
        out.problems.extend(snap.problems)
        for key, principal in snap.principals.items():
            first = out.principals.setdefault(key, principal)
            fields = differing_principal_fields(first, principal)
            if fields:
                reason = f"principal {principal.id!r} conflicts with the record at {first.source}"
                out.problems.append(
                    Problem(principal.source, f"{reason} in: {', '.join(fields)}; kept the first")
                )
        for key, resource in snap.resources.items():
            first_resource = out.resources.setdefault(key, resource)
            fields = differing_resource_fields(first_resource, resource)
            if fields:
                reason = (
                    f"resource {resource.id!r} conflicts with the record at {first_resource.source}"
                )
                out.problems.append(
                    Problem(resource.source, f"{reason} in: {', '.join(fields)}; kept the first")
                )
        for grant in snap.grants.values():
            add_grant(out.grants, grant)
    out.complete_resources = {
        key
        for key in out.resources
        if all(key in s.complete_resources for s in snapshots if key in s.resources)
    }
    out.collected_at = earliest(snapshots)
    return out
