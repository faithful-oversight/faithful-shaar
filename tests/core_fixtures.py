# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""Synthetic snapshots and returned packets for the core tests (corp.example)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from faithful_shaar import keys
from faithful_shaar.campaign import DISPLAY, Campaign, build
from faithful_shaar.model import Grant, InputFile, Principal, Resource, Snapshot, Source

if TYPE_CHECKING:
    from collections.abc import Callable

CREATED = "2026-11-01T00:00:00Z"
DOMAIN_SID = "S-1-5-21-1000-1000-1000"


def sid(rid: int) -> str:
    """Return the key of a synthetic corp.example SID."""
    return keys.sid(f"{DOMAIN_SID}-{rid}")


def person(
    rid: int, name: str, *, manager: int | None = None, enabled: bool | None = True
) -> Principal:
    """Return a user of corp.example."""
    login = name.lower().replace(" ", ".")
    return Principal(
        key=sid(rid),
        system="ad",
        id=f"{DOMAIN_SID}-{rid}",
        name=name,
        kind="user",
        enabled=enabled,
        email=f"{login}@corp.example",
        upn=f"{login}@corp.example",
        manager_key=sid(manager) if manager else "",
        last_sign_in="2026-10-30T08:00:00Z",
        source=Source("ad.jsonl", f"line {rid}"),
    )


def group(rid: int, name: str, *owners: int) -> Resource:
    """Return a group of corp.example owned by ``owners``."""
    return Resource(
        key=sid(rid),
        system="ad",
        id=f"{DOMAIN_SID}-{rid}",
        name=name,
        kind="group",
        owner_keys=tuple(sid(o) for o in owners),
        source=Source("ad.jsonl", f"line {rid}"),
    )


def grant(member: int, to: int, *, via: tuple[str, ...] = ()) -> Grant:
    """Return membership of principal ``member`` in group ``to``."""
    return Grant(
        key=keys.grant(sid(to), sid(member), "member"),
        system="ad",
        principal_key=sid(member),
        resource_key=sid(to),
        entitlement="member",
        via=via,
        source=Source("ad.jsonl", f"line {member}{to}"),
    )


def snapshot(
    principals: list[Principal], resources: list[Resource], grants: list[Grant], **kw: object
) -> Snapshot:
    """Return a snapshot whose resources are all complete unless ``incomplete`` names some."""
    incomplete = set(kw.pop("incomplete", ()))  # type: ignore[call-overload]
    return Snapshot(
        label=str(kw.pop("label", "before")),
        collected_at=str(kw.pop("collected_at", "2026-10-31T12:00:00Z")),
        systems={"ad"},
        principals={p.key: p for p in principals},
        resources={r.key: r for r in resources},
        grants={g.key: g for g in grants},
        complete_resources={r.key for r in resources} - {sid(i) for i in incomplete},
        inputs=[InputFile("ad.jsonl", "shaar export", 100, "0" * 64)],
    )


def people() -> list[Principal]:
    """Return the standard cast: a manager, two reports, an owner, and a service account."""
    return [
        person(1101, "Morgan Lead"),
        person(1102, "Avery Example", manager=1101),
        person(1103, "Blake Sample", manager=1101, enabled=False),
        person(1104, "Casey Owner"),
        Principal(sid(1105), "ad", f"{DOMAIN_SID}-1105", "svc-backup", "service"),
    ]


def resources() -> list[Resource]:
    """Return the standard groups: Casey owns Finance, Morgan owns Server Ops, both Payroll."""
    return [
        group(2001, "Finance Admins", 1104),
        group(2002, "Server Ops", 1101),
        group(2003, "Payroll Viewers", 1104, 1101),
    ]


def grants(*, morgan: bool = True) -> list[Grant]:
    """Return the standard grants; ``morgan`` adds Morgan's own Server Ops membership."""
    found = [
        grant(1102, 2001),
        grant(1103, 2001),
        grant(1102, 2002, via=("Server Ops", "Ops Helpers")),
        grant(1105, 2002),
        grant(1103, 2003),
    ]
    return [*found, grant(1101, 2002)] if morgan else found


def standard(rule: str = "manager", **kw: object) -> tuple[Snapshot, Campaign]:
    """Return a snapshot and its campaign: three groups, six grants."""
    morgan = bool(kw.pop("morgan", True))
    snap = snapshot(people(), resources(), grants(morgan=morgan), **kw)
    return snap, build(snap, name="Q4 review", created_at=CREATED, due="2026-11-15", rule=rule)


@dataclass
class FakeRow:
    """A returned row as the workbook reader gives it."""

    row: int
    values: dict[str, str]
    notes: list[str] = field(default_factory=list)


@dataclass
class FakePacket:
    """A returned workbook as the reader gives it."""

    about: dict[str, str]
    rows: list[FakeRow]
    core: dict[str, str] = field(default_factory=dict)


def returned(
    campaign: Campaign, reviewer: int | str, decisions: dict[str, str] | None = None
) -> FakePacket:
    """Return a reviewer's packet filled in.

    ``decisions`` maps ``"User|Resource"``, or just ``"User"`` for all of a user's rows, to
    the text typed in the Decision cell.
    """
    key = reviewer if isinstance(reviewer, str) else sid(reviewer)
    entry = next(r for r in campaign.reviewers if r.key == key)
    rows = []
    for number, row in enumerate(campaign.rows_for(key), start=2):
        values = {header: row.display[name] for name, header in DISPLAY}
        values |= {"Row ID": row.row_id, "Row check": row.row_check}
        chosen = decisions or {}
        user, resource = row.display["user"], row.display["resource"]
        typed = chosen.get(f"{user}|{resource}", chosen.get(user, ""))
        values |= {"Decision": typed, "Comment": ""}
        rows.append(FakeRow(number, values))
    about = {
        "Campaign ID": campaign.id,
        "Packet digest": entry.packet_digest,
        "Reviewer": entry.name,
    }
    return FakePacket(
        about, rows, {"modified": "2026-11-10T09:00:00Z", "lastModifiedBy": "Morgan Lead"}
    )


def reader(packets: dict[str, FakePacket]) -> Callable[[bytes, str], FakePacket]:
    """Return a workbook reader that hands back fake packets by file name."""
    from faithful_shaar.errors import InputError  # noqa: PLC0415

    def read(_data: bytes, name: str) -> FakePacket:
        if name not in packets:
            msg = f"{name} is not a workbook"
            raise InputError(msg)
        return packets[name]

    return read
