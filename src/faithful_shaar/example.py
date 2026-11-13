# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""A synthetic access review to try shaar with, from the first export to verification.

Every name, address and identifier is made up (``corp.example``). :func:`build` returns
the files; ``shaar example DIR`` writes them:

- ``before/``: what access looked like when the review began: an Active Directory export,
  an Entra ID export, and a CSV from a fictional finance application, "Ledger", with its
  column map.
- ``campaign/``: the campaign shaar built from them (reviewers chosen by manager).
- ``returned/``: the packets as the reviewers sent them back, decisions filled in. One
  reviewer marked an entry Unsure; another left one blank.
- ``after/``: access read again after the due date. Most removals were made; one was not,
  one resource could not be read in full, kept access was taken away anyway, and the
  contractor was given new access that the review never saw.
"""

from __future__ import annotations

import hashlib
import json
import tempfile
from pathlib import Path
from typing import Any

from faithful_shaar import campaign as cmod
from faithful_shaar.formats.xlsx import Packet, PacketRow, write_packet
from faithful_shaar.inputs import read_inputs
from faithful_shaar.outputs.files import write_files
from faithful_shaar.outputs.render import render_all
from faithful_shaar.outputs.safety import command_line
from faithful_shaar.reports import campaign_document, packets

CREATED = "2026-11-02T09:00:00Z"
BEFORE_AT = "2026-11-01T22:00:00Z"
AFTER_AT = "2026-11-20T22:00:00Z"
DUE = "2026-11-16"
NAME = "Q4 2026 access review"
TENANT = "00000000-0000-4000-8000-000000000000"
DOMAIN_SID = "S-1-5-21-1000-1000-1000"

# Who is who: (rid, entra suffix, name, login, manager rid or None, enabled, kind)
PEOPLE: tuple[tuple[int, int, str, str, int | None, bool, str], ...] = (
    (1100, 1, "Jordan Director", "jordan.director", None, True, "user"),
    (1101, 2, "Morgan Lead", "morgan.lead", 1100, True, "user"),
    (1102, 3, "Avery Example", "avery.example", 1101, True, "user"),
    (1103, 4, "Blake Sample", "blake.sample", 1101, False, "user"),
    (1104, 5, "Casey Owner", "casey.owner", 1100, True, "user"),
    (1105, 6, "Drew Analyst", "drew.analyst", 1101, True, "user"),
    (1106, 7, "Emery Contractor", "emery.contractor", 1104, True, "user"),
    (1107, 0, "svc-backup", "svc-backup", None, True, "service"),
)


def _sid(rid: int) -> str:
    return f"{DOMAIN_SID}-{rid}"


def _oid(n: int) -> str:
    return f"00000000-0000-4000-8000-{n:012d}"


def _export(
    system: str,
    scope: dict[str, Any],
    at: str,
    records: list[dict[str, Any]],
    place: dict[str, str],
) -> bytes:
    """Return a shaar export: header, records, and the trailer with count and SHA-256."""
    header = {
        "shaar_export": 1,
        "system": system,
        "collector": {"name": "shaar example", "version": "0.1.0"},
        "collected_at": at,
        "scope": scope,
        **place,
    }
    lines = [json.dumps(header, sort_keys=True)] + [json.dumps(r, sort_keys=True) for r in records]
    body = ("\n".join(lines) + "\n").encode("utf-8")
    trailer = {"end": True, "records": len(records), "sha256": hashlib.sha256(body).hexdigest()}
    return body + (json.dumps(trailer, sort_keys=True) + "\n").encode("utf-8")


def _people(ids: str) -> list[dict[str, Any]]:
    out = []
    for rid, n, name, login, manager, enabled, kind in PEOPLE:
        if ids == "entra" and kind != "user":
            continue
        ident = _sid(rid) if ids == "ad" else _oid(n)
        boss = (
            ""
            if manager is None
            else (
                _sid(manager)
                if ids == "ad"
                else _oid(next(p[1] for p in PEOPLE if p[0] == manager))
            )
        )
        out.append(
            {
                "principal": {
                    "id": ident,
                    "name": name,
                    "kind": kind,
                    "enabled": enabled,
                    "email": f"{login}@corp.example" if kind == "user" else "",
                    "upn": f"{login}@corp.example",
                    "manager_id": boss,
                    "last_sign_in": "2026-10-30T08:15:00Z" if enabled else "2026-06-01T08:15:00Z",
                    "extra": {},
                }
            }
        )
    return out


def _group(
    ident: str, name: str, owners: list[str], *, complete: bool = True, kind: str = "group"
) -> dict[str, Any]:
    return {
        "resource": {
            "id": ident,
            "name": name,
            "kind": kind,
            "owner_ids": owners,
            "complete": complete,
            "extra": {},
        }
    }


def _grant(
    principal: str, resource: str, entitlement: str = "member", via: list[str] | None = None
) -> dict[str, Any]:
    return {
        "grant": {
            "principal_id": principal,
            "resource_id": resource,
            "entitlement": entitlement,
            "via": via or [],
            "extra": {},
        }
    }


def ad_export(*, after: bool) -> bytes:
    """Return the Active Directory export, before or after the removals."""
    finance, server, helpers = _sid(2001), _sid(2002), _sid(2003)
    records = [
        *_people("ad"),
        _group(finance, "Finance Admins", [_sid(1104)]),
        _group(server, "Server Operators", [_sid(1101)]),
        _group(helpers, "Ops Helpers", [_sid(1101)]),
    ]
    grants = [
        _grant(_sid(1102), finance),
        _grant(_sid(1105), server, via=["Server Operators", "Ops Helpers"]),
        _grant(_sid(1105), helpers),
        _grant(_sid(1107), server),
    ]
    if not after:
        grants += [_grant(_sid(1103), finance), _grant(_sid(1106), server)]
    else:
        grants += [
            _grant(_sid(1106), server),  # the contractor's removal was not made
            _grant(_sid(1106), finance),  # and the contractor was added somewhere new
        ]
    scope = {"groups": ["Finance Admins", "Server Operators"]}
    return _export(
        "ad", scope, AFTER_AT if after else BEFORE_AT, records + grants, {"domain": "corp.example"}
    )


def entra_export(*, after: bool) -> bytes:
    """Return the Entra ID export, before or after the removals."""
    payroll, admin = _oid(3001), "62e90394-69f5-4237-9190-012177145e10"
    records = [
        *_people("entra"),
        _group(payroll, "Payroll App Users", [_oid(5)], complete=not after),
        _group(admin, "Global Administrator", [], kind="role"),
        _grant(_oid(2), admin, "Global Administrator"),
        _grant(_oid(3), payroll),
    ]
    if not after:
        records += [_grant(_oid(6), payroll), _grant(_oid(7), payroll)]
    return _export(
        "entra",
        {"groups": ["Payroll App Users"], "roles": True},
        AFTER_AT if after else BEFORE_AT,
        records,
        {"tenant": TENANT},
    )


LEDGER_MAP = """\
# Column map for the Ledger finance application's user export.
system = "ledger"
resource = "Ledger"
resource_kind = "application"

[columns]
principal_id = "Email"
email = "Email"
principal_name = "Full name"
manager_id = "Manager email"
enabled = "Active"
entitlement = "Role"
last_sign_in = "Last login"
"""


def ledger_csv(*, after: bool) -> bytes:
    """Return the Ledger application's user export, before or after the removals."""
    rows = [
        ("Jordan Director", "jordan.director", "", "Yes", "Viewer"),
        ("Morgan Lead", "morgan.lead", "jordan.director", "Yes", "Approver"),
        ("Avery Example", "avery.example", "morgan.lead", "Yes", "Approver"),
    ]
    if not after:
        rows.append(("Drew Analyst", "drew.analyst", "morgan.lead", "Yes", "Viewer"))
    if not after:
        rows.append(("Blake Sample", "blake.sample", "morgan.lead", "No", "Viewer"))
    lines = ["Full name,Email,Manager email,Active,Role,Last login"]
    for name, login, boss, active, role in rows:
        manager = f"{boss}@corp.example" if boss else ""
        lines.append(f"{name},{login}@corp.example,{manager},{active},{role},2026-10-29")
    return ("\r\n".join(lines) + "\r\n").encode("utf-8")


# What each reviewer decided: (user, resource) -> (decision, comment)
DECISIONS: dict[tuple[str, str], tuple[str, str]] = {
    ("Avery Example", "Finance Admins"): ("Keep", ""),
    ("Blake Sample", "Finance Admins"): ("Remove", "Left the company in September"),
    ("Blake Sample", "Ledger"): ("Remove", "Left the company in September"),
    ("Avery Example", "Ledger"): ("Keep", ""),
    ("Drew Analyst", "Ledger"): ("Keep", ""),
    ("Drew Analyst", "Server Operators"): ("Unsure", "Ask the platform team"),
    ("Emery Contractor", "Server Operators"): ("Remove", "Contract ended"),
    ("Emery Contractor", "Payroll App Users"): ("Remove", "Contract ended"),
    ("Drew Analyst", "Payroll App Users"): ("Remove", "Moved to another team"),
    ("Avery Example", "Payroll App Users"): ("Keep", ""),
    ("Morgan Lead", "Global Administrator"): ("Keep", "Break-glass holder"),
    ("Morgan Lead", "Ledger"): ("Keep", ""),
}


def _returned(campaign: cmod.Campaign) -> dict[str, bytes]:
    """The packets as reviewers returned them, decisions filled in."""
    files = {}
    for reviewer in campaign.reviewers:
        rows = []
        for row in campaign.rows_for(reviewer.key):
            decision, comment = DECISIONS.get(
                (row.display["user"], row.display["resource"]), ("", "")
            )
            rows.append(
                PacketRow(
                    row_id=row.row_id,
                    row_check=row.row_check,
                    user=row.display["user"],
                    account=row.display["account"],
                    status=row.display["status"],
                    last_sign_in=row.display["last_sign_in"],
                    access_to=row.display["resource"],
                    type=row.display["resource_kind"],
                    access=row.display["access"],
                    granted_through=row.display["via"],
                    co_owners=row.display["co_owners"],
                    decision=decision,
                    comment=comment,
                )
            )
        packet = Packet(
            campaign_name=campaign.name,
            campaign_id=campaign.id,
            reviewer_name=reviewer.name,
            reviewer_email=reviewer.email,
            due=campaign.due,
            packet_digest=reviewer.packet_digest,
            rows=rows,
            co_owner_column=campaign.rule == "owner",
            created_at=campaign.created_at,
        )
        files[reviewer.packet.replace("packet-", "returned-")] = write_packet(packet)
    return files


def build() -> dict[str, dict[str, bytes]]:
    """Return every example file by folder, building the campaign from the ``before`` files.

    The ``before`` files are written to a temporary folder and read back, so the campaign is
    built exactly as ``shaar campaign`` would build it from them.
    """
    before = {
        "ad.jsonl": ad_export(after=False),
        "entra.jsonl": entra_export(after=False),
        "ledger.csv": ledger_csv(after=False),
        "ledger-map.toml": LEDGER_MAP.encode("utf-8"),
    }
    after = {
        "ad.jsonl": ad_export(after=True),
        "entra.jsonl": entra_export(after=True),
        "ledger.csv": ledger_csv(after=True),
    }
    with tempfile.TemporaryDirectory(prefix="shaar-example-") as scratch:
        folder = Path(scratch)
        write_files(folder, before, force=True)
        names = ("ad.jsonl", "entra.jsonl", "ledger.csv")
        snapshot = read_inputs(
            [folder / n for n in names], label="campaign", csv_map=folder / "ledger-map.toml"
        )
    built = cmod.build(snapshot, name=NAME, created_at=CREATED, due=DUE, rule="manager")
    document = campaign_document(built, generated_at=CREATED, version="example")
    campaign_files = {
        "campaign.json": cmod.dump(built),
        **packets(built),
        **render_all(document, ["unassigned", "rows"]),
    }
    return {
        "before": before,
        "campaign": campaign_files,
        "returned": _returned(built),
        "after": after,
    }


def write(directory: Path, *, force: bool) -> str:
    """Write the example under ``directory`` and return the commands to try, one per line."""
    folders = build()
    for name, files in folders.items():
        write_files(directory / name, files, force=force)
    root = str(directory)
    steps = [
        command_line(
            "shaar",
            "campaign",
            f"{root}/before/ad.jsonl",
            f"{root}/before/entra.jsonl",
            f"{root}/before/ledger.csv",
            "--map",
            f"{root}/before/ledger-map.toml",
            "--name",
            NAME,
            "--reviewers",
            "manager",
            "--due",
            DUE,
            "-o",
            f"{root}/my-campaign",
        ),
        command_line(
            "shaar",
            "decisions",
            f"{root}/campaign",
            *sorted(f"{root}/returned/{n}" for n in folders["returned"]),
            "-o",
            f"{root}/decisions",
        ),
        command_line(
            "shaar",
            "verify",
            f"{root}/campaign",
            f"{root}/decisions",
            f"{root}/after/ad.jsonl",
            f"{root}/after/entra.jsonl",
            f"{root}/after/ledger.csv",
            "--map",
            f"{root}/before/ledger-map.toml",
            "-o",
            f"{root}/verification",
        ),
    ]
    return "\n".join(f"  {step}" for step in steps)


__all__ = ["build", "write"]
