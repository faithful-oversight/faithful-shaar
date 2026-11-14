# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""Helpers for end-to-end tests that run the command line on small synthetic CSV reviews."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from faithful_shaar import campaign as cmod
from faithful_shaar import example
from faithful_shaar.cli import main

if TYPE_CHECKING:
    from pathlib import Path

HEADER = "Full name,Email,Active,Role\n"
ROWS = (
    "Alice A,alice@corp.example,Yes,Admin\n"
    "Bob B,bob@corp.example,Yes,Viewer\n"
    "Carol C,carol@corp.example,Yes,Approver\n"
)
OTHER = "Zed Z,zed@corp.example,Yes,Viewer\n"  # someone the review did not cover
REVIEWERS = (
    "resource,reviewer_id,reviewer_name,reviewer_email\n"
    "Ledger,rev1,Rita Reviewer,rita@corp.example\n"
)
MAP = """\
system = "ledger"
resource = "Ledger"
resource_kind = "application"
collected_at = "{at}"
{extra}
[columns]
principal_id = "Email"
email = "Email"
principal_name = "Full name"
enabled = "Active"
entitlement = "Role"
"""
BEFORE_AT = "2026-11-01T22:00:00Z"
AFTER_AT = "2026-11-20T22:00:00Z"
DUE = "2026-11-16"


def write(path: Path, text: str | bytes) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(text, bytes):
        path.write_bytes(text)
    else:
        path.write_text(text, encoding="utf-8", newline="")
    return path


def ledger_map(root: Path, name: str, at: str, extra: str = "", columns: str | None = None) -> Path:
    text = MAP.format(at=at, extra=extra)
    if columns is not None:
        text = text.split("[columns]")[0] + "[columns]\n" + columns
    return write(root / name, text)


def start(root: Path, rows: str | bytes, *, extra: str = "", out: str = "camp") -> int:
    """Run ``shaar campaign`` on a ledger CSV with the standard header and ``rows``."""
    body = HEADER.encode() + rows if isinstance(rows, bytes) else HEADER + rows
    write(root / "before.csv", body)
    ledger_map(root, "map.toml", BEFORE_AT, extra)
    write(root / "rmap.csv", REVIEWERS)
    return main(
        [
            "campaign",
            str(root / "before.csv"),
            "--map",
            str(root / "map.toml"),
            "--name",
            "T",
            "--reviewers",
            "map",
            "--reviewer-map",
            str(root / "rmap.csv"),
            "--due",
            DUE,
            "-o",
            str(root / out),
        ]
    )


def load(root: Path, out: str = "camp") -> cmod.Campaign:
    return cmod.load((root / out / "campaign.json").read_bytes())


def answer(root: Path, decision: str, *, out: str = "camp", name: str = "r1.xlsx") -> Path:
    """Write a returned packet with ``decision`` on every row; return its path."""
    built = load(root, out)
    chosen = {(r.display["user"], r.display["resource"]): (decision, "") for r in built.rows}
    files = example.fill_packets(built, chosen)
    (data,) = files.values()
    return write(root / name, data)


def decide(root: Path, *packets: Path, out: str = "camp", to: str = "dec") -> int:
    return main(["decisions", str(root / out), *map(str, packets), "-o", str(root / to)])


def verify(root: Path, later: Path, *, out: str = "camp", dec: str = "dec", to: str = "ver") -> int:
    ledger_map(root, "amap.toml", AFTER_AT)
    return main(
        [
            "verify",
            str(root / out),
            str(root / dec),
            str(later),
            "--map",
            str(root / "amap.toml"),
            "-o",
            str(root / to),
        ]
    )


def report(root: Path, folder: str, kind: str) -> dict[str, Any]:
    data: dict[str, Any] = json.loads((root / folder / f"{kind}-report.json").read_text("utf-8"))
    return data
