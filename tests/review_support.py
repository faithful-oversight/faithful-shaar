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


def start(  # noqa: PLR0913 - the parts of a small synthetic review
    root: Path,
    rows: str | bytes,
    *,
    extra: str = "",
    out: str = "camp",
    header: str = HEADER,
    columns: str | None = None,
) -> int:
    """Run ``shaar campaign`` on a ledger CSV with the standard header and ``rows``."""
    body = header.encode() + rows if isinstance(rows, bytes) else header + rows
    write(root / "before.csv", body)
    ledger_map(root, "map.toml", BEFORE_AT, extra, columns)
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


def verify(
    root: Path,
    later: Path,
    *,
    dec: str = "dec",
    to: str = "ver",
    extra: str = "",
    columns: str | None = None,
) -> int:
    ledger_map(root, "amap.toml", AFTER_AT, extra, columns)
    return main(
        [
            "verify",
            str(root / "camp"),
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


def example_commands(root: Path) -> list[tuple[dict[str, str], list[str]]]:
    """Run ``shaar example ROOT`` and return the commands it prints, parsed.

    Each command is its environment settings and its arguments after ``shaar``. Only the
    printed text is read, exactly as a person would copy it.
    """
    import contextlib  # noqa: PLC0415
    import io  # noqa: PLC0415
    import os  # noqa: PLC0415
    import shlex  # noqa: PLC0415

    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        assert main(["example", str(root)]) == 0
    commands: list[tuple[dict[str, str], list[str]]] = []
    env: dict[str, str] = {}
    for line in out.getvalue().splitlines():
        if not line.startswith("  "):
            continue
        if os.name == "nt":
            # The Windows form keeps backslashes; only double quotes group an argument.
            parts = [
                p[1:-1] if len(p) > 1 and p[0] == p[-1] == '"' else p
                for p in shlex.split(line.strip(), posix=False)
            ]
        else:
            parts = shlex.split(line.strip())
        if parts[0] == "set":  # the Windows form: the setting is on a line of its own
            name, _, value = parts[1].partition("=")
            env[name] = value
            continue
        while "=" in parts[0] and not parts[0].startswith("-"):
            name, _, value = parts.pop(0).partition("=")
            env[name] = value
        assert parts.pop(0) == "shaar"
        commands.append((dict(env), parts))
        env = {}
    return commands


def run_command(command: tuple[dict[str, str], list[str]]) -> int:
    """Run one parsed printed command with its environment settings."""
    import os  # noqa: PLC0415

    env, argv = command
    saved = {name: os.environ.get(name) for name in env}
    os.environ.update(env)
    try:
        return main(argv)
    finally:
        for name, old in saved.items():
            if old is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = old
