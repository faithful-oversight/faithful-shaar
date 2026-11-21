# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""The committed example review is exactly what the code produces.

To regenerate it after a deliberate change: ``uv run python -m tests.test_example``.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import sys
from pathlib import Path
from typing import TYPE_CHECKING

from faithful_core.exitcodes import ExitCode

from faithful_shaar import example
from tests import review_support as rs

if TYPE_CHECKING:
    import pytest

SAMPLE = Path(__file__).resolve().parent.parent / "examples" / "corp-example"
GENERATED = "1795251600"  # 2026-11-21T09:00:00Z, after the due date
REGENERATE = "differs from the code; run: uv run python -m tests.test_example"


def produce(root: Path) -> list[int]:
    """Run exactly the commands ``shaar example`` prints, in order; return their exit codes."""
    return [rs.run_command(command) for command in rs.example_commands(root)]


def files(root: Path) -> dict[str, bytes]:
    return {
        p.relative_to(root).as_posix(): p.read_bytes()
        for p in sorted(root.rglob("*"))
        if p.is_file()
    }


def test_the_committed_example_is_what_the_code_produces(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SOURCE_DATE_EPOCH", GENERATED)
    assert produce(tmp_path / "ex") == [ExitCode.FINDINGS] * 3
    made, committed = files(tmp_path / "ex"), files(SAMPLE)
    assert sorted(made) == sorted(committed), REGENERATE
    for name, data in made.items():
        assert data == committed[name], f"{name} {REGENERATE}"


def test_the_printed_commands_chain_into_a_full_review(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # What a new user does: run `shaar example DIR`, then copy the printed commands in order.
    monkeypatch.setenv("SOURCE_DATE_EPOCH", GENERATED)
    root = tmp_path / "shaar-demo"
    commands = rs.example_commands(root)
    assert [argv[0] for _, argv in commands] == ["campaign", "decisions", "verify"]
    assert "SOURCE_DATE_EPOCH" in commands[0][0]
    assert [rs.run_command(c) for c in commands] == [ExitCode.FINDINGS] * 3
    decisions = json.loads((root / "decisions" / "decisions-report.json").read_text("utf-8"))
    assert decisions["headline"].startswith("12 of 13 entries have an accepted decision")
    verification = json.loads((root / "verification" / "verify-report.json").read_text("utf-8"))
    assert verification["headline"].startswith("2 of 5 removals verified")
    # The returned packets were accepted by the campaign the first command made.
    packets = decisions["data"]["packets"]
    assert [p["status"] for p in packets] == ["read"] * 3


def test_every_manifest_matches_its_folder() -> None:
    for manifest_path in SAMPLE.rglob("manifest.json"):
        folder = manifest_path.parent
        manifest = json.loads(manifest_path.read_text("utf-8"))
        for entry in manifest["files"]:
            data = (folder / entry["name"]).read_bytes()
            assert (len(data), hashlib.sha256(data).hexdigest()) == (entry["size"], entry["sha256"])
        listed = {entry["name"] for entry in manifest["files"]} | {"manifest.json"}
        assert {p.name for p in folder.iterdir()} == listed


def test_the_example_is_the_same_every_time() -> None:
    assert example.build() == example.build()


if __name__ == "__main__":  # pragma: no cover - the regeneration helper
    os.environ["SOURCE_DATE_EPOCH"] = GENERATED
    shutil.rmtree(SAMPLE, ignore_errors=True)
    print(produce(SAMPLE), file=sys.stderr)  # noqa: T201
