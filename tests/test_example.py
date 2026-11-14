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

from faithful_shaar import example
from faithful_shaar.cli import ExitCode, main

if TYPE_CHECKING:
    import pytest

SAMPLE = Path(__file__).resolve().parent.parent / "examples" / "corp-example"
GENERATED = "1795251600"  # 2026-11-21T09:00:00Z, after the due date
REGENERATE = "differs from the code; run: uv run python -m tests.test_example"


def produce(root: Path) -> list[int]:
    """Write the example and run decisions and verification on it; return the exit codes."""
    codes = [main(["example", str(root)])]
    returned = sorted(str(p) for p in (root / "returned").iterdir())
    codes.append(
        main(["decisions", str(root / "campaign"), *returned, "-o", str(root / "decisions")])
    )
    after = [str(root / "after" / n) for n in ("ad.jsonl", "entra.jsonl", "ledger.csv")]
    codes.append(
        main(
            [
                "verify",
                str(root / "campaign"),
                str(root / "decisions"),
                *after,
                "--map",
                str(root / "after" / "ledger-map.toml"),
                "-o",
                str(root / "verification"),
            ]
        )
    )
    return codes


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
    assert produce(tmp_path / "ex") == [ExitCode.OK, ExitCode.FINDINGS, ExitCode.FINDINGS]
    made, committed = files(tmp_path / "ex"), files(SAMPLE)
    assert sorted(made) == sorted(committed), REGENERATE
    for name, data in made.items():
        assert data == committed[name], f"{name} {REGENERATE}"


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
