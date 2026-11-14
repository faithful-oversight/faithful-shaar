# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""The whole review from the command line: campaign, decisions, verification."""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

import jsonschema
import pytest

from faithful_shaar import cli, example
from faithful_shaar.cli import ExitCode, main
from faithful_shaar.formats.xlsx import read_packet
from faithful_shaar.schema import schema_text


@pytest.fixture(scope="module")
def sample(tmp_path_factory: pytest.TempPathFactory) -> Path:
    root = tmp_path_factory.mktemp("example")
    assert main(["example", str(root / "ex")]) == ExitCode.OK
    return root / "ex"


def report(folder: Path, kind: str) -> dict[str, Any]:
    data: dict[str, Any] = json.loads((folder / f"{kind}-report.json").read_text("utf-8"))
    jsonschema.validate(data, json.loads(schema_text(f"{kind}-report-v1")))
    return data


def test_example_writes_every_stage(sample: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert sorted(p.name for p in sample.iterdir()) == ["after", "before", "campaign", "returned"]
    assert (sample / "campaign" / "campaign.json").is_file()
    assert main(["example", str(sample)]) == ExitCode.INPUT_ERROR  # never overwrites
    assert "--force" in capsys.readouterr().err


def test_campaign_from_the_command_line(
    sample: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    before = sample / "before"
    out = tmp_path / "campaign"
    code = main(
        [
            "campaign",
            str(before / "ad.jsonl"),
            str(before / "entra.jsonl"),
            str(before / "ledger.csv"),
            "--map",
            str(before / "ledger-map.toml"),
            "--name",
            example.NAME,
            "--reviewers",
            "manager",
            "--due",
            example.DUE,
            "-o",
            str(out),
        ]
    )
    assert code == ExitCode.FINDINGS  # two entries have no manager
    said = capsys.readouterr().out
    assert "have no reviewer" in said
    assert "shaar decisions" in said
    data = report(out, "campaign")
    assert data["counts"]["Reviewers"] == 3
    packets = sorted(out.glob("packet-*.xlsx"))
    assert len(packets) == 3
    read_packet(packets[0].read_bytes(), packets[0].name)
    assert {p.name for p in out.iterdir()} >= {
        "campaign.json",
        "manifest.json",
        "rows.csv",
        "unassigned.csv",
    }


def test_decisions_and_verification(sample: Path, tmp_path: Path) -> None:
    packets = sorted(str(p) for p in (sample / "returned").iterdir())
    decisions = tmp_path / "decisions"
    assert (
        main(["decisions", str(sample / "campaign"), *packets, "-o", str(decisions)])
        == ExitCode.FINDINGS
    )
    data = report(decisions, "decisions")
    assert data["counts"]["Removals to make"] == 5
    assert {row["state"] for row in data["sections"]["attention"]} >= {
        "unsure",
        "undecided",
        "unassigned",
    }
    assert (decisions / "removals.csv").read_text("utf-8").count("\n") == 6
    after = sample / "after"
    verified = tmp_path / "verified"
    code = main(
        [
            "verify",
            str(sample / "campaign" / "campaign.json"),
            str(decisions / "decisions.json"),
            str(after / "ad.jsonl"),
            str(after / "entra.jsonl"),
            str(after / "ledger.csv"),
            "--map",
            str(sample / "after" / "ledger-map.toml"),
            "-o",
            str(verified),
        ]
    )
    assert code == ExitCode.FINDINGS
    data = report(verified, "verify")
    results = sorted(row["result"] for row in data["sections"]["removals"])
    assert results == ["failed", "removed", "removed", "unknown", "unknown"]
    assert len(data["sections"]["kept_but_gone"]) == 1
    assert len(data["sections"]["new_since_review"]) == 1


def test_complete_decisions_exit_zero(sample: Path, tmp_path: Path) -> None:
    from faithful_shaar import campaign as cmod  # noqa: PLC0415
    from faithful_shaar.formats.xlsx import Packet, PacketRow, write_packet  # noqa: PLC0415

    built = cmod.load((sample / "campaign" / "campaign.json").read_bytes())
    names = []
    for reviewer in built.reviewers:
        rows = [
            PacketRow(
                r.row_id,
                r.row_check,
                r.display["user"],
                r.display["account"],
                r.display["status"],
                r.display["last_sign_in"],
                r.display["resource"],
                r.display["resource_kind"],
                r.display["access"],
                r.display["via"],
                r.display["co_owners"],
                decision="Keep",
            )
            for r in built.rows_for(reviewer.key)
        ]
        data = write_packet(
            Packet(
                built.name,
                built.id,
                reviewer.name,
                reviewer.email,
                built.due,
                reviewer.packet_digest,
                rows,
                co_owner_column=False,
                created_at=built.created_at,
            )
        )
        path = tmp_path / reviewer.packet
        path.write_bytes(data)
        names.append(str(path))
    trimmed = tmp_path / "campaign"
    shutil.copytree(sample / "campaign", trimmed)
    raw = json.loads((trimmed / "campaign.json").read_text("utf-8"))
    raw["unassigned"] = []
    built.unassigned = []
    raw["digest"] = cmod.digest(built)
    (trimmed / "campaign.json").write_text(json.dumps(raw), "utf-8")
    assert main(["decisions", str(trimmed), *names, "-o", str(tmp_path / "d")]) == ExitCode.OK


@pytest.mark.parametrize(
    ("argv", "code", "said"),
    [
        (
            ["campaign", "x.jsonl", "-o", "o", "--name", "n", "--reviewers", "map"],
            ExitCode.USAGE,
            "--reviewer-map",
        ),
        (
            [
                "campaign",
                "x.jsonl",
                "-o",
                "o",
                "--name",
                "n",
                "--reviewers",
                "owner",
                "--due",
                "2026-02-30",
            ],
            ExitCode.USAGE,
            "not a date",
        ),
        (
            [
                "campaign",
                "x.jsonl",
                "-o",
                "o",
                "--name",
                "n",
                "--reviewers",
                "owner",
                "--due",
                "26-1-1",
            ],
            ExitCode.USAGE,
            "not a date",
        ),
        (
            ["verify", "c", "d", "l", "-o", "o", "--as-of", "yesterday"],
            ExitCode.USAGE,
            "not an ISO 8601 time",
        ),
        (
            ["campaign", "missing.jsonl", "-o", "o", "--name", "n", "--reviewers", "owner"],
            ExitCode.INPUT_ERROR,
            "missing.jsonl",
        ),
    ],
)
def test_usage_and_input_errors(
    argv: list[str], code: ExitCode, said: str, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(argv) == code
    assert said in capsys.readouterr().err


def test_decisions_input_errors(
    sample: Path,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    packet = next((sample / "returned").iterdir())
    twin = tmp_path / "twin"
    twin.mkdir()
    shutil.copy(packet, twin / packet.name)
    assert (
        main(
            [
                "decisions",
                str(sample / "campaign"),
                str(packet),
                str(twin / packet.name),
                "-o",
                str(tmp_path / "o"),
            ]
        )
        == ExitCode.USAGE
    )
    assert "two packets are named" in capsys.readouterr().err
    assert (
        main(["decisions", str(sample / "campaign"), str(tmp_path), "-o", str(tmp_path / "o")])
        == ExitCode.INPUT_ERROR
    )
    assert "it is not a file" in capsys.readouterr().err
    monkeypatch.setattr(cli, "MAX_PACKET_BYTES", 10)
    assert (
        main(["decisions", str(sample / "campaign"), str(packet), "-o", str(tmp_path / "o")])
        == ExitCode.INPUT_ERROR
    )
    assert "larger than" in capsys.readouterr().err
    assert (
        main(["decisions", str(tmp_path / "nowhere"), str(packet), "-o", str(tmp_path / "o")])
        == ExitCode.INPUT_ERROR
    )


def test_an_unreadable_file_is_an_input_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    target = tmp_path / "campaign.json"
    target.write_text("{}", "utf-8")

    def refuse(_self: Path) -> bytes:
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(Path, "read_bytes", refuse)
    assert (
        main(["decisions", str(target), str(target), "-o", str(tmp_path / "o")])
        == ExitCode.INPUT_ERROR
    )
    assert "Permission denied" in capsys.readouterr().err


def test_schema_and_internal_errors(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    assert main(["schema", "manifest-v1"]) == ExitCode.OK
    assert json.loads(capsys.readouterr().out)["$schema"].startswith("https://json-schema.org/")

    def boom(_args: object) -> int:
        msg = "kaboom"
        raise RuntimeError(msg)

    monkeypatch.setattr(cli, "_schema", boom)
    assert main(["schema", "manifest-v1"]) == ExitCode.INTERNAL_ERROR
    assert "This is a bug in shaar" in capsys.readouterr().err


@pytest.mark.parametrize("epoch", ["", "x", "99999999999999999999"])
def test_now_falls_back_to_the_clock(epoch: str, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SOURCE_DATE_EPOCH", epoch)
    assert cli._now().year >= 2026  # noqa: SLF001


def test_as_of_is_normalized() -> None:
    assert cli._time("2026-11-20T09:00:00+02:00") == "2026-11-20T07:00:00Z"  # noqa: SLF001
    assert cli._time("2026-11-20T09:00:00") == "2026-11-20T09:00:00Z"  # noqa: SLF001
