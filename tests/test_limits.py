# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""The ``--limit NAME=VALUE`` option: every size limit can be raised, and none fails silently."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from faithful_core.exitcodes import ExitCode

from faithful_shaar import limits
from faithful_shaar.cli import main
from tests import review_support as rs

DOCS = Path(__file__).resolve().parent.parent / "docs"
THREE = rs.ROWS  # three people


def campaign(root: Path, *extra: str, out: str = "camp") -> int:
    """Run ``shaar campaign`` on the standard ledger with extra options."""
    rs.write(root / "before.csv", rs.HEADER + THREE)
    rs.ledger_map(root, "map.toml", rs.BEFORE_AT)
    rs.write(root / "rmap.csv", rs.REVIEWERS)
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
            rs.DUE,
            "-o",
            str(root / out),
            *extra,
        ]
    )


def manifest(root: Path, folder: str = "camp") -> dict[str, object]:
    data: dict[str, object] = json.loads((root / folder / "manifest.json").read_text("utf-8"))
    return data


def stderr(capsys: pytest.CaptureFixture[str]) -> str:
    return capsys.readouterr().err


# -- the option itself ------------------------------------------------------------------


@pytest.mark.parametrize(
    "bad",
    [
        "csv-rows",
        "nonsense=5",
        "csv-rows=",
        "csv-rows=0",
        "csv-rows=-3",
        "csv-rows=1.5",
        "csv-rows=lots",
        "csv-rows=٣",  # an Arabic-Indic digit is not an ASCII digit
        f"csv-rows={2**41}",
    ],
)
def test_a_bad_limit_is_a_usage_error_and_writes_nothing(
    tmp_path: Path, bad: str, capsys: pytest.CaptureFixture[str]
) -> None:
    assert campaign(tmp_path, "--limit", bad) == ExitCode.USAGE
    said = stderr(capsys)
    assert "NAME=VALUE" in said or "whole number" in said
    assert not (tmp_path / "camp").exists()


def test_every_run_records_the_limits_it_used_and_a_raised_one_is_marked(tmp_path: Path) -> None:
    assert campaign(tmp_path) == ExitCode.OK
    recorded = manifest(tmp_path)["limits"]
    assert isinstance(recorded, dict)
    assert set(recorded) == set(limits.NAMES)
    assert recorded == {name: limits.default(name) for name in limits.NAMES}
    assert (
        campaign(tmp_path, "--limit", "csv-rows=5000", "--limit", "csv-bytes=1_000_000", out="b")
        == 0
    )
    raised = manifest(tmp_path, "b")["limits"]
    assert isinstance(raised, dict)
    assert raised["csv-rows"] == 5000
    assert raised["csv-bytes"] == 1_000_000
    assert raised["map-bytes"] == limits.default("map-bytes")


def test_limits_do_not_leak_from_one_run_to_the_next(tmp_path: Path) -> None:
    assert campaign(tmp_path, "--limit", "csv-rows=5000") == ExitCode.OK
    assert limits.effective() == {name: limits.default(name) for name in limits.NAMES}


def test_a_limit_nobody_set_follows_the_rows_limit() -> None:
    limits.configure(["xlsx-rows=10"])
    try:
        assert limits.get("xlsx-cells") == 160
        assert limits.get("xml-elements") == 640
        limits.configure(["xlsx-rows=10", "xlsx-cells=7"])
        assert limits.get("xlsx-cells") == 7
    finally:
        limits.reset()


def test_the_output_schema_accepts_a_manifest_with_and_without_limits(tmp_path: Path) -> None:
    import jsonschema  # noqa: PLC0415

    from faithful_shaar.outputs.schema import generate_schema  # noqa: PLC0415

    assert campaign(tmp_path) == ExitCode.OK
    schema = json.loads(generate_schema("manifest-v1"))
    data = manifest(tmp_path)
    jsonschema.Draft202012Validator(schema).validate(data)
    del data["limits"]
    jsonschema.Draft202012Validator(schema).validate(data)
    data["limits"] = {"csv-rows": 0}
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.Draft202012Validator(schema).validate(data)


def test_the_docs_name_every_limit_with_its_default() -> None:
    text = (DOCS / "usage.md").read_text("utf-8")
    for name in limits.NAMES:
        assert f"`{name}`" in text, name
        assert f"{limits.default(name):,}" in text, name


# -- reading input: a limit hit is an error that names the fix, a raised limit reads it all --


def _hit_then_raise(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    name: str,
    low: int,
    high: int,
) -> None:
    assert campaign(tmp_path, "--limit", f"{name}={low}") == ExitCode.INPUT_ERROR
    assert f"--limit {name}=NUMBER" in stderr(capsys)
    assert not (tmp_path / "camp").exists()
    assert campaign(tmp_path, "--limit", f"{name}={high}") == ExitCode.OK
    assert len(rs.load(tmp_path).rows) == 3


def test_csv_rows(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    _hit_then_raise(tmp_path, capsys, "csv-rows", 2, 3)


def test_csv_bytes(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    _hit_then_raise(tmp_path, capsys, "csv-bytes", 20, 10_000)


def test_map_bytes(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    _hit_then_raise(tmp_path, capsys, "map-bytes", 10, 10_000)


def test_column_map_bytes(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    _hit_then_raise(tmp_path, capsys, "column-map-bytes", 10, 10_000)


def test_xlsx_rows_when_a_packet_is_written(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # Writing stops short of what reading accepts, so a packet is always readable again.
    _hit_then_raise(tmp_path, capsys, "xlsx-rows", 3, 4)


def test_xlsx_bytes_when_a_packet_is_written(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _hit_then_raise(tmp_path, capsys, "xlsx-bytes", 1000, 1_000_000)


def _example_first_command(root: Path) -> list[str]:
    _env, argv = rs.example_commands(root)[0]
    return argv


def test_export_bytes_and_line_bytes(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    argv = _example_first_command(tmp_path / "ex")
    out = argv.index("-o")
    argv[out + 1] = str(tmp_path / "c1")
    assert main([*argv, "--limit", "export-bytes=50"]) == ExitCode.INPUT_ERROR
    assert "--limit export-bytes=NUMBER" in stderr(capsys)
    # A line over the limit is skipped, recorded, and the run cannot be clean.
    argv[out + 1] = str(tmp_path / "c2")
    longest = max(
        len(line) for line in (tmp_path / "ex" / "before" / "ad.jsonl").read_bytes().splitlines()
    )
    assert main([*argv, "--limit", f"line-bytes={longest - 1}"]) == ExitCode.FINDINGS
    said = rs.report(tmp_path, "c2", "campaign")
    assert "--limit line-bytes=NUMBER" in json.dumps(said["problems"])
    argv[out + 1] = str(tmp_path / "c3")
    assert (
        main([*argv, "--limit", "export-bytes=10_000_000"]) == ExitCode.FINDINGS
    )  # example has gaps
    assert "line is longer" not in json.dumps(rs.report(tmp_path, "c3", "campaign")["problems"])


# -- the records and the packets ---------------------------------------------------------


def _decisions(root: Path, packet: Path, *extra: str, to: str = "dec") -> int:
    return main(["decisions", str(root / "camp"), str(packet), "-o", str(root / to), *extra])


@pytest.fixture
def started(tmp_path: Path) -> Path:
    assert campaign(tmp_path) == ExitCode.OK
    return tmp_path


def test_campaign_bytes(started: Path, capsys: pytest.CaptureFixture[str]) -> None:
    packet = rs.answer(started, "Keep")
    assert _decisions(started, packet, "--limit", "campaign-bytes=100") == ExitCode.INPUT_ERROR
    assert "--limit campaign-bytes=NUMBER" in stderr(capsys)
    assert _decisions(started, packet, "--limit", "campaign-bytes=10_000_000") == ExitCode.OK


def test_packet_bytes(started: Path, capsys: pytest.CaptureFixture[str]) -> None:
    packet = rs.answer(started, "Keep")
    assert _decisions(started, packet, "--limit", "packet-bytes=100") == ExitCode.INPUT_ERROR
    assert "--limit packet-bytes=NUMBER" in stderr(capsys)
    assert _decisions(started, packet, "--limit", "packet-bytes=10_000_000") == ExitCode.OK


def test_decisions_bytes(started: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert _decisions(started, rs.answer(started, "Remove")) == ExitCode.OK
    later = rs.write(started / "after.csv", rs.HEADER)
    rs.ledger_map(started, "amap.toml", rs.AFTER_AT)

    def verify(limit: str) -> int:
        return main(
            [
                "verify",
                str(started / "camp"),
                str(started / "dec"),
                str(later),
                "--map",
                str(started / "amap.toml"),
                "-o",
                str(started / f"ver-{limit.split('=')[1]}"),
                "--limit",
                limit,
            ]
        )

    assert verify("decisions-bytes=100") == ExitCode.INPUT_ERROR
    assert "--limit decisions-bytes=NUMBER" in stderr(capsys)
    assert verify("decisions-bytes=10_000_000") in (ExitCode.OK, ExitCode.FINDINGS)
    assert (started / "ver-10_000_000" / "verify-report.json").is_file()


@pytest.mark.parametrize(
    ("name", "low", "high"),
    [
        ("xlsx-rows", 2, 50),
        ("xlsx-cells", 5, 1000),
        ("xml-elements", 20, 100_000),
        ("xlsx-bytes", 1000, 10_000_000),
    ],
)
def test_a_returned_packet_over_a_limit_is_recorded_not_dropped(
    started: Path, name: str, low: int, high: int
) -> None:
    packet = rs.answer(started, "Keep")
    # The packet is refused and the decision record says so: it is incomplete, so exit 1.
    assert _decisions(started, packet, "--limit", f"{name}={low}") == ExitCode.FINDINGS
    said = rs.report(started, "dec", "decisions")
    assert f"--limit {name}=NUMBER" in json.dumps(said)
    assert said["data"]["complete"] is False
    assert _decisions(started, packet, "--limit", f"{name}={high}", to="dec2") == ExitCode.OK
    assert rs.report(started, "dec2", "decisions")["data"]["complete"] is True


def test_a_limit_option_is_listed_for_every_command_that_reads_files(
    capsys: pytest.CaptureFixture[str],
) -> None:
    for command in ("campaign", "decisions", "verify"):
        assert main([command, "--help"]) == ExitCode.OK
        assert "--limit NAME=VALUE" in capsys.readouterr().out
