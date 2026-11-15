# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""Regression tests for the findings of the 2026-11-14 review (SHAAR-C01 to C13).

Each test names the finding it guards. They run the command line on small synthetic reviews,
because the findings were all gaps between stages that unit tests of one stage cannot see.
"""

from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import subprocess
import sys
import unicodedata
from pathlib import Path
from typing import TYPE_CHECKING

from faithful_shaar import keys
from faithful_shaar.cli import ExitCode, main
from tests import review_support as rs

if TYPE_CHECKING:
    from collections.abc import Iterator

    import pytest

SRC = Path(__file__).resolve().parent.parent / "src"


def problems(report: dict[str, object]) -> list[str]:
    found = report["problems"]
    assert isinstance(found, list)
    return [str(p["reason"]) for p in found]


# SHAAR-C01 ------------------------------------------------------------------------------


def test_c01_decisions_carries_the_campaigns_read_problems(tmp_path: Path) -> None:
    extra_cells = rs.ROWS + "Dave D,dave@corp.example,Yes,Admin,EXTRA,CELLS\n"
    assert rs.start(tmp_path, extra_cells) == ExitCode.FINDINGS
    assert len(rs.load(tmp_path).rows) == 3  # Dave never reached a packet
    packet = rs.answer(tmp_path, "Keep")
    assert rs.decide(tmp_path, packet) == ExitCode.FINDINGS
    said = rs.report(tmp_path, "dec", "decisions")
    assert any("Dave" not in r and "row skipped" in r for r in problems(said))
    assert "could not read all of its input" in said["headline"]
    assert said["data"]["complete"] is False
    assert said["counts"]["Problems reading the inputs"] == 2
    assert any("recorded 2 problems" in g for g in said["data"]["gaps"])


def test_c01_a_clean_campaign_still_completes(tmp_path: Path) -> None:
    assert rs.start(tmp_path, rs.ROWS) == ExitCode.OK
    assert rs.decide(tmp_path, rs.answer(tmp_path, "Keep")) == ExitCode.OK
    said = rs.report(tmp_path, "dec", "decisions")
    assert said["data"]["complete"] is True
    assert problems(said) == []


def test_c01_a_resource_not_read_in_full_makes_the_record_incomplete(tmp_path: Path) -> None:
    assert rs.start(tmp_path, rs.ROWS, extra="complete = false") == ExitCode.OK
    assert rs.decide(tmp_path, rs.answer(tmp_path, "Keep")) == ExitCode.FINDINGS
    gaps = rs.report(tmp_path, "dec", "decisions")["data"]["gaps"]
    assert any("not read in full" in g and "Ledger" in g for g in gaps)


# SHAAR-C03 ------------------------------------------------------------------------------


def test_c03_verify_of_an_empty_decision_record_is_not_a_clean_result(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert rs.start(tmp_path, rs.ROWS) == ExitCode.OK
    wrong = rs.write(tmp_path / "other.xlsx", b"not a workbook")
    assert rs.decide(tmp_path, wrong) == ExitCode.FINDINGS
    later = rs.write(tmp_path / "after.csv", rs.HEADER + rs.ROWS)
    capsys.readouterr()
    assert rs.verify(tmp_path, later) == ExitCode.FINDINGS
    assert "0 of 0 removals verified" in capsys.readouterr().out
    said = rs.report(tmp_path, "ver", "verify")
    assert "decision record is not complete" in said["headline"]
    assert said["data"]["decision_record_complete"] is False
    assert any("3 entries have no accepted decision" in r for r in problems(said))
    assert said["counts"]["Decision record gaps"] >= 1


def test_c03_verify_of_a_partly_returned_review_is_not_complete(tmp_path: Path) -> None:
    assert rs.start(tmp_path, rs.ROWS) == ExitCode.OK
    packet = rs.answer(tmp_path, "Remove")
    # Everyone decided Remove is gone from the later export, so the removals were made ...
    later = rs.write(tmp_path / "after.csv", rs.HEADER + rs.OTHER)
    assert rs.decide(tmp_path, packet) == ExitCode.OK
    assert rs.verify(tmp_path, later) == ExitCode.OK
    # ... while a review with an Unsure answer is not finished, even if its removals are.
    unsure = rs.answer(tmp_path, "Unsure", name="r2.xlsx")
    assert rs.decide(tmp_path, unsure, to="dec2") == ExitCode.FINDINGS
    assert rs.verify(tmp_path, later, dec="dec2", to="ver2") == ExitCode.FINDINGS


def test_c03_a_complete_review_that_was_carried_out_exits_zero(tmp_path: Path) -> None:
    assert rs.start(tmp_path, rs.ROWS) == ExitCode.OK
    assert rs.decide(tmp_path, rs.answer(tmp_path, "Remove")) == ExitCode.OK
    later = rs.write(tmp_path / "after.csv", rs.HEADER + rs.OTHER)
    assert rs.verify(tmp_path, later) == ExitCode.OK
    said = rs.report(tmp_path, "ver", "verify")
    assert said["data"]["decision_record_complete"] is True
    assert said["counts"]["Removals verified"] == 3


# SHAAR-C11 ------------------------------------------------------------------------------


def test_c11_a_campaign_with_no_entries_is_not_a_clean_success(tmp_path: Path) -> None:
    assert rs.start(tmp_path, "") == ExitCode.FINDINGS
    said = rs.report(tmp_path, "camp", "campaign")
    assert "no access entries were found in the inputs" in problems(said)
    assert rs.decide(tmp_path, rs.write(tmp_path / "x.xlsx", b"x")) == ExitCode.FINDINGS
    later = rs.write(tmp_path / "after.csv", rs.HEADER)
    assert rs.verify(tmp_path, later) == ExitCode.FINDINGS


# SHAAR-C02 ------------------------------------------------------------------------------

ALICE_BOB = "Alice A,alice@corp.example,Yes,Admin\nBob B,bob@corp.example,Yes,Viewer\n"


def removal_results(root: Path) -> list[str]:
    said = rs.report(root, "ver", "verify")
    return [str(r["result"]) for r in said["sections"]["removals"]]


def test_c02_a_renamed_entitlement_column_makes_removals_unknown(tmp_path: Path) -> None:
    assert rs.start(tmp_path, ALICE_BOB) == ExitCode.OK
    assert rs.decide(tmp_path, rs.answer(tmp_path, "Remove")) == ExitCode.OK
    # Nobody lost access, but the later export calls the column "Position", not "Role".
    later = rs.write(
        tmp_path / "after.csv",
        "Full name,Email,Active,Position\n"
        "Alice A,alice@corp.example,Yes,Admin\nBob B,bob@corp.example,Yes,Viewer\n",
    )
    assert rs.verify(tmp_path, later) == ExitCode.INPUT_ERROR  # a map without `optional`
    assert rs.verify(tmp_path, later, extra="optional = true") == ExitCode.FINDINGS
    assert removal_results(tmp_path) == ["unknown", "unknown"]
    said = rs.report(tmp_path, "ver", "verify")
    assert any("'Role' (mapped to entitlement) is not in the file" in r for r in problems(said))


def verify_generic(root: Path, later: Path) -> int:
    """Verify with a map that names no columns, so the generic preset supplies them all."""
    rs.write(
        root / "gmap.toml",
        'preset = "generic"\nsystem = "ledger"\nresource = "Ledger"\n'
        f'collected_at = "{rs.AFTER_AT}"\n',
    )
    return main(
        [
            "verify",
            str(root / "camp"),
            str(root / "dec"),
            str(later),
            "--map",
            str(root / "gmap.toml"),
            "-o",
            str(root / "ver"),
        ]
    )


def test_c02_a_preset_entitlement_column_that_is_absent_cannot_show_a_removal(
    tmp_path: Path,
) -> None:
    assert rs.start(tmp_path, ALICE_BOB) == ExitCode.OK
    assert rs.decide(tmp_path, rs.answer(tmp_path, "Remove")) == ExitCode.OK
    later = rs.write(
        tmp_path / "after.csv",
        "principal_id,principal_name,email,role\n"
        "alice@corp.example,Alice A,alice@corp.example,Admin\n"
        "bob@corp.example,Bob B,bob@corp.example,Viewer\n",
    )
    assert verify_generic(tmp_path, later) == ExitCode.FINDINGS
    assert removal_results(tmp_path) == ["unknown", "unknown"]
    said = rs.report(tmp_path, "ver", "verify")
    assert all("no entitlement column" in r["reason"] for r in said["sections"]["removals"])


def test_c02_a_member_removal_is_still_verified_by_an_export_without_entitlements(
    tmp_path: Path,
) -> None:
    assert rs.start(tmp_path, "Bob B,bob@corp.example,Yes,\n") == ExitCode.OK  # blank = member
    assert rs.decide(tmp_path, rs.answer(tmp_path, "Remove")) == ExitCode.OK
    later = rs.write(
        tmp_path / "after.csv", "principal_id,principal_name\nzed@corp.example,Zed Z\n"
    )
    assert verify_generic(tmp_path, later) == ExitCode.OK
    assert removal_results(tmp_path) == ["removed"]  # a plain member's absence is real


def test_c02_a_cut_off_last_row_is_a_problem_and_never_a_removal(tmp_path: Path) -> None:
    assert rs.start(tmp_path, rs.ROWS) == ExitCode.OK
    assert rs.decide(tmp_path, rs.answer(tmp_path, "Remove")) == ExitCode.OK
    later = rs.write(
        tmp_path / "after.csv",
        "Full name,Email,Active,Role\nZed Z,zed@corp.example,Yes,Viewer\n"
        "Carol C,carol@corp.example",
    )
    assert rs.verify(tmp_path, later) == ExitCode.FINDINGS
    assert removal_results(tmp_path) == ["unknown", "unknown", "unknown"]
    assert any(
        "it has 2 cells but the header has 4" in r
        for r in problems(rs.report(tmp_path, "ver", "verify"))
    )


def test_c02_a_last_line_without_a_line_break_makes_the_read_not_complete(
    tmp_path: Path,
) -> None:
    # Cut off exactly after a comma: the row is the right width, but the file is not whole.
    assert rs.start(tmp_path, rs.ROWS) == ExitCode.OK
    assert rs.decide(tmp_path, rs.answer(tmp_path, "Remove")) == ExitCode.OK
    later = rs.write(
        tmp_path / "after.csv",
        "Full name,Email,Active,Role\nZed Z,zed@corp.example,Yes,Viewer\n"
        "Carol C,carol@corp.example,Yes,",
    )
    assert rs.verify(tmp_path, later) == ExitCode.FINDINGS
    assert removal_results(tmp_path) == ["unknown", "unknown", "unknown"]
    said = rs.report(tmp_path, "ver", "verify")
    assert any("does not end with a line break" in r for r in problems(said))


def test_c02_a_blank_entitlement_cell_is_still_member(tmp_path: Path) -> None:
    assert rs.start(tmp_path, "Bob B,bob@corp.example,Yes,\n") == ExitCode.OK
    assert [r.display["access"] for r in rs.load(tmp_path).rows] == ["member"]


# SHAAR-C04 ------------------------------------------------------------------------------

NFC = "josé@corp.example"
NFD = unicodedata.normalize("NFD", NFC)
FULLWIDTH = "ｊｏｓé@corp.example"


def test_c04_fold_compares_forms_and_keeps_confusables_apart() -> None:
    assert NFC != NFD
    assert keys.fold(NFC) == keys.fold(NFD) == keys.fold(FULLWIDTH)
    assert keys.fold("JOSÉ") == keys.fold(unicodedata.normalize("NFD", "josé"))
    assert keys.fold("ﬁle") == "file"  # a ligature
    assert keys.fold(chr(0x430)) != keys.fold("a")  # Cyrillic a is a different letter
    assert keys.csv("ledger", NFC) == keys.csv("ledger", NFD)
    assert keys.dn(f"CN={NFC}") == keys.dn(f"CN={NFD}")
    assert keys.grant("r", "p", "Résumé") == keys.grant(
        "r", "p", unicodedata.normalize("NFD", "Résumé")
    )


def test_c04_a_changed_unicode_form_is_not_a_removal(tmp_path: Path) -> None:
    row = "José Núñez,{},Yes,Admin\n"
    assert rs.start(tmp_path, row.format(NFC)) == ExitCode.OK
    assert rs.decide(tmp_path, rs.answer(tmp_path, "Remove")) == ExitCode.OK
    # The same person with the same access, the address written in another form.
    later = rs.write(tmp_path / "after.csv", rs.HEADER + row.format(NFD) + rs.OTHER)
    assert rs.verify(tmp_path, later) == ExitCode.FINDINGS
    results = rs.report(tmp_path, "ver", "verify")["sections"]["removals"]
    assert [r["result"] for r in results] == ["failed"]  # still present, never "removed"


def test_c04_exact_values_are_kept_in_the_packet_and_the_record(tmp_path: Path) -> None:
    assert rs.start(tmp_path, f"José Núñez,{NFD},Yes,Admin\n") == ExitCode.OK
    (built_row,) = rs.load(tmp_path).rows
    assert built_row.display["account"] == NFD
    assert built_row.display["user"] == "José Núñez"


def test_c04_one_reviewer_in_two_forms_gets_one_packet(tmp_path: Path) -> None:
    rows = "Ann A,ann@corp.example,Yes,Viewer\nBen B,ben@corp.example,Yes,Viewer\n"
    rs.write(tmp_path / "before.csv", rs.HEADER + rows)
    rs.ledger_map(tmp_path, "map.toml", rs.BEFORE_AT)
    rs.write(
        tmp_path / "rmap2.csv",
        "principal,reviewer_id,reviewer_name,reviewer_email\n"
        f"ann@corp.example,r1,Zoë Reviewer,{unicodedata.normalize('NFC', 'zoë@corp.example')}\n"
        f"ben@corp.example,r1,Zoë Reviewer,{unicodedata.normalize('NFD', 'zoë@corp.example')}\n",
    )
    code = main(
        [
            "campaign",
            str(tmp_path / "before.csv"),
            "--map",
            str(tmp_path / "map.toml"),
            "--name",
            "T",
            "--reviewers",
            "map",
            "--reviewer-map",
            str(tmp_path / "rmap2.csv"),
            "-o",
            str(tmp_path / "camp"),
        ]
    )
    assert code == ExitCode.OK
    assert len(rs.load(tmp_path).reviewers) == 1


def test_c04_an_owner_cannot_review_their_own_access_in_another_form(tmp_path: Path) -> None:
    # Ann's own address is NFD in the export and NFC in the reviewer map.
    rs.write(
        tmp_path / "before.csv",
        rs.HEADER + f"Zoë Z,{unicodedata.normalize('NFD', 'zoë@corp.example')},Yes,Viewer\n",
    )
    rs.ledger_map(tmp_path, "map.toml", rs.BEFORE_AT)
    rs.write(
        tmp_path / "rmap.csv",
        "resource,reviewer_id,reviewer_name,reviewer_email\n"
        f"Ledger,{unicodedata.normalize('NFC', 'zoë@corp.example')},Zoë Z,\n",
    )
    code = main(
        [
            "campaign",
            str(tmp_path / "before.csv"),
            "--map",
            str(tmp_path / "map.toml"),
            "--name",
            "T",
            "--reviewers",
            "map",
            "--reviewer-map",
            str(tmp_path / "rmap.csv"),
            "-o",
            str(tmp_path / "camp"),
        ]
    )
    assert code == ExitCode.FINDINGS
    (unassigned,) = rs.load(tmp_path).unassigned
    assert "cannot review their own access" in unassigned.reason


# SHAAR-C05 ------------------------------------------------------------------------------


def test_c05_force_never_deletes_the_campaign_or_its_packets(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert rs.start(tmp_path, rs.ROWS) == ExitCode.OK
    packet = rs.answer(tmp_path, "Keep")
    camp = tmp_path / "camp"
    before = {p.name: p.read_bytes() for p in camp.iterdir()}
    # Without --force the run stops and the message says what --force would do.
    assert main(["decisions", str(camp), str(packet), "-o", str(camp)]) == ExitCode.INPUT_ERROR
    assert "is, or contains, the folder of" in capsys.readouterr().err
    code = main(["decisions", str(camp), str(packet), "-o", str(camp), "--force"])
    assert code == ExitCode.INPUT_ERROR
    assert {p.name: p.read_bytes() for p in camp.iterdir()} == before
    # The campaign.json path, and the parent folder, are the same record.
    argv = ["decisions", str(camp / "campaign.json"), str(packet), "--force", "-o"]
    assert main([*argv, str(camp)]) == ExitCode.INPUT_ERROR
    assert main([*argv, str(tmp_path)]) == ExitCode.INPUT_ERROR
    assert {p.name: p.read_bytes() for p in camp.iterdir()} == before


def test_c05_verify_never_replaces_the_decision_record(tmp_path: Path) -> None:
    assert rs.start(tmp_path, rs.ROWS) == ExitCode.OK
    assert rs.decide(tmp_path, rs.answer(tmp_path, "Remove")) == ExitCode.OK
    later = rs.write(tmp_path / "after.csv", rs.HEADER + rs.OTHER)
    rs.ledger_map(tmp_path, "amap.toml", rs.AFTER_AT)
    dec = tmp_path / "dec"
    kept = {p.name: p.read_bytes() for p in dec.iterdir()}
    for out in (dec, tmp_path / "camp"):
        argv = ["verify", str(tmp_path / "camp"), str(dec), str(later), "--map"]
        argv += [str(tmp_path / "amap.toml"), "-o", str(out), "--force"]
        assert main(argv) == ExitCode.INPUT_ERROR
    assert {p.name: p.read_bytes() for p in dec.iterdir()} == kept
    assert (tmp_path / "camp" / "campaign.json").is_file()


def test_c05_another_commands_folder_is_refused_even_with_force(tmp_path: Path) -> None:
    assert rs.start(tmp_path, rs.ROWS) == ExitCode.OK
    assert rs.decide(tmp_path, rs.answer(tmp_path, "Keep")) == ExitCode.OK
    # A new campaign into the decisions folder would leave a decision record beside a
    # campaign it does not belong to.
    assert rs.start(tmp_path, rs.ROWS, out="dec") == ExitCode.INPUT_ERROR
    assert (tmp_path / "dec" / "decisions.json").is_file()


def test_c05_force_still_replaces_the_same_commands_own_output(tmp_path: Path) -> None:
    assert rs.start(tmp_path, rs.ROWS) == ExitCode.OK
    packet = rs.answer(tmp_path, "Keep")
    assert rs.decide(tmp_path, packet) == ExitCode.OK
    code = main(["decisions", str(tmp_path / "camp"), str(packet), "-o", str(tmp_path / "dec")])
    assert code == ExitCode.INPUT_ERROR  # exists, no --force
    argv = ["decisions", str(tmp_path / "camp"), str(packet), "-o", str(tmp_path / "dec")]
    assert main([*argv, "--force"]) == ExitCode.OK


# Shared: printing never changes the exit code -------------------------------------------


class ClosedPipe:
    """A stdout whose reader has gone away: every write and flush fails."""

    encoding = "utf-8"

    def write(self, _text: str) -> int:
        raise BrokenPipeError(32, "Broken pipe")

    def flush(self) -> None:
        raise BrokenPipeError(32, "Broken pipe")


@contextlib.contextmanager
def closed_stdout() -> Iterator[ClosedPipe]:
    """Replace stdout with one whose reader has gone away; close what shaar puts in its place."""
    keep = sys.stdout
    pipe = ClosedPipe()
    sys.stdout = pipe
    try:
        yield pipe
    finally:
        silenced, sys.stdout = sys.stdout, keep
        if silenced is not pipe:
            assert isinstance(silenced, io.TextIOWrapper)  # pointed at the null device
            silenced.close()


def test_a_closed_pipe_keeps_the_decided_exit_code_and_complete_files(tmp_path: Path) -> None:
    with closed_stdout() as pipe:
        code = rs.start(tmp_path, rs.ROWS + "Dave D,dave@corp.example,Yes,Admin,EXTRA,CELLS\n")
        assert sys.stdout is not pipe  # replaced: nothing more is printed
    assert code == ExitCode.FINDINGS  # the input problem, not exit 4
    names = {p.name for p in (tmp_path / "camp").iterdir()}
    assert {"campaign.json", "manifest.json", "campaign-report.json"} <= names
    manifest = json.loads((tmp_path / "camp" / "manifest.json").read_text("utf-8"))
    for entry in manifest["files"]:
        data = (tmp_path / "camp" / entry["name"]).read_bytes()
        assert hashlib.sha256(data).hexdigest() == entry["sha256"]


def test_a_closed_pipe_after_the_run_is_still_the_runs_exit_code(tmp_path: Path) -> None:
    assert rs.start(tmp_path, rs.ROWS) == ExitCode.OK
    packet = rs.answer(tmp_path, "Unsure")
    with closed_stdout():
        code = rs.decide(tmp_path, packet)
    assert code == ExitCode.FINDINGS
    assert (tmp_path / "dec" / "decisions.json").is_file()


def run_shaar(*args: str, cwd: Path, encoding: str) -> subprocess.CompletedProcess[bytes]:
    env = {**os.environ, "PYTHONIOENCODING": encoding, "PYTHONPATH": str(SRC)}
    return subprocess.run(  # noqa: S603 - the interpreter running these tests, with fixed arguments
        [sys.executable, "-I", "-m", "faithful_shaar", *args],
        cwd=cwd,
        env=env,
        capture_output=True,
        check=False,
        timeout=120,
    )


def test_ascii_only_output_with_a_non_ascii_path_keeps_the_exit_code(tmp_path: Path) -> None:
    home = tmp_path / "revisión-ñ"
    rs.write(home / "before.csv", rs.HEADER + rs.ROWS + "Dave D,dave@corp.example,Yes,Admin,X,Y\n")
    rs.ledger_map(home, "map.toml", rs.BEFORE_AT)
    rs.write(home / "rmap.csv", rs.REVIEWERS)
    done = run_shaar(
        "campaign", "before.csv", "--map", "map.toml", "--name", "T", "--reviewers", "map",
        "--reviewer-map", "rmap.csv", "-o", "résultat",
        cwd=home, encoding="ascii",
    )  # fmt: skip
    assert done.returncode == ExitCode.FINDINGS, done.stderr
    assert b"internal error" not in done.stderr
    assert "Campaign written to r\\xc3\\xa9sultat".encode("ascii")[:20] in done.stdout or (
        b"r\\xe9sultat" in done.stdout
    )
    assert (home / "résultat" / "campaign.json").is_file()
    assert (home / "résultat" / "manifest.json").is_file()


def test_a_pipe_closed_by_the_reader_is_not_an_internal_error(tmp_path: Path) -> None:
    home = tmp_path / "w"
    rs.write(home / "before.csv", rs.HEADER + rs.ROWS)
    rs.ledger_map(home, "map.toml", rs.BEFORE_AT)
    rs.write(home / "rmap.csv", rs.REVIEWERS)
    env = {**os.environ, "PYTHONPATH": str(SRC)}
    args = ["campaign", "before.csv", "--map", "map.toml", "--name", "T", "--reviewers", "map"]
    args += ["--reviewer-map", "rmap.csv", "-o", "out"]
    with subprocess.Popen(  # noqa: S603 - the interpreter running these tests, with fixed arguments
        [sys.executable, "-I", "-m", "faithful_shaar", *args],
        cwd=home,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ) as child:
        assert child.stdout is not None
        child.stdout.close()  # the reader goes away before the summary is printed
        error = child.stderr.read() if child.stderr else b""
        code = child.wait(timeout=120)
    assert code == ExitCode.OK, error
    assert b"internal error" not in error
    assert (home / "out" / "manifest.json").is_file()


# Shared: error messages name the path the person typed ----------------------------------


def test_an_unreadable_input_is_named_by_its_full_path(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    missing = tmp_path / "no" / "such" / "dir" / "a.jsonl"
    rs.write(tmp_path / "rmap.csv", rs.REVIEWERS)
    code = main(
        ["campaign", str(missing), "--name", "T", "--reviewers", "map",
         "--reviewer-map", str(tmp_path / "rmap.csv"), "-o", str(tmp_path / "o")]
    )  # fmt: skip
    assert code == ExitCode.INPUT_ERROR
    assert f"cannot read {missing}: No such file or directory" in capsys.readouterr().err


def test_a_content_error_names_the_full_path_too(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = rs.write(tmp_path / "deep" / "x.csv", rs.HEADER + rs.ROWS)
    rs.write(tmp_path / "rmap.csv", rs.REVIEWERS)
    rs.ledger_map(tmp_path, "map.toml", rs.BEFORE_AT, columns='principal_id = "Missing"\n')
    code = main(
        ["campaign", str(path), "--map", str(tmp_path / "map.toml"), "--name", "T",
         "--reviewers", "map", "--reviewer-map", str(tmp_path / "rmap.csv"),
         "-o", str(tmp_path / "o")]
    )  # fmt: skip
    assert code == ExitCode.INPUT_ERROR
    assert f"{path} has no column 'Missing'" in capsys.readouterr().err
