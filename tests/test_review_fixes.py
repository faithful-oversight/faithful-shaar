# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""Regression tests for the findings of the 2026-11-14 review (SHAAR-C01 to C13).

Each test names the finding it guards. They run the command line on small synthetic reviews,
because the findings were all gaps between stages that unit tests of one stage cannot see.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from faithful_shaar.cli import ExitCode, main
from tests import review_support as rs

if TYPE_CHECKING:
    from pathlib import Path

    import pytest


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
