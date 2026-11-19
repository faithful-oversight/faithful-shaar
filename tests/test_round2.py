# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""Regression tests for the round 2 review findings (SH-R1, SH-R2) and the output collision class.

Like ``test_review_fixes``, they run the command line on small synthetic reviews, because the
findings were gaps between stages that unit tests of one stage cannot see.
"""

from __future__ import annotations

import io
from typing import TYPE_CHECKING

import pytest

from faithful_shaar import keys
from faithful_shaar.cli import ExitCode
from faithful_shaar.inputs import csvmap, csvread
from tests import review_support as rs
from tests.test_review_fixes import ALICE_BOB, problems, removal_results

if TYPE_CHECKING:
    from pathlib import Path

# A later map that only says who the person is: no entitlement field at all.
IDENTITY_ONLY = 'principal_id = "Email"\nemail = "Email"\nprincipal_name = "Full name"\n'


# SH-R1 ---------------------------------------------------------------------------------------


def test_r1_a_custom_map_with_no_entitlement_field_cannot_show_a_removal(tmp_path: Path) -> None:
    assert rs.start(tmp_path, ALICE_BOB) == ExitCode.OK
    assert rs.decide(tmp_path, rs.answer(tmp_path, "Remove")) == ExitCode.OK
    # Alice still has an account; the later export cannot say whether Admin was removed.
    later = rs.write(
        tmp_path / "after.csv",
        "Full name,Email\nAlice A,alice@corp.example\nBob B,bob@corp.example\n",
    )
    assert rs.verify(tmp_path, later, columns=IDENTITY_ONLY) == ExitCode.FINDINGS
    assert removal_results(tmp_path) == ["unknown", "unknown"]
    said = rs.report(tmp_path, "ver", "verify")
    assert all("no entitlement column" in r["reason"] for r in said["sections"]["removals"])
    assert said["headline"].startswith("0 of 2 removals verified")


@pytest.mark.parametrize(
    ("map_text", "header"),
    [
        pytest.param(
            'system = "ledger"\nresource = "Ledger"\n[columns]\n'
            'principal_id = "id"\nprincipal_name = "name"\n',
            "id,name",
            id="custom-map-names-no-entitlement",
        ),
        pytest.param(
            'preset = "generic"\nsystem = "ledger"\nresource = "Ledger"\n',
            "principal_id,principal_name",
            id="generic-preset-column-absent",
        ),
        pytest.param(
            'preset = "ad-users-groups"\nresource = "Ledger"\n',
            "SID,Name",
            id="preset-without-an-entitlement-field",
        ),
    ],
)
def test_r1_an_export_with_no_entitlement_column_read_is_entitlement_blind(
    tmp_path: Path, map_text: str, header: str
) -> None:
    path = tmp_path / "m.toml"
    path.write_text(map_text, "utf-8")
    cmap = csvmap.load_map(path, None, None)
    assert cmap is not None
    data = f"{header}\nS-1-5-21-1-2-3-1001,Alice A\n".encode()
    snapshot, _ = csvread.read_csv(io.BytesIO(data), "later.csv", cmap)
    assert snapshot.resources  # something was read, so the blindness is not vacuous
    assert snapshot.entitlement_blind == {r.system for r in snapshot.resources.values()}


def test_r1_a_file_that_has_the_entitlement_column_is_not_blind(tmp_path: Path) -> None:
    path = tmp_path / "m.toml"
    path.write_text(
        'system = "ledger"\nresource = "Ledger"\n[columns]\n'
        'principal_id = "id"\nentitlement = "role"\n',
        "utf-8",
    )
    cmap = csvmap.load_map(path, None, None)
    assert cmap is not None
    snapshot, _ = csvread.read_csv(io.BytesIO(b"id,role\na,Admin\n"), "later.csv", cmap)
    assert snapshot.entitlement_blind == set()


def test_r1_a_member_removal_is_still_verified_by_a_custom_map_without_entitlements(
    tmp_path: Path,
) -> None:
    assert rs.start(tmp_path, "Bob B,bob@corp.example,Yes,\n") == ExitCode.OK  # blank = member
    assert rs.decide(tmp_path, rs.answer(tmp_path, "Remove")) == ExitCode.OK
    later = rs.write(tmp_path / "after.csv", "Full name,Email\nZed Z,zed@corp.example\n")
    assert rs.verify(tmp_path, later, columns=IDENTITY_ONLY) == ExitCode.OK
    assert removal_results(tmp_path) == ["removed"]  # a plain member's absence is real
    assert problems(rs.report(tmp_path, "ver", "verify")) == []


# SH-R2 ---------------------------------------------------------------------------------------

# An export whose person is keyed by an id that can change between exports.
BY_ID_HEADER = "ID,Name,Email,Role\n"
BY_ID = 'principal_id = "ID"\nemail = "Email"\nprincipal_name = "Name"\nentitlement = "Role"\n'


def review_with_id_change(root: Path, account: str, later_account: str | None = None) -> None:
    """Campaign and Remove decision for ``account``; later export keeps it under a new key."""
    assert rs.start(
        root, f"S-1001,Avery A,{account},Admin\n", header=BY_ID_HEADER, columns=BY_ID
    ) == (ExitCode.OK)
    assert rs.decide(root, rs.answer(root, "Remove")) == ExitCode.OK
    rs.write(
        root / "after.csv",
        BY_ID_HEADER + f"CN=avery-new,Avery A,{later_account or account},Admin\n",
    )


@pytest.mark.parametrize(
    "account",
    [
        pytest.param("avery​@corp.example", id="zero-width-space"),
        pytest.param("avery‮@corp.example", id="right-to-left-override"),
        pytest.param("avery@corp.example ", id="no-break-space-at-the-end"),
        pytest.param("　avery@corp.example", id="ideographic-space-at-the-start"),
        pytest.param("avery\x01@corp.example", id="a-control-character"),
        pytest.param("a" * 40_000 + "@corp.example", id="longer-than-a-cell-holds"),
    ],
)
def test_r2_the_same_account_under_a_changed_key_is_never_a_verified_removal(
    tmp_path: Path, account: str
) -> None:
    review_with_id_change(tmp_path, account)
    later = tmp_path / "after.csv"
    assert rs.verify(tmp_path, later, columns=BY_ID) == ExitCode.FINDINGS
    assert removal_results(tmp_path) == ["unknown"]
    said = rs.report(tmp_path, "ver", "verify")
    assert "the same account still holds this access under another key" in str(
        said["sections"]["removals"][0]["reason"]
    )


def test_r2_literal_escape_text_is_not_the_character_it_spells(tmp_path: Path) -> None:
    """``avery\\u200b@...`` typed out is a different account from one holding U+200B."""
    review_with_id_change(tmp_path, "avery​@corp.example", later_account="avery\\u200b@corp.example")
    assert rs.verify(tmp_path, tmp_path / "after.csv", columns=BY_ID) == ExitCode.OK
    assert removal_results(tmp_path) == ["removed"]


def test_r2_a_plain_account_under_a_changed_key_is_still_caught(tmp_path: Path) -> None:
    review_with_id_change(tmp_path, "avery@corp.example")
    assert rs.verify(tmp_path, tmp_path / "after.csv", columns=BY_ID) == ExitCode.FINDINGS
    assert removal_results(tmp_path) == ["unknown"]


def test_r2_the_packet_and_campaign_still_show_the_escaped_account(tmp_path: Path) -> None:
    review_with_id_change(tmp_path, "avery​@corp.example")
    (row,) = rs.load(tmp_path).rows
    assert row.display["account"] == "avery\\u200b@corp.example"  # the visible escape stays
    # The identity comes from the raw text, so it is not the identity of the escape text.
    assert row.account_identity == keys.identity("avery\u200b@corp.example")
    assert row.account_identity != keys.identity("avery\\u200b@corp.example")
