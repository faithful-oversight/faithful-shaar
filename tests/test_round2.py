# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""Regression tests for the round 2 review findings (SH-R1, SH-R2) and the output collision class.

Like ``test_review_fixes``, they run the command line on small synthetic reviews, because the
findings were gaps between stages that unit tests of one stage cannot see.
"""

from __future__ import annotations

import argparse
import io
import json
import os
import sys
from pathlib import Path

import pytest
from faithful_core.exitcodes import ExitCode

from faithful_shaar import keys
from faithful_shaar.cli import main
from faithful_shaar.inputs import csvmap, csvread
from tests import review_support as rs
from tests.test_review_fixes import ALICE_BOB, problems, removal_results

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
        pytest.param("avery\u200b@corp.example", id="zero-width-space"),
        pytest.param("avery\u202e@corp.example", id="right-to-left-override"),
        pytest.param("avery@corp.example\u00a0", id="no-break-space-at-the-end"),
        pytest.param("\u3000avery@corp.example", id="ideographic-space-at-the-start"),
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
    r"""``avery\u200b@...`` typed out is a different account from one holding U+200B."""
    review_with_id_change(
        tmp_path, "avery\u200b@corp.example", later_account="avery\\u200b@corp.example"
    )
    assert rs.verify(tmp_path, tmp_path / "after.csv", columns=BY_ID) == ExitCode.OK
    assert removal_results(tmp_path) == ["removed"]


def test_r2_a_plain_account_under_a_changed_key_is_still_caught(tmp_path: Path) -> None:
    review_with_id_change(tmp_path, "avery@corp.example")
    assert rs.verify(tmp_path, tmp_path / "after.csv", columns=BY_ID) == ExitCode.FINDINGS
    assert removal_results(tmp_path) == ["unknown"]


def test_r2_the_packet_and_campaign_still_show_the_escaped_account(tmp_path: Path) -> None:
    review_with_id_change(tmp_path, "avery\u200b@corp.example")
    (row,) = rs.load(tmp_path).rows
    assert row.display["account"] == "avery\\u200b@corp.example"  # the visible escape stays
    # The identity comes from the raw text, so it is not the identity of the escape text.
    assert row.account_identity == keys.identity("avery\u200b@corp.example")
    assert row.account_identity != keys.identity("avery\\u200b@corp.example")


# The input/output collision class (PAK-1 / MER-1) -------------------------------------------

needs_links = pytest.mark.skipif(
    sys.platform == "win32", reason="creating a link needs a privilege on Windows"
)


def campaign_command(root: Path, access: Path, out: Path, *extra: str) -> list[str]:
    rs.ledger_map(root, "map.toml", rs.BEFORE_AT)
    rs.write(root / "rmap.csv", rs.REVIEWERS)
    return [
        *["campaign", str(access), "--map", str(root / "map.toml"), "--name", "T"],
        *["--reviewers", "map", "--reviewer-map", str(root / "rmap.csv")],
        *["--due", rs.DUE, "-o", str(out), *extra],
    ]


def tree(folder: Path) -> dict[str, bytes]:
    return {p.name: p.read_bytes() for p in sorted(folder.iterdir()) if p.is_file()}


def test_force_never_replaces_an_access_export_with_a_report(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    out = tmp_path / "out"
    access = rs.write(out / "rows.csv", rs.HEADER + rs.ROWS)  # a name the campaign writes
    before = tree(out)
    assert main(campaign_command(tmp_path, access, out, "--force")) == ExitCode.INPUT_ERROR
    assert "is the same file as the input file" in capsys.readouterr().err
    assert tree(out) == before  # not replaced, and nothing else written


@pytest.mark.parametrize("which", ["map", "reviewer-map"])
def test_force_never_replaces_a_map_with_a_report(
    which: str, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    out = tmp_path / "out"
    access = rs.write(tmp_path / "before.csv", rs.HEADER + rs.ROWS)
    argv = campaign_command(tmp_path, access, out, "--force")
    # Put the map where the campaign writes its manifest, and point the command at it.
    held = out / "manifest.json" if which == "map" else out / "rows.csv"
    source = Path(argv[argv.index("--map" if which == "map" else "--reviewer-map") + 1])
    held.parent.mkdir(parents=True)
    held.write_bytes(source.read_bytes())
    argv[argv.index("--map" if which == "map" else "--reviewer-map") + 1] = str(held)
    assert main(argv) == ExitCode.INPUT_ERROR
    assert "is the same file as the input file" in capsys.readouterr().err
    assert held.read_bytes() == source.read_bytes()
    assert sorted(tree(out)) == [held.name]


def test_force_never_removes_an_input_an_earlier_run_listed(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """``--force`` takes away files an earlier manifest lists; one of them may be an input now."""
    assert rs.start(tmp_path, rs.ROWS) == ExitCode.OK
    out = tmp_path / "camp"
    stale = out / "unassigned.csv"
    stale.write_text(rs.HEADER + rs.ROWS, encoding="utf-8")  # an old output, used as an input
    manifest = json.loads((out / "manifest.json").read_text("utf-8"))
    manifest["files"].append({"name": "unassigned.csv", "size": 1, "sha256": "0" * 64})
    (out / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    kept = stale.read_bytes()
    capsys.readouterr()
    argv = campaign_command(tmp_path, stale, out, "--force")
    assert main(argv) == ExitCode.INPUT_ERROR
    assert "is the same file as the input file" in capsys.readouterr().err
    assert stale.read_bytes() == kept


@needs_links
def test_a_link_to_an_input_is_refused_in_every_position(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    access = rs.write(tmp_path / "before.csv", rs.HEADER + rs.ROWS)
    original = access.read_bytes()
    linked, hard, via_folder = tmp_path / "linked", tmp_path / "hard", tmp_path / "via"
    linked.mkdir()
    hard.mkdir()
    (linked / "rows.csv").symlink_to(access)
    os.link(access, hard / "rows.csv")
    via_folder.symlink_to(tmp_path, target_is_directory=True)
    for out in (linked, hard):
        assert main(campaign_command(tmp_path, access, out, "--force")) == ExitCode.INPUT_ERROR
    # The access file lives in the folder the output folder is a link to.
    rows = rs.write(tmp_path / "rows.csv", rs.HEADER + rs.ROWS)
    assert main(campaign_command(tmp_path, rows, via_folder, "--force")) == ExitCode.INPUT_ERROR
    assert "is the same file as the input file" in capsys.readouterr().err
    assert access.read_bytes() == original


def test_force_never_replaces_a_returned_packet_or_a_later_export(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert rs.start(tmp_path, rs.ROWS) == ExitCode.OK
    packet = rs.answer(tmp_path, "Remove")
    held = tmp_path / "dec-x" / "decisions-report.md"  # a name the decisions command writes
    held.parent.mkdir()
    held.write_bytes(packet.read_bytes())
    before = held.read_bytes()
    assert main(
        ["decisions", str(tmp_path / "camp"), str(held), "-o", str(held.parent), "--force"]
    ) == (ExitCode.INPUT_ERROR)
    assert held.read_bytes() == before
    # verify: the later export named like the report it would write.
    assert rs.decide(tmp_path, packet) == ExitCode.OK
    later = rs.write(tmp_path / "ver" / "verify-report.json", rs.HEADER + rs.OTHER)
    kept = later.read_bytes()
    capsys.readouterr()
    assert rs.verify(tmp_path, later, to="ver") == ExitCode.INPUT_ERROR
    assert "is the same file as the input file" in capsys.readouterr().err
    assert later.read_bytes() == kept


@pytest.mark.parametrize(
    "used", ["ca", "secret", "certificate", "client-secret", "certificate-password"]
)
def test_a_collection_never_replaces_a_file_it_was_told_to_use(used: str, tmp_path: Path) -> None:
    from faithful_shaar.collect import ad, entra  # noqa: PLC0415
    from faithful_shaar.errors import OutputError  # noqa: PLC0415

    file = tmp_path / "input.txt"
    file.write_bytes(b"line one\nline two\n")
    original = file.read_bytes()
    outputs = [file]
    if sys.platform != "win32":
        (tmp_path / "alias.txt").symlink_to(file)
        outputs.append(tmp_path / "alias.txt")
    for out in outputs:
        if used in {"certificate", "client-secret", "certificate-password"}:
            read = {
                "certificate": ["--certificate", str(file)],
                "client-secret": ["--client-secret", f"file:{file}"],
                "certificate-password": [
                    *["--certificate", str(tmp_path / "cert.pem")],
                    *["--certificate-password", f"file:{file}"],
                ],
            }[used]
            (tmp_path / "cert.pem").write_bytes(b"x")
            parser = argparse.ArgumentParser()
            sub = parser.add_subparsers(dest="c").add_parser("collect").add_subparsers(dest="s")
            entra.add_collect_entra_arguments(sub)
            args = parser.parse_args(
                [
                    *["collect", "entra", "--tenant", "contoso.example"],
                    *["--client-id", "00000000-0000-4000-8000-000000000001"],
                    *[*read, "--group", "g", "-o", str(out), "--force"],
                ]
            )
            assert entra.run_collect_entra(args) == ExitCode.INPUT_ERROR
        else:
            parser = argparse.ArgumentParser()
            sub = parser.add_subparsers(dest="c").add_parser("collect").add_subparsers(dest="s")
            ad.add_collect_ad_arguments(sub)
            role = "CA file" if used == "ca" else "secret file"
            use = (
                ["--ca-file", str(file)]
                if used == "ca"
                else ["--username", "CORP\\auditor", "--secret", f"file:{file}"]
            )
            args = parser.parse_args(
                [
                    *["collect", "ad", "--host", "dc01.corp.example", "--privileged"],
                    *["-o", str(out), *use, "--force"],
                ]
            )
            with pytest.raises(OutputError, match=f"is the same file as the {role}"):
                ad.run_collect_ad(args)
        assert file.read_bytes() == original
