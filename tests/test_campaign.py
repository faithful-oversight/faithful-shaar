# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""Building, saving and loading a campaign."""

from __future__ import annotations

import json

import pytest

from faithful_shaar import campaign as cmod
from faithful_shaar.campaign import build, display_for, dump, load, row_check
from faithful_shaar.errors import InputError
from faithful_shaar.model import Principal
from tests.core_fixtures import CREATED, grant, reviewer_key, sid, snapshot, standard


def test_rows_are_assigned_ordered_and_digested() -> None:
    _, camp = standard("manager")
    assert camp.id.startswith("C") and len(camp.id) == 17  # noqa: PT018
    assert [r.name for r in camp.reviewers] == ["Morgan Lead"]
    rows = camp.rows_for(reviewer_key(1101))
    assert [(r.display["resource"], r.display["user"]) for r in rows] == [
        ("Finance Admins", "Avery Example"),
        ("Finance Admins", "Blake Sample"),
        ("Payroll Viewers", "Blake Sample"),
        ("Server Ops", "Avery Example"),
    ]
    assert all(r.row_check == row_check(camp.id, r.row_id, r.grant_key, r.display) for r in rows)
    assert camp.reviewers[0].packet_digest == cmod.packet_digest(
        camp.reviewers[0].key, [r.row_check for r in rows]
    )
    assert camp.reviewers[0].packet.startswith("packet-01-Morgan-Lead-")
    assert {u.reason for u in camp.unassigned} == {"the input names no manager for this principal"}
    assert len(camp.unassigned) == 2


def test_what_reviewers_see() -> None:
    snap, camp = standard("manager")
    row = camp.rows_for(reviewer_key(1101))[1]
    assert row.display == {
        "user": "Blake Sample",
        "account": "blake.sample@corp.example",
        "status": "Disabled",
        "last_sign_in": "2026-10-30T08:00:00Z",
        "resource": "Finance Admins",
        "resource_kind": "group",
        "access": "member",
        "via": "Direct",
        "co_owners": "",
    }
    nested = next(r for r in camp.rows if r.display["via"] != "Direct")
    assert nested.display["via"] == "Server Ops > Ops Helpers"
    service = display_for(grant(1105, 2002), snap)
    assert service["user"] == "svc-backup (service)"
    assert service["status"] == "Unknown"
    assert service["account"] == "S-1-5-21-1000-1000-1000-1105"
    ghost = display_for(grant(1999, 2999), snap)
    assert ghost["user"] == sid(1999)
    assert ghost["resource"] == sid(2999)
    assert ghost["resource_kind"] == ""


def test_owner_rule_shows_co_owners() -> None:
    _, camp = standard("owner")
    assert [r.name for r in camp.reviewers] == ["Casey Owner", "Morgan Lead"]
    payroll = next(r for r in camp.rows if r.display["resource"] == "Payroll Viewers")
    assert (payroll.reviewer_key, payroll.display["co_owners"]) == (
        reviewer_key(1104),
        "Morgan Lead",
    )
    server = [r for r in camp.rows if r.display["resource"] == "Server Ops"]
    assert {(r.reviewer_key, r.display["co_owners"]) for r in server} == {(reviewer_key(1101), "")}
    assert [u.reason for u in camp.unassigned] == [
        "the only owner is the principal, who cannot review their own access"
    ]


def test_same_inputs_give_the_same_campaign() -> None:
    assert dump(standard()[1]) == dump(standard()[1])
    snap, _ = standard()
    other = build(snap, name="Other", created_at=CREATED, due="", rule="manager")
    assert other.id != standard()[1].id


def test_save_and_load_round_trip() -> None:
    _, camp = standard("owner")
    again = load(dump(camp))
    assert again == camp
    assert dump(again) == dump(camp)


def test_a_changed_campaign_is_refused() -> None:
    _, camp = standard()
    data = json.loads(dump(camp))
    data["rows"][0]["display"]["access"] = "owner"
    with pytest.raises(InputError, match="changed after shaar wrote it"):
        load(json.dumps(data).encode())


@pytest.mark.parametrize(
    ("raw", "match"),
    [
        (b"\xff", "not JSON"),
        (b"[]", "not a shaar campaign"),
        (b'{"shaar_campaign": 2}', "not a shaar campaign"),
        (b'{"shaar_campaign": 1}', "missing or has the wrong type"),
    ],
)
def test_bad_campaign_files(raw: bytes, match: str) -> None:
    with pytest.raises(InputError, match=match):
        load(raw)


def test_campaign_record_of_the_wrong_shape(monkeypatch: pytest.MonkeyPatch) -> None:
    data = json.loads(dump(standard()[1]))
    data["rows"][0]["surprise"] = 1
    with pytest.raises(InputError, match="wrong shape"):
        load(json.dumps(data).encode())
    monkeypatch.setattr(cmod, "MAX_CAMPAIGN_BYTES", 10)
    with pytest.raises(InputError, match="larger than"):
        load(dump(standard()[1]))


def test_a_principal_with_no_name_shows_its_id() -> None:
    snap = snapshot(
        [Principal(sid(1110), "ad", "S-1-5-21-1000-1000-1000-1110", "", "user")], [], []
    )
    assert display_for(grant(1110, 2001), snap)["user"] == "S-1-5-21-1000-1000-1000-1110"


def test_the_campaign_keeps_the_text_a_packet_cell_holds() -> None:
    long_name = "Avery\x07Example " + "x" * 40000
    snap = snapshot(
        [Principal(sid(1110), "ad", "S-1-5-21-1000-1000-1000-1110", long_name, "user")], [], []
    )
    shown = display_for(grant(1110, 2001), snap)["user"]
    assert "\x07" not in shown
    assert "\\u0007" in shown  # shown as a visible escape, as in every report
    assert shown.endswith("[truncated]")
    assert len(shown) <= 32767
