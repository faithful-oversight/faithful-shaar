# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""Reading returned packets: only trustworthy decisions are accepted."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

import pytest

from faithful_shaar import decide as dmod
from faithful_shaar.decide import DecisionRecord, dump, load, read_decisions
from faithful_shaar.errors import InputError
from tests.core_fixtures import FakePacket, FakeRow, reader, returned, reviewer_key, standard

if TYPE_CHECKING:
    from faithful_shaar.campaign import Campaign

NOW = "2026-11-12T00:00:00Z"
ALL = {"Avery Example": "Remove", "Blake Sample": "keep"}


def run(camp: Campaign, packets: dict[str, FakePacket], **kw: Any) -> DecisionRecord:
    files = [(name, name.encode()) for name in packets] + [(n, b"x") for n in kw.pop("extra", [])]
    return read_decisions(camp, files, read=reader(packets), created_at=NOW, **kw)


def states(record: DecisionRecord) -> list[tuple[str, str]]:
    return [(r.state, r.decision) for r in record.rows]


def test_a_complete_packet_is_accepted() -> None:
    _, camp = standard()
    record = run(camp, {"morgan.xlsx": returned(camp, 1101, ALL)})
    assert states(record)[:4] == [
        ("accepted", "Remove"),
        ("accepted", "Keep"),
        ("accepted", "Keep"),
        ("accepted", "Remove"),
    ]
    assert [r.state for r in record.rows[4:]] == ["unassigned", "unassigned"]
    packet = record.packets[0]
    assert (packet.status, packet.reviewer, packet.reported_by) == (
        "read",
        "Morgan Lead",
        "Morgan Lead",
    )
    assert record.rows[0].citation == "morgan.xlsx, Review row 2"


def test_complete_when_every_row_is_decided() -> None:
    _, camp = standard("owner", morgan=False)
    keep = {"Avery Example": "Keep", "Blake Sample": "Remove", "svc-backup (service)": "Keep"}
    packets = {"casey.xlsx": returned(camp, 1104, keep)}
    record = run(camp, packets)
    morgan_rows = [r for r in record.rows if r.reviewer_key == reviewer_key(1101)]
    assert {r.reason for r in morgan_rows} == {"the packet was not returned"}
    assert not record.complete
    packets["morgan.xlsx"] = returned(camp, 1101, keep)
    assert run(camp, packets).complete


def test_blank_invalid_and_comment_rules() -> None:
    _, camp = standard()
    typed = {
        "Avery Example|Finance Admins": "remove please",
        "Blake Sample|Finance Admins": "Remove",
    }
    record = run(camp, {"m.xlsx": returned(camp, 1101, typed)}, require_comment=["Remove"])
    assert [r.state for r in record.rows[:4]] == ["invalid", "invalid", "undecided", "undecided"]
    assert "is not Keep, Remove or Unsure" in record.rows[0].reason
    assert record.rows[1].reason == "Remove needs a comment in this campaign"
    assert record.rows[2].reason == "no decision"
    assert record.require_comment == ["Remove"]


def test_a_formula_cell_is_not_accepted() -> None:
    _, camp = standard()
    packet = returned(camp, 1101, ALL)
    packet.rows[0].notes.append("Decision held a formula")
    record = run(camp, {"m.xlsx": packet})
    assert record.rows[0].state == "invalid"
    assert record.rows[0].reason == "Decision held a formula"


def test_an_edited_row_is_altered_not_accepted() -> None:
    _, camp = standard()
    packet = returned(camp, 1101, ALL)
    packet.rows[0].values["Access to"] = "Payroll Admins"
    packet.rows[1].values["Row check"] = "0" * 64
    record = run(camp, {"m.xlsx": packet})
    assert record.rows[0].state == "altered"
    assert record.rows[0].reason == "changed after it was sent: Access to"
    assert record.rows[1].reason == "changed after it was sent: its hidden row check"


def test_missing_and_stray_rows() -> None:
    _, camp = standard("owner")
    casey = returned(camp, 1104, {"Avery Example": "Keep"})
    del casey.rows[0]
    casey.rows.append(FakeRow(90, {"Row ID": "RFOREIGN"}))
    casey.rows.append(FakeRow(91, {"Row ID": "", "Decision": " "}))  # an empty line
    morgan_row = returned(camp, 1101).rows[0]
    casey.rows.append(FakeRow(92, morgan_row.values))
    record = run(camp, {"casey.xlsx": casey})
    first = next(r for r in record.rows if r.row_id == camp.rows_for(reviewer_key(1104))[0].row_id)
    assert (first.state, first.reason) == ("undecided", "missing from the returned packet")
    assert first.citation == ""
    assert [(s.row_id, s.reason) for s in record.strays] == [
        ("RFOREIGN", "the row is not part of this campaign"),
        (morgan_row.values["Row ID"], "the row belongs to another reviewer's packet"),
    ]


def test_copies_of_a_row_must_agree() -> None:
    _, camp = standard()
    same = run(camp, {"a.xlsx": returned(camp, 1101, ALL), "b.xlsx": returned(camp, 1101, ALL)})
    assert same.rows[0].state == "accepted"
    other = dict(ALL, **{"Avery Example": "Keep"})
    differ = run(camp, {"a.xlsx": returned(camp, 1101, ALL), "b.xlsx": returned(camp, 1101, other)})
    assert differ.rows[0].state == "conflict"
    assert differ.rows[0].reason == "copies of this row disagree (Keep, Remove)"
    assert differ.rows[0].citation == "a.xlsx, Review row 2; b.xlsx, Review row 2"
    bad = dict(ALL, **{"Avery Example": "maybe"})
    half = run(camp, {"a.xlsx": returned(camp, 1101, ALL), "b.xlsx": returned(camp, 1101, bad)})
    assert (half.rows[0].state, half.rows[0].reason) == (
        "conflict",
        "another copy of this row is not valid (a copy says Remove)",
    )
    assert half.rows[0].decision == ""  # SHAAR-C12: nothing accepted, nothing to act on


def test_comments_from_agreeing_copies_are_kept() -> None:
    _, camp = standard()
    a, b = returned(camp, 1101, ALL), returned(camp, 1101, ALL)
    a.rows[0].values["Comment"] = "left the team"
    b.rows[0].values["Comment"] = "moved to sales"
    record = run(camp, {"a.xlsx": a, "b.xlsx": b})
    assert record.rows[0].comment == "left the team | moved to sales"


def test_packets_that_are_rejected_or_unreadable() -> None:
    _, camp = standard()
    foreign = returned(camp, 1101, ALL)
    foreign.about["Campaign ID"] = "C0000000000000000"
    unknown = returned(camp, 1101, ALL)
    unknown.about["Packet digest"] = "f" * 64
    record = run(camp, {"foreign.xlsx": foreign, "unknown.xlsx": unknown}, extra=["broken.xlsx"])
    assert [(p.file, p.status) for p in record.packets] == [
        ("foreign.xlsx", "rejected"),
        ("unknown.xlsx", "rejected"),
        ("broken.xlsx", "unreadable"),
    ]
    assert "belongs to campaign C0000000000000000" in record.packets[0].reason
    assert "matches no reviewer" in record.packets[1].reason
    assert record.packets[2].reason == "broken.xlsx is not a workbook"
    assert record.rows[0].reason == "the packet could not be read"
    empty = returned(camp, 1101, ALL)
    empty.about = {}
    assert "campaign (none)" in run(camp, {"e.xlsx": empty}).packets[0].reason


def test_about_labels_are_matched_loosely() -> None:
    _, camp = standard()
    packet = returned(camp, 1101, ALL)
    packet.about = {"campaign id:": camp.id, "PACKET_DIGEST": camp.reviewers[0].packet_digest}
    assert run(camp, {"m.xlsx": packet}).packets[0].status == "read"


def test_record_round_trip_and_tamper_check(monkeypatch: pytest.MonkeyPatch) -> None:
    _, camp = standard()
    record = run(camp, {"m.xlsx": returned(camp, 1101, ALL)})
    assert load(dump(record)) == record
    data = json.loads(dump(record))
    data["rows"][1]["decision"] = "Remove"
    with pytest.raises(InputError, match="changed after shaar wrote it"):
        load(json.dumps(data).encode())
    data["rows"][1]["surprise"] = True
    with pytest.raises(InputError, match="wrong shape"):
        load(json.dumps(data).encode())
    for raw in (b"\xff", b"{}", b"[1]"):
        with pytest.raises(InputError):
            load(raw)
    monkeypatch.setattr(dmod, "MAX_DECISIONS_BYTES", 5)
    with pytest.raises(InputError, match="larger than"):
        load(dump(record))


def test_a_packet_from_a_differently_assigned_campaign_is_not_accepted() -> None:
    # Same name, time and inputs, but the reviewers come from a different rule.
    _, by_manager = standard("manager")
    _, by_owner = standard("owner")
    assert by_manager.id != by_owner.id
    assert standard("manager")[1].id == by_manager.id  # the same campaign is the same id
    old = returned(by_manager, 1101, ALL)
    record = run(by_owner, {"old.xlsx": old})
    assert all(r.state != "accepted" for r in record.rows)
    assert [p.status for p in record.packets] == ["rejected"]
    assert "campaign" in record.packets[0].reason


def test_a_packet_digest_names_its_reviewer() -> None:
    from faithful_shaar.campaign import packet_digest  # noqa: PLC0415

    first = packet_digest("mail:a@corp.example", ["x"])
    assert first != packet_digest("mail:b@corp.example", ["x"])
