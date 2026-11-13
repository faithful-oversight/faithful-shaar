# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""Who reviews each grant, under each rule."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from faithful_shaar.assign import Reviewer, assign, by_map, read_map
from faithful_shaar.errors import InputError
from tests.core_fixtures import grant, group, people, person, snapshot

if TYPE_CHECKING:
    from pathlib import Path

    from faithful_shaar.model import Snapshot


def snap() -> Snapshot:
    return snapshot(
        [
            *people(),
            person(1106, "Self Manager", manager=1106),
            person(1107, "Lost Report", manager=1999),
        ],
        [
            group(2001, "Finance Admins", 1104),
            group(2002, "Server Ops", 1104, 1101),
            group(2003, "Orphans"),
            group(2004, "Ghost owned", 1998),
            group(2005, "Solo", 1102),
        ],
        [],
    )


def test_manager_rule() -> None:
    s = snap()
    assert assign(grant(1102, 2001), s, "manager").reviewer == Reviewer(
        "mail:morgan.lead@corp.example", "Morgan Lead", "morgan.lead@corp.example"
    )
    assert (
        assign(grant(1101, 2001), s, "manager").reason
        == "the input names no manager for this principal"
    )
    assert "not in the input" in assign(grant(1107, 2001), s, "manager").reason
    assert "their own manager" in assign(grant(1106, 2001), s, "manager").reason
    assert "no manager" in assign(grant(1999, 2001), s, "manager").reason  # principal unknown


def test_owner_rule_picks_the_first_owner_by_name_and_names_the_others() -> None:
    s = snap()
    result = assign(grant(1102, 2002), s, "owner")
    assert result.reviewer is not None
    assert result.reviewer.name == "Casey Owner"
    assert result.co_owners == ("Morgan Lead",)


def test_owner_rule_never_lets_an_owner_review_their_own_access() -> None:
    s = snap()
    result = assign(grant(1104, 2002), s, "owner")  # Casey owns it and is a member
    assert result.reviewer is not None
    assert result.reviewer.name == "Morgan Lead"
    assert result.co_owners == ("Casey Owner",)
    assert "cannot review their own access" in assign(grant(1102, 2005), s, "owner").reason


def test_owner_rule_unassigned_reasons() -> None:
    s = snap()
    assert "no owner" in assign(grant(1102, 2003), s, "owner").reason
    assert "no owner" in assign(grant(1102, 2999), s, "owner").reason
    assert "not in the input" in assign(grant(1102, 2004), s, "owner").reason


def write(tmp_path: Path, text: str, name: str = "map.csv") -> Path:
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


def test_map_rule_by_resource_then_principal(tmp_path: Path) -> None:
    entries = read_map(
        write(
            tmp_path,
            (
                "resource,principal,reviewer_id,reviewer_name,reviewer_email\n"
                "Finance Admins,,fin-lead,Riley Finance,riley@corp.example\n"
                ",avery.example@corp.example,hr-lead,Harper HR,\n"
                f",{'S-1-5-21-1000-1000-1000-1105'},svc-team,,\n"
            ),
        )
    )
    s = snap()
    assert assign(grant(1102, 2001), s, "map", entries).reviewer == Reviewer(
        "map:fin-lead", "Riley Finance", "riley@corp.example"
    )
    assert assign(grant(1102, 2002), s, "map", entries).reviewer == Reviewer(
        "map:hr-lead", "Harper HR", ""
    )
    assert assign(grant(1105, 2002), s, "map", entries).reviewer == Reviewer(
        "map:svc-team", "svc-team", ""
    )
    assert "names no reviewer" in assign(grant(1103, 2002), s, "map", entries).reason
    assert "names no reviewer" in by_map(grant(1999, 2999), s, entries).reason


def test_map_rule_refuses_contradictions_and_self_review(tmp_path: Path) -> None:
    entries = read_map(
        write(
            tmp_path,
            (
                "﻿Resource,Reviewer_ID,Reviewer_Name\n"
                "Server Ops,a,A\nserver ops,b,B\nFinance Admins,avery.example@corp.example,Avery\n"
            ),
        )
    )
    s = snap()
    assert "different reviewers" in assign(grant(1102, 2002), s, "map", entries).reason
    assert "(rows 2, 3)" in assign(grant(1102, 2002), s, "map", entries).reason
    assert "cannot review their own access" in assign(grant(1102, 2001), s, "map", entries).reason


@pytest.mark.parametrize(
    ("text", "match"),
    [
        ("resource,reviewer_name\nx,y\n", "needs the columns"),
        ("reviewer_id,reviewer_name\nx,y\n", "needs the columns"),
        ("resource,reviewer_id,reviewer_name\n,x,y\n", "row 2"),
        ("resource,reviewer_id,reviewer_name\nr,,y\n", "row 2"),
    ],
)
def test_map_file_errors(tmp_path: Path, text: str, match: str) -> None:
    with pytest.raises(InputError, match=match):
        read_map(write(tmp_path, text))


def test_map_file_must_be_readable_utf8_and_small(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with pytest.raises(InputError, match="cannot read"):
        read_map(tmp_path / "missing.csv")
    bad = tmp_path / "bad.csv"
    bad.write_bytes(b"resource,reviewer_id\n\xff\n")
    with pytest.raises(InputError, match="not UTF-8"):
        read_map(bad)
    monkeypatch.setattr("faithful_shaar.assign.MAX_MAP_BYTES", 4)
    with pytest.raises(InputError, match="larger than"):
        read_map(bad)


def test_unknown_rule() -> None:
    with pytest.raises(ValueError, match="unknown reviewer rule"):
        assign(grant(1102, 2001), snap(), "lottery")


def test_one_person_in_two_systems_is_one_reviewer_and_never_reviews_themselves() -> None:
    from faithful_shaar import keys  # noqa: PLC0415
    from faithful_shaar.model import Principal  # noqa: PLC0415

    casey_entra = Principal(
        keys.entra("00000000-0000-4000-8000-0000000000f0", "00000000-0000-4000-8000-000000000005"),
        "entra",
        "x",
        "Casey Owner",
        "user",
        email="Casey.Owner@corp.example",
    )
    s = snap()
    s.principals[casey_entra.key] = casey_entra
    held = grant(1102, 2002)
    held = held.__class__(held.key, "ad", casey_entra.key, held.resource_key, "member")
    result = assign(held, s, "owner")  # Casey owns Server Ops in AD and holds it in Entra
    assert result.reviewer is not None
    assert result.reviewer.name == "Morgan Lead"
    assert assign(grant(1102, 2001), s, "owner").reviewer == Reviewer(
        "mail:casey.owner@corp.example", "Casey Owner", "casey.owner@corp.example"
    )


def test_map_rule_catches_self_review_by_email(tmp_path: Path) -> None:
    entries = read_map(
        write(
            tmp_path,
            "resource,reviewer_id,reviewer_name,reviewer_email\n"
            "Finance Admins,r1,Someone,Avery.Example@corp.example\n",
        )
    )
    result = assign(grant(1102, 2001), snap(), "map", entries)
    assert "cannot review their own access" in result.reason


def test_owner_rule_with_a_holder_missing_from_the_input() -> None:
    result = assign(grant(1999, 2002), snap(), "owner")
    assert result.reviewer is not None
    assert result.reviewer.name == "Casey Owner"
