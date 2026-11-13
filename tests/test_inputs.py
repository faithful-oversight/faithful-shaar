# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""Tests for read_inputs: detection, fingerprints and merging."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Any

import pytest

from faithful_shaar import inputs
from faithful_shaar.errors import InputError
from faithful_shaar.inputs import export, read_inputs
from faithful_shaar.inputs.merge import earliest, merge
from faithful_shaar.model import InputFile, Snapshot
from tests.fixtures_access import (
    GENERIC_HEADERS,
    csv_bytes,
    export_bytes,
    generic_row,
    grant,
    principal,
    resource,
    sid,
    write,
)

ADMINS = sid(512)
AVERY = sid(1104)
BLAIR = sid(1105)


def records(**overrides: Any) -> list[dict[str, Any]]:
    return [
        principal(AVERY, "Avery Example", **overrides),
        resource(ADMINS, "Tier0 Admins"),
        grant(AVERY, ADMINS),
    ]


def reasons(snap: Snapshot) -> list[str]:
    return [f"{p.source}: {p.reason}" for p in snap.problems]


def ledger_csv() -> bytes:
    row = generic_row(
        principal_id="AEXAMPLE",
        principal_name="Avery Example",
        resource_id="LEDGER",
        resource_name="Ledger",
        system="hr",
    )
    return csv_bytes(GENERIC_HEADERS, [row])


def test_requires_at_least_one_input() -> None:
    with pytest.raises(InputError, match="no input files"):
        read_inputs([], label="x")


def test_reads_an_export_and_fingerprints_it(tmp_path: Path) -> None:
    data = export_bytes(records())
    path = write(tmp_path / ".", "ad-export.jsonl", data)
    snap = read_inputs([path], label="Q4 review")
    assert snap.label == "Q4 review"
    assert snap.inputs == [
        InputFile("ad-export.jsonl", "shaar-export", len(data), hashlib.sha256(data).hexdigest())
    ]
    assert snap.complete_resources == {f"ad:sid:{ADMINS}"}
    assert snap.collected_at == "2026-11-01T12:00:00Z"
    assert str(tmp_path) not in repr(snap.inputs)
    assert all(str(tmp_path) not in str(p.source) for p in snap.problems)


def test_detection_is_by_content_not_extension(tmp_path: Path) -> None:
    exported = write(tmp_path, "access.csv", export_bytes(records()))
    table = write(tmp_path, "access.jsonl", ledger_csv())
    snap = read_inputs([exported, table], label="x", preset="generic", resource=None)
    assert [i.kind for i in snap.inputs] == ["shaar-export", "csv"]
    assert "csv:hr:aexample" in snap.principals


def test_json_that_is_not_an_export_is_read_as_csv(tmp_path: Path) -> None:
    path = write(tmp_path, "other.json", b'{"a": 1}\n')
    with pytest.raises(InputError, match="no principal_id or principal_name"):
        read_inputs([path], label="x", preset="generic")


def test_is_export() -> None:
    assert inputs.is_export(b'{"shaar_export": 1}\n')
    assert inputs.is_export(b'{"shaar_export": 9}')
    assert not inputs.is_export(b"")
    assert not inputs.is_export(b"a,b\n")
    assert not inputs.is_export(b"[1]")
    assert not inputs.is_export(b'{"a": 1}')
    assert not inputs.is_export(b"[" * 100_000)


def test_csv_needs_a_map_or_preset(tmp_path: Path) -> None:
    path = write(tmp_path, "ledger.csv", ledger_csv())
    with pytest.raises(InputError, match=r"ledger\.csv is not a shaar export; to read a CSV"):
        read_inputs([path], label="x")


def test_csv_with_a_map_file(tmp_path: Path) -> None:
    mapping = tmp_path / "ledger.toml"
    mapping.write_text(
        'system = "ledger"\ncollected_at = "2026-10-15T08:00:00Z"\n'
        '[columns]\nprincipal_id = "User"\nresource_name = "Role"\n',
        encoding="utf-8",
    )
    path = write(tmp_path, "ledger.csv", csv_bytes(["User", "Role"], [["AEXAMPLE", "Approver"]]))
    snap = read_inputs([path], label="x", csv_map=mapping)
    assert "csv:ledger:aexample" in snap.principals
    assert snap.collected_at == "2026-10-15T08:00:00Z"
    assert snap.complete_resources == {"csv:ledger:approver"}
    assert snap.inputs[0].kind == "csv"


def test_a_bad_map_is_an_error_even_without_a_csv(tmp_path: Path) -> None:
    path = write(tmp_path, "ad.jsonl", export_bytes(records()))
    with pytest.raises(InputError, match="unknown preset"):
        read_inputs([path], label="x", preset="nope")


@pytest.mark.parametrize(
    ("kind", "message"),
    [
        ("missing", "cannot read thing"),
        ("directory", "thing is not a regular file"),
        ("fifo", "thing is not a regular file"),
    ],
)
def test_not_a_regular_file(tmp_path: Path, kind: str, message: str) -> None:
    path = tmp_path / "thing"
    if kind == "directory":
        path.mkdir()
    elif kind == "fifo":
        if not hasattr(os, "mkfifo"):
            pytest.skip("this platform has no named pipes")
        os.mkfifo(path)
    with pytest.raises(InputError, match=message):
        read_inputs([path], label="x")


def test_symlink_to_a_regular_file_is_read_under_its_own_name(tmp_path: Path) -> None:
    target = write(tmp_path, "real.jsonl", export_bytes(records()))
    link = tmp_path / "link.jsonl"
    link.symlink_to(target)
    snap = read_inputs([link], label="x")
    assert snap.inputs[0].name == "link.jsonl"


def test_size_cap_before_reading(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = write(tmp_path, "big.jsonl", export_bytes(records()))
    monkeypatch.setattr(export, "MAX_FILE_BYTES", 10)
    with pytest.raises(InputError, match=r"big\.jsonl is larger than the limit of 10 bytes"):
        read_inputs([path], label="x")


def test_unreadable_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = write(tmp_path, "locked.jsonl", export_bytes(records()))

    def refuse(*_args: Any, **_kwargs: Any) -> Any:
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(Path, "open", refuse)
    with pytest.raises(InputError, match=r"cannot read locked\.jsonl: Permission denied"):
        read_inputs([path], label="x")


def test_the_same_file_twice_merges_to_the_same_snapshot(tmp_path: Path) -> None:
    path = write(tmp_path, "ad.jsonl", export_bytes(records()))
    once = read_inputs([path], label="x")
    twice = read_inputs([path, path], label="x")
    assert twice.principals == once.principals
    assert twice.resources == once.resources
    assert twice.grants == once.grants
    assert twice.complete_resources == once.complete_resources
    assert len(twice.inputs) == 2
    assert not any("conflicts" in r for r in reasons(twice))


def test_earliest_collected_at_wins(tmp_path: Path) -> None:
    newer = write(
        tmp_path,
        "b.jsonl",
        export_bytes(records(), header={"collected_at": "2026-11-02T00:00:00Z"}),
    )
    older = write(
        tmp_path,
        "a.jsonl",
        export_bytes(records(), header={"collected_at": "2026-11-01T23:00:00-05:00"}),
    )
    snap = read_inputs([newer, older], label="x")
    # 23:00 at -05:00 is 04:00 UTC on 11-02, later than 00:00Z: instants decide, not text
    assert snap.collected_at == "2026-11-02T00:00:00Z"
    snap = read_inputs([older, newer], label="x")
    assert snap.collected_at == "2026-11-02T00:00:00Z"


def test_an_export_without_a_valid_time_makes_the_merge_unknown(tmp_path: Path) -> None:
    good = write(tmp_path, "a.jsonl", export_bytes(records()))
    bad = write(tmp_path, "b.jsonl", export_bytes(records(), header={"collected_at": None}))
    assert read_inputs([good, bad], label="x").collected_at == ""


def test_a_csv_without_a_time_cannot_borrow_one(tmp_path: Path) -> None:
    exported = write(tmp_path, "a.jsonl", export_bytes(records()))
    table = write(tmp_path, "b.csv", ledger_csv())
    snap = read_inputs([exported, table], label="x", preset="generic", resource=None)
    # the read as a whole is undated: one of its inputs says nothing about when it was taken
    assert snap.collected_at == ""
    assert earliest([snap]) == ""
    # each resource keeps the time of the inputs that hold it, so the export's own time stands
    # and the CSV's resources have none
    assert snap.resource_times[f"ad:sid:{ADMINS}"] == "2026-11-01T12:00:00Z"
    csv_keys = [k for k in snap.resources if k.startswith("csv:")]
    assert csv_keys
    assert all(snap.resource_times[k] == "" for k in csv_keys)
    with_time = tmp_path / "t.toml"
    with_time.write_text('system = "hr"\ncollected_at = "2026-10-01T00:00:00Z"\n', encoding="utf-8")
    snap = read_inputs([exported, table], label="x", preset="generic", csv_map=with_time)
    assert snap.collected_at == "2026-10-01T00:00:00Z"
    assert snap.resource_times[f"ad:sid:{ADMINS}"] == "2026-11-01T12:00:00Z"
    only_csv = read_inputs([table], label="x", preset="generic")
    assert only_csv.collected_at == ""


def test_systems_and_context_are_collected_from_every_input(tmp_path: Path) -> None:
    a = write(tmp_path, "ad.jsonl", export_bytes(records()))
    e = write(
        tmp_path,
        "entra.jsonl",
        export_bytes([principal("00000000-0000-4000-8000-000000000001")], system="entra"),
    )
    c = write(tmp_path, "ledger.csv", ledger_csv())
    snap = read_inputs([a, e, c], label="x", preset="generic", csv_map=None)
    assert snap.systems == {"ad", "entra", "csv:hr"}
    assert "domain[ad.jsonl]" in snap.context
    assert "tenant[entra.jsonl]" in snap.context


def test_conflicting_principals_keep_the_first_and_name_both_sources(tmp_path: Path) -> None:
    first = write(tmp_path, "one.jsonl", export_bytes(records(email="avery@corp.example")))
    second = write(
        tmp_path, "two.jsonl", export_bytes(records(email="a.example@corp.example", enabled=False))
    )
    snap = read_inputs([first, second], label="x")
    assert snap.principals[f"ad:sid:{AVERY}"].email == "avery@corp.example"
    found = [r for r in reasons(snap) if "conflicts" in r]
    assert len(found) == 1
    assert found[0].startswith("two.jsonl, line 2:")
    assert "one.jsonl, line 2" in found[0]
    assert "in: enabled, email;" in found[0]
    assert "corp.example" not in found[0]


def test_conflicting_resources_keep_the_first(tmp_path: Path) -> None:
    first = write(tmp_path, "one.jsonl", export_bytes(records()))
    other = [
        principal(AVERY, "Avery Example"),
        resource(ADMINS, "Domain Admins", owner_ids=[BLAIR]),
    ]
    second = write(tmp_path, "two.jsonl", export_bytes(other))
    snap = read_inputs([first, second], label="x")
    assert snap.resources[f"ad:sid:{ADMINS}"].name == "Tier0 Admins"
    found = [r for r in reasons(snap) if "conflicts" in r and "resource" in r]
    assert len(found) == 1
    assert "in: name, owner_keys" in found[0]


def test_grants_with_one_key_merge_their_paths_across_inputs(tmp_path: Path) -> None:
    first = write(
        tmp_path,
        "one.jsonl",
        export_bytes([*records()[:2], grant(AVERY, ADMINS, via=["Tier0 Admins", "Ops"])]),
    )
    second = write(tmp_path, "two.jsonl", export_bytes(records()))
    third = write(tmp_path, "three.jsonl", export_bytes(records()))
    snap = read_inputs([first, second, third], label="x")
    only = next(iter(snap.grants.values()))
    assert only.via == ()
    assert only.extra["paths"] == "Tier0 Admins > Ops; direct"
    assert str(only.source) == "one.jsonl, line 4"


def test_a_resource_is_complete_only_if_every_input_that_mentions_it_says_so(
    tmp_path: Path,
) -> None:
    whole = write(tmp_path, "whole.jsonl", export_bytes(records()))
    partial = write(
        tmp_path,
        "partial.jsonl",
        export_bytes([principal(AVERY), resource(ADMINS, "Tier0 Admins", complete=False)]),
    )
    cut = write(tmp_path, "cut.jsonl", export_bytes(records(), trailer=False))
    other = write(
        tmp_path,
        "other.jsonl",
        export_bytes([resource(sid(513), "Other"), principal(BLAIR, "Blair Example")]),
    )
    assert read_inputs([whole], label="x").complete_resources == {f"ad:sid:{ADMINS}"}
    assert read_inputs([whole, partial], label="x").complete_resources == set()
    assert read_inputs([cut, whole], label="x").complete_resources == set()
    both = read_inputs([whole, other], label="x")
    assert both.complete_resources == {f"ad:sid:{ADMINS}", f"ad:sid:{sid(513)}"}


def test_problems_from_every_input_are_kept_in_order(tmp_path: Path) -> None:
    first = write(tmp_path, "one.jsonl", export_bytes([{"mystery": 1}]))
    second = write(tmp_path, "two.jsonl", export_bytes([{"mystery": 2}]))
    snap = read_inputs([first, second], label="x")
    assert [str(p.source) for p in snap.problems] == [
        "one.jsonl, line 2",
        "one.jsonl",
        "two.jsonl, line 2",
        "two.jsonl",
    ]


def test_merge_of_nothing_in_particular() -> None:
    assert merge("x", []).collected_at == ""
    assert earliest([]) == ""
