# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""Tests for reading shaar exports."""

from __future__ import annotations

import io
from typing import TYPE_CHECKING, Any

import pytest

from faithful_shaar.errors import InputError
from faithful_shaar.inputs import export
from faithful_shaar.inputs.export import read_export
from tests.fixtures_access import (
    COLLECTED_AT,
    export_bytes,
    grant,
    guid,
    line,
    principal,
    resource,
    sid,
)

if TYPE_CHECKING:
    from faithful_shaar.model import Snapshot

ADMINS = sid(512)
TENANT = guid(0)
AVERY = sid(1104)
BLAIR = sid(1105)


def read(data: bytes) -> Snapshot:
    snap, info = read_export(io.BytesIO(data), "ad.jsonl")
    assert info.size == len(data)
    return snap


def reasons(snap: Snapshot) -> list[str]:
    return [f"{p.source}: {p.reason}" for p in snap.problems]


def basic() -> list[dict[str, Any]]:
    return [
        principal(AVERY, "Avery Example", email="avery@corp.example", manager_id=BLAIR.lower()),
        principal(BLAIR, "Blair Example", kind="user", enabled=False),
        resource(ADMINS, "Tier0 Admins", owner_ids=[BLAIR]),
        grant(AVERY, ADMINS),
        grant(BLAIR, ADMINS, via=["Tier0 Admins", "Server Ops"]),
    ]


def test_reads_a_clean_ad_export() -> None:
    snap = read(export_bytes(basic()))
    assert snap.problems == []
    assert snap.collected_at == COLLECTED_AT
    assert snap.systems == {"ad"}
    avery = snap.principals[f"ad:sid:{AVERY}"]
    assert (avery.name, avery.email, avery.kind, avery.enabled) == (
        "Avery Example",
        "avery@corp.example",
        "user",
        True,
    )
    assert avery.manager_key == f"ad:sid:{BLAIR}"
    assert avery.source.detail == "line 2"
    assert snap.principals[f"ad:sid:{BLAIR}"].enabled is False
    admins = snap.resources[f"ad:sid:{ADMINS}"]
    assert admins.owner_keys == (f"ad:sid:{BLAIR}",)
    assert snap.complete_resources == {f"ad:sid:{ADMINS}"}
    grants = list(snap.grants.values())
    assert len(grants) == 2
    assert grants[0].key == f"ad:sid:{ADMINS}|ad:sid:{AVERY}|member"
    assert grants[1].via == ("Tier0 Admins", "Server Ops")
    assert snap.context["domain[ad.jsonl]"] == "corp.example"
    assert "scope[ad.jsonl]" in snap.context
    assert snap.inputs[0].kind == "shaar-export"
    assert snap.label == "ad.jsonl"


def test_reads_an_entra_export_with_roles() -> None:
    role = guid(900)
    records = [
        principal(guid(1).upper(), "Avery Example", upn="avery@corp.example"),
        resource(guid(2), "Security Reader", kind="role"),
        resource(role, "Global Admins", kind="role"),
        resource(guid(3), "Finance", kind="group"),
        grant(guid(1), role, "whole directory"),
        grant(guid(1), guid(3)),
    ]
    snap = read(export_bytes(records, system="entra"))
    assert snap.problems == []
    assert f"entra:{TENANT}:id:{guid(1)}" in snap.principals
    assert f"entra:{TENANT}:role:{role}" in snap.resources
    assert f"entra:{TENANT}:id:{guid(3)}" in snap.resources
    role_key, avery_key = f"entra:{TENANT}:role:{role}", f"entra:{TENANT}:id:{guid(1)}"
    assert f"{role_key}|{avery_key}|whole directory" in snap.grants
    assert snap.systems == {"entra"}
    assert snap.context["tenant[ad.jsonl]"] == guid(0)


def test_dn_only_ids_use_dn_keys_and_a_problem() -> None:
    dn = "CN=Avery Example,OU=Staff,DC=corp,DC=example"
    group = "CN=Tier0 Admins,OU=Groups,DC=corp,DC=example"
    snap = read(export_bytes([principal(dn), resource(group), grant(dn, group)]))
    assert f"ad:dn:{dn.casefold()}" in snap.principals
    assert f"ad:dn:{group.casefold()}" in snap.resources
    assert len(snap.grants) == 1
    found = reasons(snap)
    assert any("matched by distinguished name" in r and "principal" in r for r in found)
    assert any("matched by distinguished name" in r and "resource" in r for r in found)


def test_missing_trailer_means_nothing_is_complete() -> None:
    snap = read(export_bytes(basic(), trailer=False))
    assert snap.complete_resources == set()
    assert any("no trailer" in r for r in reasons(snap))
    assert len(snap.grants) == 2


@pytest.mark.parametrize(
    ("override", "text"),
    [
        ({"records": 3}, "counts 3 records, 5 read"),
        ({"records": True}, "counts true records"),
        ({"records": None}, "counts null records"),
        ({"sha256": "0" * 64}, "sha256 does not match"),
        ({"sha256": 5}, "sha256 does not match"),
        ({"end": 1}, "'end' is not true"),
    ],
)
def test_bad_trailers_leave_no_resource_complete(override: dict[str, Any], text: str) -> None:
    snap = read(export_bytes(basic(), trailer=override))
    assert snap.complete_resources == set()
    assert any(text in r for r in reasons(snap))


def test_hash_is_case_insensitive_and_covers_header_and_body() -> None:
    good = export_bytes(basic())
    upper = good.replace(good[-66:-2], good[-66:-2].upper())
    assert read(upper).complete_resources
    tampered = good.replace(b"Avery Example", b"Avery Exampl3", 1)
    snap = read(tampered)
    assert snap.complete_resources == set()
    head_changed = good.replace(b'"test"', b'"tesx"', 1)
    assert read(head_changed).complete_resources == set()


def test_data_after_the_trailer_is_a_problem() -> None:
    data = export_bytes(basic()) + line(principal(BLAIR)) + b"\n"
    snap = read(data)
    assert snap.complete_resources == set()
    assert any("data after the trailer" in r for r in reasons(snap))
    snap = read(export_bytes(basic()) + b"\n\n")
    assert snap.complete_resources


def test_second_trailer_is_data_after_the_trailer() -> None:
    once = export_bytes(basic())
    snap = read(once + once.splitlines(keepends=True)[-1])
    assert snap.complete_resources == set()


def test_incomplete_resource_is_not_complete() -> None:
    records = [resource(ADMINS, complete=False), resource(sid(513), "Other"), grant(AVERY, ADMINS)]
    snap = read(export_bytes(records))
    assert snap.complete_resources == {f"ad:sid:{sid(513)}"}


def test_missing_or_odd_complete_flag_is_not_complete() -> None:
    odd = resource(ADMINS)
    odd["resource"]["complete"] = "yes"
    snap = read(export_bytes([odd]))
    assert snap.complete_resources == set()
    assert any("'complete' is not true or false" in r for r in reasons(snap))


def test_duplicate_principal_and_resource_ids() -> None:
    records = [
        principal(AVERY, "Avery Example"),
        principal(AVERY.lower(), "Avery Duplicate"),
        resource(ADMINS, "Tier0 Admins"),
        resource(ADMINS, "Tier0 Admins again"),
    ]
    snap = read(export_bytes(records))
    assert snap.principals[f"ad:sid:{AVERY}"].name == "Avery Example"
    assert snap.resources[f"ad:sid:{ADMINS}"].name == "Tier0 Admins"
    found = reasons(snap)
    assert any("duplicate principal" in r and "line 2" in r for r in found)
    assert any("duplicate resource" in r for r in found)
    assert snap.complete_resources == set()


def test_unknown_record_type_is_a_problem_not_a_crash() -> None:
    snap = read(export_bytes([{"future": {"a": 1}}, principal(AVERY), resource(ADMINS)]))
    assert any("unknown record type 'future'" in r and "line 2" in r for r in reasons(snap))
    # a record this reader does not know may have held a member: nothing is complete
    assert snap.complete_resources == set()
    known = read(export_bytes([principal(AVERY), resource(ADMINS)]))
    assert known.complete_resources == {f"ad:sid:{ADMINS}"}
    snap = read(export_bytes([{}]))
    assert any("unknown record type ''" in r for r in reasons(snap))


def test_record_with_two_members_is_skipped_and_costs_completeness() -> None:
    snap = read(export_bytes([{"principal": {"id": AVERY}, "grant": {}}, resource(ADMINS)]))
    assert any("more than one member" in r for r in reasons(snap))
    assert snap.complete_resources == set()
    assert any("no resource is treated as complete" in r for r in reasons(snap))


@pytest.mark.parametrize("raw", [b"{not json\n", b"[1, 2]\n", b'"text"\n', b"\xff\xfe\n"])
def test_malformed_lines_are_problems_with_line_numbers(raw: bytes) -> None:
    snap = read(export_bytes([principal(AVERY), raw, resource(ADMINS)]))
    assert any("line 3: line is not a JSON object" in r for r in reasons(snap))
    assert snap.complete_resources == set()
    assert f"ad:sid:{AVERY}" in snap.principals
    assert f"ad:sid:{ADMINS}" in snap.resources


def test_deeply_nested_line_does_not_crash() -> None:
    snap = read(export_bytes([b"[" * 100000 + b"\n", resource(ADMINS)]))
    assert any("not a JSON object" in r for r in reasons(snap))


def test_blank_line_is_a_problem_but_costs_nothing() -> None:
    snap = read(export_bytes([b"\n", resource(ADMINS)]))
    assert any("line 2: empty line" in r for r in reasons(snap))
    assert snap.complete_resources == {f"ad:sid:{ADMINS}"}


def test_line_too_long_is_skipped_and_still_hashed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(export, "MAX_LINE_BYTES", 200)
    big = line(principal(AVERY, "A" * 1000))
    snap = read(export_bytes([big, resource(ADMINS), grant(AVERY, ADMINS)]))
    assert any("line 2: line is longer than 200" in r for r in reasons(snap))
    assert not any("sha256" in r for r in reasons(snap))
    assert snap.complete_resources == set()
    assert len(snap.grants) == 1
    # a line of exactly the limit is fine
    limit = len(export_bytes([], trailer=False))
    padding = limit - len(line(principal(AVERY, "")))
    exact = line(principal(AVERY, "A" * padding))
    assert len(exact) == limit
    monkeypatch.setattr(export, "MAX_LINE_BYTES", limit)
    assert not read(export_bytes([exact])).problems


def test_too_long_last_line_without_newline(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(export, "MAX_LINE_BYTES", 200)
    data = export_bytes([resource(ADMINS)], trailer=False) + b"x" * 500
    snap = read(data)
    assert any("longer than 200" in r for r in reasons(snap))
    assert any("no trailer" in r for r in reasons(snap))


def test_file_size_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(export, "MAX_FILE_BYTES", 100)
    with pytest.raises(InputError, match="larger than the limit"):
        read(export_bytes(basic()))


@pytest.mark.parametrize(
    ("data", "text"),
    [
        (b"", "empty"),
        (b"x" * (export.MAX_LINE_BYTES + 10), "too long"),
        (b"not json\n", "not JSON"),
        (b"[]\n", "no shaar_export 1 header"),
        (b'{"shaar_export": 2, "system": "ad"}\n', "no shaar_export 1 header"),
        (b'{"shaar_export": 1, "system": "okta"}\n', "system 'okta'"),
        (b'{"shaar_export": 1, "system": {"a": 1}}\n', "expected ad or entra"),
    ],
)
def test_bad_headers_are_refused(data: bytes, text: str) -> None:
    with pytest.raises(InputError, match=text):
        read(data)


def test_header_without_valid_time_is_a_problem() -> None:
    for stamp in (None, "yesterday", "2026-11-01T12:00:00", 5):
        snap = read(export_bytes(basic(), header={"collected_at": stamp}))
        assert snap.collected_at == ""
        assert any("line 1: header has no valid collected_at" in r for r in reasons(snap))


def test_header_without_scope_or_domain() -> None:
    snap = read(export_bytes(basic(), header={"scope": None, "collector": None, "domain": None}))
    assert snap.context == {}


def test_bad_fields_in_principals() -> None:
    bad = principal(
        AVERY,
        name=5,
        kind="robot",
        enabled="yes",
        email=["a"],
        extra="x",
        manager_id=None,
    )
    snap = read(export_bytes([bad, {"principal": 7}, {"principal": {"name": "n"}}]))
    p = snap.principals[f"ad:sid:{AVERY}"]
    assert (p.kind, p.enabled, p.email, p.name) == ("unknown", None, "", AVERY)
    found = " | ".join(reasons(snap))
    for text in (
        "'name' is not text",
        "unknown kind 'robot'",
        "'enabled' is not true or false",
        "'email' is not text",
        "'extra' is not an object",
        "principal record is not an object",
        "principal record has no id",
    ):
        assert text in found


def test_extra_values_are_kept_as_text() -> None:
    rec = principal(AVERY, extra={"dept": "Finance", "level": 3, "tags": ["a"], "none": None})
    snap = read(export_bytes([rec]))
    assert snap.principals[f"ad:sid:{AVERY}"].extra == {
        "dept": "Finance",
        "level": "3",
        "tags": '["a"]',
        "none": "null",
    }


def test_bad_fields_in_resources() -> None:
    bad = resource(ADMINS, kind="vault", owner_ids="x")
    odd_owners = resource(sid(513), "Other", owner_ids=[BLAIR, 5, BLAIR.lower(), " "])
    snap = read(export_bytes([bad, odd_owners, {"resource": 3}, {"resource": {}}]))
    assert snap.resources[f"ad:sid:{ADMINS}"].kind == "other"
    assert snap.resources[f"ad:sid:{ADMINS}"].owner_keys == ()
    assert snap.resources[f"ad:sid:{sid(513)}"].owner_keys == (f"ad:sid:{BLAIR}",)
    found = " | ".join(reasons(snap))
    for text in (
        "unknown kind 'vault'",
        "'owner_ids' is not a list",
        "entries that are not text",
        "resource record is not an object",
        "resource record has no id",
    ):
        assert text in found


def test_grants_with_bad_fields_are_dropped_and_cost_that_resource() -> None:
    records = [
        resource(ADMINS),
        resource(sid(513), "Other"),
        grant(AVERY, ADMINS, ""),
        grant(AVERY, ADMINS, via="Server Ops"),
        grant(AVERY, ADMINS, via=["x", 1]),
        grant(AVERY, sid(513)),
    ]
    snap = read(export_bytes(records))
    assert len(snap.grants) == 1
    assert snap.complete_resources == {f"ad:sid:{sid(513)}"}
    found = " | ".join(reasons(snap))
    assert "grant skipped: principal_id, resource_id or entitlement is missing" in found
    assert "grant skipped: 'via' is not a list of names" in found


def test_grant_without_a_resource_id_or_not_an_object_loses_everything() -> None:
    snap = read(export_bytes([resource(ADMINS), {"grant": {"principal_id": AVERY}}]))
    assert snap.complete_resources == set()
    snap = read(export_bytes([resource(ADMINS), {"grant": 4}]))
    assert snap.complete_resources == set()
    assert any("grant record is not an object" in r for r in reasons(snap))


def test_gaps_become_problems() -> None:
    gaps: list[dict[str, Any]] = [
        {"gap": {"what": "members of Tier0 Admins", "reason": "access denied"}},
        {"gap": {}},
        {"gap": "text"},
    ]
    snap = read(export_bytes(gaps))
    found = reasons(snap)
    assert "ad.jsonl, line 2: not read: members of Tier0 Admins: access denied" in found
    assert "ad.jsonl, line 3: not read: something: no reason given" in found
    assert any("gap record is not an object" in r for r in found)


def test_grant_with_missing_records_is_kept_with_stubs() -> None:
    snap = read(export_bytes([grant(AVERY, ADMINS), grant(BLAIR, ADMINS, "Operator")]))
    assert len(snap.grants) == 2
    stub = snap.principals[f"ad:sid:{AVERY}"]
    assert (stub.kind, stub.name, stub.id, stub.extra) == (
        "unknown",
        AVERY,
        AVERY,
        {"stub": "true"},
    )
    resource_stub = snap.resources[f"ad:sid:{ADMINS}"]
    assert (resource_stub.kind, resource_stub.extra) == ("other", {"stub": "true"})
    assert snap.complete_resources == set()
    found = reasons(snap)
    assert sum("no record; kept with a stub" in r and "principal" in r for r in found) == 2
    assert sum("resource with no record" in r for r in found) == 2


def test_records_may_come_in_any_order() -> None:
    records = [grant(AVERY, ADMINS), resource(ADMINS), principal(AVERY)]
    snap = read(export_bytes(records))
    assert snap.problems == []
    assert snap.complete_resources == {f"ad:sid:{ADMINS}"}


def test_entra_grant_before_role_record_resolves_the_role_key() -> None:
    role = guid(7)
    snap = read(
        export_bytes(
            [grant(guid(1), role, "Reader"), resource(role, "Reader", kind="role")],
            system="entra",
        )
    )
    assert next(iter(snap.grants.values())).resource_key == f"entra:{TENANT}:role:{role}"
    assert any("principal with no record" in r for r in reasons(snap))
    assert not any("resource with no record" in r for r in reasons(snap))


def test_duplicate_grants_keep_the_shortest_via_and_all_paths() -> None:
    records = [
        resource(ADMINS),
        principal(AVERY),
        grant(AVERY, ADMINS, via=["Tier0 Admins", "Server Ops", "Helpdesk"]),
        grant(AVERY, ADMINS, via=["Tier0 Admins", "Server Ops"]),
        grant(AVERY, ADMINS, "MEMBER"),
        grant(AVERY, ADMINS, via=["Tier0 Admins", "Server Ops"]),
    ]
    snap = read(export_bytes(records))
    assert len(snap.grants) == 1
    only = next(iter(snap.grants.values()))
    assert only.via == ()
    assert only.extra["paths"] == (
        "Tier0 Admins > Server Ops > Helpdesk; Tier0 Admins > Server Ops; direct"
    )
    assert snap.problems == []


def test_single_path_has_no_paths_entry_and_extra_survives() -> None:
    records = [grant(AVERY, ADMINS, extra={"through": "primary group"}), principal(AVERY)]
    snap = read(export_bytes([*records, resource(ADMINS)]))
    only = next(iter(snap.grants.values()))
    assert only.extra == {"through": "primary group"}


def test_kind_may_be_left_out() -> None:
    bare_principal = {"principal": {"id": AVERY}}
    bare_resource = {"resource": {"id": ADMINS, "complete": True}}
    snap = read(export_bytes([bare_principal, bare_resource]))
    assert snap.problems == []
    assert snap.principals[f"ad:sid:{AVERY}"].kind == "unknown"
    assert snap.resources[f"ad:sid:{ADMINS}"].kind == "other"


def test_every_grant_with_a_missing_record_gets_its_own_problem() -> None:
    snap = read(export_bytes([grant(AVERY, ADMINS), grant(AVERY, sid(513))]))
    found = reasons(snap)
    assert sum("principal with no record" in r for r in found) == 2
    assert sum("resource with no record" in r for r in found) == 2
    assert len(snap.principals) == 1
