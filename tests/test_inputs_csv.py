# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""Tests for the CSV column map and the CSV reader."""

from __future__ import annotations

import dataclasses
import io
import re
from typing import TYPE_CHECKING, Any

import pytest

from faithful_shaar.errors import InputError
from faithful_shaar.inputs import csvmap, csvread
from faithful_shaar.inputs.csvmap import PRESETS, CsvMap, build_map, load_map
from faithful_shaar.inputs.csvread import read_csv
from tests.fixtures_access import (
    GENERIC_HEADERS,
    csv_bytes,
    generic_row,
    guid,
    sid,
)

if TYPE_CHECKING:
    from collections.abc import Sequence
    from pathlib import Path

    from faithful_shaar.model import Snapshot

AVERY = "AEXAMPLE"
TENANT = guid(0)
BLAIR = "BEXAMPLE"


def generic(**overrides: Any) -> CsvMap:
    data: dict[str, Any] = {**PRESETS["generic"], "system": "hr-app"}
    data.update(overrides)
    return build_map(data)


def read(data: bytes, cmap: CsvMap | None = None) -> Snapshot:
    snap, info = read_csv(io.BytesIO(data), "ledger.csv", cmap or generic())
    assert info.size == len(data)
    assert info.kind == "csv"
    return snap


def grid(*rows: dict[str, str]) -> bytes:
    return csv_bytes(GENERIC_HEADERS, [generic_row(**r) for r in rows])


def reasons(snap: Snapshot) -> list[str]:
    return [f"{p.source}: {p.reason}" for p in snap.problems]


def ok_row(**extra: str) -> dict[str, str]:
    base = {
        "principal_id": AVERY,
        "principal_name": "Avery Example",
        "resource_id": "LEDGER-ADMIN",
        "resource_name": "Ledger Admin",
    }
    return {**base, **extra}


# -- the column map ----------------------------------------------------------------------


def write_map(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "map.toml"
    path.write_text(text, encoding="utf-8")
    return path


def test_no_map_and_no_preset_is_none() -> None:
    assert load_map(None, None, "ignored") is None


def test_presets_all_build() -> None:
    for name in PRESETS:
        assert load_map(None, name, None) is not None


def test_unknown_preset() -> None:
    with pytest.raises(InputError, match=r"unknown preset 'nope'; choose one of ad-users-groups"):
        load_map(None, "nope", None)


def test_map_file_overrides_and_merges_a_preset(tmp_path: Path) -> None:
    path = write_map(
        tmp_path,
        """
system = "ledger"
owner_separator = "|"
[columns]
principal_id = "User"
[values]
enabled_true = ["Active"]
[principal_kinds]
Person = "user"
[extra]
principal = ["Department"]
resource = ["Cost center"]
grant = ["Ticket"]
""",
    )
    cmap = load_map(path, "generic", "Ledger Admins")
    assert cmap is not None
    assert cmap.columns["principal_id"] == "User"
    assert cmap.columns["principal_name"] == "principal_name"
    assert cmap.system == "ledger"
    assert cmap.resource == "Ledger Admins"
    assert cmap.owner_separator == "|"
    assert cmap.enabled_true == ("active",)
    assert cmap.enabled_false == csvmap.DEFAULT_FALSE
    assert cmap.principal_kinds == {"person": "user"}
    assert (cmap.extra_principal, cmap.extra_resource, cmap.extra_grant) == (
        ("Department",),
        ("Cost center",),
        ("Ticket",),
    )


def test_preset_named_in_the_file_and_argument_wins(tmp_path: Path) -> None:
    path = write_map(tmp_path, 'preset = "entra-members"\nsystem = "directory"\n')
    cmap = load_map(path, None, None)
    assert cmap is not None
    assert cmap.id_style == "entra"
    assert cmap.system == "directory"
    other = load_map(path, "generic", None)
    assert other is not None
    assert other.id_style == "csv"


def test_file_without_preset_stands_alone(tmp_path: Path) -> None:
    path = write_map(
        tmp_path,
        'delimiter = "tab"\nencoding = "utf-16"\ncomplete = false\noptional = true\n'
        'id_style = "sid"\nresource_kind = "role"\ncollected_at = "2026-11-01T00:00:00Z"\n'
        '[columns]\nprincipal_name = "Who"\n',
    )
    cmap = load_map(path, None, None)
    assert cmap is not None
    assert (cmap.delimiter, cmap.encoding, cmap.complete, cmap.optional) == (
        "\t",
        "utf-16",
        False,
        True,
    )
    assert (cmap.id_style, cmap.resource_kind) == ("sid", "role")
    assert cmap.collected_at == "2026-11-01T00:00:00Z"


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("bogus = 1", "unknown setting"),
        ("preset = 3", "'preset' must be text"),
        ("columns = 3", "'columns' must be a dict"),
        ("[columns]\nnope = 'x'", "unknown column field 'nope'"),
        ("[columns]\nprincipal_id = ''", "must name a header"),
        ("[columns]\nprincipal_id = 4", "must name a header"),
        ("[values]\nother = ['x']", "unknown [values] entries"),
        ("[values]\nenabled_true = 'x'", "must be a list of non-empty text"),
        ("[values]\nenabled_true = ['']", "must be a list of non-empty text"),
        ("[principal_kinds]\nx = 'robot'", "must map to one of"),
        ("[extra]\nbogus = []", "unknown [extra] entries"),
        ("[extra]\nprincipal = 'x'", "must be a list of header names"),
        ("[extra]\nprincipal = ['']", "must be a list of header names"),
        ("delimiter = ';;'", "one character"),
        ("delimiter = 3", "'delimiter' must be a str"),
        ("encoding = 'klingon'", "unknown encoding"),
        ("system = 'Bad Name'", "not a system name"),
        ("system = 'ad'", "reserved"),
        ("owner_separator = ''", "must not be empty"),
        ("via_separator = ''", "must not be empty"),
        ("id_style = 'x'", "'id_style' must be one of"),
        ("resource_kind = 'vault'", "'resource_kind' must be one of"),
        ("collected_at = 'soon'", "'collected_at' must be ISO 8601"),
        ("complete = 'no'", "'complete' must be a bool"),
    ],
)
def test_bad_maps_are_refused(tmp_path: Path, text: str, message: str) -> None:
    with pytest.raises(InputError, match=re.escape(message)):
        load_map(write_map(tmp_path, text), None, None)


def test_unreadable_map_files(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(InputError, match="cannot read the column map"):
        load_map(tmp_path / "missing.toml", None, None)
    path = write_map(tmp_path, "system = 'x'")
    path.write_bytes(b"\xff\xfe")
    with pytest.raises(InputError, match="not valid TOML"):
        load_map(path, None, None)
    path.write_text("system = ", encoding="utf-8")
    with pytest.raises(InputError, match="not valid TOML"):
        load_map(path, None, None)
    monkeypatch.setattr(csvmap, "MAX_MAP_BYTES", 5)
    path.write_text("system = 'long enough'", encoding="utf-8")
    with pytest.raises(InputError, match="larger than 5 bytes"):
        load_map(path, None, None)


# -- decoding and delimiters -------------------------------------------------------------


def one_row() -> tuple[tuple[str, ...], list[list[str]]]:
    return GENERIC_HEADERS, [generic_row(**ok_row(principal_name="Zoë Example"))]


@pytest.mark.parametrize(
    ("encoding", "bom"),
    [
        ("utf-8", False),
        ("utf-8", True),
        ("utf-16-le", True),
        ("utf-16-be", True),
    ],
)
def test_encodings_are_detected_by_byte_order_mark(encoding: str, *, bom: bool) -> None:
    headers, rows = one_row()
    snap = read(csv_bytes(headers, rows, encoding=encoding, bom=bom))
    assert snap.principals["csv:hr-app:aexample"].name == "Zoë Example"
    assert snap.problems == []


def test_undecodable_text_is_refused() -> None:
    headers, rows = one_row()
    with pytest.raises(InputError, match=r"cannot be decoded as utf-8 .*set `encoding`"):
        read(csv_bytes(headers, rows, encoding="latin-1"))
    with pytest.raises(InputError, match="cannot be decoded as utf-16"):
        read(b"\xff\xfeabc")


def test_forced_encoding_and_bom_character_is_stripped() -> None:
    headers, rows = one_row()
    data = csv_bytes(headers, rows, encoding="latin-1")
    assert read(data, generic(encoding="latin-1")).principals
    data = csv_bytes(headers, rows, bom=True)
    assert read(data, generic(encoding="utf-8")).principals


def test_nul_characters_are_refused() -> None:
    with pytest.raises(InputError, match="NUL"):
        read(b"a,b\n\x00,1\n")
    with pytest.raises(InputError, match="NUL"):
        read(b"\xff\xfe\x00\x00\x00\x00")


@pytest.mark.parametrize("delimiter", [",", ";", "\t", "|"])
def test_delimiter_is_sniffed(delimiter: str) -> None:
    headers, rows = one_row()
    snap = read(csv_bytes(headers, rows, delimiter=delimiter))
    assert len(snap.grants) == 1


def test_delimiter_from_the_map_and_quoted_header_cells() -> None:
    data = b'"principal_id","principal;name",resource_name\nA;B,x,R\n'
    snap = read(data, generic(delimiter=","))
    assert snap.principals["csv:hr-app:a;b"].name == "A;B"


def test_no_header_row() -> None:
    for data in (b"", b"\n\n  \n", b" , \n"):
        with pytest.raises(InputError, match="has no header row"):
            read(data)


def test_cannot_read_the_header() -> None:
    long = b"x" * 200_000 + b"\n1\n"
    with pytest.raises(InputError, match="header cannot be read"):
        read(long)
    with pytest.raises(InputError, match="header cannot be read"):
        read(long, generic(delimiter=","))


# -- columns -----------------------------------------------------------------------------


def test_missing_mapped_column_is_an_error_unless_optional() -> None:
    data = csv_bytes(["who", "res"], [["Avery Example", "Ledger"]])
    cmap = build_map(
        {"system": "x", "columns": {"principal_name": "who", "resource_name": "res", "upn": "UPN"}}
    )
    with pytest.raises(InputError, match=r"no column 'UPN' \(mapped to upn\)"):
        read(data, cmap)
    lenient = build_map(
        {
            "system": "x",
            "optional": True,
            "columns": {"principal_name": "who", "resource_name": "res", "upn": "UPN"},
        }
    )
    assert read(data, lenient).principals


def test_headers_match_ignoring_case_and_spaces() -> None:
    data = csv_bytes([" Principal_Name ", "RESOURCE_NAME"], [["Avery Example", "Ledger"]])
    assert read(data).principals


def test_repeated_header_names_are_refused_when_mapped() -> None:
    data = csv_bytes(
        ["principal_name", "principal_name", "resource_name", ""], [["a", "b", "c", ""]]
    )
    with pytest.raises(InputError, match="more than one column named 'principal_name'"):
        read(data)
    data = csv_bytes(["principal_name", "resource_name", "other", "other"], [["a", "c", "", ""]])
    assert read(data).principals


def test_required_columns_and_system() -> None:
    with pytest.raises(InputError, match="no principal_id or principal_name"):
        read(csv_bytes(["resource_name"], [["Ledger"]]))
    with pytest.raises(InputError, match="no resource column"):
        read(csv_bytes(["principal_name"], [["Avery Example"]]))
    with pytest.raises(InputError, match="name the system"):
        read(
            csv_bytes(["principal_name", "resource_name"], [["a", "b"]]),
            build_map(
                {
                    "optional": True,
                    "columns": {
                        "principal_name": "principal_name",
                        "resource_name": "resource_name",
                    },
                }
            ),
        )


def test_system_comes_from_a_column_when_the_map_has_none() -> None:
    cmap = build_map(PRESETS["generic"])
    data = grid(ok_row(system="Ledger"), ok_row(principal_id="B", system=""))
    snap = read(data, cmap)
    assert "csv:ledger:aexample" in snap.principals
    assert any("row 3" in r and "not a system name" in r for r in reasons(snap))
    assert snap.complete_resources == set()


def test_system_column_overrides_the_map_default() -> None:
    snap = read(grid(ok_row(system="other-app"), ok_row(principal_id="B")))
    assert "csv:other-app:aexample" in snap.principals
    assert "csv:hr-app:b" in snap.principals
    assert snap.systems == {"csv:other-app", "csv:hr-app"}


# -- rows --------------------------------------------------------------------------------


def test_a_full_row() -> None:
    row = ok_row(
        principal_kind="User",
        enabled="Yes",
        email="avery@corp.example",
        upn="avery@corp.example",
        manager_id=BLAIR,
        last_sign_in="2026-10-30",
        resource_kind="application",
        owner_ids=f"{BLAIR}; CEXAMPLE ;; {BLAIR.lower()}",
        entitlement="Approver",
        via="Finance > Ledger Users",
    )
    snap = read(grid(row))
    assert snap.problems == []
    p = snap.principals["csv:hr-app:aexample"]
    assert (p.system, p.id, p.name, p.kind, p.enabled) == (
        "csv:hr-app",
        AVERY,
        "Avery Example",
        "user",
        True,
    )
    assert (p.email, p.upn, p.last_sign_in) == ("avery@corp.example",) * 2 + ("2026-10-30",)
    assert p.manager_key == "csv:hr-app:bexample"
    assert str(p.source) == "ledger.csv, row 2"
    r = snap.resources["csv:hr-app:ledger-admin"]
    assert (r.kind, r.name, r.owner_keys) == (
        "application",
        "Ledger Admin",
        ("csv:hr-app:bexample", "csv:hr-app:cexample"),
    )
    g = next(iter(snap.grants.values()))
    assert g.key == "csv:hr-app:ledger-admin|csv:hr-app:aexample|approver"
    assert g.via == ("Finance", "Ledger Users")
    assert g.entitlement == "Approver"
    assert snap.complete_resources == {"csv:hr-app:ledger-admin"}
    assert snap.collected_at == ""
    assert snap.systems == {"csv:hr-app"}


def test_defaults_when_cells_are_blank() -> None:
    snap = read(grid(ok_row()))
    p = snap.principals["csv:hr-app:aexample"]
    assert (p.kind, p.enabled, p.manager_key) == ("unknown", None, "")
    assert snap.resources["csv:hr-app:ledger-admin"].kind == "other"
    assert next(iter(snap.grants.values())).entitlement == "member"
    assert snap.problems == []


def test_name_falls_back_to_the_id_and_the_resource_name_too() -> None:
    snap = read(grid({"principal_id": AVERY, "resource_id": "R1"}))
    assert snap.principals["csv:hr-app:aexample"].name == AVERY
    assert snap.resources["csv:hr-app:r1"].name == "R1"


def test_enabled_values_come_from_the_map() -> None:
    cmap = generic(values={"enabled_true": ["Active"], "enabled_false": ["Gone"]})
    snap = read(grid(ok_row(enabled="active"), ok_row(principal_id="B", enabled="GONE")), cmap)
    assert snap.principals["csv:hr-app:aexample"].enabled is True
    assert snap.principals["csv:hr-app:b"].enabled is False


def test_unrecognised_values_are_one_problem_each_with_a_count() -> None:
    snap = read(
        grid(
            ok_row(principal_kind="Robot", enabled="maybe", resource_kind="vault"),
            ok_row(
                principal_id="B", principal_kind="Robot", enabled="maybe", resource_kind="vault"
            ),
            ok_row(principal_id="C", principal_kind="Droid"),
        )
    )
    found = reasons(snap)
    assert (
        "ledger.csv, row 2: enabled value 'maybe' not recognised (2 rows); recorded as unknown"
        in found
    )
    assert any("principal kind 'Robot' not recognised (2 rows)" in r for r in found)
    assert any("principal kind 'Droid' not recognised (1 rows)" in r for r in found)
    assert any("resource kind 'vault' not recognised (2 rows)" in r for r in found)
    assert snap.principals["csv:hr-app:aexample"].kind == "unknown"
    assert snap.resources["csv:hr-app:ledger-admin"].kind == "other"
    assert len(snap.problems) == 4


def test_resource_kind_default_from_the_map() -> None:
    snap = read(
        grid(ok_row(), ok_row(principal_id="B", resource_kind="Vault")),
        generic(resource_kind="group"),
    )
    assert snap.resources["csv:hr-app:ledger-admin"].kind == "group"
    assert len(snap.problems) == 1
    assert "resource kind 'Vault'" in reasons(snap)[0]


def test_row_problems_skip_the_row_and_the_resource_is_not_complete() -> None:
    snap = read(
        grid(
            ok_row(principal_id="", principal_name=""),
            ok_row(resource_id="OTHER", resource_name="Other", principal_id="B"),
        ),
        generic(columns={**PRESETS["generic"]["columns"]}),
    )
    assert snap.complete_resources == {"csv:hr-app:other"}
    found = reasons(snap)
    assert "ledger.csv, row 2: row skipped: principal_id is empty" in found


def test_row_with_no_resource_makes_nothing_complete() -> None:
    snap = read(grid(ok_row(), ok_row(resource_id="", resource_name="", principal_id="B")))
    assert any("row 3: row skipped: resource_id is empty" in r for r in reasons(snap))
    assert snap.complete_resources == set()
    assert any("no resource is treated as complete" in r for r in reasons(snap))


def test_row_with_too_many_cells() -> None:
    data = csv_bytes(["principal_id", "resource_id"], [["A", "R"], ["B", "R", "extra"]])
    snap = read(data, generic())
    assert any(
        "row 3: row skipped: it has 3 cells but the header has 2" in r for r in reasons(snap)
    )
    assert snap.complete_resources == set()


def test_short_rows_are_skipped_and_leave_no_resource_complete() -> None:
    # SHAAR-C02: a short row may be a cut-off transfer; it is never padded with blanks.
    data = b"principal_id,resource_id,entitlement\nA,R,Admin\nB\n"
    snap = read(data)
    assert any(
        "row 3: row skipped: it has 1 cells but the header has 3; it may have been cut off" in r
        for r in reasons(snap)
    )
    assert len(snap.grants) == 1
    assert snap.complete_resources == set()


def test_by_name_matching_has_one_problem_each() -> None:
    data = csv_bytes(["principal_name", "resource_name"], [["Avery Example", "Ledger"]] * 3)
    snap = read(data)
    found = reasons(snap)
    assert sum("principals are matched by name" in r for r in found) == 1
    assert sum("resource is matched by name" in r for r in found) == 1
    assert (
        "ledger.csv, row 1: no principal_id column: principals are matched by name, which is weaker"
        in found
    )
    assert "csv:hr-app:avery example" in snap.principals
    assert snap.principals["csv:hr-app:avery example"].id == "Avery Example"
    assert "csv:hr-app:ledger" in snap.resources
    assert len(snap.grants) == 1


def test_by_name_with_an_empty_name_is_skipped() -> None:
    data = csv_bytes(["principal_name", "resource_name"], [["", "Ledger"], ["A", ""]])
    snap = read(data)
    found = reasons(snap)
    assert any("row 2: row skipped: principal_name is empty" in r for r in found)
    assert any("row 3: row skipped: resource_name is empty" in r for r in found)


def test_manager_and_owners_are_matched_by_name_when_there_is_no_id_column() -> None:
    data = csv_bytes(
        ["principal_name", "manager_id", "resource_name", "owner_ids"],
        [["Avery Example", "Blair Example", "Ledger", "Blair Example"]],
    )
    snap = read(data)
    assert snap.principals["csv:hr-app:avery example"].manager_key == "csv:hr-app:blair example"
    assert snap.resources["csv:hr-app:ledger"].owner_keys == ("csv:hr-app:blair example",)


def test_repeated_principal_rows_that_agree_are_quiet_and_that_differ_are_a_problem() -> None:
    snap = read(
        grid(
            ok_row(email="a@corp.example"),
            ok_row(resource_id="R2", resource_name="Second", email="a@corp.example"),
            ok_row(resource_id="R3", resource_name="Third", email="other@corp.example"),
            ok_row(
                resource_id="R2",
                resource_name="Renamed",
                entitlement="Admin",
                email="a@corp.example",
            ),
        )
    )
    found = reasons(snap)
    assert any(
        r.startswith("ledger.csv, row 4:")
        and "differs from the record at ledger.csv, row 2 in: email" in r
        for r in found
    )
    assert any(r.startswith("ledger.csv, row 5:") and "in: name" in r for r in found)
    assert snap.principals["csv:hr-app:aexample"].email == "a@corp.example"
    assert snap.resources["csv:hr-app:r2"].name == "Second"
    assert len(snap.problems) == 2


def test_two_paths_to_one_grant_merge() -> None:
    snap = read(
        grid(
            ok_row(via="A > B"),
            ok_row(via="A > B"),
            ok_row(via=""),
        )
    )
    g = next(iter(snap.grants.values()))
    assert g.via == ()
    assert g.extra["paths"] == "A > B; direct"
    assert snap.problems == []


def test_map_complete_false() -> None:
    snap = read(grid(ok_row()), generic(complete=False))
    assert snap.complete_resources == set()
    assert snap.resources


def test_collected_at_from_the_map() -> None:
    snap = read(grid(ok_row()), generic(collected_at="2026-10-01T00:00:00+00:00"))
    assert snap.collected_at == "2026-10-01T00:00:00+00:00"


def test_formula_looking_text_is_data() -> None:
    row = ok_row(
        principal_name='=HYPERLINK("http://203.0.113.5","x")',
        email="@SUM(1+1)",
        entitlement="+cmd|' /C calc'!A0",
        resource_name="-2+3",
    )
    snap = read(grid(row))
    assert snap.principals["csv:hr-app:aexample"].name.startswith("=HYPERLINK")
    assert snap.principals["csv:hr-app:aexample"].email == "@SUM(1+1)"
    assert snap.resources["csv:hr-app:ledger-admin"].name == "-2+3"
    assert next(iter(snap.grants.values())).entitlement == "+cmd|' /C calc'!A0"
    assert snap.problems == []


def test_row_numbers_are_file_lines_with_quoted_newlines_and_blank_lines() -> None:
    data = b'principal_id,principal_name,resource_id\r\nA,"Avery\r\nExample",R\r\n\r\n,Nobody,R\r\n'
    snap = read(data)
    assert snap.principals["csv:hr-app:a"].name == "Avery\r\nExample"
    assert str(snap.principals["csv:hr-app:a"].source) == "ledger.csv, row 2"
    assert any(r.startswith("ledger.csv, row 5: row skipped") for r in reasons(snap))


def test_header_may_follow_blank_lines() -> None:
    data = b"\n\nprincipal_id,resource_id\nA,R\n"
    snap = read(data)
    assert str(snap.principals["csv:hr-app:a"].source) == "ledger.csv, row 4"
    assert any("row 3: no principal_id" in r for r in reasons(snap)) is False


def test_a_field_over_the_csv_limit_is_a_problem_and_nothing_is_complete() -> None:
    data = b"principal_id,resource_id\nA,R\nB," + b"x" * 200_000 + b"\nC,R\n"
    snap = read(data)
    assert any("row 3: row cannot be read" in r for r in reasons(snap))
    assert set(snap.principals) == {"csv:hr-app:a", "csv:hr-app:c"}
    assert snap.complete_resources == set()


def test_limits(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(csvread, "MAX_ROWS", 2)
    with pytest.raises(InputError, match="more than 2 rows"):
        read(csv_bytes(["principal_id", "resource_id"], [["A", "R"]] * 3))
    monkeypatch.setattr(csvread, "MAX_CSV_BYTES", 10)
    with pytest.raises(InputError, match="larger than the limit of 10 bytes"):
        read(csv_bytes(["principal_id", "resource_id"], [["A", "R"]]))


# -- id styles and presets ---------------------------------------------------------------


def test_ad_users_groups_preset() -> None:
    headers = ["SamAccountName", "Name", "SID", "objectClass", "GroupName", "GroupSID"]
    rows = [
        ["aexample", "Avery Example", sid(1104).lower(), "user", "Tier0 Admins", sid(512)],
        [
            "svc-ledger$",
            "Ledger Service",
            sid(1200),
            "msDS-GroupManagedServiceAccount",
            "Tier0 Admins",
            sid(512),
        ],
        ["Server Ops", "Server Ops", sid(1300), "group", "Tier0 Admins", sid(512)],
        ["PC01$", "PC01", sid(1400), "computer", "Tier0 Admins", sid(512)],
        ["x", "Mystery", sid(1500), "contact", "Tier0 Admins", sid(512)],
    ]
    cmap = load_map(None, "ad-users-groups", None)
    assert cmap is not None
    snap = read(csv_bytes(headers, rows), cmap)
    avery = snap.principals[f"ad:sid:{sid(1104)}"]
    assert (avery.system, avery.kind, avery.name, avery.extra) == (
        "ad",
        "user",
        "Avery Example",
        {"SamAccountName": "aexample"},
    )
    kinds = {p.name: p.kind for p in snap.principals.values()}
    assert kinds == {
        "Avery Example": "user",
        "Ledger Service": "service",
        "Server Ops": "group",
        "PC01": "device",
        "Mystery": "unknown",
    }
    group = snap.resources[f"ad:sid:{sid(512)}"]
    assert (group.kind, group.name, group.system) == ("group", "Tier0 Admins", "ad")
    assert snap.complete_resources == {f"ad:sid:{sid(512)}"}
    assert snap.systems == {"ad"}
    assert any("principal kind 'contact'" in r for r in reasons(snap))
    assert f"ad:sid:{sid(512)}|ad:sid:{sid(1104)}|member" in snap.grants


def test_sid_style_rejects_a_value_that_is_not_a_sid() -> None:
    cmap = load_map(None, "ad-users-groups", None)
    assert cmap is not None
    headers = ["Name", "SID", "objectClass", "GroupName", "GroupSID"]
    rows = [
        ["Avery", sid(1104), "user", "Admins", sid(512)],
        ["Blair", "not-a-sid", "user", "Admins", sid(512)],
    ]
    snap = read(csv_bytes(headers, rows), cmap)
    assert any("row 3: row skipped" in r and "is not a SID" in r for r in reasons(snap))
    assert snap.complete_resources == set()


def test_sid_style_manager_and_owners_that_are_not_sids_are_dropped_with_a_problem() -> None:
    cmap = build_map(
        {
            **PRESETS["ad-users-groups"],
            "columns": {
                **PRESETS["ad-users-groups"]["columns"],
                "manager_id": "Manager",
                "owner_ids": "Owners",
            },
        }
    )
    headers = ["Name", "SID", "GroupName", "GroupSID", "Manager", "Owners"]
    rows = [["Avery", sid(1104), "Admins", sid(512), "CN=Blair", f"{sid(1105)};nope"]]
    snap = read(csv_bytes(headers, rows), cmap)
    assert snap.principals[f"ad:sid:{sid(1104)}"].manager_key == ""
    assert snap.resources[f"ad:sid:{sid(512)}"].owner_keys == (f"ad:sid:{sid(1105)}",)
    found = reasons(snap)
    assert any("manager ignored" in r for r in found)
    assert any("owner ignored" in r for r in found)


def test_entra_members_preset_with_a_fixed_resource() -> None:
    headers = ["id", "displayName", "userPrincipalName", "userType", "accountEnabled"]
    rows = [
        [guid(1).upper(), "Avery Example", "avery@corp.example", "Member", "true"],
        [guid(2), "Guest Example", "guest_x#EXT#@corp.example", "Guest", "FALSE"],
    ]
    cmap = load_map(None, "entra-members", "Finance Approvers")
    assert cmap is not None
    unscoped = read(csv_bytes(headers, rows), cmap)
    # without a tenant the ids could belong to any directory: nothing is complete
    assert f"entra:?:id:{guid(1)}" in unscoped.principals
    assert unscoped.complete_resources == set()
    assert any("tenant or domain" in p.reason for p in unscoped.problems)
    cmap = dataclasses.replace(cmap, tenant=TENANT)
    snap = read(csv_bytes(headers, rows), cmap)
    assert snap.complete_resources == {"csv:entra-members:finance approvers"}
    avery = snap.principals[f"entra:{TENANT}:id:{guid(1)}"]
    assert (avery.system, avery.upn, avery.enabled, avery.extra) == (
        "entra",
        "avery@corp.example",
        True,
        {"userType": "Member"},
    )
    assert snap.principals[f"entra:{TENANT}:id:{guid(2)}"].enabled is False
    group = snap.resources["csv:entra-members:finance approvers"]
    assert (group.name, group.kind, group.system) == (
        "Finance Approvers",
        "group",
        "csv:entra-members",
    )
    assert snap.complete_resources == {group.key}
    assert snap.systems == {"entra", "csv:entra-members"}
    assert not any("resource is matched by name" in r for r in reasons(snap))  # fixed by --resource
    assert len(snap.grants) == 2


def test_fixed_resource_wins_over_resource_columns() -> None:
    snap = read(grid(ok_row()), generic(resource="Fixed"))
    assert list(snap.resources) == ["csv:hr-app:fixed"]
    assert snap.resources["csv:hr-app:fixed"].id == "Fixed"


def test_entra_resource_without_a_fixed_name_is_an_error() -> None:
    cmap = load_map(None, "entra-members", None)
    assert cmap is not None
    with pytest.raises(InputError, match="no resource column"):
        read(csv_bytes(["id", "displayName"], [[guid(1), "Avery"]]), cmap)


def test_extra_columns() -> None:
    cmap = generic(
        extra={"principal": ["Department"], "resource": ["Cost center"], "grant": ["Ticket"]},
    )
    headers: Sequence[str] = (*GENERIC_HEADERS, "Department", "Cost center", "Ticket")
    rows = [[*generic_row(**ok_row()), "Finance", "", "T-1"]]
    snap = read(csv_bytes(headers, rows), cmap)
    assert snap.principals["csv:hr-app:aexample"].extra == {"Department": "Finance"}
    assert snap.resources["csv:hr-app:ledger-admin"].extra == {}
    assert next(iter(snap.grants.values())).extra == {"Ticket": "T-1"}
    short = read(
        csv_bytes(headers[:-1], [[*generic_row(**ok_row()), "Finance", ""]]),
        generic(optional=True, extra={"grant": ["Ticket"]}),
    )
    assert short.principals


def test_a_map_tenant_must_be_a_tenant_id() -> None:
    with pytest.raises(InputError, match="tenant id"):
        build_map({"system": "x", "tenant": "corp.example", "columns": {"principal_id": "id"}})
