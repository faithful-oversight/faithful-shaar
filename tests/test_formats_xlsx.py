# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""Tests for the packet workbook writer and reader."""

from __future__ import annotations

import contextlib
import io
import re
import secrets
import shutil
import subprocess
import zipfile
from dataclasses import replace
from pathlib import Path
from xml.etree import ElementTree as ET

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from faithful_shaar.errors import InputError
from faithful_shaar.formats import xlsx
from faithful_shaar.formats.xlsx import (
    DECISIONS,
    HEADERS,
    Packet,
    PacketRow,
    cell_text,
    read_packet,
    write_packet,
    write_packet_with_notes,
)

NS = {"m": "http://schemas.openxmlformats.org/spreadsheetml/2006/main"}
CREATED = "2026-11-12T10:00:00Z"


def make_row(index: int, **changes: str) -> PacketRow:
    row = PacketRow(
        row_id=f"R{index:012d}",
        row_check=f"{index:064x}",
        user=f"Avery Example {index}",
        account=f"aexample{index}",
        status="Enabled",
        last_sign_in="2026-10-01T08:00:00Z",
        access_to="Tier0 Admins",
        type="group",
        access="member",
        granted_through="Tier0 Admins > Server Ops",
        co_owners="Blake Example",
    )
    return replace(row, **changes)


def make_packet(count: int = 3, *, co_owners: bool = True, **changes: object) -> Packet:
    packet = Packet(
        campaign_name="Q4 privileged access",
        campaign_id="C0123456789abcdef",
        reviewer_name="Pat Example",
        reviewer_email="pat@corp.example",
        due="2026-12-01",
        packet_digest="ab" * 32,
        rows=[make_row(i) for i in range(count)],
        co_owner_column=co_owners,
        created_at=CREATED,
    )
    return replace(packet, **changes)  # type: ignore[arg-type]


def build_zip(parts: dict[str, bytes | str], *, order: list[str] | None = None) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name in order or list(parts):
            content = parts[name]
            archive.writestr(name, content if isinstance(content, bytes) else content.encode())
    return buffer.getvalue()


def replaced_parts(data: bytes, **changes: bytes | str) -> dict[str, bytes | str]:
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        parts: dict[str, bytes | str] = {n: archive.read(n) for n in archive.namelist()}
    parts.update(
        {name.replace("__", "/").replace("_xml", ".xml"): v for name, v in changes.items()}
    )
    return parts


# ---------------------------------------------------------------------------- round trip


def test_round_trip_keeps_every_row_and_the_about_fields() -> None:
    rows = [
        make_row(0),
        make_row(1, user="Zoë Ünïcode 中", granted_through="line one\nline two", co_owners=""),
        make_row(2, decision="Remove", comment="No longer needed"),
    ]
    packet = make_packet(co_owners=True, rows=rows)
    returned = read_packet(write_packet(packet), "p.xlsx")
    assert returned.headers == list(HEADERS)
    assert returned.notes == []
    assert [r.row for r in returned.rows] == [2, 3, 4]
    first = returned.rows[0].values
    assert first["Decision"] == ""
    assert first["Comment"] == ""
    assert first["Row ID"] == rows[0].row_id
    assert first["Row check"] == rows[0].row_check
    assert first["Granted through"] == "Tier0 Admins > Server Ops"
    assert returned.rows[1].values["User"] == "Zoë Ünïcode 中"
    assert returned.rows[1].values["Granted through"] == "line one\nline two"
    assert returned.rows[2].values["Decision"] == "Remove"
    assert returned.rows[2].values["Comment"] == "No longer needed"
    assert returned.about == {
        "Campaign": "Q4 privileged access",
        "Campaign ID": "C0123456789abcdef",
        "Reviewer": "Pat Example",
        "Reviewer email": "pat@corp.example",
        "Due": "2026-12-01",
        "Packet digest": "ab" * 32,
        "Rows": "3",
    }
    assert returned.core == {
        "creator": "shaar",
        "lastModifiedBy": "shaar",
        "modified": "2026-11-12T10:00:00Z",
    }


def test_without_the_co_owner_column() -> None:
    returned = read_packet(write_packet(make_packet(co_owners=False)), "p.xlsx")
    assert "Co-owners" not in returned.headers
    assert returned.headers == [h for h in HEADERS if h != "Co-owners"]
    assert len(returned.rows) == 3


def test_empty_packet_and_empty_due() -> None:
    data = write_packet(make_packet(0, due=""))
    returned = read_packet(data, "p.xlsx")
    assert returned.rows == []
    assert returned.about["Due"] == ""
    assert returned.about["Rows"] == "0"
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        sheet = archive.read("xl/worksheets/sheet1.xml").decode()
    assert 'sqref="A2:A2"' in sheet


def test_constants() -> None:
    assert DECISIONS == ("Keep", "Remove", "Unsure")
    assert HEADERS[:2] == ("Decision", "Comment")
    assert HEADERS[-2:] == ("Row ID", "Row check")


# ----------------------------------------------------------------------- written package


def parts_of(data: bytes) -> dict[str, bytes]:
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        return {n: archive.read(n) for n in archive.namelist()}


def test_every_part_is_well_formed_and_listed() -> None:
    parts = parts_of(write_packet(make_packet()))
    assert list(parts) == [
        "[Content_Types].xml",
        "_rels/.rels",
        "docProps/core.xml",
        "docProps/app.xml",
        "xl/workbook.xml",
        "xl/_rels/workbook.xml.rels",
        "xl/styles.xml",
        "xl/worksheets/sheet1.xml",
        "xl/worksheets/sheet2.xml",
    ]
    for content in parts.values():
        ET.fromstring(content)  # noqa: S314 - our own output
    overrides = re.findall(rb'PartName="/([^"]+)"', parts["[Content_Types].xml"])
    assert sorted(o.decode() for o in overrides) == sorted(
        n
        for n in parts
        if n not in {"[Content_Types].xml", "_rels/.rels", "xl/_rels/workbook.xml.rels"}
    )


def test_review_sheet_structure_and_element_order() -> None:
    sheet = parts_of(write_packet(make_packet()))["xl/worksheets/sheet1.xml"]
    root = ET.fromstring(sheet)  # noqa: S314
    order = [child.tag.split("}")[1] for child in root]
    assert order == [
        "sheetPr",
        "dimension",
        "sheetViews",
        "sheetFormatPr",
        "cols",
        "sheetData",
        "sheetProtection",
        "autoFilter",
        "dataValidations",
        "pageMargins",
        "pageSetup",
    ]
    assert root.find("m:dimension", NS).get("ref") == "A1:M4"  # type: ignore[union-attr]
    pane = root.find("m:sheetViews/m:sheetView/m:pane", NS)
    assert pane is not None
    assert (pane.get("ySplit"), pane.get("state")) == ("1", "frozen")
    protection = root.find("m:sheetProtection", NS)
    assert protection is not None
    assert protection.get("sheet") == "1"
    assert protection.get("autoFilter") == "0"
    assert protection.get("sort") == "0"
    assert protection.get("password") is None
    assert root.find("m:autoFilter", NS).get("ref") == "A1:M4"  # type: ignore[union-attr]
    validation = root.find("m:dataValidations/m:dataValidation", NS)
    assert validation is not None
    assert validation.get("type") == "list"
    assert validation.get("sqref") == "A2:A4"
    assert validation.get("showErrorMessage") == "1"
    assert validation.get("errorStyle") == "stop"
    assert validation.find("m:formula1", NS).text == '"Keep,Remove,Unsure"'  # type: ignore[union-attr]
    cols = root.findall("m:cols/m:col", NS)
    assert [c.get("hidden") for c in cols] == [None] * 11 + ["1", "1"]
    assert all(c.get("width") and c.get("customWidth") == "1" for c in cols)


def test_only_decision_and_comment_cells_are_unlocked() -> None:
    parts = parts_of(write_packet(make_packet()))
    styles = ET.fromstring(parts["xl/styles.xml"])  # noqa: S314
    xfs = styles.findall("m:cellXfs/m:xf", NS)
    unlocked = {
        i
        for i, xf in enumerate(xfs)
        if xf.find("m:protection", NS).get("locked") == "0"  # type: ignore[union-attr]
    }
    assert len(unlocked) == 1
    assert xfs[0].find("m:protection", NS).get("locked") == "1"  # type: ignore[union-attr]
    sheet = ET.fromstring(parts["xl/worksheets/sheet1.xml"])  # noqa: S314
    for row in sheet.findall("m:sheetData/m:row", NS)[1:]:
        for cell in row:
            column = re.match(r"[A-Z]+", cell.get("r", "")).group()  # type: ignore[union-attr]
            assert (int(cell.get("s", "0")) in unlocked) == (column in {"A", "B"})
    header_style = xfs[1]
    assert header_style.find("m:alignment", NS).get("wrapText") == "1"  # type: ignore[union-attr]


def test_workbook_defined_name_and_sheets() -> None:
    workbook = ET.fromstring(parts_of(write_packet(make_packet()))["xl/workbook.xml"])  # noqa: S314
    sheets = [(s.get("name"), s.get("sheetId")) for s in workbook.findall("m:sheets/m:sheet", NS)]
    assert sheets == [("Review", "1"), ("About", "2")]
    name = workbook.find("m:definedNames/m:definedName", NS)
    assert name is not None
    assert name.get("name") == "_xlnm._FilterDatabase"
    assert name.get("hidden") == "1"
    assert name.text == "Review!$A$1:$M$4"


def test_cells_are_inline_strings_never_formulas() -> None:
    risky = make_row(0, user='=HYPERLINK("http://192.0.2.1")', comment="@SUM(1)", account="+1")
    parts = parts_of(write_packet(make_packet(rows=[risky])))
    sheet = parts["xl/worksheets/sheet1.xml"].decode()
    assert "<f>" not in sheet
    assert "<f " not in sheet
    assert 't="s"' not in sheet
    assert "sharedStrings" not in parts["[Content_Types].xml"].decode()
    returned = read_packet(write_packet(make_packet(rows=[risky])), "p.xlsx")
    assert returned.rows[0].values["User"] == risky.user
    assert returned.rows[0].notes == []


# --------------------------------------------------------------------- reproducibility


def test_same_input_same_bytes() -> None:
    assert write_packet(make_packet()) == write_packet(make_packet())


def test_zip_dates_come_from_created_at_and_order_is_fixed() -> None:
    data = write_packet(make_packet(created_at="2026-11-12T10:30:44Z"))
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        dates = {info.date_time for info in archive.infolist()}
        kinds = {info.compress_type for info in archive.infolist()}
    assert dates == {(2026, 11, 12, 10, 30, 44)}
    assert kinds == {zipfile.ZIP_DEFLATED}


def test_different_created_at_changes_the_file_and_epoch_is_clamped() -> None:
    assert write_packet(make_packet()) != write_packet(
        make_packet(created_at="2026-11-13T10:00:00Z")
    )
    old = write_packet(make_packet(created_at="1970-01-01T00:00:00Z"))
    with zipfile.ZipFile(io.BytesIO(old)) as archive:
        assert archive.infolist()[0].date_time == (1980, 1, 1, 0, 0, 0)


def test_naive_and_offset_times() -> None:
    naive = write_packet(make_packet(created_at="2026-11-12T10:00:00"))
    assert naive == write_packet(make_packet())
    offset = write_packet(make_packet(created_at="2026-11-12T12:00:00+02:00"))
    assert offset == write_packet(make_packet())


def test_bad_created_at_is_a_value_error() -> None:
    with pytest.raises(ValueError, match="ISO 8601"):
        write_packet(make_packet(created_at="yesterday"))


# ---------------------------------------------------------------------- text handling


def test_forbidden_characters_are_replaced_and_noted() -> None:
    row = make_row(0, user="a\x00b\x0bc\ud800d￾e")
    data, notes = write_packet_with_notes(make_packet(rows=[row]))
    assert notes == ["Review row 2, User: replaced 4 character(s) XML does not allow with U+FFFD"]
    returned = read_packet(data, "p.xlsx")
    assert returned.rows[0].values["User"] == "a�b�c�d�e"


def test_forbidden_characters_in_about_and_title_are_noted() -> None:
    packet = make_packet(campaign_name="Q4\x01", reviewer_name="Pat\x02")
    data, notes = write_packet_with_notes(packet)
    assert any(n.startswith("About Campaign:") for n in notes)
    assert any(n.startswith("About Reviewer:") for n in notes)
    assert any(n.startswith("Document title:") for n in notes)
    ET.fromstring(parts_of(data)["docProps/core.xml"])  # noqa: S314


def test_line_breaks_are_normalized() -> None:
    assert cell_text("a\r\nb\rc\nd") == ("a\nb\nc\nd", [])


def test_long_text_is_cut_with_a_marker() -> None:
    row = make_row(0, comment="x" * 40_000)
    data, notes = write_packet_with_notes(make_packet(rows=[row]))
    assert notes == ["Review row 2, Comment: cut to Excel's limit of 32767 characters"]
    text = read_packet(data, "p.xlsx").rows[0].values["Comment"]
    assert len(text) == 32_767
    assert text.endswith(" [truncated]")


def test_text_exactly_at_the_limit_is_kept() -> None:
    assert cell_text("y" * 32_767) == ("y" * 32_767, [])
    assert cell_text("y" * 32_768)[1]


def test_truncation_counts_utf16_units() -> None:
    text, changes = cell_text("\U0001f600" * 20_000)
    assert changes
    assert len(text.encode("utf-16-le")) // 2 <= 32_767
    assert text.endswith(" [truncated]")


def test_whitespace_and_escape_lookalikes_survive() -> None:
    row = make_row(0, user="  padded  ", account="_x0041_ and _x005F_", comment="a&b <c> \"d\" 'e'")
    returned = read_packet(write_packet(make_packet(rows=[row])), "p.xlsx")
    values = returned.rows[0].values
    assert values["User"] == "  padded  "
    assert values["Account"] == "_x0041_ and _x005F_"
    assert values["Comment"] == "a&b <c> \"d\" 'e'"


_text = st.text(
    alphabet=st.characters(blacklist_categories=("Cs",), blacklist_characters="\r"), max_size=40
)


@settings(max_examples=60, deadline=None)
@given(user=_text, comment=_text)
def test_round_trip_property(user: str, comment: str) -> None:
    row = make_row(0, user=user, comment=comment)
    returned = read_packet(write_packet(make_packet(1, rows=[row])), "p.xlsx")
    assert returned.rows
    values = returned.rows[0].values
    assert values["User"] == cell_text(user)[0]
    assert values["Comment"] == cell_text(comment)[0]


@settings(max_examples=40, deadline=None)
@given(st.binary(max_size=200))
def test_arbitrary_bytes_only_raise_input_error(data: bytes) -> None:
    with contextlib.suppress(InputError):
        read_packet(data, "x.xlsx")


# ------------------------------------------------------------------- reader: rejections


def rejects(data: bytes, match: str) -> None:
    with pytest.raises(InputError, match=match) as info:
        read_packet(data, "returned.xlsx")
    assert "returned.xlsx" in str(info.value)


def test_not_a_workbook() -> None:
    rejects(b"hello", "not an Excel workbook")
    rejects(b"", "not an Excel workbook")


def test_encrypted_or_old_workbooks_are_ole_files() -> None:
    rejects(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 100, "password-protected")


def test_too_many_entries(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(xlsx, "MAX_ZIP_ENTRIES", 3)
    rejects(write_packet(make_packet()), "more than 3 entries")


def test_exactly_the_entry_limit_is_fine(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(xlsx, "MAX_ZIP_ENTRIES", 9)
    assert read_packet(write_packet(make_packet()), "p.xlsx").rows


def test_too_large_when_expanded(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(xlsx, "MAX_UNCOMPRESSED_BYTES", 1000)
    rejects(write_packet(make_packet()), "expands to more than 1000 bytes")


def test_zip_bomb_ratio() -> None:
    bomb = build_zip({"a.xml": b"\x00" * 5_000_000})
    rejects(bomb, "expands more than 200 to 1")


def test_ratio_just_inside_the_limit_is_fine() -> None:
    parts = replaced_parts(write_packet(make_packet()))
    parts["xl/extra.bin"] = secrets.token_bytes(500)
    assert read_packet(build_zip(parts), "p.xlsx").rows


def test_duplicate_entry_names() -> None:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("a", b"1")
        with pytest.warns(UserWarning, match="Duplicate name"):
            archive.writestr("a", b"2")
    rejects(buffer.getvalue(), "same entry name twice")


def test_encrypted_entry_flag() -> None:
    data = bytearray(write_packet(make_packet()))
    # Set the encryption bit (bit 0 of the general purpose flag) in the central directory
    # entry for xl/workbook.xml.
    directory = data.index(b"PK\x01\x02", data.index(b"xl/workbook.xml") - 100)
    assert data[directory + 46 : directory + 46 + 3] != b""
    index = 0
    while (index := data.find(b"PK\x01\x02", index)) != -1:
        name_length = int.from_bytes(data[index + 28 : index + 30], "little")
        name = bytes(data[index + 46 : index + 46 + name_length])
        if name == b"xl/workbook.xml":
            data[index + 8] |= 1
        index += 1
    rejects(bytes(data), "is encrypted")


def test_corrupt_compressed_data() -> None:
    data = bytearray(write_packet(make_packet()))
    start = data.index(b"xl/workbook.xml") + len(b"xl/workbook.xml")
    for i in range(start, start + 20):
        data[i] ^= 0xFF
    rejects(bytes(data), "cannot be decompressed|not safe XML|no workbook")


def test_unsupported_compression_method() -> None:
    data = bytearray(write_packet(make_packet()))
    index = 0
    while (index := data.find(b"PK\x01\x02", index)) != -1:
        name_length = int.from_bytes(data[index + 28 : index + 30], "little")
        if bytes(data[index + 46 : index + 46 + name_length]) == b"xl/workbook.xml":
            data[index + 10] = 99
        index += 1
    rejects(bytes(data), "cannot be decompressed")


def test_missing_part_listed_in_relationships() -> None:
    parts = replaced_parts(write_packet(make_packet()))
    del parts["xl/workbook.xml"]
    rejects(build_zip(parts), "no workbook part")


def test_no_relationships_at_all() -> None:
    parts = replaced_parts(write_packet(make_packet()))
    del parts["_rels/.rels"]
    rejects(build_zip(parts), "no workbook part")


def test_missing_review_or_about_sheet() -> None:
    parts = replaced_parts(write_packet(make_packet()))
    workbook = parts["xl/workbook.xml"].decode()  # type: ignore[union-attr]
    rejects(
        build_zip({**parts, "xl/workbook.xml": workbook.replace('name="Review"', 'name="Data"')}),
        "'Review'",
    )
    rejects(
        build_zip({**parts, "xl/workbook.xml": workbook.replace('name="About"', 'name="Info"')}),
        "'About'",
    )


def test_sheet_with_a_missing_part_or_wrong_relationship_is_not_found() -> None:
    parts = replaced_parts(write_packet(make_packet()))
    gone = {k: v for k, v in parts.items() if k != "xl/worksheets/sheet2.xml"}
    rejects(build_zip(gone), "'About'")
    rels = parts["xl/_rels/workbook.xml.rels"].decode()  # type: ignore[union-attr]
    wrong = rels.replace('/worksheet"', '/chartsheet"', 1)
    rejects(build_zip({**parts, "xl/_rels/workbook.xml.rels": wrong}), "'Review'")
    unknown = parts["xl/workbook.xml"].decode().replace('r:id="rId1"', 'r:id="rId99"')  # type: ignore[union-attr]
    rejects(build_zip({**parts, "xl/workbook.xml": unknown}), "'Review'")


def test_workbook_without_a_sheets_element() -> None:
    parts = replaced_parts(write_packet(make_packet()))
    parts["xl/workbook.xml"] = f'<workbook xmlns="{NS["m"]}"/>'
    rejects(build_zip(parts), "'Review'")


def test_missing_row_id_header() -> None:
    packet = make_packet()
    parts = replaced_parts(write_packet(packet))
    sheet = parts["xl/worksheets/sheet1.xml"].decode()  # type: ignore[union-attr]
    parts["xl/worksheets/sheet1.xml"] = sheet.replace("Row ID", "Identifier")
    rejects(build_zip(parts), "no 'Row ID' header")


def test_sheet_without_sheet_data_has_no_header() -> None:
    parts = replaced_parts(write_packet(make_packet()))
    parts["xl/worksheets/sheet1.xml"] = f'<worksheet xmlns="{NS["m"]}"/>'
    rejects(build_zip(parts), "no 'Row ID' header")


def test_unsafe_xml_is_refused() -> None:
    parts = replaced_parts(write_packet(make_packet()))
    parts["xl/worksheets/sheet1.xml"] = (
        f'<!DOCTYPE worksheet [<!ENTITY x "boom">]><worksheet xmlns="{NS["m"]}">&x;</worksheet>'
    )
    rejects(build_zip(parts), "not safe XML")


def test_relationship_escaping_the_package() -> None:
    parts = replaced_parts(write_packet(make_packet()))
    rels = parts["_rels/.rels"].decode().replace('Target="xl/workbook.xml"', 'Target="../../etc/x"')  # type: ignore[union-attr]
    rejects(build_zip({**parts, "_rels/.rels": rels}), "outside the package")
    rels = parts["_rels/.rels"].decode().replace('Target="xl/workbook.xml"', 'Target="/"')  # type: ignore[union-attr]
    rejects(build_zip({**parts, "_rels/.rels": rels}), "outside the package")


def test_row_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(xlsx, "MAX_ROWS", 14)
    assert len(read_packet(write_packet(make_packet(13)), "p.xlsx").rows) == 13
    rejects(write_packet(make_packet(14)), "more than 14 rows")


def sheet_with(rows: str) -> str:
    return f'<worksheet xmlns="{NS["m"]}"><sheetData>{rows}</sheetData></worksheet>'


@pytest.mark.parametrize(
    ("cell_xml", "match"),
    [
        ('<c r="not-a-ref"><v>1</v></c>', "invalid reference"),
        ('<c r="A0"><v>1</v></c>', "invalid reference|outside the sheet"),
        ('<c r="XFE1"><v>1</v></c>', "outside the sheet"),
        ('<c r="A1048577"><v>1</v></c>', "outside the sheet"),
        ('<c r="A7"><v>1</v></c>', "sits in row 1"),
        ('<c r="A1"><v>1</v></c><c r="A1"><v>2</v></c>', "twice"),
    ],
)
def test_bad_cell_references(cell_xml: str, match: str) -> None:
    parts = replaced_parts(write_packet(make_packet()))
    parts["xl/worksheets/sheet1.xml"] = sheet_with(f'<row r="1">{cell_xml}</row>')
    rejects(build_zip(parts), match)


def test_too_many_cells_in_a_row(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(xlsx, "_MAX_SHEET_COLUMN", 3)
    parts = replaced_parts(write_packet(make_packet()))
    cells = "<c><v>1</v></c>" * 4
    parts["xl/worksheets/sheet1.xml"] = (
        f'<worksheet xmlns="{NS["m"]}"><sheetData><row r="1">{cells}</row></sheetData></worksheet>'
    )
    rejects(build_zip(parts), "more cells than a sheet can hold")


@pytest.mark.parametrize("row", ['r="abc"', 'r="0"', 'r="1048577"'])
def test_bad_row_numbers(row: str) -> None:
    parts = replaced_parts(write_packet(make_packet()))
    parts["xl/worksheets/sheet1.xml"] = sheet_with(f"<row {row}><c><v>1</v></c></row>")
    rejects(build_zip(parts), "row")


# --------------------------------------------------------- reader: Excel-style workbook

WORKBOOK = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"
 xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
<sheets>
<sheet name="about" sheetId="7" r:id="rId9"/>
<sheet name="REVIEW" sheetId="3" r:id="rId4"/>
</sheets>
</workbook>"""

WORKBOOK_RELS = """<?xml version="1.0" encoding="UTF-8"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1"
Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles"
Target="styles.xml"/>
<Relationship Id="rId4"
Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet"
Target="worksheets/data-sheet.xml"/>
<Relationship Id="rId9"
Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet"
Target="/xl/worksheets/notes.xml"/>
<Relationship Id="rId11"
Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/sharedStrings"
Target="sharedStrings.xml"/>
<Relationship Id="rId12"
Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink"
Target="http://192.0.2.1/" TargetMode="External"/>
<Relationship Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/theme"
Target="theme/theme1.xml"/>
</Relationships>"""

ROOT_RELS = """<?xml version="1.0" encoding="UTF-8"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId3"
Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties"
Target="docProps/app.xml"/>
<Relationship Id="rId2"
Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties"
Target="docProps/core.xml"/>
<Relationship Id="rId1"
Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument"
Target="xl/workbook.xml"/>
</Relationships>"""

SHARED = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" count="14" uniqueCount="14">
<si><t>Row ID</t></si>
<si><t>Decision</t></si>
<si><t>Comment</t></si>
<si><t>User</t></si>
<si><t>Keep</t></si>
<si>
<r>
<rPr>
<b/>
<sz val="11"/>
</rPr>
<t xml:space="preserve">Needs </t>
</r>
<r>
<rPr>
<i/>
</rPr>
<t>review</t>
</r>
<rPh sb="0" eb="1">
<t>IGNORED</t>
</rPh>
</si>
<si><t>R000000000001</t></si>
<si><t>R000000000002</t></si>
<si><t>Avery Example</t></si>
<si><t xml:space="preserve"> Remove </t></si>
<si><t>_x0041_bc_x000D_x_x0001_</t></si>
<si><t>Campaign</t></si>
<si><t>Q4 review</t></si>
<si><t>Campaign ID</t></si>
</sst>"""

# Columns are moved (Row ID first, then User, Decision, Comment), rows are out of order,
# one row has no r=, cells in a row have no r=, one cell is a formula with a cached value.
REVIEW = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
<sheetData>
<row r="4">
<c r="A4" t="s">
<v>7</v>
</c>
<c r="B4" t="s">
<v>8</v>
</c>
<c r="C4" t="s">
<v>9</v>
</c>
<c r="D4" t="s">
<v>10</v>
</c>
</row>
<row>
<c t="s">
<v>6</v>
</c>
<c t="inlineStr">
<is>
<r>
<t>Inline </t>
</r>
<r>
<t>run</t>
</r>
</is>
</c>
<c t="b">
<v>1</v>
</c>
</row>
<row r="1">
<c r="A1" t="s">
<v>0</v>
</c>
<c r="B1" t="s">
<v>3</v>
</c>
<c r="C1" t="s">
<v>1</v>
</c>
<c r="D1" t="s">
<v>2</v>
</c>
</row>
<row r="3">
<c r="A3" t="s">
<v>6</v>
</c>
<c r="B3" t="s">
<v>8</v>
</c>
<c r="C3" t="str">
<f>"Keep"</f>
<v>Keep</v>
</c>
<c r="D3" t="s">
<v>5</v>
</c>
</row>
<row r="2">
<c r="A2" t="s">
<v>99</v>
</c>
<c r="B2" t="n">
<v>1.5</v>
</c>
<c r="C2">
<f>A1&amp;B1</f>
</c>
<c r="D2" t="b">
<v>0</v>
</c>
<c r="E2" t="e">
<v>#N/A</v>
</c>
<c r="F2" t="d">
<v>2026-01-01</v>
</c>
</row>
<row r="6"/>
<row r="7"><c r="A7" t="inlineStr"/></row>
</sheetData>
</worksheet>"""

ABOUT = """<?xml version="1.0" encoding="UTF-8"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
<sheetData>
<row r="3">
<c r="A3" t="inlineStr">
<is>
<t>  Instructions  </t>
</is>
</c>
<c r="B3" t="inlineStr">
<is>
<t>Choose.</t>
</is>
</c>
</row>
<row r="1"><c r="A1" t="s"><v>11</v></c><c r="B1" t="s"><v>12</v></c></row>
<row r="2"><c r="A2" t="s"><v>13</v></c><c r="B2"><f>1+1</f><v>2</v></c></row>
<row r="4">
<c r="A4" t="inlineStr">
<is>
<t>After</t>
</is>
</c>
<c r="B4" t="inlineStr">
<is>
<t>x</t>
</is>
</c>
</row>
<row r="0x"/>
</sheetData>
</worksheet>""".replace('<row r="0x"/>', "")

CORE = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<cp:coreProperties
xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties"
 xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/"
 xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
<dc:creator>shaar</dc:creator><cp:lastModifiedBy>Someone Example</cp:lastModifiedBy>
<dcterms:created xsi:type="dcterms:W3CDTF">2026-11-12T10:00:00Z</dcterms:created>
<dcterms:modified xsi:type="dcterms:W3CDTF">2026-11-14T09:30:00Z</dcterms:modified>
<dc:title>ignored</dc:title>
</cp:coreProperties>"""


def excel_style(**overrides: str | None) -> bytes:
    parts: dict[str, bytes | str] = {
        "[Content_Types].xml": "<Types/>",
        "_rels/.rels": ROOT_RELS,
        "docProps/core.xml": CORE,
        "xl/workbook.xml": WORKBOOK,
        "xl/_rels/workbook.xml.rels": WORKBOOK_RELS,
        "xl/sharedStrings.xml": SHARED,
        "xl/worksheets/data-sheet.xml": REVIEW,
        "xl/worksheets/notes.xml": ABOUT,
    }
    for name, content in overrides.items():
        key = name.replace("__", "/")
        if content is None:
            del parts[key]
        else:
            parts[key] = content
    return build_zip(parts)


def test_excel_style_workbook() -> None:
    returned = read_packet(excel_style(), "excel.xlsx")
    assert returned.headers == ["Row ID", "User", "Decision", "Comment"]
    by_row = {r.row: r for r in returned.rows}
    assert sorted(by_row) == [2, 3, 4, 5]
    # Row 4: shared strings, a leading/trailing-space decision is kept as written.
    assert by_row[4].values["Row ID"] == "R000000000002"
    assert by_row[4].values["User"] == "Avery Example"
    assert by_row[4].values["Decision"] == " Remove "
    assert by_row[4].values["Comment"].startswith("Abc\r")
    assert "�" in by_row[4].values["Comment"]
    # Row 3: rich text runs are joined, phonetic text is dropped, formula has a cached value.
    assert by_row[3].values["Comment"] == "Needs review"
    assert by_row[3].values["Decision"] == "Keep"
    assert by_row[3].notes == ["Decision held a formula"]
    # Row 5 has no r= on the row or its cells: it is the row after row 4's predecessor...
    assert by_row[5].values["Row ID"] == "R000000000001"
    assert by_row[5].values["User"] == "Inline run"
    # Row 2: bad shared string index, number, formula without a cached value, bool.
    assert by_row[2].values["Row ID"] == ""
    assert by_row[2].values["User"] == "1.5"
    assert by_row[2].values["Decision"] == ""
    assert by_row[2].values["Comment"] == "FALSE"
    assert "Row ID pointed to a shared string that does not exist" in by_row[2].notes
    assert "Decision held a formula with no saved result" in by_row[2].notes
    assert returned.about == {"Campaign": "Q4 review", "Campaign ID": "2"}
    assert returned.notes == ["About Campaign ID held a formula"]
    assert returned.core == {
        "creator": "shaar",
        "lastModifiedBy": "Someone Example",
        "modified": "2026-11-14T09:30:00Z",
    }


def swap_cell(xml: str, ref: str, text: str) -> str:
    pattern = re.compile(rf'<c r="{ref}"[^>]*>.*?</c>', re.DOTALL)
    new = f'<c r="{ref}" t="inlineStr"><is><t xml:space="preserve">{text}</t></is></c>'
    assert pattern.search(xml)
    return pattern.sub(new, xml, count=1)


def test_headers_are_matched_loosely_and_duplicates_noted() -> None:
    review = swap_cell(REVIEW, "C1", " row id ")
    data = excel_style(**{"xl/worksheets/data-sheet.xml": review})
    result = read_packet(data, "x.xlsx")
    assert result.headers == ["Row ID", "User", "Comment"]
    assert any("repeats the header 'Row ID'" in n for n in result.notes)


def test_blank_header_cells_are_skipped() -> None:
    review = swap_cell(REVIEW, "D1", "  ")
    result = read_packet(excel_style(**{"xl/worksheets/data-sheet.xml": review}), "x.xlsx")
    assert result.headers == ["Row ID", "User", "Decision"]


def test_no_core_properties_or_no_shared_strings() -> None:
    no_core = excel_style(**{"docProps/core.xml": None})
    assert read_packet(no_core, "x.xlsx").core == {}
    rels_without_core = ROOT_RELS.replace("core-properties", "something-else")
    assert read_packet(excel_style(**{"_rels/.rels": rels_without_core}), "x.xlsx").core == {}
    # Without the shared strings part, the header text cannot be found.
    rejects(excel_style(**{"xl/sharedStrings.xml": None}), "no 'Row ID' header")


def test_unreadable_core_properties_are_noted_not_fatal() -> None:
    result = read_packet(excel_style(**{"docProps/core.xml": "<cp:oops"}), "x.xlsx")
    assert result.core == {}
    assert "docProps/core.xml could not be read" in result.notes


def test_no_workbook_relationships_part_means_no_sheets() -> None:
    rejects(excel_style(**{"xl/_rels/workbook.xml.rels": None}), "'Review'")


def test_package_files_found_through_the_workbook_not_by_name() -> None:
    # The reader must not read xl/worksheets/sheet1.xml just because the name matches.
    parts: dict[str, bytes | str] = {
        "_rels/.rels": ROOT_RELS,
        "xl/workbook.xml": WORKBOOK,
        "xl/_rels/workbook.xml.rels": WORKBOOK_RELS,
        "xl/sharedStrings.xml": SHARED,
        "xl/worksheets/data-sheet.xml": REVIEW,
        "xl/worksheets/notes.xml": ABOUT,
        "xl/worksheets/sheet1.xml": "<not xml",
    }
    assert read_packet(build_zip(parts), "x.xlsx").headers


def test_strict_namespace_relationship_ids() -> None:
    strict = WORKBOOK.replace(
        "http://schemas.openxmlformats.org/officeDocument/2006/relationships",
        "http://purl.oclc.org/ooxml/officeDocument/relationships",
    )
    assert read_packet(excel_style(**{"xl/workbook.xml": strict}), "x.xlsx").rows


def test_sheet_names_may_be_duplicated_first_wins() -> None:
    workbook = WORKBOOK.replace(
        "</sheets>", '<sheet name="Review" sheetId="9" r:id="rId9"/></sheets>'
    )
    assert read_packet(excel_style(**{"xl/workbook.xml": workbook}), "x.xlsx").rows


# ------------------------------------------------------------------------- consumers


def test_about_stops_at_instructions_and_ignores_blank_labels() -> None:
    result = read_packet(write_packet(make_packet()), "p.xlsx")
    assert "After" not in result.about
    assert all(not key.startswith("Choose") for key in result.about)


# ------------------------------------------------------------------ other applications

SYSTEM_PYTHON = "/usr/bin/python3"


def test_openpyxl_opens_the_workbook(tmp_path: Path) -> None:
    if not Path(SYSTEM_PYTHON).exists():
        pytest.skip("the system python is not available")
    probe = subprocess.run(  # noqa: S603
        [SYSTEM_PYTHON, "-c", "import openpyxl"], capture_output=True, check=False
    )
    if probe.returncode != 0:
        pytest.skip("openpyxl is not installed for the system python")
    path = tmp_path / "packet.xlsx"
    path.write_bytes(write_packet(make_packet()))
    script = (
        "import sys, openpyxl\n"
        "wb = openpyxl.load_workbook(sys.argv[1])\n"
        "ws = wb['Review']\n"
        "assert wb.sheetnames == ['Review', 'About']\n"
        "assert ws.max_row == 4 and ws.max_column == 13\n"
        "assert ws.freeze_panes == 'A2'\n"
        "assert ws.protection.sheet\n"
        "assert ws.auto_filter.ref == 'A1:M4'\n"
        "assert ws['A1'].value == 'Decision' and ws['L2'].value == 'R000000000000'\n"
        "assert ws.column_dimensions['L'].hidden\n"
        "assert ws['A2'].protection.locked is False and ws['C2'].protection.locked\n"
        "dv = ws.data_validations.dataValidation[0]\n"
        "assert dv.type == 'list' and str(dv.sqref) == 'A2:A4'\n"
        "assert dv.formula1 == '\"Keep,Remove,Unsure\"'\n"
    )
    result = subprocess.run(  # noqa: S603
        [SYSTEM_PYTHON, "-c", script, str(path)], capture_output=True, text=True, check=False
    )
    assert result.returncode == 0, result.stderr


@pytest.mark.skipif(
    shutil.which("soffice") is None, reason="LibreOffice (soffice) is not installed"
)
def test_libreoffice_round_trip(tmp_path: Path) -> None:
    rows = [make_row(i) for i in range(4)]
    rows[1] = make_row(1, granted_through="Tier0 Admins\nServer Ops", user="Zoë 中")
    rows[2] = make_row(2, decision="Remove", comment="Left the team")
    packet = make_packet(rows=rows)
    source = tmp_path / "packet.xlsx"
    source.write_bytes(write_packet(packet))
    out = tmp_path / "out"
    profile = f"file:///tmp/shaar-lo-{secrets.token_hex(6)}"
    soffice = shutil.which("soffice")
    assert soffice is not None
    try:
        done = subprocess.run(  # noqa: S603
            [
                soffice,
                "--headless",
                f"-env:UserInstallation={profile}",
                "--convert-to",
                "xlsx",
                "--outdir",
                str(out),
                str(source),
            ],
            capture_output=True,
            text=True,
            timeout=180,
            check=False,
        )
    finally:
        shutil.rmtree(profile.removeprefix("file://"), ignore_errors=True)
    converted = out / "packet.xlsx"
    assert converted.exists(), done.stdout + done.stderr
    data = converted.read_bytes()
    returned = read_packet(data, "converted.xlsx")
    assert [r.row for r in returned.rows] == [2, 3, 4, 5]
    for original, got in zip(rows, returned.rows, strict=True):
        assert got.values["Row ID"] == original.row_id
        assert got.values["Row check"] == original.row_check
        assert got.values["User"] == original.user
        assert got.values["Granted through"] == original.granted_through
        assert got.values["Decision"] == original.decision
        assert got.values["Comment"] == original.comment
        assert got.notes == []
    assert returned.about["Campaign ID"] == packet.campaign_id
    assert returned.about["Packet digest"] == packet.packet_digest
    assert returned.about["Reviewer email"] == packet.reviewer_email
    assert returned.about["Rows"] == "4"
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        names = archive.namelist()
        sheets = sorted(n for n in names if n.startswith("xl/worksheets/sheet"))
        review = archive.read(sheets[0]).decode()
    assert "<sheetProtection" in review
    assert 'sheet="true"' in review or 'sheet="1"' in review
    assert "<dataValidation " in review
    assert "Keep,Remove,Unsure" in review
    assert "<autoFilter" in review
    assert 'state="frozen"' in review


def test_sheet_without_a_relationship_id_is_not_found() -> None:
    workbook = WORKBOOK.replace(' r:id="rId4"', "")
    rejects(excel_style(**{"xl/workbook.xml": workbook}), "'Review'")


def test_about_without_an_instructions_row() -> None:
    about = ABOUT.replace("Instructions", "Notes")
    result = read_packet(excel_style(**{"xl/worksheets/notes.xml": about}), "x.xlsx")
    assert result.about["Notes"] == "Choose."
    assert result.about["After"] == "x"
