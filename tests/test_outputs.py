# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""Tests for the report document, its renderers, the schemas and the writer."""

from __future__ import annotations

import csv
import dataclasses
import hashlib
import io
import json
import os
import re
from datetime import UTC, datetime, timedelta, timezone
from html.parser import HTMLParser
from pathlib import Path
from typing import TYPE_CHECKING, Any

import jsonschema
import pytest

from faithful_shaar.errors import UsageError
from faithful_shaar.model import InputFile, Problem, Source
from faithful_shaar.outputs.columns import SECTION_COLUMNS
from faithful_shaar.outputs.document import (
    Column,
    Document,
    Row,
    Section,
    cell_text,
    format_time,
    generated_now,
)
from faithful_shaar.outputs.files import OutputError
from faithful_shaar.outputs.render import (
    CSP,
    _md_block,
    build_manifest,
    render_all,
    render_csv,
    render_html,
    render_json,
    render_markdown,
    write_outputs,
)
from faithful_shaar.outputs.safety import escape_markdown
from faithful_shaar.outputs.schema import SCHEMA_NAMES, generate_schema, schema_id
from faithful_shaar.schema import SCHEMA_NAMES as SHIPPED_NAMES
from faithful_shaar.schema import schema_text

if TYPE_CHECKING:
    from collections.abc import Callable

WHEN = "2026-11-12T10:20:30Z"
HOSTILE = [
    "<script>alert(1)</script>",
    '"><img src=x onerror=alert(1)>',
    "<a href='javascript:alert(1)'>x</a>",
    "&lt;b&gt; &amp; &#x3c;",
    "# Heading\n| a | b |\n|---|---|\n- item\n> quote\n```\ncode\n```",
    "[click](http://evil.invalid/x) ![i](http://evil.invalid/i.png)",
    "http://evil.invalid www.evil.invalid avery@corp.example",
    '=HYPERLINK("http://evil.invalid","x")',
    "+1+1",
    "-2+3",
    "@SUM(A1)",
    "\t=1",
    "\uff1dcmd",
    "line1\nline2\r\nline3\rline4",
    "nul\x00 esc\x1b[31m bell\x07 del\x7f",
    "bidi \u202e reversed \u2066 iso",
    "zero\u200bwidth\u200d joiner \ufeff bom",
    "lone \udc80 surrogate",
    "tag\U000e0041\U000e0042 sel\ufe0f",
    "A" * 20_000,
    "\U0001f600 \u65e5\u672c \u041f\u0440",
    " leading and trailing ",
    "1. ordered",
    "2) ordered",
    "    indented code",
    "---",
    "+ plus",
    "=== title",
    "- item # trailing #",
]
INPUTS = [InputFile("ad-export.jsonl", "shaar export", 123, "a" * 64)]


def hostile_row(columns: tuple[Column, ...], i: int) -> Row:
    """A row with hostile text in every field."""
    row: Row = {}
    for n, column in enumerate(columns):
        value = HOSTILE[(i + n) % len(HOSTILE)]
        row[column.key] = [value, HOSTILE[(i + n + 1) % len(HOSTILE)]] if n % 5 == 4 else value
    return row


def make_doc(
    kind: str = "campaign", *, rows: int = 3, hostile: bool = True, empty: bool = False
) -> Document:
    sections = []
    for key, columns in SECTION_COLUMNS[kind].items():
        data: list[Row] = []
        if not empty:
            for i in range(rows):
                if hostile:
                    data.append(hostile_row(columns, i))
                else:
                    data.append({c.key: f"{c.key} {i}" for c in columns})
        sections.append(
            Section(
                key=key,
                title=f"Title of {key}",
                intro=HOSTILE[0] if hostile else f"About {key}.",
                columns=columns,
                rows=data,
                empty=f"No {key} found." if not hostile else HOSTILE[1],
                citations=columns[-1].key,
            )
        )
    return Document(
        kind=kind,
        title=HOSTILE[2] if hostile else f"A {kind} report",
        headline=HOSTILE[4] if hostile else "3 access entries for 1 reviewer.",
        facts=[("Campaign", HOSTILE[5]), (HOSTILE[0], HOSTILE[6])] if hostile else [("A", "b")],
        counts=[("Entries", 3), (HOSTILE[7], 0)] if hostile else [("Entries", 3)],
        sections=sections,
        problems=(
            [
                Problem(Source(HOSTILE[3], HOSTILE[13]), HOSTILE[14]),
                Problem(Source("a.csv", "row 4"), "bad |value|"),
            ]
            if not empty
            else []
        ),
        not_shown=["Anything outside the inputs.", HOSTILE[5] if hostile else "Other things."],
        generated_at=WHEN,
        tool_version="1.2.3",
        inputs=INPUTS if not empty else [],
        data={"campaign_id": "C0123", "note": HOSTILE[16], "nested": {"n": [1, 2, None]}},
    )


KINDS = list(SECTION_COLUMNS)

# Structure of the document ---------------------------------------------------------


def test_cell_text_covers_every_cell_type() -> None:
    assert cell_text(None) == ""
    assert cell_text(7) == "7"
    assert cell_text("x") == "x"
    assert cell_text(["a", "b"]) == "a; b"
    assert cell_text([]) == ""


def test_format_time_reads_naive_and_zoned_times() -> None:
    assert format_time(datetime(2026, 1, 2, 3, 4, 5)) == "2026-01-02T03:04:05Z"  # noqa: DTZ001
    zoned = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone(timedelta(hours=2)))
    assert format_time(zoned) == "2026-01-02T01:04:05Z"
    assert format_time(datetime(1, 1, 1, tzinfo=UTC)) == "0001-01-01T00:00:00Z"
    assert format_time(datetime(2026, 1, 2, 3, 4, 5, 999999, tzinfo=UTC)) == "2026-01-02T03:04:05Z"


def test_generated_now_honours_source_date_epoch(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "1700000000")
    assert generated_now() == "2023-11-14T22:13:20Z"
    monkeypatch.delenv("SOURCE_DATE_EPOCH")
    assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", generated_now())
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "")
    assert generated_now().endswith("Z")


@pytest.mark.parametrize("bad", ["soon", "1.5", "99999999999999999999", "-99999999999999"])
def test_generated_now_refuses_a_bad_epoch(monkeypatch: pytest.MonkeyPatch, bad: str) -> None:
    monkeypatch.setenv("SOURCE_DATE_EPOCH", bad)
    with pytest.raises(ValueError, match="SOURCE_DATE_EPOCH"):
        generated_now()


# JSON ------------------------------------------------------------------------------


def schema_for(kind: str) -> dict[str, Any]:
    return json.loads(generate_schema(f"{kind}-report-v1"))  # type: ignore[no-any-return]


@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize("hostile", [True, False])
def test_json_validates_against_its_schema(kind: str, *, hostile: bool) -> None:
    doc = make_doc(kind, hostile=hostile)
    text = render_json(doc).decode("utf-8", errors="strict") if not hostile else None
    if text is None:
        # a lone surrogate is escaped, so the bytes are still valid UTF-8
        text = render_json(doc).decode("utf-8")
    report = json.loads(text)
    schema = schema_for(kind)
    jsonschema.Draft202012Validator.check_schema(schema)
    jsonschema.Draft202012Validator(schema).validate(report)
    assert report["schema"] == schema_id(f"{kind}-report-v1")
    assert report["kind"] == kind
    assert list(report["sections"]) == sorted(SECTION_COLUMNS[kind])


@pytest.mark.parametrize("kind", KINDS)
def test_json_validates_when_everything_is_empty(kind: str) -> None:
    doc = make_doc(kind, empty=True, hostile=False)
    report = json.loads(render_json(doc))
    jsonschema.Draft202012Validator(schema_for(kind)).validate(report)
    assert all(rows == [] for rows in report["sections"].values())


def test_json_keeps_hostile_values_exactly() -> None:
    doc = make_doc("campaign", rows=len(HOSTILE))
    report = json.loads(render_json(doc))
    rows = report["sections"]["rows"]
    columns = SECTION_COLUMNS["campaign"]["rows"]
    for i, row in enumerate(rows):
        expected = hostile_row(columns, i)
        for key, value in expected.items():
            assert row[key] == value
    assert report["title"] == HOSTILE[2]
    assert report["problems"][0]["source"] == {"file": HOSTILE[3], "detail": HOSTILE[13]}
    assert report["data"]["note"] == HOSTILE[16]


def test_json_is_sorted_indented_and_ends_with_a_line_feed() -> None:
    data = render_json(make_doc(hostile=False))
    assert data.endswith(b"}\n")
    text = data.decode("utf-8")
    assert text.startswith('{\n  "counts"')
    assert json.dumps(json.loads(text), indent=2, ensure_ascii=False, sort_keys=True) + "\n" == text


def test_json_fills_missing_row_fields_with_null_and_keeps_numbers() -> None:
    doc = make_doc("campaign", hostile=False)
    reviewers = doc.sections[0]
    reviewers.rows[:] = [{"reviewer": "Avery Example", "rows": 4}]
    report = json.loads(render_json(doc))
    assert report["sections"]["reviewers"] == [
        {"reviewer": "Avery Example", "email": None, "rows": 4, "packet": None}
    ]
    jsonschema.Draft202012Validator(schema_for("campaign")).validate(report)


def test_json_omits_nothing_for_over_200_rows() -> None:
    doc = make_doc("verify", rows=450, hostile=False)
    report = json.loads(render_json(doc))
    assert all(len(rows) == 450 for rows in report["sections"].values())


@pytest.mark.parametrize(
    ("change", "message"),
    [
        (lambda d: dataclasses.replace(d, kind="other"), "unknown report kind"),
        (lambda d: dataclasses.replace(d, generated_at="yesterday"), "RFC 3339"),
        (lambda d: dataclasses.replace(d, generated_at="2026-11-12T10:20:30+00:00"), "RFC 3339"),
        (lambda d: dataclasses.replace(d, sections=d.sections[:-1]), "must be exactly"),
        (
            lambda d: dataclasses.replace(d, sections=[*d.sections, d.sections[0]]),
            "must be exactly",
        ),
        (
            lambda d: dataclasses.replace(
                d, sections=[dataclasses.replace(d.sections[0], columns=()), *d.sections[1:]]
            ),
            "registered columns",
        ),
        (
            lambda d: dataclasses.replace(
                d,
                sections=[
                    dataclasses.replace(d.sections[0], rows=[{"nope": "x"}]),
                    *d.sections[1:],
                ],
            ),
            "unknown fields",
        ),
        (lambda d: dataclasses.replace(d, facts=[("a", "1"), ("a", "2")]), "facts hold"),
        (lambda d: dataclasses.replace(d, counts=[("a", 1), ("a", 2)]), "counts hold"),
    ],
)
def test_json_refuses_a_document_the_schema_cannot_describe(
    change: Callable[[Document], Document], message: str
) -> None:
    with pytest.raises(ValueError, match=message):
        render_json(change(make_doc(hostile=False)))


# Markdown --------------------------------------------------------------------------


@pytest.mark.parametrize("kind", KINDS)
def test_markdown_structure_and_every_row(kind: str) -> None:
    doc = make_doc(kind, rows=250, hostile=False)
    text = render_markdown(doc).decode("utf-8")
    headings = [line for line in text.splitlines() if line.startswith("#")]
    titles = [f"## Title of {escape_markdown(k)} (250 rows)" for k in SECTION_COLUMNS[kind]]
    assert headings == [
        f"# A {kind} report",
        *titles,
        "## Not read (2 problems)",
        "## What this report does not show",
        "## Inputs",
    ]
    assert "## What this report does not show" in text
    assert text.rstrip().endswith("Generated by shaar 1.2.3 at 2026-11-12T10:20:30Z")
    lines = text.splitlines()
    firsts = [columns[0].key for columns in SECTION_COLUMNS[kind].values()]
    for first in set(firsts):
        for i in (0, 249):
            cell = escape_markdown(f"{first} {i}")
            found = sum(1 for ln in lines if ln.startswith(f"| {cell} |"))
            assert found == firsts.count(first)


def test_markdown_orders_headline_sections_problems_then_limits() -> None:
    text = render_markdown(make_doc(hostile=False)).decode("utf-8")
    order = [
        "# A campaign report",
        "3 access entries for 1 reviewer.",
        "## Title of reviewers",
        "## Title of rows",
        "## Title of unassigned",
        "## Not read",
        "## What this report does not show",
        "## Inputs",
        "Generated by shaar",
    ]
    positions = [text.index(item) for item in order]
    assert positions == sorted(positions)


def test_markdown_shows_empty_text_and_problem_citations() -> None:
    text = render_markdown(make_doc(hostile=False, empty=False)).decode("utf-8")
    assert "a.csv, row 4" in text
    empty = render_markdown(make_doc(hostile=False, empty=True)).decode("utf-8")
    assert "No reviewers found." in empty
    assert "(0 rows)" in empty
    assert "## Inputs" not in empty


def test_markdown_with_no_facts_or_counts_still_renders() -> None:
    doc = dataclasses.replace(make_doc(hostile=False), facts=[], counts=[])
    text = render_markdown(doc).decode("utf-8")
    assert "| Item |" not in text
    assert "| Count |" not in text


def test_markdown_one_row_is_singular() -> None:
    text = render_markdown(make_doc(rows=1, hostile=False)).decode("utf-8")
    assert "(1 row)" in text


TABLE_ROW = re.compile(r"^\| .* \|$")
SEPARATOR = re.compile(r"^\| (?:--- \| )*--- \|$")


def test_markdown_hostile_text_cannot_break_out() -> None:
    doc = make_doc("campaign", rows=len(HOSTILE))
    text = render_markdown(doc).decode("utf-8")
    assert not re.search(r"(?<!\\)<", text)
    assert not re.search(r"(?<!\\)>", text)
    # No Markdown or HTML structure can start from a value: every heading is ours.
    headings = [ln for ln in text.splitlines() if ln.startswith("#")]
    assert len(headings) == 1 + 3 + 1 + 1 + 1
    assert not [
        ln
        for ln in text.splitlines()
        if re.match(r" {0,3}(?:[-+=]|\d+[.)]|>)", ln) and not ln.startswith(("- ", "---"))
    ]
    # Every non-blank line is a table row, a bullet of ours, a heading, a rule or prose.
    for line in text.splitlines():
        if line.startswith("|"):
            assert TABLE_ROW.match(line)
    # URLs and addresses from the input cannot auto-link.
    assert "://evil" not in text
    assert "www.evil" not in text
    assert "http://\u2060evil.invalid" in text
    assert "avery@\u2060corp.example" in text
    # Every row stays one line: line breaks in values become arrows.
    rows = [ln for ln in text.splitlines() if ln.startswith("| ") and not SEPARATOR.match(ln)]
    assert len(rows) >= 3 * len(HOSTILE)
    # Invisible characters are visible escapes.
    assert "\u202e" not in text
    assert "\\u202e" in text
    assert "\x00" not in text
    assert "\\u0000" in text
    assert "\\udc80" in text
    # Long values are complete.
    assert "A" * 20_000 in text


def test_markdown_table_cell_counts_match_even_with_pipes() -> None:
    doc = make_doc("campaign", rows=len(HOSTILE))
    text = render_markdown(doc).decode("utf-8")
    for line in text.splitlines():
        if line.startswith("| ") and not SEPARATOR.match(line):
            unescaped = re.findall(r"(?<!\\)\|", line)
            assert len(unescaped) in {3, 5, 7, 11}  # 2, 4, 6 or 10 columns


# HTML ------------------------------------------------------------------------------


class Inspector(HTMLParser):
    """Collect what a browser could act on in a page."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.tags: list[str] = []
        self.attrs: list[tuple[str, str, str | None]] = []
        self.text: list[str] = []
        self.rows = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.tags.append(tag)
        if tag == "tr":
            self.rows += 1
        self.attrs.extend((tag, k, v) for k, v in attrs)

    def handle_data(self, data: str) -> None:
        self.text.append(data)


def inspect_html(data: bytes) -> Inspector:
    inspector = Inspector()
    inspector.feed(data.decode("utf-8"))
    inspector.close()
    return inspector


ALLOWED_TAGS = {
    "html", "head", "meta", "title", "style", "body", "main", "header", "h1", "h2", "p",
    "div", "table", "caption", "thead", "tbody", "tr", "th", "td", "section", "span", "ul", "li",
    "footer",
}  # fmt: skip
ALLOWED_ATTRS = {"lang", "charset", "http-equiv", "content", "name", "class", "id", "scope",
                 "role", "aria-labelledby"}  # fmt: skip


def test_html_is_standalone_with_a_csp_and_only_known_tags() -> None:
    data = render_html(make_doc("campaign", rows=len(HOSTILE)))
    page = data.decode("utf-8")
    assert page.startswith("<!DOCTYPE html>")
    assert f'<meta http-equiv="Content-Security-Policy" content="{CSP}">' in page
    assert "default-src 'none'" in CSP
    assert "script" not in CSP
    seen = inspect_html(data)
    assert set(seen.tags) <= ALLOWED_TAGS
    assert {a for _, a, _ in seen.attrs} <= ALLOWED_ATTRS
    assert not [v for _, _, v in seen.attrs if v and ("http" in v or "javascript" in v)]
    assert "<script" not in page.lower()
    assert "<img" not in page.lower()
    assert "<a " not in page
    assert "url(" not in page
    assert "@import" not in page


def test_html_escapes_every_hostile_value() -> None:
    data = render_html(make_doc("campaign", rows=len(HOSTILE)))
    seen = inspect_html(data)
    text = "\n".join(seen.text)
    assert "<script>alert(1)</script>" in text  # as text, not as a tag
    assert "alert(1)" not in [a for _, _, a in seen.attrs]
    page = data.decode("utf-8")
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page
    assert "\\u202e" in page
    assert "\u202e" not in page
    assert "\x00" not in page
    assert "\\udc80" in page
    assert "A" * 20_000 in page


@pytest.mark.parametrize("kind", KINDS)
def test_html_has_every_section_with_its_row_count_and_every_row(kind: str) -> None:
    doc = make_doc(kind, rows=300, hostile=False)
    data = render_html(doc)
    seen = inspect_html(data)
    page = data.decode("utf-8")
    sections = SECTION_COLUMNS[kind]
    for key in sections:
        assert f'Title of {key} <span class="count">(300 rows)</span>' in page
    # header rows plus data rows for each section, the problems table and the inputs table
    heads = len(sections) + 1 + 1 + 1  # section tables, problems, inputs, counts
    facts = len(doc.facts)
    expected = 300 * len(sections) + heads + len(doc.problems) + len(doc.inputs) + len(doc.counts)
    assert seen.rows == expected + facts
    assert 'Not read <span class="count">(2 problems)</span>' in page
    assert "What this report does not show" in page
    assert page.rstrip().count("Generated by shaar 1.2.3 at 2026-11-12T10:20:30Z") == 1
    assert "<title>A " + kind + " report</title>" in page


def test_html_marks_the_citation_column_and_shows_empty_text() -> None:
    page = render_html(make_doc(hostile=False)).decode("utf-8")
    assert '<td class="cite">source 0</td>' in page
    empty = render_html(make_doc(hostile=False, empty=True)).decode("utf-8")
    assert '<p class="muted">No reviewers found.</p>' in empty
    assert "No problems were recorded while reading the inputs." in empty
    assert 'id="inputs"' not in empty
    assert "(0 rows)" in empty


def test_html_one_problem_and_row_are_singular() -> None:
    doc = make_doc(rows=1, hostile=False)
    doc = dataclasses.replace(doc, problems=doc.problems[:1])
    page = render_html(doc).decode("utf-8")
    assert "(1 row)" in page
    assert "(1 problem)" in page


def test_html_without_facts_or_counts_has_neither_table() -> None:
    doc = dataclasses.replace(make_doc(hostile=False), facts=[], counts=[])
    page = render_html(doc).decode("utf-8")
    assert "<caption>Facts</caption>" not in page
    assert "<caption>Counts</caption>" not in page


def test_html_without_a_citation_column_marks_nothing() -> None:
    doc = make_doc(hostile=False)
    sections = [dataclasses.replace(s, citations="") for s in doc.sections]
    page = render_html(dataclasses.replace(doc, sections=sections)).decode("utf-8")
    assert 'class="cite"' in page  # only the problems table still has one
    assert '<td class="cite">source 0</td>' not in page


def test_html_is_print_friendly() -> None:
    page = render_html(make_doc(hostile=False)).decode("utf-8")
    assert "@media print" in page
    assert "table-header-group" in page
    assert "break-inside:avoid" in page


# CSV -------------------------------------------------------------------------------


def parse_csv(data: bytes) -> list[list[str]]:
    return list(csv.reader(io.StringIO(data.decode("utf-8"), newline="")))


def test_csv_has_keys_and_every_row_without_bom() -> None:
    doc = make_doc("campaign", rows=450, hostile=False)
    section = doc.sections[1]
    data = render_csv(section)
    assert not data.startswith(b"\xef\xbb\xbf")
    assert b"\r\n" in data
    rows = parse_csv(data)
    assert rows[0] == [c.key for c in section.columns]
    assert len(rows) == 451
    assert rows[450][0] == "row_id 449"


def test_csv_neutralizes_formulas_and_escapes_invisible_characters() -> None:
    doc = make_doc("campaign", rows=len(HOSTILE))
    for section in doc.sections:
        rows = parse_csv(render_csv(section))
        assert len(rows) == 1 + len(HOSTILE)
        for row in rows[1:]:
            for cell in row:
                assert not cell.startswith(("=", "+", "-", "@", "\t", "\r", "\n"))
                assert not any(ord(ch) < 32 and ch not in "\t\n\r" for ch in cell)
                assert "\u202e" not in cell
                assert "\x00" not in cell
    cells = {c for row in parse_csv(render_csv(doc.sections[1])) for c in row}
    assert '\'=HYPERLINK("http://evil.invalid","x")' in cells
    assert "'+1+1" in cells
    assert "'@SUM(A1)" in cells


def test_csv_handles_lists_numbers_and_blanks() -> None:
    columns = SECTION_COLUMNS["campaign"]["reviewers"]
    section = Section(
        "reviewers",
        "R",
        "",
        columns,
        [{"reviewer": ["a", "=b"], "rows": -5, "email": None, "packet": 0}],
        "none",
    )
    rows = parse_csv(render_csv(section))
    assert rows[1] == ["a; =b", "", "-5", "0"]


def test_csv_keeps_a_bool_cell_as_text() -> None:
    columns = SECTION_COLUMNS["campaign"]["reviewers"]
    section = Section("reviewers", "R", "", columns, [{"reviewer": True}], "none")
    assert parse_csv(render_csv(section))[1][0] == "True"


# Writing ---------------------------------------------------------------------------


def test_render_all_names_every_file_and_csv() -> None:
    doc = make_doc("decisions", hostile=False)
    files = render_all(doc, ["removals"])
    assert list(files) == [
        "decisions-report.json",
        "decisions-report.md",
        "decisions-report.html",
        "removals.csv",
    ]
    assert all(isinstance(v, bytes) for v in files.values())
    assert list(render_all(doc)) == list(files)[:3]
    with pytest.raises(ValueError, match="no section 'nope'"):
        render_all(doc, ["nope"])


def test_render_all_is_byte_reproducible() -> None:
    first = render_all(make_doc("campaign", rows=30), ["rows"])
    second = render_all(make_doc("campaign", rows=30), ["rows"])
    assert first == second
    other = render_all(
        dataclasses.replace(make_doc("campaign", rows=30), generated_at=WHEN[:-3] + "31Z"), ["rows"]
    )
    assert other != first


def test_write_outputs_writes_files_and_a_valid_manifest_last(tmp_path: Path) -> None:
    doc = make_doc("verify", hostile=False)
    files = render_all(doc, ["removals"])
    out = tmp_path / "out"
    manifest = write_outputs(
        out, files, force=False, generated_at=WHEN, tool_version="1.2.3", inputs=INPUTS
    )
    on_disk = json.loads((out / "manifest.json").read_text(encoding="utf-8"))
    assert on_disk == manifest
    jsonschema.Draft202012Validator(json.loads(generate_schema("manifest-v1"))).validate(on_disk)
    assert [f["name"] for f in manifest["files"]] == list(files)
    for entry in manifest["files"]:
        data = (out / entry["name"]).read_bytes()
        assert entry["size"] == len(data)
        assert entry["sha256"] == hashlib.sha256(data).hexdigest()
    assert manifest["inputs"] == [
        {"name": "ad-export.jsonl", "kind": "shaar export", "size": 123, "sha256": "a" * 64}
    ]
    assert manifest["tool"] == {"name": "shaar", "version": "1.2.3"}
    assert sorted(p.name for p in out.iterdir()) == sorted([*files, "manifest.json"])
    if os.name == "posix":
        for path in out.iterdir():
            assert path.stat().st_mode & 0o777 == 0o600


def test_manifest_is_reproducible_and_inputs_are_optional() -> None:
    files = {"a.txt": b"x"}
    one = build_manifest(files, generated_at=WHEN, tool_version="1")
    assert one == build_manifest(files, generated_at=WHEN, tool_version="1")
    assert one["inputs"] == []


def test_write_outputs_refuses_to_overwrite_without_force(tmp_path: Path) -> None:
    files = {"a.txt": b"new"}
    write_outputs(tmp_path, files, force=False, generated_at=WHEN, tool_version="1")
    before = {p.name: p.read_bytes() for p in tmp_path.iterdir()}
    with pytest.raises(OutputError, match="already exist"):
        write_outputs(
            tmp_path, {"a.txt": b"newer"}, force=False, generated_at=WHEN, tool_version="1"
        )
    assert {p.name: p.read_bytes() for p in tmp_path.iterdir()} == before
    write_outputs(tmp_path, {"a.txt": b"newer"}, force=True, generated_at=WHEN, tool_version="1")
    assert (tmp_path / "a.txt").read_bytes() == b"newer"


@pytest.mark.skipif(os.name != "posix", reason="symbolic links need POSIX here")
def test_write_outputs_never_follows_a_symlink(tmp_path: Path) -> None:
    victim = tmp_path / "victim"
    victim.write_bytes(b"precious")
    out = tmp_path / "out"
    out.mkdir()
    (out / "manifest.json").symlink_to(victim)
    (out / "a.txt").symlink_to(victim)
    with pytest.raises(OutputError, match="already exist"):
        write_outputs(out, {"a.txt": b"x"}, force=False, generated_at=WHEN, tool_version="1")
    write_outputs(out, {"a.txt": b"x"}, force=True, generated_at=WHEN, tool_version="1")
    assert victim.read_bytes() == b"precious"
    assert not (out / "a.txt").is_symlink()
    assert not (out / "manifest.json").is_symlink()


@pytest.mark.parametrize(
    "name",
    ["", "../escape.txt", "sub/a.txt", "/abs.txt", ".hidden", "a b.txt", "manifest.json", "a\x00b"],
)
def test_write_outputs_refuses_unusable_names(tmp_path: Path, name: str) -> None:
    with pytest.raises(ValueError, match="not a usable output file name"):
        write_outputs(tmp_path, {name: b"x"}, force=False, generated_at=WHEN, tool_version="1")
    assert list(tmp_path.iterdir()) == []


def test_write_outputs_refuses_no_files_and_a_bad_time(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="no files"):
        write_outputs(tmp_path, {}, force=False, generated_at=WHEN, tool_version="1")
    with pytest.raises(ValueError, match="RFC 3339"):
        write_outputs(tmp_path, {"a": b"x"}, force=False, generated_at="now", tool_version="1")


# Schemas ---------------------------------------------------------------------------


def test_every_schema_name_is_listed_once_and_matches() -> None:
    assert SCHEMA_NAMES == SHIPPED_NAMES
    assert len(set(SCHEMA_NAMES)) == 4


@pytest.mark.parametrize("name", SCHEMA_NAMES)
def test_committed_schemas_equal_the_generator(name: str) -> None:
    committed = Path(__file__).parent.parent / "src/faithful_shaar/schema" / f"{name}.schema.json"
    assert committed.read_text(encoding="utf-8") == generate_schema(name), (
        'regenerate with: uv run python -c "from pathlib import Path; '
        "from faithful_shaar.outputs.schema import SCHEMA_NAMES, generate_schema; "
        "[Path(f'src/faithful_shaar/schema/{n}.schema.json').write_text(generate_schema(n)) "
        'for n in SCHEMA_NAMES]"'
    )
    assert schema_text(name) == generate_schema(name)
    schema = json.loads(schema_text(name))
    jsonschema.Draft202012Validator.check_schema(schema)
    assert schema["$id"] == schema_id(name)
    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"


def test_no_schema_files_exist_beyond_the_listed_ones() -> None:
    folder = Path(__file__).parent.parent / "src/faithful_shaar/schema"
    names = sorted(p.name for p in folder.glob("*.json"))
    assert names == sorted(f"{n}.schema.json" for n in SCHEMA_NAMES)


def test_schema_columns_come_from_the_registry() -> None:
    for kind, sections in SECTION_COLUMNS.items():
        schema = schema_for(kind)
        for key, columns in sections.items():
            props = schema["properties"]["sections"]["properties"][key]["items"]
            assert list(props["required"]) == [c.key for c in columns]
            assert [p["title"] for p in props["properties"].values()] == [c.title for c in columns]


def test_schema_rejects_a_row_with_a_missing_or_extra_field() -> None:
    report = json.loads(render_json(make_doc("campaign", hostile=False)))
    validator = jsonschema.Draft202012Validator(schema_for("campaign"))
    validator.validate(report)
    broken = json.loads(json.dumps(report))
    del broken["sections"]["rows"][0]["source"]
    assert not validator.is_valid(broken)
    broken = json.loads(json.dumps(report))
    broken["sections"]["rows"][0]["extra"] = "x"
    assert not validator.is_valid(broken)
    broken = json.loads(json.dumps(report))
    broken["kind"] = "verify"
    assert not validator.is_valid(broken)


def test_unknown_schema_names_are_refused() -> None:
    with pytest.raises(UsageError, match="unknown schema 'nope'; choose from campaign-report-v1"):
        schema_text("nope")
    with pytest.raises(KeyError):
        generate_schema("nope")
    with pytest.raises(UsageError):
        schema_text("../../etc/passwd")


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("+ a", "\\+ a"),
        ("- a", "\\- a"),
        ("=== t", "\\=== t"),
        ("1. x", "1\\. x"),
        ("12) y", "12\\) y"),
        ("  # h #", "\\# h \\#"),
        ("    code", "code"),
        ("plain", "plain"),
        ("a\nb", "a \u21b5 b"),
        ("", ""),
    ],
)
def test_markdown_block_escaping(value: str, expected: str) -> None:
    assert _md_block(value) == expected


def test_a_section_without_an_intro_has_no_intro_paragraph() -> None:
    doc = make_doc(hostile=False)
    plain = dataclasses.replace(
        doc, sections=[dataclasses.replace(s, intro="") for s in doc.sections]
    )
    assert "About rows." not in render_markdown(plain).decode("utf-8")
    assert "About rows." in render_markdown(doc).decode("utf-8")
    assert "<p>About rows.</p>" not in render_html(plain).decode("utf-8")
    assert "<p>About rows.</p>" in render_html(doc).decode("utf-8")


def test_force_takes_away_the_earlier_runs_files_but_nothing_else(tmp_path: Path) -> None:
    # An earlier campaign had a fourth packet; the rebuilt one has three. The old packet
    # must not stay beside the new set, where it could be sent out by mistake.
    old = {"packet-01.xlsx": b"1", "packet-04.xlsx": b"old"}
    write_outputs(tmp_path, old, force=False, generated_at=WHEN, tool_version="1")
    (tmp_path / "notes.txt").write_bytes(b"mine")
    write_outputs(
        tmp_path, {"packet-01.xlsx": b"2"}, force=True, generated_at=WHEN, tool_version="1"
    )
    assert sorted(p.name for p in tmp_path.iterdir()) == [
        "manifest.json",
        "notes.txt",
        "packet-01.xlsx",
    ]


@pytest.mark.parametrize(
    "manifest", [b"not json", b"{}", b'{"files": [1]}', b'{"files": [{"name": "../x"}]}']
)
def test_an_unreadable_earlier_manifest_takes_nothing_away(tmp_path: Path, manifest: bytes) -> None:
    (tmp_path / "manifest.json").write_bytes(manifest)
    (tmp_path / "packet-04.xlsx").write_bytes(b"old")
    write_outputs(tmp_path, {"a.txt": b"x"}, force=True, generated_at=WHEN, tool_version="1")
    assert (tmp_path / "packet-04.xlsx").read_bytes() == b"old"


@pytest.mark.skipif(os.name != "posix", reason="symbolic links need POSIX here")
def test_force_never_takes_away_a_listed_link(tmp_path: Path) -> None:
    victim = tmp_path / "victim"
    victim.write_bytes(b"precious")
    out = tmp_path / "out"
    write_outputs(out, {"b.txt": b"1"}, force=False, generated_at=WHEN, tool_version="1")
    (out / "b.txt").unlink()
    (out / "b.txt").symlink_to(victim)
    write_outputs(out, {"a.txt": b"x"}, force=True, generated_at=WHEN, tool_version="1")
    assert (out / "b.txt").is_symlink()
    assert victim.read_bytes() == b"precious"
