# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""The reviewer packet workbook: a hand-written writer and a hardened reader.

The writer builds an Office Open XML workbook with :mod:`zipfile` and XML text, so no
third-party package is needed. Every cell is an inline string, never a formula. The same
input always gives the same bytes: the zip entries are written in a fixed order with a
date taken from the campaign's creation time.

The reader accepts a workbook as saved by Excel, LibreOffice or Google Sheets. It treats
the file as hostile. It refuses encrypted (CFB) files, zip bombs and files without the
sheets it needs; it parses XML with :mod:`faithful_shaar.formats.xmlsafe`; and it reads
only the parts it finds through the package relationships.

Sheet protection stops accidental edits only. It has no password, and the row digests
are the real control. Excel only lets people sort a protected sheet when the cells being
sorted are unlocked, so sorting in the returned packet may be refused for locked columns.
"""

from __future__ import annotations

import io
import posixpath
import re
import zipfile
import zlib
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, NoReturn
from xml.sax.saxutils import escape

from faithful_shaar.errors import InputError
from faithful_shaar.formats import xmlsafe

if TYPE_CHECKING:
    from xml.etree import ElementTree as ET

DECISIONS = ("Keep", "Remove", "Unsure")
"""The answers a reviewer may give, in the order the drop-down list shows them."""

_FIELDS = (
    ("Decision", "decision"),
    ("Comment", "comment"),
    ("User", "user"),
    ("Account", "account"),
    ("Status", "status"),
    ("Last sign-in", "last_sign_in"),
    ("Access to", "access_to"),
    ("Type", "type"),
    ("Access", "access"),
    ("Granted through", "granted_through"),
    ("Co-owners", "co_owners"),
    ("Row ID", "row_id"),
    ("Row check", "row_check"),
)
HEADERS = tuple(header for header, _attr in _FIELDS)
"""Every header text, visible columns first, then the hidden ``Row ID`` and ``Row check``."""

REVIEW_SHEET = "Review"
ABOUT_SHEET = "About"

MAX_ZIP_ENTRIES = 2_000
MAX_UNCOMPRESSED_BYTES = 64 * 1024 * 1024
MAX_RATIO = 200
MAX_ROWS = 100_000
MAX_CELL_CHARS = 32_767

_MAX_SHEET_ROW = 1_048_576
_MAX_SHEET_COLUMN = 16_384
_CFB_MAGIC = b"\xd0\xcf\x11\xe0"
_TRUNCATION_MARKER = " [truncated]"
_REPLACEMENT = "�"

_FORBIDDEN = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1f\ud800-\udfff￾￿]")
_ESCAPE_LOOKALIKE = re.compile(r"_x(?=[0-9A-Fa-f]{4}_)")
_ESCAPED_CHAR = re.compile(r"_x([0-9A-Fa-f]{4})_")
_CELL_REF = re.compile(r"^([A-Za-z]{1,3})([0-9]{1,7})$")

_NS_MAIN = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
_NS_REL = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
_NS_PKG_REL = "http://schemas.openxmlformats.org/package/2006/relationships"
_REL_BASE = "http://schemas.openxmlformats.org/officeDocument/2006/relationships/"
_CORE_REL = "http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties"
_XML_DECLARATION = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'

_CT_MAIN = "application/vnd.openxmlformats-officedocument.spreadsheetml"
_FIXED_ZIP_ATTR = 0o644 << 16
_ZIP_EPOCH = datetime(1980, 1, 1, tzinfo=UTC)

_INSTRUCTIONS = (
    "Choose Keep, Remove or Unsure in the Decision column for every row.",
    "Add a comment for every Remove.",
    "Do not add, delete or edit rows. Only the Decision and Comment cells can be changed.",
    "Leave the hidden Row ID and Row check columns alone: they match your answers to this review.",
    "Save the file and return it to the person who sent it.",
)

_WIDTHS = {
    "Decision": 12,
    "Comment": 40,
    "User": 26,
    "Account": 24,
    "Status": 11,
    "Last sign-in": 20,
    "Access to": 32,
    "Type": 14,
    "Access": 20,
    "Granted through": 40,
    "Co-owners": 28,
    "Row ID": 16,
    "Row check": 20,
}
_HIDDEN_ATTR = ' hidden="1"'
_HIDDEN = frozenset({"Row ID", "Row check"})
_UNLOCKED = frozenset({"Decision", "Comment"})
_WRAPPED = frozenset({"Granted through", "Comment"})

# cellXfs indexes in the styles part.
_S_DEFAULT = 0
_S_HEADER = 1
_S_UNLOCKED = 2
_S_WRAP = 3
_S_LABEL = 4
_S_TEXT = 5


@dataclass(frozen=True, slots=True)
class PacketRow:
    """One access entry in a packet. ``decision`` and ``comment`` start empty."""

    row_id: str
    row_check: str
    user: str
    account: str
    status: str
    last_sign_in: str
    access_to: str
    type: str
    access: str
    granted_through: str
    co_owners: str = ""
    decision: str = ""
    comment: str = ""


@dataclass(frozen=True, slots=True)
class Packet:
    """Everything the writer needs to build one reviewer's workbook."""

    campaign_name: str
    campaign_id: str
    reviewer_name: str
    reviewer_email: str
    due: str
    packet_digest: str
    rows: list[PacketRow]
    co_owner_column: bool
    created_at: str


@dataclass(frozen=True, slots=True)
class ReturnedRow:
    """One data row of a returned workbook."""

    row: int
    """The sheet row number, for citations."""
    values: dict[str, str]
    """Header text to cell text, ``""`` for an empty cell."""
    notes: list[str] = field(default_factory=list)
    """Things worth knowing about the row, such as ``"Decision held a formula"``."""


@dataclass(frozen=True, slots=True)
class ReturnedPacket:
    """What :func:`read_packet` found in a returned workbook."""

    about: dict[str, str]
    rows: list[ReturnedRow]
    headers: list[str]
    notes: list[str]
    core: dict[str, str]
    """``creator``, ``lastModifiedBy`` and ``modified`` as the file reports them. The file
    is untrusted, so these are claims, not facts."""


# ---------------------------------------------------------------------------------------
# Text handling shared by the writer and by callers that compare text with the workbook.


def _utf16_units(text: str) -> int:
    return len(text.encode("utf-16-le")) // 2


def cell_text(value: str) -> tuple[str, list[str]]:
    """Return the text the writer stores for ``value``, and what it had to change.

    Line breaks become line feeds. Characters XML 1.0 forbids become U+FFFD. Text longer
    than Excel's limit of 32,767 characters is cut and ends with a marker.

    Args:
        value: The text to store.

    Returns:
        The stored text and a list of short descriptions of the changes (empty when
        none).
    """
    changes: list[str] = []
    text = value.replace("\r\n", "\n").replace("\r", "\n")
    text, count = _FORBIDDEN.subn(_REPLACEMENT, text)
    if count:
        changes.append(f"replaced {count} character(s) XML does not allow with U+FFFD")
    if _utf16_units(text) > MAX_CELL_CHARS:
        budget = MAX_CELL_CHARS - len(_TRUNCATION_MARKER)
        # Cut on UTF-16 units; errors="ignore" drops a surrogate pair split in two.
        kept = text.encode("utf-16-le")[: budget * 2].decode("utf-16-le", errors="ignore")
        text = kept + _TRUNCATION_MARKER
        changes.append(f"cut to Excel's limit of {MAX_CELL_CHARS} characters")
    return text, changes


# ---------------------------------------------------------------------------------------
# Writer


def _column_letters(index: int) -> str:
    """Return the column letters for a 0-based column index."""
    letters = ""
    number = index + 1
    while number:
        number, rest = divmod(number - 1, 26)
        letters = chr(ord("A") + rest) + letters
    return letters


def _attr(value: str) -> str:
    return escape(value, {'"': "&quot;"})


def _inline_cell(ref: str, style: int, text: str) -> str:
    if text == "":
        return f'<c r="{ref}" s="{style}"/>'
    # Excel reads _xHHHH_ as an escaped character; keep a literal one literal.
    stored = _ESCAPE_LOOKALIKE.sub("_x005F_x", text)
    return (
        f'<c r="{ref}" s="{style}" t="inlineStr"><is>'
        f'<t xml:space="preserve">{escape(stored)}</t></is></c>'
    )


class _Cleaner:
    """Applies :func:`cell_text` and remembers every change with where it happened."""

    def __init__(self) -> None:
        self.notes: list[str] = []

    def clean(self, value: str, where: str) -> str:
        text, changes = cell_text(value)
        self.notes.extend(f"{where}: {change}" for change in changes)
        return text


def _timestamp(created_at: str) -> datetime:
    try:
        moment = datetime.fromisoformat(created_at)
    except ValueError:
        msg = f"created_at is not an ISO 8601 time: {created_at!r}"
        raise ValueError(msg) from None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=UTC)
    return max(moment.astimezone(UTC), _ZIP_EPOCH)


def _part(xml: str) -> bytes:
    return (_XML_DECLARATION + xml).encode("utf-8")


def _content_types() -> bytes:
    sheet = f"{_CT_MAIN}.worksheet+xml"
    return _part(
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" '
        'ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        f'<Override PartName="/xl/workbook.xml" ContentType="{_CT_MAIN}.sheet.main+xml"/>'
        f'<Override PartName="/xl/worksheets/sheet1.xml" ContentType="{sheet}"/>'
        f'<Override PartName="/xl/worksheets/sheet2.xml" ContentType="{sheet}"/>'
        f'<Override PartName="/xl/styles.xml" ContentType="{_CT_MAIN}.styles+xml"/>'
        '<Override PartName="/docProps/core.xml" '
        'ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>'
        '<Override PartName="/docProps/app.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/>'
        "</Types>"
    )


def _relationships(entries: list[tuple[str, str, str]]) -> bytes:
    items = "".join(
        f'<Relationship Id="{rid}" Type="{kind}" Target="{target}"/>'
        for rid, kind, target in entries
    )
    return _part(f'<Relationships xmlns="{_NS_PKG_REL}">{items}</Relationships>')


def _root_rels() -> bytes:
    return _relationships(
        [
            ("rId1", f"{_REL_BASE}officeDocument", "xl/workbook.xml"),
            ("rId2", _CORE_REL, "docProps/core.xml"),
            ("rId3", f"{_REL_BASE}extended-properties", "docProps/app.xml"),
        ]
    )


def _workbook_rels() -> bytes:
    return _relationships(
        [
            ("rId1", f"{_REL_BASE}worksheet", "worksheets/sheet1.xml"),
            ("rId2", f"{_REL_BASE}worksheet", "worksheets/sheet2.xml"),
            ("rId3", f"{_REL_BASE}styles", "styles.xml"),
        ]
    )


def _workbook(last_cell: str) -> bytes:
    return _part(
        f'<workbook xmlns="{_NS_MAIN}" xmlns:r="{_NS_REL}">'
        "<workbookPr/>"
        '<bookViews><workbookView activeTab="0"/></bookViews>'
        "<sheets>"
        f'<sheet name="{REVIEW_SHEET}" sheetId="1" r:id="rId1"/>'
        f'<sheet name="{ABOUT_SHEET}" sheetId="2" r:id="rId2"/>'
        "</sheets>"
        '<definedNames><definedName name="_xlnm._FilterDatabase" localSheetId="0" '
        f'hidden="1">{REVIEW_SHEET}!$A$1:{last_cell}</definedName></definedNames>'
        '<calcPr calcId="191029"/>'
        "</workbook>"
    )


def _styles() -> bytes:
    def xf(
        *,
        font: int = 0,
        fill: int = 0,
        locked: bool = True,
        wrap: bool = False,
        vertical: str = "top",
    ) -> str:
        wrap_attr = ' wrapText="1"' if wrap else ""
        return (
            f'<xf numFmtId="0" fontId="{font}" fillId="{fill}" borderId="0" xfId="0" '
            'applyFont="1" applyFill="1" applyAlignment="1" applyProtection="1">'
            f'<alignment vertical="{vertical}"{wrap_attr}/>'
            f'<protection locked="{int(locked)}"/></xf>'
        )

    cell_xfs = (
        xf(),
        xf(font=1, fill=2, wrap=True, vertical="center"),
        xf(locked=False, wrap=True),
        xf(wrap=True),
        xf(font=1),
        xf(wrap=True),
    )
    return _part(
        f'<styleSheet xmlns="{_NS_MAIN}">'
        '<fonts count="2">'
        '<font><sz val="11"/><name val="Calibri"/><family val="2"/></font>'
        '<font><b/><sz val="11"/><name val="Calibri"/><family val="2"/></font>'
        "</fonts>"
        '<fills count="3">'
        '<fill><patternFill patternType="none"/></fill>'
        '<fill><patternFill patternType="gray125"/></fill>'
        '<fill><patternFill patternType="solid"><fgColor rgb="FFD9E2F3"/>'
        '<bgColor indexed="64"/></patternFill></fill>'
        "</fills>"
        '<borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders>'
        '<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/>'
        "</cellStyleXfs>"
        f'<cellXfs count="{len(cell_xfs)}">{"".join(cell_xfs)}</cellXfs>'
        '<cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles>'
        '<dxfs count="0"/>'
        "</styleSheet>"
    )


def _core(packet: Packet, when: datetime, cleaner: _Cleaner) -> bytes:
    stamp = when.strftime("%Y-%m-%dT%H:%M:%SZ")
    title = escape(cleaner.clean(packet.campaign_name, "Document title"))
    return _part(
        '<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/'
        'metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/" '
        'xmlns:dcterms="http://purl.org/dc/terms/" xmlns:dcmitype="http://purl.org/dc/dcmitype/" '
        'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
        f"<dc:title>{title}</dc:title>"
        "<dc:creator>shaar</dc:creator>"
        "<cp:lastModifiedBy>shaar</cp:lastModifiedBy>"
        f'<dcterms:created xsi:type="dcterms:W3CDTF">{stamp}</dcterms:created>'
        f'<dcterms:modified xsi:type="dcterms:W3CDTF">{stamp}</dcterms:modified>'
        "</cp:coreProperties>"
    )


def _app() -> bytes:
    return _part(
        '<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/'
        'extended-properties"><Application>shaar</Application></Properties>'
    )


def _review_sheet(packet: Packet, cleaner: _Cleaner) -> tuple[bytes, str]:
    columns = [
        (header, attr)
        for header, attr in _FIELDS
        if header != "Co-owners" or packet.co_owner_column
    ]
    last_column = _column_letters(len(columns) - 1)
    last_row = len(packet.rows) + 1
    last_cell = f"${last_column}${last_row}"

    cols = "".join(
        f'<col min="{i}" max="{i}" width="{_WIDTHS[header]}" customWidth="1"'
        f"{_HIDDEN_ATTR if header in _HIDDEN else ''}/>"
        for i, (header, _attr_name) in enumerate(columns, start=1)
    )
    header_cells = "".join(
        _inline_cell(f"{_column_letters(i)}1", _S_HEADER, header)
        for i, (header, _attr_name) in enumerate(columns)
    )
    body = [f'<row r="1">{header_cells}</row>']
    for number, row in enumerate(packet.rows, start=2):
        cells = []
        for i, (header, attr) in enumerate(columns):
            style = _S_DEFAULT
            if header in _UNLOCKED:
                style = _S_UNLOCKED
            elif header in _WRAPPED:
                style = _S_WRAP
            text = cleaner.clean(getattr(row, attr), f"Review row {number}, {header}")
            cells.append(_inline_cell(f"{_column_letters(i)}{number}", style, text))
        body.append(f'<row r="{number}">{"".join(cells)}</row>')

    decision_column = _column_letters([h for h, _a in columns].index("Decision"))
    validation_end = max(last_row, 2)
    options = ",".join(DECISIONS)
    xml = (
        f'<worksheet xmlns="{_NS_MAIN}" xmlns:r="{_NS_REL}">'
        '<sheetPr><pageSetUpPr fitToPage="1"/></sheetPr>'
        f'<dimension ref="A1:{last_column}{last_row}"/>'
        '<sheetViews><sheetView tabSelected="1" workbookViewId="0">'
        '<pane ySplit="1" topLeftCell="A2" activePane="bottomLeft" state="frozen"/>'
        '<selection pane="bottomLeft" activeCell="A2" sqref="A2"/>'
        "</sheetView></sheetViews>"
        '<sheetFormatPr defaultRowHeight="15"/>'
        f"<cols>{cols}</cols>"
        f"<sheetData>{''.join(body)}</sheetData>"
        '<sheetProtection sheet="1" objects="1" scenarios="1" formatColumns="0" '
        'formatRows="0" autoFilter="0" sort="0"/>'
        f'<autoFilter ref="A1:{last_column}{last_row}"/>'
        '<dataValidations count="1">'
        '<dataValidation type="list" errorStyle="stop" allowBlank="1" showInputMessage="1" '
        'showErrorMessage="1" errorTitle="Decision" '
        f'error="{_attr("Choose Keep, Remove or Unsure.")}" promptTitle="Decision" '
        f'prompt="{_attr("Keep, Remove or Unsure")}" '
        f'sqref="{decision_column}2:{decision_column}{validation_end}">'
        f'<formula1>"{options}"</formula1></dataValidation></dataValidations>'
        '<pageMargins left="0.5" right="0.5" top="0.75" bottom="0.75" header="0.3" footer="0.3"/>'
        '<pageSetup orientation="landscape" fitToHeight="0"/>'
        "</worksheet>"
    )
    return _part(xml), last_cell


def _about_sheet(packet: Packet, cleaner: _Cleaner) -> bytes:
    facts = (
        ("Campaign", packet.campaign_name),
        ("Campaign ID", packet.campaign_id),
        ("Reviewer", packet.reviewer_name),
        ("Reviewer email", packet.reviewer_email),
        ("Due", packet.due),
        ("Packet digest", packet.packet_digest),
        ("Rows", str(len(packet.rows))),
    )
    lines: list[tuple[str, str]] = [
        (label, cleaner.clean(value, f"About {label}")) for label, value in facts
    ]
    lines.append(("", ""))
    lines.append(("Instructions", _INSTRUCTIONS[0]))
    lines.extend(("", line) for line in _INSTRUCTIONS[1:])
    body = "".join(
        f'<row r="{number}">'
        f"{_inline_cell(f'A{number}', _S_LABEL, label)}"
        f"{_inline_cell(f'B{number}', _S_TEXT, text)}</row>"
        for number, (label, text) in enumerate(lines, start=1)
    )
    return _part(
        f'<worksheet xmlns="{_NS_MAIN}" xmlns:r="{_NS_REL}">'
        f'<dimension ref="A1:B{len(lines)}"/>'
        '<sheetViews><sheetView workbookViewId="0"/></sheetViews>'
        '<sheetFormatPr defaultRowHeight="15"/>'
        '<cols><col min="1" max="1" width="22" customWidth="1"/>'
        '<col min="2" max="2" width="90" customWidth="1"/></cols>'
        f"<sheetData>{body}</sheetData>"
        '<sheetProtection sheet="1" objects="1" scenarios="1"/>'
        '<pageMargins left="0.7" right="0.7" top="0.75" bottom="0.75" header="0.3" footer="0.3"/>'
        "</worksheet>"
    )


def write_packet_with_notes(packet: Packet) -> tuple[bytes, list[str]]:
    """Build the workbook and report every cell the writer had to change.

    Args:
        packet: The packet to write.

    Returns:
        The workbook bytes, and notes such as ``"Review row 5, User: replaced 1
        character(s) XML does not allow with U+FFFD"``.

    Raises:
        ValueError: ``packet.created_at`` is not an ISO 8601 time.
    """
    when = _timestamp(packet.created_at)
    cleaner = _Cleaner()
    review, last_cell = _review_sheet(packet, cleaner)
    about = _about_sheet(packet, cleaner)
    parts = (
        ("[Content_Types].xml", _content_types()),
        ("_rels/.rels", _root_rels()),
        ("docProps/core.xml", _core(packet, when, cleaner)),
        ("docProps/app.xml", _app()),
        ("xl/workbook.xml", _workbook(last_cell)),
        ("xl/_rels/workbook.xml.rels", _workbook_rels()),
        ("xl/styles.xml", _styles()),
        ("xl/worksheets/sheet1.xml", review),
        ("xl/worksheets/sheet2.xml", about),
    )
    stamp = (when.year, when.month, when.day, when.hour, when.minute, when.second)
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name, content in parts:
            info = zipfile.ZipInfo(name, date_time=stamp)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3
            info.external_attr = _FIXED_ZIP_ATTR
            archive.writestr(info, content, compresslevel=9)
    return buffer.getvalue(), cleaner.notes


def write_packet(packet: Packet) -> bytes:
    """Build the packet workbook.

    The result is byte-reproducible: the same packet always gives the same bytes.

    Args:
        packet: The packet to write.

    Returns:
        The bytes of the ``.xlsx`` file.

    Raises:
        ValueError: ``packet.created_at`` is not an ISO 8601 time.
    """
    return write_packet_with_notes(packet)[0]


# ---------------------------------------------------------------------------------------
# Reader


class _Package:
    """A zip archive opened with limits, read one named part at a time."""

    def __init__(self, data: bytes, name: str) -> None:
        self.name = name
        if data[:4] == _CFB_MAGIC:
            self.fail(
                "it is an old Excel (.xls) file or a password-protected workbook, not an "
                "unprotected .xlsx; open it in Excel and save it again as .xlsx without a password"
            )
        try:
            self.archive = zipfile.ZipFile(io.BytesIO(data))
        except zipfile.BadZipFile:
            self.fail("it is not an Excel workbook (.xlsx)")
        infos = self.archive.infolist()
        self._check_limits(infos)
        self._names = {info.filename for info in infos}

    def fail(self, reason: str) -> NoReturn:
        msg = f"{self.name}: {reason}"
        raise InputError(msg)

    def _check_limits(self, infos: list[zipfile.ZipInfo]) -> None:
        if len(infos) > MAX_ZIP_ENTRIES:
            self.fail(f"it has more than {MAX_ZIP_ENTRIES} entries")
        names = [info.filename for info in infos]
        if len(set(names)) != len(names):
            self.fail("it lists the same entry name twice")
        if sum(info.file_size for info in infos) > MAX_UNCOMPRESSED_BYTES:
            self.fail(f"it expands to more than {MAX_UNCOMPRESSED_BYTES} bytes")
        for info in infos:
            if info.file_size > MAX_RATIO * info.compress_size:
                self.fail(
                    f"entry {info.filename!r} expands more than {MAX_RATIO} to 1, which is "
                    "not how a real workbook looks"
                )

    def has(self, part: str) -> bool:
        return part in self._names

    def read(self, part: str) -> bytes:
        info = self.archive.getinfo(part)
        if info.flag_bits & 0x1:
            self.fail(f"part {part!r} is encrypted")
        try:
            return self.archive.read(info)
        except (zipfile.BadZipFile, zlib.error, NotImplementedError, EOFError, RuntimeError):
            self.fail(f"part {part!r} cannot be decompressed")

    def xml(self, part: str) -> ET.Element:
        try:
            return xmlsafe.parse(self.read(part), max_bytes=MAX_UNCOMPRESSED_BYTES)
        except xmlsafe.XmlError as exc:
            self.fail(f"part {part!r} is not safe XML: {exc}")


@dataclass(frozen=True, slots=True)
class _Relationship:
    kind: str
    target: str


def _local(tag: str) -> str:
    return xmlsafe.split(tag)[1]


def _children(element: ET.Element, name: str) -> list[ET.Element]:
    return [child for child in element if _local(child.tag) == name]


def _child(element: ET.Element, name: str) -> ET.Element | None:
    found = _children(element, name)
    return found[0] if found else None


def _resolve(package: _Package, base_part: str, target: str) -> str:
    """Turn a relationship target into a zip entry name, refusing paths that escape."""
    if target.startswith("/"):
        path = posixpath.normpath(target.lstrip("/"))
    else:
        path = posixpath.normpath(posixpath.join(posixpath.dirname(base_part), target))
    if path.startswith(("..", "/")) or path in {"", "."}:
        package.fail(f"a relationship points outside the package: {target!r}")
    return path


def _relationships_of(package: _Package, part: str) -> dict[str, _Relationship]:
    """Read the relationships of ``part`` (``""`` for the package itself)."""
    if part:
        directory, base = posixpath.split(part)
        rels_part = posixpath.join(directory, "_rels", base + ".rels")
    else:
        rels_part = "_rels/.rels"
    if not package.has(rels_part):
        return {}
    found: dict[str, _Relationship] = {}
    for item in _children(package.xml(rels_part), "Relationship"):
        if item.get("TargetMode", "").casefold() == "external":
            continue
        rid, kind, target = item.get("Id"), item.get("Type", ""), item.get("Target")
        if rid and target:
            found[rid] = _Relationship(kind, _resolve(package, part or "x", target))
    return found


def _first_of_kind(rels: dict[str, _Relationship], suffix: str) -> str | None:
    for rel in rels.values():
        if rel.kind.endswith(suffix):
            return rel.target
    return None


def _relationship_id(element: ET.Element) -> str:
    for key, value in element.attrib.items():
        uri, local = xmlsafe.split(key)
        if uri and local == "id":
            return value
    return ""


def _decode_escapes(text: str) -> str:
    """Decode Excel's ``_xHHHH_`` escapes, keeping only characters XML may hold."""

    def one(match: re.Match[str]) -> str:
        char = chr(int(match.group(1), 16))
        return _REPLACEMENT if _FORBIDDEN.fullmatch(char) else char

    return _ESCAPED_CHAR.sub(one, text)


def _rich_text(element: ET.Element) -> str:
    """Join the text of a shared or inline string, runs included, phonetics excluded."""
    pieces: list[str] = []
    for child in element:
        name = _local(child.tag)
        if name == "t":
            pieces.append(child.text or "")
        elif name == "r":
            pieces.extend(run.text or "" for run in _children(child, "t"))
    return _decode_escapes("".join(pieces))


def _shared_strings(package: _Package, rels: dict[str, _Relationship]) -> list[str]:
    part = _first_of_kind(rels, "/sharedStrings")
    if part is None or not package.has(part):
        return []
    return [_rich_text(item) for item in _children(package.xml(part), "si")]


@dataclass(frozen=True, slots=True)
class _Cell:
    text: str
    note: str = ""


def _cell_value(cell: ET.Element, strings: list[str]) -> _Cell:
    kind = cell.get("t", "n")
    value = _child(cell, "v")
    inline = _child(cell, "is")
    raw = (value.text or "") if value is not None else ""
    note = ""
    if kind == "inlineStr":
        text = _rich_text(inline) if inline is not None else ""
    elif kind == "s":
        try:
            text = strings[int(raw)]
        except (ValueError, IndexError):
            text, note = "", "pointed to a shared string that does not exist"
    elif kind == "b":
        text = {"1": "TRUE", "0": "FALSE"}.get(raw.strip(), raw)
    elif kind == "str":
        text = _decode_escapes(raw)
    else:
        text = raw
    if _child(cell, "f") is not None:
        has_result = value is not None or inline is not None
        note = note or ("held a formula" if has_result else "held a formula with no saved result")
    return _Cell(text, note)


def _parse_reference(package: _Package, ref: str) -> tuple[int, int]:
    match = _CELL_REF.match(ref)
    if match is None:
        package.fail(f"a cell has an invalid reference {ref!r}")
    column = 0
    for char in match.group(1).upper():
        column = column * 26 + ord(char) - ord("A") + 1
    row = int(match.group(2))
    if not 1 <= column <= _MAX_SHEET_COLUMN or not 1 <= row <= _MAX_SHEET_ROW:
        package.fail(f"a cell is outside the sheet: {ref!r}")
    return row, column


def _row_number(package: _Package, element: ET.Element, previous: int) -> int:
    given = element.get("r")
    if given is None:
        number = previous + 1
    else:
        try:
            number = int(given)
        except ValueError:
            package.fail(f"a row has an invalid number {given!r}")
    if not 1 <= number <= _MAX_SHEET_ROW:
        package.fail(f"a row number is outside the sheet: {number}")
    return number


def _sheet_cells(package: _Package, part: str, strings: list[str]) -> dict[int, dict[int, _Cell]]:
    """Read every cell of a worksheet into ``{row number: {column number: cell}}``."""
    data = _child(package.xml(part), "sheetData")
    rows: dict[int, dict[int, _Cell]] = {}
    previous_row = 0
    for element in _children(data, "row") if data is not None else []:
        number = _row_number(package, element, previous_row)
        previous_row = number
        cells = rows.setdefault(number, {})
        if len(rows) > MAX_ROWS:
            package.fail(f"sheet has more than {MAX_ROWS} rows")
        column = 0
        for cell in _children(element, "c"):
            ref = cell.get("r")
            if ref is None:
                column += 1
            else:
                ref_row, column = _parse_reference(package, ref)
                if ref_row != number:
                    package.fail(f"cell {ref} sits in row {number}")
            if column > _MAX_SHEET_COLUMN:
                package.fail("a row has more cells than a sheet can hold")
            if column in cells:
                package.fail(f"row {number} holds column {column} twice")
            cells[column] = _cell_value(cell, strings)
    return rows


def _find_sheets(package: _Package) -> tuple[dict[str, str], dict[str, _Relationship]]:
    """Return ``{casefolded sheet name: part}`` and the workbook's relationships."""
    root_rels = _relationships_of(package, "")
    workbook = _first_of_kind(root_rels, "/officeDocument")
    if workbook is None or not package.has(workbook):
        package.fail("it is not an Excel workbook: it has no workbook part")
    rels = _relationships_of(package, workbook)
    sheets = _child(package.xml(workbook), "sheets")
    found: dict[str, str] = {}
    for sheet in _children(sheets, "sheet") if sheets is not None else []:
        rel = rels.get(_relationship_id(sheet))
        name = sheet.get("name", "").strip().casefold()
        if rel is not None and rel.kind.endswith("/worksheet") and package.has(rel.target):
            found.setdefault(name, rel.target)
    return found, rels


_HEADER_KEY = "Row ID".casefold()
_CANONICAL = {header.casefold(): header for header in HEADERS}


def _header_row(
    package: _Package, rows: dict[int, dict[int, _Cell]], notes: list[str]
) -> tuple[int, dict[int, str]]:
    for number in sorted(rows):
        if any(cell.text.strip().casefold() == _HEADER_KEY for cell in rows[number].values()):
            headers: dict[int, str] = {}
            for column in sorted(rows[number]):
                text = rows[number][column].text.strip()
                header = _CANONICAL.get(text.casefold(), text)
                if not header:
                    continue
                if header in headers.values():
                    notes.append(
                        f"column {_column_letters(column - 1)} repeats the header {header!r}"
                    )
                    continue
                headers[column] = header
            return number, headers
    return package.fail(f"the {REVIEW_SHEET} sheet has no 'Row ID' header")


def _returned_rows(
    rows: dict[int, dict[int, _Cell]], header_row: int, headers: dict[int, str]
) -> list[ReturnedRow]:
    result: list[ReturnedRow] = []
    for number in sorted(rows):
        if number <= header_row:
            continue
        cells = rows[number]
        values = {
            header: cells[col].text if col in cells else "" for col, header in headers.items()
        }
        notes = [
            f"{header} {cells[col].note}"
            for col, header in headers.items()
            if col in cells and cells[col].note
        ]
        if any(text != "" for text in values.values()) or notes:
            result.append(ReturnedRow(number, values, notes))
    return result


def _about(rows: dict[int, dict[int, _Cell]], notes: list[str]) -> dict[str, str]:
    about: dict[str, str] = {}
    for number in sorted(rows):
        cells = rows[number]
        label = cells[1].text.strip() if 1 in cells else ""
        if label.casefold() == "instructions":
            break
        if not label:
            continue
        value = cells.get(2, _Cell(""))
        about.setdefault(label, value.text.strip())
        if value.note:
            notes.append(f"About {label} {value.note}")
    return about


def _core_properties(package: _Package, notes: list[str]) -> dict[str, str]:
    part = _first_of_kind(_relationships_of(package, ""), "/core-properties")
    if part is None or not package.has(part):
        return {}
    try:
        root = package.xml(part)
    except InputError:
        notes.append("docProps/core.xml could not be read")
        return {}
    wanted = ("creator", "lastModifiedBy", "modified")
    return {
        _local(child.tag): (child.text or "").strip()
        for child in root
        if _local(child.tag) in wanted
    }


def read_packet(data: bytes, name: str) -> ReturnedPacket:
    """Read a returned packet workbook.

    Args:
        data: The bytes of the file.
        name: The file name, used in error messages.

    Returns:
        The About fields, the data rows with their sheet row numbers, and notes.

    Raises:
        InputError: The file is not an unencrypted ``.xlsx`` workbook, breaks a limit, or
            has no Review sheet, no About sheet or no ``Row ID`` header.
    """
    package = _Package(data, name)
    sheets, workbook_rels = _find_sheets(package)
    parts = {}
    for wanted in (REVIEW_SHEET, ABOUT_SHEET):
        if wanted.casefold() not in sheets:
            package.fail(f"it has no sheet named {wanted!r}")
        parts[wanted] = sheets[wanted.casefold()]
    strings = _shared_strings(package, workbook_rels)
    notes: list[str] = []
    review = _sheet_cells(package, parts[REVIEW_SHEET], strings)
    header_row, headers = _header_row(package, review, notes)
    rows = _returned_rows(review, header_row, headers)
    about = _about(_sheet_cells(package, parts[ABOUT_SHEET], strings), notes)
    core = _core_properties(package, notes)
    return ReturnedPacket(
        about=about,
        rows=rows,
        headers=list(headers.values()),
        notes=notes,
        core=core,
    )
