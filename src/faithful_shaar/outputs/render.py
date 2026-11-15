# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
r"""Render a report :class:`~faithful_shaar.outputs.document.Document` and write the files.

Values from the inputs are untrusted. Markdown is escaped so a value cannot forge a
heading, link, table or HTML tag. The HTML page escapes everything, forbids scripts and
network access with a content security policy, and never puts a value in a URL. CSV
cells are protected against formula injection. Invisible and reordering characters show
as visible escapes in every people-facing format. The JSON report keeps exact values.
No renderer shortens a value or drops a row: long tables are complete.

The CSV is UTF-8 without a byte order mark, uses ``\r\n`` line ends, and its header
holds the column keys that the JSON report uses. A spreadsheet that guesses the encoding
wrongly can be told it is UTF-8 when importing.
"""

from __future__ import annotations

import csv
import hashlib
import html
import io
import json
import re
from typing import TYPE_CHECKING, Any

from faithful_shaar.outputs.columns import SECTION_COLUMNS
from faithful_shaar.outputs.document import KINDS, Cell, Section, cell_text
from faithful_shaar.outputs.files import OutputError, write_files
from faithful_shaar.outputs.safety import csv_cell, escape_markdown, visible
from faithful_shaar.outputs.schema import MANIFEST_NAME, TIME_PATTERN, schema_id

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable, Mapping, Sequence
    from pathlib import Path

    from faithful_shaar.model import InputFile
    from faithful_shaar.outputs.document import Document

MANIFEST_FILE = "manifest.json"
CSP = "default-src 'none'; style-src 'unsafe-inline'; form-action 'none'; base-uri 'none'"
"""Content security policy: no scripts, no network access, no form submission."""
_FILE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
_TIME = re.compile(TIME_PATTERN)
NO_PROBLEMS = "No problems were recorded while reading the inputs."
NO_ROWS = "No rows."


def _plural(n: int, one: str, many: str | None = None) -> str:
    return f"{n} {one if n == 1 else many or one + 's'}"


# JSON -------------------------------------------------------------------------------


def _check(doc: Document) -> None:
    """Refuse a document the published schema could not describe: that is a bug."""
    if doc.kind not in KINDS:
        msg = f"unknown report kind {doc.kind!r}"
        raise ValueError(msg)
    if not _TIME.match(doc.generated_at):
        msg = f"generated_at {doc.generated_at!r} is not an RFC 3339 UTC time"
        raise ValueError(msg)
    registry = SECTION_COLUMNS[doc.kind]
    keys = [s.key for s in doc.sections]
    if sorted(keys) != sorted(registry) or len(set(keys)) != len(keys):
        msg = f"{doc.kind} report sections {keys} must be exactly {list(registry)}"
        raise ValueError(msg)
    for section in doc.sections:
        if section.columns != registry[section.key]:
            msg = f"section {section.key!r} does not use the registered columns"
            raise ValueError(msg)
        allowed = {c.key for c in section.columns}
        for row in section.rows:
            extra = sorted(set(row) - allowed)
            if extra:
                msg = f"section {section.key!r} has a row with unknown fields {extra}"
                raise ValueError(msg)
    for name, pairs in (("facts", doc.facts), ("counts", doc.counts)):
        labels = [label for label, _ in pairs]
        if len(set(labels)) != len(labels):
            msg = f"{name} hold a label more than once"
            raise ValueError(msg)


def _row_json(section: Section, row: Mapping[str, Any]) -> dict[str, Any]:
    return {c.key: row.get(c.key) for c in section.columns}


def _dumps(value: Any) -> str:
    text = json.dumps(value, indent=2, ensure_ascii=False, sort_keys=True) + "\n"
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:
        # A lone surrogate cannot be written as UTF-8; JSON escapes keep it exactly.
        text = json.dumps(value, indent=2, ensure_ascii=True, sort_keys=True) + "\n"
    return text


def _inputs(inputs: Iterable[InputFile]) -> list[dict[str, Any]]:
    return [{"name": i.name, "kind": i.kind, "size": i.size, "sha256": i.sha256} for i in inputs]


def render_json(doc: Document) -> bytes:
    """Render the report as JSON that follows ``<kind>-report-v1``.

    Keys are sorted, the indent is two spaces and the text ends with a line feed, so the
    same document always gives the same bytes. Values are kept exactly.

    Raises:
        ValueError: The document does not fit the published schema: its kind is
            unknown, its time is malformed, its sections or columns differ from
            :data:`~faithful_shaar.outputs.columns.SECTION_COLUMNS`, a row has a field
            that is not a column, or facts or counts repeat a label.
    """
    _check(doc)
    report = {
        "schema": schema_id(f"{doc.kind}-report-v1"),
        "kind": doc.kind,
        "title": doc.title,
        "headline": doc.headline,
        "generated_at": doc.generated_at,
        "tool": {"name": "shaar", "version": doc.tool_version},
        "facts": dict(doc.facts),
        "counts": dict(doc.counts),
        "sections": {s.key: [_row_json(s, r) for r in s.rows] for s in doc.sections},
        "problems": [
            {
                "source": {"file": p.source.file, "detail": p.source.detail},
                "reason": p.reason,
            }
            for p in doc.problems
        ],
        "not_shown": list(doc.not_shown),
        "inputs": _inputs(doc.inputs),
        "data": doc.data,
    }
    return _dumps(report).encode("utf-8")


# Markdown ---------------------------------------------------------------------------


def _md(value: str) -> str:
    """Escape a table cell."""
    return escape_markdown(value)


_BLOCK_START = re.compile(r"^(?:([+\-=])|(\d+)([.)]))")


def _md_block(value: str) -> str:
    """Escape a paragraph, heading or list item so it cannot become another block.

    On top of :func:`_md`, every ``#`` is escaped (a leading one makes a heading, a
    trailing one is dropped from headings), leading spaces go (four make a code block),
    and a leading ``+``, ``-``, ``=`` or ``1.`` is escaped so it cannot open a list or
    a rule.
    """
    text = _md(value.lstrip(" \t")).replace("#", "\\#")
    return _BLOCK_START.sub(lambda m: f"\\{m[1]}" if m[1] else f"{m[2]}\\{m[3]}", text, count=1)


def _md_table(head: Sequence[str], rows: Iterable[Sequence[str]]) -> str:
    lines = [
        "| " + " | ".join(_md(h) for h in head) + " |",
        "| " + " | ".join("---" for _ in head) + " |",
    ]
    lines.extend("| " + " | ".join(_md(c) for c in row) + " |" for row in rows)
    return "\n".join(lines) + "\n"


def _section_rows(section: Section) -> list[list[str]]:
    return [[cell_text(row.get(c.key)) for c in section.columns] for row in section.rows]


def _problem_rows(doc: Document) -> list[list[str]]:
    return [[str(p.source), p.reason] for p in doc.problems]


def render_markdown(doc: Document) -> bytes:
    """Render the report as Markdown. Every value is escaped and every row is kept."""
    out = [f"# {_md_block(doc.title)}\n", f"{_md_block(doc.headline)}\n"]
    if doc.facts:
        out.append(_md_table(("Item", "Value"), doc.facts))
    if doc.counts:
        out.append(_md_table(("Count", "Number"), [(k, str(v)) for k, v in doc.counts]))
    for section in doc.sections:
        out.append(f"## {_md_block(section.title)} ({_plural(len(section.rows), 'row')})\n")
        if section.intro:
            out.append(f"{_md_block(section.intro)}\n")
        if section.rows:
            heads = [c.title for c in section.columns]
            out.append(_md_table(heads, _section_rows(section)))
        else:
            out.append(f"{_md_block(section.empty)}\n")
    out.append(f"## Not read ({_plural(len(doc.problems), 'problem')})\n")
    if doc.problems:
        out.append("These could not be read or trusted, so what they hold is not in this report.\n")
        out.append(_md_table(("Source", "Reason"), _problem_rows(doc)))
    else:
        out.append(f"{NO_PROBLEMS}\n")
    out.append("## What this report does not show\n")
    out.append("\n".join(f"- {_md_block(item)}" for item in doc.not_shown) + "\n")
    if doc.inputs:
        out.append("## Inputs\n")
        rows = [[i.name, i.kind, str(i.size), i.sha256] for i in doc.inputs]
        out.append(_md_table(("File", "Kind", "Bytes", "SHA-256"), rows))
    out.append("---\n")
    out.append(f"Generated by shaar {_md(doc.tool_version)} at {_md(doc.generated_at)}\n")
    return "\n".join(out).encode("utf-8")


# HTML -------------------------------------------------------------------------------

_CSS = """
:root{--fg:#1f2328;--muted:#4d5661;--bg:#fff;--panel:#f6f8fa;--line:#c4ccd4;--accent:#0550ae}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);
font:15px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif}
main{max-width:80rem;margin:0 auto;padding:1rem 1.25rem 3rem}
h1{font-size:1.6rem;margin:1.25rem 0 .25rem}
h2{font-size:1.2rem;margin:2rem 0 .5rem;padding-bottom:.25rem;border-bottom:1px solid var(--line)}
.count{font-weight:400;color:var(--muted);font-size:.9rem}
.headline{font-size:1.1rem;font-weight:600;border:2px solid var(--fg);border-radius:6px;
padding:.7rem 1rem;margin:1rem 0;background:var(--panel)}
.tablewrap{overflow-x:auto;margin:.5rem 0 1rem}
table{border-collapse:collapse;width:100%;font-size:.88rem}
caption{position:absolute;left:-999px}
th,td{border:1px solid var(--line);padding:.35rem .5rem;text-align:left;vertical-align:top;
overflow-wrap:anywhere;white-space:pre-wrap}
thead th{background:var(--panel)}
thead{display:table-header-group}
tr{break-inside:avoid}
table.facts{width:auto;min-width:24rem}
table.facts th{font-weight:600;background:var(--panel)}
td.cite{color:var(--muted);font-size:.82rem}
.muted{color:var(--muted)}
code{font:.88em ui-monospace,SFMono-Regular,Consolas,"Liberation Mono",monospace}
ul.list{padding-left:1.2rem}
ul.list li{margin:.3rem 0}
footer{margin-top:2.5rem;color:var(--muted);font-size:.85rem;border-top:1px solid var(--line);
padding-top:.75rem}
@media print{body{font-size:11pt}main{max-width:none;padding:0}
h2{break-after:avoid}th,td{padding:.2rem .35rem}}
"""


def _h(value: object) -> str:
    return html.escape(visible(str(value)), quote=True)


def _h_table(
    caption: str,
    head: Sequence[str],
    rows: Iterable[Sequence[str]],
    *,
    classes: Sequence[str] = (),
    cls: str = "",
) -> str:
    """A table of plain text cells, escaped here. ``classes`` gives one class per column."""
    heads = "".join(f'<th scope="col">{_h(h)}</th>' for h in head)
    body = []
    for row in rows:
        cells = "".join(
            f'<td class="{c}">{_h(v)}</td>' if c else f"<td>{_h(v)}</td>"
            for v, c in zip(row, classes or [""] * len(row), strict=True)
        )
        body.append(f"<tr>{cells}</tr>")
    table_class = f' class="{cls}"' if cls else ""
    return (
        f'<div class="tablewrap"><table{table_class}><caption>{_h(caption)}</caption>'
        f"<thead><tr>{heads}</tr></thead><tbody>{''.join(body)}</tbody></table></div>"
    )


def _h_facts(doc: Document) -> str:
    rows = "".join(f'<tr><th scope="row">{_h(k)}</th><td>{_h(v)}</td></tr>' for k, v in doc.facts)
    return (
        f'<div class="tablewrap"><table class="facts"><caption>Facts</caption>{rows}</table></div>'
    )


def _h_section(index: int, section: Section) -> str:
    anchor = f"s{index}"
    count = _plural(len(section.rows), "row")
    heading = f'<h2 id="{anchor}">{_h(section.title)} <span class="count">({count})</span></h2>'
    out = [f'<section aria-labelledby="{anchor}">{heading}']
    if section.intro:
        out.append(f"<p>{_h(section.intro)}</p>")
    if section.rows:
        classes = ["cite" if c.key == section.citations else "" for c in section.columns]
        out.append(
            _h_table(
                section.title,
                [c.title for c in section.columns],
                _section_rows(section),
                classes=classes,
            )
        )
    else:
        out.append(f'<p class="muted">{_h(section.empty)}</p>')
    out.append("</section>")
    return "".join(out)


def render_html(doc: Document) -> bytes:
    """Render one self-contained page: no scripts, no external requests, no URLs from data.

    Every value is escaped, the content security policy forbids everything but inline
    style, and every row of every table is present.
    """
    sections = "".join(_h_section(i, s) for i, s in enumerate(doc.sections, start=1))
    if doc.problems:
        problems = (
            "<p>These could not be read or trusted, so what they hold is not in this "
            "report.</p>"
            + _h_table("Not read", ("Source", "Reason"), _problem_rows(doc), classes=("cite", ""))
        )
    else:
        problems = f'<p class="muted">{_h(NO_PROBLEMS)}</p>'
    limits = "".join(f"<li>{_h(item)}</li>" for item in doc.not_shown)
    inputs = ""
    if doc.inputs:
        rows = [[i.name, i.kind, str(i.size), i.sha256] for i in doc.inputs]
        inputs = '<h2 id="inputs">Inputs</h2>' + _h_table(
            "Inputs", ("File", "Kind", "Bytes", "SHA-256"), rows, classes=("", "", "", "mono")
        )
    counts = (
        _h_table("Counts", ("Count", "Number"), [(k, str(v)) for k, v in doc.counts])
        if doc.counts
        else ""
    )
    page = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="{CSP}">
<meta name="referrer" content="no-referrer">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{_h(doc.title)}</title>
<style>{_CSS}</style>
</head>
<body>
<main>
<header>
<h1>{_h(doc.title)}</h1>
<p class="headline" role="status">{_h(doc.headline)}</p>
</header>
{_h_facts(doc) if doc.facts else ""}
{counts}
{sections}
<section aria-labelledby="problems"><h2 id="problems">Not read \
<span class="count">({_plural(len(doc.problems), "problem")})</span></h2>{problems}</section>
<section aria-labelledby="limits"><h2 id="limits">What this report does not show</h2>
<ul class="list">{limits}</ul></section>
{inputs}
<footer>Generated by shaar {_h(doc.tool_version)} at {_h(doc.generated_at)}</footer>
</main>
</body>
</html>
"""
    return page.encode("utf-8")


# CSV --------------------------------------------------------------------------------


def _csv_value(value: Cell | list[str]) -> str:
    text = cell_text(value)
    # A whole number is the tool's own count, never text from an input.
    return text if isinstance(value, int) and not isinstance(value, bool) else csv_cell(text)


def render_csv(section: Section) -> bytes:
    """Render one section as CSV: a header of column keys, then every row.

    Cells that a spreadsheet could take for a formula get a leading apostrophe, and
    invisible characters become visible escapes. UTF-8 without a byte order mark.
    """
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\r\n")
    writer.writerow([c.key for c in section.columns])
    for row in section.rows:
        writer.writerow([_csv_value(row.get(c.key)) for c in section.columns])
    return buffer.getvalue().encode("utf-8")


# Writing ----------------------------------------------------------------------------


def render_all(doc: Document, csv_sections: Sequence[str] = ()) -> dict[str, bytes]:
    """Render every format: ``<kind>-report.json|md|html`` and ``<section key>.csv``.

    Raises:
        ValueError: A name in ``csv_sections`` is not a section of the document, or the
            document does not fit its schema (see :func:`render_json`).
    """
    by_key = {s.key: s for s in doc.sections}
    unknown = [k for k in csv_sections if k not in by_key]
    if unknown:
        msg = f"no section {unknown[0]!r} to write as CSV"
        raise ValueError(msg)
    files = {
        f"{doc.kind}-report.json": render_json(doc),
        f"{doc.kind}-report.md": render_markdown(doc),
        f"{doc.kind}-report.html": render_html(doc),
    }
    for key in csv_sections:
        files[f"{key}.csv"] = render_csv(by_key[key])
    return files


def build_manifest(
    files: Mapping[str, bytes],
    *,
    generated_at: str,
    tool_version: str,
    inputs: Iterable[InputFile] = (),
    limits: Mapping[str, int] | None = None,
) -> dict[str, Any]:
    """The manifest (``manifest-v1``) for ``files``: name, size and SHA-256 of each.

    ``limits`` are the size limits the run used; they are listed when given.
    """
    manifest: dict[str, Any] = {
        "schema": schema_id(MANIFEST_NAME),
        "tool": {"name": "shaar", "version": tool_version},
        "generated_at": generated_at,
        "files": [
            {"name": n, "size": len(d), "sha256": hashlib.sha256(d).hexdigest()}
            for n, d in files.items()
        ],
        "inputs": _inputs(inputs),
    }
    if limits:
        manifest["limits"] = dict(sorted(limits.items()))
    return manifest


def render_manifest(manifest: Mapping[str, Any]) -> bytes:
    """Return the text of ``manifest.json``, exactly as :func:`write_outputs` writes it."""
    return _dumps(manifest).encode("utf-8")


def write_outputs(  # noqa: PLR0913 - the documented API
    directory: Path,
    files: Mapping[str, bytes],
    *,
    force: bool,
    generated_at: str,
    tool_version: str,
    inputs: Iterable[InputFile] = (),
    removable: Callable[[str], bool] | None = None,
    limits: Mapping[str, int] | None = None,
) -> dict[str, Any]:
    """Write ``files`` and then ``manifest.json``, all together or not at all.

    Files are created owner-only, an existing file is never replaced unless ``force`` is
    true, and a symbolic link at a target is replaced, never followed. The manifest goes
    last, so a manifest means every other file is in place.

    With ``force``, a file that an earlier run's manifest lists and this run does not write
    is taken away only when ``removable(name)`` says the name is one this kind of run
    writes. Without ``removable`` nothing is taken away. A manifest is not proof that a
    name belongs to the command now running: an output folder reused for another command
    lists that command's files too, and ``campaign.json`` cannot be written again.

    Returns:
        The manifest as written.

    Raises:
        ValueError: A file name is not a plain name, is the manifest's name, or no file
            was given, or ``generated_at`` is not a UTC time.
        OutputError: A target exists and ``force`` is false, or writing failed. Nothing
            is left half written.
    """
    if not files:
        msg = "no files to write"
        raise ValueError(msg)
    for name in files:
        if not _FILE_NAME.match(name) or name == MANIFEST_FILE:
            msg = f"{name!r} is not a usable output file name"
            raise ValueError(msg)
    if not _TIME.match(generated_at):
        msg = f"generated_at {generated_at!r} is not an RFC 3339 UTC time"
        raise ValueError(msg)
    manifest = build_manifest(
        files, generated_at=generated_at, tool_version=tool_version, inputs=inputs, limits=limits
    )
    write_files(
        directory,
        {**files, MANIFEST_FILE: render_manifest(manifest)},
        force=force,
        remove=[n for n in _earlier_files(directory) if removable and removable(n)]
        if force
        else (),
    )
    return manifest


def _earlier_files(directory: Path) -> list[str]:
    """Return the plain file names an earlier run's manifest in ``directory`` lists.

    Only names the manifest lists are ever taken away, never other files someone put in the
    directory. An unreadable manifest lists nothing.
    """
    try:
        data = json.loads((directory / MANIFEST_FILE).read_bytes())
        listed = [entry["name"] for entry in data["files"]]
    except (OSError, ValueError, KeyError, TypeError):
        return []
    return [n for n in listed if isinstance(n, str) and _FILE_NAME.match(n) and n != MANIFEST_FILE]


__all__ = [
    "CSP",
    "OutputError",
    "build_manifest",
    "render_all",
    "render_csv",
    "render_html",
    "render_json",
    "render_markdown",
    "write_outputs",
]
