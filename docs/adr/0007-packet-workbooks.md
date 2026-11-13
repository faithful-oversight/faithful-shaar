# 7. Packet workbooks written by hand

- Status: accepted
- Date: 2026-11-13

## Context

Reviewers should use a spreadsheet they already know. That means an Excel workbook (`.xlsx`) with a drop-down list, a frozen header, and protection against accidental edits. shaar must also read the workbook back after Excel, LibreOffice, or Google Sheets saved it, which changes the file's inner structure.

A workbook is a zip file of XML. The returned file comes from outside the tool, so reading it is a risk surface: zip bombs, XML entity attacks, formulas, old binary files, and password-protected files.

Options considered:

- **openpyxl.** A mature library that reads and writes workbooks. It is a runtime dependency with its own dependencies, it reads whole sheets into memory, its writer does not give byte-identical files, and its XML handling is not under our control.
- **XlsxWriter and a separate reader.** Two dependencies, and again no control over the reader.
- **A hand-written writer and reader.** More code to own, but no dependency, a reader whose limits we set, and files that are the same bytes for the same input.

## Decision

- Write the workbook by hand with `zipfile` and XML text: two sheets (Review and About), styles, a drop-down list for Decision, a frozen header with a filter, hidden `Row ID` and `Row check` columns, and sheet protection with only the Decision and Comment cells unlocked.
- Write every cell as an inline string, never a formula. Characters that XML 1.0 forbids become U+FFFD, and a cell longer than the Excel limit is cut and marked.
- Make the bytes reproducible: a fixed zip order, entry dates and document properties taken from the campaign's creation time, and a fixed compression level. `SOURCE_DATE_EPOCH` fixes the time.
- Write a hardened reader. It finds sheets through the workbook and its relationships, never by file name. It reads shared strings, inline strings, numbers, and booleans, joins rich text runs, and finds the header row by `Row ID`, so moved columns and rows in any order still read. It reports a formula cell and uses its saved value. It refuses encrypted and OLE files, and enforces limits on entries, expanded size, expansion ratio, and rows. It parses XML with a wrapper that refuses a `DOCTYPE` and limits depth.
- Test the writer and reader with LibreOffice and openpyxl round trips (when present), and with a hand-made fixture in the Excel shared-string form that always runs.

## Consequences

No runtime dependency, no unreviewed XML or zip code on the path of untrusted files, and packets that are byte-for-byte reproducible.

The cost is code that shaar must keep correct. Real-world workbooks vary, and the reader handles what the tests and these three programs produce. A workbook shape that no test covers may be refused or misread.

No packet was opened in Microsoft Excel or Google Sheets for this release. LibreOffice and openpyxl round trips are the evidence. Excel may refuse to sort a protected sheet whose locked cells are in the sorted range. The [limitations](../limitations.md) say so.
