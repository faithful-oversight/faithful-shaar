# Reports and output

`shaar campaign`, `shaar decisions`, and `shaar verify` each write one report in three forms, a CSV for each table that people use in a spreadsheet, their own record files, and a manifest. All forms are made from one document, so they agree.

## Output files

| Command | Files |
| --- | --- |
| `campaign` | `campaign.json`, `packet-NN-NAME-HASH.xlsx` (one per reviewer), `campaign-report.json`, `.md`, `.html`, `rows.csv`, `unassigned.csv` (only when an entry has no reviewer), `manifest.json` |
| `decisions` | `decisions.json`, `decisions-report.json`, `.md`, `.html`, `removals.csv`, `attention.csv`, `decisions.csv`, `manifest.json` |
| `verify` | `verify-report.json`, `.md`, `.html`, `removals.csv`, `kept_but_gone.csv`, `new_since_review.csv`, `manifest.json` |

`campaign.json` and `decisions.json` are the records the next step reads. They carry a digest and are not meant to be edited. See [Campaigns](campaigns.md#row-checks-and-digests). The files and the rules for writing them are in [Usage](usage.md#output-folders-and-files).

## Report layout

Every report has the same parts, in this order:

1. A **headline**, such as "13 access entries for 3 reviewers. 2 entries have no reviewer."
2. A table of **facts** and a table of **counts**.
3. The **sections** for that report, each with a title, an introduction, a table, and a sentence that says so when the table is empty.
4. **Not read**: the problems found while reading the inputs, each with its source. Anything that could not be read or trusted is here, and what it holds is not in the report.
5. **What this report does not show**: a fixed list of limits.
6. **Inputs**: each input's name, kind, size, and SHA-256.

Every row cites its source, as a file name and a detail such as `ad.jsonl, line 16`, `ledger.csv, row 3`, or `returned-03-Morgan-Lead-e16dc6.xlsx, Review row 7`. No renderer shortens a value or drops a row.

### Campaign

Facts: the campaign, its id, how reviewers were chosen, the due date, when the access was read (the earliest time among the inputs), and the systems.

| Section | Columns |
| --- | --- |
| `reviewers` (Reviewers and packets) | Reviewer, Email, Entries, Packet file |
| `unassigned` (Entries with no reviewer) | User, Account, Access to, Access, Why there is no reviewer, Source |
| `rows` (All entries) | Row ID, Reviewer, User, Account, Status, Access to, Type, Access, Granted through, Source |

### Decisions

Facts: the campaign and its id, how many returned files were read, and which decisions need a comment. Counts: accepted, removals to make, undecided, not valid, changed after sending, copies disagree, no reviewer, and rows from elsewhere.

| Section | Columns |
| --- | --- |
| `removals` (Removals to make) | Row ID, User, Account, Access to, Access, Reviewer, Comment |
| `attention` (Needs attention) | Row ID, Reviewer, User, Access to, Outcome, Why it needs attention, Source |
| `decisions` (Every entry) | Row ID, Reviewer, User, Access to, Access, Decision, Comment, Outcome, Packet, Source |

Needs attention lists every row that is not accepted, every Unsure, and every stray. A packet that was rejected or unreadable is under Not read. The outcomes are the ones in [Campaigns](campaigns.md#what-makes-a-decision-count). Unassigned entries and strays have no row id of their own.

### Verification

Facts: the campaign, its id, the due date, and when the later access was read. Counts: removals verified, still present past due, still present not yet due, unknown, kept but gone, and new since the review.

| Section | Columns |
| --- | --- |
| `removals` (Removals) | Row ID, User, Access to, Access, Result, Reason, Source |
| `kept_but_gone` (Kept, but gone anyway) | Row ID, User, Access to, Access, Source |
| `new_since_review` (New since the review) | User, Access to, Access, Source |

The results are defined in [Verification](verification.md).

## JSON reports

`campaign-report.json`, `decisions-report.json`, and `verify-report.json` follow published, versioned JSON Schemas. Keys are sorted, the indent is two spaces, and the text ends with a line feed, so the same document gives the same bytes. Values are exact: the JSON keeps what the input held, where the other forms show invisible characters as escapes.

```json
{
  "schema": "https://faithful-oversight.github.io/faithful-shaar/schema/verify-report-v1.schema.json",
  "kind": "verify",
  "title": "...",
  "headline": "...",
  "generated_at": "2026-11-13T04:04:39Z",
  "tool": {"name": "shaar", "version": "0.1.1"},
  "facts": {},
  "counts": {},
  "sections": {"removals": [], "kept_but_gone": [], "new_since_review": []},
  "problems": [{"source": {"file": "...", "detail": "..."}, "reason": "..."}],
  "not_shown": [],
  "inputs": [],
  "data": {}
}
```

Each row of `sections` is an object with the keys in `outputs/columns.py`, which are the column keys used in the CSV header: for example `row_id`, `principal`, `resource`, `access`, `result`, `reason`, and `citation`. `data` holds the campaign id and digest, and for decisions the digest of the decision record and one entry per returned file (name, SHA-256, status, reason, reviewer, and what the file reports about its own author and time). For verification it holds the time used for the later access.

### JSON Schemas

```shell
shaar schema campaign-report-v1
shaar schema decisions-report-v1
shaar schema verify-report-v1
shaar schema manifest-v1
```

Each prints a schema for the installed version, with no network access. The schemas are generated from the same column registry as the reports, and a test compares them with the committed files. `campaign.json` and `decisions.json` are records for shaar's own use and have no published schema in 0.1.0.

## CSV files

One CSV per table that a person is likely to filter. The header row holds the column keys, as in the JSON. Files use UTF-8 without a byte order mark and `\r\n` line ends. A spreadsheet that guesses the encoding wrongly can be told to import it as UTF-8.

### Formula neutralization

Spreadsheets run text that starts with certain characters as a formula. In every CSV cell that comes from an input, a leading `=`, `+`, `-`, `@`, tab, carriage return, line feed, or the full-width forms of `=`, `+`, `-`, and `@` gets a leading apostrophe, which spreadsheets show as plain text. This includes a negative number: the text `-5` becomes `'-5`. A whole number that shaar counted itself, such as the number of entries, is written as it is.

Invisible and reordering characters (controls, zero-width characters, bidirectional marks, tag characters, variation selectors) become visible escapes such as `‮`.

## Markdown report

Every value is escaped, so it cannot forge a heading, a link, a table, or an HTML tag. Line breaks in a value become a visible arrow. A word joiner (U+2060) is added after `@`, `://`, and `www.`, so a viewer does not turn an email address or URL in the data into a link. As a result, an email address in the Markdown report has an invisible character after its `@`. The joiner is in the Markdown only: the JSON and CSV keep the exact text, and the HTML escapes values instead.

## HTML report

One standalone page. It has no scripts and loads nothing: a content security policy of `default-src 'none'` allows inline style only, and the page sets no referrer. Every value is escaped and no value is ever put in a URL. It prints cleanly.

## Manifest

`manifest.json` follows `manifest-v1`. It holds the tool and version, the generation time, the name, size, and SHA-256 of every other file in the folder from this run, and the inputs. It is written last, so a manifest means every other file is in place.

The inputs are the access inputs for `campaign` and `verify`. For `decisions` they are the access inputs the campaign was built from. The returned packets are recorded by name and SHA-256 in `decisions.json` and in the report's `data`.

## Repeatable output

With `SOURCE_DATE_EPOCH` set, the same inputs and options give byte-identical files, packets included. See [Usage](usage.md#repeatable-output).
