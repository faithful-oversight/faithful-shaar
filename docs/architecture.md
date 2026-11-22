# Architecture

shaar is a command-line tool and a Python library with the same core. Reading exports and CSV files, writing packets and reports, and reading packets need one runtime dependency beyond the Python standard library: [faithful-core](https://github.com/faithful-oversight/faithful-core), the shared foundation library of the Faithful Oversight tools, pinned to an exact version. The collectors and secret providers use optional dependencies, installed as extras.

```text
 domain-joined computer
   Export-ShaarAccess.ps1 --> shaar export        header, records, trailer with SHA-256
 WinRM --> shaar collect ad -----+                         |
 Microsoft Graph --> shaar collect entra ------------------+
 CSV files, with a column map or preset --------------------+
                                                           v
   inputs      detect each input's kind from its content, read it into a Snapshot, merge
                                                           |
                                                           v
   assign      one reviewer per entry: manager, owner, or reviewer map
   campaign    rows, row checks, packet digests, campaign digest --> campaign.json
   formats     one packet workbook per reviewer                   --> packet-NN-*.xlsx
                                                           |
              reviewers fill in the packets and return them
                                                           v
   formats     read each returned workbook with the hardened reader
   decide      check each row against the campaign           --> decisions.json
                                                           |
              administrators remove access
                                                           v
   verify      compare a later Snapshot with the accepted removals
   reports     fill a report document for each command
   outputs     render JSON, Markdown, HTML, CSV, and a manifest, and write them safely
   cli         arguments, files, exit codes
```

## Data flow

1. `inputs.read_inputs` fingerprints each input (size and SHA-256), detects its kind, and reads it with `inputs.export` or `inputs.csvread`. Each becomes a `Snapshot` with its principals, resources, grants, the resources whose membership was read in full, and the problems found. `inputs.merge` combines them and keeps the earliest collection time.
2. `campaign.build` asks `assign` for a reviewer for every grant. It sorts the rows, gives each a row id and a row check, gives each reviewer a packet digest, and digests the whole campaign. `campaign.dump` writes `campaign.json`.
3. `reports.packets` turns each reviewer's rows into a `formats.xlsx` packet. `reports.campaign_document` fills the campaign report.
4. `decide.read_decisions` reads returned workbooks with `formats.xlsx.read_packet` and checks each against the campaign. It yields a `DecisionRecord`, which `decide.dump` writes as `decisions.json`.
5. `verify.verify` checks a later `Snapshot` against the accepted removals.
6. `outputs.render` renders each report document and writes the files with a manifest. The renderers read only the document.

## Modules

| Module | Responsibility |
| --- | --- |
| `cli` | Arguments and the commands `campaign`, `decisions`, `verify`, `schema`, and `example`. |
| `errors` | `ShaarError`, which is faithful-core's `FaithfulError`, and the error classes shaar uses: `InputError`, `CollectionError`, `UsageError`, and `OutputError`. |
| `model` | The plain data every reader produces: `Principal`, `Resource`, `Grant`, `Snapshot`, `Source`, and `Problem`. |
| `keys` | The keys that identify principals, resources, and grants across inputs. |
| `inputs` | `export` reads a shaar export, `csvread` and `csvmap` read a CSV with its map, `combine` and `merge` combine grants and snapshots. |
| `assign` | The reviewer rules and the reviewer map. |
| `campaign` | Rows, digests, `campaign.json`, and loading it back with its digest checked. |
| `decide` | Reads returned packets into a decision record. |
| `verify` | Checks a later snapshot against the accepted removals. |
| `formats` | `xlsx` writes and reads packet workbooks. |
| `reports` | Builds the report documents and the packet files from a campaign, a decision record, or a verification. |
| `outputs` | `document` is the report contract, `columns` the columns of every section, `render` the formats, `files` the writer that names shaar's temporary files, and `schema` the JSON Schemas. |
| `collect` | `ad` and `remote` for the exporter: the checks on each line, the script's parameters, and the result. `entra` and `graph` for Microsoft Graph, `fileout`, and `script`. |
| `example` | The synthetic review for `shaar example` and tests. |
| `data` | The PowerShell exporter `Export-ShaarAccess.ps1`. |
| `schema` | The published JSON Schemas. |

## The model

A **grant** is one principal's entitlement on one resource: the unit that is reviewed. A **key** identifies each of the three across inputs, and matching uses keys only. Every record keeps a `Source`, so every finding can cite a file and a place. Every snapshot keeps its list of `Problem` records, and the set of resources whose membership was read in full. Only for those resources is the absence of a grant evidence.

## The shared library

faithful-core holds the code that every Faithful Oversight tool needs to behave the same way. shaar uses it for:

- the base error and the exit codes;
- making untrusted text safe for the terminal, CSV, Markdown, and HTML;
- the report time and the way times are written;
- printing that never changes an exit code;
- the XML parser that reads returned workbooks;
- publishing a set of files all together, without replacing a file the tool reads;
- the checks on `--host` and `--username`, the secret providers, and the redaction of every resolved secret;
- the WinRM connection, its transport rules, and the loop that takes the controller's output.

The library's own pages describe how each of these works. shaar's tests cover them through the commands, and the library's tests cover them directly. See [decision record 8](adr/0008-shared-core-library.md).

## Rules the design follows

- **Read-only.** The tool never changes the systems it examines. Collectors only read, and the Entra client can send only `GET`.
- **Unknown is a result.** Anything that could not be read, matched, or verified is reported as unknown or as a problem, never as passed, removed, or clean.
- **Every finding cites its source.** A filename and a detail: a line, a row, or a sheet row.
- **Hash-bound packets.** Row checks, packet digests, and a campaign digest tie returned work to what was sent. They are not signatures. See [decision record 6](adr/0006-campaign-integrity.md).
- **No prompts.** The tool never asks questions interactively.
- **Structured exit codes.** `0` OK, `1` findings, `2` usage, `3` input, `4` internal.
- **Safe output.** Files are owner-only and never replaced without `--force`. Reports escape every value. `SOURCE_DATE_EPOCH` makes everything reproducible.
- **Separation.** Readers handle input, `assign`, `decide`, and `verify` are logic on plain data, and renderers handle output.

## Packaging

- Python package on PyPI: `faithful-shaar`, with the command `shaar`. It needs Python 3.11 or newer. Its one runtime dependency is `faithful-core`, pinned to an exact version.
- Extras: `ad`, `entra`, `keyring`, `vault`, `aws`, and `azure`. See the README.
- A standalone executable or a container image is added only when a decision record justifies it.

## Decisions

See the [architecture decision records](adr/index.md).
