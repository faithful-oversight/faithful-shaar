# Threat model

> **Status: current for 0.1.1.** This model covers the file readers, the campaign and packet writers, the report writers, the PowerShell exporter, and the two collectors. Review it whenever an input format, output format, collector, or dependency changes. No collector has run against a real domain, WinRM endpoint, or Entra tenant, and no packet has been tested in Excel or Google Sheets, so the controls that concern them are tested against stand-ins only. See [Limitations](limitations.md).

## What the tool protects

- **Personal data.** Exports, packets, and reports hold names, accounts, managers, and access. A packet is sent to a person outside the tool.
- **The integrity of the review.** A decision record is evidence. A row that was changed, a packet that belongs to someone else, or a forged reviewer must not turn into a removal or a Keep.
- **Credentials and tokens.** Collection needs a password, a certificate, a client secret, or a Graph token. None of them may leak.
- **The systems examined.** Collection must never change them, and the accounts it uses must not be more powerful than needed.
- **The operator's machine.** shaar reads files and network replies that may come from people the operator does not fully trust.
- **The supply chain.** Users install release artifacts built by this project's pipeline.

## Trust boundaries

1. Input files enter the tool: exports, CSV files, column maps, reviewer maps. They are untrusted, including an export the exporter wrote, because the computer it ran on may be compromised.
2. Returned packets enter the tool from reviewers. They are untrusted. A reviewer may be careless or hostile, and an email attachment may have been changed on the way.
3. `campaign.json` and `decisions.json` are read back by later commands. They sit in a folder that others may be able to write.
4. The WinRM channel and the Graph API carry replies that are untrusted.
5. Secret providers return secrets to the collectors.
6. Output files leave the tool and are opened in browsers, spreadsheets, and review systems. Packets leave the tool for reviewers.
7. Release artifacts leave the build pipeline and are installed by users.

## What the digests do and do not protect

shaar binds a packet to its campaign with SHA-256 digests: a row check for each row, a packet digest for each packet, a campaign digest for `campaign.json`, and a digest in `decisions.json`. shaar uses **no secret key and no signature**.

- The digests detect accidental damage and casual changes: a reviewer who edits a row, a packet returned for another campaign, a hand-edited `campaign.json`, a truncated file.
- They do **not** stop a determined attacker. The digests are unkeyed SHA-256. Anyone who has a campaign's files, or one packet plus knowledge of another reviewer's rows, can build a packet that decides another reviewer's rows. shaar accepts it and attributes it to the assigned reviewer. Nothing in shaar can tell.
- Control who receives packets and who runs `shaar decisions`, and keep the returned files.
- Signing is out of scope for this release: the maintainer chose hash binding over signatures because it needs no key management, and the main risks it addresses are mistakes and casual edits. If you need proof of who decided, rely on the channel that carries the packets, and keep the campaign folder and the returned files in a system that controls who can write. See [decision record 6](adr/0006-campaign-integrity.md).

## Threats and controls (STRIDE)

The **Status** column says whether each control is in place today. Branch rules depend on repository settings, which are applied outside the code.

| Category | Threat | Control | Status |
| --- | --- | --- | --- |
| Spoofing | A tampered release artifact is installed in place of the real one. | Releases are built only by the release workflow from a commit on `main`, with a pinned, hash-verified build backend, a published `SHA256SUMS` file, and a software bill of materials. Build provenance attestations are added once the repository is public. The PowerShell exporter ships inside the package. | In place (attestations when public) |
| Spoofing | A reviewer is not who the workbook says. | The reviewer of record is the one the campaign assigned to the packet, identified by the packet digest on the About sheet. The author and time a workbook reports about itself are shown as claims and never used. This does not authenticate the person: whoever holds the file can fill it in. | In place; no authentication of the person |
| Spoofing | A packet for one reviewer is returned as another's, or for another campaign. | The campaign id and the packet digest on the About sheet must match. The campaign id covers the due date, the reviewer rule, and the reviewer map, and the packet digest covers the reviewer's key, so a packet from a campaign that assigned rows differently is rejected. Every row must belong to the reviewer of the packet, or it is a stray. | In place |
| Spoofing | An export from another Entra tenant or AD domain stands in for the campaign's. | Entra keys carry the tenant id, which `shaar collect entra` takes from the token, and well-known SIDs carry the domain. A key with no tenant or domain makes its resource incomplete. Removals can only be verified from the same tenant or domain. | In place |
| Spoofing | A fake server answers `shaar collect ad` and receives the credentials. | HTTPS is the default and verifies the certificate against the system's roots or `--ca-file`. No option turns verification off. `--host` must be a DNS name, so the certificate and the Kerberos service name are checked against it. HTTP needs message encryption. | In place; tested against a simulated client only |
| Tampering | `campaign.json` or `decisions.json` is edited. | Each holds a SHA-256 of its canonical content. A change makes the file fail to load, with exit code `3`. `verify` also checks that the decision record names the same campaign id and digest. A person who can write the files can recompute the digests. | In place (detects accidents, not a forger) |
| Tampering | A packet row is edited, added, or removed. | The hidden Row check is a SHA-256 over the campaign id, the row id, the grant key, and every visible field. `decisions` compares it with the campaign and also compares the visible text itself. A changed row is `altered` and its decision is not used. A row that is not the packet's own is a stray. A missing row is undecided. | In place (detects accidents, not a forger) |
| Tampering | A reviewer changes the decision after another copy was sent. | Copies of a row that disagree are a `conflict` and none is used. | In place |
| Tampering | A crafted input changes results, for example with duplicate ids or a key collision. | Strict validation. Ids are kept as text. Duplicates and ambiguities are problems, never a silent choice; a packet with two Decision columns or a reviewer map with a repeated column is refused. Grant key parts escape `|` and `%`. Two inputs that disagree about a principal or resource keep the first and record a problem. Every row cites its source. | In place |
| Tampering | An export is changed after collection. | The trailer holds the record count and a SHA-256 of every byte before it. A cut-short, damaged, or edited file is a problem, and then no resource counts as complete, so no removal can be verified from it. A forger can recompute the hash. | In place (detects accidents, not a forger) |
| Tampering | A malicious or compromised controller or tenant returns crafted data. | Replies are untrusted input. For WinRM, each line is checked as it arrives, the trailer must match, and the published file is read again by the strict reader. Graph replies are size-limited and parsed as JSON. A controller or tenant can still lie about what it holds. | In place, with residual risk below |
| Tampering | A collector changes a system. | The exporter only reads. A test checks its commands. The Entra client has no way to name a method other than GET, and a test proves every request is a GET. `shaar collect ad` sends the packaged script with fixed parameters. | In place |
| Tampering | A failed run leaves a partial file or overwrites good evidence. | Files go to private temporary files first, and the manifest is written last. Without `--force`, a file is placed only if its name is free. With `--force`, old files are moved aside and restored if a step fails. A remote collection streams into a private temporary file and publishes it only after the end line checks out. | In place |
| Tampering | A hostile workbook, CSV, or export tries to read or write outside its place. | See [hostile workbooks](#hostile-workbooks) and [hostile exports and CSV files](#hostile-exports-and-csv-files). Output paths are fixed file names, never taken from input. A symbolic link at an output name is replaced, never followed. | In place |
| Tampering | A malicious change enters the code base. | Pull requests only, a required passing check, resolved conversations, no force pushes to `main`, signed-off commits, and actions pinned to full commit hashes. | In place (branch rules need settings) |
| Repudiation | A user cannot show which inputs and rules produced a report. | Reports and manifests record the tool version, the time, and the name, kind, size, and SHA-256 of the inputs. `decisions.json` records each returned file's SHA-256. `SOURCE_DATE_EPOCH` makes the output byte-for-byte repeatable. | In place |
| Repudiation | A reviewer denies a decision. | shaar keeps the file, its SHA-256, and the row it came from. It cannot prove who typed it. | Partly: see the digests preceding |
| Repudiation | A crash is mistaken for a normal result. | Unexpected errors exit with code 4, distinct from findings (1), usage (2), and input or collection errors (3). | In place |
| Information disclosure | A packet reaches someone other than its reviewer. | Each packet holds only its reviewer's rows. shaar writes the files owner-only and does not send them. How packets travel is up to the operator. | Partly in place: delivery is outside shaar |
| Information disclosure | Exports, campaigns, reports, and decision records are read by other users. | All files and new folders are created owner-only on Linux and macOS, and never silently overwritten. shaar sets no access rules on Windows. Fixtures are synthetic. Secret scanning runs on every change and across the full history. | In place on Linux and macOS |
| Information disclosure | A password, secret, or token leaks through the command line, logs, files, or errors. | Secrets are given as references, read at start-up, and never written. shaar remembers every secret and the Graph token it handles and removes them, in plain, URL-encoded, JSON-escaped, and quoted forms, from every error and message before printing. Errors from Vault, AWS, and Azure name only the exception type. | In place, with residual risk below |
| Information disclosure | The Graph token is sent to another host. | The token goes only to the configured Graph host over HTTPS with the default certificate checks. Redirects are refused. A paging link is followed only when its scheme and host equal the base URL's and its path is under `/v1.0`. The token is never logged or written. | In place; tested against a fake Graph server |
| Information disclosure | Credentials cross the network in a form that can be stolen. | HTTPS is the default. Over HTTP, message encryption is required. Only Kerberos, Negotiate, and NTLM are offered. Basic and CredSSP are not. | In place; tested against a simulated client only |
| Information disclosure | The tool sends data over the network. | `campaign`, `decisions`, and `verify` have no network code. `collect ad` connects only to the controller and the secret provider you name. `collect entra` connects only to the Graph host, the sign-in authority, and the secret provider. No telemetry. | In place |
| Denial of service | An oversized or hostile input exhausts memory or time. | Limits on file sizes, line lengths, rows, zip entries, expansion ratio, and XML depth. See [Limitations](limitations.md#size-limits). Problems are not capped, so a hostile input can make a large report. | Partly in place: see residual risks |
| Denial of service | A hostile server sends unbounded data or never answers. | Lines, responses, and pages are bounded. Connections time out. Retries and waits are capped. A silent WinRM controller is stopped after `--timeout` seconds. | Partly in place: no limit on a collection's total size |
| Elevation of privilege | Content in an input runs as code or as a formula. | No `eval`, `exec`, or `pickle` on input. XML is parsed without entities. Formula-looking cells in a workbook are read as text, never evaluated. Workbook cells are written as inline strings, never formulas. CSV output neutralizes formulas, and Markdown and HTML output are escaped. | In place |
| Elevation of privilege | The exporter script runs hostile code on a computer. | One readable PowerShell file with no modules, shipped inside the package. Read it before you run it, and run it only from a verified release. `shaar collect ad` sends the script in the installed package. | In place |
| Elevation of privilege | A compromised dependency or build step runs with broad permissions. | Reading and writing need no runtime dependencies. Collectors and secret providers are optional extras with locked versions, vulnerability and license scanning, least-privilege workflow tokens, and workflow analysis with zizmor. | In place |

## Hostile workbooks

A returned packet is the input most exposed to a hostile or careless author. The reader (`formats/xlsx.py`) treats it as hostile:

- **Zip bombs.** At most 2,000 entries, 64 MiB uncompressed in total, and a ratio of 200 to 1 per entry. A duplicate entry name is refused.
- **Only the parts it needs.** It finds sheets through the workbook and its relationships, never by filename, and reads only those parts, the shared strings, and the document properties. A relationship that points outside the package is refused. External relationships are skipped.
- **XML attacks.** XML is parsed by the standard library's expat parser through a wrapper that refuses a `DOCTYPE` (so no entity is declared, expanded, or fetched), limits nesting to 64 levels, and ignores the declared encoding.
- **Formulas.** A cell that holds a formula is read as its saved value, and the row is noted. A decision cell that held a formula, or any cell in the row, makes the row `invalid`. Nothing is ever calculated.
- **OLE and encryption.** An old `.xls` file, or a password-protected workbook (a CFB container), is refused with a message. An encrypted part is refused.
- **Sizes.** By default at most 100,000 rows, 1,600,000 cells with content and a file of at most 64 MiB once unzipped; valid cell references. A bad reference or a cell outside the sheet is an error. These caps can be raised with `--limit` (see [Usage](usage.md#size-limits)); a raised cap trades memory for size, so raise it only for a file you trust to be large. The reader streams rows, so memory follows what is kept, not how many elements the file holds.
- **Macros.** shaar reads no macro or script part, and does not open the file in any spreadsheet program.

A refused workbook is `unreadable`, and its rows stay undecided. It never stops the other packets.

## Hostile exports and CSV files

- **Size and shape.** By default an export line is at most 1 MiB, a file at most 512 MiB, and a CSV at most 256 MiB and 2,000,000 rows. Each can be raised with `--limit`, and the limits a run used are in its `manifest.json`, so an auditor can see them. Hitting a limit is never silent: it is an error naming the limit (exit code 3), or, for a returned packet, a recorded unreadable packet and an incomplete record (exit code 1). A row with too many cells, a blank id, or a bad key is skipped with a problem. Maps and reviewer maps are size-limited and strictly validated, and unknown keys are errors.
- **A forged or cut export.** A wrong trailer means no resource is complete. A forger who recomputes the hash can still mislead the reviewer. See the digests preceding.
- **Injection into reports.** Values are untrusted text. CSV output neutralizes leading formula characters, Markdown output is escaped with a word joiner after `@`, `://`, and `www.`, HTML output is escaped under a content security policy that forbids scripts, and invisible or reordering characters show as visible escapes. A value can fill a cell but not forge a heading, a link, a table, or a tag. Terminal output is escaped too, and a packet's cell text is XML-escaped.
- **Injection into packets.** A name that starts with `=` is written as an inline string. Excel shows it as text. Invisible and reordering characters in names are written as visible escapes, as in the reports, so a reviewer and the operator read the same text.
- **Look-alike identities.** Matching normalizes Unicode (NFKC) and case, so a re-encoded address is the same person. Cross-script look-alikes are not detected.

## Personal data exposure

- Each packet holds only that reviewer's rows. The Review sheet shows name, account, status, last sign-in, access, and how it is granted. The Row check and Row ID are hidden columns, not secret.
- The campaign folder holds all packets, `campaign.json` with every row, and the reports, so it is as sensitive as the access data itself. Everything is created owner-only.
- Reports hold names and accounts. The decision record holds comments that reviewers wrote.
- Delete or protect the folders when the review is over. shaar does not.

## Network and credentials

- **Graph token.** Requests are GET only, over HTTPS to the configured Graph host, with no redirect followed and no foreign paging link accepted. A test proves that every request is a GET and that the token goes only to that host. The token is remembered for redaction and never logged or written.
- **WinRM.** The same transport rules as mishpat: HTTPS verifies, HTTP only with message encryption, Kerberos, Negotiate, or NTLM, host and user names checked first, no Basic and no CredSSP.
- **Secrets in errors.** Every secret and token that shaar resolves is removed, in several encodings, from every message before it is printed, including messages from authentication libraries.

## Write paths

Every file shaar writes goes through one of two safe writers. Neither follows a symbolic link at a target name, and neither replaces an existing file without `--force`. Files are created owner-only. Outputs are written to temporary files in the target folder and moved into place, and the manifest comes last. File names inside a campaign are fixed or built from the reviewer's name reduced to ASCII letters, digits, and hyphens, so no input can choose a path.

## Residual risks

- **Hash binding is not signing.** Anyone who can write the campaign folder and the returned packets can forge a consistent set. Protect the folder, and keep the returned files and `decisions.json` in a system that records who changed them.
- **A reviewer's identity is the channel's, not shaar's.** shaar cannot tell who filled in a packet.
- **A compromised controller, tenant, or exporting account can lie.** A valid trailer shows the file arrived whole.
- **Memory.** shaar reads files whole. Limits bound the size of an input, but memory use is a multiple of it. A returned workbook is read one row at a time, cells with no content are dropped, and a part may hold at most 50,000 elements at once, so a 12 MB file of empty cells peaks at about 0.2 GB instead of 2.9 GB. An input of the largest size that other readers accept can still need several times its size in memory.
- **Packet protection is an accident guard.** Any reviewer can remove a sheet's protection. The row checks catch the change only if the row is altered.
- **Secrets in the wrong place.** `file:PATH` reads the first line and does not check who can read the file. NTLM is weaker than Kerberos.
- **File permissions apply on Linux and macOS.** shaar sets no access rules on Windows.
- **Output folders.** `--force` takes away only files the same command wrote, and every command refuses a folder that holds or contains the campaign or decision record it was given, so a mistyped `-o` cannot delete a record that cannot be made again.
- **Delivery.** How packets travel to reviewers, and back, is outside shaar.
- **The collectors are untested against real systems.** Treat the first runs as a pilot.
- **Checksums and attestations protect users only if they verify them.** [Releasing](releasing.md) shows how.
