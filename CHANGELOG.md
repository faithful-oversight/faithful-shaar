# Changelog

All notable changes to this project are recorded in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.1] - 2026-11-14

### Fixed

- `shaar decisions` now carries the problems the campaign recorded while reading its inputs into the decision record and its report, notes resources that were not read in full, and exits with code 1 when the review may be missing entries. Before, it said "No problems were recorded" and exited 0.
- `shaar verify` now says when the decision record it is given is not complete (undecided, Unsure, unassigned, unusable packets, input problems) and exits with code 1. Before, `0 of 0 removals verified` was a clean result for a review in which nobody had answered.
- A CSV row shorter than the header is now skipped as a problem and leaves no resource complete, instead of being padded with blanks. A file whose last line has no line break is a problem too. A cut-off row used to turn an `Approver` into a `member` and a verified removal.
- A column that the map file asks for and the file lacks is now a recorded problem. A later export with no entitlement column can no longer show that an entitlement other than `member` was removed: `shaar verify` says unknown.
- Identity text (ids, names, emails, the reviewer map) is now matched after Unicode normalization, so an address in a composed or decomposed form is the same person: not a removal, not a second packet, not a missed self-review. Names are still shown exactly as read.
- `--force` can no longer delete `campaign.json`, packets, or the decision record. shaar refuses an output folder that is, or contains, the folder of the campaign or decision record it was given, and with `--force` removes only files the same command wrote. The refusal message says what `--force` does.
- A campaign with no access entries now records a problem and exits with code 1.
- A conflicting row no longer keeps a decision in `decisions.json`.
- Invisible and reordering characters in names are now shown as visible escapes in packets and `campaign.json`, as in the reports.
- A closed pipe or an output that cannot encode a character (for example an ASCII terminal and a path with an accent) no longer turns a finished run into exit code 4. The exit code is decided before the summary is printed.
- Error messages about an unreadable input, reviewer map or column map now name the path as given.
- A returned workbook is read one row at a time and empty cells are not kept, so a 12 MB file of empty cells no longer needs about 3 GB of memory. `xmlsafe` limits the elements it holds at once.
- `shaar verify`, reviewer-map assignment and per-reviewer row lookup no longer scan every row for every row, which took hours on large inputs.
- Deeply nested `campaign.json` or `decisions.json` is a bad input (exit code 3), not an internal error.
- The reviewer map is read with a size limit from a regular file only, so `/dev/zero` or a named pipe is refused.
- The Active Directory exporter dates its export when reading starts, not when it ends.
- The commands printed by `shaar example` now run in order into a full campaign, decisions and verify run. The first sets `SOURCE_DATE_EPOCH` so the campaign matches the returned packets.
- The source archive's own tests now run in the build check: it unpacks the archive outside the checkout and runs the whole suite there, instead of only collecting the tests.
- Editing a pull request title now reruns the title check, so a corrected title clears the required check.
- The dependency audit writes its export to a private temporary directory, so a planted link or a second run at the same time cannot interfere.
- The DCO check now fails when it cannot list the commits to check, instead of reporting success.
- The release script now treats only a clean "not found" answer as an absent tag; an authentication, rate-limit, network, or malformed answer stops the release.
- The dependency audit always includes every optional extra, and a new check fails it when a package named by an extra is missing from the audited export.
- The release evidence is now one SBOM per scope: `sbom-base.cdx.json` for the base install, and `sbom-all-extras.cdx.json` when the project defines optional extras. Each states its scope, and tests check what each one holds.
- The sign-off check no longer lets a commit skip sign-off by claiming Dependabot as its author. Dependabot is exempt only on its own pull requests.
- The required "All checks passed" check now fails if a CI job is missing, and a skipped title or sign-off check no longer counts as a pass on a pull request.
- `scripts/check.sh workflows` prints a clear message instead of a stack trace when GitHub rejects the token.
- `SECURITY.md` no longer says that no release has been published. It says the latest release is supported.

### Added

- `--limit NAME=VALUE` on `campaign`, `decisions` and `verify` raises any of the size limits (CSV, export, line, reviewer map, column map, `campaign.json`, `decisions.json`, returned packets, workbook rows, cells, bytes and XML elements). A file over a limit stops the run with exit code 3 and says which limit to raise; a returned packet over a limit is recorded as unreadable. Every run records the limits it used in `limits` in `manifest.json` (an optional field of `manifest-v1`).

### Changed

- The README now has a status line, a short account of how shaar differs from other kinds of tools, a runnable five-minute example with real output, and install instructions that work today (from GitHub, with `pipx ensurepath`). There is a new quickstart and an examples page.
- `shaar example` no longer writes a `campaign/` folder; the first printed command makes it.
- The package keyword `compliance` is now `audit-evidence`.
- The documentation no longer names the maintainer.
- The committed example and its reports are regenerated.
- Dependabot groups minor and patch updates of runtime dependencies into one pull request.
- `CONTRIBUTING.md` lists every tool a clean machine needs and which checks need network access or a token.
- The releasing guide covers the first PyPI publish, a failed PyPI step, scheduled checks that stop after 60 idle days, both SBOM files, and the pinned tools.

### Security

- Closed the three ways shaar could report a clean or complete result when it was not (campaign problems dropped by `decisions`, a short or cut-off CSV row, an incomplete record verified).
- Khmer and Mongolian marks that draw nothing (U+17B4, U+17B5, U+180B to U+180D, U+180F) now print as visible escapes, and an issue reference such as `#123` from the input is no longer turned into a link in the Markdown report.
- A release now stops with a clear message when the `FO_PUBLIC` setting disagrees with whether the repository is public, so a public release cannot skip provenance and PyPI by mistake.
- Release jobs check the built files against `SHA256SUMS` before attesting, uploading or publishing.
- uv and the Vale style packages used in CI are pinned to exact versions, and the style packages are checked against a SHA-256 before use.

## [0.1.0] - 2026-11-13

First release.

### Added

- `shaar campaign`, which reads access exports and CSV files, assigns one reviewer to every entry by manager, resource owner, or a reviewer map, and writes `campaign.json` and one Excel packet per reviewer, plus a report and a manifest. One person gets one packet across systems, nobody reviews their own access, and entries with no reviewer are listed and never dropped.
- Packet workbooks written by hand with no dependency: a Review sheet with a Keep, Remove, or Unsure list, hidden row identifiers and row checks, and an About sheet. They are byte-for-byte reproducible and are tested with LibreOffice and openpyxl round trips.
- `shaar decisions`, which reads returned packets with a hardened reader and checks each row against the campaign. A row is accepted, undecided, invalid, altered, in conflict, or unassigned. Rows from elsewhere are listed as strays. Unsure needs follow-up. The reviewer recorded is the one the campaign assigned. `--require-comment` demands a comment. It writes `decisions.json` and the list of removals to make.
- Hash binding of campaigns: a row check for each row, a packet digest for each packet, and a digest for `campaign.json` and `decisions.json`.
- `shaar verify`, which checks each accepted removal against a later export as removed, pending, failed, or unknown. A removal is verified only when the later input read the whole resource. It also lists kept access that is gone and access that is new since the review.
- The shaar export, a JSON Lines format with a header, records, and a trailer with a record count and a SHA-256, and keys that match principals, resources, and grants across inputs.
- CSV inputs with a TOML column map and the presets `generic`, `ad-users-groups`, and `entra-members`.
- `shaar exporter`, which writes a read-only PowerShell exporter for Active Directory groups with ranged member retrieval, nesting, primary groups, foreign security principals, managers, and owners.
- `shaar collect ad`, which runs the exporter over WinRM (the `ad` extra) with HTTPS verification, encrypted HTTP only, and secret references for `env`, `file`, `keyring`, `vault`, `aws`, and `azure`.
- `shaar collect entra`, which reads groups, owners, managers, directory roles, and eligible roles from Microsoft Graph v1.0 with GET requests only (the `entra` extra, using `azure-identity`), for the global, US government, US defense, and China clouds.
- Reports as JSON, Markdown, HTML, and CSV for each command, with a manifest of SHA-256 digests, published JSON Schemas for the reports and the manifest (`shaar schema`), and CSV formula neutralization.
- `shaar example`, which writes a synthetic review for `corp.example` that runs from campaign to verification.
- Support for `SOURCE_DATE_EPOCH`, so the same inputs give the same files.
- User documentation: usage, campaigns, verification, collecting, formats, reports and output, limitations, architecture, and threat model.
- Decision records 4 to 7: the export format, collectors, campaign integrity, and packet workbooks.
- Project foundation: license, documentation, contribution and security policies, continuous integration, and release pipeline.

### Changed

- The license check reads optional extras and platform-specific dependencies correctly, matching merilo and toledot. It no longer replaces a license a package states with a generic classifier, and reviewed exceptions are pinned to a package version.

### Fixed

- The source archive now includes `scripts`, which its tests import, and the build check collects the tests from an extracted copy.
- Findings from the second independent review, fixed before release:
  - Entra keys carry the tenant id, which `shaar collect entra` takes from the token, and well-known AD SIDs carry the domain. An id without one is never part of a complete resource, so an export from another tenant or domain cannot verify a removal.
  - A directory role grant's entitlement is its scope (`whole directory` or `scope ID`), never the role's name, so renaming a role or a refused name lookup does not make every grant look removed. Each scope is its own grant.
  - An eligible (PIM) role counts only while its schedule is provisioned and in force. Records Microsoft Graph returned but shaar could not read make their group or role incomplete.
  - A CSV without `collected_at` no longer takes another input's time. Each resource is dated by the inputs that hold it.
  - An export record of an unknown type makes the file incomplete.
  - A `|` or `%` in a name can no longer make two grants share a key.
  - The campaign id covers the due date, the reviewer rule, and the reviewer map, and the packet digest covers the reviewer, so a packet from a differently assigned campaign is rejected.
  - A packet with two Decision (or other known) columns, and a reviewer map with a repeated column or a row of the wrong width, are refused instead of read one way.
  - shaar refuses to write a packet too large to read back.
  - With `--force`, files from the earlier run that the new run does not write are taken away.
  - A reviewer map field too long for CSV, a non-text `encoding` in a column map, and a workbook with an undecodable entry name are input errors, not internal errors.
  - The AD exporter marks a group incomplete when a nested group's primary-group members cannot be read, lists one route per holding group and nesting group in `extra.paths`, reports every nesting cycle, and checks the lower bound of the last ranged member read.
- Findings from the independent recheck (routine round 1), fixed before release:
  - CSV quoting is read strictly. An unclosed quote, or text after a closing quote, makes the file incomplete instead of hiding the rows after it inside one cell.
  - A reviewer map `reviewer_id` that appears with two names or two emails is refused, so one packet never mixes two people's entries or lets someone review their own access.
  - One export resource id given as two resources (a group and a role) leaves both incomplete instead of moving its grants to one of them.
  - The reviewer map header check is linear. The AD exporter writes the total cycle count beside the first five cycles and marks how many more there were. PowerShell telemetry is turned off in tests, the syntax check, and CI.
- Findings from the independent recheck (routine round 2), fixed before release:
  - Delimiter detection tries each delimiter on its own, so a CSV whose header cells are all quoted is read again with any supported delimiter. Strict quoting stays in force for the chosen delimiter.
  - An Entra role assignment whose scope is blank or has spaces around it is a gap that makes its role incomplete, instead of a grant on the scope `scope`.
