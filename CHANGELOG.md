# Changelog

All notable changes to this project are recorded in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
