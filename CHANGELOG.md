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
