# shaar

**Access Review Kit.** Runs an offline access review: access data in, reviewer packets out, decisions back in, and a verification of what actually changed.

[![CI](https://github.com/faithful-oversight/faithful-shaar/actions/workflows/ci.yml/badge.svg)](https://github.com/faithful-oversight/faithful-shaar/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

> **Status:** Beta. shaar 0.1.0 runs a whole access review end to end and is tested on synthetic data. The Active Directory exporter, `shaar collect ad`, and `shaar collect entra` have not been run against a real domain, a real WinRM endpoint, or a real Entra tenant, and packets have been tested with LibreOffice and openpyxl, not with Excel or Google Sheets. Run a small pilot review first. See [Limitations](docs/limitations.md).

## About the name

*shaar* (SHAR). Hebrew: gate, where the elders sat to judge who could enter.

## What it does

shaar runs an access review from files. It reads who holds access in Active Directory, Entra ID, or any system that can export a CSV, picks one reviewer for every entry (the person's manager, the resource's owner, or a name from your list), and writes one Excel workbook per reviewer. Reviewers mark each row Keep, Remove, or Unsure and return the workbook. shaar checks every returned row against what it sent, writes a decision record and the list of removals for an administrator to make, and later reads a fresh export to say whether each removal really happened. Where it cannot tell, it says unknown. It never grants, changes, or removes access.

## The four steps

1. **Start a campaign.** shaar reads the exports, assigns reviewers, and writes `campaign.json` and one packet per reviewer.

   ```shell
   shaar campaign ad.jsonl entra.jsonl ledger.csv --map ledger-map.toml \
     --name "Q4 2026 access review" --reviewers manager --due 2026-11-16 -o campaign
   ```

2. **Send the packets.** Each reviewer gets only their own file from `campaign/packets`. They fill in the Decision column and send it back.
3. **Read the decisions.**

   ```shell
   shaar decisions campaign returned/*.xlsx -o decisions
   ```

   The report lists accepted decisions, the removals to make, and every row that needs attention.

4. **Verify.** After the due date, export access again and check the removals.

   ```shell
   shaar verify campaign decisions after/ad.jsonl after/entra.jsonl after/ledger.csv \
     --map ledger-map.toml -o verification
   ```

Try all of it with made-up data: `shaar example ./shaar-demo` writes the exports, returned packets, and a later export, and prints the three commands. The [usage guide](docs/usage.md) explains every option, and [campaigns](docs/campaigns.md) explains how reviewers are chosen and which returned rows count.

## Inputs

- **shaar exports** from the PowerShell exporter (`shaar exporter DIR`) or from `shaar collect ad` and `shaar collect entra`. They record nesting, owners, managers, and whether each group was read in full. See [Collecting](docs/collecting.md).
- **CSV files** from any other system, with a column map (`--map FILE.toml`) or a built-in preset (`--preset generic`, `ad-users-groups`, or `entra-members`). shaar cannot know whether a CSV is complete, so it treats it as complete unless the map says otherwise. See [Formats](docs/formats.md).

shaar detects the kind of each input from its content, not its name.

## What it will not do

- Grant, change, or remove access. An administrator makes the removals. shaar only checks them later.
- Replace an identity governance platform. It has no workflow, no reminders, and no web interface.
- Prove that a reviewer was who the workbook says. Packets are bound to the campaign by hashes, not signed.
- See access that no input recorded, or judge whether access is appropriate.

See [Limitations](docs/limitations.md) and the [threat model](docs/threat-model.md).

## Install

shaar needs Python 3.11 or newer. Reading files and writing packets needs no other package.

```shell
pipx install faithful-shaar
```

Collecting and secret providers are optional extras:

| Extra | Adds | Needed for |
| --- | --- | --- |
| `ad` | `pypsrp` | `shaar collect ad`, which runs the exporter over WinRM |
| `entra` | `azure-identity` | `shaar collect entra`, which signs in to Microsoft Graph |
| `keyring` | `keyring` | `--secret keyring:...` |
| `vault` | `hvac` | `--secret vault:...` |
| `aws` | `boto3` | `--secret aws:...` |
| `azure` | `azure-identity`, `azure-keyvault-secrets` | `--secret azure:...` |

```shell
pipx install "faithful-shaar[ad,entra]"
```

To work from source, see [CONTRIBUTING.md](CONTRIBUTING.md).

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Success, with nothing that needs attention. |
| `1` | `campaign`, `decisions`, or `verify` finished and found something to act on. |
| `2` | The command was used incorrectly. |
| `3` | An input, output, or collection problem. |
| `4` | An internal error in shaar. This is a bug. |

## Design goals

- **Read-only.** The tool never changes the systems it examines. Collectors only read, and the Entra collector sends only GET requests.
- **Explicit unknowns.** A removal that cannot be checked is unknown, never removed.
- **Traceable findings.** Every finding cites its file and place, and every output has a manifest with SHA-256 digests.
- **Private by default.** Packets hold one reviewer's rows. Files are owner-only and never overwritten without `--force`.
- **Synthetic test data only.** No real organization's data is ever committed.

## Documentation

- [Usage](docs/usage.md)
- [Formats](docs/formats.md)
- [Campaigns](docs/campaigns.md)
- [Verification](docs/verification.md)
- [Collecting](docs/collecting.md)
- [Reports and output](docs/output.md)
- [Limitations](docs/limitations.md)
- [Architecture](docs/architecture.md) and [threat model](docs/threat-model.md)
- [Releasing](docs/releasing.md) and [decision records](docs/adr/)

## Security

Please do not report security problems in public issues. See [SECURITY.md](SECURITY.md).

## Contributing

Contributions are welcome. Read [CONTRIBUTING.md](CONTRIBUTING.md) and the [code of conduct](CODE_OF_CONDUCT.md) first.

## License

Copyright 2026 Faithful Oversight, LLC. Licensed under the [Apache License, Version 2.0](LICENSE).
