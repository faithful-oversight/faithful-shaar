# Usage

```text
shaar [--version] COMMAND [options]
```

| Command | What it does |
| --- | --- |
| `campaign` | Read access exports, assign a reviewer to every entry, and write the campaign and one packet per reviewer. |
| `decisions` | Read the returned packets, check each against the campaign, and write the decision record. |
| `verify` | Check a later export: were the accepted removals made? |
| `exporter` | Write the PowerShell exporter, to run on a domain-joined computer yourself. |
| `collect ad` | Run the exporter on a domain controller over WinRM. Needs the `ad` extra. |
| `collect entra` | Read Entra ID through Microsoft Graph. Needs the `entra` extra. |
| `schema` | Print a JSON Schema. |
| `example` | Write synthetic exports, returned packets, and a later export. |

Run `shaar COMMAND --help` for the options of any command. Running `shaar` with no command prints the help and exits with code `2`.

## `campaign`

```shell
shaar campaign INPUT... -o DIR --name NAME --reviewers {manager,owner,map} [options]
```

| Option | Meaning |
| --- | --- |
| `INPUT` | One or more access inputs: [shaar exports or CSV files](formats.md). shaar detects the kind of each from its content. Inputs from different systems can be mixed. |
| `-o`, `--output` | Folder for the campaign. Required. Created if needed. |
| `--name` | The campaign's name. It appears in every packet and report. Required. |
| `--reviewers` | Who reviews each entry: `manager`, `owner`, or `map`. Required. See [Campaigns](campaigns.md#choosing-reviewers). |
| `--reviewer-map` | A CSV that names reviewers. Required with `--reviewers map`, and refused with any other rule. |
| `--due` | The date decisions and removals are due, as `YYYY-MM-DD`. [Verification](verification.md#due-date) uses it to tell `pending` from `failed`. |
| `--map` | A TOML column map for CSV inputs. See [CSV column maps](formats.md#the-column-map). |
| `--preset` | A built-in column map: `generic`, `ad-users-groups`, or `entra-members`. |
| `--resource` | The one resource a members-only CSV lists, such as the group an Entra portal download came from. |
| `--force` | Replace this command's own files that already exist. See [what `--force` does](#replacing-existing-files). |

`--map`, `--preset`, and `--resource` apply to every CSV input of the command. Run a different command, or write one map that fits all the CSV files, when your CSV files differ.

The command writes `campaign.json`, one packet for each reviewer, the campaign report in JSON, Markdown, and HTML, `rows.csv`, `unassigned.csv` when any entry has no reviewer, and `manifest.json`. See [Reports and output](output.md#campaign).

Keep the campaign folder. `shaar decisions` and `shaar verify` need `campaign.json`, and a second `campaign` run makes a new campaign with a new id, so its packets do not match the first.

A reviewer who has an email address gets one packet, even when that person appears in several systems. See [Campaigns](campaigns.md#one-reviewer-per-person).

## `decisions`

```shell
shaar decisions CAMPAIGN PACKET... -o DIR [--require-comment DECISION] [--force]
```

| Option | Meaning |
| --- | --- |
| `CAMPAIGN` | The campaign folder, or its `campaign.json`. |
| `PACKET` | One or more returned workbooks. Give every file you received. |
| `-o`, `--output` | Folder for the decision record. Required. |
| `--require-comment` | A decision that must have a comment: `Keep`, `Remove`, or `Unsure`. Repeat the option for more than one. A row that lacks the comment is [invalid](campaigns.md#what-makes-a-decision-count). |
| `--force` | Replace files that already exist. |

Two packets must not share a file name, because every decision cites its packet by name. shaar refuses the run with exit code `2` and names the file.

The command writes `decisions.json`, `removals.csv`, `attention.csv`, `decisions.csv`, the decisions report in JSON, Markdown, and HTML, and `manifest.json`. See [Reports and output](output.md#decisions).

## `verify`

```shell
shaar verify CAMPAIGN DECISIONS LATER... -o DIR [options]
```

| Option | Meaning |
| --- | --- |
| `CAMPAIGN` | The campaign folder, or its `campaign.json`. |
| `DECISIONS` | The decisions folder, or its `decisions.json`. |
| `LATER` | One or more exports or CSV files read after the removals were due. |
| `-o`, `--output` | Folder for the verification report. Required. |
| `--as-of` | When the later access was read, as an ISO 8601 time such as `2026-11-20T09:00:00Z`. A time with no offset is taken as UTC. It replaces the time the inputs record. |
| `--map`, `--preset`, `--resource` | As for `campaign`, for CSV inputs. |
| `--force` | Replace files that already exist. |

shaar refuses a decision record that does not belong to the campaign as written, with exit code `3`. The command writes `removals.csv`, `kept_but_gone.csv`, `new_since_review.csv`, the verification report in JSON, Markdown, and HTML, and `manifest.json`. See [Verification](verification.md).

## `exporter`

```shell
shaar exporter DIR [--force]
```

Writes `Export-ShaarAccess.ps1` into `DIR`, creating the folder if needed, and prints the command that runs it. It replaces an existing script only with `--force`. See [Collecting](collecting.md#the-exporter-script).

## `collect ad`

```shell
shaar collect ad --host HOST (--group GROUP... | --search-base DN | --privileged) -o FILE [options]
```

Runs the exporter on a domain controller over PowerShell remoting and writes its export. Needs the `ad` extra. [Collecting](collecting.md#collecting-over-winrm) explains the requirements and the security rules.

| Option | Meaning |
| --- | --- |
| `--host` | The controller's fully qualified DNS name, such as `dc01.corp.example`. Required. An IP address or a bare host name is refused. |
| `--group` | Groups to export, each a name, a distinguished name, or a SID. Give one or more. |
| `--search-base` | A distinguished name. Every group below it is exported. |
| `--privileged` | Export the well-known privileged groups. |
| `--auth` | `kerberos` (default), `negotiate`, or `ntlm`. |
| `--username` | `DOMAIN\user` or `user@domain.example`. |
| `--secret` | A [secret reference](collecting.md#secret-references) for the password. Never the password itself. |
| `--transport` | `https` (default) or `http`. HTTP is used only with message encryption. |
| `--port` | From 1 to 65535. Default: 5986 for `https`, 5985 for `http`. |
| `--ca-file` | A PEM file of certificate authorities for HTTPS. Refused with `http`. |
| `--timeout` | Stop when the exporter sends nothing for this many seconds, from 1 to 86400. Default: 600. |
| `-o`, `--output` | The export file to write. Required. |
| `--force` | Replace an existing file. |

Give at least one of `--group`, `--search-base`, and `--privileged`. `--username` and `--secret` go together: give both, or leave both out to use the current Kerberos ticket. `--auth ntlm` always needs both. These pairings exit with code `2`. A bad `--host` or `--username`, and `--ca-file` with `--transport http`, exit with code `3`.

## `collect entra`

```shell
shaar collect entra --tenant TENANT --client-id ID \
  (--certificate PATH | --client-secret REF | --device-code) \
  (--group ID|NAME... | --all-security-groups | --roles | --pim) -o FILE [options]
```

Reads Entra ID through Microsoft Graph with GET requests only and writes a shaar export. Needs the `entra` extra. See [Collecting](collecting.md#the-entra-collector).

| Option | Meaning |
| --- | --- |
| `--tenant` | The tenant id (a GUID) or a verified domain name. Required. |
| `--client-id` | The application (client) id, a GUID. Required. |
| `--certificate` | A PEM or PFX file for certificate sign-in. |
| `--certificate-password` | A secret reference for the certificate's password. Needs `--certificate`. |
| `--client-secret` | A secret reference for the application's client secret. |
| `--device-code` | Sign in as yourself with a device code. |
| `--cloud` | `global` (default), `usgov`, `usgovdod`, or `china`. |
| `--group` | Groups to read, each an object id or a display name that matches exactly one group. Give one or more. |
| `--all-security-groups` | Read every security-enabled group. |
| `--roles` | Read active directory role assignments. |
| `--pim` | Read eligible (Privileged Identity Management) role assignments. |
| `-o`, `--output` | The export file to write. Required. |
| `--force` | Replace an existing file. |

Give exactly one of `--certificate`, `--client-secret`, and `--device-code`, and at least one of `--group`, `--all-security-groups`, `--roles`, and `--pim`. Missing choices exit with code `2`. A missing extra, a refused sign-in, an unreadable certificate or secret, or an existing output file exits with code `3`. A part Graph would not return does not stop the run: it is printed as a `not read:` line and recorded in the file.

## `schema`

```shell
shaar schema {campaign-report-v1|decisions-report-v1|verify-report-v1|manifest-v1}
```

Prints a JSON Schema for the installed version, with no network access. See [Reports and output](output.md#json-schemas).

## `example`

```shell
shaar example DIR [--force]
```

Writes a synthetic review into `DIR`: exports for a made-up domain, `corp.example`, an Entra export, a CSV from a made-up finance application with its column map, returned packets, and a later export. It then prints three commands to run in order: the first makes the campaign (it sets `SOURCE_DATE_EPOCH` to the time the returned packets were prepared for, because a campaign made at another time has another id and refuses them), the second reads the returned packets, and the third verifies. All three exit with code `1` on purpose; the [quickstart](quickstart.md) shows each result. Without `--force`, shaar refuses to replace existing files.

### Replacing existing files

Without `--force`, shaar never replaces a file. With it, shaar replaces the files the command writes and takes away files an earlier run of **the same command** wrote there that this run does not (a packet for a reviewer who no longer has entries, for example). It never takes away `campaign.json`, `decisions.json`, or a packet when another command is writing, and it refuses an output folder that is, or contains, the folder of the campaign or decision record the command was given, or that already holds a record the command does not write. Use a new folder for each run.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Success, and nothing needs attention. Also `--help`, `--version`, `schema`, `example`, `exporter`, `collect ad`, and `collect entra` when they succeed, even when they print `not read:` lines. |
| `1` | `campaign`, `decisions`, or `verify` wrote its files, and the result needs attention. The rules are below. |
| `2` | The command was used incorrectly: an unknown or missing option, a bad value, options that do not go together, two packets with one file name, or `shaar` with no command. |
| `3` | An input, output, or collection problem: an unreadable or oversized input, a CSV with no column map, a bad map, a campaign or decision record that fails its digest, an output file that exists without `--force`, a failed collection. |
| `4` | An internal error in shaar. This is a bug. Please report it. |

Exit code `1` never means the tool failed. It means read the report.

### When each command returns 1

| Command | Exit code `1` when |
| --- | --- |
| `campaign` | At least one entry has no reviewer, any input could not be read in full (a problem is recorded), or the inputs hold no access entries at all. The files are written either way. |
| `decisions` | The record is not complete: any entry lacks an accepted decision (undecided, invalid, altered, conflict, or unassigned), any accepted decision is Unsure, any row did not belong to its packet, any returned file was rejected or unreadable, or the campaign itself recorded problems reading its inputs or had a resource it did not read in full (entries may be missing from the review). |
| `verify` | Any accepted Remove is not verified as removed (pending, failed, or unknown), **or the decision record is not complete** for any of the reasons in the `decisions` row. Kept-but-gone and new-since-review entries, and problems in the later inputs, never change the code. |

A `verify` run exits with `0` only when the decision record is complete and every accepted removal is verified. With a complete record and no accepted removals it exits with `0`. With an incomplete record it exits with `1` even if no removal was decided, and says so in its headline and in the report.

## Repeatable output

Every report records the time it was written. Set `SOURCE_DATE_EPOCH` to a whole number of seconds since 1970-01-01 UTC, and shaar uses that time instead of the clock. The campaign's `created_at`, its id, the row identifiers, the packet workbooks (their zip dates and document properties), the reports, and the manifests are then byte-for-byte the same for the same inputs. `shaar collect entra` also takes its `collected_at` from it.

```shell
SOURCE_DATE_EPOCH=1793000000 shaar campaign ad.jsonl -o campaign --name Q4 --reviewers manager
```

A value that is not a whole number of seconds, or is out of range, is ignored and shaar uses the clock. It does not warn.

## Output folders and files

- A new output folder is readable only by your user account on Linux and macOS, and so is every file in it.
- Without `--force`, shaar never replaces an existing file, even one that appears while it runs. It stops with exit code `3` and names the files.
- With `--force`, shaar moves the old files aside and puts them back if any step fails, so the folder holds either the old set or the new set. Files the earlier run's `manifest.json` lists that the new run does not write, such as a packet for a reviewer who is no longer in the campaign, are taken away too. Other files in the folder are left alone.
- A symbolic link at a target name is replaced, never followed.
- The manifest is written last. A manifest means every other file is in place.
- Run one shaar at a time per output folder. A crash or power loss while writing can leave a partial file or `.shaar-old-*` backups. The manifest lists the size and SHA-256 of every file from its run, so that is detectable.

shaar sets no access rules on Windows. Check the folder's permissions there.

## Use in a pipeline

`shaar campaign`, `decisions`, and `verify` need no network and no secrets, so they run anywhere Python does.

```shell
shaar verify campaign decisions after/ad.jsonl -o verification || test $? -eq 1
```

Treat exit code `1` as `read the report`, and codes `2`, `3`, and `4` as failures. Collect on a schedule by giving `shaar collect` a secret reference that your scheduler fills in, for example `--secret env:SHAAR_PASSWORD`. Never put a password on the command line.
