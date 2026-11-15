# Limitations

shaar is narrow on purpose. This page lists what it cannot do, so nobody relies on it for more than it provides.

## Out of scope

The tool will not:

- Grant, change, or remove access. It reads exports and writes workbooks and reports. An administrator makes the removals, and `shaar verify` checks them later.
- Replace an identity governance platform. It has no workflow, reminders, escalation, web interface, or ticketing.
- Judge whether access is appropriate. That is each reviewer's decision.
- Show what a group or role lets its members do. It shows only who holds it.
- Sign or authenticate anything. See [what the digests protect](threat-model.md#what-the-digests-do-and-do-not-protect).

## How far this release has been tested

- **No real system.** No collector has run against a real domain, a real WinRM endpoint, or a real Entra tenant. The exporter runs under PowerShell 7 against synthetic stand-ins, the remote collector against a simulated WinRM client, and the Entra collector against a fake Graph server. Windows PowerShell 5.1 has not been run. Treat the first runs as a pilot.
- **No Excel, no Google Sheets.** Packets are tested with LibreOffice and openpyxl round trips and with a hand-made file in the shared-string form that Excel writes. A packet has not been opened, edited, and saved in Microsoft Excel or Google Sheets. <!-- TODO(verify): confirm in Excel (desktop and web) and Google Sheets that the Decision list, the protection, and the hidden columns behave as described, and that the saved file reads back. -->
- **No file from Windows.** No test reads a file that Windows wrote.
- The example and its sample reports are synthetic.

## Packets

- **Sorting.** The sheet is protected, and only the Decision and Comment cells are unlocked. Excel may refuse to sort a protected range that holds locked cells, so a reviewer who wants to sort may have to copy the data or remove the protection. The protection has no password, and removing it does not affect shaar's checks. <!-- TODO(verify): the sheet allows sorting and filtering in its protection settings, but the code does not show how each spreadsheet program treats a sort over locked cells. -->
- **Personal data.** A packet holds names, accounts, and access of the people in it. Send each packet only to its reviewer, over a channel you would use for that kind of data.
- **Long text.** A cell longer than 32,767 characters is cut with a marker, and a character that XML does not allow becomes U+FFFD. Invisible and reordering characters in a name (zero-width characters, right-to-left marks) are written in the packet and in `campaign.json` as visible escapes such as `\u202e`, so the reviewer reads what the reports show.
- **A reviewer can claim anything.** shaar records the assigned reviewer, not who typed. See [the reviewer of record](campaigns.md#the-reviewer-of-record).

## Reviewers

- Nobody can be recognized as the same person across systems except by key or by identical email address. A person with a different address in each system gets a packet for each.
- Under the owner rule, one owner reviews an entry and the others are only named. Owners are not asked in turn.
- Entries with no reviewer are never sent. No fallback reviewer exists.
- Merging by email is crude. A shared mailbox merges people into one packet, and a person with two addresses gets two.

## What the inputs cannot show

- **Hidden attributes.** Active Directory hides an attribute that an account may not read, and the result looks like an empty one. A group whose members the exporting account cannot read can look empty, and nothing in the export tells shaar so. Export with an account that can read the groups.
- **Last sign-in lags.** The Active Directory last sign-in is `lastLogonTimestamp`, which controllers replicate with up to about 14 days of lag. It can be that much out of date. Entra `signInActivity` is not read, so Entra principals have no last sign-in.
- **Foreign groups.** A group from another domain across a trust is not expanded: its own members are not listed.
- **Entra roles held by groups.** A role assigned to a group is not expanded to the group's members. The collector writes a gap and the group appears as the holder. Collect the group with `--group` to review its members.
- **Nested groups.** Nesting is expanded up to 5,000 groups for each exported group in Active Directory and 1,000 in Entra, then a gap says the rest were not.
- **One moment, one controller.** An export is not a snapshot. Groups are read one after another, from one controller, and a controller that has not replicated a change shows the older state.
- **A truncated CSV.** A row shorter than the header, or a last line with no line break, is a problem and leaves no resource complete. A file cut exactly at a row boundary cannot be told from a whole one. Use an export with a trailer where you can.
- **Look-alike letters.** Text is compared after Unicode normalization (NFKC) and case folding. Letters of another script that look the same (Cyrillic a and Latin a) stay different, and shaar does not flag a name that mixes scripts.
- **A CSV's completeness cannot be known.** shaar treats a CSV as complete unless its map says `complete = false`. A filtered or truncated CSV looks complete, and a removal can then be called `removed` when the row was only left out.
- **Matching by name.** A CSV with no id column matches principals and resources by name. Two people with one name become one person, and a renamed person looks like a new one.
- **Managers and owners need records.** The manager and owner rules work only where the inputs hold managers and owners, and the manager or owner is in the inputs.

## What the decision record does not show

- That a review covered everyone. It covers what the campaign was given. When the campaign recorded input problems or did not read a resource in full, `shaar decisions` and `shaar verify` say so and exit with `1`, but they cannot name the people who were left out.

## What verification cannot prove

- That a removal was made by the person who should have made it, or for the reason given.
- That access was not given back, or granted elsewhere, between the two exports.
- Anything about access that the later input did not record.
- That the later export is true. An export is as honest as the system and the account that produced it.
- `removed` for a resource that was not read completely. That is `unknown` by design.
- A role removal when the later collection used different `--roles` and `--pim` choices from the first.

See [Verification](verification.md).

## Collection

- **Entra collection** reads only the groups and roles you ask for. `--all-security-groups` can be large, and Graph can throttle it. Managers are read one user at a time, for at most 20,000 users.
- **Device-code sign-in** and the permissions it needs have not been tried against a tenant.
- **Rights for remoting.** The account needs to open a PowerShell remoting session and to read the groups. Whether a just-enough-administration endpoint can be narrowed further has not been tested.
- **Kerberos on Linux and macOS** needs support that the `ad` extra does not install.
- **A compromised controller or tenant can lie.** A valid trailer shows that the file arrived whole.

## Size limits

shaar refuses or records as a problem:

- An export file over 512 MiB, or a line over 1 MiB.
- A CSV over 256 MiB or 2,000,000 data rows.
- A returned packet over 64 MiB. A workbook with more than 2,000 zip entries, more than 64 MiB uncompressed, an entry that expands more than 200 to 1, or a sheet of more than 100,000 rows.
- XML that nests more than 64 levels.
- A `campaign.json` or `decisions.json` over 256 MiB, and a reviewer map over 16 MiB, a column map over 1 MiB.

## Inputs that change during a run

shaar fingerprints each input and then reads it. If a file changes in between, the manifest describes a different version from the one read. Use inputs that nothing is writing to.

## Limits of any file-based check

- shaar sees only what the inputs contain. A clean result means no findings in the supplied inputs. It is not proof that the environment is correct.
- Results are only as current as the inputs. Reports show the time the inputs were read when they record it.
- Hashes show consistency, not authorship.
