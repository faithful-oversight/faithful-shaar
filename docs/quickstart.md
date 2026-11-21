# Quickstart

This page runs a whole review on made-up data in about five minutes. Nothing in it touches a real system. Install shaar first (see the [README](https://github.com/faithful-oversight/faithful-shaar#install)): PyPI publishing is being set up, so until a PyPI release exists, install from GitHub with `pipx install git+https://github.com/faithful-oversight/faithful-shaar`, then run `pipx ensurepath` once if `shaar` is not found.

## 1. Write the example

```shell
shaar example shaar-demo
```

This writes `shaar-demo/before/` (an Active Directory export, an Entra export, a CSV from a made-up finance application with its column map), `shaar-demo/returned/` (three packets as reviewers sent them back), and `shaar-demo/after/` (access read again after the due date). It prints three commands, with the paths you typed. Run them in order.

## 2. Make the campaign

The first command starts with `SOURCE_DATE_EPOCH=...`. That fixes the time the campaign is made at, which is the time the returned packets were prepared for. A campaign made at any other time has another id, and shaar refuses packets from another campaign. A real review does not set it.

```text
13 access entries for 3 reviewers. 2 entries have no reviewer.
```

It exits with code `1`: two entries have no manager, so no reviewer. The folder `shaar-demo/campaign` holds `campaign.json`, one packet for each reviewer, and a report.

## 3. Read the returned packets

The second command reads the three returned packets against the campaign:

```text
12 of 13 entries have an accepted decision; 5 removals to make. 4 items need attention.
```

Exit code `1` again, on purpose: one row was left blank, one is marked Unsure, and the two entries with no reviewer have no decision. `shaar-demo/decisions/removals.csv` is the list for an administrator to act on. See the [decisions report](https://github.com/faithful-oversight/faithful-shaar/blob/main/examples/corp-example/decisions/decisions-report.md).

## 4. Verify the removals

The third command compares the later export with the removals:

```text
2 of 5 removals verified. Still present: 1 past due, 0 not yet due. Unknown: 2.
The decision record is not complete, so this does not show that the review was carried out: ...
```

Two removals were made. One was not (the contractor still has the access). Two are unknown because the later export did not read those resources in full. The decision record is not complete, so the exit code is `1` however many removals were made. See the [verification report](https://github.com/faithful-oversight/faithful-shaar/blob/main/examples/corp-example/verification/verify-report.md).

## What next

- Use your own exports: see [Formats](formats.md) for the CSV column map and [Collecting](collecting.md) for the exporter.
- Read [Campaigns](campaigns.md) for how reviewers are chosen and [Verification](verification.md) for what each result means.
- The result of a review is never a statement that access is appropriate or that a standard is met: it says what was read, what was decided, and what could be checked.
