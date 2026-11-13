# Access review decisions: Q4 2026 access review

12 of 13 entries have an accepted decision; 5 removals to make. 4 items need attention.

| Item | Value |
| --- | --- |
| Campaign | Q4 2026 access review |
| Campaign ID | C21f06e77d8c77003 |
| Packets read | 3 of 3 returned files |
| Comment required for | no decision |

| Count | Number |
| --- | --- |
| Accepted | 12 |
| Removals to make | 5 |
| Undecided | 1 |
| Not valid | 0 |
| Changed after sending | 0 |
| Copies disagree | 0 |
| No reviewer | 2 |
| Rows from elsewhere | 0 |

## Removals to make (5 rows)

Accepted Remove decisions. shaar does not remove access: an administrator makes these changes, and shaar verify checks them later.

| Row ID | User | Account | Access to | Access | Reviewer | Comment |
| --- | --- | --- | --- | --- | --- | --- |
| R72d2dc2d4e95 | Emery Contractor | emery.contractor@⁠corp.example | Payroll App Users | member | Casey Owner | Contract ended |
| Radff3f4f68d7 | Emery Contractor | emery.contractor@⁠corp.example | Server Operators | member | Casey Owner | Contract ended |
| R070a8260809e | Blake Sample | blake.sample@⁠corp.example | Finance Admins | member | Morgan Lead | Left the company in September |
| R3c13774fa103 | Blake Sample | blake.sample@⁠corp.example | Ledger | Viewer | Morgan Lead | Left the company in September |
| R01318e99338d | Drew Analyst | drew.analyst@⁠corp.example | Payroll App Users | member | Morgan Lead | Moved to another team |

## Needs attention (4 rows)

Entries without an accepted decision, and rows that did not belong in the packet they came in.

| Row ID | Reviewer | User | Access to | Outcome | Why it needs attention | Source |
| --- | --- | --- | --- | --- | --- | --- |
| R60b815364cb6 | Morgan Lead | Drew Analyst | Ops Helpers | undecided | no decision | returned-03-Morgan-Lead-e16dc6.xlsx, Review row 7 |
| R2a6be5aaf266 | Morgan Lead | Drew Analyst | Server Operators | unsure | the reviewer was unsure; follow up for Keep or Remove | returned-03-Morgan-Lead-e16dc6.xlsx, Review row 10 |
|  |  |  |  | unassigned | the input names no manager for this principal | ledger.csv, row 2 |
|  |  |  |  | unassigned | the input names no manager for this principal | ad.jsonl, line 16 |

## Every entry (15 rows)

The outcome for every entry of the campaign.

| Row ID | Reviewer | User | Access to | Access | Decision | Comment | Outcome | Packet | Source |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| R72d2dc2d4e95 | Casey Owner | Emery Contractor | Payroll App Users | member | Remove | Contract ended | accepted | returned-01-Casey-Owner-da089e.xlsx | returned-01-Casey-Owner-da089e.xlsx, Review row 2 |
| Radff3f4f68d7 | Casey Owner | Emery Contractor | Server Operators | member | Remove | Contract ended | accepted | returned-01-Casey-Owner-da089e.xlsx | returned-01-Casey-Owner-da089e.xlsx, Review row 3 |
| R8b4b33a23130 | Jordan Director | Morgan Lead | Global Administrator | whole directory | Keep | Break-glass holder | accepted | returned-02-Jordan-Director-24304a.xlsx | returned-02-Jordan-Director-24304a.xlsx, Review row 2 |
| R7e70501da446 | Jordan Director | Morgan Lead | Ledger | Approver | Keep |  | accepted | returned-02-Jordan-Director-24304a.xlsx | returned-02-Jordan-Director-24304a.xlsx, Review row 3 |
| Rce931cefa50a | Morgan Lead | Avery Example | Finance Admins | member | Keep |  | accepted | returned-03-Morgan-Lead-e16dc6.xlsx | returned-03-Morgan-Lead-e16dc6.xlsx, Review row 2 |
| R070a8260809e | Morgan Lead | Blake Sample | Finance Admins | member | Remove | Left the company in September | accepted | returned-03-Morgan-Lead-e16dc6.xlsx | returned-03-Morgan-Lead-e16dc6.xlsx, Review row 3 |
| R3dd2ac32ff3d | Morgan Lead | Avery Example | Ledger | Approver | Keep |  | accepted | returned-03-Morgan-Lead-e16dc6.xlsx | returned-03-Morgan-Lead-e16dc6.xlsx, Review row 4 |
| R3c13774fa103 | Morgan Lead | Blake Sample | Ledger | Viewer | Remove | Left the company in September | accepted | returned-03-Morgan-Lead-e16dc6.xlsx | returned-03-Morgan-Lead-e16dc6.xlsx, Review row 5 |
| R954d0306e234 | Morgan Lead | Drew Analyst | Ledger | Viewer | Keep |  | accepted | returned-03-Morgan-Lead-e16dc6.xlsx | returned-03-Morgan-Lead-e16dc6.xlsx, Review row 6 |
| R60b815364cb6 | Morgan Lead | Drew Analyst | Ops Helpers | member |  |  | undecided | returned-03-Morgan-Lead-e16dc6.xlsx | returned-03-Morgan-Lead-e16dc6.xlsx, Review row 7 |
| R119eb45d6c64 | Morgan Lead | Avery Example | Payroll App Users | member | Keep |  | accepted | returned-03-Morgan-Lead-e16dc6.xlsx | returned-03-Morgan-Lead-e16dc6.xlsx, Review row 8 |
| R01318e99338d | Morgan Lead | Drew Analyst | Payroll App Users | member | Remove | Moved to another team | accepted | returned-03-Morgan-Lead-e16dc6.xlsx | returned-03-Morgan-Lead-e16dc6.xlsx, Review row 9 |
| R2a6be5aaf266 | Morgan Lead | Drew Analyst | Server Operators | member | Unsure | Ask the platform team | accepted | returned-03-Morgan-Lead-e16dc6.xlsx | returned-03-Morgan-Lead-e16dc6.xlsx, Review row 10 |
|  |  |  |  |  |  |  | unassigned |  | ledger.csv, row 2 |
|  |  |  |  |  |  |  | unassigned |  | ad.jsonl, line 16 |

## Not read (0 problems)

No problems were recorded while reading the inputs.

## What this report does not show

- Whether a decision was right.
- Who filled in a packet. The reviewer recorded is the one the campaign assigned; the author and time a workbook reports about itself are claims, shown as such.
- Any change to access: shaar never adds or removes access.

## Inputs

| File | Kind | Bytes | SHA-256 |
| --- | --- | --- | --- |
| ad.jsonl | shaar-export | 4029 | f248f8e56d8926cf7baf6b489a600d0266df95b241b21f9b27df521dacb68733 |
| entra.jsonl | shaar-export | 3485 | dfe2df70b884bcd6e3c5633ddf34601f073d2dd89cdec19691455798b547b0ff |
| ledger.csv | csv | 478 | ee38eb63cd3d672d6b9a45ec978f40dc71037e9834c44be1e6ad44040b4fb115 |

---

Generated by shaar 0.1.0 at 2026-11-21T09:00:00Z
