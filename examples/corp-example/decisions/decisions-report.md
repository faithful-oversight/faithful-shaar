# Access review decisions: Q4 2026 access review

12 of 13 entries have an accepted decision; 5 removals to make. 4 items need attention.

| Item | Value |
| --- | --- |
| Campaign | Q4 2026 access review |
| Campaign ID | C1966ccf07210e91a |
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
| R2a8397b44f53 | Emery Contractor | emery.contractor@⁠corp.example | Payroll App Users | member | Casey Owner | Contract ended |
| Rae38d4d67f84 | Emery Contractor | emery.contractor@⁠corp.example | Server Operators | member | Casey Owner | Contract ended |
| R42c734801af7 | Blake Sample | blake.sample@⁠corp.example | Finance Admins | member | Morgan Lead | Left the company in September |
| R824c58e8c34c | Blake Sample | blake.sample@⁠corp.example | Ledger | Viewer | Morgan Lead | Left the company in September |
| R240ac286f67a | Drew Analyst | drew.analyst@⁠corp.example | Payroll App Users | member | Morgan Lead | Moved to another team |

## Needs attention (4 rows)

Entries without an accepted decision, and rows that did not belong in the packet they came in.

| Row ID | Reviewer | User | Access to | Outcome | Why it needs attention | Source |
| --- | --- | --- | --- | --- | --- | --- |
| Reba9a6a36510 | Morgan Lead | Drew Analyst | Ops Helpers | undecided | no decision | returned-03-Morgan-Lead-e16dc6.xlsx, Review row 7 |
| R9a395c188238 | Morgan Lead | Drew Analyst | Server Operators | unsure | the reviewer was unsure; follow up for Keep or Remove | returned-03-Morgan-Lead-e16dc6.xlsx, Review row 10 |
|  |  |  |  | unassigned | the input names no manager for this principal | ledger.csv, row 2 |
|  |  |  |  | unassigned | the input names no manager for this principal | ad.jsonl, line 16 |

## Every entry (15 rows)

The outcome for every entry of the campaign.

| Row ID | Reviewer | User | Access to | Access | Decision | Comment | Outcome | Packet | Source |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| R2a8397b44f53 | Casey Owner | Emery Contractor | Payroll App Users | member | Remove | Contract ended | accepted | returned-01-Casey-Owner-da089e.xlsx | returned-01-Casey-Owner-da089e.xlsx, Review row 2 |
| Rae38d4d67f84 | Casey Owner | Emery Contractor | Server Operators | member | Remove | Contract ended | accepted | returned-01-Casey-Owner-da089e.xlsx | returned-01-Casey-Owner-da089e.xlsx, Review row 3 |
| R8745b3514235 | Jordan Director | Morgan Lead | Global Administrator | whole directory | Keep | Break-glass holder | accepted | returned-02-Jordan-Director-24304a.xlsx | returned-02-Jordan-Director-24304a.xlsx, Review row 2 |
| Ra3203c9fb2b2 | Jordan Director | Morgan Lead | Ledger | Approver | Keep |  | accepted | returned-02-Jordan-Director-24304a.xlsx | returned-02-Jordan-Director-24304a.xlsx, Review row 3 |
| R0a59068317b1 | Morgan Lead | Avery Example | Finance Admins | member | Keep |  | accepted | returned-03-Morgan-Lead-e16dc6.xlsx | returned-03-Morgan-Lead-e16dc6.xlsx, Review row 2 |
| R42c734801af7 | Morgan Lead | Blake Sample | Finance Admins | member | Remove | Left the company in September | accepted | returned-03-Morgan-Lead-e16dc6.xlsx | returned-03-Morgan-Lead-e16dc6.xlsx, Review row 3 |
| R89aecc206b71 | Morgan Lead | Avery Example | Ledger | Approver | Keep |  | accepted | returned-03-Morgan-Lead-e16dc6.xlsx | returned-03-Morgan-Lead-e16dc6.xlsx, Review row 4 |
| R824c58e8c34c | Morgan Lead | Blake Sample | Ledger | Viewer | Remove | Left the company in September | accepted | returned-03-Morgan-Lead-e16dc6.xlsx | returned-03-Morgan-Lead-e16dc6.xlsx, Review row 5 |
| R94a7683b4b39 | Morgan Lead | Drew Analyst | Ledger | Viewer | Keep |  | accepted | returned-03-Morgan-Lead-e16dc6.xlsx | returned-03-Morgan-Lead-e16dc6.xlsx, Review row 6 |
| Reba9a6a36510 | Morgan Lead | Drew Analyst | Ops Helpers | member |  |  | undecided | returned-03-Morgan-Lead-e16dc6.xlsx | returned-03-Morgan-Lead-e16dc6.xlsx, Review row 7 |
| Rdafff73f0394 | Morgan Lead | Avery Example | Payroll App Users | member | Keep |  | accepted | returned-03-Morgan-Lead-e16dc6.xlsx | returned-03-Morgan-Lead-e16dc6.xlsx, Review row 8 |
| R240ac286f67a | Morgan Lead | Drew Analyst | Payroll App Users | member | Remove | Moved to another team | accepted | returned-03-Morgan-Lead-e16dc6.xlsx | returned-03-Morgan-Lead-e16dc6.xlsx, Review row 9 |
| R9a395c188238 | Morgan Lead | Drew Analyst | Server Operators | member | Unsure | Ask the platform team | accepted | returned-03-Morgan-Lead-e16dc6.xlsx | returned-03-Morgan-Lead-e16dc6.xlsx, Review row 10 |
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
