# Access review decisions: Q4 2026 access review

12 of 13 entries have an accepted decision; 5 removals to make. 4 items need attention.

| Item | Value |
| --- | --- |
| Campaign | Q4 2026 access review |
| Campaign ID | C61b04c11174dbf64 |
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
| R7e2286fe57e8 | Emery Contractor | emery.contractor@⁠corp.example | Payroll App Users | member | Casey Owner | Contract ended |
| R11cecb2e3123 | Emery Contractor | emery.contractor@⁠corp.example | Server Operators | member | Casey Owner | Contract ended |
| Rcf3e823507b7 | Blake Sample | blake.sample@⁠corp.example | Finance Admins | member | Morgan Lead | Left the company in September |
| R7c9006452035 | Blake Sample | blake.sample@⁠corp.example | Ledger | Viewer | Morgan Lead | Left the company in September |
| Re38173dfa1b5 | Drew Analyst | drew.analyst@⁠corp.example | Payroll App Users | member | Morgan Lead | Moved to another team |

## Needs attention (4 rows)

Entries without an accepted decision, and rows that did not belong in the packet they came in.

| Row ID | Reviewer | User | Access to | Outcome | Why it needs attention | Source |
| --- | --- | --- | --- | --- | --- | --- |
| Raa06884d69bd | Morgan Lead | Drew Analyst | Ops Helpers | undecided | no decision | returned-03-Morgan-Lead-e16dc6.xlsx, Review row 7 |
| R47487ba919fb | Morgan Lead | Drew Analyst | Server Operators | unsure | the reviewer was unsure; follow up for Keep or Remove | returned-03-Morgan-Lead-e16dc6.xlsx, Review row 10 |
|  |  |  |  | unassigned | the input names no manager for this principal | ledger.csv, row 2 |
|  |  |  |  | unassigned | the input names no manager for this principal | ad.jsonl, line 16 |

## Every entry (15 rows)

The outcome for every entry of the campaign.

| Row ID | Reviewer | User | Access to | Access | Decision | Comment | Outcome | Packet | Source |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| R7e2286fe57e8 | Casey Owner | Emery Contractor | Payroll App Users | member | Remove | Contract ended | accepted | returned-01-Casey-Owner-da089e.xlsx | returned-01-Casey-Owner-da089e.xlsx, Review row 2 |
| R11cecb2e3123 | Casey Owner | Emery Contractor | Server Operators | member | Remove | Contract ended | accepted | returned-01-Casey-Owner-da089e.xlsx | returned-01-Casey-Owner-da089e.xlsx, Review row 3 |
| Rd57718e25b3c | Jordan Director | Morgan Lead | Global Administrator | Global Administrator | Keep | Break-glass holder | accepted | returned-02-Jordan-Director-24304a.xlsx | returned-02-Jordan-Director-24304a.xlsx, Review row 2 |
| R5b26d19ff14c | Jordan Director | Morgan Lead | Ledger | Approver | Keep |  | accepted | returned-02-Jordan-Director-24304a.xlsx | returned-02-Jordan-Director-24304a.xlsx, Review row 3 |
| R2e1377f5a86c | Morgan Lead | Avery Example | Finance Admins | member | Keep |  | accepted | returned-03-Morgan-Lead-e16dc6.xlsx | returned-03-Morgan-Lead-e16dc6.xlsx, Review row 2 |
| Rcf3e823507b7 | Morgan Lead | Blake Sample | Finance Admins | member | Remove | Left the company in September | accepted | returned-03-Morgan-Lead-e16dc6.xlsx | returned-03-Morgan-Lead-e16dc6.xlsx, Review row 3 |
| Rba3add9d40c3 | Morgan Lead | Avery Example | Ledger | Approver | Keep |  | accepted | returned-03-Morgan-Lead-e16dc6.xlsx | returned-03-Morgan-Lead-e16dc6.xlsx, Review row 4 |
| R7c9006452035 | Morgan Lead | Blake Sample | Ledger | Viewer | Remove | Left the company in September | accepted | returned-03-Morgan-Lead-e16dc6.xlsx | returned-03-Morgan-Lead-e16dc6.xlsx, Review row 5 |
| R3c96926303ef | Morgan Lead | Drew Analyst | Ledger | Viewer | Keep |  | accepted | returned-03-Morgan-Lead-e16dc6.xlsx | returned-03-Morgan-Lead-e16dc6.xlsx, Review row 6 |
| Raa06884d69bd | Morgan Lead | Drew Analyst | Ops Helpers | member |  |  | undecided | returned-03-Morgan-Lead-e16dc6.xlsx | returned-03-Morgan-Lead-e16dc6.xlsx, Review row 7 |
| R69e878188490 | Morgan Lead | Avery Example | Payroll App Users | member | Keep |  | accepted | returned-03-Morgan-Lead-e16dc6.xlsx | returned-03-Morgan-Lead-e16dc6.xlsx, Review row 8 |
| Re38173dfa1b5 | Morgan Lead | Drew Analyst | Payroll App Users | member | Remove | Moved to another team | accepted | returned-03-Morgan-Lead-e16dc6.xlsx | returned-03-Morgan-Lead-e16dc6.xlsx, Review row 9 |
| R47487ba919fb | Morgan Lead | Drew Analyst | Server Operators | member | Unsure | Ask the platform team | accepted | returned-03-Morgan-Lead-e16dc6.xlsx | returned-03-Morgan-Lead-e16dc6.xlsx, Review row 10 |
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
| entra.jsonl | shaar-export | 3490 | 750dd952e2622fc921a3c8f33b754e699ab480557923fd46e0b1e7a0be0707b3 |
| ledger.csv | csv | 478 | ee38eb63cd3d672d6b9a45ec978f40dc71037e9834c44be1e6ad44040b4fb115 |

---

Generated by shaar 0.1.0 at 2026-11-21T09:00:00Z
