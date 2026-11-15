# Access review decisions: Q4 2026 access review

12 of 13 entries have an accepted decision; 5 removals to make. 4 items need attention.

| Item | Value |
| --- | --- |
| Campaign | Q4 2026 access review |
| Campaign ID | C61cedf912e16213a |
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
| Problems reading the inputs | 0 |

## Removals to make (5 rows)

Accepted Remove decisions. shaar does not remove access: an administrator makes these changes, and shaar verify checks them later.

| Row ID | User | Account | Access to | Access | Reviewer | Comment |
| --- | --- | --- | --- | --- | --- | --- |
| R443b3280ba40 | Emery Contractor | emery.contractor@⁠corp.example | Payroll App Users | member | Casey Owner | Contract ended |
| R680526a4e83a | Emery Contractor | emery.contractor@⁠corp.example | Server Operators | member | Casey Owner | Contract ended |
| R07aa66e0c960 | Blake Sample | blake.sample@⁠corp.example | Finance Admins | member | Morgan Lead | Left the company in September |
| Rd60d89a91c37 | Blake Sample | blake.sample@⁠corp.example | Ledger | Viewer | Morgan Lead | Left the company in September |
| R20a314c4d7b5 | Drew Analyst | drew.analyst@⁠corp.example | Payroll App Users | member | Morgan Lead | Moved to another team |

## Needs attention (4 rows)

Entries without an accepted decision, and rows that did not belong in the packet they came in.

| Row ID | Reviewer | User | Access to | Outcome | Why it needs attention | Source |
| --- | --- | --- | --- | --- | --- | --- |
| Rc739c1246ece | Morgan Lead | Drew Analyst | Ops Helpers | undecided | no decision | returned-03-Morgan-Lead-e16dc6.xlsx, Review row 7 |
| R452dd559b7f8 | Morgan Lead | Drew Analyst | Server Operators | unsure | the reviewer was unsure; follow up for Keep or Remove | returned-03-Morgan-Lead-e16dc6.xlsx, Review row 10 |
|  |  |  |  | unassigned | the input names no manager for this principal | ledger.csv, row 2 |
|  |  |  |  | unassigned | the input names no manager for this principal | ad.jsonl, line 16 |

## Every entry (15 rows)

The outcome for every entry of the campaign.

| Row ID | Reviewer | User | Access to | Access | Decision | Comment | Outcome | Packet | Source |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| R443b3280ba40 | Casey Owner | Emery Contractor | Payroll App Users | member | Remove | Contract ended | accepted | returned-01-Casey-Owner-da089e.xlsx | returned-01-Casey-Owner-da089e.xlsx, Review row 2 |
| R680526a4e83a | Casey Owner | Emery Contractor | Server Operators | member | Remove | Contract ended | accepted | returned-01-Casey-Owner-da089e.xlsx | returned-01-Casey-Owner-da089e.xlsx, Review row 3 |
| R49a2752ed2a4 | Jordan Director | Morgan Lead | Global Administrator | whole directory | Keep | Break-glass holder | accepted | returned-02-Jordan-Director-24304a.xlsx | returned-02-Jordan-Director-24304a.xlsx, Review row 2 |
| R9ef3b18c9723 | Jordan Director | Morgan Lead | Ledger | Approver | Keep |  | accepted | returned-02-Jordan-Director-24304a.xlsx | returned-02-Jordan-Director-24304a.xlsx, Review row 3 |
| R9a7456ddfe9c | Morgan Lead | Avery Example | Finance Admins | member | Keep |  | accepted | returned-03-Morgan-Lead-e16dc6.xlsx | returned-03-Morgan-Lead-e16dc6.xlsx, Review row 2 |
| R07aa66e0c960 | Morgan Lead | Blake Sample | Finance Admins | member | Remove | Left the company in September | accepted | returned-03-Morgan-Lead-e16dc6.xlsx | returned-03-Morgan-Lead-e16dc6.xlsx, Review row 3 |
| R87624d83ac88 | Morgan Lead | Avery Example | Ledger | Approver | Keep |  | accepted | returned-03-Morgan-Lead-e16dc6.xlsx | returned-03-Morgan-Lead-e16dc6.xlsx, Review row 4 |
| Rd60d89a91c37 | Morgan Lead | Blake Sample | Ledger | Viewer | Remove | Left the company in September | accepted | returned-03-Morgan-Lead-e16dc6.xlsx | returned-03-Morgan-Lead-e16dc6.xlsx, Review row 5 |
| R776d2e37f927 | Morgan Lead | Drew Analyst | Ledger | Viewer | Keep |  | accepted | returned-03-Morgan-Lead-e16dc6.xlsx | returned-03-Morgan-Lead-e16dc6.xlsx, Review row 6 |
| Rc739c1246ece | Morgan Lead | Drew Analyst | Ops Helpers | member |  |  | undecided | returned-03-Morgan-Lead-e16dc6.xlsx | returned-03-Morgan-Lead-e16dc6.xlsx, Review row 7 |
| Rb6abd756a67e | Morgan Lead | Avery Example | Payroll App Users | member | Keep |  | accepted | returned-03-Morgan-Lead-e16dc6.xlsx | returned-03-Morgan-Lead-e16dc6.xlsx, Review row 8 |
| R20a314c4d7b5 | Morgan Lead | Drew Analyst | Payroll App Users | member | Remove | Moved to another team | accepted | returned-03-Morgan-Lead-e16dc6.xlsx | returned-03-Morgan-Lead-e16dc6.xlsx, Review row 9 |
| R452dd559b7f8 | Morgan Lead | Drew Analyst | Server Operators | member | Unsure | Ask the platform team | accepted | returned-03-Morgan-Lead-e16dc6.xlsx | returned-03-Morgan-Lead-e16dc6.xlsx, Review row 10 |
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
| ad.jsonl | shaar-export | 4029 | d8eb004a3f5ca775810261e976401b7fef1acbdba35707cb476afff9683d5e1f |
| entra.jsonl | shaar-export | 3485 | 4eefc1bf5d6a328849907ac57b4ac79c56845e8ed9668084d45a0d01bb47559c |
| ledger.csv | csv | 478 | ee38eb63cd3d672d6b9a45ec978f40dc71037e9834c44be1e6ad44040b4fb115 |

---

Generated by shaar 0.1.1 at 2026-11-21T09:00:00Z
