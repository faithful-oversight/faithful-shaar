# Campaigns

A campaign is one review. `shaar campaign` reads the access inputs, places every entry with exactly one reviewer, and writes `campaign.json` and one packet workbook per reviewer. `campaign.json` is the authoritative record of what was sent. Every later step checks its inputs against it.

## What goes into a campaign

The population is the union of the grants in all inputs. Inputs can come from different systems. An entry is one grant: one principal's entitlement on one resource. Where inputs describe the same principal or resource with one key, shaar keeps one copy. If the copies differ in any recorded field, it keeps the first and records a problem that names both sources. Two grants with one key merge into one entry, and every path to it is kept. shaar never picks by file order silently.

Entries are sorted by reviewer name, resource, user, and key, so the same inputs always give the same packets.

## Choosing reviewers

The `--reviewers` option chooses one rule for the whole campaign.

### Manager

The reviewer is the manager of the person who holds the access. The manager must be a principal in the inputs, with a name. An entry is [unassigned](#unassigned-entries) when the principal has no manager recorded, the manager is not in the inputs, or the principal is their own manager.

Active Directory exports record managers. Entra exports record them for every user shaar read. A CSV needs a `manager_id` column.

### Owner

The reviewer is an owner of the resource, from `managedBy` in Active Directory, group owners in Entra, or an `owner_ids` column in a CSV. A resource can have several owners. Each entry still goes to one reviewer: the first owner, sorted by name and then key, who is not the person holding the access. The other owners appear in the packet's **Co-owners** column, which exists only under this rule. An entry is unassigned when the resource has no owner, its owners are not in the inputs, or the only owner holds the access.

### Reviewer map

The reviewer comes from a CSV that you write, named with `--reviewer-map`:

```text
resource,reviewer_id,reviewer_name,reviewer_email
Finance Admins,ayala.reviewer,Ayala Reviewer,ayala.reviewer@corp.example
```

- `reviewer_id` and `reviewer_name` are required. `reviewer_email` is optional.
- Each row needs a `resource` or a `principal` value. A file can have both columns.
- A `resource` matches a resource's key, id, or name. A `principal` matches a principal's key, id, name, UPN, or email. Matching ignores case.
- shaar tries the resource first, then the principal. A row that matches neither is unassigned.
- When two map rows match one entry and name different reviewers, the entry is unassigned and the reason names the rows.
- The file must be UTF-8. A byte order mark is accepted. A row without a reviewer id or without a resource and principal is an error.

The map's reviewer is identified by `reviewer_id`, with case ignored. Use one id for each person.

### One reviewer per person

A person often appears in several systems with a different key in each. For the manager and owner rules, a reviewer who has an email address is identified by that address, so one person gets one packet across Active Directory, Entra ID, and a CSV. A reviewer with no email is identified by their principal key. Map reviewers are identified by `reviewer_id`. Merging by email has three consequences:

- A shared mailbox used as the email of several people merges them into one reviewer and one packet.
- A person with two different email addresses gets two packets.
- People without an email are never merged across systems.

### No self-review

Nobody reviews their own access. shaar treats two principals as one person when they share a key or an email address, so this holds across systems:

- Manager rule: a manager who is the principal is not used.
- Owner rule: owners who hold the access are skipped, and the next owner reviews it.
- Map rule: a mapped reviewer whose `reviewer_id` or `reviewer_email` equals the principal's key, id, name, UPN, or email leaves the entry unassigned.

shaar has no fallback reviewer for these entries. They are unassigned, with the reason, and you can place them with a reviewer map that names someone else.

### Unassigned entries

An entry that no rule can place is **unassigned**. It is never dropped. The campaign report lists it with the reason and its source, `unassigned.csv` holds the same list, and `shaar campaign` exits with code `1`. The entry is not in any packet. The decision record lists it with the state `unassigned`, so `shaar decisions` also exits with `1` until you have dealt with them, for example by running a new campaign with a reviewer map. Verification does not check unassigned entries, and it does not report them as new.

## The packet workbook

Each reviewer gets one `.xlsx` file named `packet-NN-NAME-HASH.xlsx`, where `NN` is a two-digit index, `NAME` is the reviewer's name reduced to ASCII letters, digits, and hyphens (at most 40 characters), and `HASH` is six hex digits of the reviewer's key, so two people with one name get different files. A packet holds only that reviewer's rows.

### The Review sheet

| Column | Content |
| --- | --- |
| Decision | Empty. The reviewer chooses `Keep`, `Remove`, or `Unsure` from a list. |
| Comment | Empty. Free text. |
| User | The principal's name. A service account, device, or group shows its kind in brackets. |
| Account | The UPN, else the email, else the id. |
| Status | `Enabled`, `Disabled`, or `Unknown`. |
| Last sign-in | The text the source gave. Empty when not recorded. |
| Access to | The resource's name. |
| Type | `group`, `role`, `application`, or `other`. |
| Access | The entitlement: `member`, a role name, or a CSV role. |
| Granted through | `Direct`, or the chain of nested groups. |
| Co-owners | Other owners. Only under the owner rule. |
| Row ID | Hidden. `R` and 12 hex digits that identify the entry in this campaign. |
| Row check | Hidden. The SHA-256 [row check](#row-checks-and-digests). |

The header row is frozen and has a filter. Every cell holds plain text: shaar writes no formulas. Characters that XML 1.0 forbids become U+FFFD, and a cell longer than Excel's limit of 32,767 characters is cut and ends with `[truncated]`. Those cells no longer match the campaign byte for byte, so shaar compares the cell text it would have written, not the source text.

### The About sheet

The About sheet holds the campaign name and id, the reviewer's name and email, the due date, the **packet digest**, the row count, and short instructions. `shaar decisions` reads the campaign id and the packet digest from it, to find out whose packet the file is.

### Protection

Both sheets are protected without a password. Only the Decision and Comment cells are unlocked, and Decision accepts only `Keep`, `Remove`, or `Unsure`.

Protection is an accident guard, not a security control. Anyone can remove it in seconds, and shaar does not rely on it. The [row checks](#row-checks-and-digests) are what detect a changed row.

### Reproducible bytes

A packet's zip entries are written in a fixed order with the campaign's creation time as their date, and the document properties use the same time and the creator `shaar`. The same campaign gives the same bytes. See [decision record 7](adr/0007-packet-workbooks.md).

## Row checks and digests

`campaign.json` holds three kinds of digest, all SHA-256:

- **Row check.** Over the canonical JSON of the campaign id, the row id, the grant key, and every field the reviewer sees. Canonical JSON has sorted keys, no extra spaces, and non-ASCII characters kept as they are.
- **Packet digest.** Over the row checks of one reviewer's rows, in packet order, joined with line feeds.
- **Campaign digest.** Over the canonical JSON of the whole campaign without the digest member.

`shaar decisions` and `shaar verify` recompute the campaign digest when they load `campaign.json`. A campaign that was edited is refused with exit code `3`. The decision record has a digest of its own, and `verify` refuses a record that was edited or that belongs to another campaign.

The campaign id is `C` and 16 hex digits over the name, the creation time, and the digests of the inputs. A row id is `R` and 12 hex digits over the campaign id and the grant key.

These digests detect accidents and casual edits. They are plain, unkeyed SHA-256 values, not signatures. Anyone who has a campaign's files can recompute them. So can anyone who has one packet and knows another reviewer's rows: they can build a packet that decides those rows, and shaar will accept it and attribute it to the assigned reviewer. Control who receives packets and who runs `shaar decisions`, and keep the returned files. See the [threat model](threat-model.md) and [decision record 6](adr/0006-campaign-integrity.md).

## What makes a decision count

`shaar decisions` reads each returned file against the campaign. First it decides whether the file as a whole is usable:

1. It must be an unencrypted `.xlsx` workbook that breaks no [limit](threat-model.md#hostile-workbooks), with a Review sheet, an About sheet, and a `Row ID` header. Otherwise it is **unreadable**.
2. The campaign id on the About sheet must be the campaign's. Otherwise it is **rejected**.
3. The packet digest on the About sheet must match one reviewer's packet in the campaign. That reviewer is the packet's owner. Otherwise the file is **rejected**.

The file name does not matter. A rejected or unreadable file is listed as a problem, and its rows stay undecided.

Then each row of the workbook gets one of these outcomes:

| Outcome | Meaning |
| --- | --- |
| `accepted` | The row is one of this reviewer's rows, it was not changed, and the decision is `Keep`, `Remove`, or `Unsure`. |
| `undecided` | The Decision cell is empty, or the row is missing from the returned packet, or the packet was not returned or could not be read. |
| `invalid` | The Decision cell holds something else than `Keep`, `Remove`, or `Unsure`, or the decision lacks a comment that `--require-comment` demands, or any cell of the row held a formula. |
| `altered` | The row changed after it was sent: the hidden Row check differs, or any visible cell other than Decision and Comment differs from the campaign. The decision is not used, and the reason lists what changed. |
| `conflict` | Copies of the row disagree: two copies with different decisions, or a valid copy and an invalid one. The decision is not used. |
| `unassigned` | The campaign had no reviewer for the entry. |

Decision text is trimmed and compared with Unicode case folding, so `remove` and ` KEEP ` count as `Remove` and `Keep`. Identical copies of a row, in one packet or across packets, count once. Row order does not matter, columns can be moved because shaar finds them by header, and a workbook saved by Excel, LibreOffice, or Google Sheets is read the same as one saved by shaar.

### Strays

A row that is not one of the packet's own rows is a **stray**: its Row ID is not in the campaign, or it belongs to another reviewer's packet. Strays are listed under Needs attention, never used, and make the record incomplete. An empty row is ignored.

### Unsure

`Unsure` is an accepted answer. It is recorded as what the reviewer said, but it is not a decision. The entry is listed under Needs attention with "follow up for Keep or Remove", and the record is not complete while any Unsure remains. Unsure never produces a removal.

### The reviewer of record

The reviewer shown for a decision is the one the campaign assigned to that packet, identified through the packet digest. The author and modified time that a workbook reports about itself (`lastModifiedBy`, `modified`) are claims that anyone can set. shaar records them next to the file's own SHA-256 as "reported by the file", and never uses them to identify anyone.

### Comments

The About sheet tells reviewers to add a comment for every Remove, but nothing enforces it unless you set `--require-comment Remove`. Use `--require-comment Remove --require-comment Unsure` to demand it for both.

### What shaar writes

`decisions.json` records, for every campaign row: the state, the decision, the comment, the reviewer, the packet file name, and a citation such as `returned-03-Morgan-Lead-e16dc6.xlsx, Review row 7`. It also lists every returned file with its SHA-256 and status, and every stray. `removals.csv` lists the accepted Remove decisions for an administrator to carry out. shaar never removes access. See [Reports and output](output.md#decisions).
