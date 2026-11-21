# 6. Campaign integrity by hash binding

- Status: accepted
- Date: 2026-11-13

## Context

A reviewer gets a workbook, edits it, and sends it back. By then it has passed through email, a file share, and a spreadsheet program. shaar has to decide what each returned row means, and a wrong decision means access is kept or removed by mistake.

The risks are mostly ordinary. A reviewer sorts the sheet and a row moves. Someone edits a name, deletes a row, or pastes over a cell. A file is returned for the wrong campaign or from an old review. A workbook says it was last modified by someone else. A hostile author is possible but less likely.

Options considered:

- **Trust the workbook.** Fast, but a changed row would silently change what a decision applies to.
- **Sign each packet or the campaign with a key.** It would defeat a determined forger. It needs key generation, storage, distribution, and rotation, and a reviewer who never touches a key cannot sign. The maintainer chose not to build it for this release.
- **Bind everything with hashes.** No keys. It detects accidental and casual changes, and it is cheap for operators to understand.
- **Rely on sheet protection.** It has no password, it is easy to remove, and a spreadsheet program does not enforce it on a program that reads the file.

## Decision

- **Row check.** Each row has a `row_id` and a `row_check`: a SHA-256 over the canonical JSON of the campaign id, the row id, the grant key, and every field the reviewer sees. The check is stored in a hidden column of the packet.
- **Packet digest.** A SHA-256 over a reviewer's row checks, in packet order. It is written to the About sheet. It identifies the packet and its reviewer.
- **Campaign digest.** A SHA-256 over the canonical JSON of `campaign.json` without the digest. Loading a campaign recomputes it, so an edited campaign is refused. The decision record has its own digest, and `verify` refuses a record that does not match the campaign as written.
- **Checks on return.** A returned packet must carry the campaign's id and a packet digest of one reviewer. Each row must belong to that reviewer, carry the right check, and show the same text as the campaign. A row that fails is `altered` and its decision is not used. Rows that are not the packet's own are strays. Copies that disagree are a `conflict`.
- **The reviewer of record** is the one the campaign assigned to the packet. The author and time a workbook reports about itself are recorded as claims, in a separate field, and never used.
- **Sheet protection** guards against accidents only, with no password.
- **No signing in 0.1.0.** The maintainer chose hash binding over signatures.

## Consequences

shaar detects accidental and casual changes to its files: a moved or edited row, a wrong or old packet, a hand-edited campaign, a damaged export.

It does not stop a determined attacker who can write the files. With no secret key, anyone can change a row, recompute the SHA-256 values, and write a consistent set. It also does not authenticate the person who filled in a packet: whoever has the file can answer. The [threat model](../threat-model.md) and the documentation say so plainly, and recommend keeping the campaign folder and returned files in a system that controls who can write and records changes.

Adding signatures later is possible without changing the model: they would sign the campaign digest and the packet digests. It would be a new record that replaces this one.
