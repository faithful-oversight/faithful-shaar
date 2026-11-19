# Verification

`shaar verify` answers one question for every accepted Remove decision: did the removal happen? It reads access exported after the due date and compares it with the decision record. It changes nothing.

```shell
shaar verify campaign decisions after/ad.jsonl after/entra.jsonl -o verification
```

shaar refuses a decision record that does not match the campaign as written (the campaign id and digest must agree), with exit code `3`.

## The decision record must be complete

Removals are only part of a review. `shaar verify` also looks at the decision record it was given. When any entry has no accepted decision (undecided, invalid, altered, in conflict, or unassigned), any accepted decision is Unsure, a row came in the wrong packet, a returned file was unusable, or the campaign recorded problems reading its inputs or did not read a resource in full, the headline says that the decision record is not complete, each reason is listed under Not read, `decision_record_complete` in the JSON report is `false`, and the exit code is `1`. That holds even when every decided removal was made, and even when nothing was decided: `0 of 0 removals verified` is not a clean result for a review in which nobody answered.

## The four results

Only accepted Remove decisions are checked. Each gets one result and a reason.

| Result | Rule |
| --- | --- |
| `removed` | The grant is absent from the later input, **and** the later input read the grant's resource completely, **and** the read has a time, **and** that time is not before the campaign began, **and** nobody else in the later input holds the same access under another key. See [what removed needs](#what-removed-needs). The reason adds a note when the principal's key is missing from the later input, or the principal is disabled. |
| `pending` | The grant is still present, and the later input was read before the due date. |
| `failed` | The grant is still present on or after the due date. Also when the campaign has no due date, or when the later input records no time and you gave no `--as-of`. |
| `unknown` | The later input cannot show it: it is of another system, it does not include the resource, it did not read the resource completely, it is a CSV from which no entitlement column was read, whether the map names none, a preset supplies none, or the file lacks the one it names (so every grant in it reads as `member`) and the removal is of another entitlement, or one of the other conditions for `removed` fails. The reason says which. |

Matching uses grant keys only. A grant reached through a different nesting path is still the same grant, so a changed `via` is not a failure. Names never match.

The order of the checks matters. A grant that is still present is `pending` or `failed` whatever else is true, because presence needs no completeness. Only an absent grant needs the resource to be complete, and it is the only way to get `removed`.

### What removed needs

An absent grant is `removed` only when all of these hold. Otherwise it is `unknown`, with the reason.

1. **A complete read.** The later input read the resource's whole membership. See [what complete means](formats.md#what-complete-means).
2. **A time.** The later inputs that hold the resource have a time: the `collected_at` of their exports, or the `--as-of` you give. Without one the reason is `the later export does not say when it was read; give --as-of`.
3. **Not before the campaign.** The time is not before the campaign's `created_at`. Otherwise the reason is `the later export was read before the campaign began`, because an older export cannot show a removal that followed the review.
4. **The same account is not still there.** Nobody else in the later input holds the same entitlement on the same resource with a UPN, email, or id equal to the row's Account. A person can change key between exports, for example when a CSV's id column changes. Their access is then absent under the old key but present under the new one. The reason is "the same account still holds this access under another key" and names the holder.

### Complete resources only

A group that was cut short, for example by a paging failure or a denied read, looks emptier than it is. If shaar called every missing grant removed, a partial export would "verify" removals that never happened. A missing grant therefore counts as removed only when the later input says it read the whole resource. See [what complete means](formats.md#what-complete-means). A CSV is complete unless its map says otherwise, so a filtered CSV can make an absence look like a removal. shaar cannot detect that.

When the later input is of another system than the access, such as an Entra export for an AD group, the result is `unknown`, never `removed`.

### Due date

The due date comes from `--due` on `shaar campaign`. The date the later access was read is the earliest `collected_at` among the later inputs that hold the resource, or the time you give with `--as-of`, which replaces it. shaar compares the UTC calendar date of the read time with the due date. A read taken before the due date gives `pending`, and one on or after it gives `failed`. A grant that is still present with no known time is `failed`, with the reason that the export does not say when it was taken. An absent grant with no known time is `unknown`.

### Earliest collection time across inputs

When you give several later inputs, shaar uses the **earliest** `collected_at`, not the latest. A verification can claim only evidence as recent as the oldest input it rests on. If one export is from before the due date and another from after, a still-present grant is `pending`, because shaar cannot rule out that the older export is the one that shows it.

Each resource takes the time of the inputs that hold it. An export or CSV without a valid time leaves its resources without a time, so an absent grant there is `unknown`; it never borrows the time of another input. The read as a whole has no time when any input lacks one. Give `--as-of` when no input records a time, or give each CSV's map its `collected_at`.

An export from another Entra tenant or AD domain holds other keys, so the campaign's resources are not in it and their grants are `unknown`.

## Active and eligible role assignments

`shaar collect entra --roles` reads active directory role assignments, and `--pim` reads eligible (Privileged Identity Management) assignments. An active and an eligible assignment of one role are two separate resources, `<role id>` and `<role id>:eligible`. Each is complete only when its own listing was read in full.

This keeps one kind from vouching for the other. A later export made with `--roles` alone does not contain the eligible resources at all, so an eligible assignment that was marked for removal is `unknown`, not `removed`. To verify a role removal, collect with the same `--roles` and `--pim` choices both times.

## Information that is not a result

Two lists in the report are information only. They never change the exit code.

- **Kept, but gone anyway.** Rows a reviewer marked Keep whose grant is absent from a later input that read the resource completely. Access may have been removed for another reason.
- **New since the review.** Grants in the later inputs, on resources that the campaign covered, that the campaign did not include. Examples are someone added after the export, or access that was not in the first export. Entries that were unassigned in the campaign are not reported here.

## Exit code

`shaar verify` exits with `0` when every accepted Remove is `removed` or there are none, and with `1` when any is `pending`, `failed`, or `unknown`.

## What verification cannot prove

- It compares two exports. It does not see what happened between them, or after the later one.
- `removed` means the grant is not in the later input. It does not prove who removed it, or that a person did not lose access to something else.
- Access that the later input never recorded is invisible. Local accounts, other systems, and nested groups that were not exported are examples.
- A CSV's completeness is a claim by whoever wrote the map.
- The later file is as trustworthy as the system and the person that produced it. See the [threat model](threat-model.md).
