# 4. A JSON Lines export with a header, records, and a trailer

- Status: accepted
- Date: 2026-11-13

## Context

shaar needs to know who holds which access, in a form that two collectors (a PowerShell script and a Graph client) can write and one reader can check. Active Directory and Entra ID describe the same ideas differently: SIDs and object ids, `member` ranges and `transitiveMembers`, `managedBy` and owners.

The file has to meet these needs:

- It must stream. The exporter runs over WinRM and sends lines, and a large directory must not need to fit in memory.
- It must show whether it is whole. An export cut off after three of forty groups must not look complete. This matters most for verification, which treats a missing grant as a removal only when the resource was read in full.
- It must say, per resource, whether its membership was read completely, because a failed page or a denied read hides members.
- It must record what could not be read, so a failure is a visible gap and not silence.
- It must be writable as pure ASCII from Windows PowerShell 5.1.

Options considered:

- **A CSV.** It cannot carry nesting, the completeness of a resource, or gaps, and it has no trailer.
- **One JSON document.** The reader must hold it whole, and a document cut short is not valid JSON, so everything in it is lost.
- **The format of each source.** Two parsers and two models, with no common way to say "not read".
- **JSON Lines with a header, records, and a trailer.** Each line stands alone, so a cut file still yields every complete line.

## Decision

- The export is JSON Lines in UTF-8 with `\n` line ends. The first line is a header with `shaar_export` set to 1, the system (`ad` or `entra`), the collector, `collected_at`, the scope, and the domain or tenant. The format is detected from that first line, never from the file name.
- Records are `principal`, `resource`, `grant`, and `gap` lines, each with exactly one member. A `resource` carries `complete`. A `grant` carries `via`, the chain of nested groups. Ids are the raw source ids. The reader builds keys from them.
- The trailer is `{"end":true,"records":N,"sha256":"..."}`. `records` counts the lines between the header and the trailer. `sha256` covers every byte before the trailer. A missing trailer, a wrong count or hash, or data after it means no resource is complete.
- A gap, a damaged line, or a dropped grant is a problem. A line that is lost without knowing its resource removes completeness from every resource. A dropped grant removes it from its own resource only.
- A grant whose principal or resource record is missing is kept with a stub record. Hiding access that exists would be worse than showing it without details.
- Limits: a line at most 1 MiB and a file at most 512 MiB.
- Keys follow `system:kind:value`, with the SID, object id, or CSV id normalized so two exports of one object agree. CSV files are mapped onto the same model.

## Consequences

One reader serves both collectors and any other tool that writes the format. A cut or damaged file is detected, and every line before the damage is still used.

The hash detects accidents and careless edits. Anyone who edits an export can compute the hash again, so it does not show who wrote the file or that its content is true. The [threat model](../threat-model.md) says so.

The PowerShell script and the Python reader are two implementations of one format. Tests check the script's output with the real reader. A change to the shape needs a new format version.

An export holds names, accounts, and managers. It is as sensitive as the directory data it was made from.
