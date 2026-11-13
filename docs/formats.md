# Formats

shaar reads two kinds of access input: its own export, and CSV files. It detects the kind from the content of the file, never from its name or extension. A file whose first line is a JSON object with a `shaar_export` member is an export. Any other file is read as a CSV, which needs a column map or a preset. A CSV given with no map or preset is refused with exit code `3`.

## The shaar export

The export is JSON Lines: one JSON object per line, UTF-8, `\n` line ends. The PowerShell exporter, `shaar collect ad`, and `shaar collect entra` all write it. A file has a header, any number of records, and a trailer.

```text
{"shaar_export":1,"system":"ad","collector":{"name":"Export-ShaarAccess.ps1","version":"0.1.0"},"collected_at":"2026-11-01T22:00:00Z","scope":{"groups":["Finance Admins"]},"domain":"corp.example"}
{"principal":{"id":"S-1-5-21-1000-1000-1000-1102","name":"Avery Example","kind":"user","enabled":true,"email":"avery.example@corp.example","upn":"avery.example@corp.example","manager_id":"S-1-5-21-1000-1000-1000-1101","last_sign_in":"2026-10-30T08:15:00Z","extra":{}}}
{"resource":{"id":"S-1-5-21-1000-1000-1000-2001","name":"Finance Admins","kind":"group","owner_ids":[],"complete":true,"extra":{}}}
{"grant":{"principal_id":"S-1-5-21-1000-1000-1000-1102","resource_id":"S-1-5-21-1000-1000-1000-2001","entitlement":"member","via":[],"extra":{}}}
{"gap":{"what":"managers","reason":"example"}}
{"end":true,"records":4,"sha256":"..."}
```

### Header

The first line. It must be valid JSON with `"shaar_export": 1` and a `system` of `ad` or `entra`, or the file is refused with exit code `3`.

| Member | Meaning |
| --- | --- |
| `shaar_export` | The format version. Always `1`. |
| `system` | `ad` or `entra`. |
| `collector` | The tool that wrote the file: `name` and `version`. |
| `collected_at` | When the access was read, as ISO 8601 with `Z` or an offset. A header without a valid time is a problem, and the time is then unknown. |
| `scope` | Free JSON that says what was asked for. |
| `domain` or `tenant` | The domain (AD) or the tenant (Entra). For Entra it is the canonical tenant id, in lower case, from the `tid` claim of the access token that was used. An Entra export has no `domain`. |
| `cloud` | Entra only: the national cloud (`global`, `usgov`, `usgovdod`, or `china`). |

shaar keeps `scope`, `collector`, `domain`, `tenant`, and `cloud` as context. It does not interpret them.

### Records

Each record line holds exactly one member: `principal`, `resource`, `grant`, or `gap`. Text members are trimmed. A member of the wrong type is ignored and noted as a problem.

| Record | Members |
| --- | --- |
| `principal` | `id` (required, the raw source id), `name`, `kind` (`user`, `group`, `service`, `device`, `other`, `unknown`), `enabled` (true, false, or null), `email`, `upn`, `manager_id`, `last_sign_in`, `extra` (an object of text). |
| `resource` | `id` (required), `name`, `kind` (`group`, `role`, `application`, `other`), `owner_ids` (a list of principal ids), `complete` (true or false), `extra`. |
| `grant` | `principal_id`, `resource_id`, `entitlement` (all required), `via` (the names of the nested groups the access came through, empty when direct), `extra`. |
| `gap` | `what` and `reason`: something the collector could not read. It becomes a problem. |

A grant is one principal's entitlement on one resource. Group membership has the entitlement `member`. A directory role grant is one scope of one role: the entitlement is `whole directory`, or the word `scope`, a space, and the scope id (for example `scope /administrativeUnits/ID`), and never the role's name, which is only in the resource's `name`. Eligible (PIM) role grants are on the resource `ROLE-ID:eligible`, and only schedules in force at `collected_at` are written. Two paths to the same access are one grant: `via` is a shortest path, and `extra.paths` lists the routes, joined with a semicolon and a space. For Active Directory these are one shortest route for each direct holding group and each group that nests it, not every route.

A `complete` of `false` means the resource's membership was cut short: a paging failure, a failed range read, access denied, or throttling.

Ids are the raw source ids: a SID for Active Directory, an object id for Entra ID. shaar builds the [keys](#keys) from them.

### Trailer

The last line: `{"end":true,"records":N,"sha256":"HEX"}`.

- `records` counts the lines between the header and the trailer, blank and unreadable lines included.
- `sha256` is the SHA-256 of every byte before the trailer line, header included.

If the trailer is missing, is not last, or has a wrong count or hash, shaar records a problem and treats **no resource as complete**. Data after the trailer is also a problem and makes the file untrusted.

Limits: a line may be at most 1 MiB and a file at most 512 MiB. A file over the limit is refused. A line over the limit is skipped, and the loss means no resource is complete.

### What shaar does with a damaged export

Nothing is thrown away silently. Each of these is a problem in the report:

- A line that is not a JSON object, an unknown record type, or a line with more than one member. The affected lines are skipped, and no resource is complete.
- A grant with a missing field or a malformed `via`. The grant is skipped and only its resource is marked not complete.
- A duplicate principal or resource id. The first is kept, and a duplicate resource is not complete.
- A grant whose principal or resource has no record. The grant is kept with a stub record (`extra.stub` is `true`), because hiding access that exists would be worse than showing it without details. A stub resource is never complete.

### What complete means

A resource is **complete** when the whole of its membership was read. shaar counts a resource as complete only if:

- the export has a valid trailer (count and hash match), and
- no line was lost, and
- the resource record says `"complete": true`, and no grant of it was dropped, and
- every input that mentions the resource says so. If two inputs read the same resource and one read it only in part, it is not complete.

This matters for [verification](verification.md). A removal is verified only when the grant is absent from a later export that read the resource completely. Without that, absence proves nothing: the group may simply have been cut short. A resource that is not complete can still be reviewed in a campaign, and its present grants are still real.

## Keys

A key identifies a principal, resource, or grant across exports. Matching across inputs uses keys only, never display names, except when a CSV offers nothing else. Keys are lower-case strings of the form `system:kind:value`.

| Key | Used for |
| --- | --- |
| `ad:sid:S-1-5-21-...` | An Active Directory object with a domain SID. The SID is upper-cased, because SIDs ignore case. |
| `ad:sid:<SID>@<domain>` | A well-known SID that every domain has, such as `S-1-5-32-544`, tied to the export's `domain`. Without a domain the key ends in `@?`. |
| `ad:dn:cn=...` | An Active Directory object with no readable SID, matched by its case-folded distinguished name. A problem notes the weaker match. |
| `entra:<tenant>:id:<object id>` | An Entra ID object in one tenant, with both ids in lower case. Without a tenant id the tenant part is `?`. |
| `entra:<tenant>:role:<role definition id>` | An Entra ID directory role in one tenant, in lower case. |
| `csv:<system>:<id>` | An identifier from a CSV, trimmed and case-folded. The system is the one the map names. |

A grant key is `RESOURCE-KEY|PRINCIPAL-KEY|entitlement`, with the entitlement trimmed and case-folded. In each part, `%` is written `%25` and `|` is written `%7C`, so a `|` inside a name cannot make two grants share a key.

The same object id in two tenants, or the same well-known SID in two domains, is two different things. A key whose tenant or domain is unknown (`?`) could stand for any of them, so no resource that holds such a key is treated as complete, and a problem says so. Two exports of the same access give the same grant key. That is what lets `verify` find a grant again, even when the nesting path changed.

A system name is 1 to 40 characters: lower-case letters, digits, `.`, `_`, and `-`, starting with a letter or digit. `ad` and `entra` are reserved for the collectors, except that a CSV map can produce `ad` or `entra` keys through `id_style`.

## CSV files

A CSV needs a column map, given with `--map FILE.toml`, a built-in preset with `--preset NAME`, or both. shaar decodes the file by its byte order mark (UTF-8, UTF-16 little or big endian), else as strict UTF-8. A file that cannot be decoded, or holds NUL characters, is refused. Set `encoding` in the map for any other encoding. The delimiter is the one of `,`, `;`, tab, and `|` that splits the header line most, unless the map sets it.

A CSV is read as text. Cells that look like formulas are data, and shaar never evaluates them. A row with more cells than the header, or that lacks a needed id, is skipped with a problem, and its resource is then not complete. A file is limited to 256 MiB and 2,000,000 data rows.

### The column map

A map is a TOML file. All keys are optional unless a rule below says otherwise.

```toml
preset = "generic"            # a starting point; the map overrides it
system = "ledger"             # the system name used in keys
resource = "Ledger"           # one fixed resource for the whole file
resource_kind = "application" # group, role, application, or other
encoding = "utf-8"            # default: by byte order mark, else strict UTF-8
delimiter = ","               # default: sniffed; "tab" is accepted
owner_separator = ";"         # splits owner_ids
via_separator = ">"           # splits via
complete = true               # false: no resource in the file counts as complete
collected_at = "2026-11-01T00:00:00Z"   # when the CSV was exported, if known
domain = "corp.example"       # with id_style sid: the domain well-known SIDs belong to
tenant = "00000000-0000-4000-8000-000000000000"  # with id_style entra: the tenant id
optional = false              # true: mapped columns missing from the file are ignored
id_style = "csv"              # csv, sid, or entra

[columns]                     # field = "header in the file"
principal_id = "Email"
principal_name = "Full name"
enabled = "Active"
entitlement = "Role"

[values]
enabled_true = ["true", "yes", "1", "enabled"]
enabled_false = ["false", "no", "0", "disabled"]

[principal_kinds]             # header value (case-insensitive) = shaar kind
inetorgperson = "user"

[extra]                       # columns kept as extra text on a record
principal = ["Department"]
resource = []
grant = []
```

| Key | Meaning |
| --- | --- |
| `preset` | Start from a built-in map. The `--preset` option wins over this key. The file's other settings override those of the preset, and its tables merge key by key. |
| `system` | The system name for keys. Needed unless the file has a `system` column. |
| `resource` | One fixed resource for the file, matched by name. The `resource_id` and `resource_name` columns are then ignored. `--resource` sets this. |
| `resource_kind` | The kind used when there is no `resource_kind` column or its value is unknown. Default `other`. |
| `encoding`, `delimiter` | See above. A delimiter is one character or the word `tab`. |
| `owner_separator`, `via_separator` | Must not be empty. Defaults `;` and `>`. |
| `complete` | Default `true`. |
| `collected_at` | ISO 8601 with `Z` or an offset. Without it the CSV records no time, and its resources have no time in verification. A CSV never takes the time of another input. |
| `domain` | With `id_style = "sid"`, the AD domain that well-known SIDs in the file belong to. |
| `tenant` | With `id_style = "entra"`, the tenant id (a GUID, not a domain name). Without it, no resource in the file is treated as complete. |
| `optional` | When `false`, a mapped column that is missing from the file is an error. |
| `id_style` | How an id column becomes a key: `csv` (`csv:SYSTEM:ID`), `sid` (an AD SID key, `ad:sid:...`), or `entra` (`entra:TENANT:id:...`). With `sid` or `entra`, an id that is not a SID or not usable is skipped with a problem. Names are always matched as `csv`. |
| `[columns]` | Maps a field to the header text, matched without regard to case. The fields are listed below. A header that appears twice is an error. |
| `[values]` | `enabled_true` and `enabled_false`: the cell values that mean enabled and disabled, matched without regard to case. Defaults as shown. A cell that matches neither is read as not recorded, and counted in one problem. |
| `[principal_kinds]` | Maps a cell value to one of `user`, `group`, `service`, `device`, `other`, `unknown`. A value that is itself one of those kinds needs no entry. Other values become `unknown`, with one problem that counts them. |
| `[extra]` | Lists of headers whose values are kept as `extra` text on principals, resources, or grants. |

An unknown key in the map, or an unknown field in `[columns]`, is an error.

The fields for `[columns]` are `principal_id`, `principal_name`, `principal_kind`, `enabled`, `email`, `upn`, `manager_id`, `last_sign_in`, `resource_id`, `resource_name`, `resource_kind`, `owner_ids`, `entitlement`, `via`, and `system`.

Rules that apply to every CSV:

- The map must name a `principal_id` or a `principal_name` column that is in the file. Without an id column, principals are matched by name, which is weaker, and a problem says so.
- There must be a resource: a fixed `resource`, or a `resource_id` or `resource_name` column. With a `resource_name` column and no `resource_id`, the resource is matched by name, and a problem says so. A fixed resource gives no problem: you name it, and the same name keys it in every export.
- There must be a system: a `system` column or `system = ...` in the map.
- A blank entitlement means `member`.
- `manager_id` and each entry of `owner_ids` are written the way principal ids are, so they match principals.
- A row with a blank id, or with a name that makes an unusable system or key, is skipped with a problem.
- Rows are cited by line number, with the header as row 1.

### Presets

| Preset | For | Columns |
| --- | --- | --- |
| `generic` | A CSV that already uses shaar's headers. | `principal_id`, `principal_name`, `principal_kind`, `enabled`, `email`, `upn`, `manager_id`, `last_sign_in`, `resource_id`, `resource_name`, `resource_kind`, `owner_ids`, `entitlement`, `via`, `system`. Every column is optional, but the rules above still need an id or name, a resource, and a system. |
| `ad-users-groups` | A `Get-ADGroupMember`-style export joined with its group. | `SID` is the principal id, `Name` the name, `objectClass` the kind, `GroupSID` the resource id, `GroupName` the resource name. `SamAccountName` is kept as extra text. The system is `ad-users-groups`, the ids are SIDs (so keys are `ad:sid:...` and match an AD export), and the resource kind is `group`. The `objectClass` values `user`, `inetOrgPerson`, `group`, `computer`, `msDS-GroupManagedServiceAccount`, and `msDS-ManagedServiceAccount` map to `user`, `user`, `group`, `device`, `service`, and `service`. |
| `entra-members` | The Entra portal's "Download members" file for one group. | `id` is the principal id, `displayName` the name, `userPrincipalName` the UPN, `accountEnabled` the enabled flag. `userType` is kept as extra text. The system is `entra-members`, ids are Entra object ids (keys `entra:id:...`), and the resource kind is `group`. Give the group's name with `--resource`. |

All presets are optional-column presets: a column that is not in the file is ignored. A preset has no manager, email, or owner column, so the `manager` rule cannot place its rows. Add the columns with your own map, or use `--reviewers map`.

### Completeness of a CSV

shaar cannot know whether a CSV holds everything. It treats every resource a CSV mentions as complete, unless the map says `complete = false`, a row was skipped, or the file could not be read to its end. A truncated export or a filtered view therefore looks complete. If your CSV may be partial, set `complete = false`: reviews still work, but verification can then say only `unknown` for removals that rest on it.

### When a CSV has no id column

Without `principal_id`, shaar matches principals by case-folded name, and with no `resource_id` it matches the resource by name. Two people with one name become one principal. Prefer a column that holds a stable id or an email address.
