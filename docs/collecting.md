# Collecting

shaar reads CSV files that you make yourself. See [Formats](formats.md). It also has two collectors that write its own [export](formats.md#the-shaar-export), which records nesting, owners, managers, and whether each group was read in full:

| Collector | Reads | Runs |
| --- | --- | --- |
| The PowerShell exporter | Active Directory groups | On a domain-joined computer, in your session. |
| `shaar collect ad` | The same, from a domain controller | Anywhere that can reach the controller over WinRM. Needs the `ad` extra. |
| `shaar collect entra` | Entra ID groups, owners, managers, and directory roles | Anywhere that can reach Microsoft Graph. Needs the `entra` extra. |

> **Status: untested on real systems.** None of the collectors has been run against a real domain, a real WinRM endpoint, or a real Entra tenant. The exporter is tested under PowerShell 7 with synthetic stand-ins for Active Directory, and the remote collector with a simulated WinRM client. The Entra collector is tested against a fake Graph server. Windows PowerShell 5.1 has not been run. Treat the first runs in your environment as a pilot, and check each export against a source you trust. See [Limitations](limitations.md).

All collectors only read.

## The exporter script

`Export-ShaarAccess.ps1` reads group membership from Active Directory and writes one shaar export. Both Windows PowerShell 5.1 and PowerShell 7 are supported, as the script's help states. It needs no module: it uses ADSI searches, not the ActiveDirectory module. It is pure ASCII, so Windows PowerShell 5.1 reads it the same as PowerShell 7.

### What it reads

- **The groups you choose.** The scope is one or more of `-Group` (a name, a distinguished name, or a SID), `-SearchBase` (every group below a distinguished name), and `-Privileged`. At least one is required. A name that matches no group, or more than one, is a gap.
- **Their members, in full.** The `member` attribute is read with ranged retrieval (`member;range=0-1499` and so on), so a group of any size is read completely. Every returned range, including the last one (`member;range=N-*`), must start where the request did. An unexpected range answer, or more than 100,000 ranges, is a gap and the group is `complete: false`.
- **Nested groups.** Each nested group is read once, breadth first, and the nesting that was found is kept as a graph. The `via` of a grant is a shortest chain of group names from the exported group down. `extra.paths` lists one shortest route for each direct holding group and each group that nests it, so a group shared by two branches shows a route through each branch. It is one shortest route per holder and nesting group, not every route: the full count of routes can grow exponentially. A cycle is reported whenever a membership edge leads to a group that can reach the edge's starting group again, including across branches. `extra.nesting_cycle_count` holds how many were found, and `extra.nesting_cycles` lists the first five, ending with `and N more` when there were more. At most 5,000 nested groups are expanded per exported group, then a gap says the rest were not.
- **The primary group.** An account whose `primaryGroupID` names a group is not in that group's `member` attribute. The script queries them and includes them with `extra.through` set to `primary group`. If a group being expanded, nested ones included, has no readable `objectSid` or relative id, that query cannot be made: it is a gap, and the group and every exported group whose expansion reached it are `complete: false`, so `verify` does not read the missing accounts as removed. Builtin groups (`S-1-5-32-*`) and groups of other domains have no primary group members in this domain, by design, and are not a gap.
- **Foreign security principals.** A member from another domain is turned into its SID, with its name when Windows can resolve it. When it cannot, the name is the SID and a gap says so. Groups across a trust are not expanded.
- **Principals.** For every member the script reads the name, the SID, the UPN, `mail`, whether the account is disabled (`userAccountControl`), the last sign-in, and the object class. The kind is `user`, `group`, `device` (computers), `service` (managed service accounts), or `other`.
- **Managers.** Each account's `manager` is resolved to a SID, and so is that manager's manager, up to 100 levels, so a reviewer can be found for everyone.
- **Owners.** A group's `managedBy` is its owner.
- **The well-known privileged groups** (`-Privileged`): Administrators, Account Operators, Server Operators, Print Operators, Backup Operators, Domain Admins, Schema Admins, Enterprise Admins, Group Policy Creator Owners, Key Admins, and Enterprise Key Admins, found by SID or relative id, and DnsAdmins, found by name. A group that does not exist in the domain is a gap.

The last sign-in is `lastLogonTimestamp`. Domain controllers replicate it with up to about 14 days of lag, so it can be that much out of date.

### Gaps

Whatever the account cannot read becomes a `gap` line, and the groups affected are written with `"complete": false`. Partial data is kept. Active Directory hides an attribute that the account may not read: it looks the same as an empty one, and nothing can detect that from the outside. A group that the account may not read at all is a gap. See [Limitations](limitations.md).

### Required rights

The script needs read access to the groups and their members. Authenticated Users have it by default. It writes only the output file.

### Run it

Write the script from the installed package, then copy it to the computer where you run it:

```shell
shaar exporter ./tools
```

On a domain-joined computer, in PowerShell:

```powershell
.\Export-ShaarAccess.ps1 -Privileged -OutFile C:\Temp\corp-access.jsonl
.\Export-ShaarAccess.ps1 -Group 'Finance Approvers' -SearchBase 'OU=Groups,DC=corp,DC=example' -OutFile C:\Temp\finance.jsonl
```

Read the script before you run it. It is one plain-text file with its help at the top, and `Get-Help .\Export-ShaarAccess.ps1 -Detailed` shows that help. If the execution policy blocks it, run it for one session only:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\Export-ShaarAccess.ps1 -Privileged -OutFile C:\Temp\corp-access.jsonl
```

| Parameter | Meaning |
| --- | --- |
| `-Group` | Groups to export, from 1 to 10,000, each a name (`sAMAccountName` or common name), a distinguished name, or a SID. |
| `-SearchBase` | A distinguished name. Every group below it is exported. |
| `-Privileged` | Export the well-known privileged groups. |
| `-Server` | The domain controller to read from. Default: any controller. |
| `-OutFile` | The file to write. Required, unless you give `-ToPipeline`. |
| `-Force` | Replace `-OutFile` if it exists. |
| `-ToPipeline` | Write the lines to the output stream instead of a file. `shaar collect ad` uses this. |

If no group can be exported at all, the script stops with an error and writes no file. Otherwise it writes a file even when parts were unreadable.

To check removals later, run the script twice with the same scope, before and after, with different file names. Reports name each input by its file name.

### How the file is written

The script writes to a temporary file next to `-OutFile`, keeps a running SHA-256, writes the trailer last, and only then moves the file into place. Without `-Force` it never replaces an existing file. If the script stops partway, no file appears under the `-OutFile` name.

### Why it is read-only

The script uses ADSI searches and never calls anything that changes a directory object. Its only write is the output file. It reads no secret and writes none. The repository tests check the script's commands and run it under PowerShell 7 against stand-ins.

## Collecting over WinRM

`shaar collect ad` sends the packaged script to a domain controller, runs it there with `-ToPipeline`, and streams the lines back into a file. Nothing is installed on the controller. The script reads from that controller (`-Server`), so its directory reads are not a second hop.

```shell
shaar collect ad --host dc01.corp.example --privileged --auth ntlm \
  --username 'CORP\auditor' --secret env:SHAAR_PASSWORD --ca-file corp-root-ca.pem \
  -o corp-access.jsonl
```

The command needs the `ad` extra (`pypsrp`):

```shell
pipx install "faithful-shaar[ad]"
```

### Prerequisites

- A WinRM listener on the controller that your computer can reach: port 5986 for HTTPS, or 5985 for HTTP with message encryption. shaar does not create or change a listener.
- For HTTPS, a controller certificate that chains to a root you trust and names the `--host` DNS name. Give the PEM file of your internal CA to `--ca-file` when the system does not already trust it.
- An account that may open a PowerShell remoting session on the controller (by default, a member of Administrators or Remote Management Users) and may read the groups. Whether a just-enough-administration endpoint can be narrowed to this script has not been tested.

On Linux and macOS, Kerberos needs support that the `ad` extra does not install: the `kerberos` extra of `pypsrp` and the system Kerberos libraries. This has not been tested.

### Security rules

shaar offers no insecure combination. These rules are the same as in the sibling tool mishpat.

- HTTPS on port 5986 is the default. It always verifies the certificate against the system's roots or the authorities in `--ca-file`. No option turns verification off.
- HTTP on port 5985 is accepted only with message encryption always required. `--ca-file` with `--transport http` is refused.
- `--host` must be a fully qualified DNS name. The certificate and the Kerberos service name are checked against it. An IP address or a bare host name is refused.
- Authentication is `kerberos` (default), `negotiate`, or `ntlm`. None sends the password to the server. Basic and CredSSP are not offered: Basic sends the password itself, and CredSSP hands the account's reusable credentials to the server. NTLM is weaker than Kerberos, so prefer Kerberos.
- shaar checks `--host`, `--username` (`DOMAIN\user` or `user@domain.example`, with the domain), and the pairing of `--username` with `--secret` before it reads a secret or connects.
- shaar waits up to 30 seconds to connect. After that there is no overall limit, only an idle one: if the controller sends nothing for `--timeout` seconds (default 600), shaar stops the remote script and fails with exit code `3`.

Use a dedicated account with only the rights listed above.

### How the file is written safely

The lines stream into a private temporary file next to the output. shaar checks each line as it arrives: it must be one line of ASCII text, at most 1 MiB, and the first must be an export header for Active Directory. Every other line must hold exactly one of `principal`, `resource`, `grant`, and `gap`, and nothing may follow the end line. At the end, the trailer's record count and SHA-256 must match what arrived. Only then does shaar publish the file, and an existing file is never replaced without `--force`. On any failure the temporary file is deleted. A partial file is never left behind.

The command prints the number of records, each group that is incomplete, and each gap as `not read:` lines. It exits with `0` even then. The check proves the transfer was whole, not that the controller told the truth.

## The Entra collector

`shaar collect entra` reads Entra ID through Microsoft Graph and writes a shaar export. It needs the `entra` extra, which adds `azure-identity`, Microsoft's maintained library for sign-in. The library handles certificate assertions and device-code sign-in, and shaar writes no token or secret to disk.

```shell
shaar collect entra --tenant corp.example --client-id 11111111-1111-4111-8111-111111111111 \
  --certificate entra-reader.pem --group "Finance Approvers" --roles --pim -o entra-access.jsonl
```

### Sign-in

Give exactly one of:

- `--certificate PATH` (PEM or PFX), with `--certificate-password REF` when the file has a password.
- `--client-secret REF`, a [secret reference](#secret-references) for the application's client secret.
- `--device-code`, which prints a URL and a code on standard error and signs in as you.

`--tenant` is the tenant id (a GUID) or a verified domain name. `--client-id` is the application's id. The sign-in scope is the Graph host's `/.default`.

The export names the tenant that answered, not the one you typed. shaar reads the `tid` claim of the access token it used (the token's payload is decoded to learn the tenant, its signature is not checked, and the token is neither shown nor stored) and writes that tenant id, in lower case, as the header's `tenant`. The header also records `cloud`, the `--cloud` value. If the token has no `tid` claim, or the claim is not a GUID, collection stops with exit code `3`. If `--tenant` is a GUID that differs from the token's `tid`, collection stops with exit code `3` too. A domain name is accepted as given, because the token is the only proof of which tenant it names.

`--cloud` chooses the national cloud:

| Cloud | Graph host |
| --- | --- |
| `global` (default) | `graph.microsoft.com` |
| `usgov` | `graph.microsoft.us` |
| `usgovdod` | `dod-graph.microsoft.us` |
| `china` | `microsoftgraph.chinacloudapi.cn` |

The matching sign-in authority is used for each.

### What to read

Give at least one:

- `--group ID|NAME ...`: groups by object id, or by display name. A name must match exactly one group. No match, or several, is a gap, and the gap lists the ids so you can use one.
- `--all-security-groups`: every group with `securityEnabled` true.
- `--roles`: active directory role assignments.
- `--pim`: eligible role assignments (PIM schedules). Only schedules in force at the collection time become grants. See [Directory roles](#directory-roles).

For each group, shaar records the group, its members and nested members, and its owners. For each user it reads, it records the manager. `signInActivity` is not read, so `last_sign_in` stays empty: it needs an extra license and the `AuditLog.Read.All` permission.

### Directory roles

Each directory role is a resource with the id `ROLE-DEFINITION-ID` (active assignments) or `ROLE-DEFINITION-ID:eligible` (PIM). The two kinds are separate resources, each complete only when its own listing was read in full.

A grant is one role, one principal, and one scope. Its entitlement is `whole directory` when the directory scope is `/`, and the word `scope`, a space, and the scope id otherwise, for example `scope /administrativeUnits/ID`. Scopes are never merged: a principal with the same role in two scopes has two grants. Neither the resource id nor the entitlement holds the role's display name, which can change or fail to be read. A role rename, or a refused role-name request, therefore changes no grant key. The name is only in the resource's `name` (with "(eligible)" added for PIM), and a role whose name was not read is named by its id.

An eligibility schedule becomes a grant only when its `status` is `Provisioned` and its window contains the collection time: `startDateTime` is missing or not later than that time, and `expiration.type` is `noExpiration` or `endDateTime` is later than that time. Schedules known not to be access now are skipped without a gap: status `Revoked`, `Canceled`, `Denied`, or `Failed`, and a window that has ended or has not started. Anything else cannot be told: another or missing status, a missing `scheduleInfo`, or a window that cannot be read or contradicts itself. Such a schedule is not a grant. It is a gap, and its role resource is incomplete.

### What makes a resource incomplete

A record that a listing returns and shaar cannot use is lost evidence, so it is a gap and it withdraws completeness:

- Role listings: an assignment without a `principalId`, without a directory scope, or an eligibility schedule that cannot be evaluated makes its role resource incomplete. An assignment without a usable `roleDefinitionId`, or a list entry that is not an object, cannot be tied to a role, so every role resource of that listing is incomplete.
- Group listings (`members`, `transitiveMembers`, `owners`): a record without an id, or a list entry that is not an object, makes that group incomplete.
- A listing that stopped early (a failed page, a refused paging link) makes the same resources incomplete as before.

An incomplete resource never proves that access was removed.

### Permissions

Create an application registration with these **read-only application permissions** and grant admin consent:

| Permission | Needed for |
| --- | --- |
| `GroupMember.Read.All` | Groups, members, and owners. |
| `User.Read.All` | Users' details and managers. |
| `RoleManagement.Read.Directory` | `--roles` and `--pim`. |

With `--device-code`, the permissions that apply are the application's delegated permissions for the signed-in user. <!-- TODO(verify): the collector's help and code name application permissions only; the delegated equivalents and a device-code sign-in have not been tried against a tenant. -->

### The Graph requests

Every request is an HTTP `GET` to the v1.0 API on the Graph host. The client has no way to name another method. Besides the requests below, only azure-identity makes network calls, to the sign-in authority for the token.

| Purpose | Endpoint |
| --- | --- |
| A group by id | `/groups/{id}?$select=id,displayName,securityEnabled` |
| Groups by name | `/groups?$filter=displayName eq '...'` |
| All security groups | `/groups?$filter=securityEnabled eq true` |
| Owners | `/groups/{id}/owners` |
| All members, nested included | `/groups/{id}/transitiveMembers` |
| Direct members and nested groups | `/groups/{id}/members` |
| A user's manager | `/users/{id}?$select=id&$expand=manager($select=...)` |
| Role names | `/roleManagement/directory/roleDefinitions` |
| Active role assignments | `/roleManagement/directory/roleAssignments?$expand=principal` |
| Eligible role assignments | `/roleManagement/directory/roleEligibilitySchedules?$expand=principal` |

Member and owner requests select `id,displayName,userPrincipalName,mail,accountEnabled,userType` and ask for pages of 999. shaar compares transitive and direct members to tell direct members from nested ones, and works out the chain of group names for nested ones. It does not use `$batch`.

### Safety rules

- **Plain paths only.** shaar puts ids from Graph responses into request paths. A path is requested only when every segment is plain letters, digits, `.`, `_`, or `-`, and none is `.` or `..`. Any other id is a gap, so a response cannot steer a request elsewhere.
- **The token never leaves the Graph host.** It goes only to the configured host over HTTPS with the default certificate checks. shaar follows no redirect. A paging link (`@odata.nextLink`) is followed only when its scheme and host equal the base URL's and its path is under `/v1.0/`. Any other link stops the listing with a gap.
- **Paging and size.** A listing stops after 500 pages, on a repeated link, or on a response over 16 MiB, with a gap. Requests time out after 60 seconds.
- **Throttling.** HTTP 429, 503, and 504 are retried up to five times, waiting as `Retry-After` says (seconds or a date), capped at 60 seconds, with doubling backoff otherwise.
- **Failures.** Other errors become gaps. A 403 names the permission needed. HTTP 401, or a failed sign-in, stops collection with exit code `3`.
- **Secrets.** shaar never logs or writes the token, and removes it and every resolved secret from every message.
- **Proxies.** The default opener honors the usual proxy environment variables.

### Gaps

A failed page, or a listing that stopped early, makes the group `complete: false` and writes a gap. A nested group that could not be read leaves its members with a `path_unknown` note. At most 1,000 nested groups are expanded per group, and managers are read for at most 20,000 users and stop after 20 failures. Each is a gap.

A role assigned to a **group** is not expanded: the group appears as the holder, and a gap says to collect the group with `--group`. Role definitions are written as resources even when nobody holds them, so an empty role can be complete.

`collected_at` is the time the collection started, or `SOURCE_DATE_EPOCH` when set.

## Secret references

`--secret`, `--client-secret`, and `--certificate-password` take a reference, never the secret. shaar reads the secret when it starts and passes it to the authentication library. It never writes it to an output file or a report.

| Provider | Reference | Extra | Notes |
| --- | --- | --- | --- |
| Environment | `env:NAME` | none | The variable must be set and not empty. |
| File | `file:PATH` | none | The first line, read as UTF-8. A byte order mark is accepted. shaar does not check who can read the file. |
| Keyring | `keyring:SERVICE/USERNAME` | `keyring` | The operating system keychain entry. |
| HashiCorp Vault | `vault:MOUNT/PATH#FIELD` | `vault` | A KV version 2 secret. Uses `VAULT_ADDR` and `VAULT_TOKEN`. `#FIELD` is required. |
| AWS Secrets Manager | `aws:SECRET_ID` or `aws:SECRET_ID#FIELD` | `aws` | The standard credential chain. With `#FIELD` the secret must be JSON. |
| Azure Key Vault | `azure:VAULT_NAME/SECRET_NAME` | `azure` | Reads `https://VAULT_NAME.vault.azure.net` with `DefaultAzureCredential`. |

A missing provider package gives an error that names the extra to install. An empty secret is refused. shaar remembers every secret it resolves and removes it, in its plain, URL-encoded, JSON-escaped, and quoted forms, from any error before printing it. Errors from Vault, AWS, and Azure name only the exception type.

## After collecting

Collect again after the removals are due, with the same scope, and give the new files to [`shaar verify`](verification.md).
