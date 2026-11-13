# 5. Collectors: a PowerShell exporter, WinRM, and Microsoft Graph

- Status: accepted
- Date: 2026-11-13

## Context

The project rule is that the tool stays read-only and offline unless a decision record says otherwise. A review needs access data, and typing it in is not realistic. shaar needs to collect it, which needs the network.

Active Directory is the first source. Running a script by hand on each computer is slow, and many teams want to collect from one workstation with nothing installed on the controller. The sibling tool mishpat already collects remotely over WinRM with the `pypsrp` library, and this record adopts its settings so an administrator who has set up one has set up both.

Entra ID is the second. It has no script to run. Its data is behind Microsoft Graph, so reading it makes shaar a network client of a cloud service. This is the first collector that talks to a service that is not a computer the operator controls.

Options considered for Active Directory: users copy the file (still supported); PowerShell remoting over SSH (needs more setup per controller); WMI or DCOM (older, with harder firewall rules); WinRM with `pypsrp`.

Options considered for Entra ID: the portal's CSV download (still supported, but it has no owners, managers, nesting, or completeness); the `Microsoft.Graph` PowerShell module (a large dependency, and no control over the requests); the Graph SDK for Python (a large dependency); standard-library HTTP with `azure-identity` for sign-in.

## Decision

- **PowerShell exporter.** `Export-ShaarAccess.ps1` reads group membership with ADSI searches, no module, read-only, and writes the [export](0004-export-format.md). `shaar exporter` writes it out.
- **`shaar collect ad`.** It sends the packaged script to a controller over WinRM and streams the lines back. HTTPS on port 5986 is the default and always verifies the certificate. HTTP is accepted only with message encryption. Only Kerberos, Negotiate, and NTLM are offered, not Basic or CredSSP. `--host` must be a DNS name. Secrets come from references, never the command line. Each line is checked as it arrives, and the file is published only after the trailer matches. The `ad` extra adds `pypsrp`.
- **`shaar collect entra`.** It reads Microsoft Graph v1.0 with the standard library's `urllib`, and signs in with `azure-identity`, installed as the `entra` extra. We chose `azure-identity` because Microsoft maintains it, it handles certificate assertions, client secrets, and device-code sign-in, and it caches tokens without writing secrets to disk.
- **Why this is acceptable for Graph.** The network use is narrow and checked:
  - The application needs only read-only application permissions: `GroupMember.Read.All`, `User.Read.All`, and `RoleManagement.Read.Directory`.
  - Every request is an HTTP `GET`. The client has no way to name another method, and a test proves every request is a `GET`.
  - The token goes only to the configured Graph host, over HTTPS with default certificate verification. Redirects are refused, and a paging link is followed only when it stays on the same scheme and host, under `/v1.0`.
  - Responses and pages are bounded, retries are capped, and throttling is honored.
  - The token and every secret are redacted from every message and never written.
  - Only `azure-identity`'s own requests for the token go anywhere else, to the sign-in authority.
- **Gaps are results.** Whatever a collector cannot read becomes a `gap` record, and the affected resource is written as not complete. Only a rejected token stops Entra collection.
- **Entra role assignments** are read as two separate resources, active and eligible, each complete only when its own listing was read in full. A role assigned to a group is not expanded.
- **Secret providers** (`env`, `file`, `keyring`, `vault`, `aws`, `azure`) are as in mishpat, each beyond the first two an optional extra.
- Network use is limited to the collect commands. `campaign`, `decisions`, and `verify` stay offline.

## Consequences

Users get an export from one computer. They must still prepare a WinRM listener and an account for Active Directory, and an application registration with admin consent for Entra ID.

`pypsrp` and `azure-identity` and their dependencies enter the supply chain, but only for users who install the extras. Locked versions, license checks, and vulnerability scans cover them.

The Entra collector issues one request per group listing, per nested group, and per user's manager. It is not fast on a large tenant, and it does not use `$batch`.

Nothing was run against a real domain, controller, WinRM endpoint, or tenant. The tests use stand-ins. This is a known limitation, and the documentation says so.

A valid trailer shows that an export arrived whole. It does not show that the controller or tenant told the truth.
