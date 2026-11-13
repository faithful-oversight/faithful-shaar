# shaar documentation

shaar runs an access review from files: it reads who holds access, writes one Excel packet per reviewer, reads the returned decisions, and later checks whether each removal happened. It says what it could not read or verify, and it never changes access.

## Start here

- [Usage](usage.md): every command, option, and exit code.
- [Campaigns](campaigns.md): how reviewers are chosen, the packet workbook, and which returned decisions count.
- [Verification](verification.md): the results of checking a later export.
- [Collecting](collecting.md): the Active Directory exporter, WinRM collection, and the Entra collector.
- [Formats](formats.md): the shaar export, keys, and CSV column maps.
- [Reports and output](output.md): the reports, JSON Schemas, and CSV files.
- [Limitations](limitations.md): what shaar cannot do.

## Design

- [Architecture](architecture.md): how the tool is built and the rules the design follows.
- [Threat model](threat-model.md): what the tool protects, the threats, and the controls.
- [Releasing](releasing.md): how releases are made and verified.
- [Architecture decision records](adr/index.md): significant decisions and the reasons for them.
