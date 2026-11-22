# 8. A shared core library, faithful-core

- Status: accepted
- Date: 2026-11-21

## Context

shaar and the other Faithful Oversight tools each carried a copy of the same code: making untrusted text safe, publishing files without clobbering, printing without changing an exit code, parsing untrusted XML, resolving secrets, checking server names, and the WinRM connection. The copies drifted. A fix in one tool had to be found, repeated, and tested again in the others, and a review of one copy said nothing about the rest.

[Decision record 2](0002-python-core.md) says each new runtime dependency needs a stated reason. This record is that reason.

Options considered:

- **Keep the copies.** No new dependency, but every fix is repeated and the copies keep drifting.
- **Copy the shared files in with a script.** The code is still reviewed and tested once per tool, and every sync is a large pull request.
- **A shared library that each tool depends on.** One tested copy, and a fix reaches each tool as one small pull request.

## Decision

- shaar depends on [faithful-core](https://github.com/faithful-oversight/faithful-core) for the code listed in the [architecture page](../architecture.md#the-shared-library). The report documents and renderers, the manifest and schemas, the checks on the exporter's lines, the Entra collector, and the commands stay in shaar.
- The pin is exact: `faithful-core==0.1.1` in `pyproject.toml`, with the version and file hashes in `uv.lock`. No version range is allowed. An update arrives as a pull request that runs shaar's own checks: its tests, the license and vulnerability checks, and the smoke test of the installed wheel.
- faithful-core uses only the standard library, so it adds no packages of its own. It is Apache-2.0, and it is released from `faithful-oversight/faithful-core` with trusted publishing and build provenance.
- `pypsrp` stays an optional extra of shaar. faithful-core imports it only when remote collection runs.

This record replaces one earlier statement. The consequences of [decision record 7](0007-packet-workbooks.md) say that shaar has no runtime dependency and no unreviewed XML or zip code on the path of untrusted files. shaar now has one runtime dependency, and the XML parser that reads returned workbooks is in faithful-core. The workbook writer and reader, the zip checks, and the byte-for-byte reproducible packets are still shaar's own, and the packet code still needs no third-party library.

This record also extends [decision record 5](0005-collectors.md), which says shaar adopts the WinRM settings and the secret providers of mishpat. Those now come from faithful-core, which every tool shares, and they behave as before.

## Consequences

One more package is in the supply chain. It belongs to the same project, it has no dependencies, and it appears in the base software bill of materials.

A bug in faithful-core reaches every tool that uses it. The exact pin means a new version reaches shaar only through a reviewed pull request, and the library's own checks run the tests of the public tools before a release.

A few messages changed where the library unified the wording. The changelog lists them.

Installing shaar needs access to a package index that holds faithful-core, so a mirror for an offline install must carry it.
