# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""The ``collect ad`` and ``exporter`` commands.

Self-contained: the main parser calls :func:`add_exporter_arguments` and
:func:`add_collect_ad_arguments`, and each command's ``run`` default points at
:func:`run_exporter` or :func:`run_collect_ad`.
"""

from __future__ import annotations

import argparse
import os
import re
import shlex
import subprocess
from pathlib import Path
from typing import TYPE_CHECKING

from faithful_core.collect import names, secrets, winrm
from faithful_core.console import say
from faithful_core.files import refuse_aliases
from faithful_core.safety import terminal_line

from faithful_shaar.collect import remote, script
from faithful_shaar.errors import CollectionError, UsageError

if TYPE_CHECKING:
    from collections.abc import Callable
    from typing import Any

_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f]")
_DN = re.compile(r"[A-Za-z][A-Za-z0-9-]*=.+")


def _bounded(low: int, high: int, what: str) -> Callable[[str], int]:
    def check(text: str) -> int:
        if not text.isdigit() or not low <= int(text) <= high:
            msg = f"give {what} from {low} to {high}"
            raise argparse.ArgumentTypeError(msg)
        return int(text)

    check.__name__ = what
    return check


_seconds = _bounded(1, 86400, "a whole number of seconds")
_port = _bounded(1, 65535, "a port")


def _group(text: str) -> str:
    """Check a group given to ``--group``: a name, distinguished name, or SID."""
    if not text.strip() or _CONTROL.search(text):
        msg = "a group must not be empty or hold control characters"
        raise argparse.ArgumentTypeError(msg)
    return text


def _search_base(text: str) -> str:
    """Check a distinguished name given to ``--search-base``."""
    if not _DN.fullmatch(text) or _CONTROL.search(text):
        msg = f"{text!r} is not a distinguished name, such as OU=Groups,DC=corp,DC=example"
        raise argparse.ArgumentTypeError(msg)
    return text


def terminal(text: str) -> str:
    """Make text safe to print on one line.

    Secrets are removed, and control, format and bidirectional characters are shown
    as escapes by the shared ``terminal_line``.
    """
    return terminal_line(secrets.redact(text))


def _quoted(*parts: str) -> str:
    if os.name == "nt":  # pragma: no cover - the other branch is tested
        return subprocess.list2cmdline(parts)
    return shlex.join(parts)


def add_exporter_arguments(subparsers: Any) -> None:
    """Register ``exporter`` on the main parser's subcommands."""
    exporter = subparsers.add_parser(
        "exporter",
        help="write the PowerShell exporter to run on a domain controller yourself",
        description=(
            f"Write {script.NAME}, the read-only Active Directory exporter, into DIR. "
            "Run it on a domain controller, or any domain-joined computer, and give the "
            "file it writes to 'shaar campaign'."
        ),
    )
    exporter.add_argument("directory", type=Path, metavar="DIR", help="where to write the script")
    exporter.add_argument("--force", action="store_true", help="replace an existing script")
    exporter.set_defaults(run=run_exporter)


def add_collect_ad_arguments(collect_subparsers: Any) -> None:
    """Register ``ad`` on the ``collect`` command's subcommands."""
    ad = collect_subparsers.add_parser(
        "ad",
        help="export group membership from Active Directory over PowerShell remoting",
        description=(
            "Run shaar's read-only exporter on a domain controller over PowerShell remoting "
            "and write its export to a file for 'shaar campaign'. HTTPS always verifies the "
            "certificate; HTTP is used only with message encryption. Give at least one of "
            "--group, --search-base and --privileged."
        ),
    )
    ad.add_argument("--host", required=True, help="the controller's DNS name")
    ad.add_argument(
        "--group", nargs="+", action="extend", type=_group, metavar="GROUP",
        help="export these groups, each a name, distinguished name, or SID",
    )  # fmt: skip
    ad.add_argument(
        "--search-base", type=_search_base, metavar="DN", help="export every group below this DN"
    )
    ad.add_argument(
        "--privileged", action="store_true",
        help="export the well-known privileged groups (Administrators, Domain Admins, ...)",
    )  # fmt: skip
    ad.add_argument("--auth", choices=winrm.AUTHS, default="kerberos")
    ad.add_argument("--username", help="DOMAIN\\user or user@domain.example")
    ad.add_argument(
        "--secret", metavar="REF",
        help="where the password is: env:NAME, file:PATH, keyring:SERVICE/USER, "
        "vault:MOUNT/PATH#FIELD, aws:SECRET_ID[#FIELD], or azure:VAULT/NAME",
    )  # fmt: skip
    ad.add_argument("--transport", choices=winrm.TRANSPORTS, default="https")
    ad.add_argument("--port", type=_port, help="default: 5986 for https, 5985 for http")
    ad.add_argument("--ca-file", type=Path, help="PEM certificate authorities for https")
    ad.add_argument(
        "--timeout", type=_seconds, default=600,
        help="stop when the exporter sends nothing for this many seconds (default: 600)",
    )  # fmt: skip
    ad.add_argument("-o", "--output", required=True, type=Path, metavar="FILE")
    ad.add_argument("--force", action="store_true", help="replace an existing file")
    ad.set_defaults(run=run_collect_ad)


def run_collect_ad(args: argparse.Namespace) -> int:
    """Collect over PowerShell remoting. Everything is checked before any secret is read."""
    host = names.server_name(args.host, flag="--host")
    username = names.account_name(args.username)
    if not (args.group or args.search_base or args.privileged):
        msg = "give at least one of --group, --search-base and --privileged"
        raise UsageError(msg)
    if args.secret and not username:
        msg = "--secret needs --username"
        raise UsageError(msg)
    if args.auth == "ntlm" and not username:
        msg = "--auth ntlm needs --username and --secret; only Kerberos can use the current logon"
        raise UsageError(msg)
    if username and not args.secret:
        msg = "--username needs --secret; leave both out to use the current Kerberos ticket"
        raise UsageError(msg)
    # The files this command reads are never the file it writes, even with --force.
    refuse_aliases([args.output], _read_files(args))
    target = winrm.Target(
        server=host,
        auth=args.auth,
        username=username,
        secret=None,
        transport=args.transport,
        port=args.port,
        ca_file=args.ca_file,
        idle_timeout=args.timeout,
    )
    winrm.settings(target)  # refuse a bad combination before the secret is read
    values = remote.parameters(
        groups=args.group, search_base=args.search_base, privileged=args.privileged, server=host
    )
    if args.secret:
        secret = secrets.resolve(args.secret, hint=remote.install_hint, keep=("ad",))
        target = winrm.Target(**{**vars(target), "secret": secret})
    result = remote.collect(target, script.text(), values, args.output, force=args.force)
    say(terminal(f"Exported {result.records} records from {host} into {result.path}."))
    for name in result.incomplete:
        say(terminal(f"  incomplete: {name}"))
    for gap in result.gaps:
        say(terminal(f"  not read: {gap}"))
    command = _quoted("shaar", "campaign", str(result.path), "-o", "review", "--name", "NAME")
    say(terminal(f"Start a review with: {command} --reviewers manager"))
    return 0


def _read_files(args: argparse.Namespace) -> list[tuple[str, Path]]:
    """The files ``collect ad`` reads, by role: the CA file and a ``file:`` secret."""
    found: list[tuple[str, Path]] = []
    if args.ca_file:
        found.append(("CA file", args.ca_file))
    if (path := remote.secret_file(args.secret)) is not None:
        found.append(("secret file", path))
    return found


def run_exporter(args: argparse.Namespace) -> int:
    """Write the packaged exporter script into a directory."""
    directory: Path = args.directory
    try:
        directory.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        msg = f"cannot create {directory}: {exc.strerror or exc}"
        raise CollectionError(msg) from None
    path = directory / script.NAME
    remote.write_private(path, script.text().encode("ascii"), force=args.force)
    command = f".\\{script.NAME} -Privileged -OutFile corp-access.jsonl"
    say(terminal(f"Wrote {path}. In PowerShell on a domain-joined computer:"))
    say(terminal(f"  {command}"))
    return 0
