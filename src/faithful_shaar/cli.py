# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""Command-line entry point."""

from __future__ import annotations

import argparse
import os
import re
import sys
from datetime import UTC, datetime
from enum import IntEnum
from pathlib import Path
from typing import TYPE_CHECKING

from faithful_shaar import __version__, campaign, decide, example, reports, verify
from faithful_shaar.assign import RULES, read_map
from faithful_shaar.collect import ad as collect_ad
from faithful_shaar.collect import entra as collect_entra
from faithful_shaar.collect.secrets import redact
from faithful_shaar.errors import InputError, ShaarError, UsageError
from faithful_shaar.formats.xlsx import read_packet
from faithful_shaar.inputs import read_inputs
from faithful_shaar.outputs.document import format_time
from faithful_shaar.outputs.files import OutputError
from faithful_shaar.outputs.render import render_all, write_outputs
from faithful_shaar.outputs.safety import command_line, terminal
from faithful_shaar.schema import schema_text

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

    from faithful_shaar.model import InputFile

SCHEMAS = ("campaign-report-v1", "decisions-report-v1", "verify-report-v1", "manifest-v1")
MAX_PACKET_BYTES = 64 * 1024 * 1024
CAMPAIGN_FILE = "campaign.json"
DECISIONS_FILE = "decisions.json"
_DATE = re.compile(r"\d{4}-\d{2}-\d{2}")
_CAMPAIGN_CSV = ("unassigned", "rows")
_DECISIONS_CSV = ("removals", "attention", "decisions")
_VERIFY_CSV = ("removals", "kept_but_gone", "new_since_review")
_RECORDS = {"campaign": CAMPAIGN_FILE, "decisions": DECISIONS_FILE}
_PACKET_FILE = re.compile(r"packet-\d+-[A-Za-z0-9-]*\.xlsx")


class ExitCode(IntEnum):
    """Process exit codes. These values are part of the public interface."""

    OK = 0
    FINDINGS = 1
    USAGE = 2
    INPUT_ERROR = 3
    INTERNAL_ERROR = 4


def _date(text: str) -> str:
    msg = f"{text!r} is not a date in the form YYYY-MM-DD"
    if not _DATE.fullmatch(text):
        raise argparse.ArgumentTypeError(msg)
    try:
        datetime.strptime(text, "%Y-%m-%d")  # noqa: DTZ007 - a calendar date, no time
    except ValueError:
        raise argparse.ArgumentTypeError(msg) from None
    return text


def _time(text: str) -> str:
    try:
        moment = datetime.fromisoformat(text)
    except ValueError:
        msg = f"{text!r} is not an ISO 8601 time such as 2026-11-20T09:00:00Z"
        raise argparse.ArgumentTypeError(msg) from None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=UTC)
    return format_time(moment.astimezone(UTC))


def _csv_options(parser: argparse.ArgumentParser) -> None:
    group = parser.add_argument_group("CSV inputs")
    group.add_argument(
        "--map", type=Path, metavar="FILE", help="a column map (TOML) for CSV inputs"
    )
    group.add_argument(
        "--preset",
        metavar="NAME",
        help="a built-in column map: generic, ad-users-groups or entra-members",
    )
    group.add_argument(
        "--resource", metavar="NAME", help="the resource a members-only CSV lists (entra-members)"
    )


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser."""
    parser = argparse.ArgumentParser(
        prog="shaar",
        description=(
            "Access Review Kit: access data in, reviewer packets out, decisions back in, and "
            "a check of which removals were actually made. shaar never changes access."
        ),
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    commands = parser.add_subparsers(title="commands", metavar="COMMAND")

    start = commands.add_parser(
        "campaign",
        help="start a review: assign reviewers and write one packet per reviewer",
        description=(
            "Read access exports (shaar exports from the AD exporter or 'shaar collect', or "
            "CSV files with a column map), assign a reviewer to every entry, and write "
            "campaign.json, one Excel packet per reviewer, and a campaign report."
        ),
    )
    start.add_argument("inputs", type=Path, nargs="+", metavar="INPUT")
    start.add_argument(
        "-o", "--output", type=Path, required=True, metavar="DIR", help="folder for the campaign"
    )
    start.add_argument("--name", required=True, help="the campaign's name, shown in every packet")
    start.add_argument(
        "--reviewers",
        choices=RULES,
        required=True,
        help=(
            "who reviews each entry: the principal's manager, the resource's owner, or a "
            "reviewer map"
        ),
    )
    start.add_argument(
        "--reviewer-map",
        type=Path,
        metavar="FILE",
        help="CSV naming reviewers (with --reviewers map)",
    )
    start.add_argument(
        "--due",
        type=_date,
        default=None,
        metavar="YYYY-MM-DD",
        help="when decisions and removals are due",
    )
    _csv_options(start)
    start.add_argument("--force", action="store_true", help="replace existing files")
    start.set_defaults(run=_campaign)

    take = commands.add_parser(
        "decisions",
        help="read returned packets into a checked decision record",
        description=(
            "Read the packets reviewers returned, check each against the campaign, and write "
            "decisions.json, the removals to make, and a decisions report."
        ),
    )
    take.add_argument(
        "campaign", type=Path, metavar="CAMPAIGN", help="the campaign folder or its campaign.json"
    )
    take.add_argument("packets", type=Path, nargs="+", metavar="PACKET")
    take.add_argument(
        "-o",
        "--output",
        type=Path,
        required=True,
        metavar="DIR",
        help="folder for the decision record",
    )
    take.add_argument(
        "--require-comment",
        action="append",
        default=[],
        choices=decide.DECISIONS,
        metavar="DECISION",
        help="a decision that needs a comment (repeatable): Keep, Remove or Unsure",
    )
    take.add_argument("--force", action="store_true", help="replace existing files")
    take.set_defaults(run=_decisions)

    check = commands.add_parser(
        "verify",
        help="check a later export: were the removals made?",
        description=(
            "Compare access read after the due date with the accepted Remove decisions. Each "
            "removal is removed, pending, failed or unknown, with the reason."
        ),
    )
    check.add_argument(
        "campaign", type=Path, metavar="CAMPAIGN", help="the campaign folder or its campaign.json"
    )
    check.add_argument(
        "decisions",
        type=Path,
        metavar="DECISIONS",
        help="the decisions folder or its decisions.json",
    )
    check.add_argument("inputs", type=Path, nargs="+", metavar="LATER")
    check.add_argument(
        "-o", "--output", type=Path, required=True, metavar="DIR", help="folder for the report"
    )
    check.add_argument(
        "--as-of",
        type=_time,
        default=None,
        metavar="TIME",
        help="when the later access was read; overrides the time the inputs record",
    )
    _csv_options(check)
    check.add_argument("--force", action="store_true", help="replace existing files")
    check.set_defaults(run=_verify)

    schema = commands.add_parser(
        "schema", help="print a JSON schema", description="Print a JSON schema, offline."
    )
    schema.add_argument("name", choices=SCHEMAS)
    schema.set_defaults(run=_schema)

    sample = commands.add_parser(
        "example",
        help="write synthetic access data and returned packets to try shaar with",
        description=(
            "Write synthetic exports, returned packets and a later export. Every name in "
            "them is made up."
        ),
    )
    sample.add_argument("directory", type=Path, metavar="DIR")
    sample.add_argument("--force", action="store_true", help="replace existing files")
    sample.set_defaults(run=_example)

    collect_ad.add_exporter_arguments(commands)
    collect = commands.add_parser(
        "collect",
        help="read access from Active Directory or Entra ID into a shaar export",
        description="Read access directly. Collection only reads; it never changes anything.",
    )
    sources = collect.add_subparsers(title="sources", metavar="SOURCE")
    collect_ad.add_collect_ad_arguments(sources)
    collect_entra.add_collect_entra_arguments(sources)
    collect.set_defaults(run=None)
    return parser


def _now() -> datetime:
    """The time: the clock, or ``SOURCE_DATE_EPOCH`` for repeatable output."""
    fixed = os.environ.get("SOURCE_DATE_EPOCH", "")
    if fixed.isascii() and fixed.isdigit():
        try:
            return datetime.fromtimestamp(int(fixed), UTC)
        except (OverflowError, OSError, ValueError):
            pass
    return datetime.now(UTC).replace(microsecond=0)


def _read(path: Path, limit: int, what: str) -> bytes:
    try:
        if not path.is_file():
            msg = f"cannot read {path.name}: it is not a file"
            raise InputError(msg)
        if path.stat().st_size > limit:
            msg = f"{path.name} is larger than {limit} bytes, so it is not read as {what}"
            raise InputError(msg)
        return path.read_bytes()
    except OSError as exc:
        msg = f"cannot read {path.name}: {exc.strerror}"
        raise InputError(msg) from None


def _record(path: Path, name: str, limit: int) -> bytes:
    return _read(path / name if path.is_dir() else path, limit, name)


def _owned(command: str) -> Callable[[str], bool]:
    """Return which file names ``command`` writes, so ``--force`` takes away no others."""
    names = {
        "campaign": {CAMPAIGN_FILE, "campaign-report.json", "campaign-report.md"}
        | {"campaign-report.html"}
        | {f"{key}.csv" for key in _CAMPAIGN_CSV},
        "decisions": {DECISIONS_FILE, "decisions-report.json", "decisions-report.md"}
        | {"decisions-report.html"}
        | {f"{key}.csv" for key in _DECISIONS_CSV},
        "verify": {"verify-report.json", "verify-report.md", "verify-report.html"}
        | {f"{key}.csv" for key in _VERIFY_CSV},
    }[command]
    packets = command == "campaign"
    return lambda name: name in names or (packets and _PACKET_FILE.fullmatch(name) is not None)


def _guard_output(directory: Path, command: str, records: Sequence[Path] = ()) -> None:
    """Refuse an output folder that would put new files among the records a run rests on.

    ``records`` are the campaign and decision records the command was given (a folder or a
    ``campaign.json``/``decisions.json`` path). The output folder may not be one of their
    folders or contain one, and may not already hold a record that this command does not
    write, whatever ``--force`` says: those records cannot be made again.
    """
    here = directory.resolve()
    for record in records:
        folder = (record if record.is_dir() else record.parent).resolve()
        if here == folder or here in folder.parents:
            msg = (
                f"the output folder {directory} is, or contains, the folder of {record}; "
                "write the result to a new folder so that record is never replaced"
            )
            raise OutputError(msg)
    for kind, name in _RECORDS.items():
        if kind != command and (directory / name).exists():
            msg = (
                f"{directory / name} is a {kind} record, which shaar {command} does not write; "
                "choose another output folder (even --force never replaces it)"
            )
            raise OutputError(msg)


def _write(  # noqa: PLR0913 - one call per command, all keywords
    directory: Path,
    files: dict[str, bytes],
    *,
    command: str,
    force: bool,
    inputs: Sequence[InputFile],
    when: str,
) -> None:
    write_outputs(
        directory,
        files,
        force=force,
        generated_at=when,
        tool_version=__version__,
        inputs=inputs,
        removable=_owned(command),
    )


def _campaign(args: argparse.Namespace) -> int:
    if (args.reviewers == "map") != (args.reviewer_map is not None):
        msg = "use --reviewer-map with --reviewers map, and only then"
        raise UsageError(msg)
    _guard_output(args.output, "campaign")
    entries = read_map(args.reviewer_map) if args.reviewer_map else None
    snapshot = read_inputs(
        args.inputs, label="campaign", csv_map=args.map, preset=args.preset, resource=args.resource
    )
    when = format_time(_now())
    built = campaign.build(
        snapshot,
        name=args.name,
        created_at=when,
        due=args.due or "",
        rule=args.reviewers,
        entries=entries,
    )
    document = reports.campaign_document(built, generated_at=when, version=__version__)
    files = {CAMPAIGN_FILE: campaign.dump(built), **reports.packets(built)}
    files |= render_all(document, list(_CAMPAIGN_CSV) if built.unassigned else ["rows"])
    _write(args.output, files, command="campaign", force=args.force, inputs=built.inputs, when=when)
    print(terminal(document.headline))  # noqa: T201
    print(terminal(f"Campaign written to {args.output}: {len(built.reviewers)} packets to send."))  # noqa: T201
    if built.reviewers:
        returned = command_line(
            "shaar", "decisions", str(args.output), "PACKET...", "-o", "DECISIONS"
        )
        print(terminal(f"When the packets come back:\n  {returned}"))  # noqa: T201
    return int(ExitCode.FINDINGS if built.unassigned or built.problems else ExitCode.OK)


def _decisions(args: argparse.Namespace) -> int:
    _guard_output(args.output, "decisions", [args.campaign])
    built = campaign.load(_record(args.campaign, CAMPAIGN_FILE, campaign.MAX_CAMPAIGN_BYTES))
    names = [path.name for path in args.packets]
    repeated = sorted({name for name in names if names.count(name) > 1})
    if repeated:
        msg = f"two packets are named {repeated[0]}; rename one so each decision's source is clear"
        raise UsageError(msg)
    files = [(path.name, _read(path, MAX_PACKET_BYTES, "a packet")) for path in args.packets]
    when = format_time(_now())
    record = decide.read_decisions(
        built, files, read=read_packet, created_at=when, require_comment=args.require_comment
    )
    document = reports.decisions_document(built, record, generated_at=when, version=__version__)
    out = {
        DECISIONS_FILE: decide.dump(record),
        **render_all(document, [*_DECISIONS_CSV]),
    }
    _write(args.output, out, command="decisions", force=args.force, inputs=built.inputs, when=when)
    print(terminal(document.headline))  # noqa: T201
    print(terminal(f"Decision record written to {args.output}."))  # noqa: T201
    return int(ExitCode.FINDINGS if decide.gaps(built, record) else ExitCode.OK)


def _verify(args: argparse.Namespace) -> int:
    _guard_output(args.output, "verify", [args.campaign, args.decisions])
    built = campaign.load(_record(args.campaign, CAMPAIGN_FILE, campaign.MAX_CAMPAIGN_BYTES))
    record = decide.load(_record(args.decisions, DECISIONS_FILE, decide.MAX_DECISIONS_BYTES))
    later = read_inputs(
        args.inputs, label="later", csv_map=args.map, preset=args.preset, resource=args.resource
    )
    when = format_time(_now())
    outcome = verify.verify(built, record, later, as_of=args.as_of or "")
    document = reports.verify_document(
        built, outcome, later, generated_at=when, version=__version__
    )
    files = render_all(document, [*_VERIFY_CSV])
    _write(args.output, files, command="verify", force=args.force, inputs=later.inputs, when=when)
    print(terminal(document.headline))  # noqa: T201
    print(terminal(f"Report written to {args.output}."))  # noqa: T201
    return int(ExitCode.OK if outcome.complete else ExitCode.FINDINGS)


def _schema(args: argparse.Namespace) -> int:
    sys.stdout.write(schema_text(args.name))
    return int(ExitCode.OK)


def _example(args: argparse.Namespace) -> int:
    written = example.write(args.directory, force=args.force)
    print(terminal(f"Wrote synthetic access data to {args.directory}. Try:\n{written}"))  # noqa: T201
    return int(ExitCode.OK)


def main(argv: Sequence[str] | None = None) -> int:
    """Run the command line and return an exit code."""
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        code = exc.code
        return int(code) if isinstance(code, int) else int(ExitCode.USAGE)
    if not getattr(args, "run", None):
        parser.print_help(sys.stderr)
        return int(ExitCode.USAGE)
    try:
        return int(args.run(args))
    except ShaarError as exc:
        print(f"shaar: error: {terminal(redact(str(exc)))}", file=sys.stderr)  # noqa: T201
        return int(ExitCode.USAGE if isinstance(exc, UsageError) else ExitCode.INPUT_ERROR)
    except Exception as exc:  # noqa: BLE001 - last-resort handler keeps crashes distinct
        print(  # noqa: T201
            f"shaar: internal error: {type(exc).__name__}: {terminal(redact(str(exc)))[:200]}\n"
            "This is a bug in shaar. Please report it.",
            file=sys.stderr,
        )
        return int(ExitCode.INTERNAL_ERROR)
