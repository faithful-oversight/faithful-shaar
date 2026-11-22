# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""Remote collection over PowerShell remoting, and the collect ad and exporter commands.

The pypsrp client is replaced by a stand-in that replays chosen output. Streams are
built here with the plain ``json`` and ``hashlib`` modules.
"""

from __future__ import annotations

import argparse
import errno
import hashlib
import importlib
import json
import os
import re
import sys
from typing import TYPE_CHECKING, Any

import pytest
from faithful_core.collect import secrets, winrm
from faithful_core.collect.winrm import Target

from faithful_shaar.collect import ad, remote, script
from faithful_shaar.collect.remote import collect, parameters
from faithful_shaar.errors import CollectionError, ShaarError, UsageError

if os.environ.get("SHAAR_REQUIRE_LIVE") == "1":  # pragma: no cover - set in CI
    # Fail at collection, not skip, when the `ad` extra is missing. Imported by name so
    # type checking does not need the extra installed.
    importlib.import_module("pypsrp")

if TYPE_CHECKING:
    from collections.abc import Sequence
    from pathlib import Path

SECRET = 'p@ss w/rd%"\\ü'  # noqa: S105 - synthetic
SERVER = "dc01.corp.example"
TARGET = Target(SERVER, "kerberos", "CORP\\auditor", SECRET)
RUNNING, COMPLETED, FAILED = 1, 4, 5


def line(value: Any) -> str:
    return json.dumps(value, separators=(",", ":"))


def stream(records: Sequence[Any] | None = None, **trailer: Any) -> list[str]:
    """A good export as the exporter writes it: header, records, end line."""
    body = [
        {"principal": {"id": "S-1-5-21-1000-1000-1000-1201", "name": "Avery Example"}},
        {
            "resource": {
                "id": "S-1-5-21-1000-1000-1000-1100",
                "name": "Tier0 Admins",
                "complete": True,
            }
        },
        {"grant": {"principal_id": "S-1-5-21-1000-1000-1000-1201", "resource_id": "x"}},
    ]
    if records is not None:
        body = list(records)
    lines = [line({"shaar_export": 1, "system": "ad", "domain": "corp.example"})]
    lines += [line(record) for record in body]
    digest = hashlib.sha256("".join(entry + "\n" for entry in lines).encode("ascii")).hexdigest()
    end = {"end": True, "records": len(body), "sha256": digest, **trailer}
    return [*lines, line(end)]


def as_file(lines: Sequence[str]) -> bytes:
    return "".join(entry + "\n" for entry in lines).encode("ascii")


LINES = stream()
GOOD = as_file(LINES)


def test_script_parameters() -> None:
    assert parameters(
        groups=["Dup"], search_base="OU=G,DC=corp,DC=example", privileged=True, server=SERVER
    ) == {
        "ToPipeline": True,
        "Group": ["Dup"],
        "SearchBase": "OU=G,DC=corp,DC=example",
        "Privileged": True,
        "Server": SERVER,
    }
    assert parameters(privileged=True) == {"ToPipeline": True, "Privileged": True}
    with pytest.raises(CollectionError, match="at least one"):
        parameters(server=SERVER)


# --- a stand-in for pypsrp --------------------------------------------------------------


class Remote:
    """The parts of pypsrp shaar uses, replaying chosen output in chosen batches."""

    def __init__(self, batches: Sequence[Sequence[object]], *, end: int = COMPLETED) -> None:
        self.batches: list[Sequence[object]] = list(batches)
        self.end = end
        self.settings: dict[str, Any] = {}
        self.script = ""
        self.parameters: dict[str, Any] = {}
        self.error: Exception | None = None
        self.errors: list[str] = []
        self.stopped = False

    def classes(self) -> tuple[Any, Any, Any, int]:  # noqa: C901 - one small class per pypsrp part
        remote_side = self

        class WSMan:
            def __init__(self, **values: Any) -> None:
                remote_side.settings = values
                if remote_side.error is not None:
                    raise remote_side.error

            def __enter__(self) -> WSMan:
                return self

            def __exit__(self, *_: object) -> None:
                return None

        class Pool:
            def __init__(self, _: object) -> None:
                pass

            def __enter__(self) -> Pool:
                return self

            def __exit__(self, *_: object) -> None:
                return None

        class Streams:
            error = remote_side.errors

        class Shell:
            def __init__(self, _: object) -> None:
                self.state = RUNNING
                self.output: list[object] = []
                self.had_errors = False
                self.streams = Streams()

            def add_script(self, text: str) -> None:
                remote_side.script = text

            def add_parameters(self, values: dict[str, Any]) -> None:
                remote_side.parameters = values

            def begin_invoke(self) -> None:
                pass

            def poll_invoke(self, timeout: int) -> None:
                assert timeout == winrm.POLL_SECONDS
                if remote_side.batches:
                    self.output.extend(remote_side.batches.pop(0))
                if not remote_side.batches:
                    self.state = remote_side.end
                    self.had_errors = remote_side.end == FAILED

            def stop(self) -> None:
                remote_side.stopped = True
                msg = "stop is best effort"
                raise RuntimeError(msg)

        return WSMan, Pool, Shell, RUNNING


@pytest.fixture
def fake(monkeypatch: pytest.MonkeyPatch) -> Remote:
    side = Remote([LINES[:2], [], LINES[2:]])
    monkeypatch.setattr(winrm, "client", lambda _hint: side.classes())
    return side


def run(destination: Path, **options: Any) -> remote.Result:
    return collect(
        TARGET,
        "script text",
        {"ToPipeline": True},
        destination,
        force=options.pop("force", False),
        **options,
    )


def leftovers(folder: Path) -> list[str]:
    return sorted(path.name for path in folder.iterdir() if path.name.endswith(".part"))


def test_a_collection_streams_into_a_checked_file(tmp_path: Path, fake: Remote) -> None:
    out = tmp_path / "ad.jsonl"
    result = run(out)
    assert result == remote.Result(out, 3, (), ())
    assert out.read_bytes() == GOOD
    assert leftovers(tmp_path) == []
    assert fake.script == "script text"
    assert fake.parameters == {"ToPipeline": True}
    assert fake.settings["cert_validation"] is True
    assert fake.settings["password"] == SECRET


def test_gaps_and_incomplete_groups_the_exporter_recorded_are_returned(
    tmp_path: Path, fake: Remote
) -> None:
    records = [
        {"resource": {"id": "a", "name": "Locked", "complete": False}},
        {"resource": {"id": "b", "complete": False}},
        {"resource": {"id": "c", "name": "Fine", "complete": True}},
        {"gap": {"what": "members of group Locked", "reason": "Access is denied."}},
    ]
    fake.batches = [stream(records)]
    result = run(tmp_path / "ad.jsonl")
    assert result.gaps == ("members of group Locked: Access is denied.",)
    assert result.incomplete == ("Locked", "b")
    assert result.records == 4


def with_trailer(**changes: Any) -> list[Sequence[object]]:
    lines = stream()
    end = json.loads(lines[-1])
    end.update(changes)
    return [[*lines[:-1], line(end)]]


BAD_STREAMS: list[tuple[str, list[Sequence[object]], str]] = [
    ("count", with_trailer(records=7), "does not match"),
    ("hash", with_trailer(sha256="0" * 64), "does not match"),
    ("no end", [LINES[:-1]], "without its end line"),
    ("after end", [[*LINES, LINES[1]]], "after its end line"),
    ("bytes", [[b"{}"]], "not one line of text"),
    ("non-ascii", [[LINES[0], '{"principal":{"name":"é"}}']], "not one line of text"),
    ("newline", [["{}\n{}"]], "not one line of text"),
    ("carriage return", [["{}\r"]], "not one line of text"),
    ("header", [["{}"]], "not a shaar export header"),
    ("wrong system", [[line({"shaar_export": 1, "system": "entra"})]], "not a shaar export header"),
    ("not json", [[LINES[0], "{nope"]], "line 2 from the exporter is not JSON"),
    ("not an object", [[LINES[0], "[1]"]], "not a JSON object"),
    ("unknown kind", [[LINES[0], '{"mystery":{}}']], r"unknown kind \(line 2\)"),
    ("two kinds", [[LINES[0], '{"gap":{},"grant":{}}']], "unknown kind"),
    ("extra key", [[LINES[0], '{"gap":{},"x":1}']], "unknown kind"),
    ("not a dict", [[LINES[0], '{"gap":[]}']], "unknown kind"),
    ("old format", [[LINES[0], '{"structure":{}}']], "unknown kind"),
    ("end flag", [[LINES[0], '{"end":false,"records":0,"sha256":"x"}']], "end line is not valid"),
    (
        "end records",
        [[LINES[0], '{"end":true,"records":"0","sha256":"x"}']],
        "end line is not valid",
    ),
    (
        "end bool",
        [[LINES[0], '{"end":true,"records":false,"sha256":"x"}']],
        "end line is not valid",
    ),
    ("end hash", [[LINES[0], '{"end":true,"records":0,"sha256":5}']], "end line is not valid"),
]


@pytest.mark.parametrize(
    ("label", "batches", "problem"), BAD_STREAMS, ids=[b[0] for b in BAD_STREAMS]
)
def test_a_damaged_export_leaves_no_file(
    tmp_path: Path, fake: Remote, label: str, batches: list[Sequence[object]], problem: str
) -> None:
    assert label
    fake.batches = batches
    out = tmp_path / "ad.jsonl"
    with pytest.raises(CollectionError, match=problem):
        run(out)
    assert not out.exists()
    assert leftovers(tmp_path) == []


def test_an_overlong_line_is_refused(tmp_path: Path, fake: Remote) -> None:
    fake.batches = [[LINES[0], "x" * remote.MAX_LINE]]
    with pytest.raises(CollectionError, match="line 2 from the exporter is too long"):
        run(tmp_path / "ad.jsonl")
    assert leftovers(tmp_path) == []


@pytest.mark.usefixtures("fake")
def test_a_file_over_the_size_cap_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(remote, "MAX_FILE", 100)
    with pytest.raises(CollectionError, match="larger than"):
        run(tmp_path / "ad.jsonl")
    assert leftovers(tmp_path) == []


def test_a_script_that_fails_reports_its_own_error(tmp_path: Path, fake: Remote) -> None:
    fake.batches = [LINES[:1]]
    fake.end = FAILED
    fake.errors.append("No group could be exported. -Group x: no group has that name")
    with pytest.raises(
        CollectionError, match=r"exporter failed on dc01.*No group could be exported"
    ):
        run(tmp_path / "ad.jsonl")
    fake.batches = [[]]
    fake.errors.clear()
    with pytest.raises(CollectionError, match="stopped with an error"):
        run(tmp_path / "ad.jsonl")
    assert leftovers(tmp_path) == []


def test_a_stalled_collection_is_stopped(tmp_path: Path, fake: Remote) -> None:
    fake.batches = [LINES[:1], *([] for _ in range(10))]
    ticks = iter(range(0, 10_000, 100))
    with pytest.raises(CollectionError, match="nothing for 600 seconds"):
        run(tmp_path / "ad.jsonl", clock=lambda: float(next(ticks)))
    assert fake.stopped is True
    assert leftovers(tmp_path) == []


@pytest.mark.parametrize("text", ["plain", "%s", "url:%s", "json:%s", "repr:%s"])
def test_library_errors_never_show_the_secret(tmp_path: Path, fake: Remote, text: str) -> None:
    from urllib.parse import quote  # noqa: PLC0415

    forms = {
        "plain": SECRET, "%s": SECRET, "url:%s": quote(SECRET, safe=""),
        "json:%s": json.dumps(SECRET)[1:-1], "repr:%s": repr(SECRET)[1:-1],
    }  # fmt: skip
    fake.error = RuntimeError(f"authentication failed for {forms[text]}")
    with pytest.raises(CollectionError) as exc:
        run(tmp_path / "ad.jsonl")
    assert SECRET not in str(exc.value)
    assert forms[text] not in str(exc.value)
    assert "[redacted]" in str(exc.value)
    assert str(exc.value).startswith(f"remote collection from {SERVER} failed")
    assert leftovers(tmp_path) == []


def test_an_error_with_no_text_still_names_its_type(tmp_path: Path, fake: Remote) -> None:
    fake.error = RuntimeError()
    with pytest.raises(CollectionError, match="failed: RuntimeError"):
        run(tmp_path / "ad.jsonl")


def test_a_collection_error_message_is_redacted_too(tmp_path: Path, fake: Remote) -> None:
    fake.batches = [[f"not json {SECRET}"]]
    with pytest.raises(CollectionError) as exc:
        run(tmp_path / "ad.jsonl")
    assert SECRET not in str(exc.value)


def test_an_existing_file_is_kept_unless_forced(tmp_path: Path, fake: Remote) -> None:
    out = tmp_path / "e.jsonl"
    out.write_text("keep", encoding="utf-8")
    with pytest.raises(CollectionError, match="already exists; pass --force"):
        run(out)
    assert fake.settings == {}  # refused before connecting
    fake.batches = [LINES]
    run(out, force=True)
    assert out.read_bytes() == GOOD


@pytest.mark.usefixtures("fake")
def test_a_file_that_appears_during_collection_is_not_clobbered(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    out = tmp_path / "e.jsonl"
    real = remote._Sink.finish  # noqa: SLF001 - the moment between check and publish

    def appear(sink: Any) -> Any:
        out.write_text("arrived", encoding="utf-8")
        return real(sink)

    monkeypatch.setattr(remote._Sink, "finish", appear)  # noqa: SLF001
    with pytest.raises(CollectionError, match="already exists"):
        run(out)
    assert out.read_text(encoding="utf-8") == "arrived"
    assert leftovers(tmp_path) == []


def no_hard_links(monkeypatch: pytest.MonkeyPatch) -> dict[str, int]:
    """Make ``os.link`` fail as on FAT; the count says how often it was tried."""
    calls = {"link": 0}

    def refuse(*_: object, **__: object) -> None:
        calls["link"] += 1
        raise OSError(errno.EPERM, "Operation not permitted")

    monkeypatch.setattr(os, "link", refuse)
    return calls


@pytest.mark.usefixtures("fake")
def test_a_file_system_without_hard_links_still_gets_a_private_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = no_hard_links(monkeypatch)
    out = tmp_path / "e.jsonl"
    result = run(out)
    assert calls["link"] == 1
    assert (result.path, result.records) == (out, 3)
    assert out.read_bytes() == GOOD
    assert sorted(path.name for path in tmp_path.iterdir()) == ["e.jsonl"]
    if os.name != "nt":
        assert out.stat().st_mode & 0o777 == 0o600


@pytest.mark.usefixtures("fake")
def test_a_failed_copy_removes_the_partly_written_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    no_hard_links(monkeypatch)
    out = tmp_path / "e.jsonl"

    def full(*_: object, **__: object) -> None:
        raise OSError(errno.ENOSPC, "No space left on device")

    monkeypatch.setattr(os, "fsync", full)  # the copy fails after the name exists
    with pytest.raises(CollectionError, match=r"cannot write .*e\.jsonl: No space left"):
        run(out)
    assert not out.exists()
    assert leftovers(tmp_path) == []


@pytest.mark.usefixtures("fake")
def test_a_file_that_appears_when_links_are_unavailable_is_not_clobbered(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    no_hard_links(monkeypatch)
    out = tmp_path / "e.jsonl"
    real = remote._Sink.finish  # noqa: SLF001

    def appear(sink: Any) -> Any:
        out.write_text("arrived", encoding="utf-8")
        return real(sink)

    monkeypatch.setattr(remote._Sink, "finish", appear)  # noqa: SLF001
    with pytest.raises(CollectionError, match="already exists"):
        run(out)
    assert out.read_text(encoding="utf-8") == "arrived"
    assert leftovers(tmp_path) == []


@pytest.mark.skipif(os.name == "nt", reason="symbolic links need privileges on Windows")
def test_a_link_at_the_destination_is_never_followed(tmp_path: Path, fake: Remote) -> None:
    outside = tmp_path / "outside.txt"
    outside.write_text("precious", encoding="utf-8")
    out = tmp_path / "e.jsonl"
    out.symlink_to(outside)
    with pytest.raises(CollectionError, match="already exists"):
        run(out)
    dangling = tmp_path / "d.jsonl"
    dangling.symlink_to(tmp_path / "nowhere")
    with pytest.raises(CollectionError, match="already exists"):
        run(dangling)
    fake.batches = [LINES]
    run(out, force=True)
    assert outside.read_text(encoding="utf-8") == "precious"
    assert not out.is_symlink()
    assert out.read_bytes() == GOOD


@pytest.mark.usefixtures("fake")
def test_an_unwritable_folder_is_reported(tmp_path: Path) -> None:
    with pytest.raises(CollectionError, match="cannot write to"):
        run(tmp_path / "missing" / "e.jsonl")


def test_the_part_file_and_the_result_are_private(tmp_path: Path, fake: Remote) -> None:
    seen: list[int] = []
    real = remote._Sink.finish  # noqa: SLF001

    def look(sink: Any) -> Any:
        seen.append(sink.temp.stat().st_mode & 0o777)
        return real(sink)

    fake.batches = [LINES]
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(remote._Sink, "finish", look)  # noqa: SLF001
        run(tmp_path / "e.jsonl")
    assert seen == [0o600] or os.name == "nt"
    if os.name != "nt":
        assert (tmp_path / "e.jsonl").stat().st_mode & 0o777 == 0o600


def test_a_collection_without_a_secret_still_publishes(tmp_path: Path, fake: Remote) -> None:
    fake.batches = [LINES]
    out = tmp_path / "e.jsonl"
    collect(Target(SERVER, "kerberos"), "s", {}, out, force=False)
    assert fake.settings["username"] is None
    assert fake.settings["password"] is None
    assert out.read_bytes() == GOOD


def test_pypsrp_missing_says_how_to_install_shaar(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setitem(sys.modules, "pypsrp.wsman", None)
    out = tmp_path / "e.jsonl"
    with pytest.raises(CollectionError) as caught:
        run(out)
    # pipx refuses a plain install over an installed shaar, so the pipx form has --force.
    assert str(caught.value).endswith(
        'pipx install --force "faithful-shaar[ad]" (or, with pip, pip install "faithful-shaar[ad]")'
    )
    assert leftovers(tmp_path) == []


# --- write_private -----------------------------------------------------------


def test_write_private_creates_owner_only_and_refuses_to_overwrite(tmp_path: Path) -> None:
    out = tmp_path / "s.ps1"
    remote.write_private(out, b"one", force=False)
    assert out.read_bytes() == b"one"
    if os.name != "nt":
        assert out.stat().st_mode & 0o777 == 0o600
    with pytest.raises(CollectionError, match="already exists; pass --force"):
        remote.write_private(out, b"two", force=False)
    assert out.read_bytes() == b"one"
    remote.write_private(out, b"two", force=True)
    assert out.read_bytes() == b"two"
    assert leftovers(tmp_path) == []


def test_write_private_reports_a_missing_folder(tmp_path: Path) -> None:
    with pytest.raises(CollectionError, match="cannot write to"):
        remote.write_private(tmp_path / "missing" / "s.ps1", b"x", force=False)


# --- the commands -----------------------------------------------------------------------


def invoke(*argv: str) -> int:
    """Run a subcommand the way the main parser will: parse, then call ``run``."""
    parser = argparse.ArgumentParser(prog="shaar")
    commands = parser.add_subparsers(dest="command", required=True)
    ad.add_exporter_arguments(commands)
    collect_parser = commands.add_parser("collect")
    collect_commands = collect_parser.add_subparsers(dest="source", required=True)
    ad.add_collect_ad_arguments(collect_commands)
    args = parser.parse_args(argv)
    code: int = args.run(args)
    return code


def collect_args(out: Path, *extra: str) -> list[str]:
    return ["collect", "ad", "--host", SERVER, "-o", str(out), *extra]


@pytest.fixture
def fetched(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    calls: list[str] = []

    def resolve(reference: str, *, hint: Any, keep: tuple[str, ...] = ()) -> str:
        assert callable(hint)
        assert keep == ("ad",)
        calls.append(reference)
        return SECRET

    monkeypatch.setattr(secrets, "resolve", resolve)
    return calls


@pytest.mark.parametrize(
    ("extra", "error", "problem"),
    [
        (["--privileged", "--host", "10.0.0.5"], CollectionError, "is an IP address"),
        (
            ["--privileged", "--username", "auditor", "--secret", "env:X"],
            CollectionError,
            "must be DOMAIN",
        ),
        ([], UsageError, "give at least one of --group"),
        (["--privileged", "--secret", "env:X"], UsageError, "--secret needs --username"),
        (["--privileged", "--username", "CORP\\auditor"], UsageError, "--username needs --secret"),
        (
            ["--privileged", "--auth", "ntlm"],
            UsageError,
            "--auth ntlm needs --username and --secret",
        ),
        (
            [
                "--privileged",
                "--transport",
                "http",
                "--ca-file",
                "ca.pem",
                "--username",
                "CORP\\a",
                "--secret",
                "env:X",
            ],
            CollectionError,
            "https only",
        ),
    ],
)
def test_collect_checks_everything_before_reading_the_secret(
    tmp_path: Path, fetched: list[str], extra: list[str], error: type[Exception], problem: str
) -> None:
    with pytest.raises(error, match=re.escape(problem)):
        invoke(*collect_args(tmp_path / "e.jsonl", *extra))
    assert fetched == []


def test_collect_runs_and_says_what_to_do_next(
    tmp_path: Path,
    fetched: list[str],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    seen: dict[str, Any] = {}

    def fake_collect(
        target: Target, text: str, values: dict[str, Any], out: Path, *, force: bool
    ) -> remote.Result:
        seen.update(target=target, text=text, values=values, force=force)
        return remote.Result(
            out, 12, ("members of group x: Access\x1b[31m is denied.",), ("Locked",)
        )

    monkeypatch.setattr(remote, "collect", fake_collect)
    out = tmp_path / "my ad.jsonl"
    args = collect_args(
        out, "--username", "auditor@corp.example", "--secret", "env:PW",
        "--group", "Finance Approvers", "Dup", "--group", "More",
        "--search-base", "OU=Groups,DC=corp,DC=example", "--privileged",
        "--timeout", "90", "--port", "443", "--force",
    )  # fmt: skip
    assert invoke(*args) == 0
    assert fetched == ["env:PW"]
    target = seen["target"]
    assert (target.username, target.secret, target.idle_timeout, target.port) == (
        "corp.example\\auditor", SECRET, 90, 443,
    )  # fmt: skip
    assert seen["text"] == script.text()
    assert seen["force"] is True
    assert seen["values"] == {
        "ToPipeline": True,
        "Group": ["Finance Approvers", "Dup", "More"],
        "SearchBase": "OU=Groups,DC=corp,DC=example",
        "Privileged": True,
        "Server": SERVER,
    }
    printed = capsys.readouterr().out
    assert f"Exported 12 records from {SERVER}" in printed
    assert "incomplete: Locked" in printed
    assert "not read: members of group x: Access\\u001b[31m is denied." in printed
    assert "\x1b" not in printed
    assert "shaar campaign" in printed
    assert SECRET not in printed


def test_collect_output_never_shows_a_resolved_secret(
    tmp_path: Path,
    fetched: list[str],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def fake_collect(*_: Any, **__: Any) -> remote.Result:
        secrets.remember(SECRET)
        return remote.Result(tmp_path, 1, (f"what: {SECRET}",))

    monkeypatch.setattr(remote, "collect", fake_collect)
    invoke(
        *collect_args(
            tmp_path / "e.jsonl", "--privileged", "--username", "CORP\\a", "--secret", "env:PW"
        )
    )
    assert fetched == ["env:PW"]
    assert SECRET not in capsys.readouterr().out


def test_collect_with_the_current_kerberos_ticket(
    tmp_path: Path, fetched: list[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[tuple[Target, dict[str, Any]]] = []

    def record(
        target: Target, _: str, values: dict[str, Any], *__: object, **___: object
    ) -> remote.Result:
        calls.append((target, values))
        return remote.Result(tmp_path, 0, ())

    monkeypatch.setattr(remote, "collect", record)
    assert invoke(*collect_args(tmp_path / "e.jsonl", "--privileged")) == 0
    target, values = calls[0]
    assert (target.username, target.secret, fetched) == (None, None, [])
    assert values == {"ToPipeline": True, "Privileged": True, "Server": SERVER}


@pytest.mark.parametrize(
    "extra",
    [
        ["--group", ""],
        ["--group", "bad\nname"],
        ["--search-base", "not a dn"],
        ["--search-base", "OU=x\n,DC=y"],
        ["--privileged", "--timeout", "0"],
        ["--privileged", "--timeout", "x"],
        ["--privileged", "--port", "70000"],
        ["--privileged", "--auth", "basic"],
        ["--privileged", "--transport", "ftp"],
    ],
)
def test_collect_option_values_are_checked(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], extra: list[str]
) -> None:
    with pytest.raises(SystemExit) as exc:
        invoke(*collect_args(tmp_path / "e.jsonl", *extra))
    assert exc.value.code == 2
    assert capsys.readouterr().err


def test_collect_requires_a_host_and_an_output() -> None:
    with pytest.raises(SystemExit) as exc:
        invoke("collect", "ad", "--privileged")
    assert exc.value.code == 2


def test_collect_end_to_end_through_the_stand_in(
    tmp_path: Path, fake: Remote, capsys: pytest.CaptureFixture[str]
) -> None:
    fake.batches = [LINES]
    out = tmp_path / "ad.jsonl"
    assert invoke(*collect_args(out, "--group", "Tier0 Admins")) == 0
    assert out.read_bytes() == GOOD
    assert fake.parameters == {"ToPipeline": True, "Group": ["Tier0 Admins"], "Server": SERVER}
    assert "Exported 3 records" in capsys.readouterr().out


def test_a_missing_secret_provider_package_says_how_to_install_shaar(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setitem(sys.modules, "keyring", None)
    args = collect_args(
        tmp_path / "e.jsonl", "--privileged", "--username", "CORP\\auditor",
        "--secret", "keyring:svc/auditor",
    )  # fmt: skip
    with pytest.raises(CollectionError) as caught:
        invoke(*args)
    # The hint keeps the extra remote collection needs, or pipx --force would drop it.
    assert 'pipx install --force "faithful-shaar[ad,keyring]"' in str(caught.value)


def test_exporter_writes_the_script_into_the_directory(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    target = tmp_path / "tools" / "nested"
    assert invoke("exporter", str(target)) == 0
    written = target / script.NAME
    assert written.read_text(encoding="ascii") == script.text()
    if os.name != "nt":
        assert written.stat().st_mode & 0o777 == 0o600
    assert f".\\{script.NAME} -Privileged -OutFile" in capsys.readouterr().out
    with pytest.raises(ShaarError, match="exist"):
        invoke("exporter", str(target))
    written.write_text("changed", encoding="ascii")
    assert invoke("exporter", str(target), "--force") == 0
    assert written.read_text(encoding="ascii") == script.text()


def test_exporter_reports_a_directory_that_cannot_be_made(tmp_path: Path) -> None:
    blocker = tmp_path / "file"
    blocker.write_text("x", encoding="utf-8")
    with pytest.raises(CollectionError, match="cannot create"):
        invoke("exporter", str(blocker / "sub"))


def test_terminal_escapes_control_characters_and_removes_secrets() -> None:
    secrets.remember(SECRET)
    assert ad.terminal(f"a\x00b\x9fc {SECRET}") == "a\\u0000b\\u009fc [redacted]"


def test_the_exporter_messages_keep_a_line_break_in_a_name_off_the_terminal() -> None:
    """The collectors' own escapers already show a line feed as text, so a gap is one line."""
    from faithful_shaar.collect import entra  # noqa: PLC0415

    assert "\n" not in ad.terminal("members of group x\nExported 0 records from y.")
    assert "\n" not in entra._terminal("group x\nread 0 grants")  # noqa: SLF001
