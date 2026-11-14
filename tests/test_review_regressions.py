# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""Counterexamples from the PR #5 review, run through the command line end to end."""

from __future__ import annotations

import hashlib
import io
import json
import shutil
import zipfile
from typing import TYPE_CHECKING, Any

import pytest

from faithful_shaar import example
from faithful_shaar.cli import ExitCode, main

if TYPE_CHECKING:
    from pathlib import Path


@pytest.fixture(scope="module")
def sample(tmp_path_factory: pytest.TempPathFactory) -> Path:
    root = tmp_path_factory.mktemp("example")
    assert main(["example", str(root / "ex")]) == ExitCode.OK
    return root / "ex"


def campaign_argv(sample: Path, out: Path, *more: str) -> list[str]:
    before = sample / "before"
    return [
        "campaign",
        str(before / "ad.jsonl"),
        str(before / "entra.jsonl"),
        str(before / "ledger.csv"),
        "--map",
        str(before / "ledger-map.toml"),
        "--name",
        example.NAME,
        "--due",
        example.DUE,
        "-o",
        str(out),
        *more,
    ]


def verify(sample: Path, out: Path, after: list[Path], ledger_map: Path) -> dict[str, str]:
    """Run verify on the example's decisions; return each removal's result by user."""
    code = main(
        [
            "verify",
            str(sample / "campaign"),
            str(decisions(sample, out.parent)),
            *map(str, after),
            "--map",
            str(ledger_map),
            "-o",
            str(out),
        ]
    )
    assert code in {ExitCode.OK, ExitCode.FINDINGS}
    data: dict[str, Any] = json.loads((out / "verify-report.json").read_text("utf-8"))
    return {
        f"{row['principal']}|{row['resource']}": row["result"]
        for row in data["sections"]["removals"]
    }


def decisions(sample: Path, root: Path) -> Path:
    out = root / "decisions"
    if not out.exists():
        returned = sorted(str(p) for p in (sample / "returned").glob("*.xlsx"))
        assert main(["decisions", str(sample / "campaign"), *returned, "-o", str(out)]) in {
            ExitCode.OK,
            ExitCode.FINDINGS,
        }
    return out


def after_set(sample: Path) -> list[Path]:
    after = sample / "after"
    return [after / "ad.jsonl", after / "entra.jsonl", after / "ledger.csv"]


def test_the_example_verifies_as_documented(sample: Path, tmp_path: Path) -> None:
    results = verify(
        sample, tmp_path / "v", after_set(sample), sample / "after" / "ledger-map.toml"
    )
    assert sorted(results.values()) == ["failed", "removed", "removed", "unknown", "unknown"]
    assert any(k.endswith("|Ledger") and v == "removed" for k, v in results.items())


def test_f03_an_undated_csv_cannot_prove_a_removal(sample: Path, tmp_path: Path) -> None:
    # The ledger export's map gives no time: the export could predate the campaign.
    text = (sample / "after" / "ledger-map.toml").read_text("utf-8")
    undated = tmp_path / "undated.toml"
    undated.write_text(
        "\n".join(line for line in text.splitlines() if not line.startswith("collected_at")),
        "utf-8",
    )
    results = verify(sample, tmp_path / "v", after_set(sample), undated)
    ledger = [v for k, v in results.items() if k.endswith("|Ledger")]
    assert ledger == ["unknown"]
    # the dated exports still prove their own removals
    assert "removed" in results.values()


def entra_after(sample: Path, folder: Path, tenant: str) -> Path:
    """The example's later Entra export, read in full, from ``tenant``."""
    lines = (sample / "after" / "entra.jsonl").read_text("utf-8").splitlines()
    header = json.loads(lines[0])
    header["tenant"] = tenant
    body = [json.dumps(header), *lines[1:-1]]
    body = [line.replace('"complete": false', '"complete": true') for line in body]
    text = "".join(f"{line}\n" for line in body)
    trailer = json.loads(lines[-1])
    trailer["sha256"] = hashlib.sha256(text.encode("utf-8")).hexdigest()
    path = folder / "entra.jsonl"
    # bytes, not text: on Windows text mode would write CRLF and break the trailer hash
    path.write_bytes((text + json.dumps(trailer) + "\n").encode("utf-8"))
    return path


def test_f02_an_export_from_another_tenant_proves_nothing(sample: Path, tmp_path: Path) -> None:
    after = after_set(sample)
    ledger_map = sample / "after" / "ledger-map.toml"
    same = tmp_path / "same"
    same.mkdir()
    control = entra_after(sample, same, example.TENANT)
    results = verify(sample, tmp_path / "v1", [after[0], control, after[2]], ledger_map)
    payroll = [v for k, v in results.items() if k.endswith("|Payroll App Users")]
    assert payroll == ["removed", "removed"]  # the same tenant, read in full: proven
    other = tmp_path / "other"
    other.mkdir()
    foreign = entra_after(sample, other, "11111111-1111-4111-8111-111111111111")
    results = verify(sample, tmp_path / "v2", [after[0], foreign, after[2]], ledger_map)
    payroll = [v for k, v in results.items() if k.endswith("|Payroll App Users")]
    assert payroll == ["unknown", "unknown"]


def test_f07_a_separator_in_a_name_cannot_merge_two_rows(tmp_path: Path) -> None:
    table = tmp_path / "app.csv"
    table.write_text(
        "user,group\nA|B,C\nA,B|C\n",
        "utf-8",
    )
    cmap = tmp_path / "map.toml"
    cmap.write_text(
        'system = "app"\ncollected_at = "2026-11-01T00:00:00Z"\n'
        '[columns]\nprincipal_name = "user"\nresource_name = "group"\n',
        "utf-8",
    )
    out = tmp_path / "c"
    code = main(
        [
            "campaign",
            str(table),
            "--map",
            str(cmap),
            "--name",
            "Pipes",
            "--due",
            "2026-12-01",
            "--reviewers",
            "owner",
            "-o",
            str(out),
        ]
    )
    assert code == ExitCode.FINDINGS  # nobody owns these: both rows are unassigned
    data = json.loads((out / "campaign.json").read_text("utf-8"))
    keys = [u["grant_key"] for u in data["unassigned"]]
    assert len(keys) == 2
    assert len(set(keys)) == 2


@pytest.mark.parametrize(
    ("text", "said"),
    [
        (
            "resource,reviewer_id,reviewer_id,reviewer_name\nTier0 Admins,expected,unexpected,N\n",
            "more than one 'reviewer_id' column",
        ),
        (
            "resource,Reviewer_ID , reviewer_id,reviewer_name\nTier0 Admins,a,b,N\n",
            "more than one 'reviewer_id' column",
        ),
        ("resource,reviewer_id,reviewer_name\nTier0 Admins,a,N,extra\n", "has 4 cells"),
        ("resource,reviewer_id,reviewer_name\nTier0 Admins," + "x" * 200_000 + ",N\n", "as CSV"),
    ],
)
def test_f14_an_ambiguous_reviewer_map_publishes_nothing(
    sample: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str], text: str, said: str
) -> None:
    reviewer_map = tmp_path / "map.csv"
    reviewer_map.write_text(text, "utf-8")
    out = tmp_path / "c"
    argv = campaign_argv(sample, out, "--reviewers", "map", "--reviewer-map", str(reviewer_map))
    assert main(argv) == ExitCode.INPUT_ERROR
    assert said in capsys.readouterr().err
    assert not out.exists() or not any(out.iterdir())


def test_a_non_text_encoding_in_a_column_map_is_an_input_error(
    sample: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    cmap = tmp_path / "map.toml"
    cmap.write_text(
        (sample / "before" / "ledger-map.toml").read_text("utf-8")
        + '\nencoding = "base64_codec"\n',
        "utf-8",
    )
    # TOML keys after a table belong to it, so put the setting at the top instead
    lines = cmap.read_text("utf-8").splitlines()
    lines = ['encoding = "base64_codec"', *lines[:-1]]
    cmap.write_text("\n".join(lines) + "\n", "utf-8")
    argv = campaign_argv(sample, tmp_path / "c", "--reviewers", "manager")
    argv[argv.index("--map") + 1] = str(cmap)
    assert main(argv) == ExitCode.INPUT_ERROR
    assert "encoding" in capsys.readouterr().err


def bad_name_zip() -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("é.xml", b"<x/>")
    # make the UTF-8 flagged name invalid UTF-8 in both headers
    return buffer.getvalue().replace("é".encode(), b"\xff\xa9")


def test_a_returned_file_with_an_undecodable_entry_name_is_unreadable_not_fatal(
    sample: Path, tmp_path: Path
) -> None:
    returned = sorted((sample / "returned").glob("*.xlsx"))
    bad = tmp_path / "bad.xlsx"
    bad.write_bytes(bad_name_zip())
    with pytest.raises(UnicodeDecodeError):
        zipfile.ZipFile(io.BytesIO(bad.read_bytes()))  # what the reader must survive
    out = tmp_path / "d"
    code = main(
        ["decisions", str(sample / "campaign"), *map(str, returned), str(bad), "-o", str(out)]
    )
    assert code == ExitCode.FINDINGS
    data = json.loads((out / "decisions.json").read_text("utf-8"))
    status = {p["file"]: p["status"] for p in data["packets"]}
    assert status["bad.xlsx"] == "unreadable"
    assert sum(s == "read" for s in status.values()) == len(returned)


def test_f13_a_forced_rebuild_leaves_no_packet_of_the_earlier_run(
    sample: Path, tmp_path: Path
) -> None:
    out = tmp_path / "c"
    assert main(campaign_argv(sample, out, "--reviewers", "manager")) == ExitCode.FINDINGS
    earlier = sorted(p.name for p in out.glob("packet-*.xlsx"))
    stale = out / "packet-09-Someone-000000.xlsx"
    shutil.copy(out / earlier[0], stale)
    manifest = json.loads((out / "manifest.json").read_text("utf-8"))
    manifest["files"].append({"name": stale.name, "size": 0, "sha256": "0" * 64})
    (out / "manifest.json").write_text(json.dumps(manifest), "utf-8")
    argv = campaign_argv(sample, out, "--reviewers", "manager", "--force")
    assert main(argv) == ExitCode.FINDINGS
    assert sorted(p.name for p in out.glob("packet-*.xlsx")) == earlier


# --- Routine round 1 (R1-R3) --------------------------------------------------------

CAMPAIGN_EPOCH = "1793577600"  # 2026-11-02T00:00:00Z
REVIEWER_MAP = (
    "resource,reviewer_id,reviewer_name,reviewer_email\n"
    "Finance Admins,rita,Rita Reviewer,rita@corp.example\n"
)


def full_review(  # noqa: PLR0913 - the parts of one review
    tmp: Path,
    before: list[Path],
    after: list[Path],
    remove: list[str],
    *,
    before_args: tuple[str, ...] = (),
    after_args: tuple[str, ...] = (),
) -> dict[str, str]:
    """Campaign from ``before``, Remove for each user in ``remove``, verify on ``after``."""
    from faithful_shaar import campaign as cmod  # noqa: PLC0415

    reviewer_map = tmp / "reviewers.csv"
    reviewer_map.write_text(REVIEWER_MAP, "utf-8")
    camp = tmp / "campaign"
    argv = [
        "campaign",
        *map(str, before),
        *before_args,
        "--name",
        "Round one",
        "--due",
        "2026-11-30",
        "--reviewers",
        "map",
        "--reviewer-map",
        str(reviewer_map),
        "-o",
        str(camp),
    ]
    assert main(argv) == ExitCode.OK
    made = cmod.load((camp / "campaign.json").read_bytes())
    chosen = {(r.display["user"], r.display["resource"]): ("Keep", "") for r in made.rows}
    for row in made.rows:
        if row.display["user"] in remove:
            chosen[(row.display["user"], row.display["resource"])] = ("Remove", "Gone")
    returned = tmp / "returned"
    returned.mkdir()
    for name, data in example.fill_packets(made, chosen).items():
        (returned / name).write_bytes(data)
    out = tmp / "decisions"
    packets = sorted(map(str, returned.glob("*.xlsx")))
    assert main(["decisions", str(camp), *packets, "-o", str(out)]) == ExitCode.OK
    verified = tmp / "verification"
    argv = ["verify", str(camp), str(out), *map(str, after), *after_args, "-o", str(verified)]
    assert main(argv) in {ExitCode.OK, ExitCode.FINDINGS}
    data = json.loads((verified / "verify-report.json").read_text("utf-8"))
    return {row["principal"]: row["result"] for row in data["sections"]["removals"]}


def csv_map(tmp: Path, name: str, at: str) -> Path:
    path = tmp / name
    path.write_text(
        f'system = "app"\nresource = "Finance Admins"\ncollected_at = "{at}"\n'
        '[columns]\nprincipal_id = "user"\n',
        "utf-8",
    )
    return path


@pytest.mark.parametrize(
    ("later", "result"),
    [
        # a stray quote before charlie, never closed: alice's row must not vanish unseen
        ('user\nbob\n"charlie\nalice\n', "unknown"),
        # text after a closing quote
        ('user\nbob\n"charlie"x\n', "unknown"),
        # a valid quoted cell over two lines still reads, and alice is really gone
        ('user,note\nbob,"two\nlines"\ncharlie,x\n', "removed"),
    ],
)
def test_r1_malformed_csv_quoting_never_proves_a_removal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, later: str, result: str
) -> None:
    monkeypatch.setenv("SOURCE_DATE_EPOCH", CAMPAIGN_EPOCH)
    first = tmp_path / "before.csv"
    first.write_text("user\nbob\ncharlie\nalice\n", "utf-8")
    second = tmp_path / "after.csv"
    second.write_bytes(later.encode("utf-8"))  # bytes: keep LF line ends on Windows
    results = full_review(
        tmp_path,
        [first],
        [second],
        ["alice"],
        before_args=("--map", str(csv_map(tmp_path, "b.toml", "2026-11-01T00:00:00Z"))),
        after_args=("--map", str(csv_map(tmp_path, "a.toml", "2026-11-20T00:00:00Z"))),
    )
    assert results == {"alice": result}


def entra_bytes(records: list[dict[str, Any]], at: str) -> bytes:
    from tests.fixtures_access import export_bytes  # noqa: PLC0415

    return export_bytes(records, system="entra", header={"collected_at": at})


@pytest.mark.parametrize("role_first", [False, True])
def test_r3_one_raw_id_as_two_resources_proves_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, role_first: bool
) -> None:
    from tests.fixtures_access import grant, guid, principal, resource  # noqa: PLC0415

    monkeypatch.setenv("SOURCE_DATE_EPOCH", CAMPAIGN_EPOCH)
    group, alice = guid(900), guid(1)
    people = [principal(alice, "alice"), principal(guid(2), "bob")]
    first = tmp_path / "before.jsonl"
    first.write_bytes(
        entra_bytes(
            [
                *people,
                resource(group, "Finance Admins"),
                grant(alice, group),
                grant(guid(2), group),
            ],
            "2026-11-01T00:00:00Z",
        )
    )
    both = [resource(group, "Finance Admins"), resource(group, "Finance Admins", kind="role")]
    later = [
        *people,
        *(both[::-1] if role_first else both),
        grant(alice, group),
        grant(guid(2), group),
    ]
    second = tmp_path / "after.jsonl"
    second.write_bytes(entra_bytes(later, "2026-11-20T00:00:00Z"))
    results = full_review(tmp_path, [first], [second], ["alice"])
    # The grant goes to whichever record came first: still there (pending), or under the
    # role, where the group is not read in full (unknown). Never removed.
    assert results == {"alice": "unknown" if role_first else "pending"}


@pytest.mark.parametrize(
    "rows",
    [
        # GPT's example: one id, the second row naming Avery, who holds the finance access
        [
            "finance,owner,Finance Reviewer,finance@corp.example",
            "payroll,owner,Avery Reviewer,avery@corp.example",
        ],
        # the same in reverse order
        [
            "payroll,owner,Avery Reviewer,avery@corp.example",
            "finance,owner,Finance Reviewer,finance@corp.example",
        ],
        # unrelated people sharing an id
        [
            "finance,owner,Casey One,casey@corp.example",
            "payroll,owner,Dana Two,dana@corp.example",
        ],
        # one with an email, one without
        ["finance,owner,Casey One,casey@corp.example", "payroll,owner,Casey One,"],
    ],
)
def test_r2_one_reviewer_id_for_two_people_is_refused(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], rows: list[str]
) -> None:
    table = tmp_path / "access.csv"
    table.write_text(
        "system,principal_id,email,resource_id\n"
        "app,avery,avery@corp.example,finance\n"
        "app,blake,blake@corp.example,payroll\n",
        "utf-8",
    )
    reviewer_map = tmp_path / "map.csv"
    reviewer_map.write_text(
        "resource,reviewer_id,reviewer_name,reviewer_email\n" + "\n".join(rows) + "\n", "utf-8"
    )
    out = tmp_path / "c"
    argv = [
        "campaign",
        str(table),
        "--preset",
        "generic",
        "--name",
        "Ids",
        "--due",
        "2026-12-01",
        "--reviewers",
        "map",
        "--reviewer-map",
        str(reviewer_map),
        "-o",
        str(out),
    ]
    assert main(argv) == ExitCode.INPUT_ERROR
    assert "rows 2 and 3 give reviewer_id 'owner'" in capsys.readouterr().err
    assert not out.exists() or not any(out.iterdir())


def test_r2_the_same_person_on_several_rows_is_fine(tmp_path: Path) -> None:
    from faithful_shaar.assign import read_map  # noqa: PLC0415

    reviewer_map = tmp_path / "map.csv"
    reviewer_map.write_text(
        "resource,reviewer_id,reviewer_name,reviewer_email\n"
        "finance,owner,Finance  Reviewer,Finance@corp.example\n"
        "payroll,OWNER,finance reviewer,finance@corp.example\n",
        "utf-8",
    )
    assert len({e.reviewer.key for e in read_map(reviewer_map)}) == 1


def test_r2_build_refuses_one_key_with_two_emails(monkeypatch: pytest.MonkeyPatch) -> None:
    # A guard behind the map check: no rule may put two people's rows in one packet.
    from faithful_shaar import campaign as cmod  # noqa: PLC0415
    from faithful_shaar.assign import Assignment, Reviewer  # noqa: PLC0415
    from faithful_shaar.errors import InputError  # noqa: PLC0415
    from tests.core_fixtures import standard  # noqa: PLC0415

    snap, _ = standard()
    people = iter(
        [Reviewer("k", "One", "one@corp.example"), Reviewer("k", "Two", "two@corp.example")] * 9
    )
    monkeypatch.setattr(cmod, "assign", lambda *_a, **_k: Assignment(next(people)))
    with pytest.raises(InputError, match="is both"):
        cmod.build(snap, name="x", created_at="2026-11-01T00:00:00Z", due="", rule="manager")


# --- Routine round 2 (S1) -----------------------------------------------------------


def quoted_csv(delimiter: str, *, quote_all: bool) -> bytes:
    import csv  # noqa: PLC0415

    buffer = io.StringIO(newline="")
    if quote_all:
        writer = csv.writer(buffer, delimiter=delimiter, quoting=csv.QUOTE_ALL, lineterminator="\n")
    else:
        writer = csv.writer(buffer, delimiter=delimiter, lineterminator="\n")
    writer.writerows([["user", "resource"], ["alice", "admins"]])
    return buffer.getvalue().encode("utf-8")


@pytest.mark.parametrize("delimiter", [",", ";", "\t", "|"])
@pytest.mark.parametrize("how", ["quoted, inferred", "plain, inferred", "quoted, given"])
def test_s1_a_quoted_header_is_read_with_any_supported_delimiter(
    tmp_path: Path, delimiter: str, how: str
) -> None:
    table = tmp_path / "access.csv"
    table.write_bytes(quoted_csv(delimiter, quote_all=how.startswith("quoted")))
    given = f"delimiter = {json.dumps(delimiter)}\n" if how.endswith("given") else ""
    cmap = tmp_path / "map.toml"
    cmap.write_text(
        f'system = "app"\n{given}[columns]\nprincipal_id = "user"\nresource_id = "resource"\n',
        "utf-8",
    )
    reviewer_map = tmp_path / "reviewers.csv"
    reviewer_map.write_text("resource,reviewer_id,reviewer_name\nadmins,rita,Rita\n", "utf-8")
    out = tmp_path / "c"
    argv = [
        "campaign",
        str(table),
        "--map",
        str(cmap),
        "--name",
        "Quoted",
        "--due",
        "2026-12-01",
        "--reviewers",
        "map",
        "--reviewer-map",
        str(reviewer_map),
        "-o",
        str(out),
    ]
    assert main(argv) == ExitCode.OK
    data = json.loads((out / "campaign.json").read_text("utf-8"))
    assert [(r["display"]["user"], r["display"]["resource"]) for r in data["rows"]] == [
        ("alice", "admins")
    ]
    assert len(list(out.glob("packet-*.xlsx"))) == 1


def test_s1_a_header_no_delimiter_can_read_is_still_an_input_error() -> None:
    from faithful_shaar.errors import InputError  # noqa: PLC0415
    from faithful_shaar.inputs.csvread import sniff  # noqa: PLC0415

    with pytest.raises(InputError, match="header cannot be read"):
        sniff('"user"x,"resource"\n', "", "bad.csv")
