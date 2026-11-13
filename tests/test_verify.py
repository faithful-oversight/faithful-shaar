# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""Verifying removals: removed only with evidence, otherwise pending, failed or unknown."""

from __future__ import annotations

import dataclasses

import pytest

from faithful_shaar import keys
from faithful_shaar.campaign import Campaign, digest
from faithful_shaar.decide import DecisionRecord, read_decisions
from faithful_shaar.errors import InputError
from faithful_shaar.model import Grant, Resource, Snapshot, Source
from faithful_shaar.verify import Verification, verify
from tests.core_fixtures import (
    grant,
    people,
    reader,
    resources,
    returned,
    sid,
    snapshot,
    standard,
)

AFTER = "2026-11-10T12:00:00Z"  # after the campaign began, before it was due
DECIDE = {
    "Avery Example|Finance Admins": "Remove",
    "Blake Sample|Finance Admins": "Keep",
    "Blake Sample|Payroll Viewers": "Remove",
    "Avery Example|Server Ops": "Keep",
}


def decided() -> tuple[Campaign, DecisionRecord]:
    _, camp = standard()
    record = read_decisions(
        camp,
        [("m.xlsx", b"")],
        read=reader({"m.xlsx": returned(camp, 1101, DECIDE)}),
        created_at="x",
    )
    return camp, record


def later(grants: list[Grant], **kw: object) -> Snapshot:
    kw.setdefault("collected_at", AFTER)
    return snapshot(people(), resources(), grants, label="after", **kw)


def results(outcome: Verification) -> list[tuple[str, str]]:
    return [(c.result, c.reason) for c in outcome.checks]


def test_removed_when_the_whole_membership_was_read() -> None:
    camp, record = decided()
    outcome = verify(camp, record, later([grant(1102, 2002, via=("Server Ops", "Ops Helpers"))]))
    assert [c.result for c in outcome.checks] == ["removed", "removed"]
    assert (
        "the principal is disabled" in outcome.checks[1].reason
        or "disabled" in outcome.checks[0].reason
    )
    assert outcome.complete
    assert outcome.as_of == AFTER


def test_still_present_is_pending_before_the_due_date_and_failed_after() -> None:
    camp, record = decided()
    before_due = verify(camp, record, later([grant(1102, 2001), grant(1103, 2003)]))
    assert {c.result for c in before_due.checks} == {"pending"}
    assert "before the due date 2026-11-15" in before_due.checks[0].reason
    after_due = verify(camp, record, later([grant(1102, 2001)]), as_of="2026-11-15T00:00:00Z")
    assert [c.result for c in after_due.checks] == ["failed", "removed"]
    assert not after_due.complete
    undated = verify(camp, record, later([grant(1102, 2001)], collected_at=""))
    assert "does not say when it was taken" in undated.checks[0].reason
    no_due = dataclasses.replace(camp, due="")
    no_due.digest = digest(no_due)
    record_for = dataclasses.replace(record, campaign_digest=no_due.digest)
    assert (
        "has no due date" in verify(no_due, record_for, later([grant(1102, 2001)])).checks[0].reason
    )


def test_unknown_without_evidence() -> None:
    camp, record = decided()
    partial = verify(camp, record, later([], incomplete=[2001, 2003]))
    assert {r for r, _ in results(partial)} == {"unknown"}
    assert "did not read this resource's whole membership" in partial.checks[0].reason
    missing = snapshot(people(), [], [], label="after")
    assert "does not include this resource" in verify(camp, record, missing).checks[0].reason
    other = snapshot([], [], [], label="after")
    other.systems = {"entra"}
    other.resources = {
        keys.entra("00000000-0000-4000-8000-000000000001"): Resource(
            keys.entra("00000000-0000-4000-8000-000000000001"), "entra", "x", "Entra group"
        )
    }
    assert "not of the system" in verify(camp, record, other).checks[0].reason


def test_a_removed_principal_is_noted() -> None:
    camp, record = decided()
    gone = snapshot(
        [p for p in people() if p.key != sid(1102)],
        resources(),
        [],
        label="after",
        collected_at=AFTER,
    )
    reason = verify(camp, record, gone).checks[0].reason
    assert "the principal's key is not in the later export" in reason


def test_information_lists() -> None:
    camp, record = decided()
    newcomer = grant(1106, 2001)
    outcome = verify(camp, record, later([newcomer, grant(1105, 2002), grant(1101, 2002)]))
    assert [n.grant_key for n in outcome.new_since_review] == [newcomer.key]
    assert [n.detail for n in outcome.kept_but_gone] == [
        "kept, but no longer present",
        "kept, but no longer present",
    ]
    assert {n.grant_key for n in outcome.kept_but_gone} == {
        grant(1103, 2001).key,
        grant(1102, 2002).key,
    }


def test_a_record_for_another_campaign_is_refused() -> None:
    camp, record = decided()
    with pytest.raises(InputError, match="does not match this campaign"):
        verify(camp, dataclasses.replace(record, campaign_digest="0" * 64), later([]))


def test_nesting_changes_do_not_matter() -> None:
    camp, record = decided()
    moved = Grant(
        grant(1102, 2001).key,
        "ad",
        sid(1102),
        sid(2001),
        "member",
        ("Finance Admins", "New Path"),
        Source("after.jsonl"),
    )
    outcome = verify(camp, record, later([moved, grant(1103, 2003)]))
    assert [c.result for c in outcome.checks] == ["pending", "pending"]


def test_absence_proves_nothing_from_an_undated_or_earlier_export() -> None:
    camp, record = decided()
    undated = verify(camp, record, later([], collected_at=""))
    assert {c.reason for c in undated.checks} == {
        "the later export does not say when it was read; give --as-of"
    }
    stale = verify(camp, record, later([], collected_at="2000-01-01T00:00:00Z"))
    assert {c.reason for c in stale.checks} == {
        "the later export was read before the campaign began"
    }
    naive = verify(camp, record, later([], collected_at="2026-11-10T12:00:00"))  # taken as UTC
    assert {c.result for c in naive.checks} == {"removed"}
    garbled = verify(camp, record, later([], collected_at="not a time"))
    assert {c.result for c in garbled.checks} == {"unknown"}
    dated = verify(camp, record, later([], collected_at=""), as_of=AFTER)
    assert {c.result for c in dated.checks} == {"removed"}


def test_the_due_date_is_judged_in_utc() -> None:
    camp, record = decided()
    # 23:30 on the 14th in UTC-5 is 04:30 UTC on the 15th: the due date, so not pending.
    late = verify(
        camp, record, later([grant(1102, 2001)], collected_at="2026-11-14T23:30:00-05:00")
    )
    assert late.checks[0].result == "failed"
    assert "on 2026-11-15" in late.checks[0].reason


def test_a_changed_key_is_not_a_removal() -> None:
    camp, record = decided()
    avery = next(p for p in people() if p.key == sid(1102))
    rekeyed = dataclasses.replace(avery, key=keys.dn("cn=avery,dc=corp,dc=example"), id="cn=avery")
    moved = Grant(
        keys.grant(sid(2001), rekeyed.key, "member"), "ad", rekeyed.key, sid(2001), "member"
    )
    snap = later([grant(1103, 2001), moved, grant(1103, 2003)])
    snap.principals[rekeyed.key] = rekeyed
    check = verify(camp, record, snap).checks[0]
    assert (check.result, check.reason) == (
        "unknown",
        "the same account still holds this access under another key (Avery Example)",
    )
