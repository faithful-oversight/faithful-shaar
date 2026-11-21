# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""Checking a later export against the decisions: was each removal actually made?

For every accepted Remove decision the result is one of:

- ``removed``: the later export read the resource's whole membership and the grant is
  not there.
- ``pending``: the grant is still there, and the export was taken before the campaign's
  due date.
- ``failed``: the grant is still there on or after the due date (or the campaign has no
  due date).
- ``unknown``: the later export cannot show it: the resource is missing from the export,
  its membership was not read in full, the export is of another system, or it has no
  entitlement column (every grant in it reads as ``member``) and the removal is of another
  entitlement.

Two further lists are information, not failures: kept access that has gone anyway, and
access on the reviewed resources that was not part of the review.

Removals are only part of a review. When the decision record is not complete (entries
without an accepted decision, Unsure answers, packets never returned, or input the
campaign could not read), the verification says so and does not count as complete, however
many of the removals that were decided have been made.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from faithful_shaar import decide
from faithful_shaar.errors import InputError
from faithful_shaar.keys import entitlement_of, identity, system_of

if TYPE_CHECKING:
    from faithful_shaar.campaign import Campaign, Row
    from faithful_shaar.decide import DecisionRecord
    from faithful_shaar.model import Snapshot

RESULTS = ("removed", "pending", "failed", "unknown")


@dataclass(frozen=True)
class Check:
    """The result for one Remove decision."""

    row_id: str
    grant_key: str
    result: str
    reason: str
    citation: str = ""


@dataclass(frozen=True)
class Note:
    """A grant worth knowing about that is not a removal result."""

    row_id: str
    grant_key: str
    citation: str
    detail: str = ""


@dataclass
class Verification:
    """The outcome of checking a later export against a decision record."""

    campaign_id: str
    as_of: str
    checks: list[Check]
    kept_but_gone: list[Note]
    new_since_review: list[Note]
    record_gaps: list[str] = field(default_factory=list)

    @property
    def removals_made(self) -> bool:
        """Whether every accepted removal was verified as made."""
        return all(check.result == "removed" for check in self.checks)

    @property
    def complete(self) -> bool:
        """Whether every removal was verified as made and the decision record is complete."""
        return self.removals_made and not self.record_gaps


def _check_record(campaign: Campaign, record: DecisionRecord) -> None:
    if record.campaign_id != campaign.id or record.campaign_digest != campaign.digest:
        msg = (
            f"the decision record is for campaign {record.campaign_id}, which does not match "
            f"this campaign ({campaign.id}) as written"
        )
        raise InputError(msg)


def _instant(text: str) -> datetime | None:
    """Return an ISO 8601 time as a UTC instant, or ``None`` when it is not one."""
    try:
        moment = datetime.fromisoformat(text.strip())
    except ValueError:
        return None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=UTC)
    return moment.astimezone(UTC)


def _date(text: str) -> str:
    """Return the UTC calendar date of an ISO 8601 time (``YYYY-MM-DD``), or ``""``."""
    moment = _instant(text)
    return moment.date().isoformat() if moment else ""


def _still_there(campaign: Campaign, as_of: str) -> tuple[str, str]:
    due = campaign.due
    taken = _date(as_of)
    if due and taken and taken < due:
        return "pending", f"still present on {taken}, before the due date {due}"
    if due and taken:
        return "failed", f"still present on {taken}, on or after the due date {due}"
    if due:
        return (
            "failed",
            f"still present; the later export does not say when it was taken (due {due})",
        )
    return "failed", "still present; the campaign has no due date"


Holders = dict[tuple[str, str], dict[str, str]]
"""For each (resource key, entitlement) of the later export: the canonical identities
(``keys.identity``, taken from the raw account texts) of the principals holding it, each with
the name to report."""


def _holders(later: Snapshot) -> Holders:
    """Index the later grants once, so each absent removal is a lookup, not a scan."""
    found: Holders = {}
    for grant in later.grants.values():
        principal = later.principals.get(grant.principal_key)
        if principal is None:
            continue
        slot = found.setdefault((grant.resource_key, entitlement_of(grant.key)), {})
        for text in (principal.upn, principal.email, principal.id):
            if found_identity := identity(text):
                slot.setdefault(found_identity, principal.name or principal.id)
    return found


def _same_person(row: Row, holders: Holders) -> str:
    """Return who in the later export holds this access under another key, or ``""``.

    A person can change key between exports, for example when a CSV's id column changes.
    Their access is then absent under the old key but present under the new one, so the
    absence is no evidence of a removal.
    """
    # The identity kept from the raw account text, not the escaped text a reviewer saw. A
    # campaign written before it was kept falls back to the displayed text, as it always did.
    account = row.account_identity or identity(row.display.get("account", ""))
    if not account:
        return ""
    return holders.get((row.resource_key, entitlement_of(row.grant_key)), {}).get(account, "")


def _absent(
    campaign: Campaign, row: Row, later: Snapshot, when: str, holders: Holders
) -> tuple[str, str]:
    """Judge access absent from a fully read resource: removed only with a dated, later read."""
    taken, started = _instant(when), _instant(campaign.created_at)
    if taken is None:
        return "unknown", "the later export does not say when it was read; give --as-of"
    if started is not None and taken < started:
        return "unknown", "the later export was read before the campaign began"
    if entitlement_of(row.grant_key) != "member" and system_of(row.resource_key) in (
        later.entitlement_blind
    ):
        return "unknown", (
            "the later export has no entitlement column, so every grant in it reads as "
            "'member' and it cannot show that this entitlement was removed"
        )
    holder = _same_person(row, holders)
    if holder:
        return "unknown", f"the same account still holds this access under another key ({holder})"
    reason = "not in the later export, which read the whole membership"
    principal = later.principals.get(row.principal_key)
    if principal is None:
        reason += "; the principal's key is not in the later export"
    elif principal.enabled is False:
        reason += "; the principal is disabled"
    return "removed", reason


def _removal(  # noqa: PLR0913 - the evidence one judgement rests on
    campaign: Campaign,
    row: Row,
    later: Snapshot,
    when: str,
    *,
    systems: set[str],
    holders: Holders,
) -> tuple[str, str]:
    """Return the result and reason for one accepted Remove decision."""
    if row.grant_key in later.grants:
        return _still_there(campaign, when)
    if row.resource_key in later.complete_resources:
        return _absent(campaign, row, later, when, holders)
    if system_of(row.resource_key) not in systems:
        return "unknown", "the later export is not of the system this access is on"
    if row.resource_key not in later.resources:
        return "unknown", "the later export does not include this resource"
    return "unknown", "the later export did not read this resource's whole membership"


def verify(
    campaign: Campaign, record: DecisionRecord, later: Snapshot, *, as_of: str = ""
) -> Verification:
    """Check a later snapshot against a decision record.

    Args:
        campaign: The campaign the decisions belong to.
        record: The decision record (checked against the campaign).
        later: The access read after the removals were due to be made.
        as_of: When the later access was read; defaults to the snapshot's own time.

    Raises:
        InputError: The decision record does not belong to this campaign as written.
    """
    _check_record(campaign, record)
    when = as_of or later.collected_at
    rows = {row.row_id: row for row in campaign.rows}
    decided = {d.row_id: d for d in record.rows if d.state == "accepted"}
    systems = set(later.systems) | {
        system_of(key) for key in later.complete_resources | set(later.resources)
    }
    holders = _holders(later)
    checks: list[Check] = []
    kept_but_gone: list[Note] = []
    for row_id, decision in sorted(decided.items()):
        row = rows.get(row_id)
        if row is None:  # pragma: no cover - load() and _check_record() rule this out
            continue
        present = row.grant_key in later.grants
        complete = row.resource_key in later.complete_resources
        if decision.decision == "Remove":
            # Each resource is judged by when its own inputs read it, not by another
            # input's time; --as-of, when given, is the operator's statement for all.
            read_at = as_of or later.resource_times.get(row.resource_key, later.collected_at)
            result, reason = _removal(
                campaign, row, later, read_at, systems=systems, holders=holders
            )
            checks.append(Check(row_id, row.grant_key, result, reason, decision.citation))
        elif decision.decision == "Keep" and not present and complete:
            kept_but_gone.append(
                Note(row_id, row.grant_key, decision.citation, "kept, but no longer present")
            )
    reviewed = {row.grant_key for row in campaign.rows} | {u.grant_key for u in campaign.unassigned}
    resources = {row.resource_key for row in campaign.rows} | {
        u.resource_key for u in campaign.unassigned
    }
    new = [
        Note("", grant.key, str(grant.source), "not in the campaign")
        for grant in sorted(later.grants.values(), key=lambda g: g.key)
        if grant.resource_key in resources and grant.key not in reviewed
    ]
    return Verification(
        campaign.id, when, checks, kept_but_gone, new, decide.gaps(campaign, record)
    )
