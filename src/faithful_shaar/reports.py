# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""Turning campaigns, decision records and verifications into report documents and packets."""

from __future__ import annotations

from typing import TYPE_CHECKING

from faithful_shaar import decide
from faithful_shaar.formats.xlsx import Packet, PacketRow, write_packet
from faithful_shaar.model import Problem, Source
from faithful_shaar.outputs.columns import SECTION_COLUMNS
from faithful_shaar.outputs.document import Document, Row, Section

if TYPE_CHECKING:
    from faithful_shaar.campaign import Campaign
    from faithful_shaar.decide import DecisionRecord
    from faithful_shaar.model import Snapshot
    from faithful_shaar.verify import Verification

CAMPAIGN_NOT_SHOWN = [
    "Access that no input recorded, such as local accounts or systems that were not exported.",
    "What a group or role lets its members do: only who holds it.",
    "Whether any access is appropriate: that is each reviewer's decision.",
]
DECISIONS_NOT_SHOWN = [
    "Whether a decision was right.",
    (
        "Who filled in a packet. The reviewer recorded is the one the campaign assigned; "
        "the author and time a workbook reports about itself are claims, shown as such."
    ),
    "Any change to access: shaar never adds or removes access.",
]
VERIFY_NOT_SHOWN = [
    "Access the later export does not cover, such as other systems or local accounts.",
    "Why access is still present.",
    "Changes made after the later export was taken.",
]


def _plural(n: int, one: str, many: str = "") -> str:
    return f"{n} {one if n == 1 else (many or one + 's')}"


# kind -> section key -> (title, intro, text when empty, citation column)
SECTION_TEXT: dict[str, dict[str, tuple[str, str, str, str]]] = {
    "campaign": {
        "reviewers": (
            "Reviewers and packets",
            "Send each reviewer their own packet.",
            "No reviewer was found for any entry.",
            "",
        ),
        "unassigned": (
            "Entries with no reviewer",
            (
                "No rule could place these entries. Assign them with a reviewer map, or "
                "review them separately."
            ),
            "Every entry has a reviewer.",
            "source",
        ),
        "rows": (
            "All entries",
            "Every entry sent for review, by reviewer.",
            "No access was found in the inputs.",
            "source",
        ),
    },
    "decisions": {
        "removals": (
            "Removals to make",
            (
                "Accepted Remove decisions. shaar does not remove access: an administrator "
                "makes these changes, and shaar verify checks them later."
            ),
            "No access is to be removed.",
            "",
        ),
        "attention": (
            "Needs attention",
            (
                "Entries without an accepted decision, and rows that did not belong in the "
                "packet they came in."
            ),
            "Nothing needs attention.",
            "citation",
        ),
        "decisions": (
            "Every entry",
            "The outcome for every entry of the campaign.",
            "The campaign has no entries.",
            "citation",
        ),
    },
    "verify": {
        "removals": (
            "Removals",
            "Each accepted Remove decision, checked against the later export.",
            "The decisions include no removals.",
            "citation",
        ),
        "kept_but_gone": (
            "Kept, but gone anyway",
            "Access a reviewer kept that is no longer present. Information only.",
            "All kept access is still present, or could not be checked.",
            "citation",
        ),
        "new_since_review": (
            "New since the review",
            "Access on the reviewed resources that the campaign did not include. Information only.",
            "No new access on the reviewed resources.",
            "citation",
        ),
    },
}


def _section(kind: str, key: str, rows: list[Row]) -> Section:
    title, intro, empty, citations = SECTION_TEXT[kind][key]
    return Section(key, title, intro, SECTION_COLUMNS[kind][key], rows, empty, citations)


def packets(campaign: Campaign) -> dict[str, bytes]:
    """Return every reviewer's packet workbook by file name."""
    files = {}
    for reviewer in campaign.reviewers:
        rows = [
            PacketRow(
                row_id=row.row_id,
                row_check=row.row_check,
                user=row.display["user"],
                account=row.display["account"],
                status=row.display["status"],
                last_sign_in=row.display["last_sign_in"],
                access_to=row.display["resource"],
                type=row.display["resource_kind"],
                access=row.display["access"],
                granted_through=row.display["via"],
                co_owners=row.display["co_owners"],
            )
            for row in campaign.rows_for(reviewer.key)
        ]
        packet = Packet(
            campaign_name=campaign.name,
            campaign_id=campaign.id,
            reviewer_name=reviewer.name,
            reviewer_email=reviewer.email,
            due=campaign.due,
            packet_digest=reviewer.packet_digest,
            rows=rows,
            co_owner_column=campaign.rule == "owner",
            created_at=campaign.created_at,
        )
        files[reviewer.packet] = write_packet(packet)
    return files


def _facts(campaign: Campaign) -> list[tuple[str, str]]:
    return [
        ("Campaign", campaign.name),
        ("Campaign ID", campaign.id),
        (
            "Reviewers chosen by",
            {"manager": "manager", "owner": "resource owner", "map": "reviewer map"}[campaign.rule],
        ),
        ("Due", campaign.due or "not set"),
        ("Access read at", campaign.collected_at or "not recorded by the inputs"),
        ("Systems", ", ".join(campaign.systems) or "none"),
    ]


def campaign_document(campaign: Campaign, *, generated_at: str, version: str) -> Document:
    """Return the campaign report."""
    names = {r.key: r.name for r in campaign.reviewers}
    headline = (
        f"{_plural(len(campaign.rows), 'access entry', 'access entries')} for "
        f"{_plural(len(campaign.reviewers), 'reviewer')}."
    )
    if campaign.unassigned:
        verb = "has" if len(campaign.unassigned) == 1 else "have"
        headline += f" {_plural(len(campaign.unassigned), 'entry', 'entries')} {verb} no reviewer."
    if campaign.problems:
        headline += " Some input could not be read; see Not read."
    reviewers: list[Row] = [
        {"reviewer": r.name, "email": r.email, "rows": r.rows, "packet": r.packet}
        for r in campaign.reviewers
    ]
    rows: list[Row] = [
        {
            "row_id": row.row_id,
            "reviewer": names[row.reviewer_key],
            "principal": row.display["user"],
            "account": row.display["account"],
            "status": row.display["status"],
            "resource": row.display["resource"],
            "resource_kind": row.display["resource_kind"],
            "access": row.display["access"],
            "via": row.display["via"],
            "source": row.source,
        }
        for row in campaign.rows
    ]
    unassigned: list[Row] = [
        {
            "principal": u.display["user"],
            "account": u.display["account"],
            "resource": u.display["resource"],
            "access": u.display["access"],
            "reason": u.reason,
            "source": u.source,
        }
        for u in campaign.unassigned
    ]
    return Document(
        kind="campaign",
        title=f"Access review campaign: {campaign.name}",
        headline=headline,
        facts=_facts(campaign),
        counts=[
            ("Access entries", len(campaign.rows)),
            ("Reviewers", len(campaign.reviewers)),
            ("Entries with no reviewer", len(campaign.unassigned)),
            ("Problems reading the inputs", len(campaign.problems)),
        ],
        sections=[
            _section("campaign", "reviewers", reviewers),
            _section("campaign", "unassigned", unassigned),
            _section("campaign", "rows", rows),
        ],
        problems=campaign.problems,
        not_shown=CAMPAIGN_NOT_SHOWN,
        generated_at=generated_at,
        tool_version=version,
        inputs=campaign.inputs,
        data={"campaign_id": campaign.id, "campaign_digest": campaign.digest},
    )


def decisions_document(
    campaign: Campaign, record: DecisionRecord, *, generated_at: str, version: str
) -> Document:
    """Return the decisions report."""
    rows_by_id = {row.row_id: row for row in campaign.rows}
    names = {r.key: r.name for r in campaign.reviewers}
    counts = {
        state: sum(1 for r in record.rows if r.state == state)
        for state in ("accepted", "undecided", "invalid", "altered", "conflict", "unassigned")
    }
    removes = [r for r in record.rows if r.state == "accepted" and r.decision == "Remove"]
    decided: list[Row] = []
    attention: list[Row] = []
    for outcome in record.rows:
        row = rows_by_id.get(outcome.row_id)
        shown = row.display if row else {}
        entry: Row = {
            "row_id": outcome.row_id,
            "reviewer": names.get(outcome.reviewer_key, ""),
            "principal": shown.get("user", ""),
            "resource": shown.get("resource", ""),
            "access": shown.get("access", ""),
            "decision": outcome.decision,
            "comment": outcome.comment,
            "state": outcome.state,
            "packet": outcome.packet,
            "citation": outcome.citation,
        }
        decided.append(entry)
        if outcome.state == "accepted" and outcome.decision == "Unsure":
            attention.append(
                {k: entry[k] for k in ("row_id", "reviewer", "principal", "resource", "citation")}
                | {
                    "state": "unsure",
                    "reason": "the reviewer was unsure; follow up for Keep or Remove",
                }
            )
        elif outcome.state != "accepted":
            attention.append(
                {
                    k: entry[k]
                    for k in ("row_id", "reviewer", "principal", "resource", "state", "citation")
                }
                | {"reason": outcome.reason}
            )
    attention.extend(
        {
            "row_id": stray.row_id,
            "reviewer": "",
            "principal": "",
            "resource": "",
            "state": "not this packet's row",
            "reason": stray.reason,
            "citation": stray.citation,
        }
        for stray in record.strays
    )
    removals: list[Row] = []
    for outcome in removes:
        row = rows_by_id[outcome.row_id]
        removals.append(
            {
                "row_id": row.row_id,
                "principal": row.display["user"],
                "account": row.display["account"],
                "resource": row.display["resource"],
                "access": row.display["access"],
                "reviewer": names.get(row.reviewer_key, ""),
                "comment": outcome.comment,
            }
        )
    problems = [
        *campaign.problems,
        *(
            Problem(Source(p.file), f"the packet was {p.status}: {p.reason}")
            for p in record.packets
            if p.status != "read"
        ),
    ]
    input_gaps = decide.campaign_gaps(campaign)
    total = len(campaign.rows)
    headline = (
        f"{counts['accepted']} of {_plural(total, 'entry', 'entries')} have an accepted "
        f"decision; {_plural(len(removes), 'removal')} to make."
    )
    if not record.complete:
        verb = "needs" if len(attention) == 1 else "need"
        headline += f" {_plural(len(attention), 'item')} {verb} attention."
    if input_gaps:
        headline += (
            " The campaign could not read all of its input, so the review may be missing "
            "entries; see Not read."
        )
    returned = [p for p in record.packets if p.status == "read"]
    return Document(
        kind="decisions",
        title=f"Access review decisions: {campaign.name}",
        headline=headline,
        facts=[
            *_facts(campaign)[:2],
            ("Packets read", f"{len(returned)} of {len(record.packets)} returned files"),
            ("Comment required for", ", ".join(record.require_comment) or "no decision"),
        ],
        counts=[
            ("Accepted", counts["accepted"]),
            ("Removals to make", len(removes)),
            ("Undecided", counts["undecided"]),
            ("Not valid", counts["invalid"]),
            ("Changed after sending", counts["altered"]),
            ("Copies disagree", counts["conflict"]),
            ("No reviewer", counts["unassigned"]),
            ("Rows from elsewhere", len(record.strays)),
            ("Problems reading the inputs", len(campaign.problems)),
        ],
        sections=[
            _section("decisions", "removals", removals),
            _section("decisions", "attention", attention),
            _section("decisions", "decisions", decided),
        ],
        problems=problems,
        not_shown=DECISIONS_NOT_SHOWN,
        generated_at=generated_at,
        tool_version=version,
        inputs=campaign.inputs,
        data={
            "campaign_id": campaign.id,
            "campaign_digest": campaign.digest,
            "decisions_digest": record.digest,
            "complete": not decide.gaps(campaign, record),
            "gaps": decide.gaps(campaign, record),
            "packets": [
                {
                    "file": p.file,
                    "sha256": p.sha256,
                    "status": p.status,
                    "reason": p.reason,
                    "reviewer": p.reviewer,
                    "reported_modified": p.reported_modified,
                    "reported_by": p.reported_by,
                }
                for p in record.packets
            ],
        },
    )


def verify_document(
    campaign: Campaign,
    verification: Verification,
    later: Snapshot,
    *,
    generated_at: str,
    version: str,
) -> Document:
    """Return the verification report."""
    rows_by_id = {row.row_id: row for row in campaign.rows}
    tally = {
        result: sum(1 for c in verification.checks if c.result == result)
        for result in ("removed", "pending", "failed", "unknown")
    }
    removals: list[Row] = []
    for check in verification.checks:
        row = rows_by_id[check.row_id]
        removals.append(
            {
                "row_id": check.row_id,
                "principal": row.display["user"],
                "resource": row.display["resource"],
                "access": row.display["access"],
                "result": check.result,
                "reason": check.reason,
                "citation": check.citation,
            }
        )
    kept: list[Row] = []
    for note in verification.kept_but_gone:
        row = rows_by_id[note.row_id]
        kept.append(
            {
                "row_id": note.row_id,
                "principal": row.display["user"],
                "resource": row.display["resource"],
                "access": row.display["access"],
                "citation": note.citation,
            }
        )
    new: list[Row] = []
    for note in verification.new_since_review:
        grant = later.grants[note.grant_key]
        principal = later.principals.get(grant.principal_key)
        resource = later.resources.get(grant.resource_key)
        new.append(
            {
                "principal": (principal.name or principal.id) if principal else grant.principal_key,
                "resource": (resource.name or resource.id) if resource else grant.resource_key,
                "access": grant.entitlement,
                "citation": note.citation,
            }
        )
    total = len(verification.checks)
    headline = f"{tally['removed']} of {_plural(total, 'removal')} verified."
    if tally["failed"] or tally["pending"] or tally["unknown"]:
        headline += (
            f" Still present: {tally['failed']} past due, {tally['pending']} not yet due. "
            f"Unknown: {tally['unknown']}."
        )
    if verification.record_gaps:
        headline += (
            " The decision record is not complete, so this does not show that the review "
            f"was carried out: {'; '.join(verification.record_gaps)}."
        )
    problems = [
        *(Problem(Source("decisions.json"), gap) for gap in verification.record_gaps),
        *later.problems,
    ]
    return Document(
        kind="verify",
        title=f"Access review verification: {campaign.name}",
        headline=headline,
        facts=[
            *_facts(campaign)[:2],
            ("Due", campaign.due or "not set"),
            ("Later access read at", verification.as_of or "not recorded by the inputs"),
        ],
        counts=[
            ("Removals verified", tally["removed"]),
            ("Still present, past due", tally["failed"]),
            ("Still present, not yet due", tally["pending"]),
            ("Unknown", tally["unknown"]),
            ("Kept but gone", len(kept)),
            ("New since the review", len(new)),
            ("Decision record gaps", len(verification.record_gaps)),
        ],
        sections=[
            _section("verify", "removals", removals),
            _section("verify", "kept_but_gone", kept),
            _section("verify", "new_since_review", new),
        ],
        problems=problems,
        not_shown=VERIFY_NOT_SHOWN,
        generated_at=generated_at,
        tool_version=version,
        inputs=later.inputs,
        data={
            "campaign_id": campaign.id,
            "campaign_digest": campaign.digest,
            "as_of": verification.as_of,
            "decision_record_complete": not verification.record_gaps,
            "decision_record_gaps": verification.record_gaps,
        },
    )
