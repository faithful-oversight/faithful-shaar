# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""Reading returned packets into a decision record, checked against the campaign.

A decision counts only when everything about it can be trusted:

- the packet belongs to this campaign and to the reviewer the campaign assigned;
- the row is one of that reviewer's rows, and what the reviewer saw is exactly what the
  campaign sent (the hidden row check and the visible text both match);
- the decision is Keep, Remove or Unsure, and no other copy of the row disagrees.

Anything else is listed with the reason, and the row stays without an accepted decision.
The reviewer recorded for a decision is the one the campaign assigned, never a name a
workbook reports about itself.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass, field
from typing import TYPE_CHECKING, Any, Protocol

from faithful_shaar import limits
from faithful_shaar.campaign import DISPLAY, canonical
from faithful_shaar.errors import InputError

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

    from faithful_shaar.campaign import Campaign, Row

FORMAT = 1
DECISIONS = ("Keep", "Remove", "Unsure")
STATES = ("accepted", "undecided", "invalid", "altered", "conflict", "unassigned")
MAX_DECISIONS_BYTES = 256 * 1024 * 1024
ROW_ID = "Row ID"
ROW_CHECK = "Row check"
DECISION = "Decision"
COMMENT = "Comment"


class ReturnedRow(Protocol):
    """A data row of a returned workbook, as :mod:`faithful_shaar.formats.xlsx` reads it."""

    @property
    def row(self) -> int:
        """The sheet row number."""

    @property
    def values(self) -> dict[str, str]:
        """Header text to cell text."""

    @property
    def notes(self) -> list[str]:
        """What the reader noticed, such as a formula in a cell."""


class ReturnedPacket(Protocol):
    """A returned workbook, as :mod:`faithful_shaar.formats.xlsx` reads it."""

    @property
    def about(self) -> dict[str, str]:
        """The About sheet's labels and values."""

    @property
    def rows(self) -> Sequence[ReturnedRow]:
        """The Review sheet's data rows."""

    @property
    def core(self) -> dict[str, str]:
        """What the file says about itself (author, time): claims, not facts."""


@dataclass(frozen=True)
class PacketRecord:
    """A returned file: what it is, whose it is, and whether it was used."""

    file: str
    sha256: str
    status: str  # "read" | "rejected" | "unreadable"
    reason: str = ""
    reviewer_key: str = ""
    reviewer: str = ""
    reported_modified: str = ""
    reported_by: str = ""


@dataclass(frozen=True)
class RowDecision:
    """The outcome for one campaign row."""

    row_id: str
    reviewer_key: str
    state: str
    decision: str = ""
    comment: str = ""
    packet: str = ""
    citation: str = ""
    reason: str = ""


@dataclass(frozen=True)
class Stray:
    """A workbook row that is not one of the packet's own rows."""

    packet: str
    citation: str
    row_id: str
    reason: str


@dataclass
class DecisionRecord:
    """Everything ``decisions.json`` holds."""

    campaign_id: str
    campaign_digest: str
    created_at: str
    require_comment: list[str]
    packets: list[PacketRecord]
    rows: list[RowDecision]
    strays: list[Stray]
    digest: str = ""

    @property
    def complete(self) -> bool:
        """Whether every row has a firm accepted decision and nothing needs attention.

        Unsure is accepted, as what the reviewer said, but it is not firm: the entry still
        needs a Keep or Remove, so a record with any Unsure is not complete.
        """
        firm = all(r.state == "accepted" and r.decision != "Unsure" for r in self.rows)
        return firm and not self.strays and all(p.status == "read" for p in self.packets)


@dataclass
class _Seen:
    """What the returned workbooks said about one row."""

    decisions: list[tuple[str, str, str, str]] = field(
        default_factory=list
    )  # (decision, comment, packet, citation)
    invalid: list[tuple[str, str, str]] = field(default_factory=list)  # (reason, packet, citation)
    altered: list[tuple[str, str, str]] = field(default_factory=list)
    blank: list[tuple[str, str]] = field(default_factory=list)  # (packet, citation)


def _key(text: str) -> str:
    return re.sub(r"[^a-z0-9]", "", text.casefold())


def _about(packet: ReturnedPacket, wanted: str) -> str:
    for label, value in packet.about.items():
        if _key(label) == _key(wanted):
            return value.strip()
    return ""


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _citation(name: str, row: ReturnedRow) -> str:
    return f"{name}, Review row {row.row}"


def _shown(campaign: Campaign) -> list[tuple[str, str]]:
    """The fields a packet shows: co-owners only under the owner rule."""
    return [(f, h) for f, h in DISPLAY if f != "co_owners" or campaign.rule == "owner"]


def _changes(row: Row, returned: ReturnedRow, shown: list[tuple[str, str]]) -> list[str]:
    """Return what differs between the campaign's row and the returned one."""
    changed = []
    if returned.values.get(ROW_CHECK, "").strip() != row.row_check:
        changed.append("its hidden row check")
    for name, header in shown:
        if returned.values.get(header, "").strip() != row.display.get(name, "").strip():
            changed.append(header)
    return changed


def _parse(text: str) -> str:
    """Return the decision a cell holds: one of :data:`DECISIONS`, ``""`` or ``"?"``."""
    value = text.strip().casefold()
    if not value:
        return ""
    for decision in DECISIONS:
        if value == decision.casefold():
            return decision
    return "?"


class _Reader:
    """Reads returned packets into per-row observations."""

    def __init__(self, campaign: Campaign, require_comment: list[str]) -> None:
        self.campaign = campaign
        self.require_comment = {c.casefold() for c in require_comment}
        self.rows = {row.row_id: row for row in campaign.rows}
        self.by_digest = {r.packet_digest: r for r in campaign.reviewers}
        self.shown = _shown(campaign)
        self.seen: dict[str, _Seen] = {}
        self.packets: list[PacketRecord] = []
        self.strays: list[Stray] = []
        self.returned: set[str] = set()

    def packet(self, name: str, data: bytes, read: Callable[[bytes, str], ReturnedPacket]) -> None:
        digest = _sha256(data)
        try:
            packet = read(data, name)
        except InputError as exc:
            self.packets.append(PacketRecord(name, digest, "unreadable", str(exc)))
            return
        reported = (packet.core.get("modified", ""), packet.core.get("lastModifiedBy", ""))
        cid = _about(packet, "Campaign ID")
        if cid != self.campaign.id:
            reason = f"it belongs to campaign {cid or '(none)'}, not {self.campaign.id}"
            self.packets.append(PacketRecord(name, digest, "rejected", reason, "", "", *reported))
            return
        owner = self.by_digest.get(_about(packet, "Packet digest"))
        if owner is None:
            reason = "its packet digest matches no reviewer's packet in this campaign"
            self.packets.append(PacketRecord(name, digest, "rejected", reason, "", "", *reported))
            return
        self.returned.add(owner.key)
        self.packets.append(
            PacketRecord(name, digest, "read", "", owner.key, owner.name, *reported)
        )
        listed: set[str] = set()
        for returned in packet.rows:
            self._row(name, owner.key, returned, listed)
        for row in self.campaign.rows_for(owner.key):
            if row.row_id not in listed:
                self.seen.setdefault(row.row_id, _Seen()).blank.append((name, f"{name}: missing"))

    def _row(self, name: str, reviewer_key: str, returned: ReturnedRow, listed: set[str]) -> None:
        values = returned.values
        row_id = values.get(ROW_ID, "").strip()
        citation = _citation(name, returned)
        if not row_id and not any(v.strip() for v in values.values()):
            return  # an empty line
        row = self.rows.get(row_id)
        if row is None:
            self.strays.append(
                Stray(name, citation, row_id, "the row is not part of this campaign")
            )
            return
        if row.reviewer_key != reviewer_key:
            self.strays.append(
                Stray(name, citation, row_id, "the row belongs to another reviewer's packet")
            )
            return
        listed.add(row_id)
        seen = self.seen.setdefault(row_id, _Seen())
        changes = _changes(row, returned, self.shown)
        if changes:
            seen.altered.append(
                (f"changed after it was sent: {', '.join(changes)}", name, citation)
            )
            return
        decision = _parse(values.get(DECISION, ""))
        comment = values.get(COMMENT, "").strip()
        notes = list(returned.notes)
        if decision == "?":
            text = values.get(DECISION, "").strip()
            seen.invalid.append((f"{text[:40]!r} is not Keep, Remove or Unsure", name, citation))
        elif decision and decision.casefold() in self.require_comment and not comment:
            seen.invalid.append((f"{decision} needs a comment in this campaign", name, citation))
        elif decision and notes:
            seen.invalid.append(("; ".join(notes), name, citation))
        elif decision:
            seen.decisions.append((decision, comment, name, citation))
        else:
            seen.blank.append((name, citation))


def _outcome(row: Row, seen: _Seen | None, returned: bool, unreadable: bool) -> RowDecision:  # noqa: FBT001, PLR0911
    key = row.reviewer_key
    if seen is None or not (seen.decisions or seen.invalid or seen.altered or seen.blank):
        if returned:  # pragma: no cover - a returned packet lists or marks every own row
            return RowDecision(row.row_id, key, "undecided", reason="no decision")
        reason = "the packet could not be read" if unreadable else "the packet was not returned"
        return RowDecision(row.row_id, key, "undecided", reason=reason)
    if seen.altered:
        reason, packet, citation = seen.altered[0]
        return RowDecision(
            row.row_id, key, "altered", packet=packet, citation=citation, reason=reason
        )
    choices = {decision for decision, *_ in seen.decisions}
    if len(choices) > 1:
        where = "; ".join(citation for *_, citation in seen.decisions)
        reason = f"copies of this row disagree ({', '.join(sorted(choices))})"
        return RowDecision(row.row_id, key, "conflict", citation=where, reason=reason)
    if seen.invalid and not choices:
        reason, packet, citation = seen.invalid[0]
        return RowDecision(
            row.row_id, key, "invalid", packet=packet, citation=citation, reason=reason
        )
    if choices:
        decision = choices.pop()
        comments = sorted({comment for _, comment, *_ in seen.decisions if comment})
        _, _, packet, citation = seen.decisions[0]
        reason = "another copy of this row is not valid" if seen.invalid else ""
        if seen.invalid:
            # Nothing is accepted, so no decision is recorded for a consumer to act on.
            return RowDecision(
                row.row_id,
                key,
                "conflict",
                "",
                " | ".join(comments),
                packet,
                citation,
                f"{reason} (a copy says {decision})",
            )
        return RowDecision(
            row.row_id, key, "accepted", decision, " | ".join(comments), packet, citation, reason
        )
    packet, citation = seen.blank[0]
    reason = "missing from the returned packet" if citation.endswith(": missing") else "no decision"
    citation = "" if citation.endswith(": missing") else citation
    return RowDecision(
        row.row_id, key, "undecided", packet=packet, citation=citation, reason=reason
    )


def read_decisions(
    campaign: Campaign,
    files: list[tuple[str, bytes]],
    *,
    read: Callable[[bytes, str], ReturnedPacket],
    created_at: str,
    require_comment: list[str] | None = None,
) -> DecisionRecord:
    """Read returned packets against a campaign.

    Args:
        campaign: The campaign the packets were sent for.
        files: Each returned workbook's display name and bytes.
        read: The workbook reader (:func:`faithful_shaar.formats.xlsx.read_packet`).
        created_at: When this record is made (ISO 8601 UTC).
        require_comment: Decisions that need a comment, such as ``["Remove"]``.
    """
    reader = _Reader(campaign, require_comment or [])
    for name, data in files:
        reader.packet(name, data, read)
    unreadable = any(p.status != "read" for p in reader.packets)
    rows = [
        _outcome(row, reader.seen.get(row.row_id), row.reviewer_key in reader.returned, unreadable)
        for row in campaign.rows
    ]
    rows.extend(
        RowDecision("", "", "unassigned", reason=item.reason, citation=item.source)
        for item in campaign.unassigned
    )
    record = DecisionRecord(
        campaign_id=campaign.id,
        campaign_digest=campaign.digest,
        created_at=created_at,
        require_comment=sorted(require_comment or []),
        packets=reader.packets,
        rows=rows,
        strays=reader.strays,
    )
    record.digest = digest(record)
    return record


def _names(items: list[str], limit: int = 3) -> str:
    """Join up to ``limit`` names, then say how many more there are."""
    shown = ", ".join(items[:limit])
    return f"{shown} and {len(items) - limit} more" if len(items) > limit else shown


def campaign_gaps(campaign: Campaign) -> list[str]:
    """Return why the campaign itself may not have put every access entry in a packet.

    A decision record can only cover what the campaign sent for review. Problems recorded
    while reading the inputs, a resource whose membership was not read in full, and a
    campaign with no entries at all each mean the review may be missing people.
    """
    gaps = []
    if campaign.problems:
        gaps.append(
            f"the campaign recorded {_plural(len(campaign.problems), 'problem')} reading its "
            "inputs (see Not read), so some access may never have reached a packet"
        )
    shown = {row.resource_key: row.display.get("resource", "") for row in campaign.rows}
    shown |= {u.resource_key: u.display.get("resource", "") for u in campaign.unassigned}
    partial = sorted(
        (name or key) for key, name in shown.items() if key not in campaign.complete_resources
    )
    if partial:
        gaps.append(
            f"{_plural(len(partial), 'resource')} not read in full when the campaign began "
            f"({_names(partial)}), so members the input did not list were never reviewed"
        )
    if not campaign.rows and not campaign.unassigned:
        gaps.append("the campaign has no access entries, so there was nothing to review")
    return gaps


def _plural(n: int, one: str, many: str = "") -> str:
    return f"{n} {one if n == 1 else many or one + 's'}"


def record_gaps(record: DecisionRecord) -> list[str]:
    """Return why the decisions themselves are not final: what lacks a firm accepted decision."""
    gaps = []
    counts = {state: sum(1 for r in record.rows if r.state == state) for state in STATES}
    open_states = [f"{state} {counts[state]}" for state in STATES[1:] if counts[state]]
    if open_states:
        total = sum(counts[state] for state in STATES[1:])
        gaps.append(
            f"{_plural(total, 'entry', 'entries')} "
            f"{'has' if total == 1 else 'have'} no accepted decision ({', '.join(open_states)})"
        )
    unsure = sum(1 for r in record.rows if r.state == "accepted" and r.decision == "Unsure")
    if unsure:
        gaps.append(f"{_plural(unsure, 'entry', 'entries')} marked Unsure")
    if record.strays:
        gaps.append(f"{_plural(len(record.strays), 'row')} came in a packet it does not belong to")
    unused = sum(1 for p in record.packets if p.status != "read")
    if unused:
        gaps.append(f"{_plural(unused, 'returned file')} could not be used")
    return gaps


def gaps(campaign: Campaign, record: DecisionRecord) -> list[str]:
    """Return every reason the decision record cannot stand for the whole review.

    It is empty only when the campaign read all of its input and every entry has a firm
    accepted decision. ``shaar decisions`` and ``shaar verify`` both take their exit code
    and their wording from this one list.
    """
    return [*campaign_gaps(campaign), *record_gaps(record)]


def _plain(record: DecisionRecord) -> dict[str, Any]:
    data = asdict(record)
    data.pop("digest")
    return data


def digest(record: DecisionRecord) -> str:
    """Return the digest of a decision record over its canonical JSON without the digest."""
    return hashlib.sha256(canonical(_plain(record)).encode("utf-8")).hexdigest()


def dump(record: DecisionRecord) -> bytes:
    """Return the text of ``decisions.json``."""
    data = {"shaar_decisions": FORMAT, **_plain(record), "digest": record.digest}
    return (json.dumps(data, sort_keys=True, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


def load(raw: bytes) -> DecisionRecord:
    """Read ``decisions.json`` and check its digest.

    Raises:
        InputError: The file is not a decision record, has the wrong shape, or was changed
            after it was written.
    """
    if len(raw) > limits.get("decisions-bytes"):
        msg = (
            f"decisions.json is larger than {limits.get('decisions-bytes')} bytes; "
            f"{limits.hint('decisions-bytes')}"
        )
        raise InputError(msg)
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        msg = "decisions.json is not JSON"
        raise InputError(msg) from None
    if not isinstance(data, dict) or data.get("shaar_decisions") != FORMAT:
        msg = f"decisions.json is not a shaar decision record of format {FORMAT}"
        raise InputError(msg)
    try:
        record = DecisionRecord(
            campaign_id=str(data["campaign_id"]),
            campaign_digest=str(data["campaign_digest"]),
            created_at=str(data["created_at"]),
            require_comment=[str(c) for c in data["require_comment"]],
            packets=[PacketRecord(**item) for item in data["packets"]],
            rows=[RowDecision(**item) for item in data["rows"]],
            strays=[Stray(**item) for item in data["strays"]],
            digest=str(data["digest"]),
        )
    except (TypeError, KeyError):
        msg = "decisions.json has a record of the wrong shape"
        raise InputError(msg) from None
    if digest(record) != record.digest:
        msg = "decisions.json was changed after shaar wrote it (its digest does not match)"
        raise InputError(msg)
    return record
