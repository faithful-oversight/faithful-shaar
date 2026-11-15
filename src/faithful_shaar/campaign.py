# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""A review campaign: who reviews which access, and the digests that bind packets to it.

A campaign is built once from the access inputs and saved as ``campaign.json``. That file
is the authoritative record of what was sent for review: every later step (reading
returned packets, verifying removals) checks its inputs against it.

Each row gets a ``row_id`` and a ``row_check``: a SHA-256 over the campaign id, the row
id, the grant key and every field the reviewer sees. Each reviewer's packet gets a
``packet_digest`` over its row checks in order. The campaign as a whole gets a digest
over its canonical JSON, so an edited ``campaign.json`` is refused.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass, field
from typing import TYPE_CHECKING, Any

from faithful_shaar.assign import MapEntry, MapIndex, assign
from faithful_shaar.errors import InputError
from faithful_shaar.formats.xlsx import cell_text
from faithful_shaar.keys import fold
from faithful_shaar.model import InputFile, Problem, Source
from faithful_shaar.outputs.safety import visible

if TYPE_CHECKING:
    from faithful_shaar.model import Grant, Snapshot

FORMAT = 1
MAX_CAMPAIGN_BYTES = 256 * 1024 * 1024

# What a reviewer sees for each row, in packet order: (field, header).
DISPLAY: tuple[tuple[str, str], ...] = (
    ("user", "User"),
    ("account", "Account"),
    ("status", "Status"),
    ("last_sign_in", "Last sign-in"),
    ("resource", "Access to"),
    ("resource_kind", "Type"),
    ("access", "Access"),
    ("via", "Granted through"),
    ("co_owners", "Co-owners"),
)
FIELDS = tuple(name for name, _ in DISPLAY)


@dataclass(frozen=True)
class Row:
    """One grant sent for review."""

    row_id: str
    grant_key: str
    principal_key: str
    resource_key: str
    reviewer_key: str
    display: dict[str, str]
    row_check: str
    source: str


@dataclass(frozen=True)
class Unassigned:
    """A grant no reviewer rule could place, and why."""

    grant_key: str
    principal_key: str
    resource_key: str
    display: dict[str, str]
    reason: str
    source: str


@dataclass(frozen=True)
class ReviewerEntry:
    """A reviewer and their packet."""

    key: str
    name: str
    email: str
    packet: str
    packet_digest: str
    rows: int


@dataclass
class Campaign:
    """Everything ``campaign.json`` holds."""

    id: str
    name: str
    created_at: str
    due: str
    rule: str
    collected_at: str
    systems: list[str]
    inputs: list[InputFile]
    reviewers: list[ReviewerEntry]
    rows: list[Row]
    unassigned: list[Unassigned]
    problems: list[Problem]
    complete_resources: list[str] = field(default_factory=list)
    digest: str = ""
    _by_reviewer: dict[str, list[Row]] | None = field(
        default=None, init=False, repr=False, compare=False
    )
    _counted: int = field(default=0, init=False, repr=False, compare=False)

    def rows_for(self, reviewer_key: str) -> list[Row]:
        """Return a reviewer's rows in packet order."""
        if self._by_reviewer is None or self._counted != len(self.rows):
            grouped: dict[str, list[Row]] = {}
            for row in self.rows:
                grouped.setdefault(row.reviewer_key, []).append(row)
            self._by_reviewer, self._counted = grouped, len(self.rows)
        return list(self._by_reviewer.get(reviewer_key, []))


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def canonical(value: Any) -> str:
    """Return the canonical JSON text digests are taken over."""
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def row_check(campaign_id: str, row_id: str, grant_key: str, display: dict[str, str]) -> str:
    """Return a row's check: SHA-256 over the campaign, the row and what the reviewer sees."""
    shown = {name: display.get(name, "") for name in FIELDS}
    payload = {
        "campaign_id": campaign_id,
        "row_id": row_id,
        "grant_key": grant_key,
        "display": shown,
    }
    return _sha256(canonical(payload))


def packet_digest(reviewer_key: str, checks: list[str]) -> str:
    """Return a packet's digest over its reviewer and its row checks in packet order.

    The reviewer is part of it, so a packet made for one reviewer cannot be taken as
    another's, even where the two would hold the same rows.
    """
    return _sha256("\n".join([reviewer_key, *checks]))


def _status(enabled: bool | None) -> str:  # noqa: FBT001 - the value shown, not a switch
    if enabled is None:
        return "Unknown"
    return "Enabled" if enabled else "Disabled"


def display_for(
    grant: Grant, snapshot: Snapshot, co_owners: tuple[str, ...] = ()
) -> dict[str, str]:
    """Return what a reviewer sees for a grant (invisible characters shown as escapes)."""
    principal = snapshot.principals.get(grant.principal_key)
    resource = snapshot.resources.get(grant.resource_key)
    if principal is None:
        user, account, status, sign_in = grant.principal_key, "", "Unknown", ""
    else:
        user = principal.name or principal.id
        account = principal.upn or principal.email or principal.id
        status = _status(principal.enabled)
        sign_in = principal.last_sign_in
        if principal.kind not in {"user", "unknown"}:
            user = f"{user} ({principal.kind})"
    shown = {
        "user": user,
        "account": account,
        "status": status,
        "last_sign_in": sign_in,
        "resource": (resource.name or resource.id) if resource else grant.resource_key,
        "resource_kind": resource.kind if resource else "",
        "access": grant.entitlement,
        "via": " > ".join(grant.via) if grant.via else "Direct",
        "co_owners": ", ".join(co_owners),
    }
    # The campaign keeps exactly the text a packet cell holds, so a returned packet can be
    # compared with it character for character.
    # Invisible and reordering characters show as visible escapes, as in every report, so the
    # reviewer and the operator read the same text for the same row.
    return {name: cell_text(visible(value))[0].strip() for name, value in shown.items()}


def campaign_id(  # noqa: PLR0913 - everything that decides who reviews what
    name: str,
    created_at: str,
    inputs: list[InputFile],
    *,
    due: str = "",
    rule: str = "",
    entries: list[MapEntry] | None = None,
) -> str:
    """Return a campaign id: ``C`` and 16 hex digits over everything that shapes the campaign.

    That is the name, time, inputs, due date, reviewer rule and reviewer map. Two campaigns
    that could assign a row differently never share an id, so a packet from one is never
    read as a packet of the other.
    """
    shaped = {
        "name": name,
        "created_at": created_at,
        "inputs": sorted(item.sha256 for item in inputs),
        "due": due,
        "rule": rule,
        "map": sorted(
            [e.resource, e.principal, e.reviewer.key, e.reviewer.name, e.reviewer.email]
            for e in entries or []
        ),
    }
    return "C" + _sha256(canonical(shaped))[:16]


def _slug(name: str, key: str) -> str:
    text = re.sub(r"[^A-Za-z0-9]+", "-", name).strip("-")[:40] or "reviewer"
    return f"{text}-{_sha256(key)[:6]}"


def build(  # noqa: PLR0913 - the parts of a campaign
    snapshot: Snapshot,
    *,
    name: str,
    created_at: str,
    due: str,
    rule: str,
    entries: list[MapEntry] | None = None,
) -> Campaign:
    """Build a campaign from a snapshot: assign every grant, then number and digest the rows."""
    cid = campaign_id(name, created_at, snapshot.inputs, due=due, rule=rule, entries=entries)
    placed: list[tuple[Grant, Any, dict[str, str]]] = []
    unassigned: list[Unassigned] = []
    reviewers: dict[str, Any] = {}
    map_index = MapIndex(entries) if entries is not None else None
    for grant in sorted(snapshot.grants.values(), key=lambda g: g.key):
        result = assign(grant, snapshot, rule, map_index)
        display = display_for(grant, snapshot, result.co_owners)
        if result.reviewer is None:
            unassigned.append(
                Unassigned(
                    grant.key,
                    grant.principal_key,
                    grant.resource_key,
                    display,
                    result.reason,
                    str(grant.source),
                )
            )
            continue
        known = reviewers.setdefault(result.reviewer.key, result.reviewer)
        if fold(known.email.strip()) != fold(result.reviewer.email.strip()):
            # Never reached through the reviewer map, which refuses this; a guard so a
            # packet's rows always belong to the one person it is sent to.
            msg = (
                f"reviewer {result.reviewer.key} is both {known.email or 'no email'} and "
                f"{result.reviewer.email or 'no email'}"
            )
            raise InputError(msg)
        placed.append((grant, result.reviewer, display))
    placed.sort(
        key=lambda item: (
            item[1].name.casefold(),
            item[1].key,
            item[2]["resource"].casefold(),
            item[2]["user"].casefold(),
            item[0].key,
        )
    )
    rows: list[Row] = []
    seen: set[str] = set()
    for grant, reviewer, display in placed:
        row_id = "R" + _sha256(f"{cid}|{grant.key}")[:12]
        if row_id in seen:  # pragma: no cover - a 48-bit collision within one campaign
            msg = f"two rows of campaign {cid} have the same id {row_id}"
            raise RuntimeError(msg)
        seen.add(row_id)
        check = row_check(cid, row_id, grant.key, display)
        rows.append(
            Row(
                row_id,
                grant.key,
                grant.principal_key,
                grant.resource_key,
                reviewer.key,
                display,
                check,
                str(grant.source),
            )
        )
    by_reviewer: dict[str, list[Row]] = {}
    for row in rows:
        by_reviewer.setdefault(row.reviewer_key, []).append(row)
    entries_out = []
    ordered = sorted(reviewers.values(), key=lambda r: (r.name.casefold(), r.key))
    for index, reviewer in enumerate(ordered, start=1):
        mine = by_reviewer.get(reviewer.key, [])
        entries_out.append(
            ReviewerEntry(
                reviewer.key,
                reviewer.name,
                reviewer.email,
                f"packet-{index:02d}-{_slug(reviewer.name, reviewer.key)}.xlsx",
                packet_digest(reviewer.key, [row.row_check for row in mine]),
                len(mine),
            )
        )
    problems = list(snapshot.problems)
    if not rows and not unassigned:
        # A header-only export, a filter that matched nothing or the wrong file looks like
        # a clean review of nobody; say so instead.
        first = snapshot.inputs[0].name if snapshot.inputs else name
        problems.append(Problem(Source(first), "no access entries were found in the inputs"))
    built = Campaign(
        id=cid,
        name=name,
        created_at=created_at,
        due=due,
        rule=rule,
        collected_at=snapshot.collected_at,
        systems=sorted(snapshot.systems),
        inputs=list(snapshot.inputs),
        reviewers=entries_out,
        rows=rows,
        unassigned=sorted(
            unassigned,
            key=lambda u: (
                u.display["resource"].casefold(),
                u.display["user"].casefold(),
                u.grant_key,
            ),
        ),
        problems=problems,
        complete_resources=sorted(snapshot.complete_resources),
    )
    built.digest = digest(built)
    return built


def _plain(campaign: Campaign) -> dict[str, Any]:
    data = asdict(campaign)
    for name in ("digest", "_by_reviewer", "_counted"):
        data.pop(name)
    data["problems"] = [{"source": str(p.source), "reason": p.reason} for p in campaign.problems]
    return data


def digest(campaign: Campaign) -> str:
    """Return the digest of a campaign: SHA-256 over its canonical JSON without the digest."""
    return _sha256(canonical(_plain(campaign)))


def dump(campaign: Campaign) -> bytes:
    """Return the text of ``campaign.json``."""
    data = {"shaar_campaign": FORMAT, **_plain(campaign), "digest": campaign.digest}
    return (json.dumps(data, sort_keys=True, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


def _need(data: dict[str, Any], key: str, kind: type) -> Any:
    value = data.get(key)
    if not isinstance(value, kind):
        msg = f"campaign.json: {key!r} is missing or has the wrong type"
        raise InputError(msg)
    return value


def _strings(data: dict[str, Any], keys: tuple[str, ...]) -> dict[str, str]:
    return {key: _need(data, key, str) for key in keys}


def load(raw: bytes) -> Campaign:
    """Read ``campaign.json`` and check its digest.

    Raises:
        InputError: The file is not a campaign, has the wrong shape, or was changed after
            it was written (its digest does not match).
    """
    if len(raw) > MAX_CAMPAIGN_BYTES:
        msg = f"campaign.json is larger than {MAX_CAMPAIGN_BYTES} bytes"
        raise InputError(msg)
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        msg = "campaign.json is not JSON"
        raise InputError(msg) from None
    if not isinstance(data, dict) or data.get("shaar_campaign") != FORMAT:
        msg = f"campaign.json is not a shaar campaign of format {FORMAT}"
        raise InputError(msg)
    try:
        campaign = Campaign(
            **_strings(data, ("id", "name", "created_at", "due", "rule", "collected_at")),
            systems=[str(s) for s in _need(data, "systems", list)],
            inputs=[InputFile(**item) for item in _need(data, "inputs", list)],
            reviewers=[ReviewerEntry(**item) for item in _need(data, "reviewers", list)],
            rows=[Row(**item) for item in _need(data, "rows", list)],
            unassigned=[Unassigned(**item) for item in _need(data, "unassigned", list)],
            problems=[
                Problem(Source(str(p["source"])), str(p["reason"]))
                for p in _need(data, "problems", list)
            ],
            complete_resources=[str(k) for k in _need(data, "complete_resources", list)],
            digest=_need(data, "digest", str),
        )
    except (TypeError, KeyError):
        msg = "campaign.json has a record of the wrong shape"
        raise InputError(msg) from None
    if digest(campaign) != campaign.digest:
        msg = "campaign.json was changed after shaar wrote it (its digest does not match)"
        raise InputError(msg)
    return campaign
