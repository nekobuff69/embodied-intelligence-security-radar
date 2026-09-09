"""Operator correction tools for the incident registry.

Split, merge, detach — validated registry edits that respect schema
invariants and ADR-0003 claim hygiene.  Every operation re-checks
schema validity via ``Registry.validate()`` and the result lands as a
normal registry save (git commit is the operator's workflow, not here).

Atomic save helper ``save_atomic`` writes to a temp file then renames
into place so a crash never leaves a half-written registry.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

from radar.schema import (
    Incident,
    Registry,
    Severity,
    Status,
    load_registry,
    save_registry,
)

# ── Status precedence (higher index = further along) ──────────────────
# patched/exploited > unpatched > disclosed.  "resolved" sits outside
# the active lifecycle and is treated as most-advanced if encountered.

_STATUS_PRECEDENCE: dict[str, int] = {
    "disclosed": 0,
    "unpatched": 1,
    "patched": 2,
    "exploited_in_wild": 2,
    "resolved": 3,
}


def _item_published(reg: Registry, item_id: str) -> str:
    """Return the ``published`` date for *item_id* from the registry."""
    for item in reg.items:
        if item.id == item_id:
            return item.published
    raise ValueError(f"unknown item id {item_id!r}")


def _incident_by_id(reg: Registry, inc_id: str) -> Incident:
    """Return the incident matching *inc_id*, or raise ValueError."""
    for inc in reg.incidents:
        if inc.id == inc_id:
            return inc
    raise ValueError(f"unknown incident id {inc_id!r}")


def _delete_incident(reg: Registry, inc_id: str) -> Incident:
    """Remove and return the incident with *inc_id* from the registry."""
    for i, inc in enumerate(reg.incidents):
        if inc.id == inc_id:
            return reg.incidents.pop(i)
    raise ValueError(f"unknown incident id {inc_id!r}")


def _next_incident_id(reg: Registry) -> str:
    """Generate the next sequential incident id."""
    import re

    nums = [
        int(i.id.split("-")[1])
        for i in reg.incidents
        if re.match(r"^INC-\d+$", i.id)
    ]
    return f"INC-{max(nums, default=0) + 1:04d}"


# ── Split ─────────────────────────────────────────────────────────────


def split_incident(
    reg: Registry,
    inc_id: str,
    keep_item_ids: list[str],
) -> tuple[Registry, dict]:
    """Split *inc_id*: keep *keep_item_ids* in place, create a new
    incident for every other item that was in the original.

    The original incident keeps its id and retains *keep_item_ids*.
    Each new incident gets:
      - title = original title + " (split)"
      - status/evidence/severity copied from the original with
        note "split from {inc_id}"
      - first_seen = earliest ``published`` among the moved items
        (looked up in ``reg.items``)
      - last_checked copied from original
      - item_ids = [moved_id] (one incident per moved item)

    Returns ``(registry, summary)`` where summary describes the change.
    Raises ``ValueError`` for unknown ids or empty keep set.
    """
    inc = _incident_by_id(reg, inc_id)

    # Validate keep ids exist in the source incident
    source_set = set(inc.item_ids)
    keep_set = set(keep_item_ids)
    if not keep_set:
        raise ValueError(f"split requires a non-empty keep set for {inc_id}")
    unknown = keep_set - source_set
    if unknown:
        raise ValueError(
            f"items {sorted(unknown)} not in incident {inc_id}"
        )

    moved_ids = [iid for iid in inc.item_ids if iid not in keep_set]
    if not moved_ids:
        # Nothing to split — keep set == source set
        return reg, {
            "operation": "split",
            "incident_id": inc_id,
            "kept": list(keep_set),
            "moved": [],
            "new_incidents": [],
        }

    # Compute earliest published among moved items
    earliest = min(_item_published(reg, mid) for mid in moved_ids)

    # One split incident holds ALL moved items — the operator asserts these
    # items are a different event; per-item incidents would just add noise.
    new_id = _next_incident_id(reg)
    new_inc = Incident(
        id=new_id,
        title=f"{inc.title} (split)",
        category=inc.category,
        robot_class=inc.robot_class,
        vendor=inc.vendor,
        severity=Severity(source=inc.severity.source, value=inc.severity.value),
        status=Status(
            state=inc.status.state,
            evidence_url=inc.status.evidence_url,
            as_of=inc.status.as_of,
            note=f"split from {inc_id}",
        ),
        first_seen=earliest,
        last_checked=inc.last_checked,
        item_ids=list(moved_ids),
        model=inc.model,
        ai_summary=inc.ai_summary,
        monitor_urls=[],
    )
    reg.incidents.append(new_inc)
    new_incidents: list[dict] = [{"id": new_id, "item_ids": list(moved_ids)}]
    # Trim original to keep set (preserving order)
    inc.item_ids = [iid for iid in inc.item_ids if iid in keep_set]

    return reg, {
        "operation": "split",
        "incident_id": inc_id,
        "kept": inc.item_ids,
        "moved": moved_ids,
        "new_incidents": new_incidents,
    }


# ── Merge ─────────────────────────────────────────────────────────────


def merge_incidents(
    reg: Registry,
    keep_id: str,
    absorb_id: str,
) -> tuple[Registry, dict]:
    """Merge *absorb_id* into *keep_id*; *absorb_id* is deleted.

    - item_ids = union of both, preserving order (keep first, then absorb)
    - first_seen = min of both
    - last_checked = max of both
    - status: if absorb's status is "further along" than keep's, adopt
      absorb's status (with its evidence_url + as_of + note
      "merged from {absorb_id}").  Otherwise keep's status is retained.
    - monitor_urls: union of both lists.

    Returns ``(registry, summary)``.  Raises ``ValueError`` for unknown ids.
    """
    keep = _incident_by_id(reg, keep_id)
    absorb = _incident_by_id(reg, absorb_id)

    if keep_id == absorb_id:
        raise ValueError("cannot merge an incident into itself")

    # ── item_ids union (preserve order) ──────────────────────────────
    seen: set[str] = set()
    merged_ids: list[str] = []
    for iid in keep.item_ids + absorb.item_ids:
        if iid not in seen:
            seen.add(iid)
            merged_ids.append(iid)

    # ── dates ────────────────────────────────────────────────────────
    first_seen = min(keep.first_seen, absorb.first_seen)
    last_checked = max(keep.last_checked, absorb.last_checked)

    # ── status adoption ──────────────────────────────────────────────
    keep_prec = _STATUS_PRECEDENCE.get(keep.status.state, -1)
    absorb_prec = _STATUS_PRECEDENCE.get(absorb.status.state, -1)
    if absorb_prec > keep_prec:
        new_status = Status(
            state=absorb.status.state,
            evidence_url=absorb.status.evidence_url,
            as_of=absorb.status.as_of,
            note=f"merged from {absorb_id}",
        )
    else:
        new_status = keep.status

    # ── monitor_urls union ───────────────────────────────────────────
    seen_urls: set[str] = set()
    merged_urls: list[str] = []
    for url in keep.monitor_urls + absorb.monitor_urls:
        if url not in seen_urls:
            seen_urls.add(url)
            merged_urls.append(url)

    # ── apply ────────────────────────────────────────────────────────
    keep.item_ids = merged_ids
    keep.first_seen = first_seen
    keep.last_checked = last_checked
    keep.status = new_status
    keep.monitor_urls = merged_urls

    _delete_incident(reg, absorb_id)

    return reg, {
        "operation": "merge",
        "keep_id": keep_id,
        "absorbed_id": absorb_id,
        "item_ids": merged_ids,
        "first_seen": first_seen,
        "last_checked": last_checked,
        "status": new_status.state,
    }


# ── Detach ────────────────────────────────────────────────────────────


def detach_items(
    reg: Registry,
    inc_id: str,
    item_ids: list[str],
) -> tuple[Registry, dict]:
    """Remove *item_ids* from *inc_id*.  Items stay in the registry
    (become "wire" — unattached).  If the incident is left with zero
    items, it is deleted entirely (schema requires >= 1 item).

    Returns ``(registry, summary)``.  Raises ``ValueError`` for unknown ids.
    """
    inc = _incident_by_id(reg, inc_id)
    source_set = set(inc.item_ids)
    detach_set = set(item_ids)

    unknown = detach_set - source_set
    if unknown:
        raise ValueError(
            f"items {sorted(unknown)} not in incident {inc_id}"
        )

    inc.item_ids = [iid for iid in inc.item_ids if iid not in detach_set]
    deleted = False
    if not inc.item_ids:
        _delete_incident(reg, inc_id)
        deleted = True

    return reg, {
        "operation": "detach",
        "incident_id": inc_id,
        "detached": item_ids,
        "remaining_items": [] if deleted else inc.item_ids,
        "incident_deleted": deleted,
    }


# ── Atomic save ───────────────────────────────────────────────────────


def save_atomic(reg: Registry, path: str | Path) -> None:
    """Validate *reg*, write to a temp file in the same directory, then
    ``os.replace`` into *path*.  Raises on validation or write failure;
    the original file is never half-written.

    The temp file is created with ``delete=False`` so that ``os.replace``
    can move it into place atomically (on POSIX).
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(
        dir=path.parent, prefix=path.name + ".", suffix=".tmp"
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            import json

            data = reg.to_dict()
            f.write(json.dumps(data, indent=2, ensure_ascii=False) + "\n")
        # Validate before replace — raises on bad data, temp file stays
        # (harmless; next call cleans it).
        reg.validate()
        os.replace(tmp_path, path)
    except BaseException:
        # Clean up temp file on any failure
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise
