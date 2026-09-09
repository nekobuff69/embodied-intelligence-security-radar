"""Thin registry store over schema.py.

Handles load/save, idempotent item application with URL dedup,
status transition hygiene (ADR-0003), and incident-item attachment.
"""

from __future__ import annotations

from pathlib import Path

from radar.schema import (
    Item,
    Incident,
    Registry,
    Status,
    STATUS_STATES,
    load_registry,
    save_registry,
)


def load(path: Path) -> Registry:
    """Load a registry from disk. Raises if file does not exist or is invalid."""
    return load_registry(path)


def save(reg: Registry, path: Path) -> None:
    """Validate and save a registry to disk."""
    path.parent.mkdir(parents=True, exist_ok=True)
    save_registry(reg, path)


def apply_items(reg: Registry, new_items: list[Item]) -> tuple[Registry, int]:
    """Add new items to registry, deduplicating by URL.

    Returns (updated_registry, count_of_genuinely_new_items).
    Items with URLs already in the registry are skipped (not counted).
    New items land unattached (no incident yet — expected pre-clusterer).
    """
    existing_urls: set[str] = {item.url for item in reg.items}
    added = 0
    for item in new_items:
        if item.url in existing_urls:
            continue
        reg.items.append(item)
        existing_urls.add(item.url)
        added += 1
    return reg, added


# ── Status hygiene (ADR-0003) ────────────────────────────────────────


def apply_status(inc: Incident, proposal: dict) -> bool:
    """Apply a status proposal to *inc* with ADR-0003 hygiene enforcement.

    *proposal* must contain ``state`` (one of STATUS_STATES),
    ``evidence_url`` (http/https) and ``as_of`` (ISO date).

    Returns *True* if the status changed; *False* if identical re-proposal
    (no-op).

    Raises ``ValueError`` on hygiene violations: missing evidence_url,
    missing or malformed as_of, or illegal state.
    """
    state = proposal.get("state")
    evidence_url = proposal.get("evidence_url")
    as_of = proposal.get("as_of")

    if state not in STATUS_STATES:
        raise ValueError(
            f"invalid status state {state!r}; must be one of {sorted(STATUS_STATES)}"
        )
    if not evidence_url or not (
        evidence_url.startswith("http://") or evidence_url.startswith("https://")
    ):
        raise ValueError(
            f"status proposal requires an http(s) evidence_url, got {evidence_url!r}"
        )
    if not as_of:
        raise ValueError("status proposal requires an as_of date")
    # Validate ISO date format
    import re as _re
    if not _re.match(r"^\d{4}-\d{2}-\d{2}$", str(as_of)):
        raise ValueError(
            f"status proposal as_of must be ISO date YYYY-MM-DD, got {as_of!r}"
        )

    # No-op if state and evidence are identical
    if (
        inc.status.state == state
        and inc.status.evidence_url == evidence_url
        and inc.status.as_of == as_of
    ):
        return False

    inc.status = Status(
        state=state,
        evidence_url=evidence_url,
        as_of=str(as_of),
        note=proposal.get("note", ""),
    )
    return True


# ── Incident-item attachment ──────────────────────────────────────────


def attach_item(inc: Incident, item: Item) -> None:
    """Append *item.id* to *inc.item_ids* if not already present.

    Idempotent: attaching the same item twice is a no-op.
    """
    if item.id not in inc.item_ids:
        inc.item_ids.append(item.id)
