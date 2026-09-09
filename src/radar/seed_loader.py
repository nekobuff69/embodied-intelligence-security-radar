"""Seed loader: merge hand-curated incidents into the registry.

Validates every seed against schema.py (ADR-0003 claim hygiene enforced
via Status __post_init__), rejects duplicates by URL collision or incident
title, assigns stable ids, and merges idempotently.

Usage:
    from radar.seed_loader import load_seeds
    reg, summary = load_seeds(Path("data/seeds"), registry)
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from radar.schema import (
    Incident,
    Item,
    Registry,
    Severity,
    Status,
    load_registry,
    next_incident_id,
)


def load_seeds(
    seeds_dir: Path,
    registry: Registry,
    *,
    dry_run: bool = False,
) -> tuple[Registry, dict[str, Any]]:
    """Load seed incidents from *seeds_dir* and merge into *registry*.

    Returns (merged_registry, summary) where summary contains:
      - loaded: number of incidents added (or would be added in dry-run)
      - skipped: incidents skipped due to URL/title/ID collisions
      - rejected: incidents that failed schema validation
      - rejected_details: list of {id, title, reason} for rejected incidents

    In dry-run mode the registry is not mutated.
    """
    seeds_path = seeds_dir / "seed_incidents.json"
    if not seeds_path.exists():
        raise FileNotFoundError(f"Seed file not found: {seeds_path}")

    raw = json.loads(seeds_path.read_text())
    seed_items_raw: list[dict] = raw.get("items", [])
    seed_incidents_raw: list[dict] = raw.get("incidents", [])

    # --- Phase 1: Parse and validate seed items ---
    existing_urls: set[str] = {item.url for item in registry.items}
    item_map: dict[str, str] = {}  # seed_item_id → registry_item_id
    validated_items: list[tuple[Item, str]] = []  # (item, original_id)
    items_skipped = 0

    for item_dict in seed_items_raw:
        original_id = item_dict["id"]
        url = item_dict.get("url", "")

        # URL collision with existing registry
        if url in existing_urls:
            # Map to existing item so incidents reference the right id
            for existing_item in registry.items:
                if existing_item.url == url:
                    item_map[original_id] = existing_item.id
                    break
            items_skipped += 1
            continue

        try:
            item = Item(**item_dict)
        except (ValueError, KeyError, TypeError) as exc:
            items_skipped += 1
            continue

        # Internal URL dedup within seed set
        if url in {item.url for item, _ in validated_items}:
            # Already have this URL in validated items; map to first
            for existing_item, eid in validated_items:
                if existing_item.url == url:
                    item_map[original_id] = eid
                    break
            items_skipped += 1
            continue

        validated_items.append((item, original_id))
        item_map[original_id] = item.id
        existing_urls.add(url)

    # --- Phase 2: Validate seed incidents (ID collision → remap, never skip) ---
    existing_titles: set[str] = {
        inc.title.lower().strip() for inc in registry.incidents
    }
    existing_inc_ids: set[str] = {inc.id for inc in registry.incidents}
    validated_incidents: list[tuple[dict, dict]] = []  # (incident_dict, item_id_map)
    rejected: list[dict[str, str]] = []

    for inc_dict in seed_incidents_raw:
        inc_id = inc_dict.get("id", "")

        # Title dedup (same title already in registry → skip)
        title = inc_dict.get("title", "").lower().strip()
        if title in existing_titles:
            continue

        try:
            # Validate by constructing the Incident object
            severity = Severity(**inc_dict["severity"])
            status = Status(**inc_dict["status"])
            _ = Incident(
                id=inc_dict["id"],
                title=inc_dict["title"],
                category=inc_dict["category"],
                robot_class=inc_dict["robot_class"],
                vendor=inc_dict["vendor"],
                severity=severity,
                status=status,
                first_seen=inc_dict["first_seen"],
                last_checked=inc_dict["last_checked"],
                item_ids=list(inc_dict.get("item_ids", [])),
                model=inc_dict.get("model"),
                ai_summary=inc_dict.get("ai_summary"),
            )
        except (ValueError, KeyError, TypeError) as exc:
            rejected.append({
                "id": inc_id,
                "title": inc_dict.get("title", ""),
                "reason": str(exc),
            })
            continue

        # Build item_id remap map for this incident.
        # item_map covers both new items and URL-colliding existing items.
        inc_item_map: dict[str, str] = {}
        unmapped = [sid for sid in inc_dict.get("item_ids", []) if sid not in item_map]
        if unmapped:
            rejected.append({
                "id": inc_id,
                "title": inc_dict.get("title", ""),
                "reason": f"references unmapped items: {unmapped}",
            })
            continue

        for seed_iid in inc_dict.get("item_ids", []):
            inc_item_map[seed_iid] = item_map[seed_iid]

        # Assign stable ID: free → keep, collision → remap to next free id
        # (batch-aware: remapped ids live in existing_inc_ids before merge)
        if inc_id not in existing_inc_ids:
            new_id = inc_id
        else:
            import re as _re
            used = {
                int(m.group(1))
                for i in existing_inc_ids | {i.id for i in registry.incidents}
                if (m := _re.match(r"^INC-(\d+)$", i))
            }
            n = max(used, default=0) + 1
            while f"INC-{n:04d}" in existing_inc_ids:
                n += 1
            new_id = f"INC-{n:04d}"
        existing_inc_ids.add(new_id)

        validated_incidents.append((inc_dict, inc_item_map, new_id))
        existing_titles.add(title)

    # --- Phase 3: Merge validated data into registry (unless dry-run) ---
    if not dry_run:
        for item, _original_id in validated_items:
            registry.items.append(item)

    loaded = 0
    for inc_dict, inc_item_map, inc_new_id in validated_incidents:
        if not dry_run:
            inc = Incident(
                id=inc_new_id,
                title=inc_dict["title"],
                category=inc_dict["category"],
                robot_class=inc_dict["robot_class"],
                vendor=inc_dict["vendor"],
                model=inc_dict.get("model"),
                severity=Severity(**inc_dict["severity"]),
                status=Status(**inc_dict["status"]),
                first_seen=inc_dict["first_seen"],
                last_checked=inc_dict["last_checked"],
                item_ids=[inc_item_map[sid] for sid in inc_dict.get("item_ids", [])],
                ai_summary=inc_dict.get("ai_summary"),
            )
            registry.incidents.append(inc)
        loaded += 1

    summary: dict[str, Any] = {
        "loaded": loaded,
        "skipped": items_skipped + (len(seed_incidents_raw) - loaded - len(rejected)),
        "rejected": len(rejected),
        "rejected_details": rejected,
    }

    return registry, summary
