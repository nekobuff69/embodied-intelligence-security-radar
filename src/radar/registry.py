"""Thin registry store over schema.py.

Handles load/save and idempotent item application with URL dedup.
"""

from __future__ import annotations

from pathlib import Path

from radar.schema import (
    Item,
    Registry,
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
