"""Retroactive pruning of the incident registry.

Protects seed incidents (item URL membership in data/seeds/seed_incidents.json),
dismisses stale (>3y) and commentary items, and demotes ineligible incidents
(not seed-protected, no CVE items, Unknown vendor) by deleting them.

Items are never deleted outright — only dismissed (removed from incidents and
items list).  The CLI persists the dismissal blocklist to data/dismissed_urls.json.
"""

from __future__ import annotations

import json
from datetime import date, timedelta
from pathlib import Path

from radar.registry import dismiss_items
from radar.schema import Registry

# Commentary terms — must stay in sync with radar.gate.COMMENTARY_TERMS.
# Kept local to avoid import coupling with the gate module (which may be
# modified by a concurrent slice).
PRUNE_COMMENTARY_TERMS: frozenset[str] = frozenset({
    "podcast",
    "episode",
    "interview",
    "opinion",
    "commentar",
    "webinar",
    "roundup",
    "meets ",
    "fun kids",
    "screen time",
})

_MAX_AGE_DAYS = 1095  # 3 years
_MAX_FUTURE_DAYS = 2


def _has_commentary(text: str) -> bool:
    """Return True if text contains any commentary term."""
    lower = text.lower()
    return any(term in lower for term in PRUNE_COMMENTARY_TERMS)


def _load_seed_urls(seeds_dir: Path) -> set[str]:
    """Collect all item URLs from seed incident files."""
    urls: set[str] = set()
    if not seeds_dir.exists():
        return urls
    for path in seeds_dir.glob("*.json"):
        try:
            data = json.loads(path.read_text())
        except (json.JSONDecodeError, OSError):
            continue
        for item in data.get("items", []):
            url = item.get("url", "")
            if url:
                urls.add(url)
    return urls


def _is_stale(published: str, today: date) -> bool:
    """Return True if *published* is older than 3 years, more than 2 days
    in the future, or not a valid ISO date."""
    try:
        pub = date.fromisoformat(published)
    except (ValueError, TypeError):
        return True  # malformed → treat as stale
    return pub < (today - timedelta(days=_MAX_AGE_DAYS)) or pub > (today + timedelta(days=_MAX_FUTURE_DAYS))


def prune(
    reg: Registry,
    seeds_dir: Path,
    today: date | str | None = None,
) -> tuple[Registry, dict]:
    """Prune stale/commentary items and demote ineligible incidents.

    Seed-protected incidents (having at least one item whose URL is in the
    seeds) are never touched.

    Returns ``(pruned_registry, summary)`` where summary contains::

        dismissed_items:   int  — items removed from registry
        dismissed_urls:    list[str] — URLs of dismissed items (for blocklist)
        demoted_incidents: int  — incidents deleted (zero remaining items)
        kept_incidents:    int  — incidents still in registry after pruning
    """
    if today is None:
        today = date.today()
    elif isinstance(today, str):
        today = date.fromisoformat(today)

    seed_urls = _load_seed_urls(seeds_dir)

    # Determine which incidents are seed-protected
    seed_protected_ids: set[str] = set()
    for inc in reg.incidents:
        for iid in inc.item_ids:
            for item in reg.items:
                if item.id == iid and item.url in seed_urls:
                    seed_protected_ids.add(inc.id)
                    break
            if inc.id in seed_protected_ids:
                break

    # Collect items to dismiss
    urls_to_dismiss: set[str] = set()

    # Stale items (malformed dates or >3y old or >2d future)
    for item in reg.items:
        if _is_stale(item.published, today):
            urls_to_dismiss.add(item.url)

    # Commentary items
    for item in reg.items:
        if item.url in urls_to_dismiss:
            continue
        text = f"{item.title} {item.body}"
        if _has_commentary(text):
            urls_to_dismiss.add(item.url)

    # Dismiss items from registry
    dismiss_result = dismiss_items(reg, urls_to_dismiss)
    dismissed_count = dismiss_result["removed_items"]

    # Demote ineligible incidents (not seed-protected, no CVE, unknown vendor)
    demoted = 0
    remaining: list = []
    for inc in reg.incidents:
        if inc.id in seed_protected_ids:
            remaining.append(inc)
            continue

        # Check if any attached item has CVEs
        has_cve_item = False
        for iid in inc.item_ids:
            for item in reg.items:
                if item.id == iid and item.cve_ids:
                    has_cve_item = True
                    break
            if has_cve_item:
                break

        vendor_unknown = inc.vendor in ("", "Unknown")

        if not has_cve_item and vendor_unknown:
            # Demote: delete incident, keep items on wire
            demoted += 1
        else:
            remaining.append(inc)

    reg.incidents = remaining

    summary = {
        "dismissed_items": dismissed_count,
        "dismissed_urls": sorted(urls_to_dismiss),
        "demoted_incidents": demoted,
        "kept_incidents": len(reg.incidents),
    }
    return reg, summary
