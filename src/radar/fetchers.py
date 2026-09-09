"""RSS fetchers: Google News keyword queries + security/robotics press feeds.

Uses feedparser over httpx-downloaded bytes. Normalizes entries to schema.Item.
"""

from __future__ import annotations

import logging
import re
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

import feedparser
import httpx

from radar.schema import Item, item_id_for_url

log = logging.getLogger(__name__)

_USER_AGENT = "RobotSecurityRadar/0.1"
_TIMEOUT = 20

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}")


class FetchError(Exception):
    """Raised when all feeds fail."""


def _parse_date(entry: Any) -> str:
    """Extract published date from a feed entry as ISO YYYY-MM-DD."""
    raw: str | None = entry.get("published") or entry.get("updated")
    if not raw:
        return date.today().isoformat()
    try:
        dt = datetime(*entry.published_parsed[:6], tzinfo=timezone.utc)
        return dt.strftime("%Y-%m-%d")
    except (AttributeError, TypeError, ValueError):
        pass
    try:
        return date.fromisoformat(raw[:10]).isoformat()
    except (ValueError, IndexError):
        return date.today().isoformat()


def _extract_cves(text: str) -> list[str]:
    """Extract unique CVE IDs from text."""
    return list(dict.fromkeys(_CVE_RE.findall(text)))


def _normalize_source(feed_type: str) -> str:
    """Map feed type to schema source."""
    if feed_type == "google_news":
        return "google_news"
    if feed_type == "press_rss":
        return "press_rss"
    return "press_rss"


def fetch(config: dict) -> list[Item]:
    """Fetch items from all configured feeds.

    Args:
        config: Must contain "feeds" key — list of dicts with type, name, url.

    Returns:
        List of Items from all feeds that succeeded.

    Raises:
        FetchError: Only if ALL feeds failed.
    """
    feeds: list[dict] = config.get("feeds", [])
    items: list[Item] = []
    errors: list[str] = []

    client = httpx.Client(
        follow_redirects=True,
        timeout=_TIMEOUT,
        headers={"User-Agent": _USER_AGENT},
    )

    for feed_cfg in feeds:
        feed_type = feed_cfg["type"]
        name = feed_cfg["name"]
        url = feed_cfg["url"]
        try:
            resp = client.get(url)
            resp.raise_for_status()
            parsed = feedparser.parse(resp.content)
            source = _normalize_source(feed_type)
            for entry in parsed.entries:
                title = (entry.get("title") or "").strip()
                link = (entry.get("link") or "").strip()
                if not title or not link:
                    continue
                body = (entry.get("summary") or entry.get("description") or "").strip()
                text = f"{title} {body}"
                item = Item(
                    id=item_id_for_url(link),
                    source=source,
                    url=link,
                    title=title,
                    body=body,
                    published=_parse_date(entry),
                    cve_ids=_extract_cves(text),
                )
                items.append(item)
        except Exception as exc:
            log.warning("Feed %s failed: %s", name, exc)
            errors.append(f"{name}: {exc}")
        finally:
            client.close()

    if errors:
        log.info("Feed errors (%d/%d): %s", len(errors), len(feeds), "; ".join(errors))

    if errors and not items:
        raise FetchError(
            f"All {len(feeds)} feeds failed: {'; '.join(errors)}"
        )

    return items
