"""RSS + structured API fetchers: Google News, press RSS, Reddit, HN, NVD, GitHub advisories, vendor pages.

Uses feedparser over httpx-downloaded bytes for RSS. Direct httpx for structured APIs.
Normalizes all entries to schema.Item.
"""

from __future__ import annotations

import hashlib
import html
import json
import logging
import re
import time
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


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

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


def _parse_iso_datetime(raw: str) -> str:
    """Parse an ISO datetime string to YYYY-MM-DD, fallback to today."""
    if not raw:
        return date.today().isoformat()
    try:
        return date.fromisoformat(raw[:10]).isoformat()
    except (ValueError, IndexError):
        return date.today().isoformat()


def _strip_html_tags(text: str) -> str:
    """Strip HTML tags and unescape entities."""
    cleaned = re.sub(r"<[^>]+>", " ", text)
    cleaned = html.unescape(cleaned)
    return re.sub(r"\s+", " ", cleaned).strip()


# ---------------------------------------------------------------------------
# RSS fetcher (Google News + press RSS)
# ---------------------------------------------------------------------------

def _fetch_rss(client: httpx.Client, feed_cfg: dict) -> list[Item]:
    """Fetch and parse a single RSS/Atom feed into Items."""
    name = feed_cfg["name"]
    url = feed_cfg["url"]
    resp = client.get(url)
    resp.raise_for_status()
    parsed = feedparser.parse(resp.content)
    items: list[Item] = []
    for entry in parsed.entries:
        title = (entry.get("title") or "").strip()
        link = (entry.get("link") or "").strip()
        if not title or not link:
            continue
        body = (entry.get("summary") or entry.get("description") or "").strip()
        text = f"{title} {body}"
        items.append(
            Item(
                id=item_id_for_url(link),
                source="google_news" if feed_cfg["type"] == "google_news" else "press_rss",
                url=link,
                title=title,
                body=body,
                published=_parse_date(entry),
                cve_ids=_extract_cves(text),
            )
        )
    log.info("Fetched %d items from RSS feed %s", len(items), name)
    return items


# ---------------------------------------------------------------------------
# Reddit fetcher
# ---------------------------------------------------------------------------

def _fetch_reddit(client: httpx.Client, feed_cfg: dict) -> list[Item]:
    """Fetch hot posts from a Reddit subreddit via .json endpoint."""
    name = feed_cfg["name"]
    url = feed_cfg["url"]
    resp = client.get(url)
    resp.raise_for_status()
    data = resp.json()
    items: list[Item] = []
    for child in data.get("data", {}).get("children", []):
        post = child.get("data", {})
        title = (post.get("title") or "").strip()
        permalink = post.get("permalink", "")
        if not title or not permalink:
            continue
        post_url = f"https://www.reddit.com{permalink}"
        body = (post.get("selftext") or post.get("subreddit_name_prefixed") or "").strip()
        text = f"{title} {body}"
        created = post.get("created_utc", 0)
        try:
            pub_date = datetime.fromtimestamp(created, tz=timezone.utc).strftime("%Y-%m-%d")
        except (ValueError, OSError):
            pub_date = date.today().isoformat()
        items.append(
            Item(
                id=item_id_for_url(post_url),
                source="reddit",
                url=post_url,
                title=title,
                body=body,
                published=pub_date,
                cve_ids=_extract_cves(text),
            )
        )
    log.info("Fetched %d items from Reddit %s", len(items), name)
    return items


# ---------------------------------------------------------------------------
# Hacker News fetcher
# ---------------------------------------------------------------------------

def _fetch_hn(client: httpx.Client, feed_cfg: dict) -> list[Item]:
    """Fetch HN stories via Algolia search_by_date API."""
    name = feed_cfg["name"]
    url = feed_cfg["url"]
    resp = client.get(url)
    resp.raise_for_status()
    data = resp.json()
    items: list[Item] = []
    for hit in data.get("hits", []):
        title = (hit.get("title") or "").strip()
        story_url = hit.get("url") or f"https://news.ycombinator.com/item?id={hit.get('objectID', '')}"
        if not title:
            continue
        body = hit.get("story_text") or hit.get("comment_text") or ""
        body = body.strip()[:500]
        text = f"{title} {body}"
        created_at = hit.get("created_at", "")
        pub_date = _parse_iso_datetime(created_at)
        items.append(
            Item(
                id=item_id_for_url(story_url),
                source="hn",
                url=story_url,
                title=title,
                body=body,
                published=pub_date,
                cve_ids=_extract_cves(text),
            )
        )
    log.info("Fetched %d items from HN query %s", len(items), name)
    return items


# ---------------------------------------------------------------------------
# NVD CVE fetcher
# ---------------------------------------------------------------------------

def _fetch_nvd(client: httpx.Client, feed_cfg: dict) -> list[Item]:
    """Fetch CVEs from NVD 2.0 API by keyword search. Handles 403 gracefully."""
    name = feed_cfg["name"]
    queries = ["robot", "humanoid robot", "quadruped robot"]
    items: list[Item] = []
    for i, q in enumerate(queries):
        if i > 0:
            time.sleep(6)  # NVD rate limit: ~5 requests per 30 seconds without API key
        resp = client.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params={"keywordSearch": q, "resultsPerPage": 20},
        )
        if resp.status_code == 403:
            log.warning("NVD returned 403 for query %r — skipping", q)
            continue
        resp.raise_for_status()
        data = resp.json()
        for vuln in data.get("vulnerabilities", []):
            cve = vuln.get("cve", {})
            cve_id = cve.get("id", "")
            if not cve_id:
                continue
            descriptions = cve.get("descriptions", [])
            desc_en = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")
            pub_date = cve.get("published", "")
            items.append(
                Item(
                    id=item_id_for_url(cve_id),
                    source="nvd",
                    url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                    title=cve_id,
                    body=desc_en[:500],
                    published=_parse_iso_datetime(pub_date),
                    cve_ids=[cve_id] if re.match(r"^CVE-\d{4}-\d{4,}$", cve_id) else [],
                )
            )
    log.info("Fetched %d CVE items from NVD (%s)", len(items), name)
    return items


# ---------------------------------------------------------------------------
# GitHub Advisory fetcher
# ---------------------------------------------------------------------------

_ADVISORY_KEYWORDS = re.compile(r"robot|humanoid|quadruped", re.IGNORECASE)


def _fetch_github_advisory(client: httpx.Client, feed_cfg: dict) -> list[Item]:
    """Fetch GitHub advisories API, filter client-side for robot-related keywords."""
    name = feed_cfg["name"]
    items: list[Item] = []
    page = 1
    max_pages = 5
    while page <= max_pages:
        resp = client.get(
            "https://api.github.com/advisories",
            params={"per_page": 20, "page": page},
        )
        if resp.status_code == 403:
            log.warning("GitHub advisory API rate-limited — stopping at page %d", page)
            break
        resp.raise_for_status()
        advisories = resp.json()
        if not advisories:
            break
        for adv in advisories:
            summary = adv.get("summary", "") or ""
            description = adv.get("description", "") or ""
            text = f"{summary} {description}"
            if not _ADVISORY_KEYWORDS.search(text):
                continue
            ghsa_id = adv.get("ghsa_id", "")
            html_url = adv.get("html_url", "")
            published = adv.get("published_at", "")
            cve_list = [c.get("cve_id") for c in adv.get("cves", []) if c.get("cve_id")]
            if not cve_list and ghsa_id:
                cve_list = []
            items.append(
                Item(
                    id=item_id_for_url(html_url or ghsa_id),
                    source="github_advisory",
                    url=html_url,
                    title=summary[:200] if summary else ghsa_id,
                    body=description[:500] if description else summary[:500],
                    published=_parse_iso_datetime(published),
                    cve_ids=[c for c in cve_list if re.match(r"^CVE-\d{4}-\d{4,}$", c)],
                )
            )
        page += 1
        time.sleep(1)  # Be polite to GitHub API
    log.info("Fetched %d robot-related advisories from GitHub (%s)", len(items), name)
    return items


# ---------------------------------------------------------------------------
# Vendor page fetcher (hash-diff monitoring)
# ---------------------------------------------------------------------------

def _vendor_hashes_path(data_dir: Path) -> Path:
    """Path to the vendor page content hashes state file."""
    data_dir.mkdir(parents=True, exist_ok=True)
    return data_dir / ".vendor_hashes.json"


def _load_vendor_hashes(path: Path) -> dict[str, str]:
    """Load {url: sha256_hex} from the state file."""
    if path.exists():
        try:
            return json.loads(path.read_text())
        except (json.JSONDecodeError, OSError):
            log.warning("Failed to load vendor hashes from %s — starting fresh", path)
    return {}


def _save_vendor_hashes(path: Path, hashes: dict[str, str]) -> None:
    path.write_text(json.dumps(hashes, indent=2, ensure_ascii=False) + "\n")


def _fetch_vendor_page(
    client: httpx.Client,
    feed_cfg: dict,
    data_dir: Path,
) -> list[Item]:
    """Fetch a vendor page and emit an Item only if content hash changed.

    Content hash is tracked in data/.vendor_hashes.json to avoid emitting
    duplicate items on every run. This is a monitoring stub — full change
    detection arrives in a later issue.
    """
    name = feed_cfg["name"]
    url = feed_cfg["url"]
    hashes_file = _vendor_hashes_path(data_dir)
    hashes = _load_vendor_hashes(hashes_file)
    try:
        resp = client.get(url)
        resp.raise_for_status()
    except Exception as exc:
        log.warning("Vendor page %s failed: %s", name, exc)
        return []

    content = resp.text
    content_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()

    if hashes.get(url) == content_hash:
        log.debug("Vendor page %s unchanged (hash match) — skipping", name)
        return []

    hashes[url] = content_hash
    _save_vendor_hashes(hashes_file, hashes)

    # Extract title from <title> tag
    title_match = re.search(r"<title[^>]*>(.*?)</title>", content, re.IGNORECASE | re.DOTALL)
    title = html.unescape(title_match.group(1).strip()) if title_match else name

    # Extract body: strip tags, take first 500 chars
    body_text = _strip_html_tags(content)[:500]

    pub_date = date.today().isoformat()
    text = f"{title} {body_text}"

    log.info("Vendor page %s content changed — emitting item", name)
    return [
        Item(
            id=item_id_for_url(url),
            source="vendor_page",
            url=url,
            title=title,
            body=body_text,
            published=pub_date,
            cve_ids=_extract_cves(text),
        )
    ]


# ---------------------------------------------------------------------------
# Main fetch dispatch
# ---------------------------------------------------------------------------

def fetch(config: dict, data_dir: Path | None = None) -> list[Item]:
    """Fetch items from all configured feeds.

    Args:
        config: Must contain "feeds" key — list of dicts with type, name, url.
        data_dir: Project data directory (for vendor page hash state). Defaults
                  to ``data/`` relative to the project root.

    Returns:
        List of Items from all feeds that succeeded.

    Raises:
        FetchError: Only if ALL feeds failed.
    """
    if data_dir is None:
        data_dir = Path(__file__).resolve().parents[2] / "data"

    feeds: list[dict] = config.get("feeds", [])
    items: list[Item] = []
    errors: list[str] = []

    client = httpx.Client(
        follow_redirects=True,
        timeout=_TIMEOUT,
        headers={"User-Agent": _USER_AGENT},
    )

    try:
        for feed_cfg in feeds:
            feed_type = feed_cfg["type"]
            name = feed_cfg["name"]
            try:
                if feed_type in ("google_news", "press_rss"):
                    items.extend(_fetch_rss(client, feed_cfg))
                elif feed_type == "reddit":
                    items.extend(_fetch_reddit(client, feed_cfg))
                elif feed_type == "hn":
                    items.extend(_fetch_hn(client, feed_cfg))
                elif feed_type == "nvd":
                    items.extend(_fetch_nvd(client, feed_cfg))
                elif feed_type == "github_advisory":
                    items.extend(_fetch_github_advisory(client, feed_cfg))
                elif feed_type == "vendor_page":
                    items.extend(_fetch_vendor_page(client, feed_cfg, data_dir))
                else:
                    log.warning("Unknown feed type %r for %s — skipping", feed_type, name)
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
