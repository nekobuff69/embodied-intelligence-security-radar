"""RSS 2.0 feed emitter for Robot Security Radar."""

from __future__ import annotations

from email.utils import format_datetime
from pathlib import Path
from xml.sax.saxutils import escape, quoteattr

from .schema import Registry


def _rfc2822_date(iso_date: str) -> str:
    """Convert ISO date YYYY-MM-DD to RFC 2822 date string for RSS pubDate."""
    from datetime import date, datetime, timezone

    d = date.fromisoformat(iso_date)
    dt = datetime.combine(d, datetime.min.time(), tzinfo=timezone.utc)
    return format_datetime(dt, usegmt=True)


def _entry_updated(incident, registry: Registry) -> str:
    """max(status.as_of, latest item published) as ISO date string."""
    latest_published = ""
    for item_id in incident.item_ids:
        for item in registry.items:
            if item.id == item_id and item.published > latest_published:
                latest_published = item.published
    return max(incident.status.as_of, latest_published) if latest_published else incident.status.as_of


def _item_description(incident) -> str:
    """description = (ai_summary or title) + status line (returns unescaped text)."""
    lead = incident.ai_summary or incident.title
    return (
        f"{lead}. "
        f"Status: {incident.status.state} as of {incident.status.as_of}"
    )


def emit_feed(registry: Registry, site_dir: str | Path, site_url: str = "") -> None:
    """Write site/feed.xml — RSS 2.0 feed with one <item> per Incident."""
    from datetime import date

    site = Path(site_dir)
    feed_path = site / "feed.xml"

    # Build entries sorted by updated desc, cap 100
    entries: list[tuple[str, object]] = []
    for inc in registry.incidents:
        updated = _entry_updated(inc, registry)
        entries.append((updated, inc))
    entries.sort(key=lambda e: e[0], reverse=True)
    entries = entries[:100]

    lines: list[str] = []
    lines.append('<?xml version="1.0" encoding="UTF-8"?>')
    lines.append('<rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom">')
    lines.append("<channel>")
    lines.append(f"<title>{escape('Robot Security Radar')}</title>")

    link_text = escape(site_url) if site_url else ""
    lines.append(f"<link>{link_text}</link>")
    lines.append(
        f"<description>"
        f"{escape('Security incidents across embodied robots — buyer-first, strictly sourced')}"
        f"</description>"
    )
    lines.append(f"<language>en</language>")
    lines.append(f"<lastBuildDate>{_rfc2822_date(date.today().isoformat())}</lastBuildDate>")

    if site_url:
        lines.append(
            f'<atom:link rel="self" type="application/rss+xml" href={quoteattr(site_url)} />'
        )

    for updated, inc in entries:
        pub_date = _rfc2822_date(updated)
        detail_link = f"index.html?inc={inc.id}"
        if site_url:
            detail_link = f"{site_url.rstrip('/')}/{detail_link}"

        lines.append("<item>")
        lines.append(f"<title>{escape(inc.title)}</title>")
        lines.append(f"<link>{escape(detail_link)}</link>")
        lines.append(f"<guid isPermalink=\"false\">{escape(inc.id)}</guid>")
        lines.append(f"<pubDate>{pub_date}</pubDate>")
        lines.append(f"<category>{escape(inc.category)}</category>")
        lines.append(f"<description>{escape(_item_description(inc))}</description>")
        lines.append("</item>")

    lines.append("</channel>")
    lines.append("</rss>")
    lines.append("")

    feed_path.parent.mkdir(parents=True, exist_ok=True)
    feed_path.write_text("\n".join(lines))
