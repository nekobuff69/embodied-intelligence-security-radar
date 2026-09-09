"""Tests for the retroactive registry pruning pipeline.

Covers:
- Stale items (>3y old, malformed date) dismissed
- Commentary/podcast items dismissed
- Ineligible incidents (Unknown vendor, no CVE) demoted
- Seed-protected incidents untouched
- CVE-bearing incidents kept
- dismiss_items detaches items and deletes emptied incidents
- Blocklist persistence shape
"""

from __future__ import annotations

import json
import tempfile
from datetime import date, timedelta
from pathlib import Path

import pytest

from radar.prune import prune
from radar.registry import dismiss_items, load_dismissed, save_dismissed
from radar.schema import (
    Incident,
    Item,
    Registry,
    Severity,
    Status,
)


# ── Helpers ──────────────────────────────────────────────────────────


def _item(
    url: str = "https://example.com/test-item",
    title: str = "Test item title",
    body: str = "Test item body text",
    published: str = "2026-09-01",
    cve_ids: list[str] | None = None,
    source: str = "press_rss",
) -> Item:
    return Item(
        id="itm-" + url.split("/")[-1].replace("-", "")[:12],
        source=source,
        url=url,
        title=title,
        body=body,
        published=published,
        cve_ids=cve_ids or [],
    )


def _incident(
    inc_id: str = "INC-0001",
    vendor: str = "TestVendor",
    model: str | None = "TestModel",
    state: str = "disclosed",
    evidence_url: str = "https://example.com/advisory",
    as_of: str = "2026-08-01",
    item_ids: list[str] | None = None,
) -> Incident:
    iid_list = item_ids or ["itm-default"]
    return Incident(
        id=inc_id,
        title=f"Test incident {inc_id}",
        category="vuln",
        robot_class="quadruped",
        vendor=vendor,
        model=model,
        severity=Severity(source="estimated", value="high"),
        status=Status(state=state, evidence_url=evidence_url, as_of=as_of),
        first_seen="2026-07-01",
        last_checked=as_of,
        item_ids=iid_list,
    )


def _registry_with(
    incidents: list[Incident] | None = None,
    items: list[Item] | None = None,
) -> Registry:
    reg = Registry()
    if incidents:
        reg.incidents.extend(incidents)
    if items:
        reg.items.extend(items)
    return reg


def _make_seeds(_dir_ignored, item_urls: list[str]) -> Path:
    """Create a minimal seed_incidents.json in a fresh temp dir.

    Callers historically pass tmp_path or a date object as the first arg;
    the seeds dir is tempfile-backed so either is harmless.
    """
    import tempfile

    seeds_dir = Path(tempfile.mkdtemp()) / "seeds"
    seeds_dir.mkdir(parents=True)
    items = [
        {"id": f"itm-seed-{i}", "url": url, "title": f"Seed item {i}", "body": "...", "published": "2025-01-01"}
        for i, url in enumerate(item_urls)
    ]
    data = {"incidents": [{"id": "SEED-0001", "title": "Seed incident"}], "items": items}
    (seeds_dir / "seed_incidents.json").write_text(json.dumps(data))
    return seeds_dir


# ═══════════════════════════════════════════════════════════════════
# Stale items
# ═══════════════════════════════════════════════════════════════════


class TestStaleItems:
    """Items older than 3 years or with malformed dates are dismissed."""

    def test_old_item_dismissed(self):
        """Published in 1998 → stale → dismissed."""
        today = date(2026, 9, 9)
        old_item = _item(
            url="https://example.com/old",
            title="Old article",
            body="From long ago",
            published="1998-05-15",
        )
        inc = _incident(item_ids=[old_item.id])
        reg = _registry_with([inc], [old_item])
        seeds_dir = _make_seeds(today, [])

        reg, summary = prune(reg, seeds_dir, today=today)

        assert summary["dismissed_items"] == 1
        assert "https://example.com/old" in summary["dismissed_urls"]
        assert len(reg.items) == 0

    def test_malformed_date_rejected_at_schema_boundary(self):
        """Non-ISO dates can never enter a Registry — schema.py rejects the
        Item at construction, so the pipeline (and prune) never sees one.
        Fetchers normalize malformed dates to today before constructing Items.
        """
        import pytest

        today = date(2026, 9, 9)
        with pytest.raises(ValueError, match="published"):
            _item(
                url="https://example.com/bad-date",
                title="Bad date article",
                body="Some text",
                published="not-a-date",
            )

    def test_recent_item_kept(self):
        """Item published recently → not stale → kept."""
        today = date(2026, 9, 9)
        item = _item(
            url="https://example.com/recent",
            title="Recent article",
            body="From last month",
            published="2026-08-15",
        )
        inc = _incident(item_ids=[item.id])
        reg = _registry_with([inc], [item])
        seeds_dir = _make_seeds(today, [])

        reg, summary = prune(reg, seeds_dir, today=today)

        assert summary["dismissed_items"] == 0
        assert len(reg.items) == 1


# ═══════════════════════════════════════════════════════════════════
# Commentary items
# ═══════════════════════════════════════════════════════════════════


class TestCommentaryItems:
    """Podcast/opinion/entertainment items are dismissed."""

    def test_podcast_item_dismissed(self):
        """Item with 'podcast' in title → dismissed."""
        today = date(2026, 9, 9)
        item = _item(
            url="https://example.com/podcast",
            title="Robot Security Podcast Episode 42",
            body="This week on the podcast we discuss robot security",
            published="2026-08-01",
        )
        inc = _incident(item_ids=[item.id])
        reg = _registry_with([inc], [item])
        seeds_dir = _make_seeds(today, [])

        reg, summary = prune(reg, seeds_dir, today=today)

        assert summary["dismissed_items"] == 1
        assert "https://example.com/podcast" in summary["dismissed_urls"]

    def test_interview_item_dismissed(self):
        """Item with 'interview' in body → dismissed."""
        today = date(2026, 9, 9)
        item = _item(
            url="https://example.com/interview",
            title="Robot CEO speaks",
            body="An interview with the CEO about robot safety",
            published="2026-08-01",
        )
        inc = _incident(item_ids=[item.id])
        reg = _registry_with([inc], [item])
        seeds_dir = _make_seeds(today, [])

        reg, summary = prune(reg, seeds_dir, today=today)

        assert summary["dismissed_items"] == 1


# ═══════════════════════════════════════════════════════════════════
# Seed protection
# ═══════════════════════════════════════════════════════════════════


class TestSeedProtection:
    """Incidents with seed-URL items are never touched."""

    def test_seed_protected_unknown_vendor_kept(self):
        """Seed-protected incident with Unknown vendor → NOT demoted."""
        today = date(2026, 9, 9)
        seed_url = "https://github.com/example/seed-advisory"
        item = _item(
            url=seed_url,
            title="Seed advisory",
            body="Security advisory for Unknown vendor robot",
            published="2026-01-15",
        )
        inc = _incident(
            inc_id="INC-1000",
            vendor="Unknown",
            model=None,
            item_ids=[item.id],
        )
        reg = _registry_with([inc], [item])
        seeds_dir = _make_seeds(today, [seed_url])

        reg, summary = prune(reg, seeds_dir, today=today)

        assert summary["demoted_incidents"] == 0
        assert summary["kept_incidents"] == 1
        assert any(i.id == "INC-1000" for i in reg.incidents)


# ═══════════════════════════════════════════════════════════════════
# Ineligible incident demotion
# ═══════════════════════════════════════════════════════════════════


class TestIneligibleDemotion:
    """Non-seed incidents with Unknown vendor and no CVE items → demoted."""

    def test_unknown_vendor_no_cve_demoted(self):
        """Unknown vendor, no CVE items → incident deleted, items kept."""
        today = date(2026, 9, 9)
        item = _item(
            url="https://example.com/unknown-vendor-article",
            title="Some robot article",
            body="About an unknown vendor robot",
            published="2026-08-01",
        )
        inc = _incident(
            inc_id="INC-2000",
            vendor="Unknown",
            model=None,
            item_ids=[item.id],
        )
        reg = _registry_with([inc], [item])
        seeds_dir = _make_seeds(today, [])

        reg, summary = prune(reg, seeds_dir, today=today)

        assert summary["demoted_incidents"] == 1
        assert summary["kept_incidents"] == 0
        assert len(reg.incidents) == 0
        # Item kept on wire (not dismissed, just orphaned from incident)
        assert len(reg.items) == 1

    def test_known_vendor_kept(self):
        """Known vendor → incident kept even without CVE."""
        today = date(2026, 9, 9)
        item = _item(
            url="https://example.com/known-vendor",
            title="Unitree robot issue",
            body="Issue with Unitree robot",
            published="2026-08-01",
        )
        inc = _incident(
            inc_id="INC-3000",
            vendor="Unitree",
            model="Go2",
            item_ids=[item.id],
        )
        reg = _registry_with([inc], [item])
        seeds_dir = _make_seeds(today, [])

        reg, summary = prune(reg, seeds_dir, today=today)

        assert summary["demoted_incidents"] == 0
        assert summary["kept_incidents"] == 1

    def test_cve_incident_kept(self):
        """Incident with CVE item → kept even with Unknown vendor."""
        today = date(2026, 9, 9)
        item = _item(
            url="https://example.com/cve-report",
            title="CVE-2026-99999 affects robot",
            body="Critical vulnerability",
            published="2026-08-01",
            cve_ids=["CVE-2026-99999"],
        )
        inc = _incident(
            inc_id="INC-4000",
            vendor="Unknown",
            model=None,
            item_ids=[item.id],
        )
        reg = _registry_with([inc], [item])
        seeds_dir = _make_seeds(today, [])

        reg, summary = prune(reg, seeds_dir, today=today)

        assert summary["demoted_incidents"] == 0
        assert summary["kept_incidents"] == 1

    def test_empty_vendor_demoted(self):
        """Empty-string vendor with no CVE → demoted."""
        today = date(2026, 9, 9)
        item = _item(
            url="https://example.com/empty-vendor",
            title="Robot issue",
            body="Some issue",
            published="2026-08-01",
        )
        inc = _incident(
            inc_id="INC-5000",
            vendor="",
            model=None,
            item_ids=[item.id],
        )
        reg = _registry_with([inc], [item])
        seeds_dir = _make_seeds(today, [])

        reg, summary = prune(reg, seeds_dir, today=today)

        assert summary["demoted_incidents"] == 1
        assert summary["kept_incidents"] == 0


# ═══════════════════════════════════════════════════════════════════
# dismiss_items
# ═══════════════════════════════════════════════════════════════════


class TestDismissItems:
    """dismiss_items removes items and cleans up incidents."""

    def test_removes_item_and_deletes_emptied_incident(self):
        """Dismissing all items of an incident deletes the incident."""
        today = date(2026, 9, 9)
        item1 = _item(url="https://example.com/junk1", title="Junk 1", body="Junk", published="2026-08-01")
        item2 = _item(url="https://example.com/keep", title="Keep", body="Keep this", published="2026-08-01")
        inc = _incident(
            inc_id="INC-6000",
            item_ids=[item1.id, item2.id],
        )
        reg = _registry_with([inc], [item1, item2])

        result = dismiss_items(reg, {"https://example.com/junk1"})

        assert result["removed_items"] == 1
        # Incident still has item2 → kept
        assert result["removed_incidents"] == 0
        assert len(reg.incidents) == 1
        assert inc.item_ids == [item2.id]

    def test_dismiss_all_items_deletes_incident(self):
        """Dismissing all items of an incident deletes it."""
        item1 = _item(url="https://example.com/junk1", title="Junk 1", body="Junk", published="2026-08-01")
        item2 = _item(url="https://example.com/junk2", title="Junk 2", body="Junk", published="2026-08-01")
        inc = _incident(
            inc_id="INC-7000",
            item_ids=[item1.id, item2.id],
        )
        reg = _registry_with([inc], [item1, item2])

        result = dismiss_items(reg, {"https://example.com/junk1", "https://example.com/junk2"})

        assert result["removed_items"] == 2
        assert result["removed_incidents"] == 1
        assert len(reg.incidents) == 0
        assert len(reg.items) == 0

    def test_dismiss_unrelated_urls_noop(self):
        """Dismissing URLs not in registry → no-op."""
        item = _item(url="https://example.com/real", title="Real", body="Real", published="2026-08-01")
        inc = _incident(item_ids=[item.id])
        reg = _registry_with([inc], [item])

        result = dismiss_items(reg, {"https://example.com/not-here"})

        assert result["removed_items"] == 0
        assert result["removed_incidents"] == 0
        assert len(reg.items) == 1

    def test_detach_preserves_other_incident_items(self):
        """Dismissing one item from a multi-item incident keeps others."""
        items = [
            _item(url=f"https://example.com/item-{i}", title=f"Item {i}", body="Body", published="2026-08-01")
            for i in range(5)
        ]
        inc = _incident(
            inc_id="INC-8000",
            item_ids=[it.id for it in items],
        )
        reg = _registry_with([inc], items)

        # Dismiss only the first item
        result = dismiss_items(reg, {items[0].url})

        assert result["removed_items"] == 1
        assert result["removed_incidents"] == 0
        assert len(inc.item_ids) == 4
        assert items[0].id not in inc.item_ids


# ═══════════════════════════════════════════════════════════════════
# Blocklist persistence
# ═══════════════════════════════════════════════════════════════════


class TestBlocklistPersistence:
    """load_dismissed / save_dismissed round-trip correctly."""

    def test_save_and_load(self):
        """Saved URLs can be loaded back."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "dismissed.json"
            urls = {"https://a.com", "https://b.com"}
            save_dismissed(path, urls)
            loaded = load_dismissed(path)
            assert loaded == urls

    def test_load_nonexistent_returns_empty(self):
        """Loading from non-existent file returns empty set."""
        result = load_dismissed(Path("/nonexistent/path.json"))
        assert result == set()

    def test_prune_returns_urls_for_blocklist(self):
        """Prune summary contains dismissed_urls suitable for persistence."""
        today = date(2026, 9, 9)
        stale = _item(
            url="https://example.com/stale",
            title="Stale",
            body="Old",
            published="2000-01-01",
        )
        inc = _incident(item_ids=[stale.id])
        reg = _registry_with([inc], [stale])
        seeds_dir = _make_seeds(today, [])

        _, summary = prune(reg, seeds_dir, today=today)

        assert isinstance(summary["dismissed_urls"], list)
        assert "https://example.com/stale" in summary["dismissed_urls"]
        # Shape is JSON-serializable list
        json.dumps(summary["dismissed_urls"])
