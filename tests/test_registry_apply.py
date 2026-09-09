"""Tests for registry apply_items idempotent dedup."""

import pytest

from radar.registry import apply_items
from radar.schema import Item, Registry, item_id_for_url


def _item(url: str = "https://example.com/test", title: str = "Test item") -> Item:
    """Create a valid test Item."""
    return Item(
        id=item_id_for_url(url),
        source="google_news",
        url=url,
        title=title,
        body="Test body",
        published="2026-01-01",
        cve_ids=[],
    )


class TestApplyIdempotent:
    """apply_items must be idempotent — same payload twice adds 0 on second call."""

    def test_second_apply_adds_zero(self):
        reg = Registry()
        items = [
            _item("https://example.com/a", "Item A"),
            _item("https://example.com/b", "Item B"),
        ]
        reg, added = apply_items(reg, items)
        assert added == 2
        assert len(reg.items) == 2

        reg2, added2 = apply_items(reg, items)
        assert added2 == 0
        assert len(reg2.items) == 2

    def test_single_item_idempotent(self):
        reg = Registry()
        item = _item("https://example.com/single")
        reg, added = apply_items(reg, [item])
        assert added == 1

        reg, added = apply_items(reg, [item])
        assert added == 0
        assert len(reg.items) == 1


class TestUrlDedup:
    """Items with duplicate URLs are skipped; different URLs are added."""

    def test_different_urls_added(self):
        reg = Registry()
        items = [
            _item("https://example.com/1", "First"),
            _item("https://example.com/2", "Second"),
        ]
        reg, added = apply_items(reg, items)
        assert added == 2
        assert {i.url for i in reg.items} == {"https://example.com/1", "https://example.com/2"}

    def test_mixed_new_and_duplicate(self):
        reg = Registry()
        items_a = [_item("https://example.com/1", "First"), _item("https://example.com/2", "Second")]
        reg, added = apply_items(reg, items_a)
        assert added == 2

        # Mix: one duplicate, one new
        items_b = [_item("https://example.com/1", "First again"), _item("https://example.com/3", "Third")]
        reg, added = apply_items(reg, items_b)
        assert added == 1
        assert len(reg.items) == 3

    def test_all_duplicates(self):
        reg = Registry()
        items = [_item("https://example.com/x", "X")]
        reg, added = apply_items(reg, items)
        assert added == 1

        reg, added = apply_items(reg, items)
        assert added == 0
        assert len(reg.items) == 1


class TestFixtureDedup:
    """Dedup against the existing fixture registry items."""

    def test_fixture_url_not_readded(self):
        from radar.schema import load_registry
        from pathlib import Path

        fixture = load_registry(Path("data/fixtures/registry.json"))
        fixture_urls = [i.url for i in fixture.items]
        assert len(fixture_urls) > 0

        reg = Registry()
        # Add fixture items
        reg, added = apply_items(reg, fixture.items)
        assert added == len(fixture.items)

        # Try adding the same items again — should add 0
        reg, added = apply_items(reg, fixture.items)
        assert added == 0
        assert len(reg.items) == len(fixture.items)


class TestRegistryEmpty:
    def test_empty_items(self):
        reg = Registry()
        reg, added = apply_items(reg, [])
        assert added == 0
        assert len(reg.items) == 0


class TestRegistryValidation:
    """Malformed items raise ValueError via schema validation."""

    def test_empty_title_raises(self):
        """Item with empty title fails schema validation."""
        with pytest.raises(ValueError, match="item.title must not be empty"):
            Item(
                id="itm-test00000001",
                source="google_news",
                url="https://example.com/empty-title",
                title="",
                body="Some body",
                published="2026-01-01",
                cve_ids=[],
            )

    def test_invalid_source_raises(self):
        """Item with invalid source fails schema validation."""
        with pytest.raises(ValueError, match="item.source"):
            Item(
                id="itm-test00000002",
                source="invalid_source",
                url="https://example.com/bad-source",
                title="Valid title",
                body="Some body",
                published="2026-01-01",
                cve_ids=[],
            )

    def test_invalid_url_raises(self):
        """Item with non-http URL fails schema validation."""
        with pytest.raises(ValueError, match="item.url"):
            Item(
                id="itm-test00000003",
                source="google_news",
                url="ftp://example.com/bad-url",
                title="Valid title",
                body="Some body",
                published="2026-01-01",
                cve_ids=[],
            )

    def test_invalid_date_raises(self):
        """Item with invalid date fails schema validation."""
        with pytest.raises(ValueError, match="item.published"):
            Item(
                id="itm-test00000004",
                source="google_news",
                url="https://example.com/bad-date",
                title="Valid title",
                body="Some body",
                published="not-a-date",
                cve_ids=[],
            )

    def test_invalid_cve_id_raises(self):
        """Item with malformed CVE ID fails schema validation."""
        with pytest.raises(ValueError, match="malformed CVE id"):
            Item(
                id="itm-test00000005",
                source="google_news",
                url="https://example.com/bad-cve",
                title="Valid title",
                body="Some body",
                published="2026-01-01",
                cve_ids=["CVE-1234"],
            )
