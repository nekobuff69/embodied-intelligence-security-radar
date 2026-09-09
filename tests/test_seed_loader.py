"""Tests for seed_loader: validate, merge, idempotency, collision, bad-seed, dry-run."""

from __future__ import annotations

import copy
import json
import tempfile
from pathlib import Path

import pytest

from radar.schema import Item, Registry, load_registry
from radar.seed_loader import load_seeds

FIXTURE_PATH = Path("data/fixtures/registry.json")
SEEDS_DIR = Path("data/seeds")


def _load_fixture() -> Registry:
    """Load a fresh copy of the fixture registry."""
    return load_registry(FIXTURE_PATH)


class TestSeedValidation:
    """All seed incidents must validate against schema.py."""

    def test_all_seeds_validate(self):
        """Loading seeds into an empty registry should succeed."""
        reg = Registry()
        merged, summary = load_seeds(SEEDS_DIR, reg)

        assert summary["rejected"] == 0, f"Rejected: {summary['rejected_details']}"
        assert summary["loaded"] >= 5, f"Expected >=5 incidents, got {summary['loaded']}"
        assert len(merged.incidents) >= 5
        assert len(merged.items) > 0

    def test_seed_incident_fields_present(self):
        """Every loaded incident must have the required schema fields."""
        reg = Registry()
        merged, _ = load_seeds(SEEDS_DIR, reg)

        for inc in merged.incidents:
            assert inc.id.startswith("INC-")
            assert inc.title
            assert inc.category in {"vuln", "attack", "safety"}
            assert inc.robot_class in {"humanoid", "quadruped", "consumer"}
            assert inc.vendor
            assert inc.status.state in {"disclosed", "unpatched", "patched", "exploited_in_wild", "resolved"}
            assert inc.status.evidence_url.startswith("http")
            assert inc.status.as_of
            assert inc.first_seen
            assert inc.last_checked
            assert inc.item_ids  # must reference at least one item

    def test_seed_items_validate(self):
        """Every loaded item must have the required schema fields."""
        reg = Registry()
        merged, _ = load_seeds(SEEDS_DIR, reg)

        for item in merged.items:
            assert item.id.startswith("itm-")
            assert item.url.startswith("http")
            assert item.title.strip()
            assert item.published

    def test_flagship_unitree_ble_present(self):
        """The Unitree BLE flagship incident must be in the seed set."""
        reg = Registry()
        merged, _ = load_seeds(SEEDS_DIR, reg)

        titles = [inc.title.lower() for inc in merged.incidents]
        assert any("unitree" in t and "ble" in t and "command injection" in t for t in titles), \
            "Flagship Unitree BLE incident not found in seed set"

    def test_seeds_have_real_urls(self):
        """Seed items should reference real URLs (spot-check key domains)."""
        reg = Registry()
        merged, _ = load_seeds(SEEDS_DIR, reg)

        urls = {item.url for item in merged.items}
        # At least some should be from known real domains
        real_domains = ["github.com", "ieee.org", "techcrunch.com", "cisa.gov", "nvd.nist.gov"]
        found = [d for d in real_domains if any(d in u for u in urls)]
        assert len(found) >= 3, f"Expected >=3 real domains, found: {found}"


class TestMergeIntoFixture:
    """Seeds merge cleanly into a copy of the fixture registry."""

    def test_merge_adds_seeds(self):
        """Seeds should be added to the fixture registry without errors."""
        reg = _load_fixture()
        initial_incidents = len(reg.incidents)
        initial_items = len(reg.items)

        merged, summary = load_seeds(SEEDS_DIR, reg)

        assert summary["rejected"] == 0
        assert summary["loaded"] >= 5
        assert len(merged.incidents) == initial_incidents + summary["loaded"]
        assert len(merged.items) >= initial_items

    def test_fixture_items_preserved(self):
        """Fixture items should remain after merging seeds."""
        reg = _load_fixture()
        fixture_urls = {item.url for item in reg.items}

        merged, _ = load_seeds(SEEDS_DIR, reg)

        for url in fixture_urls:
            assert any(item.url == url for item in merged.items), \
                f"Fixture item with url {url} lost after merge"


class TestIdempotency:
    """Second load must add 0 incidents and 0 items."""

    def test_second_load_adds_zero(self):
        reg = _load_fixture()
        merged, summary1 = load_seeds(SEEDS_DIR, reg)
        count_incidents = len(merged.incidents)
        count_items = len(merged.items)

        merged2, summary2 = load_seeds(SEEDS_DIR, merged)

        assert summary2["loaded"] == 0, f"Second load added {summary2['loaded']} incidents"
        assert len(merged2.incidents) == count_incidents
        assert len(merged2.items) == count_items

    def test_triple_load_stable(self):
        """Three consecutive loads produce identical registry state."""
        reg = Registry()
        merged, _ = load_seeds(SEEDS_DIR, reg)
        count1 = len(merged.incidents)

        merged, _ = load_seeds(SEEDS_DIR, merged)
        assert len(merged.incidents) == count1

        merged, _ = load_seeds(SEEDS_DIR, merged)
        assert len(merged.incidents) == count1


class TestDuplicateItemCollision:
    """Items whose URLs already exist in the registry are skipped."""

    def test_url_collision_skips_item(self):
        """An item with a URL already in the registry should not be re-added."""
        reg = _load_fixture()
        # Add a seed item's URL to the fixture
        seeds_raw = json.loads((SEEDS_DIR / "seed_incidents.json").read_text())
        first_seed_url = seeds_raw["items"][0]["url"]
        first_seed_title = seeds_raw["items"][0]["title"]

        from radar.schema import Item
        collision_item = Item(
            id="itm-collision-test",
            source="google_news",
            url=first_seed_url,
            title=first_seed_title,
            body="Collision test body",
            published="2026-01-01",
            cve_ids=[],
        )
        reg.items.append(collision_item)

        merged, summary = load_seeds(SEEDS_DIR, reg)

        # The colliding item should be skipped, not duplicated
        url_count = sum(1 for i in merged.items if i.url == first_seed_url)
        assert url_count == 1, f"Expected 1 item with url {first_seed_url}, got {url_count}"

    def test_incident_references_mapped_existing_item(self):
        """If a seed item URL collides, the incident should reference the existing item."""
        reg = _load_fixture()
        seeds_raw = json.loads((SEEDS_DIR / "seed_incidents.json").read_text())

        # Find the first seed incident's items
        first_inc = seeds_raw["incidents"][0]
        first_item_id = first_inc["item_ids"][0]
        first_item_url = next(
            i["url"] for i in seeds_raw["items"] if i["id"] == first_item_id
        )

        # Add item with that URL to fixture
        from radar.schema import Item
        existing = Item(
            id="itm-exists-already",
            source="google_news",
            url=first_item_url,
            title="Pre-existing item",
            body="Already here",
            published="2026-01-01",
            cve_ids=[],
        )
        reg.items.append(existing)

        merged, summary = load_seeds(SEEDS_DIR, reg)

        # The incident's item_ids should now reference itm-exists-already
        inc = next((i for i in merged.incidents if i.title == first_inc["title"]), None)
        assert inc is not None, "First seed incident not loaded"
        assert "itm-exists-already" in inc.item_ids, \
            f"Expected itm-exists-already in item_ids, got {inc.item_ids}"


class TestBadSeedRejection:
    """Crafted bad seeds (e.g., status without evidence) are rejected with reason."""

    def test_status_without_evidence_rejected(self):
        """An incident with a status missing evidence_url must be rejected."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)
            bad_seed = {
                "incidents": [
                    {
                        "id": "INC-BAD1",
                        "title": "Bad incident with no evidence",
                        "category": "vuln",
                        "robot_class": "quadruped",
                        "vendor": "TestVendor",
                        "severity": {"source": "estimated", "value": "high"},
                        "status": {"state": "unpatched"},
                        "first_seen": "2026-01-01",
                        "last_checked": "2026-09-09",
                        "item_ids": ["itm-bad-item-1"],
                    }
                ],
                "items": [
                    {
                        "id": "itm-bad-item-1",
                        "source": "google_news",
                        "url": "https://example.com/bad-seed-test",
                        "title": "Bad seed test item",
                        "body": "Test body",
                        "published": "2026-01-01",
                        "cve_ids": [],
                    }
                ],
            }
            (tmpdir / "seed_incidents.json").write_text(json.dumps(bad_seed))

            reg = Registry()
            merged, summary = load_seeds(tmpdir, reg)

            assert summary["rejected"] == 1
            assert summary["rejected_details"][0]["id"] == "INC-BAD1"
            assert "evidence_url" in summary["rejected_details"][0]["reason"].lower() or \
                   "required" in summary["rejected_details"][0]["reason"].lower()

    def test_invalid_category_rejected(self):
        """An incident with an invalid category must be rejected."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)
            bad_seed = {
                "incidents": [
                    {
                        "id": "INC-BAD2",
                        "title": "Bad incident with invalid category",
                        "category": "INVALID",
                        "robot_class": "quadruped",
                        "vendor": "TestVendor",
                        "severity": {"source": "estimated", "value": "high"},
                        "status": {
                            "state": "unpatched",
                            "evidence_url": "https://example.com/evidence",
                            "as_of": "2026-09-09",
                            "note": "Test",
                        },
                        "first_seen": "2026-01-01",
                        "last_checked": "2026-09-09",
                        "item_ids": ["itm-bad-item-2"],
                    }
                ],
                "items": [
                    {
                        "id": "itm-bad-item-2",
                        "source": "google_news",
                        "url": "https://example.com/bad-category-test",
                        "title": "Bad category test item",
                        "body": "Test body",
                        "published": "2026-01-01",
                        "cve_ids": [],
                    }
                ],
            }
            (tmpdir / "seed_incidents.json").write_text(json.dumps(bad_seed))

            reg = Registry()
            merged, summary = load_seeds(tmpdir, reg)

            assert summary["rejected"] == 1
            assert "category" in summary["rejected_details"][0]["reason"].lower()

    def test_malformed_cve_rejected(self):
        """An item with malformed CVE id must cause rejection."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)
            bad_seed = {
                "incidents": [
                    {
                        "id": "INC-BAD3",
                        "title": "Bad incident with malformed CVE",
                        "category": "vuln",
                        "robot_class": "quadruped",
                        "vendor": "TestVendor",
                        "severity": {"source": "estimated", "value": "high"},
                        "status": {
                            "state": "unpatched",
                            "evidence_url": "https://example.com/evidence",
                            "as_of": "2026-09-09",
                            "note": "Test",
                        },
                        "first_seen": "2026-01-01",
                        "last_checked": "2026-09-09",
                        "item_ids": ["itm-bad-cve-item"],
                    }
                ],
                "items": [
                    {
                        "id": "itm-bad-cve-item",
                        "source": "google_news",
                        "url": "https://example.com/bad-cve-test",
                        "title": "Bad CVE test item",
                        "body": "Test body",
                        "published": "2026-01-01",
                        "cve_ids": ["CVE-1234"],
                    }
                ],
            }
            (tmpdir / "seed_incidents.json").write_text(json.dumps(bad_seed))

            reg = Registry()
            merged, summary = load_seeds(tmpdir, reg)

            # Item with bad CVE should fail validation → incident rejected
            assert summary["rejected"] == 1
            assert "unmapped" in summary["rejected_details"][0]["reason"].lower() or \
                   "cve" in summary["rejected_details"][0]["reason"].lower()


class TestDryRun:
    """Dry-run validates and reports without writing."""

    def test_dry_run_same_counts(self):
        """Dry-run returns same loaded/rejected counts as actual load."""
        reg = _load_fixture()
        _, summary_actual = load_seeds(SEEDS_DIR, reg)

        reg2 = _load_fixture()
        _, summary_dry = load_seeds(SEEDS_DIR, reg2, dry_run=True)

        assert summary_dry["loaded"] == summary_actual["loaded"]
        assert summary_dry["rejected"] == summary_actual["rejected"]

    def test_dry_run_does_not_mutate(self):
        """Dry-run must not modify the registry."""
        reg = _load_fixture()
        original_incidents = len(reg.incidents)
        original_items = len(reg.items)

        load_seeds(SEEDS_DIR, reg, dry_run=True)

        assert len(reg.incidents) == original_incidents
        assert len(reg.items) == original_items

    def test_dry_run_with_bad_seed(self):
        """Dry-run still reports rejections for invalid seeds."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)
            bad_seed = {
                "incidents": [
                    {
                        "id": "INC-DRY-BAD",
                        "title": "Dry run bad seed",
                        "category": "vuln",
                        "robot_class": "quadruped",
                        "vendor": "TestVendor",
                        "severity": {"source": "estimated", "value": "high"},
                        "status": {"state": "unpatched"},
                        "first_seen": "2026-01-01",
                        "last_checked": "2026-09-09",
                        "item_ids": ["itm-dry-bad-item"],
                    }
                ],
                "items": [
                    {
                        "id": "itm-dry-bad-item",
                        "source": "google_news",
                        "url": "https://example.com/dry-run-test",
                        "title": "Dry run test item",
                        "body": "Test body",
                        "published": "2026-01-01",
                        "cve_ids": [],
                    }
                ],
            }
            (tmpdir / "seed_incidents.json").write_text(json.dumps(bad_seed))

            reg = Registry()
            merged, summary = load_seeds(tmpdir, reg, dry_run=True)

            assert summary["rejected"] == 1
            assert len(reg.incidents) == 0  # dry run, nothing added


class TestStableIds:
    """Seed incidents preserve their given IDs when free."""

    def test_seed_ids_preserved(self):
        """Incident IDs from the seed file are preserved in the registry."""
        reg = Registry()
        merged, _ = load_seeds(SEEDS_DIR, reg)

        for inc in merged.incidents:
            assert inc.id.startswith("INC-")
            # IDs should be sequential from INC-0001
            num = int(inc.id.split("-")[1])
            assert 1 <= num <= 20

    def test_next_id_when_collision(self):
        """If a seed ID collides, the incident gets the next available ID
        while the original incident stays untouched. Item URLs must NOT collide
        so that idempotency doesn't legitimately load zero."""
        from radar.schema import Incident, Severity, Status

        # Fresh registry: no item URL collisions with seeds, but INC-0001 occupied
        reg = Registry()
        collision_item = Item(
            id="itm-collide-test",
            source="google_news",
            url="https://example.com/collide-test",
            title="Collision test item",
            body="Synthetic item for collision test",
            published="2026-01-01",
            cve_ids=[],
        )
        reg.items.append(collision_item)
        reg.incidents.append(Incident(
            id="INC-0001",
            title="Collision test",
            category="safety",
            robot_class="humanoid",
            vendor="Test",
            severity=Severity(source="estimated", value="low"),
            status=Status(state="disclosed", evidence_url="https://example.com", as_of="2026-01-01"),
            first_seen="2026-01-01",
            last_checked="2026-09-09",
            item_ids=["itm-collide-test"],
        ))

        merged, summary = load_seeds(SEEDS_DIR, reg)

        # All 7 seeds load (item URLs don't collide)
        assert summary["loaded"] == 7, f"Expected 7 loaded, got {summary['loaded']}"
        # The collision-test incident is untouched
        assert any(inc.id == "INC-0001" and inc.title == "Collision test" for inc in merged.incidents)
        # No seed kept INC-0001 — all 7 got remapped to INC-0002..INC-0008
        seed_ids = {inc.id for inc in merged.incidents if inc.title != "Collision test"}
        assert seed_ids == {"INC-0002", "INC-0003", "INC-0004", "INC-0005", "INC-0006", "INC-0007", "INC-0008"}
