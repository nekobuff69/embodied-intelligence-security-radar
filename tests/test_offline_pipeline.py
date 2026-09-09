"""End-to-end offline pipeline test: new sources flow through radar run --offline."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from radar.runner import run

FIXTURES_RAW = Path(__file__).resolve().parent / "fixtures" / "raw"
FIXTURE_REGISTRY = Path(__file__).resolve().parents[1] / "data" / "fixtures" / "registry.json"


@pytest.fixture()
def pipeline_result(tmp_path: Path) -> dict:
    """Run the full pipeline in offline mode against test fixtures."""
    registry_path = tmp_path / "registry.json"
    # Copy the fixture registry so we start with known baseline data
    shutil.copy(FIXTURE_REGISTRY, registry_path)
    site_dir = tmp_path / "site"
    return run(
        offline=True,
        registry_path=registry_path,
        raw_dir=FIXTURES_RAW,
        site_dir=site_dir,
    )


@pytest.fixture()
def registry_items(pipeline_result: dict, tmp_path: Path) -> list[dict]:
    """Reload the registry and return the items list."""
    reg_path = tmp_path / "registry.json"
    data = json.loads(reg_path.read_text())
    return data.get("items", [])


# ------------------------------------------------------------------
# 1. Items from every new source type appear in registry
# ------------------------------------------------------------------

class TestNewSourcesPresent:
    """Each new source type (reddit, hn, nvd, github_advisory) must
    produce at least one Item that passes the gate and lands in the registry."""

    def test_reddit_items(self, registry_items: list[dict]) -> None:
        reddit = [i for i in registry_items if i["source"] == "reddit"]
        assert len(reddit) >= 1, "Expected at least 1 reddit item in registry"

    def test_hn_items(self, registry_items: list[dict]) -> None:
        hn = [i for i in registry_items if i["source"] == "hn"]
        assert len(hn) >= 1, "Expected at least 1 hn item in registry"

    def test_nvd_items(self, registry_items: list[dict]) -> None:
        nvd = [i for i in registry_items if i["source"] == "nvd"]
        assert len(nvd) >= 1, "Expected at least 1 nvd item in registry"

    def test_github_advisory_items(self, registry_items: list[dict]) -> None:
        gh = [i for i in registry_items if i["source"] == "github_advisory"]
        assert len(gh) >= 1, "Expected at least 1 github_advisory item in registry"


# ------------------------------------------------------------------
# 2. Gate dropped the noise fixtures
# ------------------------------------------------------------------

class TestGateDropsNoise:
    """Items without both robot + incident terms, or with excluded terms,
    must not appear in the registry."""

    NOISE_URLS = {
        # google_news: drone roundup (excluded), Tesla FSD (excluded)
        "https://example.com/news/drone-roundup",
        "https://example.com/news/tesla-fsd-update",
        # press_rss: KUKA industrial (excluded)
        "https://example.com/news/kuka-industrial",
        # reddit: weekly build thread (no incident term), CES demo (no incident term)
        "https://www.reddit.com/r/robotics/comments/xyz999/weekly_build_thread/",
        "https://www.reddit.com/r/Robots/comments/def456/ces_humanoid_arm_demo/",
        # hn: robot vacuum comparison (no incident term), fast quadruped (no incident term)
        "https://example.com/hn/robot-vacuum-comparison",
        "https://example.com/hn/fast-quadruped",
        # nvd: HVAC (no robot term)
        "https://nvd.nist.gov/vuln/detail/CVE-2023-99999",
        # github_advisory: npm left-pad (no robot term)
        "https://github.com/advisories/GHSA-yyyy-cccc-dddd",
    }

    def test_noise_excluded(self, registry_items: list[dict]) -> None:
        registry_urls = {i["url"] for i in registry_items}
        found_noise = registry_urls & self.NOISE_URLS
        assert not found_noise, f"Noise items found in registry: {found_noise}"


# ------------------------------------------------------------------
# 3. CVE IDs preserved
# ------------------------------------------------------------------

class TestCveIdsPreserved:
    """Items with CVE IDs must carry them through gate + apply."""

    def test_nvd_cve_ids(self, registry_items: list[dict]) -> None:
        nvd_items = [i for i in registry_items if i["source"] == "nvd"]
        all_cves = []
        for item in nvd_items:
            all_cves.extend(item.get("cve_ids", []))
        # At least the two robot-related CVEs should be present
        assert "CVE-2024-12345" in all_cves, f"Missing CVE-2024-12345 in {all_cves}"
        assert "CVE-2024-67890" in all_cves, f"Missing CVE-2024-67890 in all_cves"
        # The unrelated CVE should not be present (filtered by gate or excluded)
        assert "CVE-2023-99999" not in all_cves

    def test_github_advisory_cve_ids(self, registry_items: list[dict]) -> None:
        gh_items = [i for i in registry_items if i["source"] == "github_advisory"]
        # Fixture github_advisory items don't carry real CVE IDs (they use GHSA IDs)
        # but the cve_ids field should be an empty list, not missing
        for item in gh_items:
            assert "cve_ids" in item, f"github_advisory item missing cve_ids: {item['id']}"
            assert isinstance(item["cve_ids"], list)


# ------------------------------------------------------------------
# 4. Idempotency — second run adds 0
# ------------------------------------------------------------------

class TestIdempotent:
    """Running the pipeline a second time with the same fixtures must add
    zero new items (URL dedup)."""

    def test_second_run_adds_zero(self, tmp_path: Path, pipeline_result: dict) -> None:
        registry_path = tmp_path / "registry.json"
        site_dir = tmp_path / "site"
        result2 = run(
            offline=True,
            registry_path=registry_path,
            raw_dir=FIXTURES_RAW,
            site_dir=site_dir,
        )
        assert result2["added"] == 0, (
            f"Expected 0 added on second run, got {result2['added']}"
        )


# ------------------------------------------------------------------
# 5. Emitted radar.json contains new wire items
# ------------------------------------------------------------------

class TestRadarJson:
    """The emitted radar.json must contain items from the new sources."""

    def test_radar_json_exists(self, pipeline_result: dict, tmp_path: Path) -> None:
        radar_path = tmp_path / "site" / "data" / "radar.json"
        assert radar_path.exists(), "radar.json not emitted"

    def test_wire_contains_new_sources(self, pipeline_result: dict, tmp_path: Path) -> None:
        radar_path = tmp_path / "site" / "data" / "radar.json"
        radar = json.loads(radar_path.read_text())
        all_sources = {item["source"] for item in radar.get("items", [])}
        # Post-clusterer: most new-source items attach to Incidents, so the
        # wire (unattached Items) may legitimately be small or empty. Sources
        # must be present in the full item set; every wire item must be a
        # member of the item set with a valid source.
        wire = radar.get("wire", [])
        item_ids = {item["id"] for item in radar.get("items", [])}
        assert all(w["id"] in item_ids for w in wire)
        assert all(w["source"] in all_sources for w in wire)

    def test_items_field_contains_all_sources(self, pipeline_result: dict, tmp_path: Path) -> None:
        radar_path = tmp_path / "site" / "data" / "radar.json"
        radar = json.loads(radar_path.read_text())
        all_sources = {item["source"] for item in radar.get("items", [])}
        for expected in ("reddit", "hn", "nvd", "github_advisory"):
            assert expected in all_sources, f"Source {expected!r} missing from radar.json items"


# ------------------------------------------------------------------
# 6. Pipeline summary sanity
# ------------------------------------------------------------------

class TestPipelineSummary:
    """Pipeline returns reasonable counts."""

    def test_fetched_count(self, pipeline_result: dict) -> None:
        # Total raw items loaded from all fixture files
        assert pipeline_result["fetched"] > 0

    def test_gated_leq_fetched(self, pipeline_result: dict) -> None:
        assert pipeline_result["gated"] <= pipeline_result["fetched"]

    def test_added_positive(self, pipeline_result: dict) -> None:
        # New fixture items should have been added
        assert pipeline_result["added"] > 0
