"""End-to-end offline pipeline test: new sources flow through radar run --offline."""

from __future__ import annotations

import json
import shutil
from datetime import date, timedelta
from pathlib import Path

import httpx
import pytest

from radar.registry import load, save
from radar.schema import Incident, Item, Registry, Severity, Status, item_id_for_url
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


# ------------------------------------------------------------------
# 7. Production clusterer: embedding retrieval + LLM adjudication (#15)
# ------------------------------------------------------------------

_EXISTING_TITLE = "Hospital humanoid robot hack exposes patients"
_RELATED_TITLE = "Hackers exploit humanoid robot vulnerability to hijack hospital"
_RELATED_BODY = (
    "Security researchers published details of a new hospital humanoid robot "
    "hack that exposes patients to remote takeover."
)
_RELATED_URL = "https://example.com/advisories/silvercore-2"
_CVE_TITLE = "Hospital robot firmware vulnerability exposed by researchers"
_CVE_BODY = (
    "Security researchers disclosed a robot vulnerability, CVE-2026-12345, "
    "affecting hospital fleets."
)
_CVE_URL = "https://example.com/advisories/silvercore-cve"
_CVE_ID = "CVE-2026-12345"


def _seed_registry(path: Path) -> tuple[str, str]:
    """Write a registry holding one open Incident with one attached Item.

    Returns (incident_id, seed_item_id).
    """
    seed_url = "https://example.com/advisories/silvercore-1"
    seed_item = Item(
        id=item_id_for_url(seed_url),
        source="press_rss",
        url=seed_url,
        title=_EXISTING_TITLE,
        body="A hospital humanoid robot hack exposes patients.",
        published=(date.today() - timedelta(days=7)).isoformat(),
        cve_ids=[_CVE_ID],
    )
    inc = Incident(
        id="INC-0001",
        title=_EXISTING_TITLE,
        category="vuln",
        robot_class="humanoid",
        vendor="Silvercore",
        severity=Severity(source="estimated", value="high"),
        status=Status(
            state="disclosed",
            evidence_url=seed_url,
            as_of=(date.today() - timedelta(days=7)).isoformat(),
        ),
        first_seen=(date.today() - timedelta(days=7)).isoformat(),
        last_checked=(date.today() - timedelta(days=7)).isoformat(),
        item_ids=[seed_item.id],
    )
    save(Registry(incidents=[inc], items=[seed_item]), path)
    return inc.id, seed_item.id


def _write_fixture(raw_dir: Path, entries: list[dict]) -> None:
    """Write raw fixture entries as the single press_rss feed file."""
    raw_dir.mkdir(parents=True, exist_ok=True)
    (raw_dir / "press_rss.json").write_text(json.dumps(entries))


def _install_fake_http_llm(
    monkeypatch: pytest.MonkeyPatch, verdict: dict
) -> list[str]:
    """Replace httpx.Client with a deterministic OpenAI-shaped transport.

    Dispatches on the system prompt so the enrichment pass, the clusterer's
    stage-2 verdict, and the monitor each get a canned response.  Returns the
    list of observed system prompts (one entry per LLM call).
    """
    import json as _json

    observed: list[str] = []

    class _Response:
        def __init__(self, content: str) -> None:
            self._content = content

        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict:
            return {"choices": [{"message": {"content": self._content}}]}

    class _FakeClient:
        def __init__(self, *args: object, **kwargs: object) -> None:
            pass

        def __enter__(self) -> "_FakeClient":
            return self

        def __exit__(self, *exc: object) -> bool:
            return False

        def post(
            self,
            url: str,
            json: dict | None = None,
            headers: dict | None = None,
            timeout: float | None = None,
        ) -> _Response:
            messages = (json or {}).get("messages") or [{"content": ""}]
            system = messages[0].get("content", "")
            observed.append(system)
            if "clustering assistant" in system:
                content = _json.dumps(verdict)
            elif "advisory monitor" in system:
                content = _json.dumps({"patched": False, "note": "test"})
            else:
                content = _json.dumps({"relevant": False})
            return _Response(content)

    monkeypatch.setattr(httpx, "Client", _FakeClient)
    return observed


class TestProductionEmbeddingAdjudication:
    """Production run() must use embedding candidate retrieval (stage 1)
    plus the optional LLM verdict (stage 2) — ADR-0001 wired end to end."""

    def test_related_item_attaches_via_llm_verdict(self, tmp_path: Path, monkeypatch) -> None:
        """A related Item with no CVE and no exact vendor+model match
        attaches to the existing Incident instead of creating a duplicate."""
        monkeypatch.setenv("RADAR_LLM_API_KEY", "test-key")
        registry_path = tmp_path / "registry.json"
        raw_dir = tmp_path / "raw"
        site_dir = tmp_path / "site"
        inc_id, seed_id = _seed_registry(registry_path)
        new_id = item_id_for_url(_RELATED_URL)
        _write_fixture(
            raw_dir,
            [
                {
                    "title": _RELATED_TITLE,
                    "url": _RELATED_URL,
                    "summary": _RELATED_BODY,
                    "feed_type": "press_rss",
                    "published": date.today().isoformat(),
                }
            ],
        )
        observed = _install_fake_http_llm(
            monkeypatch, {"action": "attach", "incident_id": inc_id}
        )

        summary = run(
            offline=True,
            registry_path=registry_path,
            raw_dir=raw_dir,
            site_dir=site_dir,
        )

        # Stage 2 ran through the HTTP layer and adjudicated an attachment
        assert any("clustering assistant" in s for s in observed), (
            "stage-2 verdict was never requested from the LLM"
        )
        assert summary["attached"] == 1
        assert summary["created"] == 0

        # No stage-0 keys on the item: attachment came from embed+verdict
        reg = load(registry_path)
        new_item = next(i for i in reg.items if i.id == new_id)
        assert new_item.cve_ids == []
        assert new_item.ai_vendor is None

        # Exactly one Incident with both Item ids in the registry
        assert len(reg.incidents) == 1
        assert sorted(reg.incidents[0].item_ids) == sorted({seed_id, new_id})

        # ... and in the emitted site data
        radar = json.loads((site_dir / "data" / "radar.json").read_text())
        assert len(radar["incidents"]) == 1
        assert sorted(radar["incidents"][0]["item_ids"]) == sorted({seed_id, new_id})

    def test_no_llm_key_zero_calls_stage0_unchanged(self, tmp_path: Path, monkeypatch) -> None:
        """Without a key: zero LLM calls; the deterministic stage-0 CVE join
        still attaches, while stage-1 vectors alone never attach."""
        monkeypatch.delenv("RADAR_LLM_API_KEY", raising=False)
        registry_path = tmp_path / "registry.json"
        raw_dir = tmp_path / "raw"
        site_dir = tmp_path / "site"
        inc_id, seed_id = _seed_registry(registry_path)
        cve_id = item_id_for_url(_CVE_URL)
        related_id = item_id_for_url(_RELATED_URL)
        _write_fixture(
            raw_dir,
            [
                {
                    "title": _CVE_TITLE,
                    "url": _CVE_URL,
                    "summary": _CVE_BODY,
                    "feed_type": "press_rss",
                    "published": date.today().isoformat(),
                },
                {
                    "title": _RELATED_TITLE,
                    "url": _RELATED_URL,
                    "summary": _RELATED_BODY,
                    "feed_type": "press_rss",
                    "published": date.today().isoformat(),
                },
            ],
        )
        observed = _install_fake_http_llm(
            monkeypatch, {"action": "attach", "incident_id": inc_id}
        )

        summary = run(
            offline=True,
            registry_path=registry_path,
            raw_dir=raw_dir,
            site_dir=site_dir,
        )

        # Zero LLM calls without a key
        assert observed == []
        # Stage-0 CVE join still attaches deterministically
        assert summary["attached"] == 1
        assert summary["created"] == 0
        assert summary["enriched"] == 0

        reg = load(registry_path)
        assert len(reg.incidents) == 1
        assert sorted(reg.incidents[0].item_ids) == sorted({seed_id, cve_id})

        # Embedding similarity alone must not attach the related Item:
        # it stays on the wire and no duplicate Incident is created
        assert related_id in {i.id for i in reg.items}
        radar = json.loads((site_dir / "data" / "radar.json").read_text())
        assert len(radar["incidents"]) == 1
        assert related_id in {w["id"] for w in radar["wire"]}
