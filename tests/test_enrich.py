"""Contract tests for radar.enrich — provider-swappable LLM enrichment.

All tests use the transport seam (no network).  Fixture responses live in
tests/fixtures/llm/responses.json.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from radar.enrich import _apply_enrichment, _extract_json, _parse_severity, enrich
from radar.schema import Item, Severity

FIXTURES = Path(__file__).parent / "fixtures" / "llm" / "responses.json"


# ── Helpers ──────────────────────────────────────────────────────────


def _load_fixtures() -> list[dict[str, str]]:
    return json.loads(FIXTURES.read_text())


def _make_item(
    title: str = "Unitree Go2 BLE vulnerability",
    body: str = "CVE-2024-1234 affects the Unitree Go2 quadruped robot.",
    url: str = "https://example.com/1",
) -> Item:
    return Item(
        id="itm-test001",
        source="press_rss",
        url=url,
        title=title,
        body=body,
        published="2026-01-15",
    )


def _transport_for(content: str):
    """Return a transport that always yields *content*."""
    def transport(payload: dict) -> dict:
        return {"choices": [{"message": {"content": content}}]}
    return transport


def _transport_queue(contents: list[str]):
    """Return a transport that yields *contents* in order, then cycles."""
    idx = [0]
    def transport(payload: dict) -> dict:
        c = contents[idx[0] % len(contents)]
        idx[0] += 1
        return {"choices": [{"message": {"content": c}}]}
    return transport


def _json_response(data: dict) -> str:
    return json.dumps(data)


# ── JSON extraction ──────────────────────────────────────────────────


class TestExtractJson:
    def test_valid_json(self):
        fx = _load_fixtures()
        result = _extract_json(fx[0]["content"])
        assert result is not None
        assert result["ai_category"] == "vuln"

    def test_fence_wrapped(self):
        fx = _load_fixtures()
        result = _extract_json(fx[1]["content"])
        assert result is not None
        assert result["ai_category"] == "vuln"
        assert result["ai_vendor"] == "Acme Robotics"

    def test_prose_embedded(self):
        fx = _load_fixtures()
        result = _extract_json(fx[2]["content"])
        assert result is not None
        assert result["ai_category"] == "safety"
        assert result["ai_robot_class"] == "humanoid"

    def test_malformed_returns_none(self):
        fx = _load_fixtures()
        result = _extract_json(fx[3]["content"])
        assert result is None

    def test_illegal_category_extracts(self):
        """JSON is valid; the illegal value is caught later by _apply_enrichment."""
        fx = _load_fixtures()
        result = _extract_json(fx[4]["content"])
        assert result is not None
        assert result["ai_category"] == "malware"


# ── Severity parsing ─────────────────────────────────────────────────


class TestParseSeverity:
    def test_valid_cvss(self):
        sev = _parse_severity({"source": "cvss", "value": "8.1"})
        assert isinstance(sev, Severity)
        assert sev.source == "cvss"
        assert sev.value == "8.1"

    def test_valid_estimated(self):
        sev = _parse_severity({"source": "estimated", "value": "high"})
        assert isinstance(sev, Severity)
        assert sev.source == "estimated"
        assert sev.value == "high"

    def test_invalid_source(self):
        assert _parse_severity({"source": "unknown", "value": "high"}) is None

    def test_invalid_estimated_band(self):
        assert _parse_severity({"source": "estimated", "value": "extreme"}) is None

    def test_cvss_non_numeric(self):
        assert _parse_severity({"source": "cvss", "value": "abc"}) is None

    def test_none_input(self):
        assert _parse_severity(None) is None

    def test_empty_dict(self):
        assert _parse_severity({}) is None


# ── Enrichment application ──────────────────────────────────────────


class TestApplyEnrichment:
    def test_valid_data_sets_all_fields(self):
        item = _make_item()
        data = {
            "ai_summary": "A critical BLE vulnerability affects Unitree Go2 robots.",
            "ai_category": "vuln",
            "ai_vendor": "Unitree",
            "ai_model": "Go2",
            "ai_robot_class": "quadruped",
            "ai_severity": {"source": "estimated", "value": "high"},
        }
        _apply_enrichment(item, data)
        assert item.ai_summary == "A critical BLE vulnerability affects Unitree Go2 robots."
        assert item.ai_category == "vuln"
        assert item.ai_vendor == "Unitree"
        assert item.ai_model == "Go2"
        assert item.ai_robot_class == "quadruped"
        assert isinstance(item.ai_severity, Severity)
        assert item.ai_severity.source == "estimated"
        assert item.ai_severity.value == "high"

    def test_invalid_category_drops_to_none(self):
        item = _make_item()
        _apply_enrichment(item, {"ai_category": "malware"})
        assert item.ai_category is None

    def test_invalid_robot_class_drops_to_none(self):
        item = _make_item()
        _apply_enrichment(item, {"ai_robot_class": "drone"})
        assert item.ai_robot_class is None

    def test_empty_summary_becomes_none(self):
        item = _make_item()
        _apply_enrichment(item, {"ai_summary": "   "})
        assert item.ai_summary is None

    def test_empty_vendor_becomes_none(self):
        item = _make_item()
        _apply_enrichment(item, {"ai_vendor": ""})
        assert item.ai_vendor is None

    def test_missing_keys_leave_fields_none(self):
        item = _make_item()
        _apply_enrichment(item, {})
        assert item.ai_summary is None
        assert item.ai_category is None
        assert item.ai_vendor is None
        assert item.ai_model is None
        assert item.ai_robot_class is None
        assert item.ai_severity is None


# ── Full enrich pipeline (transport seam) ───────────────────────────


class TestEnrich:
    def test_valid_response_enriches_item(self):
        fx = _load_fixtures()
        item = _make_item()
        enrich([item], "http://fake", "model", "key", transport=_transport_for(fx[0]["content"]))
        assert item.ai_category == "vuln"
        assert item.ai_summary is not None
        assert item.ai_vendor == "Unitree"

    def test_fence_wrapped_enriches_item(self):
        fx = _load_fixtures()
        item = _make_item()
        enrich([item], "http://fake", "model", "key", transport=_transport_for(fx[1]["content"]))
        assert item.ai_category == "vuln"
        assert item.ai_vendor == "Acme Robotics"

    def test_prose_embedded_enriches_item(self):
        fx = _load_fixtures()
        item = _make_item()
        enrich([item], "http://fake", "model", "key", transport=_transport_for(fx[2]["content"]))
        assert item.ai_category == "safety"
        assert item.ai_robot_class == "humanoid"

    def test_malformed_leaves_unenriched(self):
        fx = _load_fixtures()
        item = _make_item()
        enrich([item], "http://fake", "model", "key", transport=_transport_for(fx[3]["content"]))
        assert item.ai_summary is None
        assert item.ai_category is None

    def test_illegal_category_drops_to_none(self):
        fx = _load_fixtures()
        item = _make_item()
        enrich([item], "http://fake", "model", "key", transport=_transport_for(fx[4]["content"]))
        assert item.ai_category is None
        # summary should still be set from the same response
        assert item.ai_summary is not None

    def test_cvss_in_text_overrides_to_cvss(self):
        """Item text contains CVSS:8.1 → source forced to cvss regardless of model output."""
        item = _make_item(
            title="Critical vulnerability in Unitree Go2",
            body="A CVSS:8.1 vulnerability was found in the Unitree Go2 firmware.",
        )
        # Model claims estimated, but text has CVSS
        resp = _json_response({
            "ai_summary": "Test.",
            "ai_category": "vuln",
            "ai_vendor": "Unitree",
            "ai_model": "Go2",
            "ai_robot_class": "quadruped",
            "ai_severity": {"source": "estimated", "value": "high"},
        })
        enrich([item], "http://fake", "model", "key", transport=_transport_for(resp))
        assert isinstance(item.ai_severity, Severity)
        assert item.ai_severity.source == "cvss"
        assert item.ai_severity.value == "8.1"

    def test_no_cvss_uses_estimated(self):
        """No CVSS in text → use model's estimated band."""
        item = _make_item(
            title="Robot safety incident reported",
            body="A consumer robot malfunctioned during operation.",
        )
        resp = _json_response({
            "ai_summary": "Test.",
            "ai_category": "safety",
            "ai_vendor": "Acme",
            "ai_model": None,
            "ai_robot_class": "consumer",
            "ai_severity": {"source": "estimated", "value": "medium"},
        })
        enrich([item], "http://fake", "model", "key", transport=_transport_for(resp))
        assert isinstance(item.ai_severity, Severity)
        assert item.ai_severity.source == "estimated"
        assert item.ai_severity.value == "medium"

    def test_transport_exception_leaves_unenriched(self):
        """Transport raising an exception must not crash the run."""
        def boom(payload: dict) -> dict:
            raise ConnectionError("network down")
        item = _make_item()
        enrich([item], "http://fake", "model", "key", transport=boom)
        assert item.ai_summary is None
        assert item.ai_category is None

    def test_provider_swappability(self):
        """Two different transports produce different results on identical items."""
        item_a = _make_item(url="https://example.com/a")
        item_b = _make_item(url="https://example.com/b")

        def transport_a(payload: dict) -> dict:
            return {"choices": [{"message": {"content": _json_response({
                "ai_summary": "Summary A",
                "ai_category": "vuln",
            })}}]}

        def transport_b(payload: dict) -> dict:
            return {"choices": [{"message": {"content": _json_response({
                "ai_summary": "Summary B",
                "ai_category": "safety",
            })}}]}

        enrich([item_a], "http://fake", "model", "key", transport=transport_a)
        enrich([item_b], "http://fake", "model", "key", transport=transport_b)

        assert item_a.ai_summary == "Summary A"
        assert item_a.ai_category == "vuln"
        assert item_b.ai_summary == "Summary B"
        assert item_b.ai_category == "safety"

    def test_multiple_items_via_queue(self):
        """Queue transport feeds different responses to successive items."""
        fx = _load_fixtures()
        items = [_make_item(url=f"https://example.com/{i}") for i in range(3)]
        contents = [fx[0]["content"], fx[1]["content"], fx[2]["content"]]
        enrich(items, "http://fake", "model", "key", transport=_transport_queue(contents))
        assert items[0].ai_category is not None  # valid
        assert items[1].ai_category is not None  # fence-wrapped
        assert items[2].ai_category is not None  # prose-embedded

    def test_empty_list_noop(self):
        """Enriching an empty list should not call the transport."""
        called = [False]
        def tracking_transport(payload: dict) -> dict:
            called[0] = True
            return {}
        enrich([], "http://fake", "model", "key", transport=tracking_transport)
        assert not called[0]


# ── Runner no-key skip ──────────────────────────────────────────────


class TestRelevance:
    """Test the relevance verdict handling in _apply_enrichment."""

    def test_relevant_false_sets_ai_relevant_and_leaves_others_none(self):
        """relevant:false → ai_relevant=False, all other ai_* fields stay None."""
        item = _make_item()
        data = {
            "relevant": False,
            "ai_summary": "This is a podcast episode about robots.",
            "ai_category": "vuln",
            "ai_vendor": "Unitree",
            "ai_model": "Go2",
            "ai_robot_class": "quadruped",
            "ai_severity": {"source": "estimated", "value": "high"},
        }
        _apply_enrichment(item, data)
        assert item.ai_relevant is False
        assert item.ai_summary is None
        assert item.ai_category is None
        assert item.ai_vendor is None
        assert item.ai_model is None
        assert item.ai_robot_class is None
        assert item.ai_severity is None

    def test_relevant_true_populates_fields(self):
        """relevant:true → ai_relevant=True, other fields enriched normally."""
        item = _make_item()
        data = {
            "relevant": True,
            "ai_summary": "A critical BLE vulnerability affects Go2 robots.",
            "ai_category": "vuln",
            "ai_vendor": "Unitree",
            "ai_model": "Go2",
            "ai_robot_class": "quadruped",
            "ai_severity": {"source": "estimated", "value": "high"},
        }
        _apply_enrichment(item, data)
        assert item.ai_relevant is True
        assert item.ai_summary == "A critical BLE vulnerability affects Go2 robots."
        assert item.ai_category == "vuln"
        assert item.ai_vendor == "Unitree"
        assert item.ai_model == "Go2"
        assert item.ai_robot_class == "quadruped"
        assert isinstance(item.ai_severity, Severity)

    def test_missing_relevant_leaves_ai_relevant_none(self):
        """Missing relevant → ai_relevant=None (legacy path)."""
        item = _make_item()
        data = {
            "ai_summary": "A vulnerability disclosure.",
            "ai_category": "vuln",
        }
        _apply_enrichment(item, data)
        assert item.ai_relevant is None

    def test_non_boolean_relevant_leaves_ai_relevant_none(self):
        """Non-boolean relevant → ai_relevant=None."""
        item = _make_item()
        data = {"relevant": "yes"}
        _apply_enrichment(item, data)
        assert item.ai_relevant is None

    def test_relevant_false_via_enrich_transport(self):
        """Full enrich pipeline: relevant:false sets ai_relevant=False."""
        fx = _load_fixtures()
        item = _make_item()
        enrich([item], "http://fake", "model", "key",
               transport=_transport_for(fx[5]["content"]))
        assert item.ai_relevant is False
        assert item.ai_summary is None
        assert item.ai_category is None

    def test_relevant_true_via_enrich_transport(self):
        """Full enrich pipeline: relevant:true enriches normally."""
        fx = _load_fixtures()
        item = _make_item()
        enrich([item], "http://fake", "model", "key",
               transport=_transport_for(fx[0]["content"]))
        assert item.ai_relevant is True
        assert item.ai_category == "vuln"
        assert item.ai_summary is not None

    def test_missing_relevant_via_enrich_transport(self):
        """Full enrich pipeline: missing relevant → ai_relevant=None."""
        item = _make_item()
        resp = _json_response({
            "ai_summary": "Test.",
            "ai_category": "vuln",
            "ai_vendor": "Unitree",
            "ai_model": "Go2",
            "ai_robot_class": "quadruped",
            "ai_severity": {"source": "estimated", "value": "high"},
        })
        enrich([item], "http://fake", "model", "key",
               transport=_transport_for(resp))
        assert item.ai_relevant is None
        assert item.ai_category == "vuln"


class TestNoKeySkip:
    def test_runner_skips_enrichment_without_key(self, monkeypatch, tmp_path):
        """When RADAR_LLM_API_KEY is unset, enriched count must be 0."""
        monkeypatch.delenv("RADAR_LLM_API_KEY", raising=False)
        monkeypatch.delenv("RADAR_LLM_BASE_URL", raising=False)
        monkeypatch.delenv("RADAR_LLM_MODEL", raising=False)

        from radar.runner import run

        raw_dir = Path(__file__).parent / "fixtures" / "raw"
        registry_path = tmp_path / "registry.json"
        summary = run(
            offline=True,
            raw_dir=raw_dir,
            registry_path=registry_path,
            site_dir=tmp_path / "site",
        )
        assert summary["enriched"] == 0
        assert summary["llm_provider"] == "skipped"
        assert summary["llm_model"] == "skipped"

    def test_runner_records_provider_when_key_set(self, monkeypatch, tmp_path):
        """When RADAR_LLM_API_KEY is set, summary records the provider/model."""
        monkeypatch.setenv("RADAR_LLM_API_KEY", "test-key")
        monkeypatch.setenv("RADAR_LLM_BASE_URL", "http://fake-llm/v1")
        monkeypatch.setenv("RADAR_LLM_MODEL", "test-model")

        from radar.runner import run

        raw_dir = Path(__file__).parent / "fixtures" / "raw"
        registry_path = tmp_path / "registry.json"

        # Mock enrich to avoid real network calls
        with patch("radar.runner.enrich") as mock_enrich:
            summary = run(
                offline=True,
                raw_dir=raw_dir,
                registry_path=registry_path,
                site_dir=tmp_path / "site",
            )
            mock_enrich.assert_called_once()
            args = mock_enrich.call_args
            assert args[0][1] == "http://fake-llm/v1"  # base_url
            assert args[0][2] == "test-model"  # model

        assert summary["llm_provider"] == "http://fake-llm/v1"
        assert summary["llm_model"] == "test-model"
