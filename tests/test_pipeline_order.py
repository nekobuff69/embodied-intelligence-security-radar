"""Pipeline-order tests: dedup and blocklist filtering precede the LLM pass.

Drives the real ``radar.runner.run`` offline with a counting fake LLM
transport, so every assertion is about consumer-visible outcomes: which
Items reach the enrichment pass, what the run summary reports, and what
lands in the registry.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import radar.runner
from radar.registry import load, save
from radar.runner import run
from radar.schema import Item, Registry, item_id_for_url

NEW_URL = "https://vendor.example.com/new-advisory"
SEEN_URL = "https://vendor.example.com/seen-advisory"
DISMISSED_URL = "https://vendor.example.com/dismissed-advisory"
BOTH_URL = "https://vendor.example.com/seen-and-dismissed-advisory"

NEW_TITLE = "Robot firmware vulnerability disclosed"
SEEN_TITLE = "Humanoid robot exploit reported"
DISMISSED_TITLE = "Quadruped robot hijack warning"
BOTH_TITLE = "Android robot breach report resurfaced"

# Valid enrichment response (strict-JSON, as _extract_json expects).
_ENRICHMENT_CONTENT = json.dumps({
    "ai_summary": "Confirmed robot vulnerability.",
    "ai_category": "vuln",
    "ai_vendor": "Unitree",
    "ai_model": "Go2",
    "ai_robot_class": "quadruped",
    "ai_severity": {"source": "estimated", "value": "high"},
    "ai_relevant": True,
})


class CountingTransport:
    """Fake LLM transport that records every payload it serves."""

    def __init__(self) -> None:
        self.payloads: list[dict] = []

    def __call__(self, payload: dict) -> dict:
        self.payloads.append(payload)
        return {"choices": [{"message": {"content": _ENRICHMENT_CONTENT}}]}

    @property
    def user_messages(self) -> list[str]:
        return [
            m["content"]
            for p in self.payloads
            for m in p["messages"]
            if m["role"] == "user"
        ]


def _write_feed(raw_dir: Path) -> None:
    """Write one offline fixture file holding all four feed Items."""
    raw_dir.mkdir(parents=True, exist_ok=True)
    entries = [
        {"title": NEW_TITLE, "url": NEW_URL,
         "summary": "Hackers exploit the robot camera stream.", "published": "2026-10-25"},
        {"title": SEEN_TITLE, "url": SEEN_URL,
         "summary": "Attack targets robot navigation security.", "published": "2026-10-25"},
        {"title": DISMISSED_TITLE, "url": DISMISSED_URL,
         "summary": "Vulnerability allows remote takeover.", "published": "2026-10-25"},
        {"title": BOTH_TITLE, "url": BOTH_URL,
         "summary": "Breach of robot telemetry reported.", "published": "2026-10-25"},
    ]
    (raw_dir / "feed.json").write_text(json.dumps(entries))


def _seed_registry(registry_path: Path) -> None:
    """Pre-populate the registry with already-seen Items."""
    reg = Registry(items=[
        Item(
            id=item_id_for_url(url),
            source="press_rss",
            url=url,
            title=title,
            body="Previously ingested advisory.",
            published="2026-10-01",
        )
        for url, title in ((SEEN_URL, SEEN_TITLE), (BOTH_URL, BOTH_TITLE))
    ])
    save(reg, registry_path)


@pytest.fixture()
def env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict:
    """Offline pipeline environment: seeded registry, dismissed blocklist,
    LLM env, and a counting fake transport wired through run()."""
    monkeypatch.setenv("RADAR_LLM_API_KEY", "test-key")
    monkeypatch.setenv("RADAR_LLM_BASE_URL", "http://fake-llm/v1")
    monkeypatch.setenv("RADAR_LLM_MODEL", "test-model")
    # Blocklist is loaded via radar.runner.load_dismissed; stub the repo-level
    # file so the test controls which URLs are dismissed.
    monkeypatch.setattr(
        radar.runner, "load_dismissed",
        lambda _path: {DISMISSED_URL, BOTH_URL},
    )

    # The cluster stage builds its own httpx-based LLM client; make it fail
    # fast into its existing exception fallback so no real network is hit.
    class _NoNetworkClient:
        def __init__(self, *args, **kwargs):
            raise ConnectionError("no network in tests")

    monkeypatch.setattr(radar.runner.httpx, "Client", _NoNetworkClient)

    raw_dir = tmp_path / "raw"
    _write_feed(raw_dir)
    registry_path = tmp_path / "registry.json"
    _seed_registry(registry_path)

    transport = CountingTransport()
    return {
        "raw_dir": raw_dir,
        "registry_path": registry_path,
        "site_dir": tmp_path / "site",
        "transport": transport,
    }


def _run(env: dict) -> dict:
    return run(
        offline=True,
        registry_path=env["registry_path"],
        raw_dir=env["raw_dir"],
        site_dir=env["site_dir"],
        llm_transport=env["transport"],
    )


class TestFilterPrecedesLLMSpend:
    """Seen and dismissed URLs must be filtered out before the enrichment
    pass; genuinely new Items must still be enriched."""

    def test_only_new_item_reaches_llm_pass(self, env: dict) -> None:
        summary = _run(env)

        assert len(env["transport"].payloads) == 1, (
            "Exactly the one genuinely new Item must reach the LLM pass"
        )
        served = env["transport"].user_messages[0]
        assert NEW_TITLE in served
        assert SEEN_TITLE not in served
        assert DISMISSED_TITLE not in served
        assert BOTH_TITLE not in served

        assert summary["added"] == 1
        assert summary["enriched"] == 1

    def test_summary_reports_skip_counts(self, env: dict) -> None:
        summary = _run(env)

        # SEEN_URL and BOTH_URL are already in the registry; BOTH_URL is
        # counted once, as already-seen, not double-counted as dismissed.
        assert summary["skipped_seen"] == 2
        assert summary["dismissed_blocked"] == 1

    def test_new_item_enriched_and_persisted(self, env: dict) -> None:
        """New Items are enriched normally: LLM fields reach the registry."""
        _run(env)

        reg = load(env["registry_path"])
        new_item = next(i for i in reg.items if i.url == NEW_URL)
        assert new_item.ai_category == "vuln"
        assert new_item.ai_summary == "Confirmed robot vulnerability."

    def test_filtered_items_absent_from_registry(self, env: dict) -> None:
        _run(env)

        reg = load(env["registry_path"])
        urls = [i.url for i in reg.items]
        assert DISMISSED_URL not in urls
        assert urls.count(SEEN_URL) == 1
        assert urls.count(BOTH_URL) == 1


class TestSecondRunZeroSpend:
    """A second consecutive run over the same feed must make zero
    enrichment calls."""

    def test_second_run_makes_no_llm_calls(self, env: dict) -> None:
        first = _run(env)
        assert first["added"] == 1  # sanity: run 1 did real work

        env["transport"].payloads.clear()
        second = _run(env)

        assert env["transport"].payloads == []
        assert second["skipped_seen"] == 3  # SEEN, BOTH, and now-registered NEW
        assert second["dismissed_blocked"] == 1  # DISMISSED_URL
        assert second["added"] == 0
        assert second["enriched"] == 0
