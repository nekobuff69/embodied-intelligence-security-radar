"""Pipeline orchestrator: fetch → gate → apply → save → emit.

Supports live mode (network fetch) and offline mode (fixture replay).
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any

from radar.emitters import emit
from radar.enrich import enrich
from radar.fetchers import fetch
from radar.gate import apply_gate
from radar.registry import apply_items, load, save
from radar.schema import Item, Registry, item_id_for_url

log = logging.getLogger(__name__)


def _load_raw_fixtures(raw_dir: Path) -> list[Item]:
    """Load recorded raw payloads from fixture JSON files."""
    items: list[Item] = []
    for fixture_file in sorted(raw_dir.glob("*.json")):
        data = json.loads(fixture_file.read_text())
        for entry in data:
            title = entry.get("title", "").strip()
            url = entry.get("url", "").strip()
            if not title or not url:
                continue
            body = entry.get("summary", "").strip()
            text = f"{title} {body}"
            import re
            cve_re = re.compile(r"CVE-\d{4}-\d{4,}")
            items.append(
                Item(
                    id=item_id_for_url(url),
                    source=entry.get("feed_type", "press_rss"),
                    url=url,
                    title=title,
                    body=body,
                    published=entry.get("published", "2026-01-01"),
                    cve_ids=list(dict.fromkeys(cve_re.findall(text))),
                )
            )
    return items


def _load_config() -> dict:
    """Load feed configuration from data/sources.json."""
    config_path = Path(__file__).resolve().parents[2] / "data" / "sources.json"
    return json.loads(config_path.read_text())


def run(
    offline: bool = False,
    registry_path: Path = Path("data/registry.json"),
    raw_dir: Path | None = None,
    site_dir: Path = Path("site"),
) -> dict:
    """Run the full pipeline.

    Args:
        offline: If True, load from raw_dir fixtures instead of network.
        registry_path: Path to the registry JSON file.
        raw_dir: Directory containing raw fixture JSON files (offline mode).
        site_dir: Output directory for emitted site files.

    Returns:
        Summary dict with fetched, gated, added counts.

    Raises:
        RuntimeError: On pipeline failure.
    """
    # 1. Load or create registry
    if registry_path.exists():
        reg = load(registry_path)
    else:
        reg = Registry()

    # 2. Fetch
    if offline:
        if raw_dir is None:
            raise RuntimeError("raw_dir required in offline mode")
        fetched_items = _load_raw_fixtures(raw_dir)
    else:
        config = _load_config()
        fetched_items = fetch(config)

    # 3. Gate
    gated_items = apply_gate(fetched_items)

    # 3b. LLM enrichment (skipped when RADAR_LLM_API_KEY is unset)
    enriched_count = 0
    llm_provider = "skipped"
    llm_model = "skipped"
    llm_key = os.environ.get("RADAR_LLM_API_KEY", "")
    if llm_key:
        base_url = os.environ.get("RADAR_LLM_BASE_URL", "https://api.openai.com/v1")
        model = os.environ.get("RADAR_LLM_MODEL", "gpt-4o-mini")
        llm_provider = base_url
        llm_model = model
        enrich(gated_items, base_url, model, llm_key)
        enriched_count = sum(
            1
            for it in gated_items
            if it.ai_category is not None or it.ai_summary is not None
        )

    # 4. Apply (idempotent dedup)
    reg, added = apply_items(reg, gated_items)

    # 5. Save
    save(reg, registry_path)

    # 6. Emit
    emit(reg, site_dir)

    summary = {
        "fetched": len(fetched_items),
        "gated": len(gated_items),
        "added": added,
        "enriched": enriched_count,
        "llm_provider": llm_provider,
        "llm_model": llm_model,
    }
    log.info("Pipeline complete: %s", summary)
    return summary
