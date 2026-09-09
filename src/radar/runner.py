"""Pipeline orchestrator: fetch → gate → apply → save → emit.

Supports live mode (network fetch) and offline mode (fixture replay).
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any, Callable

import httpx

from radar.cluster import cluster
from radar.emitters import emit
from radar.enrich import enrich
from radar.fetchers import fetch
from radar.gate import apply_gate
from radar.monitor import monitor
from radar.registry import apply_items, load, load_dismissed, save
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
        base_url = os.environ.get("RADAR_LLM_BASE_URL") or "https://api.openai.com/v1"
        model = os.environ.get("RADAR_LLM_MODEL") or "gpt-4o-mini"
        llm_provider = base_url
        llm_model = model
        enrich(gated_items, base_url, model, llm_key)
        enriched_count = sum(
            1
            for it in gated_items
            if it.ai_category is not None or it.ai_summary is not None
        )

    # 4. Apply (idempotent dedup) — cluster only genuinely new items so the
    # registry never references deduped-away ids and attachments stay 1:1.
    seen_urls = {it.url for it in reg.items}
    new_items: list[Item] = []
    for it in gated_items:
        if it.url in seen_urls:
            continue
        seen_urls.add(it.url)
        new_items.append(it)

    # 4a. Filter against dismissed-URL blocklist (retroactive pruning)
    dismissed_path = Path(__file__).resolve().parents[2] / "data" / "dismissed_urls.json"
    dismissed_urls = load_dismissed(dismissed_path)
    dismissed_blocked = 0
    if dismissed_urls:
        filtered: list[Item] = []
        for it in new_items:
            if it.url in dismissed_urls:
                dismissed_blocked += 1
            else:
                filtered.append(it)
        new_items = filtered

    reg, added = apply_items(reg, new_items)

    # 4b. Cluster items into incidents (ADR-0001)
    cluster_llm: Callable | None = None
    if llm_key:
        _base_url = os.environ.get("RADAR_LLM_BASE_URL") or "https://api.openai.com/v1"
        _model = os.environ.get("RADAR_LLM_MODEL") or "gpt-4o-mini"

        def _cluster_llm(candidates: list[dict], item: Item) -> dict:
            """Wrap LLM call for the clusterer's stage-2 verdict."""
            prompt_parts = [
                f"Title: {item.title}",
                f"Body: {item.body}",
                "",
                "Candidate incidents (top-{k}):".format(k=len(candidates)),
            ]
            for c in candidates:
                prompt_parts.append(
                    f"- {c['id']}: {c['title']} (status={c['status']}, "
                    f"first_seen={c['first_seen']})"
                )
            prompt_parts.append("")
            prompt_parts.append(
                'Return STRICT JSON: {"action": "attach"|"create", '
                '"incident_id": "<id if attach>"}'
            )
            user_msg = "\n".join(prompt_parts)

            payload = {
                "model": _model,
                "messages": [
                    {
                        "role": "system",
                        "content": (
                            "You are a security incident clustering assistant. "
                            "Given an item and candidate incidents, decide whether "
                            "the item belongs to an existing incident or is new. "
                            "Return ONLY the JSON object."
                        ),
                    },
                    {"role": "user", "content": user_msg},
                ],
                "temperature": 0.0,
                "max_tokens": 1024,
            }
            try:
                headers = {
                    "Authorization": f"Bearer {llm_key}",
                    "Content-Type": "application/json",
                }
                session_id = os.environ.get("RADAR_LLM_SESSION_ID") or ""
                if session_id:
                    headers["x-opencode-session"] = session_id
                with httpx.Client() as client:
                    resp = client.post(
                        f"{_base_url}/chat/completions",
                        json=payload,
                        headers=headers,
                        timeout=30.0,
                    )
                    resp.raise_for_status()
                    content = resp.json()["choices"][0]["message"]["content"]
                # Defensive JSON extraction (same pattern as enrich.py)
                cleaned = content.strip()
                if cleaned.startswith("```"):
                    import re as _re
                    cleaned = _re.sub(r"^```\w*\s*\n?", "", cleaned)
                    cleaned = _re.sub(r"\n?```\s*$", "", cleaned)
                    cleaned = cleaned.strip()
                import json as _json
                return _json.loads(cleaned)
            except Exception as exc:
                return {"action": "create"}

        cluster_llm = _cluster_llm

    reg, cluster_decisions = cluster(reg, new_items, llm=cluster_llm)

    created = sum(1 for d in cluster_decisions if d["action"] == "create")
    attached = sum(1 for d in cluster_decisions if d["action"] == "attach")
    status_changed = sum(
        1 for d in cluster_decisions if "status_proposal" in d
    )

    # 5. Vendor-page monitor (live mode only — offline skips network)
    monitor_summary: dict = {"checked": 0, "unchanged": 0, "changed": 0, "interpreted": 0}
    if not offline:
        config = _load_config()
        data_dir = Path(__file__).resolve().parents[2] / "data"
        hashes_path = data_dir / ".vendor_hashes.json"
        monitor_llm: Callable | None = None
        if llm_key:
            _monitor_base = os.environ.get("RADAR_LLM_BASE_URL") or "https://api.openai.com/v1"
            _monitor_model = os.environ.get("RADAR_LLM_MODEL") or "gpt-4o-mini"

            def _monitor_llm(page_text: str) -> dict:
                payload = {
                    "model": _monitor_model,
                    "messages": [
                        {
                            "role": "system",
                            "content": (
                                "You are a security advisory monitor. Analyze the "
                                "following page content and determine if a fix/patch "
                                "has been disclosed. Return STRICT JSON: "
                                '{"patched": bool, "note": "brief explanation"}'
                            ),
                        },
                        {"role": "user", "content": page_text[:2000]},
                    ],
                    "temperature": 0.0,
                    "max_tokens": 1024,
                }
                try:
                    headers = {
                        "Authorization": f"Bearer {llm_key}",
                        "Content-Type": "application/json",
                    }
                    session_id = os.environ.get("RADAR_LLM_SESSION_ID") or ""
                    if session_id:
                        headers["x-opencode-session"] = session_id
                    with httpx.Client() as client:
                        resp = client.post(
                            f"{_monitor_base}/chat/completions",
                            json=payload,
                            headers=headers,
                            timeout=30.0,
                        )
                        resp.raise_for_status()
                        content = resp.json()["choices"][0]["message"]["content"]
                    cleaned = content.strip()
                    if cleaned.startswith("```"):
                        import re as _re
                        cleaned = _re.sub(r"^```\w*\s*\n?", "", cleaned)
                        cleaned = _re.sub(r"\n?```\s*$", "", cleaned)
                        cleaned = cleaned.strip()
                    import json as _json
                    return _json.loads(cleaned)
                except Exception as exc:
                    log.warning("Monitor LLM call failed: %s", exc)
                    return {}

            monitor_llm = _monitor_llm
        monitor_summary = monitor(reg, config, hashes_path, llm=monitor_llm)

    # 6. Save
    save(reg, registry_path)

    # 7. Emit
    emit(reg, site_dir)

    summary = {
        "fetched": len(fetched_items),
        "gated": len(gated_items),
        "added": added,
        "enriched": enriched_count,
        "created": created,
        "attached": attached,
        "status_changed": status_changed,
        "dismissed_blocked": dismissed_blocked,
        "llm_provider": llm_provider,
        "llm_model": llm_model,
        **{f"monitor_{k}": v for k, v in monitor_summary.items()},
    }
    log.info("Pipeline complete: %s", summary)
    return summary
