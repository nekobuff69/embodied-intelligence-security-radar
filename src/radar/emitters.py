"""Emitter: transform Registry into site/data/radar.json for the frontend."""

from __future__ import annotations

from datetime import date, timedelta
from pathlib import Path

from .schema import Registry

OPEN_STATES = {"disclosed", "unpatched", "exploited_in_wild"}


def _patch_lag_days(first_seen: str, today: date) -> int:
    """Days from first_seen to today, clamped >= 0."""
    fs = date.fromisoformat(first_seen)
    return max((today - fs).days, 0)


def emit(registry: Registry, site_dir: str | Path) -> None:
    """Write site/data/radar.json derived from *registry*."""
    site = Path(site_dir)
    out_dir = site / "data"
    out_dir.mkdir(parents=True, exist_ok=True)
    today = date.today()

    incidents_out: list[dict] = []
    for inc in registry.incidents:
        d = {
            "id": inc.id,
            "title": inc.title,
            "category": inc.category,
            "robot_class": inc.robot_class,
            "vendor": inc.vendor,
            "model": inc.model,
            "severity": {"source": inc.severity.source, "value": inc.severity.value},
            "status": {
                "state": inc.status.state,
                "evidence_url": inc.status.evidence_url,
                "as_of": inc.status.as_of,
            },
            "first_seen": inc.first_seen,
            "last_checked": inc.last_checked,
            "item_ids": inc.item_ids,
            "ai_summary": inc.ai_summary,
            "open": inc.status.state in OPEN_STATES,
        }
        incidents_out.append(d)

    open_lags = [
        _patch_lag_days(inc.first_seen, today)
        for inc in registry.incidents
        if inc.status.state in OPEN_STATES
    ]

    counts = {
        "incidents": len(registry.incidents),
        "unpatched": sum(
            1 for d in incidents_out if d["status"]["state"] in {"unpatched", "exploited_in_wild"}
        ),
        "max_patch_lag_days": max(open_lags) if open_lags else 0,
    }

    attached_ids = set()
    for inc in registry.incidents:
        attached_ids.update(inc.item_ids)

    wire = [item for item in registry.items if item.id not in attached_ids]

    radar = {
        "meta": {
            "schema_version": registry.meta.get("schema_version", 1),
            "generated_at": today.isoformat(),
            "counts": counts,
        },
        "incidents": incidents_out,
        "items": [item.__dict__ for item in registry.items],
        "wire": [item.__dict__ for item in wire],
    }

    import json

    (out_dir / "radar.json").write_text(
        json.dumps(radar, indent=2, ensure_ascii=False) + "\n"
    )
