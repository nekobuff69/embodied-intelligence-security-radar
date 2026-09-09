"""Vendor-page hash-compare monitor (ADR-0001 zero-cost silence).

For each vendor_page source (and each Incident.monitor_urls):
1. Fetch page bytes via injectable ``_fetch`` (default: httpx).
2. SHA-256 hash the content.
3. Compared to stored hash in ``data/.vendor_hashes.json``:
   - Unchanged  → advance that Incident's last_checked (zero LLM).
   - Changed    → store new hash; if ``llm`` callable: one interpretive
                  call → if ``patched:true`` apply_status; else leave.
                  If ``llm`` is None: leave status, log pending.
   - New page   → store hash, no LLM call.

Fetch failures are caught, logged, and skipped — never raised.
"""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import date
from pathlib import Path
from typing import Callable

import httpx

from radar.registry import apply_status, touch_last_checked
from radar.schema import Registry

log = logging.getLogger(__name__)

_TIMEOUT = 20
_USER_AGENT = "RobotSecurityRadar/0.1"


# ---------------------------------------------------------------------------
# Injectable transport (module-level for test monkeypatching)
# ---------------------------------------------------------------------------

def _fetch(url: str) -> str:
    """Fetch page text via httpx.  Raises on failure."""
    with httpx.Client(
        follow_redirects=True,
        timeout=_TIMEOUT,
        headers={"User-Agent": _USER_AGENT},
    ) as client:
        resp = client.get(url)
        resp.raise_for_status()
        return resp.text


# ---------------------------------------------------------------------------
# Hash state helpers (reuse data/.vendor_hashes.json)
# ---------------------------------------------------------------------------

def _load_hashes(path: Path) -> dict[str, str]:
    if path.exists():
        try:
            return json.loads(path.read_text())
        except (json.JSONDecodeError, OSError):
            log.warning("Failed to load hashes from %s — starting fresh", path)
    return {}


def _save_hashes(path: Path, hashes: dict[str, str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(hashes, indent=2, ensure_ascii=False) + "\n")


# ---------------------------------------------------------------------------
# Main monitor entry point
# ---------------------------------------------------------------------------

def monitor(
    reg: Registry,
    sources: dict,
    hashes_path: Path,
    llm: Callable[[str], dict] | None = None,
    today: str | None = None,
) -> dict:
    """Run the vendor-page hash-compare monitor.

    Parameters
    ----------
    reg : Registry
        Registry whose Incidents' ``last_checked`` may be advanced.
    sources : dict
        ``data/sources.json`` config; ``sources["feeds"]`` list is scanned
        for ``type == "vendor_page"`` entries.
    hashes_path : Path
        Path to ``data/.vendor_hashes.json``.
    llm : callable or None
        ``(page_text) -> dict`` interpretive LLM.  Must return
        ``{"patched": bool, "note": str}``.  When *None*, changed pages
        are logged as pending but status is not modified.
    today : str or None
        Override for ``date.today()`` (testing).

    Returns
    -------
    dict
        Summary: ``{checked, unchanged, changed, interpreted}``.
    """
    if today is None:
        today = date.today().isoformat()

    hashes = _load_hashes(hashes_path)
    summary = {"checked": 0, "unchanged": 0, "changed": 0, "interpreted": 0}

    # Collect URLs to monitor: from sources config + Incident.monitor_urls
    urls_to_incident: dict[str, str | None] = {}
    for feed in sources.get("feeds", []):
        if feed.get("type") == "vendor_page":
            url = feed.get("url", "")
            if url:
                inc_id = feed.get("incident_id")
                urls_to_incident[url] = inc_id

    # Incident.monitor_urls linkage is authoritative over an unlinked
    # sources-config entry (a vendor_page feed without incident_id).
    for inc in reg.incidents:
        for url in getattr(inc, "monitor_urls", []):
            urls_to_incident[url] = inc.id

    for url, inc_id in urls_to_incident.items():
        summary["checked"] += 1
        try:
            content = _fetch(url)
        except Exception as exc:
            log.warning("Monitor fetch failed for %s: %s — skipping", url, exc)
            continue

        content_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()

        if hashes.get(url) == content_hash:
            # Unchanged → advance last_checked only
            summary["unchanged"] += 1
            if inc_id:
                touch_last_checked(reg, inc_id, today)
            continue
        # Changed → store new hash; a successful check advances last_checked
        # regardless of whether the content changed.
        hashes[url] = content_hash
        _save_hashes(hashes_path, hashes)
        summary["changed"] += 1
        if inc_id:
            touch_last_checked(reg, inc_id, today)

        if llm is not None:
            try:
                verdict = llm(content)
            except Exception as exc:
                log.warning("Monitor LLM call failed for %s: %s", url, exc)
                verdict = {}

            if verdict.get("patched") is True and inc_id:
                summary["interpreted"] += 1
                for inc in reg.incidents:
                    if inc.id == inc_id:
                        apply_status(inc, {
                            "state": "patched",
                            "evidence_url": url,
                            "as_of": today,
                            "note": verdict.get("note", ""),
                        })
                        break
            elif verdict.get("patched") is True and not inc_id:
                summary["interpreted"] += 1
                log.info("LLM says patched for %s but no incident_id linked", url)
        else:
            log.info("Monitor: %s changed but no LLM key — interpretation pending", url)

    _save_hashes(hashes_path, hashes)
    return summary
