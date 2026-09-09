"""LLM enrichment pass for items that survive the gate.

Provider-agnostic: calls an OpenAI-compatible chat/completions endpoint
via httpx.  Transport seam (``transport`` kwarg) allows injecting a fake
callable for tests so no network is required.

When ``RADAR_LLM_API_KEY`` is unset the runner skips this stage entirely,
keeping offline / dev / test runs token-free.
"""

from __future__ import annotations

import json
import logging
import os
import re
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable

import httpx

from radar.schema import (
    CATEGORIES,
    ROBOT_CLASSES,
    SEVERITY_BANDS,
    Item,
    Severity,
)

log = logging.getLogger(__name__)

# Match CVSS scores in item text: "CVSS:8.1", "CVSSv3.1 Score: 7.5", etc.
_CVSS_RE = re.compile(
    r"CVSS(?:v\d+(?:\.\d+)?)?[:\s]*(?:Score[:\s]*)?(\d+(?:\.\d+)?)",
    re.IGNORECASE,
)

_SYSTEM_PROMPT = """\
You are a security analyst for robotics products.
Given an article title and body, FIRST judge whether the article describes \
a real incident, then extract fields as STRICT JSON (no markdown, no commentary).

RELEVANCE RUBRIC — an incident is a discrete, verifiable security or safety EVENT:
  - Vulnerability with CVE ID or vendor advisory
  - Confirmed attack, takeover, or breach
  - Physical safety incident or recall
NOT an incident (relevant: false):
  - Podcast episodes, interviews, opinion pieces, commentary
  - Product reviews, roundups, best-of lists
  - Entertainment segments, hype, speculation, vague "could happen" framing
  - Marketing, announcements, product launches without a security event

{
  "relevant": true | false,
  "ai_summary": "2-3 sentence buyer-facing plain English summary of the security risk",
  "ai_category": "vuln" | "attack" | "safety",
  "ai_vendor": "<vendor name or null if unknown>",
  "ai_model": "<model name or null if unknown>",
  "ai_robot_class": "humanoid" | "quadruped" | "consumer",
  "ai_severity": {
    "source": "cvss" | "estimated",
    "value": "<numeric CVSS score string like '7.5' if CVSS present, else 'low' | 'medium' | 'high' | 'critical'>"
  }
}

Rules:
- relevant MUST be true only if the article describes a discrete security \
or safety incident.  If relevant is false, set all other fields to null.
- ai_category MUST be one of: vuln, attack, safety
- ai_robot_class MUST be one of: humanoid, quadruped, consumer
- ai_severity.source MUST be "cvss" only if the article text contains an \
explicit CVSS score.  If source is cvss, value must be the numeric score \
string (e.g. "7.5").  If source is "estimated", value must be one of: \
low, medium, high, critical.
- ai_summary MUST be 2-3 sentences in plain English suitable for a \
non-technical buyer.
- Return ONLY the JSON object.  No markdown fences, no extra text."""


# ── Helpers ──────────────────────────────────────────────────────────


def _parse_severity(raw: dict[str, Any] | None) -> Severity | None:
    """Parse severity from LLM response, returning *None* if invalid."""
    if not raw or not isinstance(raw, dict):
        return None
    source = raw.get("source")
    value = raw.get("value")
    if source not in ("cvss", "estimated"):
        return None
    if source == "cvss":
        if not isinstance(value, str) or not re.match(r"^\d+(?:\.\d+)?$", value):
            return None
        return Severity(source="cvss", value=value)
    # estimated
    if value not in SEVERITY_BANDS:
        return None
    return Severity(source="estimated", value=value)


def _extract_json(text: str) -> dict[str, Any] | None:
    """Try to extract a JSON object from LLM text output.

    Handles clean JSON, markdown-fenced JSON, and prose containing an
    embedded JSON object.
    """
    cleaned = text.strip()

    # Strip markdown code fences (```json ... ``` or ``` ... ```)
    if cleaned.startswith("```"):
        cleaned = re.sub(r"^```\w*\s*\n?", "", cleaned)
        cleaned = re.sub(r"\n?```\s*$", "", cleaned)
        cleaned = cleaned.strip()

    # Direct parse
    try:
        return json.loads(cleaned)
    except (json.JSONDecodeError, ValueError):
        pass

    # Find the outermost { ... } pair
    try:
        start = cleaned.index("{")
        end = cleaned.rindex("}") + 1
        return json.loads(cleaned[start:end])
    except (ValueError, json.JSONDecodeError):
        return None


def _apply_enrichment(item: Item, data: dict[str, Any]) -> None:
    """Apply parsed LLM data to *item* in place.

    Invalid enum values are silently dropped to ``None`` — never crash.
    Severity follows the CVSS-over-text rule: if the item text carries an
    explicit CVSS score we use ``source=cvss``; otherwise the model's
    estimated band is used with ``source=estimated``.

    When ``relevant`` is explicitly ``false`` the item is marked as
    ``ai_relevant=False`` and all other ``ai_*`` fields are left as ``None``.
    When ``relevant`` is ``true`` the remaining fields are enriched normally.
    When ``relevant`` is absent or non-boolean ``ai_relevant`` is set to
    ``None`` (legacy behavior, eligibility layer decides).
    """
    # Relevance verdict — first check
    relevant = data.get("relevant")
    if isinstance(relevant, bool):
        item.ai_relevant = relevant
        if not relevant:
            # Commentary / non-incident: leave other ai_* fields as None
            return
    else:
        # Malformed or missing — leave as None (legacy path)
        item.ai_relevant = None

    # Basic string fields — drop empty / non-string to None
    summary = data.get("ai_summary")
    item.ai_summary = (
        summary if isinstance(summary, str) and summary.strip() else None
    )

    vendor = data.get("ai_vendor")
    item.ai_vendor = (
        vendor if isinstance(vendor, str) and vendor.strip() else None
    )

    model = data.get("ai_model")
    item.ai_model = (
        model if isinstance(model, str) and model.strip() else None
    )

    # Enum fields — only accept known values
    cat = data.get("ai_category")
    item.ai_category = cat if cat in CATEGORIES else None

    rc = data.get("ai_robot_class")
    item.ai_robot_class = rc if rc in ROBOT_CLASSES else None

    # Severity — CVSS-in-text takes precedence over model output
    cvss_match = _CVSS_RE.search(f"{item.title} {item.body}")
    if cvss_match:
        score = cvss_match.group(1)
        item.ai_severity = Severity(source="cvss", value=score)
    else:
        item.ai_severity = _parse_severity(data.get("ai_severity"))


def _build_payload(item: Item, model: str) -> dict[str, Any]:
    """Build the chat/completions request payload for one item."""
    return {
        "model": model,
        "messages": [
            {"role": "system", "content": _SYSTEM_PROMPT},
            {"role": "user", "content": f"Title: {item.title}\nBody: {item.body}"},
        ],
        "temperature": 0.2,
        "max_tokens": 1500,
    }


def _enrich_one(
    item: Item,
    base_url: str,
    model: str,
    api_key: str,
    transport: Callable[[dict], dict] | None,
) -> None:
    """Enrich a single item.  On *any* failure the item is left unenriched."""
    payload = _build_payload(item, model)
    try:
        if transport is not None:
            resp = transport(payload)
        else:
            headers = {
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            }
            session_id = os.environ.get("RADAR_LLM_SESSION_ID") or ""
            if session_id:
                headers["x-opencode-session"] = session_id
            with httpx.Client() as client:
                http_resp = client.post(
                    f"{base_url}/chat/completions",
                    json=payload,
                    headers=headers,
                    timeout=30.0,
                )
                http_resp.raise_for_status()
                resp = http_resp.json()

        content: str = resp["choices"][0]["message"]["content"]
        data = _extract_json(content)
        if data is None:
            log.warning("enrich: could not parse JSON for item %s", item.id)
            return
        _apply_enrichment(item, data)
    except Exception as exc:
        log.warning("enrich: item %s failed: %s", item.id, exc)


# ── Public API ───────────────────────────────────────────────────────


def enrich(
    items: list[Item],
    base_url: str,
    model: str,
    api_key: str,
    transport: Callable[[dict], dict] | None = None,
) -> None:
    """Enrich *items* in place via an OpenAI-compatible LLM.

    Parameters
    ----------
    items:
        Items to enrich (mutated in place).
    base_url:
        OpenAI-compatible API base URL (e.g. ``https://api.openai.com/v1``).
    model:
        Model name (e.g. ``gpt-4o-mini``).
    api_key:
        API key for the provider.
    transport:
        Injectable callable ``(payload_dict) -> response_dict`` for tests.
        When *None* the real httpx client is used with bounded concurrency.
    """
    if not items:
        return

    if transport is not None:
        # Synchronous path (tests / single-item)
        for item in items:
            _enrich_one(item, base_url, model, api_key, transport)
    else:
        # Production path — bounded concurrency via thread pool
        with ThreadPoolExecutor(max_workers=4) as pool:
            pool.map(
                lambda it: _enrich_one(it, base_url, model, api_key, None),
                items,
            )
