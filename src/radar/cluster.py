"""Retrieve-then-adjudicate incident clustering (ADR-0001).

Stage 0: exact CVE / vendor+model join — zero LLM cost.
Stage 1: embedding cosine top-k over open + reopen-window incidents.
Stage 2: optional LLM verdict on remaining unmatched items.

Status proposals are deterministic: keyword phrases in item text produce
evidence-carrying proposals (ADR-0003).  The ``llm`` callable is injectable
(runner wires it from RADAR_LLM_* env vars); when *None* stage 2 is skipped.

Create eligibility: only items with CVE IDs *or* ai_relevant=True with a
known vendor (non-empty, non-Unknown) may create a new incident.  Items
failing this gate are ``defer``-ed: they remain on the wire but no incident
is created.
"""

from __future__ import annotations

import hashlib
import logging
import math
import re
from collections import defaultdict
from datetime import date, timedelta
from typing import Callable

from radar.registry import apply_status, attach_item
from radar.schema import (
    CATEGORIES,
    ROBOT_CLASSES,
    SEVERITY_BANDS,
    Incident,
    Item,
    Registry,
    Severity,
    Status,
    next_incident_id,
)

log = logging.getLogger(__name__)

# ── Vendor-only temporal join window ──────────────────────────────────

VENDOR_JOIN_DAYS = 120  # max days between item.published and incident.first_seen


def _parse_date_safe(iso_str: str | None) -> date | None:
    """Parse an ISO date string; return *None* on *None* or malformed input."""
    if not iso_str:
        return None
    try:
        return date.fromisoformat(iso_str)
    except (ValueError, TypeError):
        return None


# ── Deterministic status proposal keywords (ADR-0003) ────────────────

_PATCHED_KEYWORDS = (
    "patch released",
    "fixed in version",
    "update available",
    "patch available",
    "fix shipped",
)

_EXPLOITED_KEYWORDS = (
    "actively exploited",
    "exploited in the wild",
    "hacked in the wild",
)


# ── Char-trigram embedding (stdlib-only, deterministic) ──────────────

_EMBED_DIM = 256


def _trigram_embedder(text: str) -> list[float]:
    """Deterministic char-trigram hash embedding (no network, no LLM).

    Produces a 256-dim sparse-ish vector suitable for cosine similarity
    ranking.  Quality is sufficient for top-k candidate selection where
    an LLM later adjudicates.
    """
    text = text.lower()
    vec = [0.0] * _EMBED_DIM
    if len(text) < 3:
        # Pad short texts so they still produce a non-zero vector
        padded = (text + "   ")[:3]
        vec[sum(ord(c) for c in padded) % _EMBED_DIM] = 1.0
        return vec
    for i in range(len(text) - 2):
        tri = text[i : i + 3]
        h = int(hashlib.md5(tri.encode()).hexdigest(), 16)
        idx = h % _EMBED_DIM
        vec[idx] += 1.0
    # L2-normalise
    norm = math.sqrt(sum(v * v for v in vec)) or 1.0
    return [v / norm for v in vec]


# ── Similarity helpers ────────────────────────────────────────────────

def _cosine(a: list[float], b: list[float]) -> float:
    """Cosine similarity between two equal-length vectors."""
    return sum(x * y for x, y in zip(a, b))


def _top_k_candidates(
    query_emb: list[float],
    index: dict[str, list[float]],
    k: int = 3,
    threshold: float = 0.35,
) -> list[tuple[str, float]]:
    """Return up to *k* (incident_id, score) pairs above *threshold*."""
    scored = [
        (inc_id, _cosine(query_emb, emb))
        for inc_id, emb in index.items()
    ]
    scored.sort(key=lambda t: t[1], reverse=True)
    return [
        (inc_id, score)
        for inc_id, score in scored[:k]
        if score >= threshold
    ]


# ── Status proposal from item text (deterministic) ───────────────────


def _propose_status(text: str, evidence_url: str, as_of: str) -> dict | None:
    """Return a status proposal dict if text contains known keywords.

    Proposal carries evidence_url and as_of (ADR-0003 hygiene).
    Returns *None* when no keyword matches.
    """
    lower = text.lower()
    for kw in _PATCHED_KEYWORDS:
        if kw in lower:
            return {"state": "patched", "evidence_url": evidence_url, "as_of": as_of}
    for kw in _EXPLOITED_KEYWORDS:
        if kw in lower:
            return {"state": "exploited_in_wild", "evidence_url": evidence_url, "as_of": as_of}
    return None


# ── Main clustering pipeline ─────────────────────────────────────────


def candidate_index(
    reg: Registry,
    today: str | None = None,
    reopen_window_days: int = 60,
) -> dict[str, Incident]:
    """Return open + reopen-window Incidents that participate in clustering.

    Candidate set = Incidents whose status.state is open
    (disclosed / unpatched / exploited_in_wild) **or** whose status.as_of
    is within *reopen_window_days* of *today* (patch-bypass coverage).

    A fully-closed Incident whose as_of is older than the window is excluded.
    """
    if today is None:
        today = date.today().isoformat()
    open_states = {"disclosed", "unpatched", "exploited_in_wild"}
    try:
        cutoff = (date.fromisoformat(today) - timedelta(days=reopen_window_days)).isoformat()
    except (ValueError, TypeError):
        cutoff = "0000-01-01"
    result: dict[str, Incident] = {}
    for inc in reg.incidents:
        is_open = inc.status.state in open_states
        is_reopen_window = inc.status.as_of >= cutoff
        if is_open or is_reopen_window:
            result[inc.id] = inc
    return result


def cluster(
    reg: Registry,
    items: list[Item],
    embedder: Callable[[str], list[float]] | None = None,
    llm: Callable[[list[dict], Item], dict] | None = None,
    vector_memo: dict[str, list[float]] | None = None,
    today: str | None = None,
) -> tuple[Registry, list[dict]]:
    """Cluster *items* into *reg* incidents.

    Pipeline per item:
      stage 0  exact CVE / vendor+model join → attach (zero cost)
      stage 1  embedding cosine top-3 over open + reopen-window incidents
      stage 2  optional LLM verdict (only when stage 0 missed and stage 1
               found candidates; ``llm=None`` → skipped)

    Create eligibility: when no stage matched and a new incident would be
    created, only items with ``cve_ids`` *or* ``ai_relevant is True`` with
    a known vendor are eligible.  Ineligible items are deferred (stayed on
    the wire, no incident created).

    *vector_memo*: optional per-run dict keyed by incident id, caching
    precomputed vectors.  Passed in from a prior call (or empty dict on
    first call) so that repeated runs over an unchanged registry re-embed
    nothing (silence is free).  The memo is mutated in-place.

    Deterministic keyword phrases in item text produce evidence-carrying
    status proposals (ADR-0003).  Only ``patched`` and ``exploited_in_wild``
    are proposed; other transitions are human-curated.

    Returns ``(registry, decisions)`` where each decision is::

        {"action": "attach"|"create"|"defer",
         "incident_id"?: str,
         "status_proposal"?: dict}
    """
    if today is None:
        today = date.today().isoformat()
    decisions: list[dict] = []

    # ── Build candidate index ────────────────────────────────────────

    cand_incidents = candidate_index(reg, today)
    candidate_index_meta: dict[str, dict] = {}
    candidate_embeddings: dict[str, list[float]] = {}

    if vector_memo is None:
        vector_memo = {}
    query_vecs: dict[str, list[float]] = {}
    candidate_index_meta: dict = {}
    candidate_embeddings: dict = {}

    for inc_id, inc in cand_incidents.items():
        candidate_index_meta[inc.id] = {
            "id": inc.id,
            "title": inc.title,
            "vendor": inc.vendor,
            "model": inc.model,
            "status": inc.status.state,
            "first_seen": inc.first_seen,
        }
        # Reuse cached vector or compute once per run
        if inc.id in vector_memo:
            candidate_embeddings[inc.id] = vector_memo[inc.id]
        elif embedder is not None:
            text = f"{inc.title} {inc.vendor} {inc.model or ''}"
            vec = embedder(text)
            vector_memo[inc.id] = vec
            candidate_embeddings[inc.id] = vec

    # ── Process each item ────────────────────────────────────────────

    # Pre-compute set of already-attached item IDs for idempotency:
    # items already clustered into an incident are skipped on re-runs.
    already_attached: set[str] = set()
    for inc in reg.incidents:
        already_attached.update(inc.item_ids)

    for item in items:
        # Skip items already attached to an incident (idempotent re-run)
        if item.id in already_attached:
            continue

        matched_inc: Incident | None = None

        # Stage 0: exact joins in strict precedence order — three separate
        # passes over the registry so a weaker rule on an earlier incident
        # can never shadow a stronger rule on a later one.
        # Pass 1: CVE join (strongest).
        if item.cve_ids:
            item_cves = set(item.cve_ids)
            for inc in reg.incidents:
                inc_cves: set[str] = set()
                for iid in inc.item_ids:
                    for iobj in reg.items:
                        if iobj.id == iid:
                            inc_cves.update(iobj.cve_ids)
                if inc_cves & item_cves:
                    matched_inc = inc
                    break
        # Pass 2: full vendor+model.
        if matched_inc is None and item.ai_vendor is not None:
            for inc in reg.incidents:
                if not (inc.vendor and item.ai_vendor.lower() == inc.vendor.lower()):
                    continue
                if item.ai_model is not None and inc.model and item.ai_model.lower() == inc.model.lower():
                    matched_inc = inc
                    break
                if item.ai_model is None and inc.model is None:
                    matched_inc = inc
                    break
        # Pass 3: vendor-only temporal join — same vendor, at least one side
        # has unknown model, within VENDOR_JOIN_DAYS of the incident's
        # first-seen. Deterministic: no LLM cost, operator can split later.
        if matched_inc is None and item.ai_vendor is not None:
            item_date = _parse_date_safe(item.published)
            if item_date is not None:
                for inc in reg.incidents:
                    if not (inc.vendor and item.ai_vendor.lower() == inc.vendor.lower()):
                        continue
                    if not (item.ai_model is None or inc.model is None):
                        continue
                    inc_date = _parse_date_safe(inc.first_seen)
                    if inc_date is not None and abs((item_date - inc_date).days) <= VENDOR_JOIN_DAYS:
                        matched_inc = inc
                        break

        # Stage 1 & 2: embedding + optional LLM
        if matched_inc is None and embedder is not None and candidate_embeddings:
            query_text = f"{item.title} {item.body}"
            query_emb = embedder(query_text)
            query_vecs[item.id] = query_emb
            top = _top_k_candidates(query_emb, candidate_embeddings)

            if top and llm is not None:
                candidate_blubs = []
                for cid, _score in top:
                    cand = candidate_index_meta[cid]
                    candidate_blubs.append(
                        {
                            "id": cand["id"],
                            "title": cand["title"],
                            "status": cand["status"],
                            "first_seen": cand["first_seen"],
                        }
                    )
                verdict = llm(candidate_blubs, item)
                action = verdict.get("action", "create")
                if action == "attach":
                    vid = verdict.get("incident_id")
                    for inc in reg.incidents:
                        if inc.id == vid:
                            matched_inc = inc
                            break

        # ── Decision ─────────────────────────────────────────────────

        if matched_inc is not None:
            # Attach
            attach_item(matched_inc, item)
            dec: dict = {"action": "attach", "incident_id": matched_inc.id}

            # Deterministic status proposal from item text keywords
            proposal = _propose_status(
                f"{item.title} {item.body}", item.url, item.published
            )
            if proposal is not None:
                changed = apply_status(matched_inc, proposal)
                if changed:
                    dec["status_proposal"] = proposal

            decisions.append(dec)
        else:
            # Create-eligibility gate: only items with CVE IDs or
            # ai_relevant=True with a known vendor may create incidents.
            # Ineligible items stay on the wire (deferred).
            has_cve = bool(item.cve_ids)
            is_eligible = has_cve or (
                item.ai_relevant is True
                and item.ai_vendor not in (None, "", "Unknown")
            )
            if not is_eligible:
                decisions.append({"action": "defer"})
                continue

            # Create new incident
            inc_id = next_incident_id(reg)

            vendor = item.ai_vendor or "Unknown"
            model = item.ai_model
            category = item.ai_category if item.ai_category in CATEGORIES else "vuln"
            robot_class = (
                item.ai_robot_class
                if item.ai_robot_class in ROBOT_CLASSES
                else "consumer"
            )

            if item.ai_severity and item.ai_severity.value in SEVERITY_BANDS:
                severity = Severity(source="estimated", value=item.ai_severity.value)
            else:
                severity = Severity(source="estimated", value="medium")

            # Deterministic initial status from keywords
            proposal = _propose_status(
                f"{item.title} {item.body}", item.url, item.published
            )
            if proposal is not None:
                init_state = proposal["state"]
                init_evidence = proposal["evidence_url"]
                init_as_of = proposal["as_of"]
            else:
                init_state = "disclosed"
                init_evidence = item.url
                init_as_of = item.published

            inc = Incident(
                id=inc_id,
                title=item.title,
                category=category,
                robot_class=robot_class,
                vendor=vendor,
                model=model,
                severity=severity,
                status=Status(
                    state=init_state,
                    evidence_url=init_evidence,
                    as_of=init_as_of,
                ),
                first_seen=item.published,
                last_checked=today,
                item_ids=[item.id],
            )
            reg.incidents.append(inc)
            # The new incident's vector is the item's query vector — store it
            # so later runs in the same memo never re-embed this incident.
            if item.id in query_vecs:
                vector_memo[inc_id] = query_vecs[item.id]
            decisions.append({"action": "create", "incident_id": inc_id})

    return reg, decisions
