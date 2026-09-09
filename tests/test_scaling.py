"""Tests for registry scaling: candidate_index, vector memo, silence-free re-runs.

Covers ADR-0001 cost bounds:
- candidate_index excludes closed-beyond-60d and includes open + reopen-window.
- Vector memo: second cluster() call over same registry re-embeds nothing.
- Silence is free: offline double-run performs zero LLM calls.
"""

from __future__ import annotations

from datetime import date, timedelta
from pathlib import Path
from typing import Callable

import pytest

from radar.cluster import candidate_index, cluster, _trigram_embedder
from radar.schema import (
    Incident,
    Item,
    Registry,
    Severity,
    Status,
    item_id_for_url,
    next_incident_id,
)


# ── Helpers ──────────────────────────────────────────────────────────


def _make_incident(
    inc_id: str,
    state: str = "disclosed",
    as_of: str = "2026-01-01",
    vendor: str = "Vendor",
    model: str | None = "Model",
) -> tuple[Incident, list[Item]]:
    it = Item(
        id=item_id_for_url(f"https://example.com/{inc_id}"),
        source="press_rss",
        url=f"https://example.com/{inc_id}",
        title=f"Advisory for {inc_id}",
        body=f"Body for {inc_id}",
        published=as_of,
    )
    inc = Incident(
        id=inc_id,
        title=f"Test incident {inc_id}",
        category="vuln",
        robot_class="quadruped",
        vendor=vendor,
        model=model,
        severity=Severity(source="estimated", value="high"),
        status=Status(state=state, evidence_url=f"https://example.com/{inc_id}", as_of=as_of),
        first_seen=as_of,
        last_checked=as_of,
        item_ids=[it.id],
    )
    return inc, [it]


def _registry_with(*incidents_inc_items: tuple[Incident, list[Item]]) -> Registry:
    reg = Registry()
    for inc, items in incidents_inc_items:
        reg.incidents.append(inc)
        reg.items.extend(items)
    return reg


def _make_new_item(title: str = "New report", url_suffix: str = "new") -> Item:
    return Item(
        id=item_id_for_url(f"https://example.com/{url_suffix}"),
        source="press_rss",
        url=f"https://example.com/{url_suffix}",
        title=title,
        body="Body of new report about robot vulnerability",
        published="2026-09-01",
    )


# ═══════════════════════════════════════════════════════════════════
# 1. candidate_index membership
# ═══════════════════════════════════════════════════════════════════


class TestCandidateIndexMembership:
    """candidate_index includes open + reopen-window, excludes closed-beyond-60d."""

    def test_open_included(self):
        inc, items = _make_incident("INC-0001", state="unpatched", as_of="2026-08-01")
        reg = _registry_with((inc, items))
        ci = candidate_index(reg, today="2026-09-09")
        assert "INC-0001" in ci

    def test_disclosed_included(self):
        inc, items = _make_incident("INC-0001", state="disclosed", as_of="2026-08-01")
        reg = _registry_with((inc, items))
        ci = candidate_index(reg, today="2026-09-09")
        assert "INC-0001" in ci

    def test_exploited_in_wild_included(self):
        inc, items = _make_incident("INC-0001", state="exploited_in_wild", as_of="2026-08-01")
        reg = _registry_with((inc, items))
        ci = candidate_index(reg, today="2026-09-09")
        assert "INC-0001" in ci

    def test_closed_within_60d_included(self):
        """Patched incident whose as_of is within 60 days → included."""
        cutoff_date = date(2026, 9, 9) - timedelta(days=55)  # 55 days ago → within window
        inc, items = _make_incident("INC-0001", state="patched", as_of=cutoff_date.isoformat())
        reg = _registry_with((inc, items))
        ci = candidate_index(reg, today="2026-09-09")
        assert "INC-0001" in ci

    def test_closed_beyond_60d_excluded(self):
        """Patched incident whose as_of is >60 days ago → excluded."""
        cutoff_date = date(2026, 9, 9) - timedelta(days=65)  # 65 days ago → beyond window
        inc, items = _make_incident("INC-0001", state="patched", as_of=cutoff_date.isoformat())
        reg = _registry_with((inc, items))
        ci = candidate_index(reg, today="2026-09-09")
        assert "INC-0001" not in ci

    def test_resolved_beyond_60d_excluded(self):
        cutoff_date = date(2026, 9, 9) - timedelta(days=90)
        inc, items = _make_incident("INC-0001", state="resolved", as_of=cutoff_date.isoformat())
        reg = _registry_with((inc, items))
        ci = candidate_index(reg, today="2026-09-09")
        assert "INC-0001" not in ci

    def test_empty_registry(self):
        reg = Registry()
        ci = candidate_index(reg, today="2026-09-09")
        assert ci == {}


class TestCandidateIndexEdgeCases:
    """Boundary conditions for reopen window."""

    def test_exactly_60d_included(self):
        """as_of == today - 60 days → included (>= cutoff)."""
        cutoff_date = date(2026, 9, 9) - timedelta(days=60)
        inc, items = _make_incident("INC-0001", state="patched", as_of=cutoff_date.isoformat())
        reg = _registry_with((inc, items))
        ci = candidate_index(reg, today="2026-09-09")
        assert "INC-0001" in ci

    def test_61d_excluded(self):
        cutoff_date = date(2026, 9, 9) - timedelta(days=61)
        inc, items = _make_incident("INC-0001", state="patched", as_of=cutoff_date.isoformat())
        reg = _registry_with((inc, items))
        ci = candidate_index(reg, today="2026-09-09")
        assert "INC-0001" not in ci


# ═══════════════════════════════════════════════════════════════════
# 2. Vector memo kills redundant embedding
# ═══════════════════════════════════════════════════════════════════


class TestVectorMemo:
    """Second cluster() call with same registry re-embeds nothing (memo hit)."""

    def test_second_call_zero_embeds(self):
        # Create a registry with 200 open incidents
        reg = Registry()
        for i in range(200):
            inc, items = _make_incident(
                f"INC-{i+1:04d}",
                state="unpatched",
                as_of="2026-09-01",
                vendor=f"Vendor{i}",
                model=f"Model{i}",
            )
            reg.incidents.append(inc)
            reg.items.extend(items)

        embed_calls = {"n": 0}

        def counting_embedder(text: str) -> list[float]:
            embed_calls["n"] += 1
            return _trigram_embedder(text)

        memo: dict[str, list[float]] = {}

        # First run: 200 incident vectors + 1 query embed for the item itself
        new_item_1 = _make_new_item("First report", "first-run")
        _, _ = cluster(reg, [new_item_1], embedder=counting_embedder, llm=None, vector_memo=memo)
        first_run_embeds = embed_calls["n"]
        assert first_run_embeds == 201, f"expected 200 incident embeds + 1 query, got {first_run_embeds}"

        # Second run, same registry: memo must prevent re-embedding the 200
        # incident vectors; only the new item's query embed occurs.
        new_item_2 = _make_new_item("Second report", "second-run")
        embed_calls["n"] = 0
        _, _ = cluster(reg, [new_item_2], embedder=counting_embedder, llm=None, vector_memo=memo)
        second_run_embeds = embed_calls["n"]
        assert second_run_embeds == 1, (
            f"Expected 1 embed (query only) on second run with memo, got {second_run_embeds}"
        )

    def test_new_incident_gets_embedded(self):
        """A new incident added between runs is embedded once; existing ones are memoized."""
        reg = Registry()
        for i in range(10):
            inc, items = _make_incident(
                f"INC-{i+1:04d}",
                state="unpatched",
                as_of="2026-09-01",
                vendor=f"Vendor{i}",
            )
            reg.incidents.append(inc)
            reg.items.extend(items)

        embed_calls = {"n": 0}

        def counting_embedder(text: str) -> list[float]:
            embed_calls["n"] += 1
            return _trigram_embedder(text)

        memo: dict[str, list[float]] = {}

        # First run: 10 incident vectors + 1 query embed
        item_1 = _make_new_item("Report 1", "r1")
        cluster(reg, [item_1], embedder=counting_embedder, llm=None, vector_memo=memo)
        assert embed_calls["n"] == 11, f"expected 10 incident embeds + 1 query, got {embed_calls['n']}"

        new_inc, new_items = _make_incident(
            "INC-0101", state="unpatched", as_of="2026-09-01", vendor="NewVendor"
        )
        reg.incidents.append(new_inc)
        reg.items.extend(new_items)

        # Second run: only the new incident's vector (1) + the query embed (1)
        embed_calls["n"] = 0
        item_2 = _make_new_item("Report 2", "r2")
        cluster(reg, [item_2], embedder=counting_embedder, llm=None, vector_memo=memo)
        assert embed_calls["n"] == 2, (
            f"Expected 2 embeds (new incident vector + query), got {embed_calls['n']}"
        )


# ═══════════════════════════════════════════════════════════════════
# 3. Silence is free: offline double-run zero LLM + stable counts
# ═══════════════════════════════════════════════════════════════════


class TestSilenceIsFree:
    """An offline double-run with the same fixtures performs zero LLM calls
    and incident count stays stable."""

    def test_offline_double_run(self, tmp_path: Path):
        """Simulate: build registry, run cluster twice with no new items → 0 LLM calls."""
        from radar.runner import run

        # We need raw fixtures; use the existing test fixtures
        fixtures_raw = Path(__file__).resolve().parent / "fixtures" / "raw"
        registry_path = tmp_path / "registry.json"

        # First run
        result1 = run(
            offline=True,
            registry_path=registry_path,
            raw_dir=fixtures_raw,
            site_dir=tmp_path / "site1",
        )
        incident_count_1 = result1["created"] + result1["attached"]
        llm_calls_run1 = result1.get("llm_model", "skipped")

        # Second run — same fixtures, should be idempotent
        result2 = run(
            offline=True,
            registry_path=registry_path,
            raw_dir=fixtures_raw,
            site_dir=tmp_path / "site2",
        )

        # Zero LLM calls in offline mode (no API key → skipped)
        assert result2["llm_model"] == "skipped"
        assert result2["llm_provider"] == "skipped"

        # Monitor skipped in offline mode
        assert result2.get("monitor_checked", 0) == 0

        # Incident count stable
        assert result2["created"] == 0, "Second run should create 0 new incidents"
        assert result2["added"] == 0, "Second run should add 0 new items"
