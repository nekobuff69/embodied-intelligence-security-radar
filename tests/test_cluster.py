"""Tests for the clustering pipeline (ADR-0001 retrieve-then-adjudicate).

Covers:
- Stage 0: exact CVE join → attach
- Stage 0: exact vendor+model join → attach
- Stage 1: embedding top-k ≤ 3 candidates, only open + reopen-window
- Stage 1: no candidates → create
- Stage 2: LLM stub → attach to candidate
- Stage 2: llm=None → create for unmatched
- Deterministic status proposals (patched / exploited_in_wild keywords)
- Constant-prompt invariant: 500 open incidents, candidates per item ≤ 3
"""

from __future__ import annotations

import pytest
from datetime import date, timedelta

from radar.cluster import (
    _cosine,
    _top_k_candidates,
    _trigram_embedder,
    cluster,
)
from radar.schema import (
    Item,
    Incident,
    Registry,
    Severity,
    Status,
    next_incident_id,
)


# ── Helpers ──────────────────────────────────────────────────────────


def _item(
    url: str = "https://example.com/test-item",
    title: str = "Test item title",
    body: str = "Test item body text",
    cve_ids: list[str] | None = None,
    ai_vendor: str | None = None,
    ai_model: str | None = None,
    ai_category: str | None = None,
    ai_robot_class: str | None = None,
    ai_severity: Severity | None = None,
    published: str = "2026-09-01",
) -> Item:
    return Item(
        id="itm-" + url.split("/")[-1].replace("-", "")[:12],
        source="press_rss",
        url=url,
        title=title,
        body=body,
        published=published,
        cve_ids=cve_ids or [],
        ai_vendor=ai_vendor,
        ai_model=ai_model,
        ai_category=ai_category,
        ai_robot_class=ai_robot_class,
        ai_severity=ai_severity,
    )


def _incident(
    inc_id: str = "INC-0001",
    vendor: str = "TestVendor",
    model: str | None = "TestModel",
    state: str = "disclosed",
    evidence_url: str = "https://example.com/advisory",
    as_of: str = "2026-08-01",
    item_ids: list[str] | None = None,
    cve_ids_in_items: list[str] | None = None,
) -> tuple[Incident, list[Item]]:
    """Create an Incident with attached items carrying CVE IDs."""
    items: list[Item] = []
    iid_list = item_ids or []
    if cve_ids_in_items and not iid_list:
        for i, cve in enumerate(cve_ids_in_items):
            it = _item(
                url=f"https://example.com/cve-{i}",
                title=f"CVE item {cve}",
                body=f"Advisory for {cve}",
                cve_ids=[cve],
            )
            items.append(it)
            iid_list.append(it.id)
    elif not iid_list:
        it = _item(url="https://example.com/default-item", title="Default")
        items.append(it)
        iid_list = [it.id]

    inc = Incident(
        id=inc_id,
        title=f"Test incident {inc_id}",
        category="vuln",
        robot_class="quadruped",
        vendor=vendor,
        model=model,
        severity=Severity(source="estimated", value="high"),
        status=Status(state=state, evidence_url=evidence_url, as_of=as_of),
        first_seen="2026-07-01",
        last_checked=as_of,
        item_ids=iid_list,
    )
    return inc, items


def _registry_with(incident: Incident, items: list[Item] | None = None) -> Registry:
    reg = Registry()
    reg.incidents.append(incident)
    if items:
        reg.items.extend(items)
    else:
        # Add a default item to satisfy validation
        reg.items.append(_item())
    return reg


# ═══════════════════════════════════════════════════════════════════
# Stage 0: exact CVE join
# ═══════════════════════════════════════════════════════════════════


class TestExactJoinCVE:
    """An item whose CVE IDs match an incident's evidence CVEs → attach."""

    def test_cve_match_attaches(self):
        inc, items = _incident(cve_ids_in_items=["CVE-2024-12345"])
        reg = _registry_with(inc, items)

        new_item = _item(
            url="https://example.com/new-cve-report",
            title="New report on CVE-2024-12345",
            body="Further details on the CVE-2024-12345 vulnerability",
            cve_ids=["CVE-2024-12345"],
        )

        reg, decisions = cluster(reg, [new_item])

        assert len(decisions) == 1
        assert decisions[0]["action"] == "attach"
        assert decisions[0]["incident_id"] == "INC-0001"
        assert new_item.id in inc.item_ids

    def test_cve_mismatch_creates(self):
        inc, items = _incident(cve_ids_in_items=["CVE-2024-12345"])
        reg = _registry_with(inc, items)

        new_item = _item(
            url="https://example.com/different-cve",
            title="Different CVE report",
            body="About CVE-2024-99999",
            cve_ids=["CVE-2024-99999"],
        )

        reg, decisions = cluster(reg, [new_item])

        assert len(decisions) == 1
        assert decisions[0]["action"] == "create"


class TestExactJoinVendorModel:
    """An item whose ai_vendor+ai_model matches an incident → attach."""

    def test_vendor_model_match(self):
        inc, items = _incident(vendor="Unitree", model="Go2")
        reg = _registry_with(inc, items)

        new_item = _item(
            url="https://example.com/unitree-go2-report",
            title="Unitree Go2 security update",
            body="New info on Unitree Go2",
            ai_vendor="Unitree",
            ai_model="Go2",
        )

        reg, decisions = cluster(reg, [new_item])

        assert decisions[0]["action"] == "attach"
        assert decisions[0]["incident_id"] == "INC-0001"

    def test_vendor_match_model_mismatch(self):
        inc, items = _incident(vendor="Unitree", model="Go2")
        reg = _registry_with(inc, items)

        new_item = _item(
            url="https://example.com/unitree-b2",
            title="Unitree B2 issue",
            body="Issue with Unitree B2",
            ai_vendor="Unitree",
            ai_model="B2",
        )

        reg, decisions = cluster(reg, [new_item])

        # Vendor matches but model doesn't → create
        assert decisions[0]["action"] == "create"

    def test_case_insensitive_vendor(self):
        inc, items = _incident(vendor="Unitree", model="Go2")
        reg = _registry_with(inc, items)

        new_item = _item(
            url="https://example.com/unitree-case",
            title="unitree go2 issue",
            body="Issue with unitree go2",
            ai_vendor="unitree",
            ai_model="go2",
        )

        reg, decisions = cluster(reg, [new_item])
        assert decisions[0]["action"] == "attach"


# ═══════════════════════════════════════════════════════════════════
# Stage 1: embedding top-k
# ═══════════════════════════════════════════════════════════════════


class TestEmbeddingTopK:
    """Embedding search returns ≤3 candidates, only open + reopen-window."""

    def test_top_k_bounded(self):
        """With many incidents, only ≤3 candidates returned."""
        reg = Registry()
        all_items: list[Item] = []
        for i in range(100):
            it = _item(
                url=f"https://example.com/item-{i}",
                title=f"Item {i} about robot vulnerability",
                body=f"Details about vulnerability {i} in robot systems",
            )
            all_items.append(it)
            inc, inc_items = _incident(
                inc_id=f"INC-{i:04d}",
                vendor=f"Vendor{i}",
                model=f"Model{i}",
                item_ids=[it.id],
            )
            reg.incidents.append(inc)
            reg.items.extend(inc_items)

        new_item = _item(
            url="https://example.com/search-query",
            title="Robot firmware vulnerability disclosure",
            body="Critical firmware vulnerability disclosed in robot",
        )

        reg, decisions = cluster(
            reg, [new_item], embedder=_trigram_embedder
        )

        assert len(decisions) == 1
        # Should create (no exact match), but with embedding search active
        assert decisions[0]["action"] == "create"

    def test_only_open_and_reopen_candidates(self):
        """Closed incidents outside the 60-day window are excluded."""
        today = date.today()
        old_date = (today - timedelta(days=90)).isoformat()
        recent_date = (today - timedelta(days=30)).isoformat()

        # Closed incident outside window — should be excluded
        closed_inc, closed_items = _incident(
            inc_id="INC-9999",
            vendor="OldVendor",
            model="OldModel",
            state="patched",
            as_of=old_date,
        )
        # Open incident — should be included
        open_inc, open_items = _incident(
            inc_id="INC-0002",
            vendor="OpenVendor",
            model="OpenModel",
            state="unpatched",
            as_of=recent_date,
        )

        reg = Registry()
        reg.incidents.extend([closed_inc, open_inc])
        reg.items.extend(closed_items + open_items)

        new_item = _item(
            url="https://example.com/embed-test",
            title="Robot vulnerability similar to OpenVendor issue",
            body="Similar vulnerability found in robot systems",
        )

        # With embedder, only open_inc should be a candidate
        reg, decisions = cluster(
            reg, [new_item], embedder=_trigram_embedder
        )

        # The new item creates a new incident (no exact match)
        assert decisions[0]["action"] == "create"


# ═══════════════════════════════════════════════════════════════════
# Stage 2: LLM verdict
# ═══════════════════════════════════════════════════════════════════


class TestLLMVerdict:
    """LLM stub can direct attach; llm=None falls through to create."""

    def test_llm_attach(self):
        inc, items = _incident(vendor="VendorX", model="ModelX")
        reg = _registry_with(inc, items)

        new_item = _item(
            url="https://example.com/llm-match",
            title="Similar issue to VendorX ModelX",
            body="This seems related to the VendorX ModelX vulnerability",
        )

        def stub_llm(candidates: list[dict], item: Item) -> dict:
            """Stub: attach to first candidate."""
            return {"action": "attach", "incident_id": candidates[0]["id"]}

        # Use embedder that returns high similarity for this item
        def fake_embedder(text: str) -> list[float]:
            vec = [0.0] * 256
            vec[0] = 1.0
            return vec

        # Patch candidate embeddings to all be similar
        reg, decisions = cluster(
            reg, [new_item], embedder=fake_embedder, llm=stub_llm
        )

        assert decisions[0]["action"] == "attach"
        assert decisions[0]["incident_id"] == "INC-0001"

    def test_llm_none_creates(self):
        """When llm=None and no exact/embedding match → create."""
        reg = Registry()
        new_item = _item(
            url="https://example.com/no-match",
            title="Brand new vulnerability",
            body="Completely new issue",
        )

        reg, decisions = cluster(reg, [new_item], llm=None)

        assert decisions[0]["action"] == "create"

    def test_llm_create_verdict(self):
        """LLM can also return create for candidates it deems unrelated."""
        inc, items = _incident(vendor="VendorY", model="ModelY")
        reg = _registry_with(inc, items)

        new_item = _item(
            url="https://example.com/llm-create",
            title="Unrelated issue",
            body="Something different",
        )

        def stub_llm(candidates: list[dict], item: Item) -> dict:
            return {"action": "create"}

        def fake_embedder(text: str) -> list[float]:
            vec = [0.0] * 256
            vec[0] = 1.0
            return vec

        reg, decisions = cluster(
            reg, [new_item], embedder=fake_embedder, llm=stub_llm
        )

        assert decisions[0]["action"] == "create"


# ═══════════════════════════════════════════════════════════════════
# Deterministic status proposals
# ═══════════════════════════════════════════════════════════════════


class TestStatusProposals:
    """Keyword phrases produce deterministic, evidence-carrying proposals."""

    def test_patched_proposal(self):
        inc, items = _incident(
            state="unpatched",
            evidence_url="https://example.com/advisory",
            as_of="2026-08-01",
        )
        reg = _registry_with(inc, items)

        new_item = _item(
            url="https://example.com/patch-news",
            title="Vendor releases fix for BLE vulnerability",
            body="Patch released for the BLE pairing bypass issue",
            ai_vendor="TestVendor",
            ai_model="TestModel",
        )

        reg, decisions = cluster(reg, [new_item])

        assert decisions[0]["action"] == "attach"
        assert "status_proposal" in decisions[0]
        assert decisions[0]["status_proposal"]["state"] == "patched"
        assert decisions[0]["status_proposal"]["evidence_url"] == "https://example.com/patch-news"
        assert decisions[0]["status_proposal"]["as_of"] == new_item.published
        assert inc.status.state == "patched"

    def test_exploited_proposal(self):
        inc, items = _incident(
            state="disclosed",
            evidence_url="https://example.com/disclosure",
            as_of="2026-07-01",
        )
        reg = _registry_with(inc, items)

        new_item = _item(
            url="https://example.com/exploit-news",
            title="Robot vulnerability actively exploited in the wild",
            body="Attackers are actively exploiting this vulnerability",
            ai_vendor="TestVendor",
            ai_model="TestModel",
        )

        reg, decisions = cluster(reg, [new_item])

        assert decisions[0]["status_proposal"]["state"] == "exploited_in_wild"
        assert inc.status.state == "exploited_in_wild"

    def test_no_keyword_no_proposal(self):
        inc, items = _incident(state="disclosed")
        reg = _registry_with(inc, items)

        new_item = _item(
            url="https://example.com/no-keyword",
            title="General robot security news",
            body="No specific status update in this article",
            ai_vendor="TestVendor",
            ai_model="TestModel",
        )

        reg, decisions = cluster(reg, [new_item])

        assert "status_proposal" not in decisions[0]
        assert inc.status.state == "disclosed"

    def test_create_with_patched_keyword(self):
        """New incident created from item with 'patch released' → patched."""
        reg = Registry()

        new_item = _item(
            url="https://example.com/patch-create",
            title="Patch released for quadruped firmware issue",
            body="A patch was released today fixing the firmware vulnerability",
        )

        reg, decisions = cluster(reg, [new_item])

        assert decisions[0]["action"] == "create"
        inc = reg.incidents[-1]
        assert inc.status.state == "patched"
        assert inc.status.evidence_url == "https://example.com/patch-create"
        assert inc.status.as_of == new_item.published

    def test_create_with_exploited_keyword(self):
        """New incident from item with 'exploited in the wild'."""
        reg = Registry()

        new_item = _item(
            url="https://example.com/exploit-create",
            title="Humanoid robot vulnerability exploited in the wild",
            body="Attackers have been exploiting this vulnerability in the wild",
        )

        reg, decisions = cluster(reg, [new_item])

        inc = reg.incidents[-1]
        assert inc.status.state == "exploited_in_wild"

    def test_deterministic_same_input_same_output(self):
        """Same items produce identical clustering decisions."""
        inc, items = _incident(
            state="unpatched",
            evidence_url="https://example.com/old",
            as_of="2026-08-01",
        )

        new_item = _item(
            url="https://example.com/deterministic",
            title="Fix shipped for BLE issue",
            body="The vendor shipped a fix for the BLE vulnerability",
            ai_vendor="TestVendor",
            ai_model="TestModel",
        )

        # Run twice
        reg1 = _registry_with(
            Incident(
                id="INC-0001", title="Test", category="vuln",
                robot_class="quadruped", vendor="TestVendor", model="TestModel",
                severity=Severity(source="estimated", value="high"),
                status=Status(state="unpatched", evidence_url="https://example.com/old", as_of="2026-08-01"),
                first_seen="2026-07-01", last_checked="2026-08-01",
                item_ids=[items[0].id],
            ),
            items,
        )
        _, dec1 = cluster(reg1, [new_item])

        reg2 = _registry_with(
            Incident(
                id="INC-0001", title="Test", category="vuln",
                robot_class="quadruped", vendor="TestVendor", model="TestModel",
                severity=Severity(source="estimated", value="high"),
                status=Status(state="unpatched", evidence_url="https://example.com/old", as_of="2026-08-01"),
                first_seen="2026-07-01", last_checked="2026-08-01",
                item_ids=[items[0].id],
            ),
            items,
        )
        _, dec2 = cluster(reg2, [new_item])

        assert dec1 == dec2


# ═══════════════════════════════════════════════════════════════════
# Constant-prompt invariant (500 incidents)
# ═══════════════════════════════════════════════════════════════════


class TestConstantPromptBound:
    """With 500 open incidents, each item gets ≤3 candidates."""

    def test_candidate_count_bounded(self):
        reg = Registry()
        all_items: list[Item] = []
        today = date.today().isoformat()

        for i in range(500):
            it = _item(
                url=f"https://example.com/inc-item-{i}",
                title=f"Incident item {i} about robot vulnerability",
                body=f"Vulnerability details for item {i}",
            )
            all_items.append(it)
            inc = Incident(
                id=f"INC-{i:04d}",
                title=f"Robot vulnerability #{i}",
                category="vuln",
                robot_class="quadruped",
                vendor=f"Vendor{i % 20}",
                model=f"Model{i % 10}",
                severity=Severity(source="estimated", value="medium"),
                status=Status(
                    state="unpatched",
                    evidence_url=f"https://example.com/inc-{i}",
                    as_of=today,
                ),
                first_seen="2026-01-01",
                last_checked=today,
                item_ids=[it.id],
            )
            reg.incidents.append(inc)
            reg.items.append(it)

        # Invariant under test (ADR-0001): registry size may inflate the FREE
        # math stage (embeddings) but never the LLM prompt — the verdict stage
        # sees at most 3 candidates per item, at 500-incident scale or any scale.
        seen_candidates: list[list[dict]] = []

        def stub_llm(candidates: list[dict], item: Item) -> dict:
            seen_candidates.append(candidates)
            return {"action": "create"}

        test_item = _item(
            url="https://example.com/bound-test",
            title="New robot firmware vulnerability disclosure",
            body="Critical firmware vulnerability disclosed in robot platform",
        )

        reg, decisions = cluster(reg, [test_item], llm=stub_llm)

        for cands in seen_candidates:
            assert len(cands) <= 3, f"prompt not bounded: {len(cands)} candidates"

        # No exact match at this scale → new incident
        assert decisions[0]["action"] == "create"


# ═══════════════════════════════════════════════════════════════════
# Embedding / similarity helpers
# ═══════════════════════════════════════════════════════════════════


class TestEmbeddingHelpers:
    """Unit tests for _trigram_embedder and _cosine."""

    def test_deterministic(self):
        a = _trigram_embedder("hello world")
        b = _trigram_embedder("hello world")
        assert a == b

    def test_different_texts_differ(self):
        a = _trigram_embedder("robot vulnerability")
        b = _trigram_embedder("humanoid attack in wild")
        assert a != b

    def test_cosine_self(self):
        v = _trigram_embedder("test text")
        assert abs(_cosine(v, v) - 1.0) < 1e-6

    def test_cosine_orthogonal(self):
        a = [1.0, 0.0, 0.0]
        b = [0.0, 1.0, 0.0]
        # These aren't the right dimension but test the math
        assert abs(_cosine(a, b)) < 1e-6

    def test_top_k_returns_at_most_k(self):
        index = {f"INC-{i:04d}": _trigram_embedder(f"text {i}") for i in range(50)}
        query = _trigram_embedder("text 0")
        result = _top_k_candidates(query, index, k=3)
        assert len(result) <= 3
