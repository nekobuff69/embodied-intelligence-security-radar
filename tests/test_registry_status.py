"""Tests for registry status hygiene (ADR-0003) and offline double-run stability.

Covers:
- apply_status: rejects missing evidence_url / bad as_of / illegal state
- apply_status: identical re-proposal is a no-op
- attach_item: idempotent
- Runner-level: offline double-run → incident count stable (no duplicate creation)
"""

from __future__ import annotations

import json
import pytest
from pathlib import Path

from radar.registry import apply_status, apply_items, attach_item, load, save
from radar.schema import (
    Item,
    Incident,
    Registry,
    Severity,
    Status,
    next_incident_id,
)

FIXTURES_RAW = Path(__file__).resolve().parent / "fixtures" / "raw"
FIXTURE_REGISTRY = (
    Path(__file__).resolve().parents[1] / "data" / "fixtures" / "registry.json"
)


# ── Helpers ──────────────────────────────────────────────────────────


def _item(
    url: str = "https://example.com/test-item",
    title: str = "Test item",
    body: str = "Test body",
    published: str = "2026-09-01",
    cve_ids: list[str] | None = None,
    ai_vendor: str | None = None,
    ai_model: str | None = None,
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
    )


def _incident(
    inc_id: str = "INC-0001",
    state: str = "disclosed",
    evidence_url: str = "https://example.com/evidence",
    as_of: str = "2026-08-01",
) -> Incident:
    return Incident(
        id=inc_id,
        title=f"Test incident {inc_id}",
        category="vuln",
        robot_class="quadruped",
        vendor="TestVendor",
        model="TestModel",
        severity=Severity(source="estimated", value="high"),
        status=Status(state=state, evidence_url=evidence_url, as_of=as_of),
        first_seen="2026-07-01",
        last_checked=as_of,
        item_ids=["itm-default"],
    )


# ═══════════════════════════════════════════════════════════════════
# apply_status hygiene
# ═══════════════════════════════════════════════════════════════════


class TestApplyStatusHygiene:
    """ADR-0003: every status change requires evidence_url + as_of."""

    def test_missing_evidence_url(self):
        inc = _incident()
        with pytest.raises(ValueError, match="evidence_url"):
            apply_status(inc, {"state": "patched", "as_of": "2026-09-01"})

    def test_empty_evidence_url(self):
        inc = _incident()
        with pytest.raises(ValueError, match="evidence_url"):
            apply_status(inc, {
                "state": "patched",
                "evidence_url": "",
                "as_of": "2026-09-01",
            })

    def test_non_http_evidence_url(self):
        inc = _incident()
        with pytest.raises(ValueError, match="evidence_url"):
            apply_status(inc, {
                "state": "patched",
                "evidence_url": "ftp://example.com/file",
                "as_of": "2026-09-01",
            })

    def test_missing_as_of(self):
        inc = _incident()
        with pytest.raises(ValueError, match="as_of"):
            apply_status(inc, {
                "state": "patched",
                "evidence_url": "https://example.com/evidence",
            })

    def test_bad_as_of_format(self):
        inc = _incident()
        with pytest.raises(ValueError, match="as_of"):
            apply_status(inc, {
                "state": "patched",
                "evidence_url": "https://example.com/evidence",
                "as_of": "2026/09/01",
            })

    def test_illegal_state(self):
        inc = _incident()
        with pytest.raises(ValueError, match="invalid status state"):
            apply_status(inc, {
                "state": "bogus_state",
                "evidence_url": "https://example.com/evidence",
                "as_of": "2026-09-01",
            })

    def test_valid_transition(self):
        inc = _incident(state="disclosed")
        changed = apply_status(inc, {
            "state": "patched",
            "evidence_url": "https://example.com/patch",
            "as_of": "2026-09-01",
        })
        assert changed is True
        assert inc.status.state == "patched"
        assert inc.status.evidence_url == "https://example.com/patch"
        assert inc.status.as_of == "2026-09-01"


# ═══════════════════════════════════════════════════════════════════
# Idempotency
# ═══════════════════════════════════════════════════════════════════


class TestApplyStatusIdempotent:
    """Identical re-proposal is a no-op (same state + same evidence)."""

    def test_same_proposal_noop(self):
        inc = _incident(state="patched", evidence_url="https://example.com/p", as_of="2026-09-01")
        changed = apply_status(inc, {
            "state": "patched",
            "evidence_url": "https://example.com/p",
            "as_of": "2026-09-01",
        })
        assert changed is False
        assert inc.status.state == "patched"

    def test_different_evidence_is_change(self):
        inc = _incident(state="patched", evidence_url="https://example.com/p1", as_of="2026-09-01")
        changed = apply_status(inc, {
            "state": "patched",
            "evidence_url": "https://example.com/p2",
            "as_of": "2026-09-02",
        })
        assert changed is True

    def test_different_state_is_change(self):
        inc = _incident(state="disclosed")
        changed = apply_status(inc, {
            "state": "patched",
            "evidence_url": "https://example.com/evidence",
            "as_of": "2026-09-01",
        })
        assert changed is True


class TestAttachItem:
    """attach_item is idempotent."""

    def test_first_attach(self):
        inc = _incident()
        item = _item(url="https://example.com/new", title="New")
        attach_item(inc, item)
        assert item.id in inc.item_ids

    def test_second_attach_noop(self):
        inc = _incident()
        item = _item(url="https://example.com/new", title="New")
        attach_item(inc, item)
        attach_item(inc, item)
        assert inc.item_ids.count(item.id) == 1

    def test_different_items_both_added(self):
        inc = _incident()
        item1 = _item(url="https://example.com/a", title="A")
        item2 = _item(url="https://example.com/b", title="B")
        attach_item(inc, item1)
        attach_item(inc, item2)
        assert item1.id in inc.item_ids
        assert item2.id in inc.item_ids
        assert len(inc.item_ids) == 3  # itm-default + the two added


# ═══════════════════════════════════════════════════════════════════
# Registry validation: no status without evidence
# ═══════════════════════════════════════════════════════════════════


class TestRegistryNoBareStatus:
    """Schema validation rejects status without evidence (ADR-0003)."""

    def test_fixture_registry_valid(self):
        """The committed fixture registry must pass validation."""
        reg = load(FIXTURE_REGISTRY)
        # validate() is called by load_registry/from_dict, so if we got
        # here it already passed.  Double-check explicitly:
        reg.validate()

    def test_incident_requires_item_ids(self):
        """An incident with empty item_ids is invalid."""
        with pytest.raises(ValueError, match="must reference at least one Item"):
            Incident(
                id="INC-BAD",
                title="Bad",
                category="vuln",
                robot_class="quadruped",
                vendor="X",
                severity=Severity(source="estimated", value="medium"),
                status=Status(
                    state="disclosed",
                    evidence_url="https://example.com/e",
                    as_of="2026-09-01",
                ),
                first_seen="2026-09-01",
                last_checked="2026-09-01",
                item_ids=[],
            )


# ═══════════════════════════════════════════════════════════════════
# Offline double-run stability
# ═══════════════════════════════════════════════════════════════════


class TestOfflineDoubleRunStability:
    """Running the full pipeline offline twice produces stable incident counts.

    The second run must not add new incidents beyond the first run.
    This tests the idempotency of the full cluster + registry pipeline.
    """

    def test_incident_count_stable(self, tmp_path: Path):
        from radar.runner import run

        reg_path = tmp_path / "registry.json"
        site_dir = tmp_path / "site"

        # First run
        s1 = run(
            offline=True,
            registry_path=reg_path,
            raw_dir=FIXTURES_RAW,
            site_dir=site_dir,
        )
        count_after_first = s1["created"]

        # Second run (same fixtures, same registry)
        s2 = run(
            offline=True,
            registry_path=reg_path,
            raw_dir=FIXTURES_RAW,
            site_dir=site_dir,
        )

        # Reload and count
        reg = load(reg_path)
        total_incidents = len(reg.incidents)

        # The second run created 0 new incidents (items already in registry,
        # clustering is idempotent)
        assert s2["created"] == 0, (
            f"Second run created {s2['created']} incidents; expected 0"
        )
        assert s2["attached"] == 0, (
            f"Second run attached {s2['attached']} items; expected 0"
        )

        # Total incidents unchanged
        assert total_incidents > 0, "First run should have created incidents"

    def test_no_duplicate_items(self, tmp_path: Path):
        """Second run must not add duplicate items."""
        from radar.runner import run

        reg_path = tmp_path / "registry.json"
        site_dir = tmp_path / "site"

        run(offline=True, registry_path=reg_path, raw_dir=FIXTURES_RAW, site_dir=site_dir)
        run(offline=True, registry_path=reg_path, raw_dir=FIXTURES_RAW, site_dir=site_dir)

        reg = load(reg_path)
        item_urls = [i.url for i in reg.items]
        assert len(item_urls) == len(set(item_urls)), "Duplicate items found"
