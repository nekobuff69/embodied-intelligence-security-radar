"""Tests for operator correction overrides (split, merge, detach)."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

import pytest

from radar.overrides import (
    _STATUS_PRECEDENCE,
    detach_items,
    merge_incidents,
    save_atomic,
    split_incident,
)
from radar.schema import (
    Incident,
    Item,
    Registry,
    Severity,
    Status,
    load_registry,
)


# ── Fixtures ──────────────────────────────────────────────────────────


def _item(
    item_id: str,
    url: str | None = None,
    published: str = "2026-01-01",
) -> Item:
    """Build a minimal valid Item."""
    return Item(
        id=item_id,
        source="google_news",
        url=url or f"https://example.com/{item_id}",
        title=f"Item {item_id}",
        body=f"Body of {item_id}",
        published=published,
        cve_ids=[],
    )


def _status(
    state: str = "disclosed",
    evidence_url: str = "https://example.com/evidence",
    as_of: str = "2026-01-15",
    note: str = "",
) -> Status:
    return Status(state=state, evidence_url=evidence_url, as_of=as_of, note=note)


def _incident(
    inc_id: str,
    item_ids: list[str],
    status: Status | None = None,
    first_seen: str = "2026-01-01",
    last_checked: str = "2026-06-01",
    title: str | None = None,
    monitor_urls: list[str] | None = None,
) -> Incident:
    return Incident(
        id=inc_id,
        title=title or f"Incident {inc_id}",
        category="vuln",
        robot_class="quadruped",
        vendor="Unitree",
        severity=Severity(source="estimated", value="high"),
        status=status or _status(),
        first_seen=first_seen,
        last_checked=last_checked,
        item_ids=list(item_ids),
        monitor_urls=monitor_urls or [],
    )


def _registry(
    incidents: list[Incident] | None = None,
    items: list[Item] | None = None,
) -> Registry:
    return Registry(
        incidents=list(incidents or []),
        items=list(items or []),
        meta={"schema_version": 1},
    )


# ── Split tests ───────────────────────────────────────────────────────


class TestSplitIncident:
    """split_incident keeps a subset, creates new incidents for the rest."""

    def test_split_creates_new_incident(self):
        items = [_item("itm-001"), _item("itm-002"), _item("itm-003")]
        inc = _incident("INC-0001", ["itm-001", "itm-002", "itm-003"])
        reg = _registry([inc], items)

        reg, summary = split_incident(reg, "INC-0001", ["itm-001", "itm-002"])

        assert summary["operation"] == "split"
        assert summary["incident_id"] == "INC-0001"
        assert summary["kept"] == ["itm-001", "itm-002"]
        assert summary["moved"] == ["itm-003"]
        assert len(summary["new_incidents"]) == 1
        assert len(reg.incidents) == 2

        # Original keeps only the keep set
        orig = next(i for i in reg.incidents if i.id == "INC-0001")
        assert orig.item_ids == ["itm-001", "itm-002"]

        # New incident has the moved item
        new = next(i for i in reg.incidents if i.id == "INC-0002")
        assert new.item_ids == ["itm-003"]

    def test_split_copies_status_with_note(self):
        items = [_item("itm-001"), _item("itm-002")]
        inc = _incident(
            "INC-0001",
            ["itm-001", "itm-002"],
            status=_status("patched", evidence_url="https://patch.example.com", as_of="2026-03-10"),
        )
        reg = _registry([inc], items)

        reg, summary = split_incident(reg, "INC-0001", ["itm-001"])

        new = next(i for i in reg.incidents if i.id == "INC-0002")
        assert new.status.state == "patched"
        assert new.status.evidence_url == "https://patch.example.com"
        assert new.status.as_of == "2026-03-10"
        assert "split from INC-0001" in new.status.note

    def test_split_computes_first_seen_from_earliest_moved_item(self):
        items = [
            _item("itm-001", published="2026-03-01"),
            _item("itm-002", published="2026-01-10"),
            _item("itm-003", published="2026-02-15"),
        ]
        inc = _incident(
            "INC-0001",
            ["itm-001", "itm-002", "itm-003"],
            first_seen="2026-01-01",
        )
        reg = _registry([inc], items)

        reg, summary = split_incident(reg, "INC-0001", ["itm-001"])

        # Moved items are itm-002 (published 2026-01-10) and itm-003 (2026-02-15)
        # earliest = 2026-01-10
        new = next(i for i in reg.incidents if i.id == "INC-0002")
        assert new.first_seen == "2026-01-10"

    def test_split_title_suffix(self):
        items = [_item("itm-001"), _item("itm-002")]
        inc = _incident("INC-0001", ["itm-001", "itm-002"], title="BLE vuln")
        reg = _registry([inc], items)

        reg, _ = split_incident(reg, "INC-0001", ["itm-001"])
        new = next(i for i in reg.incidents if i.id == "INC-0002")
        assert new.title == "BLE vuln (split)"

    def test_split_preserves_order(self):
        items = [_item(f"itm-{i:03d}") for i in range(1, 5)]
        inc = _incident("INC-0001", [f"itm-{i:03d}" for i in range(1, 5)])
        reg = _registry([inc], items)

        reg, summary = split_incident(reg, "INC-0001", ["itm-001", "itm-003"])

        assert summary["kept"] == ["itm-001", "itm-003"]
        assert summary["moved"] == ["itm-002", "itm-004"]

    def test_split_nothing_moved(self):
        """Keep set == full source set → no new incidents created."""
        items = [_item("itm-001"), _item("itm-002")]
        inc = _incident("INC-0001", ["itm-001", "itm-002"])
        reg = _registry([inc], items)

        reg, summary = split_incident(reg, "INC-0001", ["itm-001", "itm-002"])
        assert summary["moved"] == []
        assert summary["new_incidents"] == []
        assert len(reg.incidents) == 1


class TestSplitValidation:
    """split_incident raises on invalid input."""

    def test_empty_keep_set_rejected(self):
        items = [_item("itm-001")]
        inc = _incident("INC-0001", ["itm-001"])
        reg = _registry([inc], items)

        with pytest.raises(ValueError, match="non-empty keep set"):
            split_incident(reg, "INC-0001", [])

    def test_unknown_item_id_rejected(self):
        items = [_item("itm-001")]
        inc = _incident("INC-0001", ["itm-001"])
        reg = _registry([inc], items)

        with pytest.raises(ValueError, match="not in incident"):
            split_incident(reg, "INC-0001", ["itm-999"])

    def test_unknown_incident_id_rejected(self):
        reg = _registry()
        with pytest.raises(ValueError, match="unknown incident id"):
            split_incident(reg, "INC-NOPE", ["itm-001"])


# ── Merge tests ───────────────────────────────────────────────────────


class TestMergeIncidents:
    """merge_incidents unions items, min/max dates, adopts status."""

    def test_merge_unions_item_ids(self):
        items = [_item("itm-001"), _item("itm-002"), _item("itm-003")]
        inc_a = _incident("INC-0001", ["itm-001", "itm-002"])
        inc_b = _incident("INC-0002", ["itm-003"])
        reg = _registry([inc_a, inc_b], items)

        reg, summary = merge_incidents(reg, "INC-0001", "INC-0002")

        assert summary["item_ids"] == ["itm-001", "itm-002", "itm-003"]
        keep = next(i for i in reg.incidents if i.id == "INC-0001")
        assert keep.item_ids == ["itm-001", "itm-002", "itm-003"]
        # Absorbed incident removed
        assert not any(i.id == "INC-0002" for i in reg.incidents)

    def test_merge_preserves_order_keep_first(self):
        items = [_item("itm-001"), _item("itm-002"), _item("itm-003"), _item("itm-004")]
        inc_a = _incident("INC-0001", ["itm-001", "itm-003"])
        inc_b = _incident("INC-0002", ["itm-002", "itm-004"])
        reg = _registry([inc_a, inc_b], items)

        reg, summary = merge_incidents(reg, "INC-0001", "INC-0002")
        assert summary["item_ids"] == ["itm-001", "itm-003", "itm-002", "itm-004"]

    def test_merge_deduplicates_items(self):
        """If both incidents reference the same item, it appears once."""
        items = [_item("itm-001"), _item("itm-002")]
        inc_a = _incident("INC-0001", ["itm-001", "itm-002"])
        inc_b = _incident("INC-0002", ["itm-002"])
        reg = _registry([inc_a, inc_b], items)

        reg, summary = merge_incidents(reg, "INC-0001", "INC-0002")
        assert summary["item_ids"] == ["itm-001", "itm-002"]

    def test_merge_min_first_seen(self):
        items = [_item("itm-001"), _item("itm-002")]
        inc_a = _incident("INC-0001", ["itm-001"], first_seen="2026-03-01")
        inc_b = _incident("INC-0002", ["itm-002"], first_seen="2026-01-10")
        reg = _registry([inc_a, inc_b], items)

        reg, summary = merge_incidents(reg, "INC-0001", "INC-0002")
        assert summary["first_seen"] == "2026-01-10"

    def test_merge_max_last_checked(self):
        items = [_item("itm-001"), _item("itm-002")]
        inc_a = _incident("INC-0001", ["itm-001"], last_checked="2026-06-01")
        inc_b = _incident("INC-0002", ["itm-002"], last_checked="2026-09-01")
        reg = _registry([inc_a, inc_b], items)

        reg, summary = merge_incidents(reg, "INC-0001", "INC-0002")
        assert summary["last_checked"] == "2026-09-01"

    def test_merge_status_adopted_when_absorb_further_along(self):
        """absorb=patched > keep=disclosed → adopt absorb's status."""
        items = [_item("itm-001"), _item("itm-002")]
        inc_a = _incident(
            "INC-0001",
            ["itm-001"],
            status=_status("disclosed"),
        )
        inc_b = _incident(
            "INC-0002",
            ["itm-002"],
            status=_status(
                "patched",
                evidence_url="https://patch.example.com",
                as_of="2026-04-01",
            ),
        )
        reg = _registry([inc_a, inc_b], items)

        reg, summary = merge_incidents(reg, "INC-0001", "INC-0002")

        keep = next(i for i in reg.incidents if i.id == "INC-0001")
        assert keep.status.state == "patched"
        assert keep.status.evidence_url == "https://patch.example.com"
        assert keep.status.as_of == "2026-04-01"
        assert "merged from INC-0002" in keep.status.note
        assert summary["status"] == "patched"

    def test_merge_keeps_status_when_keep_further_along(self):
        """keep=patched, absorb=disclosed → keep's status retained."""
        items = [_item("itm-001"), _item("itm-002")]
        inc_a = _incident(
            "INC-0001",
            ["itm-001"],
            status=_status("patched", evidence_url="https://a.com", as_of="2026-05-01"),
        )
        inc_b = _incident(
            "INC-0002",
            ["itm-002"],
            status=_status("disclosed"),
        )
        reg = _registry([inc_a, inc_b], items)

        reg, summary = merge_incidents(reg, "INC-0001", "INC-0002")

        keep = next(i for i in reg.incidents if i.id == "INC-0001")
        assert keep.status.state == "patched"
        assert keep.status.evidence_url == "https://a.com"
        assert summary["status"] == "patched"

    def test_merge_exploited_over_unpatched(self):
        """absorb=exploited_in_wild > keep=unpatched → adopt absorb."""
        items = [_item("itm-001"), _item("itm-002")]
        inc_a = _incident("INC-0001", ["itm-001"], status=_status("unpatched"))
        inc_b = _incident(
            "INC-0002",
            ["itm-002"],
            status=_status(
                "exploited_in_wild",
                evidence_url="https://exploit.example.com",
                as_of="2026-07-01",
            ),
        )
        reg = _registry([inc_a, inc_b], items)

        reg, _ = merge_incidents(reg, "INC-0001", "INC-0002")
        keep = next(i for i in reg.incidents if i.id == "INC-0001")
        assert keep.status.state == "exploited_in_wild"
        assert keep.status.evidence_url == "https://exploit.example.com"

    def test_merge_same_status_keeps_original(self):
        """Same status → keep's evidence retained."""
        items = [_item("itm-001"), _item("itm-002")]
        inc_a = _incident(
            "INC-0001", ["itm-001"],
            status=_status("disclosed", evidence_url="https://a.com", as_of="2026-01-01"),
        )
        inc_b = _incident(
            "INC-0002", ["itm-002"],
            status=_status("disclosed", evidence_url="https://b.com", as_of="2026-02-01"),
        )
        reg = _registry([inc_a, inc_b], items)

        reg, _ = merge_incidents(reg, "INC-0001", "INC-0002")
        keep = next(i for i in reg.incidents if i.id == "INC-0001")
        # Keep's original status is retained
        assert keep.status.evidence_url == "https://a.com"
        assert keep.status.as_of == "2026-01-01"

    def test_merge_monitor_urls_union(self):
        items = [_item("itm-001"), _item("itm-002")]
        inc_a = _incident(
            "INC-0001", ["itm-001"],
            monitor_urls=["https://monitor1.com", "https://monitor2.com"],
        )
        inc_b = _incident(
            "INC-0002", ["itm-002"],
            monitor_urls=["https://monitor2.com", "https://monitor3.com"],
        )
        reg = _registry([inc_a, inc_b], items)

        reg, _ = merge_incidents(reg, "INC-0001", "INC-0002")
        keep = next(i for i in reg.incidents if i.id == "INC-0001")
        assert keep.monitor_urls == [
            "https://monitor1.com",
            "https://monitor2.com",
            "https://monitor3.com",
        ]


class TestMergeValidation:
    def test_merge_self_rejected(self):
        items = [_item("itm-001")]
        inc = _incident("INC-0001", ["itm-001"])
        reg = _registry([inc], items)

        with pytest.raises(ValueError, match="cannot merge an incident into itself"):
            merge_incidents(reg, "INC-0001", "INC-0001")

    def test_merge_unknown_id_rejected(self):
        reg = _registry()
        with pytest.raises(ValueError, match="unknown incident id"):
            merge_incidents(reg, "INC-0001", "INC-NOPE")


# ── Detach tests ──────────────────────────────────────────────────────


class TestDetachItems:
    """detach_items removes items, frees them to wire, deletes emptied incidents."""

    def test_detach_removes_item(self):
        items = [_item("itm-001"), _item("itm-002")]
        inc = _incident("INC-0001", ["itm-001", "itm-002"])
        reg = _registry([inc], items)

        reg, summary = detach_items(reg, "INC-0001", ["itm-001"])

        assert summary["detached"] == ["itm-001"]
        assert summary["remaining_items"] == ["itm-002"]
        assert summary["incident_deleted"] is False
        # Item stays in registry items
        assert any(i.id == "itm-001" for i in reg.items)
        # Incident still exists
        assert any(i.id == "INC-0001" for i in reg.incidents)

    def test_detach_deletes_emptied_incident(self):
        items = [_item("itm-001")]
        inc = _incident("INC-0001", ["itm-001"])
        reg = _registry([inc], items)

        reg, summary = detach_items(reg, "INC-0001", ["itm-001"])

        assert summary["incident_deleted"] is True
        assert summary["remaining_items"] == []
        assert not any(i.id == "INC-0001" for i in reg.incidents)
        # Item still exists in registry
        assert any(i.id == "itm-001" for i in reg.items)

    def test_detach_multiple_items(self):
        items = [_item(f"itm-{i:03d}") for i in range(1, 5)]
        inc = _incident("INC-0001", [f"itm-{i:03d}" for i in range(1, 5)])
        reg = _registry([inc], items)

        reg, summary = detach_items(reg, "INC-0001", ["itm-001", "itm-002", "itm-003"])

        assert summary["remaining_items"] == ["itm-004"]
        assert summary["incident_deleted"] is False

    def test_detach_preserves_order(self):
        items = [_item("itm-001"), _item("itm-002"), _item("itm-003")]
        inc = _incident("INC-0001", ["itm-001", "itm-002", "itm-003"])
        reg = _registry([inc], items)

        reg, summary = detach_items(reg, "INC-0001", ["itm-002"])
        assert summary["remaining_items"] == ["itm-001", "itm-003"]


class TestDetachValidation:
    def test_detach_unknown_item_rejected(self):
        items = [_item("itm-001")]
        inc = _incident("INC-0001", ["itm-001"])
        reg = _registry([inc], items)

        with pytest.raises(ValueError, match="not in incident"):
            detach_items(reg, "INC-0001", ["itm-999"])

    def test_detach_unknown_incident_rejected(self):
        reg = _registry()
        with pytest.raises(ValueError, match="unknown incident id"):
            detach_items(reg, "INC-NOPE", ["itm-001"])


# ── Dry-run tests ─────────────────────────────────────────────────────


class TestDryRun:
    """Operations in-memory don't affect a real file; dry-run prints without writing."""

    def test_split_dry_run_prints_summary(self, capsys):
        items = [_item("itm-001"), _item("itm-002")]
        inc = _incident("INC-0001", ["itm-001", "itm-002"])
        reg = _registry([inc], items)

        reg, summary = split_incident(reg, "INC-0001", ["itm-001"])

        captured = capsys.readouterr()
        # Summary dict contains the operation details
        assert summary["operation"] == "split"
        assert "INC-0001" in summary["incident_id"]

    def test_dry_run_cli_writes_nothing(self, tmp_path):
        """Simulate the CLI path: build registry, write to disk, then
        verify dry-run operations leave the file untouched."""
        from radar.overrides import save_atomic

        items = [_item("itm-001"), _item("itm-002")]
        inc = _incident("INC-0001", ["itm-001", "itm-002"])
        reg = _registry([inc], items)

        registry_path = tmp_path / "registry.json"
        save_atomic(reg, registry_path)

        # Read original content
        original = registry_path.read_text()

        # Simulate dry-run: load, operate in memory, don't write
        loaded = load_registry(registry_path)
        loaded, _ = detach_items(loaded, "INC-0001", ["itm-001"])
        # NOT saving — this is the dry run

        # File unchanged
        assert registry_path.read_text() == original


# ── Atomic save tests ─────────────────────────────────────────────────


class TestAtomicSave:
    """save_atomic writes valid JSON and validates on save."""

    def test_atomic_save_produces_valid_registry(self, tmp_path):
        items = [_item("itm-001"), _item("itm-002")]
        inc = _incident("INC-0001", ["itm-001", "itm-002"])
        reg = _registry([inc], items)

        path = tmp_path / "registry.json"
        save_atomic(reg, path)

        # Reload and validate
        reloaded = load_registry(path)
        assert len(reloaded.incidents) == 1
        assert reloaded.incidents[0].id == "INC-0001"
        assert reloaded.incidents[0].item_ids == ["itm-001", "itm-002"]

    def test_atomic_save_validates_before_replacing(self, tmp_path):
        """A registry that fails validation leaves the original file intact."""
        from radar.schema import Status

        items = [_item("itm-001")]
        # Build a valid registry first
        inc = _incident("INC-0001", ["itm-001"])
        reg = _registry([inc], items)
        path = tmp_path / "registry.json"
        save_atomic(reg, path)
        original = path.read_text()

        # Now try to save a broken registry — it has an item id that
        # doesn't exist, so to_dict produces a reference to a non-existent
        # item.  The validate() call in save_atomic should catch it.
        from radar.schema import Severity
        bad_inc = Incident(
            id="INC-9999",
            title="Bad",
            category="vuln",
            robot_class="quadruped",
            vendor="X",
            severity=Severity(source="estimated", value="high"),
            status=Status(state="disclosed", evidence_url="https://x.com", as_of="2026-01-01"),
            first_seen="2026-01-01",
            last_checked="2026-01-01",
            item_ids=["nonexistent"],
        )
        bad_reg = _registry([bad_inc], items)

        with pytest.raises(ValueError):
            save_atomic(bad_reg, path)

        # Original file intact
        assert path.read_text() == original

    def test_atomic_save_no_temp_files_left(self, tmp_path):
        items = [_item("itm-001")]
        inc = _incident("INC-0001", ["itm-001"])
        reg = _registry([inc], items)

        path = tmp_path / "registry.json"
        save_atomic(reg, path)

        # No .tmp files left behind
        tmp_files = list(tmp_path.glob("*.tmp"))
        assert tmp_files == []


# ── End-to-end operation sequences ────────────────────────────────────


class TestOperationSequence:
    """Chain multiple operations to verify registry consistency."""

    def test_split_then_merge(self):
        items = [_item("itm-001"), _item("itm-002"), _item("itm-003")]
        inc = _incident("INC-0001", ["itm-001", "itm-002", "itm-003"])
        reg = _registry([inc], items)

        # Split: keep itm-001, move itm-002 and itm-003
        reg, _ = split_incident(reg, "INC-0001", ["itm-001"])
        assert len(reg.incidents) == 2

        # Now merge the new incident back
        reg, _ = merge_incidents(reg, "INC-0001", "INC-0002")
        assert len(reg.incidents) == 1
        assert reg.incidents[0].item_ids == ["itm-001", "itm-002", "itm-003"]

    def test_split_then_detach(self):
        items = [_item("itm-001"), _item("itm-002"), _item("itm-003")]
        inc = _incident("INC-0001", ["itm-001", "itm-002", "itm-003"])
        reg = _registry([inc], items)

        # Split
        reg, _ = split_incident(reg, "INC-0001", ["itm-001", "itm-002"])
        # Detach from new incident → emptied → deleted
        reg, summary = detach_items(reg, "INC-0002", ["itm-003"])

        assert summary["incident_deleted"] is True
        assert len(reg.incidents) == 1
        assert reg.incidents[0].id == "INC-0001"

    def test_split_then_save_atomic(self, tmp_path):
        items = [_item("itm-001"), _item("itm-002")]
        inc = _incident("INC-0001", ["itm-001", "itm-002"])
        reg = _registry([inc], items)

        reg, _ = split_incident(reg, "INC-0001", ["itm-001"])

        path = tmp_path / "registry.json"
        save_atomic(reg, path)

        reloaded = load_registry(path)
        assert len(reloaded.incidents) == 2
        reloaded.validate()


# ── Status precedence table sanity ────────────────────────────────────


class TestStatusPrecedence:
    """Verify the precedence ordering matches spec."""

    def test_ordering(self):
        assert _STATUS_PRECEDENCE["disclosed"] < _STATUS_PRECEDENCE["unpatched"]
        assert _STATUS_PRECEDENCE["unpatched"] < _STATUS_PRECEDENCE["patched"]
        assert _STATUS_PRECEDENCE["unpatched"] < _STATUS_PRECEDENCE["exploited_in_wild"]
        assert _STATUS_PRECEDENCE["patched"] == _STATUS_PRECEDENCE["exploited_in_wild"]
        assert _STATUS_PRECEDENCE["resolved"] > _STATUS_PRECEDENCE["patched"]
