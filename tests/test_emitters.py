"""Tests for radar.emitters — emit() producing site/data/radar.json."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from radar.emitters import emit
from radar.schema import load_registry


FIXTURE = Path("data/fixtures/registry.json")


@pytest.fixture()
def registry() -> object:
    return load_registry(FIXTURE)


@pytest.fixture()
def radar_json(registry: object, tmp_path: Path) -> dict:
    emit(registry, tmp_path)
    return json.loads((tmp_path / "data" / "radar.json").read_text())


def test_file_created(radar_json: dict) -> None:
    assert isinstance(radar_json, dict)
    assert "meta" in radar_json
    assert "incidents" in radar_json
    assert "items" in radar_json
    assert "wire" in radar_json


def test_counts(radar_json: dict) -> None:
    c = radar_json["meta"]["counts"]
    assert c["incidents"] == 3
    # INC-0001 unpatched, INC-0002 exploited_in_wild => 2 open
    assert c["unpatched"] == 2
    assert c["max_patch_lag_days"] >= 0


def test_open_flags(radar_json: dict) -> None:
    by_id = {i["id"]: i for i in radar_json["incidents"]}
    assert by_id["INC-0001"]["open"] is True
    assert by_id["INC-0002"]["open"] is True
    assert by_id["INC-0003"]["open"] is True  # disclosed is an open state


def test_all_items_attached(registry: object, radar_json: dict) -> None:
    all_ids = {i.id for i in registry.items}  # type: ignore[attr-defined]
    attached = set()
    for inc in registry.incidents:  # type: ignore[attr-defined]
        attached.update(inc.item_ids)
    wire_ids = {w["id"] for w in radar_json["wire"]}
    assert wire_ids == all_ids - attached


def test_wire_empty_for_fixture(radar_json: dict) -> None:
    assert radar_json["wire"] == []


def test_severity_preserved(radar_json: dict) -> None:
    by_id = {i["id"]: i for i in radar_json["incidents"]}
    assert by_id["INC-0001"]["severity"] == {"source": "estimated", "value": "high"}
    assert by_id["INC-0002"]["severity"] == {"source": "estimated", "value": "critical"}
    assert by_id["INC-0003"]["severity"] == {"source": "estimated", "value": "medium"}


def test_status_preserved(radar_json: dict) -> None:
    by_id = {i["id"]: i for i in radar_json["incidents"]}
    assert by_id["INC-0001"]["status"]["state"] == "unpatched"
    assert by_id["INC-0002"]["status"]["state"] == "exploited_in_wild"
    assert by_id["INC-0003"]["status"]["state"] == "disclosed"


def test_ai_summary_preserved(radar_json: dict) -> None:
    by_id = {i["id"]: i for i in radar_json["incidents"]}
    assert by_id["INC-0001"]["ai_summary"] is not None
    assert by_id["INC-0002"]["ai_summary"] is not None
    assert by_id["INC-0003"].get("ai_summary") is None


def test_schema_version(radar_json: dict) -> None:
    assert radar_json["meta"]["schema_version"] == 1


def test_idempotent(registry: object, tmp_path: Path) -> None:
    emit(registry, tmp_path)
    first = (tmp_path / "data" / "radar.json").read_bytes()
    emit(registry, tmp_path)
    second = (tmp_path / "data" / "radar.json").read_bytes()
    assert first == second
