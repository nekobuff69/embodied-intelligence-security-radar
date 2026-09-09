"""Item/Incident data contract for Robot Security Radar.

This module is the single source of truth for the pipeline<->frontend
contract. Every producer (fetchers, LLM pass, clusterer, seed loader)
and every consumer (emitters, frontend) must go through these types.
Claim-hygiene invariants (ADR-0003) are enforced here, not at the edges.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field, asdict
from datetime import date, datetime, timezone
from pathlib import Path

CATEGORIES = {"vuln", "attack", "safety"}
ROBOT_CLASSES = {"humanoid", "quadruped", "consumer"}
STATUS_STATES = {"disclosed", "unpatched", "patched", "exploited_in_wild", "resolved"}
SEVERITY_BANDS = {"low", "medium", "high", "critical"}
SEVERITY_SOURCES = {"cvss", "estimated"}
SOURCES = {"google_news", "press_rss", "reddit", "hn", "nvd", "github_advisory", "vendor_page"}
SCHEMA_VERSION = 1

_ISO = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$")


def _require(cond: bool, msg: str) -> None:
    if not cond:
        raise ValueError(msg)


def _check_date(value: str, what: str) -> None:
    _require(bool(_ISO.match(value)), f"{what} must be ISO date YYYY-MM-DD, got {value!r}")
    date.fromisoformat(value)


def _check_http_url(value: str, what: str) -> None:
    _require(value.startswith(("http://", "https://")), f"{what} must be an http(s) URL, got {value!r}")


@dataclass
class Status:
    state: str
    evidence_url: str
    as_of: str
    note: str = ""

    def __post_init__(self) -> None:
        _require(self.state in STATUS_STATES, f"status.state {self.state!r} not in {sorted(STATUS_STATES)}")
        _check_http_url(self.evidence_url, "status.evidence_url")
        _check_date(self.as_of, "status.as_of")


@dataclass
class Severity:
    source: str  # "cvss" | "estimated"
    value: str

    def __post_init__(self) -> None:
        _require(self.source in SEVERITY_SOURCES, f"severity.source {self.source!r} not in {sorted(SEVERITY_SOURCES)}")
        if self.source == "cvss":
            _require(bool(re.match(r"^\d(\.\d)?$", self.value)), f"cvss severity must be a numeric score, got {self.value!r}")
        else:
            _require(self.value in SEVERITY_BANDS, f"estimated severity {self.value!r} not in {sorted(SEVERITY_BANDS)}")


@dataclass
class Item:
    id: str
    source: str
    url: str
    title: str
    body: str
    published: str
    cve_ids: list[str] = field(default_factory=list)
    fetched_at: str = ""
    # LLM-pass enrichment (optional; clusterer later lifts these into Incidents)
    ai_summary: str | None = None
    ai_category: str | None = None
    ai_vendor: str | None = None
    ai_model: str | None = None
    ai_robot_class: str | None = None
    ai_severity: Severity | None = None
    ai_relevant: bool | None = None  # LLM relevance verdict; None = not yet enriched

    def __post_init__(self) -> None:
        _require(self.source in SOURCES, f"item.source {self.source!r} not in {sorted(SOURCES)}")
        _check_http_url(self.url, "item.url")
        _require(self.title.strip() != "", "item.title must not be empty")
        _check_date(self.published, "item.published")
        for cve in self.cve_ids:
            _require(bool(_CVE.match(cve)), f"malformed CVE id {cve!r}")
        if self.ai_category is not None:
            _require(self.ai_category in CATEGORIES, f"ai_category {self.ai_category!r} not in {sorted(CATEGORIES)}")
        if self.ai_robot_class is not None:
            _require(self.ai_robot_class in ROBOT_CLASSES, f"ai_robot_class {self.ai_robot_class!r} not in {sorted(ROBOT_CLASSES)}")
        if not self.fetched_at:
            self.fetched_at = datetime.now(timezone.utc).strftime("%Y-%m-%d")


@dataclass
class Incident:
    id: str
    title: str
    category: str
    robot_class: str
    vendor: str
    severity: Severity
    status: Status
    first_seen: str
    last_checked: str
    item_ids: list[str] = field(default_factory=list)
    model: str | None = None
    ai_summary: str | None = None
    monitor_urls: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        _require(self.category in CATEGORIES, f"category {self.category!r} not in {sorted(CATEGORIES)}")
        _require(self.robot_class in ROBOT_CLASSES, f"robot_class {self.robot_class!r} not in {sorted(ROBOT_CLASSES)}")
        _check_date(self.first_seen, "first_seen")
        _check_date(self.last_checked, "last_checked")
        _require(self.item_ids, f"incident {self.id} must reference at least one Item")


@dataclass
class Registry:
    incidents: list[Incident] = field(default_factory=list)
    items: list[Item] = field(default_factory=list)
    meta: dict = field(default_factory=lambda: {"schema_version": SCHEMA_VERSION})

    def validate(self) -> None:
        item_ids = set()
        for item in self.items:
            _require(item.id not in item_ids, f"duplicate Item id {item.id}")
            item_ids.add(item.id)
        incident_ids = set()
        attached: dict[str, str] = {}
        for inc in self.incidents:
            _require(inc.id not in incident_ids, f"duplicate Incident id {inc.id}")
            incident_ids.add(inc.id)
            _require(inc.item_ids, f"incident {inc.id} has no Items")
            for iid in inc.item_ids:
                _require(iid in item_ids, f"incident {inc.id} references unknown Item {iid}")
                prev = attached.get(iid)
                _require(prev is None, f"Item {iid} attached to multiple Incidents ({prev}, {inc.id})")
                attached[iid] = inc.id
        for item in self.items:
            for cve in item.cve_ids:
                _require(bool(_CVE.match(cve)), f"malformed CVE id {cve!r}")

    def to_dict(self) -> dict:
        return {
            "meta": {**self.meta, "schema_version": SCHEMA_VERSION},
            "incidents": [asdict(i) for i in self.incidents],
            "items": [asdict(i) for i in self.items],
        }

    @classmethod
    def from_dict(cls, raw: dict) -> Registry:
        incidents = [
            Incident(
                id=i["id"], title=i["title"], category=i["category"], robot_class=i["robot_class"],
                vendor=i["vendor"], model=i.get("model"),
                severity=Severity(**i["severity"]), status=Status(**i["status"]),
                first_seen=i["first_seen"], last_checked=i["last_checked"],
                item_ids=list(i["item_ids"]), ai_summary=i.get("ai_summary"),
                monitor_urls=list(i.get("monitor_urls", [])),
            )
            for i in raw.get("incidents", [])
        ]
        items = [Item(**it) for it in raw.get("items", [])]
        reg = cls(incidents=incidents, items=items, meta=raw.get("meta", {}))
        reg.validate()
        return reg


def load_registry(path: str | Path) -> Registry:
    return Registry.from_dict(json.loads(Path(path).read_text()))


def save_registry(reg: Registry, path: str | Path) -> None:
    reg.validate()
    Path(path).write_text(json.dumps(reg.to_dict(), indent=2, ensure_ascii=False) + "\n")


def item_id_for_url(url: str) -> str:
    import hashlib
    return "itm-" + hashlib.sha1(url.encode()).hexdigest()[:12]


def next_incident_id(reg: Registry) -> str:
    nums = [int(i.id.split("-")[1]) for i in reg.incidents if re.match(r"^INC-\d+$", i.id)]
    return f"INC-{max(nums, default=0) + 1:04d}"
