"""Tests for radar.feed — RSS 2.0 feed.xml emitter."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from radar.feed import emit_feed
from radar.schema import (
    Incident,
    Item,
    Registry,
    Severity,
    Status,
    load_registry,
)

FIXTURE = Path("data/fixtures/registry.json")


@pytest.fixture()
def registry() -> Registry:
    return load_registry(FIXTURE)


@pytest.fixture()
def feed_tree(registry: Registry, tmp_path: Path) -> ET.Element:
    emit_feed(registry, tmp_path)
    return ET.parse(tmp_path / "feed.xml").getroot()


# ── Structural ────────────────────────────────────────────────────────


def test_well_formed_xml(registry: Registry, tmp_path: Path) -> None:
    emit_feed(registry, tmp_path)
    ET.parse(tmp_path / "feed.xml")  # parses without error


def test_channel_title(feed_tree: ET.Element) -> None:
    title = feed_tree.find("./channel/title")
    assert title is not None
    assert title.text == "Robot Security Radar"


def test_channel_description(feed_tree: ET.Element) -> None:
    desc = feed_tree.find("./channel/description")
    assert desc is not None
    assert "buyer-first" in desc.text


def test_item_count_matches_incidents(feed_tree: ET.Element, registry: Registry) -> None:
    items = feed_tree.findall("./channel/item")
    assert len(items) == len(registry.incidents)


# ── Per-item assertions ──────────────────────────────────────────────


def test_inc0001_link(feed_tree: ET.Element) -> None:
    items = feed_tree.findall("./channel/item")
    inc0001 = [i for i in items if i.find("guid").text == "INC-0001"]
    assert len(inc0001) == 1
    link = inc0001[0].find("link").text
    assert "index.html?inc=INC-0001" in link


def test_inc0001_category(feed_tree: ET.Element) -> None:
    items = feed_tree.findall("./channel/item")
    inc0001 = [i for i in items if i.find("guid").text == "INC-0001"][0]
    cat = inc0001.find("category").text
    assert cat == "vuln"


def test_inc0001_description_status(feed_tree: ET.Element) -> None:
    items = feed_tree.findall("./channel/item")
    inc0001 = [i for i in items if i.find("guid").text == "INC-0001"][0]
    desc = inc0001.find("description").text
    assert "Status: unpatched" in desc


def test_inc0001_guid_not_permalink(feed_tree: ET.Element) -> None:
    items = feed_tree.findall("./channel/item")
    inc0001 = [i for i in items if i.find("guid").text == "INC-0001"][0]
    assert inc0001.find("guid").attrib.get("isPermalink") == "false"


def test_inc0001_has_pub_date(feed_tree: ET.Element) -> None:
    items = feed_tree.findall("./channel/item")
    inc0001 = [i for i in items if i.find("guid").text == "INC-0001"][0]
    pd = inc0001.find("pubDate").text
    assert pd is not None and len(pd) > 0


# ── Escape path ──────────────────────────────────────────────────────


def test_xml_escaping(tmp_path: Path) -> None:
    """Incident title containing & < > must be escaped in output."""
    item = Item(
        id="itm-escape-001",
        source="press_rss",
        url="https://example.com/escape-test",
        title="Escape test article",
        body="body",
        published="2026-01-01",
    )
    inc = Incident(
        id="INC-9999",
        title="Foo <bar> & baz \"qux\" 'quote'",
        category="vuln",
        robot_class="humanoid",
        vendor="Test",
        severity=Severity(source="estimated", value="high"),
        status=Status(
            state="unpatched",
            evidence_url="https://example.com/evidence",
            as_of="2026-06-01",
        ),
        first_seen="2026-01-01",
        last_checked="2026-06-01",
        item_ids=["itm-escape-001"],
    )
    reg = Registry(incidents=[inc], items=[item])

    emit_feed(reg, tmp_path)
    raw = (tmp_path / "feed.xml").read_text()

    # Raw XML must contain escaped forms, not bare specials in element text
    assert "&lt;bar&gt;" in raw
    assert "&amp; baz" in raw

    # Must still be parseable
    tree = ET.parse(tmp_path / "feed.xml").getroot()
    title_el = tree.find("./channel/item/title")
    assert title_el is not None
    assert title_el.text == 'Foo <bar> & baz "qux" \'quote\''


# ── Site URL self-link ───────────────────────────────────────────────


def test_self_link_with_site_url(tmp_path: Path) -> None:
    item = Item(
        id="itm-self-001",
        source="hn",
        url="https://example.com/self-test",
        title="Self link test",
        body="body",
        published="2026-01-01",
    )
    inc = Incident(
        id="INC-8888",
        title="Self link incident",
        category="attack",
        robot_class="consumer",
        vendor="X",
        severity=Severity(source="estimated", value="low"),
        status=Status(
            state="disclosed",
            evidence_url="https://example.com/evidence",
            as_of="2026-03-01",
        ),
        first_seen="2026-02-01",
        last_checked="2026-03-01",
        item_ids=["itm-self-001"],
    )
    reg = Registry(incidents=[inc], items=[item])

    emit_feed(reg, tmp_path, site_url="https://example.com")
    raw = (tmp_path / "feed.xml").read_text()
    tree = ET.parse(tmp_path / "feed.xml").getroot()

    ns = {"atom": "http://www.w3.org/2005/Atom"}
    self_link = tree.find("./channel/atom:link[@rel='self']", ns)
    assert self_link is not None
    assert self_link.attrib["href"] == "https://example.com"

    # Item link should be absolute
    item_link = tree.find("./channel/item/link")
    assert item_link.text.startswith("https://example.com/")


# ── Sort order ───────────────────────────────────────────────────────


def test_items_sorted_by_updated_desc(feed_tree: ET.Element) -> None:
    items = feed_tree.findall("./channel/item")
    guids = [i.find("guid").text for i in items]
    # INC-0001 as_of=2026-09-01, INC-0002 as_of=2026-08-20, INC-0003 as_of=2026-07-02
    assert guids == ["INC-0001", "INC-0002", "INC-0003"]


# ── Idempotency ──────────────────────────────────────────────────────


def test_idempotent(registry: Registry, tmp_path: Path) -> None:
    emit_feed(registry, tmp_path)
    first = (tmp_path / "feed.xml").read_bytes()
    emit_feed(registry, tmp_path)
    second = (tmp_path / "feed.xml").read_bytes()
    assert first == second
