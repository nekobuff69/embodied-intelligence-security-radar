"""Tests for the deterministic Rules gate."""

from radar.gate import (
    EXCLUDE_DRONE_TERMS,
    EXCLUDE_INDUSTRIAL_TERMS,
    INCIDENT_TERMS,
    ROBOT_TERMS,
    apply_gate,
)
from radar.schema import Item, item_id_for_url


def _item(title: str, body: str = "", url: str = "https://example.com/test") -> Item:
    """Create a test Item with the given title and body."""
    return Item(
        id=item_id_for_url(url),
        source="google_news",
        url=url,
        title=title,
        body=body,
        published="2026-01-01",
        cve_ids=[],
    )


class TestGateKeeps:
    """Items that should pass the gate."""

    def test_robot_and_hack(self):
        items = [_item("Robot hacked at conference", "A robot was compromised by researchers.")]
        result = apply_gate(items)
        assert len(result) == 1
        assert result[0].title == "Robot hacked at conference"

    def test_humanoid_and_vulnerability(self):
        items = [_item(
            "Humanoid robot vulnerability disclosed",
            "A security researcher found a critical vulnerability in humanoid firmware.",
        )]
        result = apply_gate(items)
        assert len(result) == 1

    def test_quadruped_and_exploit(self):
        items = [_item(
            "Quadruped robot exploit allows remote takeover",
            "Researchers demonstrated an exploit that allows full takeover of a quadruped robot.",
        )]
        result = apply_gate(items)
        assert len(result) == 1

    def test_android_and_malware(self):
        items = [_item(
            "Android robot infected with malware",
            "An android unit was found running malware after a firmware update.",
        )]
        result = apply_gate(items)
        assert len(result) == 1

    def test_cobot_and_breach(self):
        items = [_item(
            "Cobot safety breach reported",
            "A collaborative robot safety breach was reported at a manufacturing plant.",
        )]
        result = apply_gate(items)
        assert len(result) == 1

    def test_robotic_and_attack(self):
        items = [_item(
            "Robotic system under DDoS attack",
            "A robotic system was targeted by a DDoS attack disrupting operations.",
        )]
        result = apply_gate(items)
        assert len(result) == 1

    def test_robot_and_injury(self):
        items = [_item(
            "Robot injures factory worker",
            "A factory robot injured a worker during an unsafe operation.",
        )]
        result = apply_gate(items)
        assert len(result) == 1

    def test_robot_and_cve_alone(self):
        """CVE-ID regex hit counts as incident term."""
        items = [_item(
            "Unitree humanoid firmware CVE-2024-12345",
            "A vulnerability in the Unitree humanoid was assigned CVE-2024-12345.",
        )]
        result = apply_gate(items)
        assert len(result) == 1

    def test_robot_and_recall(self):
        items = [_item(
            "Consumer robot recall issued after safety concerns",
            "Manufacturer issues recall for consumer robot after multiple safety incidents.",
        )]
        result = apply_gate(items)
        assert len(result) == 1

    def test_robot_and_hijack(self):
        items = [_item(
            "Home robot camera hijacked by attacker",
            "An attacker hijacked the camera stream of a home robot.",
        )]
        result = apply_gate(items)
        assert len(result) == 1

    def test_robot_and_unsafe(self):
        items = [_item(
            "Humanoid robot declared unsafe after testing",
            "Testing revealed the humanoid robot operates in unsafe conditions.",
        )]
        result = apply_gate(items)
        assert len(result) == 1

    def test_robot_and_takeover(self):
        items = [_item(
            "Quadruped robot takeover via Bluetooth flaw",
            "A Bluetooth flaw allows remote takeover of quadruped robots.",
        )]
        result = apply_gate(items)
        assert len(result) == 1

    def test_robot_and_security_stem(self):
        """'security' is an incident term."""
        items = [_item(
            "Consumer robot security flaw disclosed",
            "A security flaw in a consumer robot allows unauthorized access.",
        )]
        result = apply_gate(items)
        assert len(result) == 1


class TestGateDropsDrones:
    """Drone/UAV/AV items should be excluded."""

    def test_drone_hacked(self):
        items = [_item("Drone hacked mid-flight", "A consumer drone was hacked during a flight test.")]
        result = apply_gate(items)
        assert len(result) == 0

    def test_uav_exploit(self):
        items = [_item("UAV exploit allows remote control", "A vulnerability in a UAV was exploited.")]
        result = apply_gate(items)
        assert len(result) == 0

    def test_self_driving_vulnerability(self):
        items = [_item("Self-driving car vulnerability found", "A critical vulnerability in self-driving systems.")]
        result = apply_gate(items)
        assert len(result) == 0

    def test_autonomous_vehicle_breach(self):
        items = [_item("Autonomous vehicle security breach", "A breach was reported in autonomous vehicle software.")]
        result = apply_gate(items)
        assert len(result) == 0

    def test_tesla_autopilot_hack(self):
        items = [_item("Tesla Autopilot hacked by researchers", "A hack of Tesla Autopilot was demonstrated.")]
        result = apply_gate(items)
        assert len(result) == 0

    def test_fsd_exploit(self):
        items = [_item("FSD exploit discovered", "A full self-driving exploit was found in Tesla FSD.")]
        result = apply_gate(items)
        assert len(result) == 0


class TestGateDropsIndustrial:
    """Industrial robot/warehouse items should be excluded."""

    def test_industrial_robot_hack(self):
        items = [_item("Industrial robot hacked at factory", "An industrial robot was compromised.")]
        result = apply_gate(items)
        assert len(result) == 0

    def test_warehouse_robot_vulnerability(self):
        items = [_item("Warehouse robot vulnerability disclosed", "A warehouse robot had a vulnerability exposed.")]
        result = apply_gate(items)
        assert len(result) == 0

    def test_kuka_exploit(self):
        items = [_item("KUKA robot arm exploit found", "Researchers found an exploit in KUKA robotic arms.")]
        result = apply_gate(items)
        assert len(result) == 0

    def test_fanuc_hack(self):
        items = [_item("FANUC controller hacked", "A FANUC industrial controller was hacked remotely.")]
        result = apply_gate(items)
        assert len(result) == 0

    def test_abb_robot_breach(self):
        items = [_item("ABB robot security breach", "A breach in ABB robot firmware was reported.")]
        result = apply_gate(items)
        assert len(result) == 0

    def test_yaskawa_vulnerability(self):
        items = [_item("Yaskawa robot vulnerability CVE-2025-99999", "A vulnerability in Yaskawa robots.")]
        result = apply_gate(items)
        assert len(result) == 0


class TestGateDropsNoIncident:
    """Robot items without incident terms should be dropped."""

    def test_robot_without_incident(self):
        items = [_item(
            "New robot unveiled at trade show",
            "Company展示ed a new humanoid robot prototype at CES.",
        )]
        result = apply_gate(items)
        assert len(result) == 0

    def test_humanoid_product_launch(self):
        items = [_item(
            "Humanoid robot product launch announced",
            "The company announced a new humanoid robot for consumer use.",
        )]
        result = apply_gate(items)
        assert len(result) == 0


class TestGateDropsNoRobot:
    """Incident items without robot terms should be dropped."""

    def test_software_vulnerability(self):
        items = [_item(
            "Critical vulnerability found in Linux kernel",
            "A critical vulnerability CVE-2024-99999 was found in the Linux kernel.",
        )]
        result = apply_gate(items)
        assert len(result) == 0

    def test_car_hack(self):
        items = [_item(
            "Car hack exposes millions of vehicles",
            "A security researcher demonstrated a car hack affecting millions of vehicles.",
        )]
        result = apply_gate(items)
        assert len(result) == 0


class TestGateEmpty:
    def test_empty_input(self):
        assert apply_gate([]) == []


class TestGateConstants:
    """Verify module-level constants are well-defined."""

    def test_robot_terms_are_lowercase(self):
        for term in ROBOT_TERMS:
            assert term == term.lower(), f"ROBOT_TERMS entry {term!r} must be lowercase"

    def test_incident_terms_are_lowercase(self):
        for term in INCIDENT_TERMS:
            assert term == term.lower(), f"INCIDENT_TERMS entry {term!r} must be lowercase"

    def test_exclusion_terms_are_lowercase(self):
        for term in EXCLUDE_DRONE_TERMS | EXCLUDE_INDUSTRIAL_TERMS:
            assert term == term.lower(), f"Exclusion term {term!r} must be lowercase"

    def test_robot_terms_non_empty(self):
        assert len(ROBOT_TERMS) > 0

    def test_incident_terms_non_empty(self):
        assert len(INCIDENT_TERMS) > 0
