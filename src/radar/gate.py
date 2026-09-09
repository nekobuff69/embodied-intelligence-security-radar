"""Deterministic Rules gate: keep items mentioning both a robot term AND an incident term.

Module-level constants define the term lists. Pure function — no side effects.
"""

from __future__ import annotations

from radar.schema import Item

# --- Robot terms (lowercase substrings) ---
ROBOT_TERMS: frozenset[str] = frozenset({
    "robot",
    "robotic",
    "humanoid",
    "quadruped",
    "android",
    "cobot",
})

# --- Incident terms (lowercase stems / substrings) ---
INCIDENT_TERMS: frozenset[str] = frozenset({
    "hack",
    "exploit",
    "vulnerab",
    "breach",
    "takeover",
    "hijack",
    "malware",
    "injur",
    "attack",
    "unsafe",
    "recall",
    "security",
})

# --- Exclusion terms: items matching these are dropped ---
EXCLUDE_DRONE_TERMS: frozenset[str] = frozenset({
    "drone",
    "uav",
    "self-driving",
    "autonomous vehicle",
    "tesla autopilot",
    "fsd",
})

EXCLUDE_INDUSTRIAL_TERMS: frozenset[str] = frozenset({
    "industrial robot",
    "warehouse robot",
    "kuka",
    "fanuc",
    "abb",
    "yaskawa",
})

_ALL_EXCLUDES: frozenset[str] = EXCLUDE_DRONE_TERMS | EXCLUDE_INDUSTRIAL_TERMS


def _has_term(text: str, term: str) -> bool:
    """Check if term appears as a lowercase substring."""
    return term in text.lower()


def apply_gate(items: list[Item]) -> list[Item]:
    """Keep items whose title+body contains a robot term AND an incident term,
    excluding items about drones, autonomous vehicles, or industrial robots.

    CVE-ID regex hit in title+body counts as an incident term alone
    (the item must still contain a robot term).
    """
    import re
    cve_re = re.compile(r"CVE-\d{4}-\d{4,}")

    kept: list[Item] = []
    for item in items:
        text = f"{item.title} {item.body}".lower()

        # Exclusions first
        if any(_has_term(text, ex) for ex in _ALL_EXCLUDES):
            continue

        # Robot term required
        has_robot = any(_has_term(text, rt) for rt in ROBOT_TERMS)
        if not has_robot:
            continue

        # Incident term required (including CVE-ID regex)
        has_incident = any(_has_term(text, it) for it in INCIDENT_TERMS)
        if not has_incident and not cve_re.search(text):
            continue

        kept.append(item)

    return kept
