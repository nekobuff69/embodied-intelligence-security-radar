"""Deterministic Rules gate: keep items mentioning both a robot term AND an incident term.

Module-level constants define the term lists. Pure function — no side effects.

Also enforces date sanity (drops items older than 3 years or more than 2 days
in the future) and commentary/podcast exclusion.
"""

from __future__ import annotations

from datetime import date, timedelta

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

# --- Negation guards: hedged "no security issue" phrasing is not an incident ---
NEGATION_TERMS: frozenset[str] = frozenset({
    "no security concern",
    "no security issues",
    "not a security",
    "no vulnerab",
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

# --- Date sanity: drop items older than 3 years or more than 2 days in the future ---
MAX_AGE_DAYS = 1095  # 3 years
_MAX_FUTURE_DAYS = 2

# --- Commentary exclusion: opinion/entertainment content is never an incident ---
COMMENTARY_TERMS: frozenset[str] = frozenset({
    "podcast",
    "episode",
    "interview",
    "opinion",
    "commentar",
    "webinar",
    "roundup",
    "meets ",
    "fun kids",
    "screen time",
})


def _has_term(text: str, term: str) -> bool:
    """Check if term appears as a lowercase substring."""
    return term in text.lower()


def _parse_published(published: str) -> date | None:
    """Try to parse a published date string; return None on failure."""
    try:
        return date.fromisoformat(published)
    except (ValueError, TypeError):
        return None


def apply_gate(items: list[Item], *, today: date | None = None) -> list[Item]:
    """Keep items whose title+body contains a robot term AND an incident term,
    excluding items about drones, autonomous vehicles, or industrial robots,
    items older than 3 years, items more than 2 days in the future,
    and commentary/podcast/opinion content.

    CVE-ID regex hit in title+body counts as an incident term alone
    (the item must still contain a robot term).
    """
    import re
    cve_re = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)

    if today is None:
        today = date.today()

    oldest = today - timedelta(days=MAX_AGE_DAYS)
    newest = today + timedelta(days=_MAX_FUTURE_DAYS)

    kept: list[Item] = []
    for item in items:
        # Date sanity: drop items outside the valid window or with malformed dates
        pub_date = _parse_published(item.published)
        if pub_date is None or pub_date < oldest or pub_date > newest:
            continue

        text = f"{item.title} {item.body}".lower()

        # Commentary exclusion: podcast/opinion/entertainment items are never incidents
        if any(_has_term(text, ct) for ct in COMMENTARY_TERMS):
            continue

        # Exclusions first (domain scopes + negated-security phrasing)
        if any(_has_term(text, ex) for ex in _ALL_EXCLUDES) or any(_has_term(text, ng) for ng in NEGATION_TERMS):
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
