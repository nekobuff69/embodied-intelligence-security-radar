# ADR-0002: Own pipeline + vanilla static site on GitHub Actions/Pages

Date: 2026-09-09

## Status

Accepted

## Context

Horizon (MIT) demonstrates the exact operating model: Python fetch pipeline → AI scoring/filter → static output → GitHub Pages, driven by a scheduled Actions run, zero servers, zero hosting cost. Layout inspiration (a single-file HTML artifact) shows the desired frontend is achievable without a framework. Forking Horizon wholesale was considered: fastest to first light, but its output format is daily-briefing Markdown and cannot express incident status (ADR-0001) or the dossier-grid layout.

## Decision

Build an own pipeline in Python (uv) that reuses Horizon's fetcher modules where useful (RSS, Reddit, Hacker News) but owns the pipeline stages and all output formats. Runs once daily via GitHub Actions cron. Pipeline writes `data/registry.json` (committed to the repo — git history is the audit trail; *(amendment 2026-09-09: the originally planned `data/incidents.json` + `data/items.json` pair was consolidated into this single registry file)*) and `feed.xml`. The frontend is one hand-built vanilla HTML/CSS/JS page reading the JSON, hosted on GitHub Pages. No build toolchain, no server, no framework.

## Consequences

- Zero cost, zero infra to operate; failure mode is a red Actions run, visible and auditable.
- Freshness is batch (daily); accepted for v1.
- Client-side filtering/search over the JSON index is sufficient at v1 volume (tens of Incidents, hundreds of Items).
- Patch lag and counters are computed client-side from `first_seen`/`last_checked` so the static data does not look stale between runs.
- Adding Astro or a serverless layer later is a frontend swap only; the JSON contract is the seam.
- Horizon fork (rejected): inherited briefing data model would be fought at the incident layer. Serverless app (rejected): costs and ops for daily-batch freshness needs.

## Related

- ADR-0001 (incident entity data model)
