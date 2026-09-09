# ADR-0004: No Manual Seed Set

## Status

Accepted

## Context

The original plan (PRD, ADR-0001) included a human-curated seed set: a hand-authored backlog of 5–15 historical incidents (flagship: Unitree BLE vulnerability) merged into the registry before the first pipeline run. The seed loader (`seed_loader.py`) validated, merged, and deduplicated seeds against the pipeline registry.

Product-owner review of the LLM-configured pipeline determined that manual curation introduces a second source of truth and ongoing maintenance burden. The pipeline with LLM relevance filtering produces buyer-grade content directly — first-run incidents come from whatever sources surface on launch day. Notable older incidents (e.g. Unitree BLE) enter the radar only when sources resurface them.

## Decision

No manual seed set. The previous seed loader, seed files, and seed-protection logic in `prune.py` are removed. Fixture data (`data/fixtures`) remains test-only, never live data.

## Consequences

- Claim hygiene (ADR-0003) now rests entirely on the LLM relevance verdict + rules gate + prune. No manual curation layer exists to override pipeline output.
- First-run content depends on what sources surface on the day. There is no guaranteed flagship incident at launch.
- Notable older incidents enter the radar only when sources resurface them. Operator corrections remain possible via `radar override`.
- Supersedes the seed-set element of the original plan (see PRD #1 discussion). ADR-0003 claim-hygiene rules unchanged and now apply purely to pipeline output.
