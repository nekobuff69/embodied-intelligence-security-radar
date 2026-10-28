# Data contract

Single source of truth: `src/radar/schema.py`. Glossary vocabulary per `CONTEXT.md`.

## Registry file (`data/registry.json`, committed)

```
meta:    {schema_version: 1, generated_at?}
items:   [{id, source, url, title, body, published, cve_ids?, fetched_at}]
         source ∈ google_news|press_rss|reddit|hn|nvd|github_advisory|vendor_page
         (google_news is legacy: kept for existing items/fixtures; no longer
         fetched as of 2026-09-09)
         items also carry optional LLM enrichment (filled by the LLM pass,
         lifted into Incidents by the clusterer): ai_summary?, ai_category?,
         ai_vendor?, ai_model?, ai_robot_class?, ai_severity?, ai_relevant?
incidents: [{id, title, category, robot_class, vendor, model?, severity, status,
             first_seen, last_checked, item_ids, ai_summary?, monitor_urls?}]
         category ∈ vuln|attack|safety ; robot_class ∈ humanoid|quadruped|consumer
         severity: {source: cvss|estimated, value: "8.1" | low|medium|high|critical}
         status:   {state: disclosed|unpatched|patched|exploited_in_wild|resolved,
                    evidence_url, as_of, note?}
```

## Invariants (validated in `schema.py`)

- Every `status` carries `evidence_url` (http/s) + `as_of` (ADR-0003); no bare Status change.
- `severity.source=cvss` ⇒ numeric score; `estimated` ⇒ band only, never fabricated numbers.
- Item `url` unique; Item attached to at most one Incident; Incident references ≥1 existing Item.
- CVE ids match `CVE-YYYY-NNNNN+`.
- **Incident creation requires hard-fact evidence** (ADR-0004): the Item carries CVE ids, or `ai_relevant=true` with a non-Unknown `ai_vendor`. Ineligible Items are held in the Wire or dismissed.
- Items with `ai_relevant=false` (commentary/opinion/entertainment per the LLM rubric) are dismissed and their URLs blocklisted.

## Pipeline state files (`data/`, committed)

- `registry.json` — the store above; git history is the audit trail.
- `dismissed_urls.json` — URL blocklist; `apply_items` never re-admits a dismissed URL (feeds resurface old stories).
- `.vendor_hashes.json` — advisory-page hash state driving the `last_checked` monitor. An unchanged page advances the date with zero LLM cost. A changed page is interpreted only when it is linked to an Incident and an LLM key is configured; unlinked discovery pages are hashed but never interpreted.

## Emitter output (`site/data/radar.json`, generated, not committed)

Registry plus derived fields. Shape:

```
meta:      {schema_version, generated_at, counts: {incidents, unpatched, max_patch_lag_days}}
incidents: [...]   # each carries an `open` bool; patch lag is recomputed client-side from first_seen
items:     [...]   # the full Item set
wire:      [...]   # unattached Items; the site does not render this list
```

The frontend may rely only on fields present in this file.

## Module & ops surface

- Pipeline writes only `data/registry.json`; emitters write only `site/data/radar.json` + `site/feed.xml`.
- Runner flags: `radar run --offline` (fixture replay, no network, no LLM), `radar run` (live), `radar emit` (fixture fallback for local dev), `radar prune` (+ `--dry-run`), `radar override` (`--op split|merge|detach`, validated Registry edits), `radar link-monitor` (`--incident <id> --url <http(s)>`, links a vendor page for hash-compare monitoring without changing Status).
- LLM config via env: `RADAR_LLM_API_KEY` (unset ⇒ the LLM pass, cluster verdicts, and monitor interpretation are skipped, token-free; deterministic CVE/vendor joins still run), `RADAR_LLM_BASE_URL`, `RADAR_LLM_MODEL`, `RADAR_LLM_SESSION_ID` (sent as `x-opencode-session`).
- Workflows: `daily.yml` (cron 06:00 UTC: fetch→gate→filter→enrich→cluster→monitor→prune→commit `data/`, then triggers deploy), `pages-deploy.yml` (emit + publish to GitHub Pages). No other workflow files.
