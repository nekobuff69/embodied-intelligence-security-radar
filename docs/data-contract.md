# Data contract

Single source of truth: `src/radar/schema.py`. Glossary vocabulary per `CONTEXT.md`.

## Registry file (`data/registry.json`, committed)

```
meta:    {schema_version: 1, generated_at?}
items:   [{id, source, url, title, body, published, cve_ids?, fetched_at}]
         source ∈ google_news|press_rss|reddit|hn|nvd|github_advisory|vendor_page
         items also carry optional LLM enrichment (filled by the LLM pass,
         lifted into Incidents by the clusterer): ai_summary?, ai_category?,
         ai_vendor?, ai_model?, ai_robot_class?, ai_severity?
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

## Emitter output (`site/data/radar.json`, generated, not committed)

Registry + derived fields: `patch_lag_days` (client-recomputed), `open` bool, counts. Frontend may rely only on fields present in this file.

## Module ownership boundaries

- `schema.py` — contract; changes require updating this doc + fixtures.
- Pipeline writes only `data/registry.json`; emitters write only `site/data/radar.json` + `site/feed.xml`.
- Runner flags: `radar run --offline` (fixture mode, no network), `radar run` (live), `radar emit`, `radar load-seed`.
- Workflows: `daily.yml` (cron: fetch→gate→apply→commit, then triggers deploy), `pages-deploy.yml` (emit + publish). No other workflow files.
