# Context: Robot Security Radar

Public-awareness news aggregator for security incidents involving embodied-intelligence products (humanoids, quadrupeds, consumer/service robots). Thesis: mass adoption is outrunning liability, and buyers are uninformed about security and accountability risk. The radar finds notable intelligence from open-access sources and presents it buyer-first, strictly sourced.

Stack reference (patterns only, not a fork): [Thysrael/Horizon](https://github.com/Thysrael/Horizon) (MIT) — fetch → dedup → score → summarize → static site on scheduled GitHub Actions. Layout reference: dark "radar terminal" dossier-grid aesthetic (single-page HTML/CSS/JS over a JSON index).

## Audience

- **Primary**: prospective robot buyers — procurement, ops, consumers. Plain-language risk framing ("what this means if you own or plan to buy one").
- **Secondary**: security researchers and journalists. Technical detail (CVE IDs, sources) is a metadata layer, never the headline.

## Scope (v1)

- **Incident categories**: (1) vulnerabilities & disclosures, (2) attacks in the wild, (3) physical safety incidents. Liability/litigation, regulation/policy, and hype-vs-reality watch are **deferred to v2**.
- **Robot domain**: emerging embodied products only — humanoids, quadrupeds, consumer/service robots (Unitree, Optimus, Figure, home robots). **Excluded**: drones/UAVs, autonomous vehicles, industrial arms/cobots (mature existing coverage elsewhere; excluding cuts noise and keeps the adoption-gap thesis sharp).

## Deferred scope (gated by success criteria)

Chinese localization, liability/litigation category, vendor threat-board dashboard, newsletter/email digest, X/Twitter + Telegram sources, automated historical backfill.

## Success criteria (30-day quality gate)

V2 scope unlocks when, 30 days after launch:

1. Pipeline ran unattended ≥ 25 of 30 days.
2. Incident registry holds ≥ 25 clustered incidents with audited correct statuses.
3. Zero fabricated-status or unsourced-claim regressions in the audit.
4. ≥ 1 unsolicited external share or citation.

## Glossary

- **Item** — a single fetched, filtered piece of source content (one article, advisory, post). Attaches to at most one Incident.
- **Incident** — a clustered real-world event or vulnerability across Items, first-class entity with: category, robot class, vendor/model, severity, **status**, first-seen date, and the Items that evidence it.
- **Status** — lifecycle state of an Incident: `disclosed` → `unpatched` → `patched` / `exploited-in-wild` / `resolved`. May only change with a linked, dated source.
- **Patch lag** — days from first disclosure to latest check without a disclosed fix. The radar's signature metric; powers the patch-lag sort.
- **Registry** — the full set of tracked Incidents and Items (`data/registry.json`, committed; git history is the audit trail). Only **open** Incidents participate in clustering; closed ones leave the candidate index after the reopen window. Registry growth never inflates LLM prompts (ADR-0001 retrieve-then-adjudicate).
- **Claim hygiene** — the rule set from ADR-0003: statuses sourced and dated, absence-of-evidence caveats explicit, AI summaries labeled, no fabricated numbers.
- **Rules gate** — deterministic keyword prefilter (robot terms AND incident terms) applied before any LLM spend; also drops stale items (>3 years) and commentary/entertainment phrasing.
- **Relevance screening** — the LLM pass emits `ai_relevant` per Item: an incident is a discrete, verifiable security/safety event; podcasts, opinion, roundups, and hype are never incidents and get dismissed outright (URL blocklisted so feeds cannot resurrect them).
- **Hard-fact eligibility** — an Item may create an Incident only with evidence: a CVE id, or `ai_relevant=true` plus an extracted non-Unknown vendor. Everything else stays in the **Wire** (unattached Items list on the site).
- **LLM pass** — relevance verdict, category/vendor/model/class extraction, severity (CVSS verbatim or Estimated band), a 2–3 sentence buyer-facing summary, and cluster-verdict candidates — run on gate survivors only, over an OpenAI-compatible provider (OpenCode Go) with a per-client session header.
- **Prune** — retroactive hygiene pass: dismisses stale, commentary, and `ai_relevant=false` Items (URLs blocklisted), demotes Incidents without hard-fact evidence, protects nothing manually curated (none exists since ADR-0004).
- **METHOD page** — five sections: What it is (with merged disclaimer), How the Radar works (plain language), Limitations, Data sources, Contribution.

## Key decisions

- ADR-0001: Incidents are entities; the site renders as a feed but statuses and patch lag survive dedup.
- ADR-0002: Own Python pipeline (uv) on GitHub Actions daily cron; static JSON + vanilla HTML/CSS/JS on GitHub Pages; Horizon reused as modules, not forked.
- ADR-0003: Strict claim hygiene for every status claim.
- ADR-0004: Launch content is pipeline-derived only: the LLM-configured pipeline run produces the incident set; no manual curation layer.
- Severity: CVSS verbatim where a CVE exists; otherwise Estimated band. Sort treats bands coarsely, ties broken by recency.
- Sources (v1): Google News keyword RSS, security press (BleepingComputer, The Register, SecurityWeek, Ars Technica) + robotics press (IEEE Spectrum, The Robot Report, TechCrunch) RSS, Reddit (r/robotics, r/Robots, r/unitree) + Hacker News, NVD/CVE keyword feed + GitHub advisories/PoC repos, plus vendor advisory-page monitors with hash-compare state.
- LLM: OpenCode Go gateway (`opencode.ai/zen/go/v1`, currently `mimo-v2.5`) via a swappable OpenAI-compatible config (`.env` locally, repo secrets in Actions; session header `x-opencode-session` sent when configured).
- Hard-fact eligibility (ADR-0004): Incidents are created only from evidence — a CVE id, or `ai_relevant=true` with a non-Unknown vendor; rejected Items are dismissed (URL blocklist) or held in the Wire.
- Cadence: one daily Actions run (fetch → gate → enrich → cluster → monitor → prune → commit) plus a Pages deploy; pipeline also emits `feed.xml` (RSS) of new/updated Incidents.
- Name: **Robot Security Radar** (compact: RobotSec Radar). Live at GitHub Pages.
- Navigation: hero with live counters (N incidents / M unpatched / longest patch lag) → three category axis cards → single ALL INCIDENTS grid (search; vendor / robot-class / status filter chips; sort: newest, severity, patch lag) → per-incident detail (query-param view with Item timeline + source links) → WIRE (unattached Items) → METHOD page. Everything one page, client-side filtered.

## Data & site shape (v1)
- Pipeline state lives in `data/`: `registry.json` (Incidents + Items, committed; git history is the audit trail), `dismissed_urls.json` (never re-admit dismissed Items), `.vendor_hashes.json` (advisory hash state for the `last_checked` monitor).
- Emitters write `site/data/radar.json` (frontend contract, generated, not committed) and `site/feed.xml` (RSS).
- Site: one `index.html` + CSS + vanilla JS reading the JSON; no build toolchain, no server. Statuses and Patch lag are computed client-side (`first_seen` + `last_checked`) so static data stays fresh-looking.
- Live: GitHub Pages (`https://nekobuff69.github.io/embodied-intelligence-security-radar/`), deployed by `pages-deploy.yml` on every push touching `data/` or `site/`.
