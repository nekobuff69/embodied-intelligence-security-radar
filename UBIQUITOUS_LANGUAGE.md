# Ubiquitous Language

## Core entities

| Term | Definition | Aliases to avoid |
| --- | --- | --- |
| **Item** | A single fetched piece of source content (article, advisory, post) that may attach to an Incident | Story, entry, record |
| **Incident** | A real-world event or vulnerability, clustered from one or more Items, carrying a Status and evidence | Issue, event, case |
| **Registry** | The committed store of all Items and Incidents (`data/registry.json`); git history is the audit trail | Store, database, repo |
| **Wire** | The list of unattached Items displayed on the site as raw, unclustered intel | Feed, stream, raw list |

## Incident lifecycle

| Term | Definition | Aliases to avoid |
| --- | --- | --- |
| **Status** | Lifecycle state of an Incident: disclosed → unpatched → patched / exploited-in-wild / resolved | State, stage, phase |
| **Patch lag** | Days from first disclosure to latest check without a disclosed fix; the radar's signature metric | Days-unpatched, age, staleness |
| **Hard-fact eligibility** | Rule that an Item may only create an Incident if it carries a CVE id, or is enriched with ai_relevant=true and a non-Unknown vendor | Incident-eligibility, creation gate |
| **Relevance screening** | LLM verdict that classifies an Item as a discrete, verifiable incident (true) or commentary/opinion/hype (false) | Triage, classification, AI filter |
| **Claim hygiene** | Rule set requiring every Status to carry a sourced evidence URL and as-of date; AI summaries labeled; severity never fabricated | Sourcing discipline, citation policy |

## Pipeline stages

| Term | Definition | Aliases to avoid |
| --- | --- | --- |
| **Rules gate** | Deterministic keyword prefilter (robot + incident terms, date sanity, commentary exclusion) applied before any LLM spend | Gate, filter, prefilter |
| **LLM pass** | Enrichment stage producing relevance, category, vendor/model/class extraction, severity, and buyer-facing summary on gate survivors | Enrichment (as a stage), AI stage, scoring |
| **Clusterer** | Groups Items into Incidents via exact join → vendor join → embedding similarity → optional LLM verdict | Deduplicator, grouper, merger |
| **Prune** | Retroactive pass that dismisses stale/commentary/irrelevant Items and demotes ineligible Incidents | Cleanup, hygiene pass, purge |
| **Monitor** | Advisory page hash-compare that advances `last_checked` with zero LLM cost when content is unchanged | Watcher, poller, staleness check |

## Actions on Items and Incidents

| Term | Definition | Aliases to avoid |
| --- | --- | --- |
| **Dismiss** | Remove an Item from the Registry and record its URL in the blocklist so feeds can never resurrect it | Delete, remove, drop |
| **Demote** | Detach all Items from an ineligible Incident, deleting the Incident and leaving Items in the Wire | Downgrade, unassign, break |
| **Defer** | Keep an Item in the Wire without creating an Incident (item lacks hard-fact eligibility) | Hold, queue, park |
| **Attach** | Link an existing Item to an existing Incident during clustering | Merge, join, add-to |
| **Create** | Instantiate a new Incident from an Item during clustering (hard-fact eligible) | Spawn, open, generate |

## Display and output

| Term | Definition | Aliases to avoid |
| --- | --- | --- |
| **Severity** | Risk rating — CVSS verbatim when present, otherwise an estimated band (low/medium/high/critical) | Risk, score, rating |
| **Axis card** | Homepage card summarizing one incident category (Vulnerabilities / Attacks / Physical Safety) with count | Category card, filter card |
| **METHOD page** | The about/methodology page explaining the pipeline, limitations, and disclaimer | Methodology, About, How |
| **Envelope** | — | — |

## Sources and data

| Term | Definition | Aliases to avoid |
| --- | --- | --- |
| **Source** | A configured feed origin (press RSS, Reddit, HN, NVD, GitHub advisory, vendor page) | Feed (as an origin), provider, input |
| **Blocklist** | Set of dismissed URLs (`data/dismissed_urls.json`) preventing re-admission by the feed pipeline | Denylist, block, ban |
| **Vendor advisory** | A security page published by the robot vendor, monitored by hash-compare for status changes | Advisory, notice, bulletin |

## Relationships

- An **Item** attaches to at most one **Incident**
- An **Incident** references one or more **Items** as evidence
- Every **Incident** carries exactly one **Status**, which changes only with a linked source
- **Dismiss** affects Items; **Demote** affects Incidents
- The **Rules gate** runs before the **LLM pass**; **Prune** runs after the **Clusterer**
- **Hard-fact eligibility** constrains which Items may **Create** Incidents
- The **Blocklist** persists across runs; **Dismissed** Items never reappear

## Example dialogue

> **Dev:** "I see two DJI vacuum incidents on the site. Are they the same story?"

> **Domain expert:** "Yes — **INC-0001** is the press coverage of the camera hack, and **INC-0009** is the CVE advisory. The same underlying event, reported two ways. The **Clusterer** couldn't **Attach** them because the press **Item** lacked the CVE id and the **vendor-only temporal join** wasn't implemented yet."

> **Dev:** "So the fix is the vendor-only pass in stage-0?"

> **Domain expert:** "Right — same vendor, model unknown on one side, within 120 days → **Attach**. That's deterministic, no LLM cost. After that, `radar override --op merge` cleans up the existing pair. Future runs attach automatically."

> **Dev:** "What happens to press Items that don't carry a CVE?"

> **Domain expert:** "They still **Create** an Incident if the **LLM pass** marks them **Relevance screening: true** with a non-Unknown vendor. If the model says false, the Item is **Dismissed** — URL blocklisted, gone. No more Google News noise."

## Flagged ambiguities

- **"source"** is used for both a configured feed origin (e.g., press_rss, reddit) and a citation linked from an Incident's Status (evidence_url). These are distinct: a **Source** is where you fetch from; a **citation** is what you cite in a Status claim. Always use **Source** for the former and **citation** or **evidence URL** for the latter.

- **"open"** is used for both Incident states (disclosed/unpatched/exploited_in_wild are the "open" set that participates in clustering) and GitHub issue state. In the codebase, `OPEN_STATES` refers to Incident lifecycle; GitHub issues use their own state vocabulary.

- **"dismiss" vs "demote" vs "delete"**: these are three distinct actions with different consequences. **Dismiss** = Item removed + URL blocklisted (permanent). **Demote** = Incident deleted, Items survive in Wire. **Delete** is never used for either — always use the precise term.

- **"enrichment"** is used as both the LLM-pass stage and the per-Item fields it produces (ai_summary, ai_category, etc.). In pipeline discussions, say **LLM pass** for the stage; in schema discussions, say **enrichment fields** for the outputs.

- **"cluster" vs "clustering" vs "clusterer"**: **Clusterer** is the module; **clustering** is the process; **cluster** (verb) is the action an Item undergoes. Avoid using "cluster" as a noun in domain discussions — say **Incident** instead.
