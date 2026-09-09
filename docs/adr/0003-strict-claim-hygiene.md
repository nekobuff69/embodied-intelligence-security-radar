# ADR-0003: Strict claim hygiene for status and severity claims

Date: 2026-09-09

## Status

Accepted

## Context

The radar's signature output — "Vendor X product Y: unpatched for N days" — is an inference from absence of evidence, attached to a named, live company. Sloppy phrasing is defamation-adjacent; precise phrasing is credible journalism. AI-generated summaries add a second risk: fluent fabrication. The site's product is credibility, so every rhetorical weapon must be armored.

## Decision

1. **Statuses change only with a linked, dated source.** The status field carries its evidence link and `as_of` date.
2. **Absence-of-evidence is stated as such.** "No fix disclosed as of 2026-09-09; advisory last checked {date}" — never bare "unpatched" without the apparatus, because a vendor may fix silently and the radar can lag.
3. **Patch lag is honest arithmetic.** Days from first disclosure to `last_checked`, with the caveat attached; never padded.
4. **AI summaries are labeled AI-generated** with "verify with the linked source" adjacent. Snippets always link the source; the summary never replaces it.
5. **Severity provenance is explicit.** CVSS verbatim where a CVE exists; otherwise an LLM-assigned qualitative band shown as "estimated". Never a fabricated numeric score.
6. **METHOD page** documents the pipeline, its failure modes, AI usage, and a "not security or legal advice" disclaimer. *(Amendment 2026-09-09: the manual seed set was removed by ADR-0004; hygiene now rests on the LLM relevance verdict, the rules gate, and `radar prune`.)*

Aggressive naming (badges/wall-of-shame framing without per-claim caveats) was rejected: maximum rhetorical force, unacceptable legal and reputational exposure.

## Consequences

- The pipeline's LLM pass must emit claim metadata (evidence URL, as_of date) alongside status, and the schema enforces it.
- Editorial review of the curated seed set must meet the same bar as automated output.
- Sorting by severity treats bands coarsely (no fake precision); ties break by recency.

## Related

- ADR-0001 (statuses and patch lag only exist because Incidents are entities)
- CONTEXT.md glossary: Claim hygiene, Estimated band, Patch lag
