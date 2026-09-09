# ADR-0001: Incidents are first-class entities behind a feed rendering

Date: 2026-09-09

## Status

Accepted

## Context

The motivating example is the Unitree BLE vulnerability: disclosed, and still unfixed roughly a year later. The story is not the disclosure event — it is the risk persisting for 365 days. A flat, deduplicated news feed shows the disclosure once and then goes silent; it structurally cannot express "still unfixed." However, the site's rendering ambition for v1 is a simple feed.

## Decision

Items (fetched, filtered content) cluster into Incidents during the LLM pass. Each Incident carries a status (`disclosed` → `unpatched` → `patched` / `exploited-in-wild` / `resolved`), a first-seen date, and its evidencing Items. The site still renders as a simple feed, but cards expose status and patch lag ("unpatched for 367 days"), and an Incident resurfaces when new Items attach. Incident detail is a query-param view with the Item timeline and source links — no separate page infrastructure in v1.

## Consequences

- One clustering field + status in the pipeline prompt; the dedup step Horizon already has becomes the clustering hook.
- Clustering is retrieve-then-adjudicate so LLM cost stays flat as the registry grows: stage 0 — exact key join (CVE ID, vendor+model+disclosure-date) attaches obvious Items with zero LLM cost; stage 1 — embedding similarity over the registry picks the top-k (k=3) candidates (dot products are free CPU math, no tokens); stage 2 — the LLM pass sees only the Item plus those k candidate blurbs and returns attach-or-new in the same call. Prompt size per Item is constant; registry size inflates only the free math stage.
- The candidate registry holds **open Incidents** (`disclosed`/`unpatched`/`exploited-in-wild`) plus recently closed ones for a reopen window (60–90 days, for patch-bypass coverage); fully closed Incidents leave the index. An open Incident with no arriving Items costs zero tokens per day; `last_checked` advances via advisory-page hash comparison (unchanged page → free, no LLM; changed page → one small interpretive call).
- Status changes require a linked, dated source (see ADR-0003); "unpatched" is an absence-of-evidence claim and must be phrased as such.
- Pure-flat-feed (rejected) would have made the flagship story invisible. Full incident tracker with dedicated pages/timelines/vendor scorecards is deferred to v2, gated by the 30-day quality gate.

## Related

- ADR-0003 (strict claim hygiene)
- CONTEXT.md glossary: Item, Incident, Status, Patch lag
