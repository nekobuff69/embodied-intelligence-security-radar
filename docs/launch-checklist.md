# Launch Checklist

Pre-launch verification for Robot Security Radar. All items must be checked before the repository is made public.

---

## Pipeline & Tests

- [ ] All tests green (`uv run pytest` passes with zero failures)
- [ ] Pipeline runs successfully in offline/fixture mode (`radar run --offline`)

## GitHub Actions

- [ ] Manual daily Actions run triggered and completed green (check Actions tab for the `daily.yml` workflow)

## RSS Feed

- [ ] `feed.xml` validates (check with an XML validator or feed reader; no malformed entries)

## Editorial Sign-Off

- [ ] METHOD page editorial sign-off recorded on [issue #12](https://github.com/nekobuff69/embodied-intelligence-security-radar/issues/12)
- [x] LLM provider config verified with enrichment active in a live run (OpenCode Go gateway `opencode.ai/zen/go/v1`, model `mimo-v2.5`, `x-opencode-session` header) — locally via `.env` (gitignored), 2026-09-09
- [ ] Repo secrets set for the nightly cron: `RADAR_LLM_API_KEY` (+ optional `RADAR_LLM_BASE_URL` / `RADAR_LLM_MODEL` / `RADAR_LLM_SESSION_ID`); without them the scheduled run executes enrichment-less

## Repository Visibility
- [x] Repository flipped to public (2026-09-09 — GitHub Pages requires a public repo on the free plan):
  ```
  gh repo edit nekobuff69/embodied-intelligence-security-radar --visibility public --accept-visibility-change-consequences
  ```
  Pages enabled with `build_type=workflow`; deploy verified green.

## Claim Hygiene Spot Check

Sample 5 incidents from the registry. For each, verify:

- [ ] Evidence links resolve (HTTP 200) to a real article or advisory
- [ ] `as_of` dates are present and reasonable (not future-dated, not epoch)
- [ ] Absence-of-evidence phrasing is correct: "No fix disclosed as of [date]" or equivalent caveat, never bare "unpatched"

## Hero Counters

- [ ] Dashboard hero counters are sane on production data:
  - Incident count matches registry size
  - Unpatched count matches incidents with status `unpatched`
  - Longest lag (days) is a plausible number consistent with the oldest unpatched incident
