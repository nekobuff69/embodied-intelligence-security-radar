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

- [ ] METHOD page editorial sign-off recorded on [issue #12](https://github.com/saga3k/embodied-intelligence-security-radar/issues/12)
- [ ] Seed-set editorial sign-off recorded on [issue #11](https://github.com/saga3k/embodied-intelligence-security-radar/issues/11)

## Repository Visibility

- [ ] Repository flipped to public:
  ```
  gh repo edit saga3k/embodied-intelligence-security-radar --visibility public
  ```
  *Command noted here for reference; do NOT execute until all other items pass.*

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
