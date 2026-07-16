# Security Digest Status

## 1. As of

2026-07-16

This file records the current, changeable project state. Stable design and operating decisions are recorded in [DECISIONS.md](DECISIONS.md).

## 2. Current versions

| Contract | Current value |
|---|---|
| ARTICLE prompt | `article-analysis-v7` |
| BRIEF prompt | `today-brief-v3` |
| Daily JSON `schema_version` | `1` |
| Gemini model | `gemini-2.5-flash` |

The code-level version source of truth is `daily_json.py`; the model source of truth is `fetch.py`.

## 3. Generation and publication

- Daily Security Digest runs through `.github/workflows/fetch.yml`.
- Supported triggers are the daily schedule and explicit `workflow_dispatch`.
- There is no ordinary `pull_request` or `push` CI workflow.
- Production generation writes daily JSON under `data/` and static output under `docs/`.
- GitHub Pages publishes the `docs/` directory from `main`.
- A normal code merge does not require a manual daily run or real Gemini diagnostic unless the ticket's acceptance plan explicitly requires one.

## 4. Source status

The canonical configuration is `source_definitions.json`.

| Source/path | Current state | Notes |
|---|---|---|
| CISA advisory RSS | Disabled / on hold | Repeated HTTP 403 in GitHub Actions; reactivation conditions are recorded in the source definition |
| CISA KEV | Enabled | Uses the official `cisagov/kev-data` GitHub mirror |
| NIST NVD article collection | Disabled / on hold | This is the standalone article-source path |
| NVD vulnerability facts | Active through a separate path | Used for CVE facts and is distinct from NVD article collection |

Other enabled RSS/Atom sources are controlled by `source_definitions.json`; this file does not duplicate the entire list.

## 5. Recently completed work

- Ticket 16a: feed-native rich content for ARTICLE input — completed
- Ticket 17a: advisory action wording lint false-positive fix — completed
- ARTICLE internal-identifier exposure hotfix — completed
- Ticket 15b: state-aware BRIEF v3 — completed
- Ticket 15c: BRIEF display hierarchy — completed
- README / AGENTS / STATUS / DECISIONS alignment — in progress

## 6. Known issues and limitations

- Pull requests have no ordinary GitHub Actions checks; local tests and independent diff review are currently used as merge evidence.
- CISA advisory RSS remains disabled until its documented reactivation conditions are met.
- The reason and reactivation conditions for standalone NIST NVD article collection are not fully documented.
- Ticket 16a's standalone real-Gemini diagnostic for the Microsoft reference article remains unverified; this did not block its production acceptance.
- `schedule.sh`, `setup.sh`, and `deploy.sh` describe legacy local operation and are not the current production runbook.

## 7. Next candidates

- Define Security Digest's own `editorial-style-v1` and partially introduce it to BRIEF through `today-brief-v4`.
- Keep ARTICLE outside `editorial-style-v1` initially.
- Consider adding an ordinary `pull_request` CI workflow.
- Decide whether to remove or explicitly deprecate the legacy local operation scripts.

## 8. Sources of truth

| Subject | Source of truth |
|---|---|
| ARTICLE／BRIEF／daily schema versions | `daily_json.py` |
| Gemini model and prompt bodies | `fetch.py` |
| Source URLs and enablement | `source_definitions.json` |
| Daily workflow triggers and permissions | `.github/workflows/fetch.yml` |
| Generated daily data | `data/` |
| Published static output | `docs/` |
| Stable decisions | `DECISIONS.md` |
| Implementation-agent constraints | `AGENTS.md` |
