# Security Digest Status

## 1. As of

2026-07-17

This file records the current, changeable project state. Incomplete, partially addressed, and acceptance-pending items are recorded in [BACKLOG.md](BACKLOG.md). Stable design and operating decisions are recorded in [DECISIONS.md](DECISIONS.md).

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
- Project documentation alignment — completed in [PR #13](https://github.com/matkei31/security-digest/pull/13)
- Legacy local operation scripts — removed

## 6. Known issues and limitations

- [BL-001](BACKLOG.md#bl-001--pull-request-ci): Pull requests have no ordinary GitHub Actions checks; scope-appropriate local verification and independent diff review are currently used as merge evidence.
- CISA advisory RSS remains disabled until its documented reactivation conditions are met.
- [BL-011](BACKLOG.md#bl-011--standalone-nist-nvd記事取得の保留理由再開条件): The reason and reactivation conditions for standalone NIST NVD article collection are not fully documented.
- [BL-014](BACKLOG.md#bl-014--過去ユーザーコメントの体系的棚卸し): The initial canonical-backlog import is not a complete audit of past user comments; the migration audit remains incomplete.
- Ticket 16a's standalone real-Gemini diagnostic for the Microsoft reference article remains unverified; this did not block its production acceptance.

## 7. Next candidates

1. [BL-001](BACKLOG.md#bl-001--pull-request-ci) — Add ordinary pull request CI.
2. [BL-002〜BL-004](BACKLOG.md#bl-002--記事カードの楕円バッジ多用を見直す) — Specify the UI/badge redesign and obtain Fable 5 review.
3. [BL-005](BACKLOG.md#bl-005--editorial-style-v1とtoday-brief-v4) — Design `editorial-style-v1` and `today-brief-v4`.

See [BACKLOG.md](BACKLOG.md) for BL-006 and later items; they remain recorded and are not removed by this short priority list.

The initial backlog import is not a complete historical-comment audit; [BL-014](BACKLOG.md#bl-014--過去ユーザーコメントの体系的棚卸し) tracks that migration work. Stable brand and domain directions are recorded in [SD-010](DECISIONS.md#sd-010--use-monomi-digest-as-the-future-public-brand) and [SD-011](DECISIONS.md#sd-011--use-monomidigestcom-as-the-primary-domain), with implementation scope in BL-006 and BL-007.

## 8. Sources of truth

| Subject | Source of truth |
|---|---|
| ARTICLE／BRIEF／daily schema versions | `daily_json.py` |
| Gemini model and prompt bodies | `fetch.py` |
| Source URLs and enablement | `source_definitions.json` |
| Daily workflow triggers and permissions | `.github/workflows/fetch.yml` |
| Generated daily data | `data/` |
| Published static output | `docs/` |
| Incomplete, partial, and acceptance-pending items | `BACKLOG.md` |
| Stable decisions | `DECISIONS.md` |
| Implementation-agent constraints | `AGENTS.md` |
