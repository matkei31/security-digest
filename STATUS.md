# Security Digest Status

## 1. As of

2026-07-17

This file records the current, changeable project state. Incomplete, partially addressed, and acceptance-pending items are recorded in [BACKLOG.md](BACKLOG.md). Stable design and operating decisions are recorded in [DECISIONS.md](DECISIONS.md).

## 2. Current versions

| Contract | Current value |
|---|---|
| ARTICLE prompt | `article-analysis-v8` |
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

- Ordinary article card, variant B (removes source/importance/urgency/category ellipse badges, keeps 関連タグ round and non-clickable) — completed and user-accepted (2026-07-17, verbatim: 「見られたけど、いいと思うよ」); see [SD-013](DECISIONS.md#sd-013--ordinary-article-card-variant-b-remove-classification-label-badges-keep-関連タグ-round), [BL-002](BACKLOG.md#bl-002--記事カードの楕円バッジ多用を見直す), [BL-003](BACKLOG.md#bl-003--aiで機械処理された印象を弱める), [PR #18](https://github.com/matkei31/security-digest/pull/18)
- Dashboard v2 (single lightweight block), 優先確認 as a reasoned index, and the ARTICLE `reason` no-imperative prompt contract (`article-analysis-v8`) — completed; see [SD-012](DECISIONS.md#sd-012--dashboard-v2-priority-index-and-the-article-reason-no-imperative-contract)
- Ticket 16a: feed-native rich content for ARTICLE input — completed
- Ticket 17a: advisory action wording lint false-positive fix — completed
- ARTICLE internal-identifier exposure hotfix — completed
- Ticket 15b: state-aware BRIEF v3 — completed
- Ticket 15c: BRIEF display hierarchy — completed
- Project documentation alignment — completed in [PR #13](https://github.com/matkei31/security-digest/pull/13)
- Legacy local operation scripts — removed
- BL-016 status-line relabel: the deterministic status line dropped its "本日の状態" label/brackets/colon/trailing period for a plain `｜`-delimited format, and all existing per-day archive HTML was regenerated from existing daily JSON (no Gemini/HTTP calls, no data/ changes) — implemented; production visual acceptance still outstanding

## 6. Known issues and limitations

- [BL-001](BACKLOG.md#bl-001--プルリクエストci): Pull requests have no ordinary GitHub Actions checks; scope-appropriate local verification and independent diff review are currently used as merge evidence.
- CISA advisory RSS remains disabled until its documented reactivation conditions are met.
- [BL-011](BACKLOG.md#bl-011--standalone-nist-nvd記事取得の保留理由再開条件): The reason and reactivation conditions for standalone NIST NVD article collection are not fully documented.
- [BL-016](BACKLOG.md#bl-016--本日の要点の表示階層を目視受入する): The "本日の状態" label/brackets/colon/trailing period have been removed from the deterministic status line, and all existing per-day archive HTML has been regenerated from existing daily JSON; explicit production visual acceptance (PC/390px) of the resulting display has not yet been recorded.
- [BL-018](BACKLOG.md#bl-018--トップページとjson再構築時の記事時刻表示を一致させる): Rebuilding the top page from stored daily JSON can show a different article-meta timestamp than the original production render; root cause and fix are not yet implemented.
- [BL-017](BACKLOG.md#bl-017--過去ダイジェスト間を前後移動できるようにする): One-click previous/next navigation between existing daily archives is not yet implemented.
- [BL-015](BACKLOG.md#bl-015--公開サイトと生成基盤のセキュリティ要件を定義する): A comprehensive security requirements document does not yet exist; existing rules remain scattered across `AGENTS.md` and code.
- Ticket 16a's standalone real-Gemini diagnostic for the Microsoft reference article remains unverified; this did not block its production acceptance.

## 7. Next candidates

1. [BL-016](BACKLOG.md#bl-016--本日の要点の表示階層を目視受入する) — Visually accept the current "本日の要点" display on production, PC and 390px.
2. [BL-018](BACKLOG.md#bl-018--トップページとjson再構築時の記事時刻表示を一致させる) — Determine and fix the article-meta timestamp discrepancy between normal generation and daily JSON reconstruction.
3. [BL-001](BACKLOG.md#bl-001--プルリクエストci) — Add ordinary pull request CI.
4. [BL-017](BACKLOG.md#bl-017--過去ダイジェスト間を前後移動できるようにする) — Implement one-click previous/next navigation between daily archives.

[BL-015](BACKLOG.md#bl-015--公開サイトと生成基盤のセキュリティ要件を定義する) (P2, security requirements document) is recorded in BACKLOG.md but is not placed ahead of BL-001 in this priority list.

This short priority list is not exhaustive. BL-004 and the other open items remain recorded in BACKLOG.md.

The initial backlog import is not a complete historical-comment audit; [BL-014](BACKLOG.md#bl-014--過去ユーザーコメントの体系的棚卸し) tracks that migration work, and [BACKLOG_AUDIT.md](BACKLOG_AUDIT.md) records its batch-by-batch progress. Stable brand and domain directions are recorded in [SD-010](DECISIONS.md#sd-010--use-monomi-digest-as-the-future-public-brand) and [SD-011](DECISIONS.md#sd-011--use-monomidigestcom-as-the-primary-domain), with implementation scope in BL-006 and BL-007.

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
