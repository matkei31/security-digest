# Security Digest Status

## 1. As of

2026-07-20

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
- BL-016 status-line relabel: the deterministic status line dropped its "本日の状態" label/brackets/colon/trailing period for a plain `｜`-delimited format, and all existing per-day archive HTML was regenerated from existing daily JSON (no Gemini/HTTP calls, no data/ changes) — completed and user-accepted (2026-07-18, verbatim: 「新しい表示もPC・390px・過去ダイジェストとも問題なし」); see [PR #23](https://github.com/matkei31/security-digest/pull/23), merge commit `b8c0ab0fa5411930fc55b1b9f97cfda016c29373`
- BL-017 archive-list cleanup and previous/next navigation between existing daily archives — completed in [PR #24](https://github.com/matkei31/security-digest/pull/24), merge commit `8cb8e95639d125fec31057737bb4c445252433f7`, and user-accepted on 2026-07-18; see [BL-017](BACKLOG.md#bl-017--過去ダイジェストの回遊性と一覧表示を改善する)
- BL-001 Pull Request CI — completed in [PR #26](https://github.com/matkei31/security-digest/pull/26), merge commit `f5bbd04f42643d4a87f999d01f538d574fe39f17`, after [Pull Request CI run 29640129033](https://github.com/matkei31/security-digest/actions/runs/29640129033) succeeded on the draft PR; see [BL-001](BACKLOG.md#bl-001--プルリクエストci)
- BL-018 article-meta JST normalization — completed in [PR #28](https://github.com/matkei31/security-digest/pull/28), merge commit `196c77bcc2b71f8aecd9d0c6aef03388ffd5edf1`; [Pages deployment run 29643207764](https://github.com/matkei31/security-digest/actions/runs/29643207764) succeeded, and the user accepted the top-page timestamps, article order, and body content on 2026-07-18; see [BL-018](BACKLOG.md#bl-018--トップページとjson再構築時の記事時刻表示を一致させる)
- BL-004 UI specification — completed with [UI_SPEC.md](UI_SPEC.md) Version 1.0／承認済み; the seven choices are ユーザー裁定済み and recorded in [SD-016](DECISIONS.md#sd-016--resolve-the-remaining-bl-004-ui-choices-without-changing-the-accepted-layout); [PR #30](https://github.com/matkei31/security-digest/pull/30) was merged as `198b5a6dc723870b691575ba89c2aaae89e35b8c` and is merge後検証済み; see [BL-004](BACKLOG.md#bl-004--fable-5によるuiレビューとui設計書)
- BL-019 source-footer count/list consistency — completed in [PR #32](https://github.com/matkei31/security-digest/pull/32), merge commit `d08a1b00d43488892ba6ef74b184340ab14a72c0`; [Pages deployment run 29692162999](https://github.com/matkei31/security-digest/actions/runs/29692162999) and post-merge verification succeeded, and the user's acceptance is limited to the 15-source correction while source colors continue separately as BL-020; see [BL-019](BACKLOG.md#bl-019--収集元見出し件数と列挙対象を一致させる)

## 6. Known issues and limitations

- [BL-020](BACKLOG.md#bl-020--収集元一覧の取得元別カラーを廃止する): the per-source color and pill-like treatment in the collapsible source footer is a specified but unimplemented small UI fix, separate from the completed source-count correction.
- CISA advisory RSS remains disabled until its documented reactivation conditions are met.
- [BL-011](BACKLOG.md#bl-011--standalone-nist-nvd記事取得の保留理由再開条件): The reason and reactivation conditions for standalone NIST NVD article collection are not fully documented.
- [BL-015](BACKLOG.md#bl-015--公開サイトと生成基盤のセキュリティ要件を定義する): A comprehensive security requirements document does not yet exist; existing rules remain scattered across `AGENTS.md` and code.
- Ticket 16a's standalone real-Gemini diagnostic for the Microsoft reference article remains unverified; this did not block its production acceptance.

## 7. Next candidates

1. [BL-005](BACKLOG.md#bl-005--editorial-style-v1とtoday-brief-v4) (P1) — BL-004／Fable 5デザインレビューへの依存は完了した。[SD-007](DECISIONS.md#sd-007--create-security-digest-editorial-style-v1-and-introduce-it-to-brief-first)の既存方向性に従い、次に`editorial-style-v1`と`today-brief-v4`の要件、完了条件、比較評価方法を確定する。Gemini promptのproduction実装にはまだ着手せず、ARTICLEは初期スコープ外とする。決定論的なBRIEF state/count logic、trusted-context境界、ARTICLEとの分離、daily JSON schemaを維持する。

[BL-015](BACKLOG.md#bl-015--公開サイトと生成基盤のセキュリティ要件を定義する) (P2, security requirements document) is recorded in BACKLOG.md but is not included in this short priority list.

This short priority list is not exhaustive. Other open items remain recorded in BACKLOG.md.

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
| Approved UI specification and UI decision history | `UI_SPEC.md` |
| Implementation-agent constraints | `AGENTS.md` |
