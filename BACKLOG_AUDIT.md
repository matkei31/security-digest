# Backlog Audit

This file records the systematic audit of past user comments tracked by [BL-014](BACKLOG.md#bl-014--過去ユーザーコメントの体系的棚卸し). It is a continuing, batch-by-batch record of audit scope, classification, and unresolved items. It does not replace [BACKLOG.md](BACKLOG.md), [STATUS.md](STATUS.md), or [DECISIONS.md](DECISIONS.md); it records how items were routed into them.

## Audit rules

- Recoverable original wording is preserved verbatim.
- Reconstructed wording is not quoted as a user statement.
- Implementation and user acceptance are recorded and evaluated separately.
- Partial completion retains its residual scope; it is not marked `Done`.
- Audit completion is not inferred from one batch. BL-014 remains open until the full scope below is covered and the user has reviewed the result.

## Audit scope

- Target period: 2026-05-27 through 2026-07-17.
- GitHub PR #1–#18.
- PR bodies, comments, and completion records.
- `BACKLOG.md`, `STATUS.md`, `DECISIONS.md`, `README.md`, `AGENTS.md`.
- Current `main` implementation.
- Limitation: direct project-conversation history is not fully available to Claude Code. Original wording used in this audit was supplied to Claude Code by the user/ChatGPT-side record; Claude Code did not reconstruct it and did not independently verify conversation timestamps beyond what was supplied.
- Pre-PR direct-push history (2026-05-27 through the first PR, 2026-07-12; over 150 commits) remains incompletely audited.

## Batch 1 — 2026-07-17

| Audit ID | User wording / provenance | Classification | Mapping | Evidence | Residual / reevaluation condition | Status |
|---|---|---|---|---|---|---|
| BL014-A | Verbatim user comment: 「URLがgithubのユーザー名なのが気になる」（2026-07-09 project conversation） | Existing BL update | [BL-007](BACKLOG.md#bl-007--monomidigestcomへの移行) | `BACKLOG.md` BL-007; `DECISIONS.md` SD-011; no `CNAME` file, no `monomidigest`/`monomi.jp` reference in `fetch.py`/`daily_json.py`/`source_definitions.json` | BL-007 implementation itself (domain acquisition, DNS, Pages configuration, canonical URLs, redirects) remains not implemented | Recorded; BL-007's `Original user comment` field updated in this batch |
| BL014-B | Three separate original texts, preserved without merging — see [Candidate B detail](#candidate-b-detail--daily-jsonの公開範囲) below. The Accepted wording used as SD-014's decision text is quoted in full in SD-014 itself | Stable Decision | [SD-014](DECISIONS.md#sd-014--keep-daily-json-outside-the-github-pages-publication-tree-and-limit-stored-content) | `daily_json.py` (`DATA_DIR`, `build_raw_excerpt`, `compute_content_hash`), `fetch.py` (`DOCS_DIR`), `.github/workflows/fetch.yml`, SD-002 | None for the current implementation (data placement and non-storage of secrets/raw AI response/full article text/rich content already match the accepted approach); reevaluation required if stored scope is proposed to expand | Recorded; SD-014 added in this batch |
| BL014-C | Verbatim user comment 1: 「セキュリティ要件みたいなのも後で決めよう」／Verbatim user comment 2: 「OK.ここはfable5にもレビューしてもらおう。公開情報を扱うものだから厳しいセキュリティ対策をする必要はないと思うが、必要なものは網羅しつつ過剰じゃないように整理して、fable5にレビューさせられる形にして。」（両者は別々に保存し、1つに統合しない） | New BL | [BL-015](BACKLOG.md#bl-015--公開サイトと生成基盤のセキュリティ要件を定義する) | `AGENTS.md`「## Security requirements」節（既存の個別ルール）; repo直下に`SECURITY.md`／`SECURITY_REQUIREMENTS.md`が存在しないこと | Requirements draft, evidence mapping, proportionality review, Fable 5 review, gap-ticket decision, user acceptance | Captured / Not completed |
| BL014-D | Original wording not recovered（Recovered paraphrase / user-accepted approach。原文は引用形式にしない） | Done reference | [Completed reference — 取得時証跡と内部日付別アーカイブ](BACKLOG.md#取得時証跡と内部日付別アーカイブ) | `daily_json.py`（`build_raw_excerpt`, `compute_content_hash`）, `fetch.py`（`build_daily_archive_html`, `generate_archive_outputs`）, 実データ`data/2026-07-17.json` | raw_excerpt範囲拡大、記事全文保存、rich content保存、外部archiveサービスへの自動送信、private feed対応、保存データの外部提供のいずれかが生じた場合は再オープン | Done |
| BL014-E | Verbatim user comment: 「うん。タグ検索みたいなのは後からやろう。今って、記事検索機能はないよね？サイトの目的としては不要かな？だとしたらタグ検索も不要かな？」 | Out of scope / No action | なし（[SD-013](DECISIONS.md#sd-013--ordinary-article-card-variant-b-remove-classification-label-badges-keep-関連タグ-round) / [BL-002](BACKLOG.md#bl-002--記事カードの楕円バッジ多用を見直す) / [PR #18](https://github.com/matkei31/security-digest/pull/18)を参照） | SD-013決定文（検索機能非導入の明記）、`fetch.py`の`<span class="article-tag">`（非クリック） | 将来、アーカイブ横断検索の明確な需要が確認された場合のみ再評価 | 新規BLなし。記録のみ |
| BL014-F | 該当なし（Engineering finding） | Evaluated under BL-015; no independent BL yet | [BL-015](BACKLOG.md#bl-015--公開サイトと生成基盤のセキュリティ要件を定義する)（Acceptance criteriaの評価項目として記載） | `.github/workflows/fetch.yml`（`actions/checkout@v4`, `actions/setup-python@v5`、いずれもfull commit SHA pinningではない）、`.github/`配下に`dependabot.yml`が存在しないこと | BL-015レビューで具体的なgapと対応方針が承認された場合のみ、新規Engineering finding BLとして分割する | BL-015スコープ内で評価対象として記録。独立BLは未採番 |

BL014-Dの分類に伴い、[BACKLOG.md](BACKLOG.md)のCompleted referenceへ「取得時証跡と内部日付別アーカイブ」を追加した。詳細な完了範囲・証跡・再オープン条件は`BACKLOG.md`のCompleted reference本文を参照。

### Candidate B detail — daily JSONの公開範囲

daily JSONの公開範囲について、本監査依頼で提供された発言は3つある。いずれも別々の発言として記録し、1つの原文へ統合しない。同一内容の重複と見なして片方を削除することもしない。発言日はいずれも確認できておらず、推測しない。

- **Verbatim user comment 1（問題提起）:** 「jsonは公開する意味ないと思うから場所変えよう」
- **Verbatim user comment 2（問題提起、上記とは別記録）:** 「jsonは公開する意味ないので場所を変えたい」
- **Clarification（確認質問）:** 「よくわかってないけど、動作に問題なければJSONは外から見える意味ないのでは？見えないといけない？」
- **Date:** Not confirmed for any of the three texts above.
- **Accepted wording（最終合意、以下は本監査依頼で提供された文言）:** [SD-014](DECISIONS.md#sd-014--keep-daily-json-outside-the-github-pages-publication-tree-and-limit-stored-content)にそのまま記録されているため、ここでは重複して引用しない。

## Remaining audit scope

- BL-005 original wording recovery.
- BL-008 original wording recovery.
- BL-009 original wording recovery.
- BL-010 original wording recovery.
- Pre-PR history / direct pushes（2026-05-27〜2026-07-12、PR化以前の直push分）.
- Any other uncategorized user comments.
- Final user review and explicit statement on whether unclassified comments remain.
- Additional finding (not yet actioned): PR #2, #3, #4, #6, #9 correspond to completed tickets (Ticket 13c, Ticket 14a, Ticket 15a, Ticket 15c) that are not yet cross-referenced in `BACKLOG.md`'s Completed reference section. Whether they need explicit Completed reference entries (to prevent accidental reopening) is unresolved and left to a future batch.
