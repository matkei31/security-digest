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

## Batch 2 — 2026-07-18

### Scope and method

- Target period: 2026-05-27 through 2026-07-17（PR化以前のdirect push、およびGitHub PR #1〜#19の証跡）。
- Role boundary: 本バッチではproject conversation履歴からの原文回収は対象外。原文はGitHub上の証跡（PR本文・コメント・commit）に限定して探索した。原文を回収できない事項は、推測せず`Original wording not recovered`のまま維持した。commit messageとPR本文は実装／運用の証跡として扱い、ユーザー原文としては扱わなかった。
- 開始時`main` HEAD: `4181a304e802a4d58015b74a01bc9aef6a3bdd90`（想定HEADと一致、差分なし）。working tree clean。
- 参照した情報源: `main`の全git log（214 commits、うちPR #1作成時刻2026-07-12T16:32:14Z以前の149 commitsを対象に個別分類）、GitHub PR #1〜#19の本文・コメント・merge commit、`BACKLOG.md`／`STATUS.md`／`DECISIONS.md`／`README.md`／`AGENTS.md`（現行`main`時点）、現行`main`実装（`fetch.py`／`daily_json.py`／`vulnerability_facts.py`／`source_definitions.json`／`.github/workflows/fetch.yml`）、および本ファイルの第1バッチ記録。
- 証跡区分: 実装証跡（コード・commit・PRの存在）、merge証跡（merge commit SHA・PRのmerged状態）、本番証跡（PR本文が明示する場合のみ）、ユーザー受入証跡（推測ではない明示的なユーザー確認）、原文証跡（PR／コメント／commitで直接確認できる引用）、後続変更・Supersede証跡（後続commit／PR／SDが明示するか）を、事項ごとに区別して記録した。
- 本バッチでは、リポジトリ内ファイルの新規作成・編集・削除、branch作成、commit／push／PR作成、merge、GitHub Actions workflowの実行、Gemini API呼び出し、`data/`／`docs/`の生成は一切行っていない。`BACKLOG.md`／`STATUS.md`／`DECISIONS.md`／`BACKLOG_AUDIT.md`は読み取りのみ行った（分類結果の反映は本バッチ完了後、別途この文書自身への更新として実施）。

### Audit A — Direct-push history（149 commits、21機能グループ）

`git log --reverse`を用い、`main`上でPR #1のmerge commit（`8f6c5dfdcfc2113cba410a7059d230026d6d1a7a`）の第一親（direct push側の履歴）に到達可能な149 commitsを抽出した。単純なauthor date比較（PR #1作成時刻`2026-07-12T16:32:14Z`より前）では150件がヒットするが、うち1件（`7b24151`、Ticket 12c/PR #1自身の唯一のcommit、author date `2026-07-12T16:14:49Z`）はPR #1のfeature branch側からmergeで取り込まれたものであり、direct pushではない（`git log --first-parent`で確認、mainの第一親chainには現れない）。これを除いた149件が正しいdirect push集合であり、`git rev-list --count`で149件であることを直接確認した。merge commit（`Merge feature/ticketN-...`）が存在する範囲はそれで区切り、ticket番号制導入以前の範囲はcommit messageのテーマでグルーピングした。全149 commitsは以下21グループのいずれか一つに過不足なく属する（PRE-02が80件の定型`digest: YYYY-MM-DD HH:MM`commitをまとめて含む。定型digest commitは合計83件存在するが、うち3件はPRE-09／PRE-15／PRE-20の各グループに個別のticket commitと同時に発生したものとしてそれぞれのグループへ含めて数えた）。

| Group | 日付範囲 | 対象commit数 | 内容（実装証跡） | 現行BL/SD | 分類 |
|---|---|---|---|---|---|
| PRE-00 | 2026-05-27 | 4 | リポジトリ初期作成、初回GitHub Actions workflow | なし | Out of scope / No action |
| PRE-01 | 2026-05-27 | 1 | trend/policy focused sourcesへの切替（refactor） | なし | Superseded（Ticket 2の`source_definitions.json`により置換） |
| PRE-02 | 2026-06-06〜2026-07-12 | 80 | 定型`digest: ...`commit（本番生成出力） | STATUS.md §3の現行生成機構が相当 | Out of scope / No action |
| PRE-03 | 2026-06-07〜2026-06-08 | 2 | 壊れたNVD feedの無効化、Talos/Cloudflare feed追加（ticket番号制以前のad hoc変更） | [BL-011](BACKLOG.md#bl-011--standalone-nist-nvd記事取得の保留理由再開条件)の前史 | Superseded（`source_definitions.json`とSD-003により置換） |
| PRE-04 | 2026-06-08〜2026-06-10 | 10 | Gemini AI分析の初導入（v1）、モデル選定、rate/attempt制限、構造化出力化 | [SD-001](DECISIONS.md#sd-001--keep-article-and-brief-as-separate-prompt-contracts) | Superseded（`ARTICLE_PROMPT_VERSION` v2〜v8により反復的に置換） |
| PRE-05 | 2026-07-07 | 5 | cyber関連性filter（信頼ソース bypass付き）、初期executive summary、source毎の件数制限、rate/timezone修正 | `TRUSTED_CYBER_SOURCES`（`fetch.py`に現存） | Out of scope / No action |
| PRE-06 | 2026-07-09 | 3 | Gemini認証headerの試行錯誤（Bearer→`x-goog-api-key`）、rate limit sleep延長 | なし | Out of scope / No action（解決済み運用修正） |
| PRE-07 | 2026-07-10 | 3 | Ticket 1: HTML escapeとsafe URL検証の導入 | `AGENTS.md`「Security requirements」節 | Out of scope / No action（現行`esc()`／`safe_url()`として存続） |
| PRE-08 | 2026-07-10〜2026-07-11 | 5 | Ticket 2: `source_definitions.json`をsource正本として導入 | `README.md`／SD-003 | Out of scope / No action |
| PRE-09 | 2026-07-11 | 4 | Ticket 3: daily JSON schemaと保存（`daily_json.py`新設） | [SD-014](DECISIONS.md#sd-014--keep-daily-json-outside-the-github-pages-publication-tree-and-limit-stored-content)（commit `1c65be6`を直接引用） | Out of scope / No action |
| PRE-10 | 2026-07-11 | 3 | Ticket 4: ARTICLE分析へcategory/urgency/tags/reasonを拡張 | 現行ARTICLE schemaの基礎、SD-004／SD-009 | Out of scope / No action |
| PRE-11 | 2026-07-11 | 3 | Ticket 5: 記事カード表示の初版（楕円バッジ layout） | [SD-012](DECISIONS.md#sd-012--dashboard-v2-priority-index-and-the-article-reason-no-imperative-contract)／[SD-013](DECISIONS.md#sd-013--ordinary-article-card-variant-b-remove-classification-label-badges-keep-関連タグ-round) | Superseded（詳細は本ファイル「Ticket 5 / Ticket 7 / Ticket 11b」参照） |
| PRE-12 | 2026-07-11 | 3 | Ticket 6: 「重要項目」セクション初版、URL重複記事のdedup修正 | SD-012／SD-013（`select_important_items()`は不変と明記） | Out of scope / No action（優先確認へ改称・再設計済みだが選定ロジックは継続） |
| PRE-13 | 2026-07-11 | 2 | Ticket 7: dashboardセクション初版（3カード構成） | SD-012（`Supersedes`に明記） | Superseded（詳細は本ファイル「Ticket 5 / Ticket 7 / Ticket 11b」参照） |
| PRE-14 | 2026-07-11 | 3 | Ticket 8: Today's Brief初版（4要素）、BRIEF入力のuntrusted境界導入 | SD-001／SD-009の起点、`today-brief-v3`へ発展 | Out of scope / No action |
| PRE-15 | 2026-07-11 | 4 | Ticket 9: 内部日付別archive初版 | [取得時証跡と内部日付別アーカイブ](BACKLOG.md#取得時証跡と内部日付別アーカイブ)（第1バッチCompleted reference） | Out of scope / No action |
| PRE-16 | 2026-07-11 | 2 | Ticket 10: 全記事の表示順序定義 | なし | Out of scope / No action |
| PRE-17 | 2026-07-11 | 3 | Ticket 11a: importance/urgencyの分離 | `AGENTS.md`「ARTICLE status, fallback, and validation」節 | Out of scope / No action |
| PRE-18 | 2026-07-11〜2026-07-12 | 4 | Ticket 11b: 記事表示整理、anchor調整、reasonラベル調整 | SD-012（用語統一の前史） | Superseded（詳細は本ファイル「Ticket 5 / Ticket 7 / Ticket 11b」参照） |
| PRE-19 | 2026-07-12 | 2 | Ticket 12a: vulnerability facts基盤（`vulnerability_facts.py`の起点） | `AGENTS.md`architecture節 | Out of scope / No action |
| PRE-20 | 2026-07-12 | 3 | Ticket 12b: 記事カードへのCVE/CVSS/KEV表示初版 | PR #17／PR #18で「Non-changed scope」と明記 | Out of scope / No action |

要約: 21グループすべてが、既存のSD-001／SD-003／SD-004／SD-009／SD-012／SD-013／SD-014、または現行実装により説明可能であり、本バッチから新規BL候補は生じなかった。PRE-11／PRE-13／PRE-18（Ticket 5/7/11b）のみ、下記の通りSuperseded referenceとして個別に記録する。

### Audit B–E — BL-005／BL-008／BL-009／BL-010（GitHub側証跡の再監査）

いずれも`git log --all -i --grep`によるキーワード検索、および全19件のPR本文・コメントの全文検索を実施した。

- **BL-005（editorial-style-v1とtoday-brief-v4）:** 「editorial-style」「today-brief-v4」「Gist」の文字列は、[BL-005](BACKLOG.md#bl-005--editorial-style-v1とtoday-brief-v4)自身と[SD-007](DECISIONS.md#sd-007--create-security-digest-editorial-style-v1-and-introduce-it-to-brief-first)自身を除き、リポジトリ内のいかなるPR本文・コメント・commit messageにも存在しない。BL-005とSD-007は同一PR（[PR #13](https://github.com/matkei31/security-digest/pull/13)、「README・AGENTSを更新しSTATUS・DECISIONSを追加」、merge commit `0fcdf88e175c25ab1e877bb78e0a25de5b29b5ec`、2026-07-16T13:36:20Z）で同時に導入された。PR #13自身の本文は既存文書の再構成を目的とすると述べており、SD-007の内容の出典となる個別のユーザー発言を引用・参照していない。SD-007の`Evidence`欄自身も、本バッチ実施前時点で「文書同期時に記録された判断」であることを認めていた（本バッチでこの欄を補強した — [DECISIONS.md](DECISIONS.md)のSD-007参照）。結論として、SD-007がGitHub上で単独に遡れる証跡はPR #13の文書同期イベントのみであり、これより前に独立して存在した提案・同意の記録はGitHub上に見つからなかった。**原文は回収できていない。**
- **BL-005の会話側記録に関する確認事項:** conversation-side recordでは、外部Gistの全面コピーを避けること、Geminiを本番生成に維持すること、style rulesの埋込み／参照方法を検討したことが確認されている。これはBL-005の既存`Interpretation`欄（「Do not copy an external Gist in full」「Gemini remains the production BRIEF generator」）と整合し、これらを否定する証跡は見つからなかった。ただし、この確認は原文の引用ではなく、既存記録の内容が会話側記録と矛盾しないことの確認にとどまる。新しい原文はここでも作成しない。
- **BL-008（Fable 5による全体コードレビュー）:** 「codebase」「全体レビュー」「whole codebase」等のキーワード検索は0件。既知の2件のFable 5レビュー（[PR #10](https://github.com/matkei31/security-digest/pull/10): feed-rich-content機能単位のレビュー、PR #17/#18: dashboard/記事カードのUIレビュー）はいずれも全体コードレビューではなく、機能単位またはUI単位のレビューであることを再確認した。両者を混同する記録は見つからなかった。**原文は回収できていない。** 現行`BACKLOG.md`の記録（`Captured`）を維持する。
- **BL-009（SEOと閲覧者増加策）:** 「SEO」「閲覧者」「readership」検索は、[PR #16](https://github.com/matkei31/security-digest/pull/16)本文の1件のみヒットした。この記載はPR #16自身が「Ticket 14a-3／14a-4は完了済みであり、SEOの未完了前提へ戻していない」ことを確認する検証コメントであり、SEOそのものに関する新しいユーザー発言ではない。**原文は回収できていない。** 依存条件（Ticket 14a-3/14a-4完了、BL-006/BL-007/BL-005/BL-002-004、About/metadata/public navigation）を2026-07-18時点で再確認したところ、Ticket 14a-3/14a-4は完了済み、BL-002/BL-003は完了済みだが、BL-004〜BL-007は未完了のままであり、SEO実装の前提はまだ揃っていない。SEO実装・最新のSEO調査は本バッチでは一切行っていない。
- **BL-010（多言語対応の意義判断）:** 「多言語」「multilingual」「translat」検索は0件（`translate()`/`translate_cache`は既存の非公式タイトル翻訳機能であり、サイトの多言語対応とは無関係）。「decision exerciseであり実装ticketではない」という現行の枠組みを変更する根拠は見つからなかった。**原文は回収できていない。** 現行`BACKLOG.md`の記録（`Captured / Parked until prerequisites`）を維持する。

いずれの項目についても、本バッチはBACKLOG.mdの既存Status／Original user comment欄を変更せず維持を確認するにとどめ、新しい原文や新しい要約を作成しない。

### Audit F — Completed reference gaps（PR #1／#2／#3／#6／#8／#9）

`BACKLOG.md`の既存Completed referenceはTicket 14a-3、Ticket 14a-4、「取得時証跡と内部日付別アーカイブ」の3件のみであった。本バッチで以下を確認した。

| PR | Ticket | Merge commit | 対応 |
|---|---|---|---|
| #1 | Ticket 12c | `8f6c5dfdcfc2113cba410a7059d230026d6d1a7a` | `BACKLOG.md`のCompleted referenceへ追加した |
| #2 | Ticket 13c | `a8b551818443f2ca9deb2df160fc661aab8faf77` | `BACKLOG.md`のCompleted referenceへ追加した |
| #3 | Ticket 14a | `d90fa3986a541aafbdf76bc6e6b4d8f0130ed19c` | `BACKLOG.md`のCompleted referenceへ追加した（Ticket 14a-3/14a-4はこの修正の拡張であり、重複ではない） |
| #4 | Ticket 14a-3 | `9ae5240b4e1b00e74f4b7af7a03e6d5769d53511` | 既存Completed reference entryのため対応不要 |
| #6 | Ticket 15a | `4daab96b6e78a3fcf9bfb30c1d3dc0a2d7c424c3` | 本ファイル「Ticket 15a / PR #6」節にHistorical / Superseded referenceとして記録（Completed referenceへは追加していない） |
| #8 | ARTICLE内部識別子漏洩の修正 | `d1518910cd1a685cffc5d526ec65f6e708a4d535` | `BACKLOG.md`のCompleted referenceへ追加し、一般化した境界ルールを[SD-015](DECISIONS.md#sd-015--project-trusted-context-through-an-explicit-allowlist-and-do-not-expose-internal-identifiers)として記録した |
| #9 | Ticket 15c | `82b23c720b5871c5f46d068813defc12af164e4a` | Completed referenceへは追加せず、[BL-016](BACKLOG.md#bl-016--本日の要点の表示階層を目視受入する)として記録した（PR本文が「本番受入は未実施です」と明記しており、後続の明示的なユーザー受入記録がGitHub上に見つからなかったため） |

各PRのCompleted scope、現行実装への残存範囲、後続変更による置換範囲、reopen ruleは`BACKLOG.md`の各entryに記録した（本ファイルでは重複記載しない）。

### PR #8の内部識別子漏洩とSD-015

[PR #8](https://github.com/matkei31/security-digest/pull/8)（merge commit `d1518910cd1a685cffc5d526ec65f6e708a4d535`）は、実際の本番実行2件（run ID `29367843566`、`29374504304`）に対して再現された、確認済みの本番データ露出インシデントである。内部キー`recent_kev_additions`がARTICLE分析の`analysis.reason`、daily JSON、トップページ、当日archiveへ露出した。raw Gemini responseは保存されておらず直接確認はできないが、原因は入力契約（verified contextへ内部キー名をそのまま格納したこと）にあることがPR本文から確認できる。この修正が確立した「trusted contextを専用builder経由のexplicit allowlistで構築し、内部識別子やraw response dataを利用者向け出力へ露出させない」という一般原則を、[SD-015](DECISIONS.md#sd-015--project-trusted-context-through-an-explicit-allowlist-and-do-not-expose-internal-identifiers)として新規記録した。ユーザー受入を推測して追加してはおらず、実装済みの恒久的な設計判断として記録している。

### Ticket 15a / PR #6 — Historical / Superseded reference

- [PR #6](https://github.com/matkei31/security-digest/pull/6)（Ticket 15a: ARTICLE v4→v5、merge commit `4daab96b6e78a3fcf9bfb30c1d3dc0a2d7c424c3`）はmerge済みである。
- PR本文は末尾で「本番実行後に生成品質（title_ja の自然さ・reason 2文遵守・recent KEV に基づく本日確認判定・kev_date_added 非流出）を目視確認すること」と明記しているが、この目視確認が実施されたことを示すGitHub上の明示的な受入証跡は見つからなかった。
- ARTICLE promptはこのv5から後続のv6（PR #8）・v7（PR #12、Ticket 17a）・v8（SD-012）へ置換されている。v5契約自体を今から遡って受入確認することは、本バッチでは行わない。
- **Classification:** `Superseded / No current action`。新規BLは作らない。現行v8で新しい問題が確認された場合のみ、現行契約を対象に別途再評価する。

### Ticket 5 / Ticket 7 / Ticket 11b — Historical / Superseded reference

- **Ticket 5**（PRE-11、記事カードの初版badge実装）: 現行のordinary article-card badge実装は、[SD-013](DECISIONS.md#sd-013--ordinary-article-card-variant-b-remove-classification-label-badges-keep-関連タグ-round)（[PR #18](https://github.com/matkei31/security-digest/pull/18)）で置換済み。SD-012/SD-013の`Supersedes`欄は置換された挙動（楕円バッジ）を明記しているが、「Ticket 5」という名称そのものは明示的に引用していない — 記述の正確性に問題はなく、名称参照は任意の可読性向上に過ぎない。`Superseded`。新規BLなし。
- **Ticket 7**（PRE-13、dashboard旧実装、3カード構成）: [SD-012](DECISIONS.md#sd-012--dashboard-v2-priority-index-and-the-article-reason-no-imperative-contract)の`Supersedes`欄が「The 3-card dashboard layout and the 確認優先度 display label」として明示的にsupersede済み。`Superseded`。追加BLなし。
- **Ticket 11b**（PRE-18、anchor/reasonラベル実装）: anchor機構自体はSD-012が`:target`ハイライトを追加する形で発展的に継続しているが、「確認優先度」ラベル等の表示仕様はSD-012の用語統一（重要度／確認目安）により機能的に置換された。後続SD-012のshared numbering／anchor／label契約へ統合・置換されたと判断する。`Superseded reference`。新規BLなし。

いずれも、元Ticketの範囲と後続変更の範囲を混同せず、それぞれ個別に記録した。

### 実装証跡とユーザー受入証跡の区別（本バッチ全体の適用結果）

本バッチで検討した全項目について、PRのmerge自体は実装証跡としてのみ扱い、ユーザー受入証跡としては扱わなかった。明示的なユーザー受入がGitHub上に見つからない項目（BL-016の対象となったTicket 15c、Ticket 15aの目視確認要求）は、実装済みであってもDoneや無条件Supersededとはせず、それぞれBL-016（受入待ち）またはSuperseded（契約自体の受入なしにv6以降へ置換済みという事実のみを記録し、v5自体を遡って受入確認しない）という区別された分類とした。

### 原文を回収できなかった事項（本バッチのGitHub側探索の結論）

- BL-005（editorial-style-v1/today-brief-v4）およびSD-007: GitHub上に原文なし。SD-007自身の内容の出典もPR #13の文書同期以前に遡れない。
- BL-008（Fable 5全体コードレビュー）: GitHub上に原文なし。
- BL-009（SEO）: GitHub上に原文なし（PR #16の言及はSEOに関する新しい発言ではなく、既存前提の検証コメント）。
- BL-010（多言語対応）: GitHub上に原文なし。

これらの原文回収は、会話側記録へのアクセスを要する範囲を除き、本バッチの役割（GitHub証跡限定）では完了できない。

### 残存する未解決事項（本バッチのUnresolved）

- SD-007の`Accepted`Statusは、それを記録したPR #13自身より前に遡れる独立した同意記録がGitHub上にない。本バッチはEvidence欄を補強してこの限界を明記したが、Status自体（`Accepted / Not implemented`）は変更していない。
- Ticket 15c（PR #9）の「本番受入は未実施です」という明記に対する、その後の明示的な受入確認はGitHub上に見つからなかった。これをBL-016として記録した。
- Ticket 15a（PR #6）が要求した本番実行後の目視品質確認について、実施を示す証跡はGitHub上に見つからなかった。ARTICLE promptがv6〜v8へ3回置換された後も回帰報告が見つからないことは間接的な傍証にとどまり、明示的な確認の代替にはならない。v5契約自体の遡及的な受入確認は本バッチのスコープ外とする。
- PR #11〜#16およびPR #19自身のcommit単位の履歴について、本バッチはpre-PR時代とAudit Fで指定された5件のPR（#1/#2/#3/#6/#9）を中心に監査しており、それ以外のCompleted reference／Superseded reference候補の網羅的な確認は行っていない。将来バッチの対象として残す。
- 「About content, metadata, public navigation」（BL-009の依存条件として言及）について、専用BL項目を新設すべきかは本バッチでは未検討（SEO/content scoping作業となるため対象外）。

## Remaining audit scope

（この節はBatch 2完了時点、2026-07-18のhistorical snapshotである。以下の各項目が「## Final completion」でどのように解消または既存BLへ移管されたかは、同節を参照。）

- BL-005／BL-008／BL-009／BL-010のconversation-side original wording回収（GitHub証跡は本バッチで探索を尽くしたが、会話側記録へのアクセスが必要）。
- SD-007の`Accepted`Statusの独立した同意記録についての、会話側記録に基づく確認。
- [BL-016](BACKLOG.md#bl-016--本日の要点の表示階層を目視受入する)の目視受入（PC／390px本番確認）。
- PR #11〜#16、PR #19自身のcommit単位の履歴に対する、Completed reference／Superseded reference候補の網羅的確認。
- 「About content, metadata, public navigation」への専用BL項目要否の検討。
- その他の未分類コメントの確認。
- 最終的なユーザーレビューと、未分類コメントが残っていないことの明記。

## Final completion — 2026-07-18

この節は[BL-014](BACKLOG.md#bl-014--過去ユーザーコメントの体系的棚卸し)を`Done`として完了させる最終記録である。上記「Remaining audit scope」のうち、BL-014自身の完了条件に関わる項目を本節が解消する。それ以外の項目（後述）は、BL-014とは独立した個別項目として引き続き扱う。

- **ユーザー受入:** BL-014全体の完了について、ユーザーによる明示的な承認（verbatim）が得られた。原文は[BACKLOG.md](BACKLOG.md#bl-014--過去ユーザーコメントの体系的棚卸し)のBL-014「User acceptance evidence」欄に記録済み。同一の引用を本ファイルへ重複して転記しない。
- **BL-009の原文回収:** 別々の原文2件が供給され、[BL-009](BACKLOG.md#bl-009--seoと閲覧者増加策)へ「Original user comment」「Additional original user comment」としてそれぞれ記録した。Source typeを`Recovered paraphrase (recorded user request)`から`Verbatim user comment`へ更新した。
- **BL-010の原文回収:** 原文1件が供給され、[BL-010](BACKLOG.md#bl-010--多言語対応の意義判断)へ「Original user comment」として記録した。Source typeを同様に更新した。
- **BL-005・BL-008の原文:** `Original wording not recovered`のまま確定した。これはBL-014の最終的な受入状態として記録するものであり、将来バッチへ持ち越す未解決事項ではない。仮に今後いずれかの原文が判明した場合は、[初期移行範囲](BACKLOG.md#初期移行範囲)の原則（原文と出所を添えて追記する）に従って個別に追記するが、それはBL-014自体の完了条件ではない。
- **未分類コメント:** 本完了時点で、関係者が把握している未分類の過去コメントはない。これは現時点で把握している範囲についての記録であり、将来的に別の過去コメントが判明しないことを保証するものではない。判明した場合は[初期移行範囲](BACKLOG.md#初期移行範囲)の原則どおり、この完了記録への違反としてではなく、原文と出所を添えた追記として扱う。
- **BL-014の完了と独立して継続する項目:** [BL-001](BACKLOG.md#bl-001--プルリクエストci)、[BL-004](BACKLOG.md#bl-004--fable-5によるuiレビューとui設計書)、[BL-006](BACKLOG.md#bl-006--monomi-digestへのブランド変更)、[BL-007](BACKLOG.md#bl-007--monomidigestcomへの移行)、[BL-015](BACKLOG.md#bl-015--公開サイトと生成基盤のセキュリティ要件を定義する)、[BL-016](BACKLOG.md#bl-016--本日の要点の表示階層を目視受入する)は、それぞれの内容に基づき引き続きopenのままである。BL-014の`Done`は過去ユーザーコメントの体系的棚卸しという工程自体の完了を意味し、これら個別項目の完了・受入・変更を意味しない。
- **SD-007の`Accepted`Status:** project conversation recordを根拠として維持する。原文はGitHub上で回収できていないが、これはBL-014の残作業ではない。[SD-007](DECISIONS.md#sd-007--create-security-digest-editorial-style-v1-and-introduce-it-to-brief-first)自体のStatus・Decision本文は本パスで変更しない。
- **BL-016の目視受入:** 独立した[BL-016](BACKLOG.md#bl-016--本日の要点の表示階層を目視受入する)へ既に移管済みであり、BL-014の残作業ではない。
- **PR #11〜#16／PR #19:** 本最終完了パスで確認済み。新規BL、Completed reference、Superseded referenceの追加は不要と判断した。
- **About content／metadata／public navigation:** 専用BL項目を新設する必要はない。[BL-006](BACKLOG.md#bl-006--monomi-digestへのブランド変更)／[BL-007](BACKLOG.md#bl-007--monomidigestcomへの移行)／[BL-009](BACKLOG.md#bl-009--seoと閲覧者増加策)の依存・残作業の範囲で扱う。
- **上記「Remaining audit scope」との関係:** 同リストの全項目は、本節により解消済み、または既存BL（[BL-016](BACKLOG.md#bl-016--本日の要点の表示階層を目視受入する)等）へ移管済みである。BL-014自体に残作業はない。
