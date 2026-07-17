# Security Digest Backlog

`BACKLOG.md` is the canonical source for requirements and issues that are incomplete, partially addressed, or awaiting user acceptance. Current operating state belongs in [STATUS.md](STATUS.md); stable decisions belong in [DECISIONS.md](DECISIONS.md).

## Provenance types

- **Verbatim user comment:** Wording directly recoverable from the user. Preserve characters, endings, and ambiguity without correction.
- **User-confirmed summary:** A summary written by an implementation participant and explicitly affirmed by the user. Do not present it as verbatim wording.
- **Recovered paraphrase:** A meaning reconstructed from earlier records when the original wording is unavailable. Do not place it in quotation marks; state `Original wording not recovered`.
- **Engineering finding:** A test failure, warning, implementation limitation, or design finding not originating from a user comment.

## Status definitions

- **Captured:** Recorded but not yet fully specified.
- **Specified:** Acceptance scope is sufficiently defined for planning.
- **In progress:** Approved work has started.
- **Implemented:** Implementation exists but may still require acceptance.
- **Awaiting user acceptance:** Implementation or design awaits explicit user review.
- **Done:** Required implementation and acceptance are complete.
- **Parked:** Intentionally deferred.
- **Superseded:** Replaced by another recorded item without deleting the original record.

Statuses may be combined, for example `Implemented / Awaiting user acceptance`. Initial records also use these explicit qualifiers:

- **Accepted:** The direction or decision is accepted; this does not mean implementation is complete.
- **Not implemented:** No implementation satisfying the item exists yet.
- **Not completed:** The recorded work or audit has not been completed.
- **Parked until prerequisites:** Deferred until the recorded dependencies are satisfied.

## Completion rules

1. Do not put original wording and implementation interpretation in the same field.
2. Do not quote wording as a user statement when the original wording has not been recovered.
3. A merged implementation PR alone does not make a subjective UI or writing-quality item `Done`.
4. UI, writing quality, and brand expression require explicit user acceptance.
5. A partially addressed item must retain its residual scope and must not be marked `Done`.
6. When an item is split, merged, or marked `Superseded`, retain the original comment and old ID.
7. Reopening a completed item requires new evidence.
8. Do not replace a concrete comment with a broader generalization for implementation convenience.

## Initial migration scope

- BL-001 through BL-013 are the initial import into the canonical backlog.
- They are not the result of a complete audit of past user comments.
- BL-014 tracks the systematic migration audit and completeness review.
- If additional past comments are found, add them with their original wording and provenance. Their discovery reflects an incomplete migration audit, not an error in preserving the initial backlog.

## Open backlog

## BL-001 — Pull request CI

- **ID:** BL-001
- **Title:** Pull request CI
- **Priority:** P0
- **Status:** Specified / Not implemented
- **Source type:** Engineering finding
- **Original user comment:** Not applicable — engineering finding.
- **User-confirmed summary:** Not defined.
- **Interpretation:** Add ordinary `pull_request` CI that runs the full unittest suite and `git diff --check` for every PR without performing production work.
- **Acceptance criteria:** CI runs the full unittest suite and `git diff --check`; it does not call Gemini, receive secrets, generate or commit `data/` or `docs/`, or perform production publication.
- **Dependencies:** GitHub Actions workflow design and repository permissions review.
- **Implementation evidence:** Not implemented. [STATUS.md](STATUS.md) and [`.github/workflows/fetch.yml`](.github/workflows/fetch.yml) record that ordinary `pull_request` CI is absent.
- **User acceptance evidence:** Not applicable yet — no implementation exists.
- **Residual scope:** Workflow implementation, PR validation, and explicit merge acceptance.
- **Notes:** Existing local-test and independent-review evidence remains the fallback until this item is implemented.

## BL-002 — 記事カードの楕円バッジ多用を見直す

- **ID:** BL-002
- **Title:** 記事カードの楕円バッジ多用を見直す
- **Priority:** P1
- **Status:** Done
- **Source type:** Verbatim user comment
- **Original user comment:** 「楕円が並んでる見た目が気に入らないみたいなことを言った気がするんだよね。」
- **User-confirmed summary:** 出元別の色分けや、楕円形のバッジが横に並ぶ見た目は要らない。全体として再設計したい。
- **Interpretation:** Existing badge colors and corner radii are not the full issue. Redesign the article-card information hierarchy and the label representation itself.
- **Acceptance criteria:** Concretized for the now-decided B案 (2026-07-17): (1) 取得元/重要度/確認目安/カテゴリ do not use ellipse (rounded-pill) badges on the ordinary article card; (2) 取得元 and the publish date render as plain text; (3) 重要度 and 確認目安 render as plain text on separate, independently-labeled axes (not a shared undifferentiated badge row); (4) emphasis is limited to 重要度「高」and 確認目安「本日確認」only — no other value gets equivalent visual weight; (5) category is removed from the card's display, while its storage, response schema, validation, and dashboard aggregation are unchanged; (6) only 関連タグ keeps a rounded, low-contrast `<span>` treatment, placed at the bottom of the card; (7) 関連タグ stays non-clickable (no `<a>`/`button`/click handler/`role="button"`); (8) no article search or tag search feature is introduced by this ticket; (9) the user visually reviews and approves the actual PC and 390px implementation (not just the mock) before this item is marked `Done`.
- **Dependencies:** BL-004; coordinate with BL-003.
- **Implementation evidence:** Implemented. The dashboard was redesigned from three heavy badge-like cards into a single lightweight block, and the new 優先確認 (priority index) section shows 重要度/確認目安 as plain text rather than ellipse badges (see the “feat: dashboard v2 + priority index + reason contract” ticket). A follow-on ticket (branch `feature/article-card-variant-b`, [PR #18](https://github.com/matkei31/security-digest/pull/18)) further removes the ordinary article-card source-color pill, `.importance-badge`, `.urgency-badge`, and `.category-badge` entirely: source and publish date render as a plain-text meta line, 重要度/確認目安 render as plain text with a light text-color/left-border accent limited to 高/本日確認 (no ellipse shape), and category is no longer displayed on the ordinary card at all (its daily-JSON storage, response schema, validation, and dashboard aggregation are unchanged). Per the user's explicit B案 choice, `.article-tag` (関連タグ) is the one label kept in its rounded pill form, relocated to a footer at the bottom of the card.
- **User acceptance evidence:** Dashboard v2 and the 優先確認 reasoned index: accepted by the user in the project conversation on 2026-07-17. Article-card B案 direction: explicitly approved by the user in the project conversation on 2026-07-17, based on a reviewed two-variant mock. The actual PC/390px implementation (screenshots reviewed by the user outside the repository) was visually accepted by the user on 2026-07-17, verbatim: 「見られたけど、いいと思うよ」.
- **Residual scope:** None.
- **Notes:** If a future ticket introduces tag search or a tag landing page, the current non-clickable 関連タグ treatment should be re-evaluated at that time (not before).

## BL-003 — AIで機械処理された印象を弱める

- **ID:** BL-003
- **Title:** AIで機械処理された印象を弱める
- **Priority:** P1
- **Status:** Done
- **Source type:** User-confirmed summary
- **Original user comment:** Original wording not recovered.
- **User-confirmed summary:** AIで機械処理された印象を弱める。
- **Interpretation:** Do not conceal machine processing. Reduce unnecessary “AI-processed” appearance caused by repeated badge shapes, dense classification metadata, and overly uniform article cards.
- **Acceptance criteria:** Concretized for the now-decided B案 (2026-07-17): (1) 取得元/重要度/確認目安/カテゴリ no longer render as a row of same-shaped, same-treatment classification labels; (2) the article title and body content are what the reader's eye reaches before the classification metadata, not after competing with it; (3) only 関連タグ remains as rounded, low-contrast supplementary information at the bottom of the card — it is not restyled to compete with the title/body for attention; (4) the user visually reviews the actual PC and 390px implementation and confirms the "AI-processed" impression has been sufficiently reduced before this item is marked `Done`.
- **Dependencies:** BL-002 and BL-004.
- **Implementation evidence:** Implemented. The dashboard's dense, repeated 3-card structure was replaced by one lightweight block with a clearer information hierarchy (重要度/確認目安 as primary axes, category as a visually de-emphasized supplementary row), and the 優先確認 section was reframed as a short reasoned index instead of a dense repeated recap of full article metadata. A follow-on ticket (branch `feature/article-card-variant-b`, [PR #18](https://github.com/matkei31/security-digest/pull/18)) additionally reworks ordinary article cards: source/importance/urgency/category no longer render as a row of same-shaped colored pills — source+date is plain text, 重要度/確認目安 is plain text with a light accent limited to 高/本日確認, and category is not shown. Only 関連タグ keeps a rounded, low-contrast pill treatment at the card's bottom, per the user's explicit B案 choice.
- **User acceptance evidence:** Dashboard v2 and the 優先確認 reasoned index: accepted by the user in the project conversation on 2026-07-17. Article-card B案 direction: explicitly approved by the user in the project conversation on 2026-07-17, based on a reviewed two-variant mock. The actual PC/390px implementation (screenshots reviewed by the user outside the repository) was visually accepted by the user on 2026-07-17, verbatim: 「見られたけど、いいと思うよ」.
- **Residual scope:** None.
- **Notes:** Related to BL-002 but was a separate user-quality requirement; the same 2026-07-17 implementation and acceptance satisfy both independently.

## BL-004 — Fable 5によるUIレビューとUI設計書

- **ID:** BL-004
- **Title:** Fable 5によるUIレビューとUI設計書
- **Priority:** P1
- **Status:** Specified / In progress
- **Source type:** Verbatim user comment / User-confirmed summary
- **Original user comment:** 「設計書は作成済みの理解で合ってる？」
- **User-confirmed summary:** Fable 5に現行画面をレビューさせ、名称・色・形・配置・重複・導線を検討したうえでUI仕様を作る。
- **Interpretation:** Produce a dedicated UI design specification for labels, article cards, and visual hierarchy; README, AGENTS, STATUS, and DECISIONS are not that specification.
- **Acceptance criteria:** Fable 5 reviews the current UI; the proposed specification covers name, color, shape, placement, duplication, navigation, and acceptance examples; the user explicitly approves the specification.
- **Dependencies:** Current-page review material; prerequisite for implementation of BL-002 and BL-003.
- **Implementation evidence:** Not implemented as a dedicated specification document. Fable 5 review of the current UI, including ordinary article cards, has been completed. A dashboard mock generated outside the repository was reviewed and explicitly approved by the user in the project conversation on 2026-07-17; that approval informed the dashboard v2 implementation, and the resulting terminology decision (重要度/確認目安, not 確認優先度) is recorded in [DECISIONS.md](DECISIONS.md). Separately, a two-variant (A/B) ordinary-article-card mock, generated outside the repository, was reviewed by the user, who explicitly chose variant B (round labels removed from source/importance/urgency/category; only 関連タグ kept round, non-clickable) over variant A (all classification labels removed) — that choice is recorded above under BL-002/BL-003 and implemented on branch `feature/article-card-variant-b`. Neither review produced a standalone, repo-resident UI design specification document (name/color/shape/placement/duplication/navigation contract with acceptance examples); both were mock review + explicit user decision, not a formal spec artifact.
- **User acceptance evidence:** Dashboard scope: accepted 2026-07-17. Article-card scope: the user explicitly chose a variant (B) for ordinary article cards in the project conversation on 2026-07-17, and separately visually accepted the resulting PC/390px implementation on 2026-07-17 (verbatim: 「見られたけど、いいと思うよ」; see [BL-002](#bl-002--記事カードの楕円バッジ多用を見直す)/[BL-003](#bl-003--aiで機械処理された印象を弱める)). This satisfies BL-004's acceptance criteria for the dashboard and article-card *decisions* themselves; it does not substitute for the still-missing dedicated specification document (see Residual scope).
- **Residual scope:** A dedicated, repo-resident UI design specification document (covering name/color/shape/placement/duplication/navigation/acceptance examples for both the dashboard and article cards) does not exist. User adjudication of any remaining Fable 5 proposals beyond the dashboard and article-card decisions already made is outstanding.
- **Notes:** Answered fact: README, AGENTS, STATUS, and DECISIONS exist, but a dedicated UI design document defining labels, article cards, and visual hierarchy has not been created. Fable 5 review itself is complete (including article cards); the user has since made concrete, explicit choices for both the dashboard (v2) and ordinary article cards (variant B) from reviewed mocks, without a formal specification document being authored. Status moved from `Captured` to `Specified / In progress` to reflect this concrete review-and-decision activity — it is not `Done`, since no repo-resident specification document exists yet.

## BL-005 — editorial-style-v1とtoday-brief-v4

- **ID:** BL-005
- **Title:** editorial-style-v1とtoday-brief-v4
- **Priority:** P1
- **Status:** Specified / Not implemented
- **Source type:** User-confirmed summary (project decision)
- **Original user comment:** Original wording not recovered.
- **User-confirmed summary:** Security Digest独自の`editorial-style-v1`を作り、最初はBRIEFへ部分導入し、`today-brief-v4`でGemini promptへ本文を埋め込む。ARTICLEへは初期適用しない。
- **Interpretation:** Use Fable 5 for design and comparative evaluation while retaining Gemini for production BRIEF generation. Do not copy an external Gist in full.
- **Acceptance criteria:** Not fully defined. Must preserve deterministic BRIEF state/count logic, trusted-context boundaries, ARTICLE separation, and schema unless separately approved.
- **Dependencies:** [SD-007](DECISIONS.md#sd-007--create-security-digest-editorial-style-v1-and-introduce-it-to-brief-first); Fable 5 design review.
- **Implementation evidence:** Not implemented. The accepted direction is recorded in SD-007.
- **User acceptance evidence:** Direction accepted; implementation acceptance not applicable until an implementation exists.
- **Residual scope:** Editorial rules, prompt-size assessment, version update, fixtures, tests, comparative review, and production acceptance.
- **Notes:** Gemini remains the production BRIEF generator. ARTICLE is outside the initial scope.

## BL-006 — Monomi Digestへのブランド変更

- **ID:** BL-006
- **Title:** Monomi Digestへのブランド変更
- **Priority:** P2
- **Status:** Accepted / Not implemented
- **Source type:** User-confirmed summary
- **Original user comment:** Original wording not recovered.
- **User-confirmed summary:** 将来のサービス名は`Monomi Digest`とする。`Security Digest`と`Monomi Digest`のどちらにするかという未決定事項へ戻さない。
- **Interpretation:** The decided future brand name is `Monomi Digest`. Do not reopen “Security Digest or Monomi Digest” as an undecided naming choice.
- **Acceptance criteria:** Not defined. Implementation scope, migration timing, and treatment of the old name remain unspecified.
- **Dependencies:** [SD-010](DECISIONS.md#sd-010--use-monomi-digest-as-the-future-public-brand), BL-007; About, SEO, public navigation, repository and publication naming decisions.
- **Implementation evidence:** Not implemented. Current product and repository display remain `Security Digest`.
- **User acceptance evidence:** Direction reconfirmed in the project conversation on 2026-07-17. Implementation acceptance is not recorded.
- **Residual scope:** Inventory all brand surfaces, define migration and compatibility, implement, and obtain user acceptance.
- **Notes:** This backlog introduction must not change the current displayed brand.

## BL-007 — monomidigest.comへの移行

- **ID:** BL-007
- **Title:** monomidigest.comへの移行
- **Priority:** P2
- **Status:** Accepted / Not implemented
- **Source type:** Verbatim user comment / User-confirmed summary
- **Original user comment:** 「URLがgithubのユーザー名なのが気になる」
- **Provenance:** 2026-07-09 project conversation.
- **User-confirmed summary:** 主ドメインは`monomidigest.com`とし、`monomi.jp`は不要とする。
- **Interpretation:** Use `monomidigest.com` as the primary domain. The recorded decision says `monomi.jp` is unnecessary.
- **Acceptance criteria:** Not defined. Domain ownership and DNS state must be verified before implementation.
- **Dependencies:** [SD-011](DECISIONS.md#sd-011--use-monomidigestcom-as-the-primary-domain), BL-006, About content, SEO, canonical URLs, and public navigation.
- **Implementation evidence:** Not implemented. Domain acquisition and DNS configuration are not verified.
- **User acceptance evidence:** Direction reconfirmed in the project conversation on 2026-07-17. Domain acquisition, configuration, and implementation acceptance are not recorded.
- **Residual scope:** Verify ownership, define DNS/Pages configuration and redirects, update public metadata, test, and obtain user acceptance.
- **Notes:** Do not infer that the domain has been purchased or configured.

## BL-008 — Fable 5による全体コードレビュー

- **ID:** BL-008
- **Title:** Fable 5による全体コードレビュー
- **Priority:** P2
- **Status:** Captured
- **Source type:** Recovered paraphrase
- **Original user comment:** Original wording not recovered.
- **User-confirmed summary:** Not recovered.
- **Interpretation:** At an appropriate stable point, perform a critical whole-codebase review of structure, duplication, responsibilities, overimplementation, and maintainability.
- **Acceptance criteria:** Not defined.
- **Dependencies:** A sufficiently stable implementation baseline and an agreed review package.
- **Implementation evidence:** Not implemented.
- **User acceptance evidence:** Not recorded.
- **Residual scope:** Define timing, review questions, evidence package, evaluator role, and how findings become scoped tickets.
- **Notes:** Fable 5 is not being designated as the routine implementation agent by this item.

## BL-009 — SEOと閲覧者増加策

- **ID:** BL-009
- **Title:** SEOと閲覧者増加策
- **Priority:** P2
- **Status:** Captured / Parked until prerequisites
- **Source type:** Recovered paraphrase (recorded user request)
- **Original user comment:** Original wording not recovered.
- **User-confirmed summary:** Not recovered.
- **Interpretation:** Later, review SEO and ways to increase readership, and surface the topic when prerequisites make the timing appropriate.
- **Acceptance criteria:** Not defined.
- **Dependencies:** Ticket 14a-3 and Ticket 14a-4 are completed and are not prerequisites to reopen. At SEO start, confirm that no new P0/P1 data-quality issue is open. Also depends on BL-006, BL-007, the Japanese editorial specification, BL-002–BL-004, About content, metadata, and public navigation.
- **Implementation evidence:** Not implemented.
- **User acceptance evidence:** Not recorded.
- **Residual scope:** Define audience and goals, audit technical/content SEO, prioritize measures, implement separately, and measure outcomes.
- **Notes:** Parked until prerequisites; the recovered summary is not a verbatim quotation.

## BL-010 — 多言語対応の意義判断

- **ID:** BL-010
- **Title:** 多言語対応の意義判断
- **Priority:** P3
- **Status:** Captured / Parked until prerequisites
- **Source type:** Recovered paraphrase (recorded user request)
- **Original user comment:** Original wording not recovered.
- **User-confirmed summary:** Not recovered.
- **Interpretation:** After the Japanese edition is stable, decide whether multilingual support provides sufficient value relative to cost.
- **Acceptance criteria:** Not defined. This is initially a decision exercise, not an implementation ticket.
- **Dependencies:** Stable Japanese edition, BL-009, target-audience definition, and regulatory-mapping needs.
- **Implementation evidence:** Not implemented.
- **User acceptance evidence:** Not recorded.
- **Residual scope:** Define candidate languages, audience value, editorial/translation cost, regulatory impact, SEO impact, and decision criteria.
- **Notes:** Do not begin implementation before the prerequisite decision.

## BL-011 — standalone NIST NVD記事取得の保留理由・再開条件

- **ID:** BL-011
- **Title:** standalone NIST NVD記事取得の保留理由・再開条件
- **Priority:** P2
- **Status:** Captured
- **Source type:** Engineering finding
- **Original user comment:** Not applicable — engineering finding.
- **User-confirmed summary:** Not defined.
- **Interpretation:** Document why standalone NIST NVD article collection is disabled and define evidence-based reactivation conditions without conflating it with NVD vulnerability-facts acquisition.
- **Acceptance criteria:** The hold reason, owner, review trigger, reactivation conditions, and validation plan are recorded; the separate NVD facts path remains active and clearly distinguished.
- **Dependencies:** Source history and current `source_definitions.json` behavior.
- **Implementation evidence:** Not implemented. The gap is recorded in [STATUS.md](STATUS.md); NVD facts continue through a separate path.
- **User acceptance evidence:** Not applicable yet.
- **Residual scope:** Recover the original operational reason, specify reactivation criteria, and update the appropriate source/status records.
- **Notes:** This item does not request immediate source re-enablement.

## BL-012 — Gemini response error taxonomyの細分化

- **ID:** BL-012
- **Title:** Gemini response error taxonomyの細分化
- **Priority:** P2
- **Status:** Captured
- **Source type:** Engineering finding
- **Original user comment:** Not applicable — engineering finding.
- **User-confirmed summary:** Not defined.
- **Interpretation:** The current `schema_parse_error` classification does not sufficiently distinguish JSON decoding, response-schema mismatch, strict validation, and semantic/action-lint failures.
- **Acceptance criteria:** Not defined. Taxonomy, compatibility, observability benefit, cost, and migration behavior require specification.
- **Dependencies:** ARTICLE status/fallback contract and operational reporting requirements.
- **Implementation evidence:** Not implemented. Ticket 17a corrected one lint false positive but did not introduce a general error taxonomy.
- **User acceptance evidence:** Not applicable yet.
- **Residual scope:** Inventory failure paths, propose stable categories, assess schema/logging impact, define tests, and obtain approval.
- **Notes:** Do not reopen or reimplement Ticket 17a under this item.

## BL-013 — GitHub Actions Node.js警告

- **ID:** BL-013
- **Title:** GitHub Actions Node.js警告
- **Priority:** P3
- **Status:** Parked
- **Source type:** Engineering finding
- **Original user comment:** Not applicable — engineering finding.
- **User-confirmed summary:** Not defined.
- **Interpretation:** GitHub Pages build/deploy currently succeeds but emits a Node.js runtime deprecation warning from actions. Do not start speculative upgrades until the warning, supported versions, and deadline are verified.
- **Acceptance criteria:** Confirm the affected action versions, GitHub deadline, supported replacement path, and regression plan before changing workflows.
- **Dependencies:** Official GitHub Actions/Pages guidance and an approved workflow-maintenance scope.
- **Implementation evidence:** No remediation implemented. Recent Pages build and deployment completed successfully despite the warning.
- **User acceptance evidence:** Not applicable yet.
- **Residual scope:** Verify urgency, select supported action versions if needed, test build/deploy behavior, and obtain workflow-change approval.
- **Notes:** Parked because current builds succeed and no verified deadline is recorded here.

## BL-014 — 過去ユーザーコメントの体系的棚卸し

- **ID:** BL-014
- **Title:** 過去ユーザーコメントの体系的棚卸し
- **Priority:** P0
- **Status:** In progress / Not completed
- **Source type:** Verbatim user comment
- **Original user comment:** 「うん。他に未対応と見られる私のコメントある？同じように汎化してるなら私自身のコメントに立ち返って確認して。本来、指摘コメントを勝手に書き換えて対応済み扱いするのありえないから。ちゃんとバックログ管理して」
- **User-confirmed summary:** 過去のプロジェクト会話にある指摘・要望を原文へ立ち返って棚卸しし、実装済み、部分対応、未対応、受入待ち、Superseded、バックログ対象外のいずれかへ根拠付きで分類する。実装側が作った一般化表現で原コメントを置き換えない。
- **Interpretation:** PR #16のBL-001〜BL-013は初期登録であり、過去のユーザーコメントを網羅的に監査した結果ではない。会話履歴、PRコメント、既存文書、完了記録を照合して、取りこぼしと誤完了を確認する。
- **Acceptance criteria:** 棚卸し対象の会話範囲と期間を明示する。原文を取得できたコメントは原文のまま記録し、原文未回収は引用しない。各コメントを既存BL ID、新規BL ID、Done reference、Superseded、対象外のいずれかへ割り当てる。部分対応はresidual scopeを残す。完了判断にはPRだけでなく、必要に応じてユーザー受入を確認する。棚卸し結果をユーザーがレビューし、未分類コメントが残っていないかを明記する。
- **Dependencies:** プロジェクト会話履歴、GitHub PR／コメント、README／STATUS／DECISIONS／BACKLOG、実装証跡へのアクセス。
- **Implementation evidence:** PR #16は管理方式と初期項目を作成した。2026-07-17、第1バッチ（Candidate A〜F）の監査を実施し、A→BL-007更新、B→SD-014、C→BL-015、D→Completed reference、E→対応不要（新規BLなし）、F→BL-015スコープ内で評価対象として記録、へそれぞれ分類した。監査範囲・手法・各分類の根拠は[BACKLOG_AUDIT.md](BACKLOG_AUDIT.md)に記録。過去コメントの体系的棚卸しは第1バッチの範囲でのみ実施済みであり、全体としては未完了。
- **User acceptance evidence:** バックログ管理方式の導入には同意済み。第1バッチの分類記録自体は実施済みとするが、過去コメント棚卸し全体（残バッチを含む）の完了についてユーザーが明示的に承認した記録はない。
- **Residual scope:** BL-005／BL-008／BL-009／BL-010の原文回収、PR以前の会話・direct push履歴の棚卸し、その他未分類コメントの発見・分類、追加バッチの実施、最終的なユーザーレビューと、未分類コメントが残っていないことの明記。
- **Notes:** BL-014がDoneになるまで、BL-001〜BL-013を「過去要望の完全な一覧」と表現しない。第1バッチの実施はBL-014全体の完了を意味しない。

## BL-015 — 公開サイトと生成基盤のセキュリティ要件を定義する

- **ID:** BL-015
- **Title:** 公開サイトと生成基盤のセキュリティ要件を定義する
- **Priority:** P2
- **Status:** Captured / Not completed
- **Source type:** Verbatim user comment
- **Original user comment:** 「セキュリティ要件みたいなのも後で決めよう」
- **Additional original user comment:** 「OK.ここはfable5にもレビューしてもらおう。公開情報を扱うものだから厳しいセキュリティ対策をする必要はないと思うが、必要なものは網羅しつつ過剰じゃないように整理して、fable5にレビューさせられる形にして。」
- **User-confirmed summary:** Not recorded.
- **Interpretation:** For the static public site, GitHub Actions, external fetching, Gemini, stored data, secrets, and future custom-domain use, define a security requirements set proportionate to the current architecture, as a dedicated document (candidate name `SECURITY_REQUIREMENTS.md`, distinct from GitHub's vulnerability-reporting `SECURITY.md`). Do not uniformly introduce excessive controls; state necessity and reevaluation conditions for each item explicitly.
- **Acceptance criteria:** The document defines: target systems and data flow; the trusted/untrusted boundary; what may and may not be stored; external URL handling, HTML escaping, and `safe_url`; secrets management; GitHub Actions permissions; logs/artifacts handling; dependency and GitHub Actions supply-chain management (including an explicit necessity evaluation of full commit SHA pinning and of Dependabot for GitHub Actions); the current state of least privilege; reevaluation triggers for adopting a custom domain; reevaluation triggers for adding forms, authentication, a database, or persistent storage; a clear separation of current measures, identified gaps, and reasons for not adopting a given measure; a Fable 5 review pass; and final user approval. Full commit SHA pinning, Dependabot, and similar concrete measures are not decided as required at this stage — they become separate tickets only if the evaluation above approves a specific gap response.
- **Dependencies:** Current architecture; coordinate with [BL-001](#bl-001--pull-request-ci) (Pull request CI); coordinate with [BL-007](#bl-007--monomidigestcomへの移行) (monomidigest.comへの移行); existing security rules already recorded in `AGENTS.md` (「Security requirements」節) and in `DECISIONS.md`.
- **Implementation evidence:** Individual rules already exist (`AGENTS.md`: HTML escaping, `http`/`https`-only links, `rel="noopener noreferrer"`, no forms/auth/database/new external dependencies/persistent storage without approval, standard-library/existing-dependency-only policy, static GitHub Pages compatibility), but no comprehensive, dedicated requirements document exists. `.github/workflows/fetch.yml` currently references `actions/checkout@v4` and `actions/setup-python@v5` by version tag (not full commit SHA), and no `.github/dependabot.yml` exists — recorded here as an evaluation item (see BL014-F in [BACKLOG_AUDIT.md](BACKLOG_AUDIT.md)), not as a decided requirement.
- **User acceptance evidence:** Not recorded. Direction ("decide this later", "have Fable 5 review it") is captured from the original comments; no requirements draft has been reviewed or approved by the user yet.
- **Residual scope:** Requirements draft, evidence mapping, proportionality review, Fable 5 review, gap-ticket decision for any approved concrete measure, user acceptance.
- **Notes:** Do not decide SHA pinning, Dependabot, or other individual Actions supply-chain measures as required before this ticket's evaluation is complete. See [BACKLOG_AUDIT.md](BACKLOG_AUDIT.md) Batch 1 (BL014-C, BL014-F) for the audit trail that produced this item.

## Completed reference

These references exist only to prevent completed work from being accidentally reopened as unfinished backlog.

### Ticket 14a-3 — Atom date parsing and undated article filtering

- **Status:** Done
- **Evidence:** [PR #4](https://github.com/matkei31/security-digest/pull/4), merge commit `9ae5240b4e1b00e74f4b7af7a03e6d5769d53511`
- **Completed scope:** Fix-forward for fractional-second Atom date parsing, UTC comparison, published-before-updated selection, and filtering of missing or unparseable dates.
- **Reopen rule:** Do not return this completed ticket to open backlog without new evidence.

### Ticket 14a-4 — 2026-07-11〜13 stale history repair

- **Status:** Done
- **Evidence:** [PR #5](https://github.com/matkei31/security-digest/pull/5), merge commit `0e7a5d26dafaca6a8f7d65bb07144d5da31369c0`
- **Completed scope:** Repair of stale history for 2026-07-11 through 2026-07-13 after the Atom date fix.
- **Reopen rule:** Do not return this completed ticket to open backlog without new evidence.

### 取得時証跡と内部日付別アーカイブ

- **Status:** Done
- **Original wording:** Original wording not recovered.
- **Source type:** Recovered paraphrase / user-accepted approach
- **Evidence:** `daily_json.py` (`build_raw_excerpt()` — bounded to 200 characters from the fetched feed description, no article-page scraping; `compute_content_hash()` — SHA-256 of `canonical_url`+`raw_title`+`raw_excerpt`); `fetch.py` (`build_daily_archive_html()`, `generate_archive_outputs()` — internal date-based archive built from daily JSON); `test_daily_json.py`, `test_archive.py`; commit `1c65be67eaaa223d65ca1056313fb933d31f1ec4` ("feat: add daily JSON schema and storage (Ticket 3)"), commit `b51de673b3ea15347413d905f32d473e6f92712e` ("feat: add daily archive pages", Ticket 9, merged at `fbba0b8e57a68adafa0bcabe69a621a3f0c08e54`)
- **Completed scope:** Store, per article, `url`/`canonical_url`, `title`, `published_at`, `fetched_at`, a bounded `raw_excerpt`, and `content_hash` as minimal provenance against future link rot. Build an internal date-based archive (`docs/archive/YYYY-MM-DD.html`) from daily JSON. Do not store full article text or rich content (consistent with SD-002). Do not submit fetched URLs to an external archive service (no Wayback/archive.org integration exists in the codebase).
- **Reopen rule:** Do not return this completed scope to open backlog without new evidence. Reopen/reevaluate if any of the following is proposed: expanding the `raw_excerpt` length or source beyond the current bounded, description-based contract; storing full article text; storing rich content; automatically submitting fetched URLs to an external archive service; supporting private/authenticated feeds; or providing stored data to an external party.
