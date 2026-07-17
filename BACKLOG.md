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
- **Status:** Specified / In progress
- **Source type:** Verbatim user comment
- **Original user comment:** 「楕円が並んでる見た目が気に入らないみたいなことを言った気がするんだよね。」
- **User-confirmed summary:** 出元別の色分けや、楕円形のバッジが横に並ぶ見た目は要らない。全体として再設計したい。
- **Interpretation:** Existing badge colors and corner radii are not the full issue. Redesign the article-card information hierarchy and the label representation itself.
- **Acceptance criteria:** Not defined. Define after Fable 5 review and explicit user confirmation.
- **Dependencies:** BL-004; coordinate with BL-003.
- **Implementation evidence:** Partially implemented. The dashboard was redesigned from three heavy badge-like cards into a single lightweight block, and the new 優先確認 (priority index) section shows 重要度/確認目安 as plain text rather than ellipse badges (see the “feat: dashboard v2 + priority index + reason contract” ticket). A follow-on ticket (branch `feature/article-card-variant-b`) further removes the ordinary article-card source-color pill, `.importance-badge`, `.urgency-badge`, and `.category-badge` entirely: source and publish date render as a plain-text meta line, 重要度/確認目安 render as plain text with a light text-color/left-border accent limited to 高/本日確認 (no ellipse shape), and category is no longer displayed on the ordinary card at all (its daily-JSON storage, response schema, validation, and dashboard aggregation are unchanged). Per the user's explicit B案 choice, `.article-tag` (関連タグ) is the one label kept in its rounded pill form, relocated to a footer at the bottom of the card, and is intentionally not part of this item's remaining scope.
- **User acceptance evidence:** Dashboard v2 and the 優先確認 reasoned index: accepted by the user in the project conversation on 2026-07-17. Article-card B案 direction (source/importance/urgency/category badges removed, only 関連タグ kept round and non-clickable, no category on the card, no search features this round): explicitly approved by the user in the project conversation on 2026-07-17, based on a reviewed two-variant mock. Visual acceptance of this ticket's actual implementation (PC/390px screenshots) is pending and not yet recorded.
- **Residual scope:** Visual/user acceptance of the B案 implementation itself. If a future ticket introduces tag search or a tag landing page, the current non-clickable 関連タグ treatment should be re-evaluated at that time (not before).
- **Notes:** Do not mark this item `Done` until the user has visually reviewed and accepted the B案 implementation (PC and 390px) — direction approval of the mock is not the same as implementation acceptance.

## BL-003 — AIで機械処理された印象を弱める

- **ID:** BL-003
- **Title:** AIで機械処理された印象を弱める
- **Priority:** P1
- **Status:** Specified / In progress
- **Source type:** User-confirmed summary
- **Original user comment:** Original wording not recovered.
- **User-confirmed summary:** AIで機械処理された印象を弱める。
- **Interpretation:** Do not conceal machine processing. Reduce unnecessary “AI-processed” appearance caused by repeated badge shapes, dense classification metadata, and overly uniform article cards.
- **Acceptance criteria:** Not defined. Requires design criteria and explicit user acceptance.
- **Dependencies:** BL-002 and BL-004.
- **Implementation evidence:** Partially implemented. The dashboard's dense, repeated 3-card structure was replaced by one lightweight block with a clearer information hierarchy (重要度/確認目安 as primary axes, category as a visually de-emphasized supplementary row), and the 優先確認 section was reframed as a short reasoned index instead of a dense repeated recap of full article metadata. A follow-on ticket (branch `feature/article-card-variant-b`) additionally reworks ordinary article cards: source/importance/urgency/category no longer render as a row of same-shaped colored pills — source+date is plain text, 重要度/確認目安 is plain text with a light accent limited to 高/本日確認, and category is not shown. Only 関連タグ keeps a rounded, low-contrast pill treatment at the card's bottom, per the user's explicit B案 choice.
- **User acceptance evidence:** Dashboard v2 and the 優先確認 reasoned index: accepted by the user in the project conversation on 2026-07-17. Article-card B案 direction: explicitly approved by the user in the project conversation on 2026-07-17, based on a reviewed two-variant mock. Visual acceptance of this ticket's actual implementation is pending and not yet recorded.
- **Residual scope:** Visual/user acceptance of the B案 implementation itself. Whether 関連タグ's remaining round-pill treatment still reads as "machine-processed" after the rest of the card is quieted is a judgment for the user's visual review, not predetermined by this ticket.
- **Notes:** Related to BL-002 but must remain a separate user-quality requirement.

## BL-004 — Fable 5によるUIレビューとUI設計書

- **ID:** BL-004
- **Title:** Fable 5によるUIレビューとUI設計書
- **Priority:** P1
- **Status:** Captured
- **Source type:** Verbatim user comment / User-confirmed summary
- **Original user comment:** 「設計書は作成済みの理解で合ってる？」
- **User-confirmed summary:** Fable 5に現行画面をレビューさせ、名称・色・形・配置・重複・導線を検討したうえでUI仕様を作る。
- **Interpretation:** Produce a dedicated UI design specification for labels, article cards, and visual hierarchy; README, AGENTS, STATUS, and DECISIONS are not that specification.
- **Acceptance criteria:** Fable 5 reviews the current UI; the proposed specification covers name, color, shape, placement, duplication, navigation, and acceptance examples; the user explicitly approves the specification.
- **Dependencies:** Current-page review material; prerequisite for implementation of BL-002 and BL-003.
- **Implementation evidence:** Not implemented as a dedicated specification document. Fable 5 review of the current UI, including ordinary article cards, has been completed. A dashboard mock generated outside the repository was reviewed and explicitly approved by the user in the project conversation on 2026-07-17; that approval informed the dashboard v2 implementation, and the resulting terminology decision (重要度/確認目安, not 確認優先度) is recorded in [DECISIONS.md](DECISIONS.md). Separately, a two-variant (A/B) ordinary-article-card mock, generated outside the repository, was reviewed by the user, who explicitly chose variant B (round labels removed from source/importance/urgency/category; only 関連タグ kept round, non-clickable) over variant A (all classification labels removed) — that choice is recorded above under BL-002/BL-003 and implemented on branch `feature/article-card-variant-b`. Neither review produced a standalone, repo-resident UI design specification document (name/color/shape/placement/duplication/navigation contract with acceptance examples); both were mock review + explicit user decision, not a formal spec artifact.
- **User acceptance evidence:** Dashboard scope: accepted 2026-07-17. Article-card scope: the user has explicitly chosen a variant (B) for ordinary article cards in the project conversation on 2026-07-17; visual acceptance of the resulting implementation is separate and still pending.
- **Residual scope:** A dedicated, repo-resident UI design specification document (covering name/color/shape/placement/duplication/navigation/acceptance examples for both the dashboard and article cards) does not exist. User adjudication of any remaining Fable 5 proposals beyond the dashboard and article-card decisions already made is outstanding.
- **Notes:** Answered fact: README, AGENTS, STATUS, and DECISIONS exist, but a dedicated UI design document defining labels, article cards, and visual hierarchy has not been created. Fable 5 review itself is complete (including article cards); the user has since made concrete, explicit choices for both the dashboard (v2) and ordinary article cards (variant B) from reviewed mocks, without a formal specification document being authored.

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
- **Source type:** User-confirmed summary
- **Original user comment:** Original wording not recovered.
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
- **Status:** Captured / Not completed
- **Source type:** Verbatim user comment
- **Original user comment:** 「うん。他に未対応と見られる私のコメントある？同じように汎化してるなら私自身のコメントに立ち返って確認して。本来、指摘コメントを勝手に書き換えて対応済み扱いするのありえないから。ちゃんとバックログ管理して」
- **User-confirmed summary:** 過去のプロジェクト会話にある指摘・要望を原文へ立ち返って棚卸しし、実装済み、部分対応、未対応、受入待ち、Superseded、バックログ対象外のいずれかへ根拠付きで分類する。実装側が作った一般化表現で原コメントを置き換えない。
- **Interpretation:** PR #16のBL-001〜BL-013は初期登録であり、過去のユーザーコメントを網羅的に監査した結果ではない。会話履歴、PRコメント、既存文書、完了記録を照合して、取りこぼしと誤完了を確認する。
- **Acceptance criteria:** 棚卸し対象の会話範囲と期間を明示する。原文を取得できたコメントは原文のまま記録し、原文未回収は引用しない。各コメントを既存BL ID、新規BL ID、Done reference、Superseded、対象外のいずれかへ割り当てる。部分対応はresidual scopeを残す。完了判断にはPRだけでなく、必要に応じてユーザー受入を確認する。棚卸し結果をユーザーがレビューし、未分類コメントが残っていないかを明記する。
- **Dependencies:** プロジェクト会話履歴、GitHub PR／コメント、README／STATUS／DECISIONS／BACKLOG、実装証跡へのアクセス。
- **Implementation evidence:** PR #16は管理方式と初期項目を作成したが、過去コメントの体系的棚卸し自体は未実施。
- **User acceptance evidence:** バックログ管理方式の導入には同意済み。過去コメント棚卸しの完了受入は未実施。
- **Residual scope:** 棚卸し、分類、追加登録、完了状態の検証、ユーザーによる最終確認。
- **Notes:** BL-014がDoneになるまで、BL-001〜BL-013を「過去要望の完全な一覧」と表現しない。

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
