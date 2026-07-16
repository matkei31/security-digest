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
- **Status:** Captured
- **Source type:** Verbatim user comment
- **Original user comment:** 「楕円が並んでる見た目が気に入らないみたいなことを言った気がするんだよね。」
- **User-confirmed summary:** 出元別の色分けや、楕円形のバッジが横に並ぶ見た目は要らない。全体として再設計したい。
- **Interpretation:** Existing badge colors and corner radii are not the full issue. Redesign the article-card information hierarchy and the label representation itself.
- **Acceptance criteria:** Not defined. Define after Fable 5 review and explicit user confirmation.
- **Dependencies:** BL-004; coordinate with BL-003.
- **Implementation evidence:** Not implemented. Prior importance/urgency wording or UI tickets are not evidence that this full request is complete.
- **User acceptance evidence:** Not recorded.
- **Residual scope:** Label necessity, source differentiation, shape, color, placement, duplication, responsive behavior, and article-card hierarchy.
- **Notes:** Do not mark this item `Done` based only on earlier label wording or styling adjustments.

## BL-003 — AIで機械処理された印象を弱める

- **ID:** BL-003
- **Title:** AIで機械処理された印象を弱める
- **Priority:** P1
- **Status:** Captured
- **Source type:** User-confirmed summary
- **Original user comment:** Original wording not recovered.
- **User-confirmed summary:** AIで機械処理された印象を弱める。
- **Interpretation:** Do not conceal machine processing. Reduce unnecessary “AI-processed” appearance caused by repeated badge shapes, dense classification metadata, and overly uniform article cards.
- **Acceptance criteria:** Not defined. Requires design criteria and explicit user acceptance.
- **Dependencies:** BL-002 and BL-004.
- **Implementation evidence:** Not implemented.
- **User acceptance evidence:** Not recorded.
- **Residual scope:** Define which visual patterns create the unwanted impression and validate a redesign with the user.
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
- **Implementation evidence:** Not implemented. Project governance documents exist, but no dedicated UI design document exists.
- **User acceptance evidence:** Not recorded.
- **Residual scope:** Review request, response evaluation, specification drafting, user approval, and later implementation tickets.
- **Notes:** Answered fact: README, AGENTS, STATUS, and DECISIONS exist, but a UI design document defining labels, article cards, and visual hierarchy has not been created. Treat this as the design stage before BL-002 and BL-003 implementation.

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
- **Source type:** Recovered paraphrase (recovered project decision)
- **Original user comment:** Original wording not recovered.
- **User-confirmed summary:** Not recovered as a user-confirmed summary.
- **Interpretation:** The decided future brand name is `Monomi Digest`. Do not reopen “Security Digest or Monomi Digest” as an undecided naming choice.
- **Acceptance criteria:** Not defined. Implementation scope, migration timing, and treatment of the old name remain unspecified.
- **Dependencies:** BL-007; About, SEO, public navigation, repository and publication naming decisions.
- **Implementation evidence:** Not implemented. Current product and repository display remain `Security Digest`.
- **User acceptance evidence:** The recovered project decision records the name as accepted; implementation acceptance is not recorded.
- **Residual scope:** Inventory all brand surfaces, define migration and compatibility, implement, and obtain user acceptance.
- **Notes:** This backlog introduction must not change the current displayed brand.

## BL-007 — monomidigest.comへの移行

- **ID:** BL-007
- **Title:** monomidigest.comへの移行
- **Priority:** P2
- **Status:** Accepted / Not implemented
- **Source type:** Recovered paraphrase (recovered project decision)
- **Original user comment:** Original wording not recovered.
- **User-confirmed summary:** Not recovered as a user-confirmed summary.
- **Interpretation:** Use `monomidigest.com` as the primary domain. The recorded decision says `monomi.jp` is unnecessary.
- **Acceptance criteria:** Not defined. Domain ownership and DNS state must be verified before implementation.
- **Dependencies:** BL-006, About content, SEO, canonical URLs, and public navigation.
- **Implementation evidence:** Not implemented. Domain acquisition and DNS configuration are not verified.
- **User acceptance evidence:** Direction is recorded as accepted; implementation acceptance is not recorded.
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
- **Dependencies:** Data quality, BL-006, BL-007, Japanese editorial specification, BL-002–BL-004, About content, metadata, and public navigation.
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
