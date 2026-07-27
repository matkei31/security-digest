# Monomi Digest Decisions

This file records stable project decisions in an ADR-lite format. Current versions and temporary operating state belong in [STATUS.md](STATUS.md), not here. When historical PR text differs from the merged implementation, the merged code and completion record are authoritative.

## SD-001 — Keep ARTICLE and BRIEF as separate prompt contracts

- **ID:** SD-001
- **Date:** 2026-07-15
- **Status:** Accepted / Implemented
- **Context:** ARTICLE evaluates individual news items, while BRIEF summarizes the distribution and themes of the day. They have different inputs, response schemas, validation, and release cadence.
- **Decision:** Maintain independent ARTICLE and BRIEF prompt versions and change them separately. A change to one contract must not automatically change the other.
- **Consequences:** Version assertions, request-body tests, response-schema tests, and production acceptance must identify which prompt changed. The daily JSON schema remains a separate contract.
- **Evidence:** [`daily_json.py`](daily_json.py), [`fetch.py`](fetch.py), [PR #7](https://github.com/matkei31/security-digest/pull/7), [PR #8](https://github.com/matkei31/security-digest/pull/8)
- **Supersedes:** None

## SD-002 — Use feed-native rich content without additional article HTTP requests

- **ID:** SD-002
- **Date:** 2026-07-16
- **Status:** Accepted / Implemented
- **Context:** Short feed descriptions can omit facts needed for ARTICLE evaluation, but fetching and scraping article pages would expand communication, storage, security, and source-specific maintenance scope.
- **Decision:** ARTICLE may use richer content already present in the fetched RSS/Atom response. It must not perform additional article-page HTTP requests or source-specific scraping. Rich input is deterministically sanitized, bounded, and kept inside the untrusted article boundary.
- **Consequences:** Rich content is transient Gemini input only. It is not stored in daily JSON, HTML, normal logs, error logs, or translation cache. `raw_excerpt` remains description-based. Selection and excerpt placement must remain source-, vendor-, actor-, and keyword-independent.
- **Evidence:** [`fetch.py`](fetch.py), [`test_feed_rich_content.py`](test_feed_rich_content.py), [PR #10](https://github.com/matkei31/security-digest/pull/10), [Ticket 16a completion record](https://github.com/matkei31/security-digest/pull/10#issuecomment-4984908665)
- **Supersedes:** The description-only ARTICLE input policy

## SD-003 — Disable CISA advisory RSS and obtain CISA KEV from the official GitHub mirror

- **ID:** SD-003
- **Date:** 2026-07-16
- **Status:** Accepted / Implemented
- **Context:** The CISA advisory RSS path repeatedly returned HTTP 403 in GitHub Actions and produced no ordinary CISA RSS articles in the examined daily data. The KEV catalog remains required and has an official machine-readable mirror maintained under the CISA GitHub organization.
- **Decision:** Keep the CISA advisory RSS definition but disable it and place it on hold. Obtain CISA KEV from the official `cisagov/kev-data` GitHub mirror. Do not substitute third-party proxies, search results, or HTML scraping.
- **Consequences:** CISA RSS can be re-enabled only when the activation conditions in `source_definitions.json` are satisfied. CISA KEV remains a separate enabled structured source.
- **Evidence:** [`source_definitions.json`](source_definitions.json), [`test_source_definitions.py`](test_source_definitions.py), [PR #11](https://github.com/matkei31/security-digest/pull/11)
- **Supersedes:** The enabled CISA advisory RSS route and the previous KEV download endpoint

## SD-004 — Preserve fallback and fix validation false positives in validation

- **ID:** SD-004
- **Date:** 2026-07-16
- **Status:** Accepted / Implemented
- **Context:** ARTICLE uses strict validation for `success` and a bounded recovery path for useful partial output. Validation false positives can incorrectly move otherwise usable analysis to fallback, but that does not make fallback itself incorrect.
- **Decision:** Preserve the `success`, `fallback`, `failed`, and `not_attempted` status contract. Correct a false positive in the relevant validator or input contract instead of deleting fallback, treating invalid output as success, or discarding required semantics.
- **Consequences:** Validation changes require direct regression coverage for the affected boundary and must not silently broaden the success contract. Fallback remains observable in daily JSON and run counts.
- **Evidence:** [`fetch.py`](fetch.py), [`daily_json.py`](daily_json.py), [PR #8](https://github.com/matkei31/security-digest/pull/8), [PR #12](https://github.com/matkei31/security-digest/pull/12)
- **Supersedes:** None

## SD-005 — Do not treat “〜を検討する” as a state-change command

- **ID:** SD-005
- **Date:** 2026-07-16
- **Status:** Accepted / Implemented
- **Context:** The recommended-actions lint treated advisory wording such as “脅威検知サービスの導入を検討する” as if it directly ordered a state change. This false positive was identified in the Mandiant fallback diagnosis and was capable of moving otherwise usable analysis to fallback. The stored diagnostic evidence did not establish the complete path of the unsaved production response.
- **Decision:** Treat “導入を検討する” and equivalent consideration wording for the covered state-change verbs as advisory evaluation, not as an unconditional state-change command. Continue rejecting explicit execution forms such as “導入する”.
- **Consequences:** Consideration and explicit execution remain distinguishable. If a sentence also contains an explicit covered execution form, the explicit command is still rejected.
- **Evidence:** [`fetch.py`](fetch.py), [`test_article_v5.py`](test_article_v5.py), [PR #12](https://github.com/matkei31/security-digest/pull/12)
- **Supersedes:** The prior lint behavior that included “を検討” among strong state-change forms

## SD-006 — Do not infer omitted Japanese objects in action lint

- **ID:** SD-006
- **Date:** 2026-07-16
- **Status:** Accepted / Implemented
- **Context:** A temporary object-omission inference was considered during Ticket 17a review to treat a later “実施する” as inheriting the object of an earlier consideration phrase. It introduced false positives for evaluation, confirmation, negative, and conditional wording and was rejected. Reliable inference would require semantic Japanese parsing beyond this lint's intended scope.
- **Decision:** Do not infer an omitted object for “実施する” in action lint. Detect explicit covered state-change forms and defined conditions only.
- **Consequences:** Some semantically implied commands may remain outside the lint. Avoiding broad false positives and unexpected fallback is preferred to speculative inference. Any future expansion requires a separately approved specification and examples.
- **Evidence:** [`fetch.py`](fetch.py), [`test_article_v5.py`](test_article_v5.py), [PR #12](https://github.com/matkei31/security-digest/pull/12)
- **Supersedes:** None

## SD-007 — Create Security Digest editorial-style-v1 and introduce it to BRIEF first

- **ID:** SD-007
- **Date:** 2026-07-16
- **Status:** Accepted / Not implemented
- **Context:** BRIEF would benefit from a stable Security Digest-specific editorial voice, but ARTICLE has a different factual evaluation contract and should not inherit presentation rules without separate validation.
- **Decision:** Create an original `editorial-style-v1` for Security Digest and first introduce only the applicable portions to BRIEF. Do not copy an external Gist in full. Do not apply the style to ARTICLE at this stage. Embed the approved style text into the Gemini BRIEF prompt when releasing `today-brief-v4`.
- **Consequences:** The style needs its own scoped design and tests before implementation. BRIEF v4 must preserve deterministic state/count generation, trusted-context boundaries, and the daily schema unless separately approved. ARTICLE remains on its existing editorial and validation contract. Follow-up: the prompt-only implementation path attempted under this direction (v4/v5/v6) was discontinued by [SD-017](#sd-017--do-not-merge-prompt-only-todays-brief-experiments-redesign-semantic-validation-separately); semantic validation continues as a separate effort under BL-021.
- **Evidence:** The project conversation record (outside GitHub) is the basis for this direction; no GitHub-traceable artifact prior to [PR #13](https://github.com/matkei31/security-digest/pull/13) (merge commit `0fcdf88e175c25ab1e877bb78e0a25de5b29b5ec`) contains this decision's content — exhaustive search confirmed this in [BACKLOG_AUDIT.md](BACKLOG_AUDIT.md) Batch 2, Audit B. PR #13 is the PR that first recorded this already-decided direction into canonical project documentation (`BACKLOG.md`/`DECISIONS.md`); PR #13 by itself is not treated as the origin of user acceptance for this decision, only as the documentation-sync event. Future implementation must add its own PR and merged-code evidence here.
- **Supersedes:** None

## SD-008 — Use local verification and review records when PR CI does not exist

- **ID:** SD-008
- **Date:** 2026-07-16
- **Status:** Accepted / Active
- **Context:** The repository currently has no ordinary `pull_request` or `push` CI workflow, so a PR can legitimately report zero checks.
- **Decision:** When no PR checks exist, use scope-appropriate local verification and an independent review record as merge evidence, and record the substitution on the PR or completion record. Implementation changes require the successful local full unittest suite and confirmation that the PR diff matches the approved final diff. For documentation-only changes, first check whether any static test inspects each changed document. If a related static test exists, update it with the document and run at least the related tests. Only when no relevant static test exists may the full unittest suite be omitted with a recorded reason. Markdown-link verification, changed-file scope, `git diff --check`, and independent diff review remain required.
- **Consequences:** Zero checks must not be described as successful CI. Merge remains subject to human approval, mergeability, conflict checks, and confirmation that no unexpected commits or files were added. If required PR CI is introduced later, its checks take precedence.
- **Evidence:** [`.github/workflows/fetch.yml`](.github/workflows/fetch.yml), [PR #12 evidence comment](https://github.com/matkei31/security-digest/pull/12#issuecomment-4991807236)
- **Supersedes:** None

## SD-009 — Preserve original user feedback separately from implementation interpretation

- **ID:** SD-009
- **Date:** 2026-07-16
- **Status:** Accepted / Active
- **Context:** Replacing a concrete user comment with a broader implementation interpretation can hide residual scope and make a partially addressed request appear complete. Merged code is implementation evidence, but it is not automatically user acceptance of subjective UI, writing-quality, or brand outcomes.
- **Decision:** Preserve recoverable original user wording without editing it. Store interpretation and acceptance criteria in separate fields. Do not quote reconstructed wording as a user statement, and do not present a user-confirmed summary as verbatim. Do not mark partially addressed items `Done`; subjective UI, writing-quality, and brand-expression items require explicit user acceptance. Use [BACKLOG.md](BACKLOG.md) as the canonical source for incomplete, partial, and acceptance-pending requirements and issues.
- **Consequences:** Tickets identify related backlog IDs and update status, implementation evidence, user acceptance evidence, and residual scope. Splitting, merging, or superseding an item retains its old ID and original comment. This decision establishes the management contract but does not specify any individual backlog item's implementation.
- **Evidence:** [BACKLOG.md](BACKLOG.md), [AGENTS.md](AGENTS.md)
- **Supersedes:** None

## SD-010 — Use Monomi Digest as the future public brand

- **ID:** SD-010
- **Date:** 2026-07-17
- **Status:** Accepted
- **Context:** The future public brand direction was reconfirmed, while the current site and repository still display `Security Digest` and the migration scope remains undefined.
- **Decision:** Use `Monomi Digest` as the future public brand. Do not return the choice between `Security Digest` and `Monomi Digest` to an undecided state.
- **Consequences:** [BL-006](BACKLOG.md#bl-006--monomi-digestへのブランド変更) managed the scope for the brand-change implementation across README, site, metadata, current-state documentation, and user acceptance, and is complete. Repository rename, custom domain/DNS (BL-007), and About/meta description/analytics (BL-009) remain explicitly out of scope of this decision and are tracked as separate tickets.
- **Evidence:** [BL-006](BACKLOG.md#bl-006--monomi-digestへのブランド変更) — published brand text switched to `Monomi Digest` (`🔐` retained) in generated HTML and project documentation; user-accepted 2026-07-26; merged via [PR #57](https://github.com/matkei31/security-digest/pull/57) (merge commit `ea79ae12f5ddca2b241420f0c06cdfe3c6badf27`); public GitHub Pages confirmed live with the new brand.
- **Supersedes:** None

## SD-011 — Use monomidigest.com as the primary domain

- **ID:** SD-011
- **Date:** 2026-07-17
- **Status:** Accepted / Not implemented
- **Context:** The primary-domain direction was reconfirmed, but ownership, DNS, GitHub Pages configuration, canonical metadata, and redirects have not been verified or implemented.
- **Decision:** Use `monomidigest.com` as the primary domain. `monomi.jp` is not required.
- **Consequences:** Verify ownership, DNS, GitHub Pages, canonical URLs, and redirects before implementation; [BL-007](BACKLOG.md#bl-007--monomidigestcomへの移行) manages that work and acceptance. Do not infer that the domain has been acquired.
- **Evidence:** [BL-007](BACKLOG.md#bl-007--monomidigestcomへの移行)
- **Supersedes:** None

## SD-012 — Dashboard v2, priority index, and the ARTICLE reason no-imperative contract

- **ID:** SD-012
- **Date:** 2026-07-17
- **Status:** Accepted / Implemented
- **Context:** The dashboard rendered three separate badge-like cards (a total-count box plus three `.dashboard-group` panels) and used the display label 「確認優先度」for importance, which reads as a time-axis term and conflicts with the intended 重要度/確認目安 distinction (impact/weight vs. confirmation timing). The 優先確認 section already avoided a full re-listing of article metadata, but it did not show 重要度/確認目安 per item, showed its selection-condition note even when empty, and had no `:target` affordance for the anchor jump to the full card. The ARTICLE `reason` field had no rule preventing reader-facing imperative sentences (「〜してください」「〜すべきです」); the existing Ticket 17a hedging-allowed regex is scoped only to `recommended_actions`, not `reason`.
- **Decision:** Standardize on 「重要度」(importance) and 「確認目安」(urgency) everywhere in generated HTML and display-time reason-label conversion; 「確認優先度」is retired from all generated output (it remains only in the ARTICLE prompt's/response-schema's internal definition text for `importance`, which is out of scope for this decision). Replace the 3-card dashboard with a single lightweight block: article count, 重要度 (高/中/低, 未判定 shown only when present), 確認目安 (本日確認/今週確認/参考, 未判定 shown only when present), and a visually de-emphasized 主なカテゴリ row (only categories with count > 0, existing `CATEGORY_VALUES` order). No collection-source count, no CISA KEV count, no ellipse badges, no JavaScript. 優先確認 becomes an explicit reasoned index: shared article numbering, English-original-title-primary display (unchanged contract), 重要度/確認目安 as plain text (not badges), the existing `reason` field verbatim (no re-summarization, no truncation), and an anchor link to the full card. Its selection-condition note renders only when the list is non-empty. `select_important_items()`'s selection logic is unchanged. Add a narrow, purely regex-based lint (`reason_has_reader_directed_imperative`) that rejects `reason` text containing 「てください/でください」(anywhere in the text) or a sentence-final 「すべきです/すべきだ/すべき」(immediately before 句点/感嘆符/疑問符 or the end of the string only; mid-sentence uses such as 「すべきかを検討する」「すべきと説明しています」「すべき範囲」are not matched). This lint is applied inside the strict success-path validator (`normalize_article_analysis`); on failure, validation falls through to the existing fallback-extraction path (per SD-004). `fallback_ai_analysis()` additionally applies this same lint to its own extracted `reason`: if the fallback response's `reason` contains a reader-directed imperative, that field alone is set to `None` (no substitute text is generated), while the rest of the fallback analysis (`importance`/`summary`/`financial_impact`/`recommended_actions`/`category`/`urgency`/`tags`) is unaffected — this closes the gap where an imperative `reason` that fails strict validation could otherwise reach 優先確認 unchanged via the fallback path, which does not go through `normalize_article_analysis`. Hedge and conditional expressions (「確認が必要となり得る」「検討対象となる」「確認の優先度が高い」, negation, conditionals) are explicitly preserved as acceptable. Bump `ARTICLE_PROMPT_VERSION` to `article-analysis-v8` for this prompt-content change.
- **Consequences:** `daily_json.ARTICLE_PROMPT_VERSION` is `article-analysis-v8`; `BRIEF_PROMPT_VERSION`, `SCHEMA_VERSION`, the ARTICLE/BRIEF response schemas, the importance/urgency evaluation definitions, and `select_important_items()`'s selection criteria are unchanged. Ordinary article-card layout, its source-color/importance/urgency/category badges (shape and placement), and related tags are unchanged — only badge label text was updated to the 重要度/確認目安 terminology; ellipse-badge removal for ordinary cards is deferred to a follow-on ticket (tracked in [BL-002](BACKLOG.md#bl-002--記事カードの楕円バッジ多用を見直す)/[BL-003](BACKLOG.md#bl-003--aiで機械処理された印象を弱める)). A dedicated UI design specification document (per [BL-004](BACKLOG.md#bl-004--fable-5によるuiレビューとui設計書)) still does not exist; the reviewed mock used here covered the dashboard only.
- **Evidence:** [`fetch.py`](fetch.py), [`daily_json.py`](daily_json.py), [`test_fetch.py`](test_fetch.py), [`test_article_v5.py`](test_article_v5.py)
- **Supersedes:** The 3-card dashboard layout and the 確認優先度 display label

## SD-013 — Ordinary article-card variant B: remove classification-label badges, keep 関連タグ round

- **ID:** SD-013
- **Date:** 2026-07-17
- **Status:** Accepted / Implemented
- **Context:** SD-012 deferred ordinary article-card badge removal to a follow-on ticket. The ordinary card showed取得元 (colored ellipse pill), 重要度, 確認目安, and カテゴリ all as same-shaped rounded badges alongside 関連タグ, which read as a uniform, machine-generated classification block (BL-002/BL-003). Two mock variants generated outside the repository were reviewed by the user: variant A removes all classification labels (including 関連タグ); variant B keeps only 関連タグ as a low-contrast rounded pill at the card's bottom. The user explicitly chose variant B.
- **Decision:** Remove the source-color pill, `.importance-badge`, `.urgency-badge`, and `.category-badge` from the ordinary article card. 取得元 and the publish date render as one plain-text meta line (`source ・ date`) placed after the title. 重要度/確認目安 render as plain text (`重要度 <value>` / `確認目安 <value>`), each independently getting a light text-color/left-border accent (`is-accent`) only when the value is 高 or 本日確認 respectively; 中/低/今週確認/参考 get no extra emphasis, and neither axis uses an ellipse shape or the `.article-tag` pill styling. category is no longer displayed on the ordinary card at all — its daily-JSON storage, ARTICLE response-schema field, `normalize_article_analysis` validation, and dashboard category aggregation (`compute_dashboard_counts`, 主なカテゴリ) are unchanged. `関連タグ` keeps its existing rounded-pill `<span>` presentation, relocated to a footer at the bottom of the card (after the 元記事を読む link), and stays non-clickable: `<span>` only, no `<a>`/`button`, no click handler, no `role="button"`, no `cursor:pointer`. Card information order becomes: article number → English title → Japanese title → 取得元・日時 → 重要度・確認目安 → 何が起きた → 脆弱性情報 (when present) → なぜ金融機関に関係する → 確認すべきこと → 元記事を読む → 関連タグ. No article search, tag search, or tag landing page is introduced by this decision.
- **Consequences:** `build_html()`'s card-rendering block and its inline `<style>` change; `build_daily_archive_html()` reuses the same function, so archive pages get the same card layout with no separate code path. `daily_json.py` schema/versions, the ARTICLE/BRIEF response schemas, `select_important_items()` selection logic, the 優先確認 index, and dashboard v2 are unchanged — this decision is scoped to the ordinary card only. `SOURCE_COLORS` remains in use for the collapsible “収集元” footer list, which is unaffected. A dedicated, repo-resident UI design specification document (per [BL-004](BACKLOG.md#bl-004--fable-5によるuiレビューとui設計書)) still does not exist; this decision rests on the reviewed A/B mock and the user's explicit choice, not a formal spec artifact. The user visually reviewed the actual PC/390px implementation (screenshots reviewed outside the repository) and accepted it on 2026-07-17, verbatim: 「見られたけど、いいと思うよ」; see [BL-002](BACKLOG.md#bl-002--記事カードの楕円バッジ多用を見直す)/[BL-003](BACKLOG.md#bl-003--aiで機械処理された印象を弱める).
- **Evidence:** [`fetch.py`](fetch.py), [`test_fetch.py`](test_fetch.py)
- **Supersedes:** The ordinary-card ellipse badges for 取得元/重要度/確認目安/カテゴリ (SD-012's deferred scope)

## SD-014 — Keep daily JSON outside the GitHub Pages publication tree and limit stored content

- **ID:** SD-014
- **Date:** 2026-07-17
- **Status:** Accepted / Implemented
- **Context:** The user questioned whether daily JSON needs to be exposed to site visitors. It is needed for generation history and for rebuilding the internal date-based archive, but does not need to be part of the GitHub Pages publication tree. The user accepted that the file remaining readable inside the public GitHub repository is acceptable.
- **Decision:** Store daily JSON under `data/`, not `docs/`; it is not served as GitHub Pages site content. Being readable inside the public repository is acceptable. Do not store secrets, credentials, raw Gemini/AI responses, full article text, or rich content in daily JSON. `raw_excerpt` keeps its existing bounded, description-based contract — currently a 200-character cap built from the already-fetched feed description, with no article-page scraping (`daily_json.build_raw_excerpt()`). Expanding what is stored requires separate approval.

  Accepted wording, recorded verbatim (original line breaks preserved):

  > 「daily JSONはサイト利用者へ公開する必要はない。
  > GitHub Pagesの公開対象であるdocs/には置かず、生成・履歴管理用としてdata/に保存する。
  > public repository内で閲覧可能であることは許容するが、秘密情報、raw AI response、記事全文など公開不適切な情報を保存しない。」

- **Consequences:** `daily_json.py`'s `DATA_DIR` remains under `data/`; `fetch.py`'s `DOCS_DIR` remains the separate GitHub Pages output tree. This decision does not assert that daily JSON was ever previously stored elsewhere; the earliest daily-JSON introduction found in this repository's history (commit `1c65be6`, "feat: add daily JSON schema and storage (Ticket 3)") already wrote to `data/`. This is consistent with [SD-002](#sd-002--use-feed-native-rich-content-without-additional-article-http-requests) (rich content is not stored). Any future proposal to store additional content types in daily JSON, or to publish it through `docs/`, requires a new decision record.
- **Evidence:** [`daily_json.py`](daily_json.py) (`DATA_DIR`, `build_raw_excerpt()`, `compute_content_hash()`), [`fetch.py`](fetch.py) (`DOCS_DIR`), [`.github/workflows/fetch.yml`](.github/workflows/fetch.yml) (`git add docs/ data/`), [SD-002](#sd-002--use-feed-native-rich-content-without-additional-article-http-requests), [`test_daily_json.py`](test_daily_json.py), commit `1c65be67eaaa223d65ca1056313fb933d31f1ec4`
- **Supersedes:** None

## SD-015 — Project trusted context through an explicit allowlist and do not expose internal identifiers

- **ID:** SD-015
- **Date:** 2026-07-18 (record creation date; not the date of the underlying incident — see Evidence)
- **Status:** Accepted / Implemented
- **Context:** The internal container key `recent_kev_additions` in ARTICLE's verified context was imitated by Gemini into natural-language output. It reached `analysis.reason`, daily JSON, the top page, and the current-day archive for real production articles. The raw Gemini response was not stored, so the leaked text could not be directly inspected after the fact; the input contract itself — an internal key name placed directly into the verified-context object passed to the prompt — was the exposure path, not a response-side handling gap.
- **Decision:** Gemini-facing trusted context is built exclusively through a dedicated builder function, which is the sole entry point for constructing ARTICLE's verified context. Internal container names, field names, flag values, and machine-readable status values are never passed through to the prompt as-is. An explicit allowlist projects them onto human-readable labels and meaning-preserving values. Unknown fields, flags, or status values are omitted rather than automatically propagated. Meaningful values that a reader or the model legitimately needs — CVE IDs, dates, CVSS scores, product names — are preserved. Asking the prompt not to output something, post-hoc string replacement, and broad sanitizers are not treated as the primary control; the primary control is the input-side allowlist projection. Internal identifiers and raw response data must not reach user-visible output.
- **Consequences:** Any future change to the trusted-context boundary requires request-body regression tests covering what actually reaches the Gemini request. Passing a new internal field to Gemini requires an explicit projection entry and review — it is not opt-out. The key used to store a value internally in daily JSON and the label used to present the same concept to Gemini are kept as separate namespaces, not reused directly. This decision's boundary is the same trusted-context/untrusted-article boundary that `AGENTS.md`'s "Prompt and schema contracts" section already states must be maintained; it must stay consistent with that section.
- **Evidence:** [PR #8](https://github.com/matkei31/security-digest/pull/8) ("Fix internal identifier leakage in ARTICLE output"), merge commit `d1518910cd1a685cffc5d526ec65f6e708a4d535`; current `build_verified_context_for_prompt` in [`fetch.py`](fetch.py); related regression tests in [`test_fetch.py`](test_fetch.py) / [`test_article_v5.py`](test_article_v5.py); [`AGENTS.md`](AGENTS.md) "Prompt and schema contracts" (trusted-context boundary) and "Security requirements"; current `main` implementation.
- **Supersedes:** None

## SD-016 — Resolve the remaining BL-004 UI choices without changing the accepted layout

- **ID:** SD-016
- **Date:** 2026-07-18
- **Status:** Accepted / Active
- **Context:** [UI_SPEC.md](UI_SPEC.md) Draft 0.1 integrated the accepted dashboard v2, ordinary article-card variant B, BL-016〜BL-018, the current `main` implementation, regression tests, and the known Fable 5 proposal history. Seven choices still required explicit user adjudication before the document could become the approved UI specification. All seven choices preserve the accepted current layout and require no UI implementation change.
- **Decision:** Resolve all seven remaining choices as follows: (1) do not add an AI-use note to the current UI, including per-article-card or per-analysis-section notes; reconsider whether an explanation is needed only if a future About page or public navigation is designed as a separately approved scope; (2) keep the current mobile sticky header and `20px 16px 16px` padding at 600px and below, reject compression, and preserve the current anchor-offset contract; (3) keep `🔐` for the current Security Digest and do not remove it under BL-004, while allowing BL-006 to replace it later as part of the Monomi Digest brand migration; (4) reject mobile English-original-title clamp, keep natural wrapping without a line limit, and do not omit any part of the English original title; (5) keep the current amber pill for `CISA KEV掲載` as an exceptional emphasis for an objective and important state, distinct in meaning, color, and emphasis from related tags and not a return to classification-pill overuse; (6) keep the tested per-section empty states for 優先確認, dashboard, article list, and the other current sections on zero-article days, and do not replace the whole page with one dedicated empty state; (7) keep the browser-default focus display, do not add a dedicated `:focus-visible` treatment, never remove outline or focus visibility, and require any future replacement to be at least as clear as the browser default.

  The user's adjudication of these seven items is recorded verbatim:

  > 「7点ともこの方針でOK」

- **Consequences:** No current UI implementation change is produced by this decision. The seven choices are confirmed requirements in [UI_SPEC.md](UI_SPEC.md) Version 1.0. BL-006 takes precedence for a future Security Digest-to-Monomi Digest brand migration, including possible replacement of `🔐`. Any future consideration of an AI explanation in an About page or public navigation requires separate approval. Do not reopen these seven resolved choices as active unresolved items. Changing any of them requires a new explicit user decision and a new decision record that identifies this decision in its `Supersedes` field.
- **Evidence:** [UI_SPEC.md](UI_SPEC.md) Version 1.0; [BL-004](BACKLOG.md#bl-004--fable-5によるuiレビューとui設計書); [PR #30](https://github.com/matkei31/security-digest/pull/30); existing UI implementation in [`fetch.py`](fetch.py); related regression tests in [`test_fetch.py`](test_fetch.py), [`test_archive.py`](test_archive.py), and [`test_ui_spec.py`](test_ui_spec.py).
- **Supersedes:** The seven items recorded as unresolved in UI_SPEC.md Draft 0.1: AI-use note, mobile sticky-header compression, header emoji removal, mobile English-original-title clamp, KEV display shape, whole-page zero-article presentation, and focus styling.

## SD-017 — Do not merge prompt-only Today's Brief experiments; redesign semantic validation separately

- **ID:** SD-017
- **Date:** 2026-07-23
- **Status:** Accepted
- **Context:** Following the direction accepted in [SD-007](#sd-007--create-security-digest-editorial-style-v1-and-introduce-it-to-brief-first), Today's Brief structural guards and prompt-only fidelity instructions were implemented and screened across three iterations (v4, v5, v6) under [BL-005](BACKLOG.md#bl-005--editorial-style-v1とtoday-brief-v4). Structural guards and average editorial quality reached an acceptable level, but the absolute semantic-fidelity gate did not pass: a subject/scope change from an external actor to the financial institution itself recurred even after the prompt explicitly prohibited it, and a factual date alteration also occurred.
- **Decision:** Do not integrate the v4, v5, or v6 Today's Brief experiments into `main`. Discontinue further prompt-only improvement attempts for this specific failure mode. Retain the structural-guard design knowledge already established (highlight eligibility, source ID validation, public `list[str]` projection, and related deterministic guards). Redesign semantic validation as a separate effort under [BL-021](BACKLOG.md#bl-021--todays-briefの意味忠実性semantic-validation再設計). Keep the experimental branches as local evidence; do not publish them.
- **Consequences:** Production continues to run `today-brief-v3`. BL-005 is closed as No-Go for its prompt-only implementation path. BL-021 will examine additional verification approaches, their API cost, fallback rate, and false-positive/over-removal rate. The experimental commits are not published to the remote.
- **Evidence:** Real-API screening across 5 fixtures × 2 runs (10 logical runs): API success 10/10; deterministic guards 262/262 pass; ID laundering 0; orphan references 0; Run 1 comparison gate: pass; absolute gate: fail. Representative failure instances: a factual year changed from 2026 to 2024; an external body's (NCSC) SME support content extended into the financial institution's own oversight of its business-partner SMEs' security posture.
- **Supersedes:** [SD-007](#sd-007--create-security-digest-editorial-style-v1-and-introduce-it-to-brief-first), but only its prompt-only `editorial-style-v1` implementation path for Today's Brief. The goal of improving editorial quality and semantic fidelity itself is not superseded; it continues under BL-021.

## SD-018 — Screen deterministic extractive Today's Brief without a semantic blocking validator

- **ID:** SD-018
- **Date:** 2026-07-23
- **Status:** Accepted / Implemented and verified in production
- **Context:** BL-021 Phase 1 tested semantic validator prompts v1 and v2 on fixed pilot and shadow data. Both variants detected all known major violations in the applicable Safety Gates, but the blocking decision also rejected human-reviewed faithful output. The single general prompt correction did not fix SH-A04 and increased faithful false positives, so a validator that removes or blocks Brief content is not usable for production. The alternative composition contract was subsequently implemented and merged through PR #35, then verified through one authorized production generation and the resulting Pages deployment.
- **Decision:** Do not adopt the Phase 1 semantic validator as a blocking production gate, and end further prompt tuning for that path. Adopt the alternative composition contract `today-brief-extractive-v1` on `main`: build overview only from the existing deterministic trusted-context formatters; select eligible ARTICLE `summary` values as `important_highlights`; select eligible ARTICLE `financial_impact` values as the section displayed as 「金融機関との関連」; and select ARTICLE `recommended_actions` for `check_items`. Preserve each selected string verbatim, validate internal source IDs, apply stable ordering and existing public limits, remove exact duplicates only, and project only `list[str]` to daily JSON and HTML. Production `build_todays_brief()` must not call the BRIEF Gemini API. Keep ARTICLE generation, prompt, schema, version, and API path unchanged.
- **Consequences:** This composition removes new cross-article semantic generation at the BRIEF stage and therefore loses generated narrative synthesis, semantic action merging, and the former cross-article meaning of `discussion_points`. It does not newly guarantee that the ARTICLE analysis itself is factually correct; it preserves ARTICLE text as received. The existing `prompt_version` field is retained for backward compatibility and identifies the Brief composition contract. Existing historical `today-brief-v3` daily JSON and archives continue to use 「本日の注目論点」, while new extractive output uses 「金融機関との関連」. Implementation, production generation, PC/390px verification, and user acceptance were completed on 2026-07-23.
- **Evidence:** [BL-021](BACKLOG.md#bl-021--todays-briefの意味忠実性semantic-validation再設計); [PR #35](https://github.com/matkei31/security-digest/pull/35), merge commit `d1755d413cd554d6905715af26521e9e3169001c`; [Pull Request CI run 29990255618](https://github.com/matkei31/security-digest/actions/runs/29990255618); merge-triggered [Pages deployment run 30011612439](https://github.com/matkei31/security-digest/actions/runs/30011612439); authorized [Daily Security Digest run 30012552188](https://github.com/matkei31/security-digest/actions/runs/30012552188), generation commit `1afbd0e7f5b008ea3051af676e57fb2951b648ed`, and [Pages deployment run 30012791302](https://github.com/matkei31/security-digest/actions/runs/30012791302); PC 1280px／390px production review; repository-external Phase 1 closure, final live, and extractive screening artifacts. Check items use a two-stage selection: first one verbatim action per eligible article in today/week and display priority, then remaining actions only when capacity remains.
- **Supersedes:** [SD-017](#sd-017--do-not-merge-prompt-only-todays-brief-experiments-redesign-semantic-validation-separately) only for BL-021's next local evaluation method. SD-017's No-Go decision for v4/v5/v6 remains active.

## SD-019 — Do not adopt the prompt-only ARTICLE editorial-quality candidate

- **ID:** SD-019
- **Date:** 2026-07-23
- **Status:** Accepted / No-Go
- **Context:** BL-023 evaluated one minimal `article-analysis-v9` candidate intended to remove self-evident reader-organization usage disclaimers from `financial_impact` and generally omit CVE IDs from `recommended_actions`. The candidate was fixed before evaluation and tested against 15 fixtures in 2 logical runs (30 attempts, no retry). The Technical Gate passed, but the field-quality and safety gates did not.
- **Decision:** Do not adopt the evaluated `article-analysis-v9` prompt-only candidate and do not continue prompt retuning for this path. Production remains on `article-analysis-v8`. Preserve the repository-external pilot outputs as No-Go evidence. Do not compensate with generic regex deletion, prohibited-word lists, CVE string removal, or BRIEF-side rewriting. Reconsider ARTICLE editorial quality only through a separately designed structured ARTICLE-field contract or a facts-based, narrowly bounded deterministic composition.
- **Consequences:** ARTICLE prompt, version, schema, validation, status/fallback contracts, and production behavior remain unchanged. The desired editorial-quality outcome remains open only under the stated redesign condition; the rejected prompt candidate is not an implementation baseline.
- **Evidence:** [BL-023](BACKLOG.md#bl-023--article編集品質改善); repository-external `BL-023/article-editorial-quality-pilot/` evaluation artifacts. Technical Gate PASS; `financial_impact`, `recommended_actions`, and Safety／Non-regression Gates FAIL due to source-unsupported assertions, loss of material conditions, and control-fixture importance/urgency degradation.
- **Supersedes:** None

## SD-020 — Link the top page to the latest validated earlier digest

- **ID:** SD-020
- **Date:** 2026-07-23
- **Status:** Accepted / Implemented and verified in production
- **Context:** The top page always linked to the Archive list but required another click to reach the immediately preceding published digest. Calendar subtraction can create a broken link when a publication date is missing, and `data/index.json` ordering must not be assumed.
- **Decision:** Keep 「過去のダイジェストを見る →」and, when possible, add a sibling link to the latest validated published digest strictly earlier than the current `digest_date`. Determine the target by date comparison across entries that are present in validated `data/index.json`, have a corresponding valid daily JSON, and have a generated Archive HTML. Use 「← 前日のダイジェスト」when the target is exactly one calendar day earlier; otherwise use 「← 前回のダイジェスト（M/D）」. Omit only the direct link when no earlier published digest exists. Keep both links in the existing wrapping `.archive-nav`; do not change daily Archive previous/next navigation.
- **Consequences:** The top-page generator reads existing local publication metadata and files but does not fetch external data or modify daily JSON. Current and future dates are excluded. ARTICLE／BRIEF contracts, Gemini model, daily schema, Archive-page navigation, article cards, `data/`, and generated `docs/` are unchanged by the feature branch. UI_SPEC advances to Version 1.1.
- **Evidence:** [BL-022](BACKLOG.md#bl-022--前日ダイジェスト直接リンク); [UI_SPEC.md](UI_SPEC.md) Version 1.1; [PR #37](https://github.com/matkei31/security-digest/pull/37), merge commit `d43c563a9a59506aaaa4a41cc6297620cbb6f276`; [Pages deployment run 30022728319](https://github.com/matkei31/security-digest/actions/runs/30022728319); production generation commit `e8183bd9ee6bb8288dc329eaf68c412225eecbc8`; [`fetch.py`](fetch.py); [`test_archive.py`](test_archive.py); repository-external BL-022 offline screening artifacts; user confirmation that the published direct link was visible and functional.
- **Supersedes:** [UI_SPEC.md](UI_SPEC.md) Version 1.0 section 6.1 only where the top-page Archive navigation listed the Archive index link without the newly approved direct-link behavior.

## SD-021 — Unify digest navigation labels and separate direction from global navigation

- **ID:** SD-021
- **Date:** 2026-07-24
- **Status:** Accepted / Implemented and verified in production
- **Context:** After the PR #37 direct link was published and confirmed functional, the user approved using one consistent set of navigation terms without dates and separating direction movement from global navigation so that links do not cluster at the left on PC.
- **Decision:** Use exactly four navigation labels: 「← 前のダイジェスト」for backward movement, 「次のダイジェスト →」for forward movement, 「最新のダイジェスト」for the current top page, and 「過去のダイジェスト」for the Archive list. Do not include dates in navigation-link labels. On the top page, place the optional backward link in the left direction group and the always-present Archive-list link in the right global group. At both the top and bottom of each daily Archive, place existing backward and forward links in the left direction group and always place the latest-page and Archive-list links in the right global group. Omit only unavailable directions. Preserve DOM order and group distinction when the groups wrap at 390px.
- **Consequences:** The validated date-selection and broken-link prevention rules from [SD-020](#sd-020--link-the-top-page-to-the-latest-validated-earlier-digest) remain unchanged, including traversal across missing calendar dates. Existing daily JSON is used to regenerate only static HTML. ARTICLE／BRIEF prompts, models, schemas, validation, fallback, daily JSON, `data/index.json`, article content and ordering, source definitions, and workflows do not change.
- **Evidence:** [BL-022](BACKLOG.md#bl-022--前日ダイジェスト直接リンク); [UI_SPEC.md](UI_SPEC.md) Version 1.2; [PR #38](https://github.com/matkei31/security-digest/pull/38), merge commit `85e1b3e3cd4bb3c8927c9b1608652c77a9ebb6e9`; [Pull Request CI run 30061712600](https://github.com/matkei31/security-digest/actions/runs/30061712600); [Pages deployment run 30061770611](https://github.com/matkei31/security-digest/actions/runs/30061770611); public PC 1280px and 390px verification; [`fetch.py`](fetch.py); [`test_archive.py`](test_archive.py).
- **Supersedes:** [SD-020](#sd-020--link-the-top-page-to-the-latest-validated-earlier-digest) only for navigation labels, date display, placement, and its previous exclusion of daily-Archive navigation from the BL-022 UI change. SD-020's validated earlier-date selection and publication-artifact verification remain active. It also supersedes the displayed return labels and placement recorded by [BL-017](BACKLOG.md#bl-017--過去ダイジェストの回遊性と一覧表示を改善する), without changing BL-017's accepted existing-date traversal logic.

## SD-022 — Do not adopt the fixed article-analysis-v10 financial-impact simplification candidate

- **ID:** SD-022
- **Date:** 2026-07-24
- **Status:** Accepted / No-Go
- **Context:** BL-023 evaluated a fixed `article-analysis-v10` candidate that replaced the detailed `financial_impact` instructions from v8 with a self-contained, concise one-to-two-sentence contract. The candidate was fixed before evaluation and tested against 17 fixtures in 2 logical runs (34 attempts, no retry). HTTP 200 and schema parsing succeeded for all 34 attempts, with no technical error, missing field, or internal-identifier leak, but the financial-impact, safety/non-regression, and mandatory-article gates did not pass.
- **Decision:** Do not implement or adopt the fixed `article-analysis-v10` candidate. Production remains on `article-analysis-v8`, and no additional prompt adjustment will be made in response to this evaluation. This No-Go is limited to the fixed v10 candidate's inability to guarantee source-bounded output and non-regression of other fields consistently; it does not establish that simplification or prompt-based improvement is generally impossible. Reconsider BL-023 only through a separately designed structured ARTICLE-field contract or a facts-based, narrowly bounded deterministic composition.
- **Consequences:** ARTICLE prompt, version, schema, validation, status/fallback contracts, and production behavior remain unchanged, and the evaluation made zero repository changes. Although the transport and schema path worked technically, the quality, Safety／Non-regression, and mandatory Zimbra／NCSC gates prevent this candidate from becoming a production option. The v10 candidate is not an implementation baseline.
- **Evidence:** [BL-023](BACKLOG.md#bl-023--article編集品質改善); repository-external `BL-023/article-financial-impact-v10-screening/` evaluation artifacts. Fixed 17 fixtures, 2 logical runs, 34 attempts, retry 0; HTTP 200 34/34; schema parse 34/34; Technical Gate PASS; financial_impact Gate FAIL; Safety／Non-regression Gate FAIL; mandatory Zimbra／NCSC articles FAIL.
- **Supersedes:** None. SD-019を置換せず、`article-analysis-v9`のNo-Go記録を補完する。

## SD-023 — Remove source-specific colors and pill styling from the source footer

- **ID:** SD-023
- **Date:** 2026-07-24
- **Status:** Accepted / Implemented and verified in production
- **Context:** The collapsible source footer used per-source background colors without an explained semantic system or legend, and multiple sources shared colors, so the styling provided weak identification while adding decorative noise. Ordinary article cards already removed classification pills under SD-013. This BL-020 UI change is independent of BL-019's completed correction of the footer count, enabled-source set, and definition order.
- **Decision:** Keep the collapsible 「収集元」 section and its `details`／`summary` behavior, but remove source-specific backgrounds and pill styling. Render every enabled source, including CISA KEV, through the same achromatic, low-emphasis plain-text `ul`／`li` contract. Keep the count, source set, and source-definition order from `build_footer_sources()` unchanged, and use the same rendering on the top page and daily Archives.
- **Consequences:** The footer no longer identifies sources by color; in return, it has less decorative noise and no link-like or chip-like treatment. Source names, count, order, collection behavior, ARTICLE／BRIEF contracts, daily JSON, source definitions, and workflows remain unchanged. `SOURCE_COLORS` and its compatibility builder are removed because no production display uses them after this change, while the historical `color` metadata in `source_definitions.json` remains unchanged.
- **Evidence:** [BL-020](BACKLOG.md#bl-020--収集元一覧の取得元別カラーを廃止する); [UI_SPEC.md](UI_SPEC.md) Version 1.3; [`fetch.py`](fetch.py); [`test_archive.py`](test_archive.py); repository-external PC 1280px／390px top-page and daily-Archive screenshots; implementation commit `f6990564de8f84dabdd2e614a7fe72996cf961fe`; final accepted PR head `1d55897e1241138d6bbb0bd2bd2381e10bc05f2e`; [PR #41](https://github.com/matkei31/security-digest/pull/41); merge commit `d16a2ce28c05a2381d98ed3dbb28599ebd317b7b`; [Pull Request CI run 30068786053](https://github.com/matkei31/security-digest/actions/runs/30068786053); [Pages deployment run 30068840298](https://github.com/matkei31/security-digest/actions/runs/30068840298). The user visually accepted the pre-merge generated screenshots with 「この表示でOK、進めて」, including the three-column PC display, one-column 390px display, neutral plain-text treatment, and browser-default focus indication. After merge, Work objectively verified the public top page and 2026-07-24 daily Archive at PC 1280px／390px and confirmed that the accepted column counts, source list, color-free and pill-free treatment, wrapping, emphasis, and no-horizontal-overflow contract matched. The user did not review the public site.
- **Supersedes:** [UI_SPEC.md](UI_SPEC.md) Version 1.2 section 12.1 only where it required source-specific colors, and SD-013 only where its Consequences stated that `SOURCE_COLORS` remained in use for the collapsible source footer. It does not supersede SD-013's ordinary-card variant B or any part of BL-019's count, enabled-source set, or definition-order contract.

## SD-024 — Approve Security Requirements Version 1.0 and the proportionate security roadmap

- **ID:** SD-024
- **Date:** 2026-07-24
- **Status:** Accepted / Version 1.0 merged
- **Context:** BL-015 organized security requirements for the current static GitHub Pages site and repository-backed generation pipeline. Draft 0.1 received a Fable 5 review with Critical 0 and High 0. The user's finding adjudication was incorporated into Draft 0.2, while files Fable could not retrieve were reviewed independently. Repository-external settings were not inferred: GAP-010 was completed through a read-only repository-owner checklist. The user then answered 「ok」 to the complete decision brief covering Version 1.0, the proportional dispositions, and follow-up ticket boundaries.
- **Decision:** Approve [SECURITY_REQUIREMENTS.md](SECURITY_REQUIREMENTS.md) Version 1.0. Approve full commit SHA pinning for both workflows, weekly GitHub Actions Dependabot, and production concurrency with `cancel-in-progress: false` as one follow-up ticket. Explicitly accept current production checkout credential persistence because the current official-Actions/repository-code job requires a later `git push`. Approve source URL scheme validation as a separate ticket and one compact Security Operations documentation ticket for secret rotation, incident response, published-output correction, and repository-external artifact handling. Integrate custom-domain security into BL-007. Accept the unofficial translation endpoint only for bounded public information. Defer a common network response byte cap until its trigger, and leave GAP-009 unresolved for later prioritization. Implement security controls only through their individual tickets and pull requests.
- **Consequences:** BL-015 can be completed as a security-requirements definition after PR #44 merges. Version 1.0 is the baseline for the current architecture; approved follow-up controls remain unimplemented and visible in the gap register and [BACKLOG.md](BACKLOG.md). Requirements approval is not automatic approval of any implementation PR, GitHub setting change, production run, or merge. Re-evaluate the baseline when a listed architecture or risk trigger occurs.
- **Evidence:** [SECURITY_REQUIREMENTS.md](SECURITY_REQUIREMENTS.md) Version 1.0; Fable 5 review and adjudication; user approval quote 「ok」 in the complete decision-brief context; completed GAP-010 repository-owner checklist; [PR #44](https://github.com/matkei31/security-digest/pull/44) final head `eef80a3a589bbaee8dbb373c4a0ee0f75038546d`; merge commit `3f1803388161495f9145150e760d91b03821ad80`; [Pull Request CI run 30095261901](https://github.com/matkei31/security-digest/actions/runs/30095261901); related tests; follow-up [BL-024](BACKLOG.md#bl-024--最小security-operationsと公開済み生成物の訂正手順を定義する), [BL-025](BACKLOG.md#bl-025--収集元urlをhttphttps-schemeへ制限する), and [BL-026](BACKLOG.md#bl-026--github-actions-supply-chainとproduction-concurrencyを強化する).
- **Supersedes:** None. This integrates the current security baseline without replacing existing individual security decisions or the implementation boundaries in [AGENTS.md](AGENTS.md).

## SD-025 — Approve Security Operations Version 1.0 and the minimal incident and correction policy

- **ID:** SD-025
- **Date:** 2026-07-24
- **Status:** Accepted / Version 1.0 merged
- **Context:** BL-024 combined GAP-006, GAP-008, GAP-013, and GAP-014 into a compact operations runbook for the current personally managed static site. Draft 0.1 received a Fable 5 review with Critical 0 and High 1 (F-001); the user's finding adjudication was incorporated into Draft 0.2, and `test_security_operations.py`, which Fable could not retrieve, was independently reviewed. The user then answered 「ok」 to the complete final decision brief covering the remaining policy choices.
- **Decision:** Approve [SECURITY_OPERATIONS.md](SECURITY_OPERATIONS.md) Version 1.0. Use a dedicated branch, the smallest change, fast-track pull request, relevant local tests, Pull Request CI, scope review, and normal approval/merge as the emergency default without skipping review or CI. Permit a direct public hotfix only when continued publication creates material harm and that normal path is clearly too slow, with explicit Repository owner and User approval owner approval, a normally `docs/`-only minimal public change, strict prohibitions on contracts, code, workflows, settings, secrets, external calls, production, and history rewriting, and a complete after-action branch and pull request within 24 hours. For withdrawal, prefer an explicit notice, then blank output, and use deletion last; the first real withdrawal requires its own ticket and user approval and must preserve navigation, Archive, and daily-JSON contracts. For a supported material correction, correct daily JSON and index consistency, validate, deterministically regenerate all affected HTML offline, review the translation cache, test, retain Git history, record canonical BL/commit/PR evidence, confirm Pages, and directly verify material public changes. Add no correction-notice schema or UI now. Keep detailed external artifacts for 90 days from evaluation completion by default; longer retention requires a recorded User approval owner exception, and long-term evidence should prefer sanitized summaries, manifests, hashes, gate results, and decision records over raw material. The unconditional credential-value ban takes precedence.
- **Consequences:** [SECURITY_REQUIREMENTS.md](SECURITY_REQUIREMENTS.md) becomes Version 1.1 as a maintenance update: SR-015, SR-020, SR-032, and SR-043 are Met, while GAP-006, GAP-008, GAP-013, and GAP-014 remain historically visible with disposition `Completed by documentation`. This is documentation completion, not evidence of a runtime security control, an executed incident, a production correction, a GitHub setting change, or existing-artifact cleanup. A minimal [AGENTS.md](AGENTS.md) reference points relevant future work to the runbook without changing approval boundaries.
- **Evidence:** [BL-024](BACKLOG.md#bl-024--最小security-operationsと公開済み生成物の訂正手順を定義する); [SECURITY_OPERATIONS.md](SECURITY_OPERATIONS.md) Version 1.0; [SECURITY_REQUIREMENTS.md](SECURITY_REQUIREMENTS.md) Version 1.1; Fable 5 review and user finding adjudication; independent test review; user approval quote 「ok」 in the complete final decision-brief context; [PR #46](https://github.com/matkei31/security-digest/pull/46) final head `a04e3a3b6c5789d0a2e4de983054035080f0ce75`; merge commit `047534601d8d15419a8d3b45142d8828bc655ad4`; [Pull Request CI run 30102905467](https://github.com/matkei31/security-digest/actions/runs/30102905467); [Pages deployment run 30103074821](https://github.com/matkei31/security-digest/actions/runs/30103074821); related static contract tests.
- **Supersedes:** [SD-024](#sd-024--approve-security-requirements-version-10-and-the-proportionate-security-roadmap) only where it recorded GAP-006, GAP-008, GAP-013, and GAP-014 as approved but unimplemented documentation follow-ups. It does not replace the Version 1.0 architecture baseline, other roadmap decisions, residual risks, or any approval boundary.

## SD-026 — Redesign 本日の要点 and article-card headings; compose 重要・優先事項 from paired ARTICLE fields

- **ID:** SD-026
- **Date:** 2026-07-27
- **Status:** Accepted
- **Context:** The user found the public heading 「金融機関との関連」 (「本日の要点」's `discussion_points` heading, introduced by [SD-018](#sd-018--screen-deterministic-extractive-todays-brief-without-a-semantic-blocking-validator)) unclear in purpose, and separately found the article-card headings 「何が起きた」／「なぜ金融機関に関係する」weak. A read-only investigation (BL-029) confirmed `discussion_points` was a verbatim re-post of each eligible article's `financial_impact`, duplicating the article card's own 「なぜ金融機関に関係する」 section, and that UI_SPEC.md's own §7.1 text had drifted from the actual production heading.
- **Decision:** Rename public headings under [BL-029](BACKLOG.md#bl-029--金融機関との関連とarticle見出しの情報設計を再検討する): 「本日の要点」's child headings become 概況／重要・優先事項／確認事項; the article card's headings become 概要（`summary`）／金融機関との関連（`financial_impact`）／確認すべきこと（unchanged label）. 「重要・優先事項」 replaces the single-field `financial_impact` re-post with one list item per eligible article (same selection condition as the prior `discussion_points`: `importance=="高"` or `urgency` in 「本日確認」／「今週確認」), each item showing that article's `summary` and `financial_impact` verbatim as two separate paragraphs, with pair-based (not single-field) exact-duplicate removal. New generations record the composition contract as `today-brief-extractive-v2` (`daily_json.BRIEF_PROMPT_VERSION`); ARTICLE prompt, ARTICLE response schema, `ARTICLE_PROMPT_VERSION`, ARTICLE Gemini model/validation/fallback, and the public daily JSON schema (`overview`/`important_highlights`/`discussion_points`/`check_items` as `list[str]`) are all unchanged. `important_highlights` remains stored for compatibility but is not newly displayed. HTML rendering reconstructs 重要・優先事項 from `items[].ai_analysis` at render time via a single shared helper (`select_priority_items()`), independent of the stored `brief.prompt_version` — so existing Archives (`today-brief-extractive-v1`, `today-brief-v3`, etc.) receive the same new heading and two-paragraph structure wherever their stored ARTICLE analysis supports it. A day is displayed under the legacy heading 「注目論点」, showing its saved `discussion_points` verbatim as single-paragraph items, only when reconstruction from `items[].ai_analysis` is not possible and a saved `discussion_points` exists; that day is not treated as migrated to the new UI. Past `data/*.json` files, including their `prompt_version` and `discussion_points` values, are not rewritten.
- **Consequences:** 「本日の要点」の重要・優先事項 section now presents ARTICLE-level `summary` and `financial_impact` together per article instead of `financial_impact` alone, removing the confusing standalone re-post while adding no new AI-generated text at the Brief stage. `important_highlights` remains an unused-for-display but schema-compatible field. Historical daily JSON is unaffected; only HTML regenerated after this decision reflects the new headings, and any day whose analysis cannot support reconstruction keeps showing its original `discussion_points` content under 「注目論点」 rather than being silently dropped or force-fit into the new structure.
- **Evidence:** [BL-029](BACKLOG.md#bl-029--金融機関との関連とarticle見出しの情報設計を再検討する); user-confirmed specification. Draft branch, PR head, merge commit, and Pages confirmation are recorded at closure.
- **Supersedes:** [SD-018](#sd-018--screen-deterministic-extractive-todays-brief-without-a-semantic-blocking-validator) only for (a) the specific rule that `discussion_points` is constructed from `financial_impact` values alone, and (b) the display heading 「金融機関との関連」 as a `discussion_points`-only label under 「本日の要点」 (the same string is now the article-card `financial_impact` heading instead). SD-018's other contracts remain in force unchanged: no new AI semantic generation at the Brief composition stage, no BRIEF-dedicated Gemini call, verbatim preservation of selected ARTICLE text, source ID validation, stable ordering, projecting only `list[str]` to daily JSON/HTML, removing only exact duplicates (now defined at the pair level for 重要・優先事項), and never rewriting past daily JSON.
