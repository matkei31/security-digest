# Security Digest Decisions

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
- **Consequences:** The style needs its own scoped design and tests before implementation. BRIEF v4 must preserve deterministic state/count generation, trusted-context boundaries, and the daily schema unless separately approved. ARTICLE remains on its existing editorial and validation contract.
- **Evidence:** Project decision recorded during the documentation sync; future implementation must add its PR and merged-code evidence here.
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
- **Status:** Accepted / Not implemented
- **Context:** The future public brand direction was reconfirmed, while the current site and repository still display `Security Digest` and the migration scope remains undefined.
- **Decision:** Use `Monomi Digest` as the future public brand. Do not return the choice between `Security Digest` and `Monomi Digest` to an undecided state.
- **Consequences:** Migrate current display in a separate ticket. [BL-006](BACKLOG.md#bl-006--monomi-digestへのブランド変更) manages the scope for README, site, metadata, repository name, About, domain, old-name treatment, and user acceptance. This PR does not change the displayed brand.
- **Evidence:** [BL-006](BACKLOG.md#bl-006--monomi-digestへのブランド変更)
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
- **Status:** Accepted / Implemented / Awaiting user acceptance — the decision and its code implementation are both done; the user's visual PC/390px review of the actual implementation (distinct from the earlier mock/direction approval) is still outstanding. See [BL-002](BACKLOG.md#bl-002--記事カードの楕円バッジ多用を見直す)/[BL-003](BACKLOG.md#bl-003--aiで機械処理された印象を弱める).
- **Context:** SD-012 deferred ordinary article-card badge removal to a follow-on ticket. The ordinary card showed取得元 (colored ellipse pill), 重要度, 確認目安, and カテゴリ all as same-shaped rounded badges alongside 関連タグ, which read as a uniform, machine-generated classification block (BL-002/BL-003). Two mock variants generated outside the repository were reviewed by the user: variant A removes all classification labels (including 関連タグ); variant B keeps only 関連タグ as a low-contrast rounded pill at the card's bottom. The user explicitly chose variant B.
- **Decision:** Remove the source-color pill, `.importance-badge`, `.urgency-badge`, and `.category-badge` from the ordinary article card. 取得元 and the publish date render as one plain-text meta line (`source ・ date`) placed after the title. 重要度/確認目安 render as plain text (`重要度 <value>` / `確認目安 <value>`), each independently getting a light text-color/left-border accent (`is-accent`) only when the value is 高 or 本日確認 respectively; 中/低/今週確認/参考 get no extra emphasis, and neither axis uses an ellipse shape or the `.article-tag` pill styling. category is no longer displayed on the ordinary card at all — its daily-JSON storage, ARTICLE response-schema field, `normalize_article_analysis` validation, and dashboard category aggregation (`compute_dashboard_counts`, 主なカテゴリ) are unchanged. `関連タグ` keeps its existing rounded-pill `<span>` presentation, relocated to a footer at the bottom of the card (after the 元記事を読む link), and stays non-clickable: `<span>` only, no `<a>`/`button`, no click handler, no `role="button"`, no `cursor:pointer`. Card information order becomes: article number → English title → Japanese title → 取得元・日時 → 重要度・確認目安 → 何が起きた → 脆弱性情報 (when present) → なぜ金融機関に関係する → 確認すべきこと → 元記事を読む → 関連タグ. No article search, tag search, or tag landing page is introduced by this decision.
- **Consequences:** `build_html()`'s card-rendering block and its inline `<style>` change; `build_daily_archive_html()` reuses the same function, so archive pages get the same card layout with no separate code path. `daily_json.py` schema/versions, the ARTICLE/BRIEF response schemas, `select_important_items()` selection logic, the 優先確認 index, and dashboard v2 are unchanged — this decision is scoped to the ordinary card only. `SOURCE_COLORS` remains in use for the collapsible “収集元” footer list, which is unaffected. A dedicated, repo-resident UI design specification document (per [BL-004](BACKLOG.md#bl-004--fable-5によるuiレビューとui設計書)) still does not exist; this decision rests on the reviewed A/B mock and the user's explicit choice, not a formal spec artifact.
- **Evidence:** [`fetch.py`](fetch.py), [`test_fetch.py`](test_fetch.py)
- **Supersedes:** The ordinary-card ellipse badges for 取得元/重要度/確認目安/カテゴリ (SD-012's deferred scope)
