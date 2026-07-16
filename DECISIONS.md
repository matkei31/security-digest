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
