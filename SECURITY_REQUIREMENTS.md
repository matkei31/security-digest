# Monomi Digest Security Requirements

- **Version:** 1.5
- **Status:** Approved
- **As of:** 2026-07-31
- **Scope:** Current static GitHub Pages site and its repository-backed generation pipeline
- **Out of scope:** Runtime and platform hardening beyond the accepted BL-025 loader-boundary change, the accepted BL-026 workflow hardening (Action pinning, GitHub Actions Dependabot, and production concurrency), the accepted BL-027 Action major-version upgrade (`actions/checkout` v7.0.1, `actions/setup-python` v7.0.0), and the production enforcement of per-source content usage modes (deferred to BL-032, not implemented by this Version)

Version 1.5 (this Version) is the most recent **Approved** architecture security-requirements
baseline, not the GitHub vulnerability-reporting policy normally placed in a `SECURITY.md` file.
It is an **Approved** maintenance update layered on top of the previously Approved Version 1.4
baseline, with its own approval recorded by [SD-030](DECISIONS.md#sd-030--approve-source-usage-policy-version-01-and-defer-runtime-enforcement-to-bl-032).
Version 1.4 retains
requirements, repository evidence, register entries, proportional exclusions, owner-check
results, and approved roadmap decisions; records the approved Security Operations
documentation completed by BL-024; records the accepted BL-025 collection-URL validator;
records the accepted BL-026 GitHub Actions supply-chain and production-concurrency hardening
(full-commit-SHA pinning for `actions/checkout` and `actions/setup-python`, a weekly
`github-actions`-only Dependabot configuration, and a workflow-level production concurrency
group); and records the accepted BL-027 GitHub Actions major-version upgrade (`actions/checkout`
to v7.0.1, `actions/setup-python` to v7.0.0, both pinned to the same full commit SHA in both
workflows), validated by one explicitly user-authorized production `workflow_dispatch` run
rather than the originally planned next ordinary schedule run. BL-027 is limited to the Action
version upgrade and its one-time production validation; it does not implement any broader
runtime or platform hardening, does not establish `workflow_dispatch` as a standing validation
method for future Action changes, and no GitHub-side setting change was made as part of it.
Version 1.5 is an Approved maintenance update. It records the completed BL-030 (unofficial
translation-endpoint removal, `docs/translate_cache.json` deletion, and the CrowdStrike/
Cloudflare temporary suspension) and the completed BL-031 (a read-only official-terms audit
of all 17 sources, recorded in [SOURCE_USAGE_POLICY.md](SOURCE_USAGE_POLICY.md) Approved 0.1,
and the resulting Dark Reading temporary suspension). It does not record production enforcement
of any per-source content usage mode; that implementation is deferred to the registered
[BL-032](BACKLOG.md#bl-032--取得元別content-usage-policy-enforcement) ticket (要件定義済み／未着手).
This Version's approval is the audit-and-policy approval described above; it is not a
pre-approval of BL-032's runtime enforcement, of production execution, of `workflow_dispatch`,
or of any GitHub-side setting change.

Fable 5 reviewed Draft 0.1 as proportional to the current architecture and suitable for
continued review, with no Critical or High findings. Draft 0.2 incorporated the user's
adjudication of F-001 through F-009. Fable 5 could not retrieve `STATUS.md` or
`test_security_requirements.py`; those two files were instead checked independently at the
PR head. The repository-owner checklist was then completed read-only, and the user approved
the complete decision brief with 「ok」. Version 1.0 recorded that policy approval. Version 1.1
recorded the separately approved
[SECURITY_OPERATIONS.md](SECURITY_OPERATIONS.md) Version 1.0 and [SD-025](DECISIONS.md#sd-025--approve-security-operations-version-10-and-the-minimal-incident-and-correction-policy),
Version 1.2 records the separately accepted BL-025 loader-boundary implementation without
expanding it into a new network-security policy, Version 1.3 records the separately
accepted BL-026 GitHub Actions supply-chain and production-concurrency hardening, accepted by
the user with 「ok」 at [PR #50](https://github.com/matkei31/security-digest/pull/50) head
`394dd157395b69e86928d98a376386131474b20f`, without expanding it into a new Action-upgrade,
runtime-dependency, or Pages-operations policy, and Version 1.4 records the separately
accepted BL-027 GitHub Actions major-version upgrade, accepted by the user with 「ok」 at
[PR #54](https://github.com/matkei31/security-digest/pull/54) head
`d7461b9adfe474793a60f61cd6fe8b219153b499`; the acceptance-recording commit produced final
head `241e7f69c9c843fc212c1c590f3a328da5946579`, which passed Pull Request CI and merged as
`69f7da859e1856beffac9fa381f0f0cc92564e36`, with production validated by one authorized
`workflow_dispatch` run ([run 30147337332](https://github.com/matkei31/security-digest/actions/runs/30147337332))
that generated commit `226db6285021d9daf98fe2941248b7f5b20ba143` and pushed it successfully,
without expanding acceptance into an ongoing Action-upgrade cadence, an auto-merge policy, or a
standing `workflow_dispatch` authorization.

## 1. Purpose and proportionality

Monomi Digest collects public cybersecurity information, produces daily JSON, and publishes
static HTML. The repository contains no application login, form submission, payment flow, or
personal-information database. Its risk profile is therefore different from an interactive
service that stores customer data.

The architecture nevertheless has boundaries that need protection:

- production GitHub Actions uses write permission and credentials;
- external RSS, Atom, JSON, NVD, KEV, and Gemini inputs cross trust boundaries;
- Gemini output and external content can reach repository history and public HTML after
  processing;
- prompt, schema, validation, source configuration, daily JSON, and generated HTML are
  integrity-sensitive;
- repository-external evaluation artifacts and CI logs can retain more detail than the
  published site.

Controls must be proportional to these assets and boundaries. The project does not adopt
every technically possible security product by default. A control becomes mandatory only
when an accepted requirement, a confirmed risk, or a re-evaluation trigger justifies it.

## 2. System scope and components

The current repository-backed system comprises:

- configured RSS and Atom feeds plus structured NVD and CISA KEV inputs;
- [`source_definitions.json`](source_definitions.json), loaded and validated by
  `load_source_definitions()` in [`fetch.py`](fetch.py);
- feed parsing, normalization, bounded retry, and feed-native rich-content selection in
  [`fetch.py`](fetch.py);
- ARTICLE processing with Gemini, including trusted verified context and untrusted article
  content;
- deterministic-extractive Today's Brief composition, which does not call a BRIEF model;
- daily JSON construction, validation, and atomic persistence in
  [`daily_json.py`](daily_json.py);
- CVE extraction and NVD/KEV retrieval with bounded caching in
  [`vulnerability_facts.py`](vulnerability_facts.py);
- static top-page and Archive HTML generation in [`fetch.py`](fetch.py);
- the public GitHub repository, production workflow
  [`.github/workflows/fetch.yml`](.github/workflows/fetch.yml), PR workflow
  [`.github/workflows/pr-ci.yml`](.github/workflows/pr-ci.yml), and GitHub Pages;
- repository-external evaluation and review artifacts recorded by backlog and decision
  evidence but not managed by production code;
- the live `monomidigest.com` custom domain (completed by
  [BL-007](BACKLOG.md#bl-007--monomidigestcomへの移行) and recorded in
  [SD-028](DECISIONS.md#sd-028--migrate-github-pages-to-monomidigestcom-as-the-primary-custom-domain)),
  served via `docs/CNAME`, with `https://www.monomidigest.com/` and the prior
  `matkei31.github.io/security-digest/` URL both redirecting to the apex;
- a documented content-usage policy for external sources
  ([SOURCE_USAGE_POLICY.md](SOURCE_USAGE_POLICY.md) Approved 0.1), which this Version records as
  audit-only; per-source enforcement in production code is deferred to BL-032.

No component for forms, authentication, sessions, a database, payments, inbound webhooks, or
an application API is present in the current repository.

## 3. Data flow

The production flow is:

```text
[Untrusted RSS / Atom / structured public sources]
             |
             v
  fetch + parse + normalize + bounded retry
             |                       ^
             |                       |
             |          [Trusted repository configuration:
             |           source_definitions.json]
             v
  selected feed description or feed-native rich content
             |
             v
  untrusted_article_json ----------------------------+
                                                     |
[System-derived NVD / KEV facts]                     |
             |                                       |
             v                                       v
  allowlisted verified_context_json ------------> ARTICLE Gemini
                                                     |
                                                     v
                                           [Untrusted Gemini output]
                                                     |
                                                     v
                                      parse + strict validation
                                           |               |
                                        success       fallback / failed
                                           \               /
                                            v             v
                                   normalized ARTICLE analysis
                                             |
                                             v
                              deterministic-extractive Brief
                                  (no BRIEF Gemini request)
                                             |
                         +-------------------+-------------------+
                         v                                       v
              validated daily JSON                    escaped static HTML
                    data/                                     docs/
                         \                                       /
                          +---- production commit to repository-+
                                             |
                                             v
                                        GitHub Pages
```

Operational metadata and error messages go to Actions logs. Feed-retrieval errors use a
bounded sanitizer; the inconsistent exception paths recorded in GAP-009 remain a gap. Raw
Gemini responses and feed-native rich content are process-memory inputs and must not be
written to normal logs, daily JSON, or generated HTML. BL-030 removed the unofficial
translation endpoint and `docs/translate_cache.json`; no translation cache exists in the
current architecture (see GAP-012).
Repository-external screening may retain requests, responses, evaluations, manifests, or
screenshots only under the separate artifact-handling requirements below.

## 4. Assets and data classification

| Asset | Classification | Repository storage | Public exposure and retention |
|---|---|---|---|
| GitHub and external-provider credentials | Secret | Prohibited | Never public; configured secret names were owner-verified for Version 1.0, while values, access audit, and rotation state remain outside repository evidence |
| Workflow write permission and checkout credential | Privileged capability | Workflow configuration is stored; credential value is not | Configuration is public; runtime credential must be limited to its workflow purpose and lifetime |
| Source configuration | Trusted configuration / public | Allowed in `source_definitions.json` | Public and versioned; changes require review because they control outbound inputs |
| Prompt, schema, validation, and fallback contracts | Integrity-sensitive source | Allowed and required | Public and versioned; changes require contract-specific review and tests |
| Daily JSON in `data/` | Public repository data, not Pages publication data | Allowed after validation | Visible in the public repository and history; not intentionally served from the `docs/` Pages tree |
| Generated HTML in `docs/` | Public publication data | Allowed | Public through Pages and repository history |
| Feed descriptions and feed-native rich content | Untrusted public input | Only bounded description-derived `raw_excerpt` and approved projections may be stored | Full rich content must not be retained in daily JSON, HTML, or normal logs |
| Raw Gemini responses | Untrusted transient processing data | Prohibited in production repository output | Must not be published or logged; repository-external evaluation retention requires explicit scope |
| Normal production and CI logs | Operational metadata | Held by GitHub, not committed by repository code | Must exclude secrets and raw content; 90-day retention was owner-verified, while actual notification delivery and individual access events remain outside repository evidence |
| Repository-external evaluation artifacts | Review-sensitive; may include raw request/response data | Prohibited unless separately approved for the repository | Store outside the repository, exclude credentials and local paths from committed documents, and define access/retention per evaluation |
| Public source URLs | Public configuration/provenance | Allowed | May be published after URL validation where rendered as a link |
| Live DNS and domain ownership (`monomidigest.com`) | Administrative security asset | `docs/CNAME` is the repository-side source of truth | XServer registrar account, DNS records, and GitHub Pages Custom domain/Enforce HTTPS settings are outside current repository evidence; re-evaluate before any further DNS or Pages change (see GAP-011) |
| Source-terms audit and content-usage policy | Trusted configuration / public | [SOURCE_USAGE_POLICY.md](SOURCE_USAGE_POLICY.md) Approved 0.1 | Public and versioned; records per-source official terms, confidence, and unresolved issues; does not itself enforce production behavior (see GAP-016) |

## 5. Trust boundaries

1. **RSS, Atom, NVD, and KEV responses are external.** Their content, structure, error text, and
   availability are not trusted merely because a source is configured.
2. **Article content is untrusted data, not instruction.** HTML fragments and embedded prompt
   text remain article data through parsing and Gemini serialization.
3. **Gemini output is untrusted until parsed and validated.** A successful HTTP response is not
   equivalent to a valid ARTICLE result.
4. **Verified context is trusted only after deterministic projection.** Internal facts and flags
   become Gemini input solely through `build_verified_context_for_prompt()` and its allowlists.
5. **Source definitions are trusted configuration, not validated external content.** A reviewed
   repository change can alter collection endpoints and source properties, so loader validation
   and review are both required.
6. **GitHub Actions event input has different privilege levels.** Ordinary `pull_request` CI is
   read-only and receives no production secrets; scheduled or manually dispatched production
   generation has `contents: write` and secret references.
7. **Generated HTML is a public sink.** External and AI-generated strings must be escaped, and
   link destinations must pass scheme validation before an `href` is emitted.
8. **The public repository and GitHub Pages are different publication surfaces.** `data/` is not
   in the Pages directory but remains readable in public repository history; `docs/` is both
   repository content and Pages content.
9. **Local and repository-external artifacts have separate ownership.** They are not production
   outputs and must not be treated as implicitly safe to commit, publish, or retain indefinitely.
10. **A source's official terms, license, and AI-provider data-use conditions are external and
    can change.** A source configured as enabled today is not permanently authorized; content
    usage mode assignment in [SOURCE_USAGE_POLICY.md](SOURCE_USAGE_POLICY.md) is a point-in-time
    audit recorded per source in that document's row-level `checked_at` column (2026-07-29 for
    most sources; 2026-07-30 for `google_tag`/`mandiant`, reflecting their post-effective-date
    Google Terms recheck), and must be re-checked on its recorded triggers (source terms/license
    change, robots.txt or other machine-readable-instruction change, feed-path change, or any
    future Google Terms revision beyond the 2026-07-30 version already reviewed). Neither this
    document nor `SOURCE_USAGE_POLICY.md` makes a final legal determination.

## 6. Security requirements

The `Current state` values are limited to `Met`, `Partially met`, `Not met`,
`Not applicable now`, and `Unverified outside repository`. `Met` means that the contract,
implementation, or test is satisfied only to the extent confirmed by repository evidence; it
does not attest to GitHub, Pages, DNS, or other repository-external settings. For human or
agent process requirements, `Met` confirms documented policy and repository evidence, not
perfect compliance in every future execution. Exceptions and repository-external matters are
shown in the Gap / exception column or as `Unverified outside repository`.

### 6.1 Input and content handling

| ID | Requirement | Rationale | Current state | Evidence | Gap / exception | Re-evaluation trigger |
|---|---|---|---|---|---|---|
| SR-001 | Treat feed, article, structured-source, and API response content as untrusted input and fail closed or fall back at its parser boundary. | External content can be malformed, unavailable, or instruction-like. | Met | [`fetch.py`](fetch.py): `_parse_feed_items()`, `normalize_feed_body_text()`, `_fetch_feed_result()`; [`vulnerability_facts.py`](vulnerability_facts.py): normalization and cache validation; [`test_feed_fetch_status.py`](test_feed_fetch_status.py) | No current exception. | New source format, parser, provider, or article-page retrieval. |
| SR-002 | Escape every external or AI-generated string before inserting it into HTML; allow only `http` and `https` rendered links through `safe_url()`; add `rel="noopener noreferrer"` to external links opened with `target="_blank"`. | Prevents markup/script injection and unsafe navigation. | Met | [`fetch.py`](fetch.py): `esc()`, `safe_url()`, `build_html()`; [`test_fetch.py`](test_fetch.py): `HtmlEscapeTest`, `SafeUrlTest`, article-link tests; [`test_archive.py`](test_archive.py): `test_internal_and_external_links_are_safe` | Internal navigation intentionally does not use external-link attributes. | New renderer, HTML field, URL source, or client-side script. |
| SR-003 | Permit production outbound collection only to reviewed `http`/`https` endpoints and validate that scheme at the configuration boundary. | A trusted configuration error should not silently enable a non-web URL handler. | Met | [`fetch.py`](fetch.py): `URL_REQUIRED_COLLECTION_METHODS`, `ALLOWED_COLLECTION_URL_SCHEMES`, `_validate_collection_url()`, and `_validate_source_entry()`; [`test_source_definitions.py`](test_source_definitions.py); [BL-025](BACKLOG.md#bl-025--収集元urlをhttphttps-schemeへ制限する); [PR #48](https://github.com/matkei31/security-digest/pull/48), including its final head, Pull Request CI, and merge record | URL-required collection methods now require a non-empty string with no surrounding whitespace, an absolute `http`/`https` URL, and a host at loader time, including disabled sources. Hostname allowlisting, private/loopback address restrictions, DNS, redirect destinations, ports, TLS, and new `display_url` validation remain outside this requirement. See GAP-001. | Any source-definition, collection-method, collection URL field, or source-loader change. |
| SR-004 | Do not fetch article pages for richer content. Use only feed-native content, select one bounded representation deterministically, and do not store the full rich body. | Limits new attack surface, data transfer, and unintended retention. | Met | [`fetch.py`](fetch.py): `build_article_body_text()`, `apply_article_body_char_limit()`; [`daily_json.py`](daily_json.py): `build_raw_excerpt()`; [`test_feed_rich_content.py`](test_feed_rich_content.py): `SafetyBoundaryTest`, `RawExcerptAndArticleEntryUnaffectedTest` | No current exception. BL-030 removed the unofficial translation endpoint that previously received a bounded summary. | Article-page scraping, full-content storage, or another content provider. |
| SR-005 | Add source-specific behavior only through an approved source contract; do not add unbounded title-, vendor-, CVE-, or article-specific exceptions. | Special cases can bypass common safety and validation paths. | Met | [`AGENTS.md`](AGENTS.md): Scope discipline; [`source_definitions.json`](source_definitions.json); [`test_feed_rich_content.py`](test_feed_rich_content.py): source/name-independence tests | Current approved source-specific behavior, such as shared CISA KEV URLs, remains explicit and tested. | A source cannot be supported without bypassing a common boundary. |

### 6.2 Prompt and AI boundary

| ID | Requirement | Rationale | Current state | Evidence | Gap / exception | Re-evaluation trigger |
|---|---|---|---|---|---|---|
| SR-006 | Serialize verified context and untrusted article data as separate inputs, and state that embedded article instructions are data. | Reduces prompt-injection confusion between system-derived facts and article text. | Met | [`fetch.py`](fetch.py): `gemini_analyze()`, `enrich_with_ai()`; [`test_feed_rich_content.py`](test_feed_rich_content.py): `test_prompt_injection_in_rich_content_does_not_break_boundary`; [`test_vulnerability_facts_prompt.py`](test_vulnerability_facts_prompt.py) | This boundary mitigates but does not prove immunity from all model behavior. | Prompt structure, AI provider, or new trusted-context field. |
| SR-007 | Project trusted context through an explicit allowlist; unknown internal keys and machine identifiers must not automatically reach the prompt or public output. | Prevents internal contract leakage and accidental trust expansion. | Met | [`fetch.py`](fetch.py): `build_verified_context_for_prompt()`; [`test_article_internal_identifier_leak.py`](test_article_internal_identifier_leak.py); [SD-015](DECISIONS.md#sd-015--project-trusted-context-through-an-explicit-allowlist-and-do-not-expose-internal-identifiers) | No current exception. | New fact, rule flag, trusted context, or internal identifier. |
| SR-008 | Treat Gemini output as untrusted until JSON parsing, strict field validation, normalization, and ARTICLE status/fallback handling succeed. | HTTP success alone does not establish output safety or schema validity. | Met | [`fetch.py`](fetch.py): `parse_article_analysis()`, `normalize_article_analysis()`, `gemini_analyze()`; [`daily_json.py`](daily_json.py): `validate_daily_digest()`; [`test_article_analysis.py`](test_article_analysis.py), [`test_article_v5.py`](test_article_v5.py) | Semantic truth cannot be completely guaranteed by structural validation. | Prompt, response schema, validation, fallback, or model change. |
| SR-009 | Do not store raw Gemini responses, request credentials, or internal prompt identifiers in daily JSON, HTML, normal logs, or repository artifacts. | These may expose secrets, unreviewed content, or internal contracts. | Met | [`test_article_analysis.py`](test_article_analysis.py): `SecurityTest`; [`test_article_internal_identifier_leak.py`](test_article_internal_identifier_leak.py); [`test_todays_brief.py`](test_todays_brief.py): raw-input exclusion tests | Explicit repository-external live evaluations can retain raw responses only under a separately approved artifact scope. | New logging, tracing, evaluation, or observability path. |
| SR-010 | Review ARTICLE and BRIEF as independent contracts; prompt, schema, normalization, validation, model, and version changes require scope-specific tests and version assessment. | A change to one contract must not silently alter the other. | Met | [`AGENTS.md`](AGENTS.md): Prompt and schema contracts; [`daily_json.py`](daily_json.py): `ARTICLE_PROMPT_VERSION`, `BRIEF_PROMPT_VERSION`; related request-boundary tests | No current exception. | Any AI contract or daily schema change. |
| SR-011 | Keep production Brief deterministic-extractive: select validated ARTICLE fields with source provenance and public limits, and make no BRIEF Gemini request. | Avoids a second generative trust boundary and cross-article semantic invention. | Met | [`fetch.py`](fetch.py): `compose_extractive_brief()`, `build_todays_brief()`; [`test_todays_brief.py`](test_todays_brief.py): production no-request, source-ID, and projection tests; [SD-018](DECISIONS.md#sd-018--screen-deterministic-extractive-todays-brief-without-a-semantic-blocking-validator) | ARTICLE text itself remains model-generated and subject to ARTICLE validation limits. | Reintroduction of generated Brief text or another composition model. |

Structural and schema validation do not by themselves guarantee semantic fidelity. Fixed
BL-005 and BL-023 evaluations observed unsupported assertions and subject or scope regressions;
the article-analysis-v9 and article-analysis-v10 prompt-only candidates were No-Go, while
production remains article-analysis-v8. This is a known residual content-integrity risk, not
evidence that improvement in general is impossible or that production v8 always fails.

### 6.3 Storage and publication

| ID | Requirement | Rationale | Current state | Evidence | Gap / exception | Re-evaluation trigger |
|---|---|---|---|---|---|---|
| SR-012 | Keep validated generation/history data in `data/` and Pages output in `docs/`; do not equate “outside Pages” with confidential. | The repository is public even when a file is outside the Pages source tree. | Met | [`daily_json.py`](daily_json.py): `DATA_DIR`, atomic save functions; [`fetch.py`](fetch.py): `DOCS_DIR`; [STATUS.md](STATUS.md): Generation and publication; [SD-014](DECISIONS.md#sd-014--keep-daily-json-outside-the-github-pages-publication-tree-and-limit-stored-content) | Actual Pages repository settings are outside repository evidence. | Pages source change, repository visibility change, or different publication platform. |
| SR-013 | Store only bounded provenance and validated analysis in daily JSON; exclude full article/rich content, raw AI responses, credentials, and unnecessary private data. | Repository history is durable and public. | Met | [`daily_json.py`](daily_json.py): `build_raw_excerpt()`, `build_article_entry()`, `validate_daily_digest()`; [`test_daily_json.py`](test_daily_json.py); [`test_feed_rich_content.py`](test_feed_rich_content.py) | Public source title, URL, bounded excerpt, facts, and analysis are intentionally retained. | Schema expansion or new retained input/output. |
| SR-014 | Validate daily JSON before atomic replacement and escape/revalidate data when rebuilding HTML from stored JSON. | Prevents partial writes and avoids trusting historical generated content as safe HTML. | Met | [`daily_json.py`](daily_json.py): `atomic_write_json()`, `validate_daily_digest()`; [`fetch.py`](fetch.py): archive reconstruction and HTML validation; [`test_archive.py`](test_archive.py) | No current exception. | New storage backend, incremental writer, or renderer. |
| SR-015 | Classify every repository-external evaluation artifact, exclude credentials, define intended reviewers, and set an explicit retention/disposal decision before creation. | Raw requests, responses, screenshots, and local metadata may exceed public-output scope. | Met | [`AGENTS.md`](AGENTS.md): secret/raw-response and generated-output restrictions; [SECURITY_OPERATIONS.md](SECURITY_OPERATIONS.md) Version 1.0 sections 8–9; [SD-025](DECISIONS.md#sd-025--approve-security-operations-version-10-and-the-minimal-incident-and-correction-policy) | The documentation contract is complete; no retention automation or existing-artifact cleanup is claimed. See GAP-008. | Any new live evaluation, review bundle, external artifact store, or artifact-inventory review. |
| SR-016 | Do not commit user-specific absolute paths or local credential-store details to project documents or artifacts intended for review. | Prevents local identity and filesystem disclosure. | Met | [`test_fetch.py`](test_fetch.py): `test_no_local_absolute_paths_leaked`; management-document conventions in [`AGENTS.md`](AGENTS.md) | Repository-external artifacts still require their own scan before sharing. | New artifact generator or imported local report. |

### 6.4 Secrets

| ID | Requirement | Rationale | Current state | Evidence | Gap / exception | Re-evaluation trigger |
|---|---|---|---|---|---|---|
| SR-017 | Never write credentials or authorization material to source, generated HTML, daily JSON, caches, logs, manifests, screenshots, or review bundles. | Credential leakage can permit API abuse or repository modification. | Partially met | [`.github/workflows/fetch.yml`](.github/workflows/fetch.yml) passes secrets through environment; [`test_article_analysis.py`](test_article_analysis.py): API-key and error-body non-persistence tests; [`AGENTS.md`](AGENTS.md) | Some general exception logging paths do not use the bounded sanitizer used by feed retrieval. See GAP-009. | Logging change, new provider SDK, or artifact capture. |
| SR-018 | Supply production secrets only to the production generation step; ordinary PR workflows must not receive or use them. | Untrusted PR code must not gain production credentials. | Met | [`.github/workflows/pr-ci.yml`](.github/workflows/pr-ci.yml): `pull_request`, `contents: read`, no secret references; [`test_pr_ci_workflow.py`](test_pr_ci_workflow.py); [`.github/workflows/fetch.yml`](.github/workflows/fetch.yml) | Repository/fork policy outside the workflow file is separately unverified. | New PR workflow, `pull_request_target`, reusable workflow, or secret-consuming job. |
| SR-019 | Keep the production secret inventory minimal and document purpose without recording values. Treat existence, access policy, and platform-side configuration as unverified until an owner checks them. | Minimizes credential exposure while avoiding false claims from repository-only evidence. | Partially met | [`.github/workflows/fetch.yml`](.github/workflows/fetch.yml) references the Gemini and NVD secret names; section 13 records that required `GEMINI_API_KEY` is configured and optional `NVD_API_KEY` is not configured, both at repository-secret scope | No value was inspected. Access audit and last rotation remain outside recorded evidence. See GAP-010. | New credential, provider, environment, or repository visibility. |
| SR-020 | Define minimum rotation/revocation triggers: suspected disclosure, unexpected use, collaborator/access change, provider compromise, or replacement of a credential owner. | Fast revocation limits damage when preventive controls fail. | Met | [SECURITY_OPERATIONS.md](SECURITY_OPERATIONS.md) Version 1.0 sections 2, 4–6, and 9 define owners, triggers, immediate revocation, controlled rotation, verification, and sanitized evidence; [SD-025](DECISIONS.md#sd-025--approve-security-operations-version-10-and-the-minimal-incident-and-correction-policy) | The procedure is documented; no real secret operation or provider validation was performed. See GAP-006 and GAP-013. | Before adding another secret, or immediately after suspected leakage. |

### 6.5 GitHub Actions

| ID | Requirement | Rationale | Current state | Evidence | Gap / exception | Re-evaluation trigger |
|---|---|---|---|---|---|---|
| SR-021 | Declare workflow permissions explicitly and grant only the minimum needed by each job. | Default or broad tokens increase impact if a step is compromised. | Met | PR CI declares `contents: read`; production job declares `contents: write` for generated-output commit in [`.github/workflows/`](.github/workflows); [`test_pr_ci_workflow.py`](test_pr_ci_workflow.py) | Platform-default metadata access is implicit; repository-level defaults are unverified. | New workflow/job or new API operation. |
| SR-022 | Keep ordinary PR validation separate from scheduled/manual production generation; PR CI must not fetch production data, call Gemini, commit, push, or publish Pages. | Separates untrusted code review from secret-bearing write operations. | Met | [`.github/workflows/pr-ci.yml`](.github/workflows/pr-ci.yml); [`test_pr_ci_workflow.py`](test_pr_ci_workflow.py); [BL-001](BACKLOG.md#bl-001--プルリクエストci) | No current exception. | Reusable workflows or new event types. |
| SR-023 | Disable checkout credential persistence where no push is needed; where production must push, make persistence and cleanup behavior explicit and review the least-privilege alternative. | A persisted token is available to later steps in that job. | Met | PR CI sets `persist-credentials: false`; production checkout retains the default credential because the same official-Actions/repository-code job later runs `git push` in [`.github/workflows/fetch.yml`](.github/workflows/fetch.yml); Version 1.0 explicitly accepts this current state | This repository-level assessment does not attest to unrelated platform settings. Re-evaluate if checkout, job composition, or publication changes. See GAP-005. | Checkout/action upgrade or change in publication method. |
| SR-024 | Treat `workflow_dispatch`, production generation, Pages operations, and manual edits to generated output as separately authorized actions. | A safe code change does not imply authorization to mutate production state. | Met | [`AGENTS.md`](AGENTS.md): Approval boundaries and Gemini/production safety; production workflow exposes only schedule and explicit dispatch | Who can dispatch and approve in GitHub settings is unverified outside the repository. | Permission, owner, or workflow-trigger change. |
| SR-025 | Prevent conflicting runs where concurrent writers could race; cancellation must not expose secrets or corrupt output. | Production commits and pushes shared generated paths. | Met | [`.github/workflows/fetch.yml`](.github/workflows/fetch.yml) declares a workflow-level `concurrency` block with `group: daily-security-digest-production` and `cancel-in-progress: false`, serializing `schedule` and `workflow_dispatch`; [`test_fetch.py`](test_fetch.py) `WorkflowStaticCheckTest` covers the block; [PR #50](https://github.com/matkei31/security-digest/pull/50), user acceptance 「ok」, and its merge record; one authorized BL-027 `workflow_dispatch` production run ([run 30147337332](https://github.com/matkei31/security-digest/actions/runs/30147337332)) exercised this workflow under the current pinned Actions and completed cleanly | GitHub's standard concurrency semantics allow one running and one pending run per group, and a new pending run can replace an existing pending run even under `cancel-in-progress: false`; this repository accepts that standard behavior at its current low run frequency instead of an independent durable queue. An in-flight run is not cancelled by a new trigger. The BL-027 production run validated a single normal execution of this workflow; it did not exercise the concurrent-overlap scenario (two simultaneous triggers), which remains unobserved in production. See GAP-004. | Increased run frequency, another write workflow, an observed pending-replacement or push conflict, or a publication-architecture change. |
| SR-026 | Limit automated commits to intended `data/` and `docs/` paths, review generated content before publication where practicable, and verify the Pages result after relevant changes. | A secret-bearing writer publishes durable public content. | Partially met | Production explicitly stages `docs/ data/`; [`daily_json.py`](daily_json.py) validates JSON; [`fetch.py`](fetch.py) validates HTML; section 13 verifies branch publication from `main/docs` | Main has no configured protection/ruleset, and publication review remains an operational step. See GAP-010. | Generated scope expansion, Pages configuration change, or another writer. |

### 6.6 Dependencies and supply chain

| ID | Requirement | Rationale | Current state | Evidence | Gap / exception | Re-evaluation trigger |
|---|---|---|---|---|---|---|
| SR-027 | Prefer the Python standard library and local modules; require explicit approval and security review for new runtime dependencies. | A small static generator should avoid unnecessary supply-chain surface. | Met | Imports in [`fetch.py`](fetch.py), [`daily_json.py`](daily_json.py), and [`vulnerability_facts.py`](vulnerability_facts.py) are standard-library or local; no Python dependency manifest is present; [`AGENTS.md`](AGENTS.md) requires approval | GitHub Actions remain external build dependencies. | Any package manifest or third-party runtime import. |
| SR-028 | Review third-party Actions for publisher, purpose, permissions, update path, and immutable-reference trade-offs. Pinning both workflows to full commit SHAs is approved for a separate implementation ticket. | Major tags are readable and maintainable but mutable; immutable SHAs improve provenance and require an update process. | Met | Both [`.github/workflows/fetch.yml`](.github/workflows/fetch.yml) and [`.github/workflows/pr-ci.yml`](.github/workflows/pr-ci.yml) pin `actions/checkout` to `3d3c42e5aac5ba805825da76410c181273ba90b1` (v7.0.1) and `actions/setup-python` to `5fda3b95a4ea91299a34e894583c3862153e4b97` (v7.0.0), each confirmed read-only against the upstream tag before use; [`test_workflow_action_pinning.py`](test_workflow_action_pinning.py) and [`test_pr_ci_workflow.py`](test_pr_ci_workflow.py); the weekly `github-actions` Dependabot in [`.github/dependabot.yml`](.github/dependabot.yml) provides the update path; [PR #50](https://github.com/matkei31/security-digest/pull/50) established the pinning practice at v4.4.0/v5.6.0, and [BL-027](BACKLOG.md#bl-027--github-actions-checkoutsetup-pythonをv7系へmajor-upgradeする)/[PR #54](https://github.com/matkei31/security-digest/pull/54) moved both Actions to the current major (v7.0.1/v7.0.0), user acceptance 「ok」, and its merge record; production use of these exact SHAs was validated by one authorized BL-027 `workflow_dispatch` run ([run 30147337332](https://github.com/matkei31/security-digest/actions/runs/30147337332)) | A future SHA update from Dependabot is reviewed for publisher, release notes, permissions, diff, and CI before merge rather than auto-merged; a major-version upgrade or a new third-party Action is a separate decision; this repository evidence does not attest to the upstream repository's future state. | New Action, Action compromise/advisory, new release, major upgrade, or workflow expansion. |
| SR-029 | Define how dependency and Action updates are discovered and reviewed, including publisher/ownership and official-mirror verification for source repositories. Weekly GitHub Actions Dependabot is approved with full-SHA pinning in one separate implementation ticket. | Update automation can reduce stale dependencies but creates review volume and must fit the pinning policy; a mirror must not be trusted solely by name. | Met | The weekly `github-actions`-only [`.github/dependabot.yml`](.github/dependabot.yml) surfaces updates as ordinary PRs that run [`.github/workflows/pr-ci.yml`](.github/workflows/pr-ci.yml) (full unittest and diff check) and require a full-SHA update reviewed against the official upstream tag/repository, consistent with [`AGENTS.md`](AGENTS.md)'s dependency/workflow approval boundary and the user-review/merge separation demonstrated by [PR #50](https://github.com/matkei31/security-digest/pull/50); [`test_workflow_action_pinning.py`](test_workflow_action_pinning.py) and [`test_pr_ci_workflow.py`](test_pr_ci_workflow.py); user acceptance 「ok」 and its merge record | No Python runtime dependency exists today, so the general runtime-dependency ownership/provenance checklist remains deferred to GAP-007, which is re-evaluated on a new third-party Action or the first runtime dependency; a Dependabot update PR is never auto-merged. | First runtime dependency, new Action, source-repository change, or a Dependabot PR requiring policy judgment. |

### 6.7 Logging and artifacts

| ID | Requirement | Rationale | Current state | Evidence | Gap / exception | Re-evaluation trigger |
|---|---|---|---|---|---|---|
| SR-030 | Log bounded operational status, counts, error types, and HTTP status where useful; do not log raw feed/rich content, raw Gemini output, authorization headers, credentials, cookies, or response bodies. | Logs have a separate access and retention surface. | Partially met | [`fetch.py`](fetch.py): `_safe_fetch_error_text()` and response-length-only schema warnings; [`test_feed_rich_content.py`](test_feed_rich_content.py): rich-content log test; [`test_article_analysis.py`](test_article_analysis.py): error-body test | General Gemini exception paths print unsanitized exception text. See GAP-009. | New provider, SDK, debug mode, or tracing. |
| SR-031 | Sanitize exception messages before logging: remove local paths, control characters, request URLs containing content, headers, and overlong text. | Exceptions can include more context than intended. | Partially met | [`fetch.py`](fetch.py): `_safe_fetch_error_text()` implements bounded feed-error logging; [`test_feed_fetch_status.py`](test_feed_fetch_status.py) | The sanitizer is not consistently used by Gemini general-exception handling. See GAP-009. | Any error-handling change. |
| SR-032 | Treat generated JSON/HTML as intentionally public; treat screenshots and evaluation bundles according to their contents, not merely their file extension. | Visual and evaluation artifacts can capture local or raw model data. | Met | `data/` and `docs/` roles are defined in [STATUS.md](STATUS.md); [SECURITY_OPERATIONS.md](SECURITY_OPERATIONS.md) Version 1.0 sections 8–9 define classification, access, retention, minimized evidence, and the unconditional credential ban | The documentation contract is complete; platform log retention and existing-artifact inventory remain separate. See GAP-008. | New screenshot, review bundle, external sharing destination, or artifact-inventory review. |
| SR-033 | Confirm Actions log/artifact visibility and retention through repository-owner review; do not infer platform settings from workflow YAML. | Repository configuration does not reveal every GitHub-side control. | Partially met | No `upload-artifact` step exists in repository workflows; section 13 records public repository visibility and 90-day log/default artifact retention | Individual access events, actual notification delivery, and future per-artifact overrides remain outside recorded evidence. See GAP-010. | Repository visibility, organization policy, or workflow artifact use. |

The Draft 0.2 exception-output audit covered `fetch.py`, `daily_json.py`,
`vulnerability_facts.py`, every local module imported by the production path, and shell output
from both workflows. This table describes the current code paths only; BL-030 removed the
translation-endpoint row this audit previously also covered (see the Version 1.5 history above
and GAP-012):

| Path | Observed handling at the PR head |
|---|---|
| RSS / Atom retrieval | `_safe_fetch_error_text()` bounds common HTTP/network failures; XML parse errors are logged separately without a response body. |
| Standalone NIST NVD and ARTICLE / legacy BRIEF Gemini | `fetch_nist_nvd()`, `gemini_analyze()`, and `gemini_todays_brief()` have general exception paths that print raw exception text; Gemini paths also print the exception type. |
| Active NVD facts and KEV structured-source retrieval | `vulnerability_facts.py` prints raw network, decoding, parsing, and cache-write exception text in several paths. |
| Source-definition loader | `load_source_definitions()` does not directly print the path-bearing error; it raises it during module initialization, so an uncaught failure can reach workflow stderr with a traceback and local path. |
| Daily JSON, archive, and cache persistence | Some write, scan, validation, and archive-load failures are re-raised or later printed without the feed sanitizer and can expose a local path, URL, or validation value. |
| Workflow shell | No shell tracing or explicit secret dump is configured, but `python3 fetch.py`, Git, and uncaught Python failures can emit the application and command errors above to Actions stderr. |

No explicit traceback-printing helper or response-body logger was found. Uncaught Python
exceptions can still produce a traceback. GAP-009 covers the inconsistent exception-output
boundary; this Draft adds no sanitizer.

### 6.8 Availability and recovery

| ID | Requirement | Rationale | Current state | Evidence | Gap / exception | Re-evaluation trigger |
|---|---|---|---|---|---|---|
| SR-034 | Bound source timeouts and retries, apply proportionate external-response resource-consumption limits, and isolate source failures so one unavailable or oversized source does not produce unbounded retry, memory use, or response-body exposure. | External sources fail independently and can delay or exhaust scheduled generation. | Partially met | [`fetch.py`](fetch.py) and [`vulnerability_facts.py`](vulnerability_facts.py) use bounded timeouts/retries and post-parse or downstream limits; [`test_feed_fetch_status.py`](test_feed_fetch_status.py) | External HTTP responses are read without a consistent network byte cap before parsing. See GAP-015. | New source/provider, oversized response, memory/time failure, source SLA change, or repeated schedule overrun. |
| SR-035 | Record ARTICLE `success`, `fallback`, `failed`, and `not_attempted` states and preserve safe empty behavior when generation cannot produce validated output. | A failed AI call must not masquerade as successful analysis. | Met | [`fetch.py`](fetch.py): `gemini_analyze()`, `enrich_with_ai()`; [`daily_json.py`](daily_json.py): validation/status contracts; ARTICLE regression tests | Fallback is availability behavior, not proof of semantic correctness. | Status/fallback/validation change. |
| SR-036 | Use atomic writes, repository history, validated daily JSON, and offline HTML regeneration as the primary recovery mechanisms for the current scale. | These controls support recovery without introducing a new stateful service. | Met | [`daily_json.py`](daily_json.py): `atomic_write_json()`; [`fetch.py`](fetch.py): `atomic_write_text()`, `generate_archive_outputs()`; [`test_daily_json.py`](test_daily_json.py), [`test_archive.py`](test_archive.py) | GitHub service recovery objectives are outside repository evidence. | Database, external object store, or non-repository publication. |
| SR-037 | Detect scheduled-generation and Pages failures through existing Actions results and operator review; do not require 24/7 SOC monitoring for the current public static site. | Monitoring effort should reflect impact and architecture. | Partially met | Workflows have timeouts; [STATUS.md](STATUS.md) records run and Pages verification practices; section 13 verifies an Actions failure route and Pages visibility through Actions | Actual delivery success and recovery ownership remain outside recorded evidence. See GAP-010. | Paid service, confidential data, contractual uptime, forms/authentication, or critical operational dependency. |

The Draft 0.2 response-size audit found no consistent byte cap at the network `read()` boundary.
This table describes the current code paths only; BL-030 removed the translation row this
audit previously also covered (see the Version 1.5 history above and GAP-012):

| External response | Network read | Later bound, which is not a network byte cap |
|---|---|---|
| RSS / Atom | Entire response is read before XML parsing. | At most three feed items are selected after parsing; ARTICLE feed-native body input is then limited to 4,000 characters and stored `raw_excerpt` to 200 characters. |
| ARTICLE Gemini | Entire response is read before JSON parsing. | `maxOutputTokens` and response-schema limits constrain the provider contract, not bytes accepted from the network. |
| Legacy BRIEF Gemini | Entire response is read before JSON parsing; this boundary is not used by current deterministic-extractive production Brief. | Provider token/schema limits are not network byte caps. |
| Standalone NIST NVD | Entire response is read before JSON parsing; the source is currently disabled. | `resultsPerPage=3` is a server query parameter, not a local response byte cap. |
| Active NVD facts | Entire response is read before JSON parsing. | CVE requests are chunked to 100 identifiers, but response bytes remain unbounded. |
| CISA KEV structured source | The full catalog response is read before JSON parsing. | Article selection and normalization happen only after the catalog is in memory. |

GAP-015 records the hardening candidate. No response-reader implementation is changed here.

### 6.9 Change and review control

| ID | Requirement | Rationale | Current state | Evidence | Gap / exception | Re-evaluation trigger |
|---|---|---|---|---|---|---|
| SR-038 | Use a dedicated branch and pull request for each ticket; run ticket-focused tests, related regressions, the full unittest suite, and `git diff --check` before publication. | Security and integrity controls depend on reviewable, reproducible change evidence. | Met | [`AGENTS.md`](AGENTS.md): Approval boundaries and Testing and review; [`.github/workflows/pr-ci.yml`](.github/workflows/pr-ci.yml) runs the full suite and base/head diff check; [`test_pr_ci_workflow.py`](test_pr_ci_workflow.py) | Generated production commits are a separate authorized workflow rather than feature PRs. | Review-process or workflow change. |
| SR-039 | Confirm changed-file scope, inspect the final diff, preserve unrelated changes, and record review evidence before push, Ready, or merge. | Passing tests do not prove that only approved files changed. | Partially met | [`AGENTS.md`](AGENTS.md): Scope discipline, Approval boundaries, Git and generated output | This remains a required human/agent review step rather than an automated semantic scope check. | New automation capable of enforcing approved scope. |
| SR-040 | Require explicit authorization for production workflow execution, Pages operations, generated-output mutation, Ready, and merge; do not infer these permissions from edit/test approval. | Repository and production mutations have different impact and ownership. | Met | [`AGENTS.md`](AGENTS.md): Approval boundaries; [`.github/workflows/fetch.yml`](.github/workflows/fetch.yml) separates production triggers from PR CI | GitHub-side actor permissions are unverified outside the repository. | Repository role or workflow-trigger change. |
| SR-041 | For prompt, request-boundary, schema, validation, fallback, or workflow changes, perform the additional contract-specific review and mocked request/transport tests defined by project policy; real API or production diagnostics need separate approval. | High-risk boundary changes need evidence beyond generic unit tests. | Met | [`AGENTS.md`](AGENTS.md): Prompt and schema contracts, Gemini and production safety, Testing and review; mocked request tests in [`test_article_analysis.py`](test_article_analysis.py), [`test_vulnerability_facts_prompt.py`](test_vulnerability_facts_prompt.py), and [`test_todays_brief.py`](test_todays_brief.py) | The exact additional test set depends on the approved ticket. | Any listed contract or workflow change. |
| SR-042 | Keep acceptance-pending UI, writing-quality, brand, and security-requirements work open until the required user approval is recorded without inventing or paraphrasing a quote as verbatim evidence. | Merge evidence and user acceptance answer different questions. | Met | [`AGENTS.md`](AGENTS.md): Backlog provenance and completion; [BACKLOG.md](BACKLOG.md) state/completion rules; BL-015 remains pending | Objective technical tickets may close through defined non-subjective criteria where recorded. | Change to backlog completion policy or approval owner. |
| SR-043 | Define a correction, withdrawal, regeneration, and record procedure for published daily JSON or HTML when a major factual error, unsupported claim, subject or scope shift, or prompt-injection-derived output is confirmed. Decide in advance which HTML, daily JSON, and repository history are affected; align the procedure with SD-014; record the correction reason and impact scope. | Published generated content is durable and can affect reader decisions and trust. | Met | [SD-014](DECISIONS.md#sd-014--keep-daily-json-outside-the-github-pages-publication-tree-and-limit-stored-content) defines the storage/history boundary; [SECURITY_OPERATIONS.md](SECURITY_OPERATIONS.md) Version 1.0 sections 4 and 7 define correction, withdrawal priority, offline regeneration, evidence, emergency limits, and after-action review; [SD-025](DECISIONS.md#sd-025--approve-security-operations-version-10-and-the-minimal-incident-and-correction-policy) | The minimum procedure is documented without adding a correction schema/UI or executing a production correction. See GAP-014. | A confirmed published-output integrity issue; reevaluate the schema/UI contract if withdrawals or corrections recur. |

### 6.10 Source content-usage policy and AI provider data-use boundary

| ID | Requirement | Rationale | Current state | Evidence | Gap / exception | Re-evaluation trigger |
|---|---|---|---|---|---|---|
| SR-044 | Audit each configured source's official terms, license, or FAQ, and record a proposed content usage mode (`structured_open`, `feed_summary`, `limited_feed_analysis`, `metadata_only`, `disabled_legal_review`), confidence, unresolved issues, and a recheck trigger before assuming broader reuse than description/metadata is permitted. | Feed availability does not by itself authorize AI processing, public summarization, or content storage. | Partially met | [SOURCE_USAGE_POLICY.md](SOURCE_USAGE_POLICY.md) Approved 0.1 records the audit for all 17 configured sources, including official evidence URLs/types, confidence, and recheck triggers. `limited_feed_analysis` (`the_hacker_news`, `krebs_on_security`) is an explicit, bounded risk acceptance, not a determination that reuse is permitted. | This is an audit and policy record only; `source_definitions.json` has no `content_usage_mode` field and `fetch.py` does not enforce any mode in production. See GAP-016; enforcement is deferred to BL-032. | Any source-terms, license, or FAQ change; addition of a new source; BL-032 implementation. |
| SR-045 | Do not send publisher-derived article content to the Gemini API for AI processing or public summarization unless the Gemini API's data-use terms for the request path (`paid_verified` Cloud Billing-linked Project) have been owner-confirmed; treat `unpaid` or `unknown` status as requiring metadata-only handling for sources whose own terms do not clearly authorize AI processing. | Google's Gemini API terms treat Unpaid Services differently from Paid Services with respect to using submitted content for product/model improvement. | Met | [SOURCE_USAGE_POLICY.md](SOURCE_USAGE_POLICY.md) section 5 (Gemini data-use gate) records `gemini_data_use_status: paid_verified`, owner-confirmed 2026-07-29 via the Google AI Studio API Keys screen (the `security-digest` Google Cloud Project has active Cloud Billing, Tier 1 pay-as-you-go); no API key, Project ID, billing account ID, amount, or screenshot is recorded. | The Gemini-side data-use gate condition is satisfied. Per-source production enforcement of content usage modes remains deferred to BL-032 (see SR-044, GAP-016), and each source's own terms conditions (e.g. `google_tag`/`mandiant`'s classification under the Google Terms version confirmed effective 2026-07-30, see [SOURCE_USAGE_POLICY.md](SOURCE_USAGE_POLICY.md) section 8) are unaffected by this confirmation. See GAP-017. | Owner confirms a billing/Project/API-key change; Gemini API terms change. |
| SR-046 | Track each disabled source's re-enablement condition (`activation_condition`) explicitly, including any robots.txt, User-Agent-scope, or written-permission condition, and do not re-enable a source until its recorded condition is satisfied. | Ad hoc re-enablement without re-checking terms would undo the audit's purpose. | Partially met | [`source_definitions.json`](source_definitions.json): non-empty `activation_condition` for `cisa`, `crowdstrike`, `cloudflare`, and `dark_reading`; [`test_source_definitions.py`](test_source_definitions.py) | `nist_nvd` is disabled but its `activation_condition` field is an empty string; only its `notes` field records why standalone collection is off (a historical, pre-BL-030 note), not a re-enablement condition in the `activation_condition` field this requirement tracks. This Version does not add a `nist_nvd.activation_condition` value, since doing so would change a `source_definitions.json` field for a source other than Dark Reading, which is outside this Version's scope. | BL-032, or a future ticket that reconsiders standalone `nist_nvd` collection and records its `activation_condition`. |

## 7. Current control mapping

| Area | Requirement IDs | Current implementation | Evidence | Aggregate status | SR state breakdown |
|---|---|---|---|---|---|
| Input and content handling | SR-001–SR-005 | Common parsers, HTML normalization, bounded rich-content selection, `esc()`, `safe_url()`, source-definition review, and loader-time collection URL validation | [`fetch.py`](fetch.py), [`test_fetch.py`](test_fetch.py), [`test_feed_rich_content.py`](test_feed_rich_content.py), [`test_source_definitions.py`](test_source_definitions.py) | Met | Met 5 / Partial 0 / Not met 0 / Unverified 0 |
| Prompt and AI boundary | SR-006–SR-011 | Separate verified/untrusted JSON, allowlist projection, ARTICLE validation/fallback, no BRIEF API | [`fetch.py`](fetch.py), [`daily_json.py`](daily_json.py), [`test_article_internal_identifier_leak.py`](test_article_internal_identifier_leak.py), [`test_todays_brief.py`](test_todays_brief.py) | Met | Met 6 / Partial 0 / Not met 0 / Unverified 0 |
| Storage and publication | SR-012–SR-016 | Validated atomic daily JSON in `data/`, escaped HTML in `docs/`, bounded stored content, and documented external-artifact handling | [`daily_json.py`](daily_json.py), [`fetch.py`](fetch.py), [SECURITY_OPERATIONS.md](SECURITY_OPERATIONS.md), [SD-014](DECISIONS.md#sd-014--keep-daily-json-outside-the-github-pages-publication-tree-and-limit-stored-content) | Met | Met 5 / Partial 0 / Not met 0 / Unverified 0 |
| Secrets | SR-017–SR-020 | Production-only secret references, owner-verified configuration state, persistence tests, and documented rotation/revocation; no values recorded | [`.github/workflows/fetch.yml`](.github/workflows/fetch.yml), [`.github/workflows/pr-ci.yml`](.github/workflows/pr-ci.yml), [SECURITY_OPERATIONS.md](SECURITY_OPERATIONS.md), [`test_article_analysis.py`](test_article_analysis.py), section 13 | Partially met | Met 2 / Partial 2 / Not met 0 / Unverified 0 |
| GitHub Actions | SR-021–SR-026 | Explicit per-workflow permissions, isolated PR CI, production-only commit/push, documented production checkout credential rationale, full-commit-SHA Action pinning at the current major (v7), a serialized production concurrency group, and one production `workflow_dispatch` run validating the v7 checkout/commit/push path | [`.github/workflows/`](.github/workflows), [`test_pr_ci_workflow.py`](test_pr_ci_workflow.py), [`test_workflow_action_pinning.py`](test_workflow_action_pinning.py), [`test_fetch.py`](test_fetch.py), [BL-001](BACKLOG.md#bl-001--プルリクエストci), [BL-026](BACKLOG.md#bl-026--github-actions-supply-chainとproduction-concurrencyを強化する), [BL-027](BACKLOG.md#bl-027--github-actions-checkoutsetup-pythonをv7系へmajor-upgradeする), [PR #50](https://github.com/matkei31/security-digest/pull/50), [PR #54](https://github.com/matkei31/security-digest/pull/54), [run 30147337332](https://github.com/matkei31/security-digest/actions/runs/30147337332) | Partially met | Met 5 / Partial 1 / Not met 0 / Unverified 0 |
| Dependencies and supply chain | SR-027–SR-029 | Standard-library runtime; official Actions pinned to approved full commit SHAs at the current major (v7); weekly `github-actions` Dependabot providing the update path | Python imports, [`.github/workflows/`](.github/workflows), [`.github/dependabot.yml`](.github/dependabot.yml), [`test_workflow_action_pinning.py`](test_workflow_action_pinning.py), [BL-026](BACKLOG.md#bl-026--github-actions-supply-chainとproduction-concurrencyを強化する), [BL-027](BACKLOG.md#bl-027--github-actions-checkoutsetup-pythonをv7系へmajor-upgradeする), [PR #50](https://github.com/matkei31/security-digest/pull/50), [PR #54](https://github.com/matkei31/security-digest/pull/54) | Met | Met 3 / Partial 0 / Not met 0 / Unverified 0 |
| Logging and artifacts | SR-030–SR-033 | Bounded feed errors, no raw response persistence, documented external-artifact handling, and owner-verified default platform retention | [`fetch.py`](fetch.py), related logging tests, [SECURITY_OPERATIONS.md](SECURITY_OPERATIONS.md), section 13 | Partially met | Met 1 / Partial 3 / Not met 0 / Unverified 0 |
| Availability and recovery | SR-034–SR-037 | Bounded timeouts/retries, explicit statuses, atomic writes, repository history, and offline regeneration; response-size limits remain open | [`fetch.py`](fetch.py), [`daily_json.py`](daily_json.py), related tests | Partially met | Met 2 / Partial 2 / Not met 0 / Unverified 0 |
| Change and review control | SR-038–SR-043 | Dedicated branches/PRs, full unittest and diff CI, scope review, separate production authorization, contract-specific tests, and documented published-output correction | [`AGENTS.md`](AGENTS.md), [SECURITY_OPERATIONS.md](SECURITY_OPERATIONS.md), [`.github/workflows/pr-ci.yml`](.github/workflows/pr-ci.yml), [`test_pr_ci_workflow.py`](test_pr_ci_workflow.py) | Partially met | Met 5 / Partial 1 / Not met 0 / Unverified 0 |
| Source content-usage policy and AI provider data-use boundary | SR-044–SR-046 | Read-only official-terms audit of all 17 sources with proposed content usage modes ([SOURCE_USAGE_POLICY.md](SOURCE_USAGE_POLICY.md) Approved 0.1); owner-confirmed Gemini Paid Services gate (`paid_verified`); documented per-source `activation_condition` for disabled sources, except `nist_nvd` (empty `activation_condition`) | [SOURCE_USAGE_POLICY.md](SOURCE_USAGE_POLICY.md), [`source_definitions.json`](source_definitions.json), [`test_source_definitions.py`](test_source_definitions.py) | Partially met | Met 1 / Partial 2 / Not met 0 / Unverified 0 |
| Forms, authentication, database, and payments | Re-evaluation triggers only | No such component exists in the current repository | [`AGENTS.md`](AGENTS.md), current static generator and HTML | Not applicable now | No current SR count |
| GitHub/Pages/DNS settings outside the repository | SR-019, SR-024, SR-026, SR-033, SR-037 | Version 1.0 records the non-sensitive repository-owner settings verified in section 13; owner-specific delivery and rotation evidence remain limited | Repository-owner read-only checklist in section 13 | Partially met | Cross-cutting owner checks; not counted again in domain totals |

## 8. Gap register

These are register entries, not a claim that every item is a confirmed security defect.
`Security gap`, `Hardening candidate`, `Policy decision`, `Owner verification`, and
`Future trigger` distinguish current gaps from optional hardening, accepted choices,
repository-external checks, and future-only conditions. A current disposition approves
only the stated ticket, documentation, current state, residual risk, trigger, or verification;
it does not mean the underlying control is implemented.

| Gap ID | Classification | Current disposition | Related requirement | Description | Risk | Proportionality | Approved handling | Separate ticket | Trigger / timing |
|---|---|---|---|---|---|---|---|---|---|
| GAP-001 | Security gap | Implemented | SR-003 | The Version 1.1 baseline did not enforce `http`/`https` for outbound collection URLs. | A reviewed configuration error could select an unintended handler. | Small deterministic validation at an existing boundary. | BL-025 implemented loader-time validation in [`fetch.py`](fetch.py), covered by [`test_source_definitions.py`](test_source_definitions.py), user acceptance 「ok」, and [PR #48](https://github.com/matkei31/security-digest/pull/48), including its final head, Pull Request CI, and merge record. Collection and display URL roles remain distinct. | [BL-025](BACKLOG.md#bl-025--収集元urlをhttphttps-schemeへ制限する) | Implemented; re-evaluate on a collection method, collection URL field, or source-loader change. |
| GAP-002 | Policy decision | Implemented | SR-028 | Actions use major-version tags, not full commit SHAs. | Mutable tags provide weaker immutable provenance. | Pinning requires an update path but is proportionate for both workflows. | BL-026 pinned both workflows' `actions/checkout` (`11d5960a326750d5838078e36cf38b85af677262`, v4.4.0) and `actions/setup-python` (`a26af69be951a213d495a4c3e4e4022e16d87065`, v5.6.0) to verified full commit SHAs with version comments, covered by [`test_workflow_action_pinning.py`](test_workflow_action_pinning.py) and [`test_pr_ci_workflow.py`](test_pr_ci_workflow.py), with the weekly `github-actions` Dependabot in [`.github/dependabot.yml`](.github/dependabot.yml) as the update path, user acceptance 「ok」, and [PR #50](https://github.com/matkei31/security-digest/pull/50), including its final head, Pull Request CI, and merge record. Dependabot subsequently proposed a major-version update ([PR #51](https://github.com/matkei31/security-digest/pull/51)/[#52](https://github.com/matkei31/security-digest/pull/52)), and [BL-027](BACKLOG.md#bl-027--github-actions-checkoutsetup-pythonをv7系へmajor-upgradeする) re-pinned both workflows to `actions/checkout` v7.0.1 (`3d3c42e5aac5ba805825da76410c181273ba90b1`) and `actions/setup-python` v7.0.0 (`5fda3b95a4ea91299a34e894583c3862153e4b97`) via a replacement PR ([#54](https://github.com/matkei31/security-digest/pull/54)) rather than merging the Dependabot PRs directly, with user acceptance 「ok」, its merge record, and production validated by one authorized `workflow_dispatch` run ([run 30147337332](https://github.com/matkei31/security-digest/actions/runs/30147337332)). | [BL-026](BACKLOG.md#bl-026--github-actions-supply-chainとproduction-concurrencyを強化する); [BL-027](BACKLOG.md#bl-027--github-actions-checkoutsetup-pythonをv7系へmajor-upgradeする) | Implemented; re-evaluate on Action advisory, new release, major upgrade, new Action, or workflow expansion. |
| GAP-003 | Policy decision | Implemented | SR-029 | GitHub Actions update automation is absent. | Action updates may be noticed late. | Only the `github-actions` ecosystem is needed now. | BL-026 added [`.github/dependabot.yml`](.github/dependabot.yml) with a single `github-actions` ecosystem entry, `directory: "/"`, and a weekly schedule, with no reviewers, assignees, labels, target-branch, open-PR limit, registries, groups, or ignore rules; covered by [`test_workflow_action_pinning.py`](test_workflow_action_pinning.py), user acceptance 「ok」, and [PR #50](https://github.com/matkei31/security-digest/pull/50), including its final head, Pull Request CI, and merge record. | [BL-026](BACKLOG.md#bl-026--github-actions-supply-chainとproduction-concurrencyを強化する) | Implemented. |
| GAP-004 | Hardening candidate | Implemented | SR-025 | Production generation has no concurrency group. | Scheduled and manual writers could race. | A serialized group is proportionate but low priority. | BL-026 added a workflow-level `concurrency` block to [`.github/workflows/fetch.yml`](.github/workflows/fetch.yml) with a fixed `group: daily-security-digest-production` and `cancel-in-progress: false`, serializing `schedule` and `workflow_dispatch` in a group distinct from PR CI's; no independent queue was added, and GitHub's standard pending-run replacement semantics are accepted as-is. No production execution occurred during BL-026 implementation. Covered by [`test_fetch.py`](test_fetch.py), user acceptance 「ok」, and [PR #50](https://github.com/matkei31/security-digest/pull/50), including its final head, Pull Request CI, and merge record. [BL-027](BACKLOG.md#bl-027--github-actions-checkoutsetup-pythonをv7系へmajor-upgradeする) subsequently exercised this workflow once via one authorized `workflow_dispatch` run ([run 30147337332](https://github.com/matkei31/security-digest/actions/runs/30147337332)), which completed under the same concurrency configuration without incident; the concurrent-overlap scenario itself (two simultaneous triggers) remains unobserved in production. | [BL-026](BACKLOG.md#bl-026--github-actions-supply-chainとproduction-concurrencyを強化する); [BL-027](BACKLOG.md#bl-027--github-actions-checkoutsetup-pythonをv7系へmajor-upgradeする) | Implemented; before frequency increases or after overlap/push conflict. |
| GAP-005 | Policy decision | Accepted current state | SR-023 | Production checkout retains its credential for a later `git push`. | The token remains available to later job steps. | The job executes official Actions and repository code and requires the push. | Keep default persistence; reevaluate if checkout, job composition, or publication changes. | None now | Checkout or publication redesign. |
| GAP-006 | Policy decision | Completed by documentation | SR-020 | The Version 1.0 baseline lacked a minimum secret rotation and revocation procedure. | Response may be delayed after suspected leakage if the documented procedure is not followed. | A short operations document is proportionate. | [SECURITY_OPERATIONS.md](SECURITY_OPERATIONS.md) Version 1.0 defines rotation, revocation, suspected leakage, and minimal response. | [BL-024](BACKLOG.md#bl-024--最小security-operationsと公開済み生成物の訂正手順を定義する); [SD-025](DECISIONS.md#sd-025--approve-security-operations-version-10-and-the-minimal-incident-and-correction-policy) | Completed by documentation; apply before another secret is added and immediately on suspected leakage. |
| GAP-007 | Future trigger | Deferred until trigger | SR-029 | No concrete dependency ownership/provenance/update checklist exists. | A future dependency could receive inconsistent review. | No runtime third-party dependency exists today. | Define a compact checklist before the first runtime dependency or new third-party Action. | Not yet | First runtime dependency or third-party Action. |
| GAP-008 | Policy decision | Completed by documentation | SR-015, SR-032 | The Version 1.0 baseline lacked a common retention/access/disposal rule for repository-external evaluation artifacts. | Detailed artifacts may persist longer than intended if the documented rule is not applied. | A small default and per-evaluation exceptions are sufficient. | [SECURITY_OPERATIONS.md](SECURITY_OPERATIONS.md) Version 1.0 sets a 90-day detailed-artifact default, sanitized long-term evidence priority, credential prohibition, and recorded longer-retention exceptions. Existing artifacts are reviewed at the next inventory; this update deletes none. | [BL-024](BACKLOG.md#bl-024--最小security-operationsと公開済み生成物の訂正手順を定義する); [SD-025](DECISIONS.md#sd-025--approve-security-operations-version-10-and-the-minimal-incident-and-correction-policy) | Completed by documentation; apply to new artifacts and the next artifact inventory. |
| GAP-009 | Security gap | Remains open for later prioritization | SR-017, SR-030, SR-031 | Exception handling can bypass `_safe_fetch_error_text()` on several paths. | Raw exception text or uncaught tracebacks can expose paths, URLs, or validation context. | Public inputs reduce confidentiality impact, but log hygiene remains a real gap. | Keep open; do not add a sanitizer without a separately prioritized ticket. | Not yet | Debug logging, another provider, or confirmed sensitive diagnostic leak. |
| GAP-010 | Owner verification | Completed owner verification | SR-019, SR-024, SR-026, SR-033, SR-037 | GitHub/Pages configuration required owner-side confirmation. | Repository-only evidence could overstate coverage. | Read-only confirmation is sufficient; no setting change is implied. | Required non-sensitive settings were verified and are recorded in section 13. Owner-specific delivery confirmation remains limited. | None | Relevant GitHub setting, ownership, visibility, workflow, secret inventory, or Pages change. |
| GAP-011 | Future trigger | Deferred until trigger | SR-012, SR-037 | BL-007 completed the `monomidigest.com` cutover using an approved custom-domain security preflight (ownership; verified-domain/domain verification; dangling DNS and takeover prevention; safe Pages/DNS cutover and teardown order; registrar MFA, auto-renew, expiration protection, and registrar/transfer lock; repository rename impact; HTTPS, canonical URLs, redirects, rollback, and responsible ownership), exercised once for the initial rollout (see SD-028). | An unsafe future teardown, rollback, or repository-rename change could still leave a dangling binding if it does not repeat this preflight. | This is not a current-site security gap because the custom domain is now live and reflects the approved preflight; no further DNS or Pages change is planned by this Version. | Repeat the same BL-007 preflight (ownership; verified-domain/domain verification; dangling DNS and takeover prevention; safe Pages/DNS cutover and teardown order; registrar MFA, auto-renew, expiration protection, and registrar/transfer lock; repository rename impact; HTTPS, canonical URLs, redirects, rollback, and responsible ownership) before any further custom-domain DNS or Pages change. | [BL-007](BACKLOG.md#bl-007--monomidigestcomへの移行) | Before any further custom-domain DNS or Pages change (teardown, rollback, or repository rename). |
| GAP-012 | Policy decision | Resolved by BL-030 | SR-001, SR-030 | Previously: the unofficial translation endpoint received bounded public article text in a URL query, and `docs/translate_cache.json` persisted provider output in the repository and Pages across days, with no cache TTL or provider-response integrity validation. | Resolved; no longer a live risk. | N/A (resolved). | [BL-030](BACKLOG.md#bl-030--取得元翻訳経路の緊急リスク低減) removed the unofficial translation endpoint (`load_cache()`, `save_cache()`, `translate()`) from [`fetch.py`](fetch.py) and deleted `docs/translate_cache.json` from the repository tree (no history rewrite); `resolve_display_title()` now falls back only to `raw_title`. Accepted by the user at [PR #66](https://github.com/matkei31/security-digest/pull/66) and recorded in [SD-029](DECISIONS.md#sd-029--temporarily-remove-the-unofficial-translation-path-and-suspend-crowdstrike-and-cloudflare-pending-source-terms-review). | [BL-030](BACKLOG.md#bl-030--取得元翻訳経路の緊急リスク低減) | Resolved; re-open only if an unofficial or unreviewed translation path is reintroduced. |
| GAP-013 | Policy decision | Completed by documentation | SR-020, SR-033 | The Version 1.0 baseline lacked a compact security-incident/credential-leakage response procedure. | Containment and evidence preservation may be improvised if the documented procedure is not followed. | A minimal procedure is proportionate. | [SECURITY_OPERATIONS.md](SECURITY_OPERATIONS.md) Version 1.0 defines assessment, containment, credential paths, sanitized evidence, closure, and the limited emergency exception. | [BL-024](BACKLOG.md#bl-024--最小security-operationsと公開済み生成物の訂正手順を定義する); [SD-025](DECISIONS.md#sd-025--approve-security-operations-version-10-and-the-minimal-incident-and-correction-policy) | Completed by documentation; apply immediately after an incident. |
| GAP-014 | Security gap | Completed by documentation | SR-043 | The Version 1.0 baseline lacked a published-output correction, withdrawal, regeneration, and repository-history procedure. | A major factual error or unsupported output can harm readers and trust. | A discovery-time procedure is proportionate; 24/7 monitoring is not required. | [SECURITY_OPERATIONS.md](SECURITY_OPERATIONS.md) Version 1.0 defines HTML/daily-JSON/history treatment, withdrawal priority, offline regeneration, reason/scope evidence, SD-014 alignment, and the first-use schema/UI boundary. | [BL-024](BACKLOG.md#bl-024--最小security-operationsと公開済み生成物の訂正手順を定義する); [SD-025](DECISIONS.md#sd-025--approve-security-operations-version-10-and-the-minimal-incident-and-correction-policy) | Completed by documentation; apply if an issue is confirmed and reevaluate the contract on recurrence. |
| GAP-015 | Hardening candidate | Deferred until trigger | SR-034 | External responses have no common network byte cap before parsing. | Oversized responses can increase memory use or delay generation. | The audit records that no incident was found; endpoint-specific limits need separate design. | Defer until a new source/provider, oversized response, or memory/time failure. | Not yet | New source/provider, oversized response, or observed memory/time failure. |
| GAP-016 | Security gap | Remains open for later prioritization | SR-044 | [SOURCE_USAGE_POLICY.md](SOURCE_USAGE_POLICY.md) Approved 0.1 assigns a content usage mode (including the new `limited_feed_analysis` risk-acceptance mode) to each of the 17 sources, but `source_definitions.json` has no `content_usage_mode` (or equivalent) field, and `fetch.py`'s common `content:encoded`/Atom-content selection, Gemini input, storage, and public-summary paths do not enforce any per-source mode. | A `feed_summary`, `limited_feed_analysis`, or `metadata_only` source is currently processed the same as a `structured_open` source in production code; the audit's proposed restrictions are not technically enforced. | The Approved 0.1 audit itself is a proportionate first step; enforcement is a larger, separately reviewable implementation. | Keep open until BL-032 implements `content_usage_mode` fields and enforcement in `fetch.py`, with its own tests. Do not treat the BL-031 audit alone as closing this gap. | [BL-032](BACKLOG.md#bl-032--取得元別content-usage-policy-enforcement) (registered; 要件定義済み／未着手) | BL-032 implementation; any confirmed production processing of a `feed_summary`/`limited_feed_analysis`/`metadata_only` source beyond its recorded mode. |
| GAP-017 | Owner verification | Completed owner verification | SR-045 | `gemini_data_use_status` was `unknown`; the repository owner has confirmed, via the Google AI Studio API Keys screen on 2026-07-29, that the `security-digest` Google Cloud Project used for the Gemini API key has active Cloud Billing (Tier 1, pay-as-you-go). | Resolved for the Gemini-side data-use question: submitted content is not subject to Unpaid Services product/model-improvement use for this Project, as owner-verified. | Owner confirmation was proportionate: a non-confidential yes/no on active billing, without recording API keys, billing amounts, account IDs, or screenshots. | Confirmed 2026-07-29: `security-digest` Project, active Cloud Billing, Tier 1 pay-as-you-go. This confirms the Gemini-side condition only; per-source production enforcement of content usage modes and each source's own terms conditions are unaffected and remain governed by SR-044/GAP-016 and [SOURCE_USAGE_POLICY.md](SOURCE_USAGE_POLICY.md) respectively. | [SOURCE_USAGE_POLICY.md](SOURCE_USAGE_POLICY.md) section 5; [BL-032](BACKLOG.md#bl-032--取得元別content-usage-policy-enforcement) (registered) | Billing cancellation, Project change, or API key migration; re-verify if any occurs. |

## 9. Explicitly non-required controls for the current architecture

These controls are not declared permanently unnecessary. They are not normally required for
the current static, public-information architecture:

| Control | Current disposition and reason |
|---|---|
| WAF | Not applicable now: there is no repository-operated dynamic origin or inbound application endpoint. Re-evaluate with an API, form, or hosted dynamic service. |
| Application login security | Not applicable now: the site has no application accounts or login flow. Re-evaluate before authentication is added. |
| Session management | Not applicable now: no application sessions exist. Re-evaluate with authentication or stateful user interaction. |
| Database encryption and customer-data retention controls | Not applicable now: no database or customer-data store exists. Public repository data still follows the storage requirements above. |
| Payment security / PCI controls | Not applicable now: there is no payment flow or cardholder data. |
| Dedicated DDoS service | Not required now beyond the hosting platform's normal service: there is no separately operated origin. Re-evaluate if availability becomes contractual or an origin is introduced. |
| 24/7 SOC monitoring | Not proportionate to the present public static digest. Existing Actions/Pages results and operator review are the baseline. |
| Dynamic application scanning (DAST) | Not applicable to a static generator with no dynamic endpoint. Continue unit tests and review; re-evaluate if an application/API appears. |
| Container and Kubernetes security | Not applicable now: no container image, cluster, or Kubernetes manifest is part of the architecture. |
| Dedicated SAST product | Not automatically required for this standard-library project. Re-evaluate with dependency growth, an interactive service, or a confirmed need; current PR CI and review remain required. |
| Mandatory CSP in this Draft | Not approved as a new control here. Re-evaluate before third-party scripts, analytics, forms, or a custom domain materially changes browser-side risk. |
| Paid secret-scanning features | Not required by Version 1.0. Repository-owner settings and available platform controls must be reviewed without assuming a paid feature. |

## 10. Re-evaluation triggers

Review affected requirements before:

- introducing `monomidigest.com`;
- changing DNS, redirects, HTTPS/Pages binding, or canonical URL configuration;
- adding forms, authentication, sessions, or user-submitted content;
- adding a database, object store, or other persistent storage;
- adding analytics, tracking, advertising, or a third-party browser script;
- adding a runtime dependency or a new third-party GitHub Action;
- adding a new AI or translation provider;
- changing repository visibility;
- handling private, confidential, personal, customer, or regulated data;
- adding a webhook, application API, or other inbound endpoint;
- adding a workflow or job with write permission;
- expanding the generated-output, log, cache, or artifact storage scope;
- reintroducing generative BRIEF output or changing ARTICLE prompt/schema/validation/fallback;
- changing Pages source, publication branch, or hosting platform;
- increasing production frequency or adding another generated-output writer.

An incident, suspected credential leak, source compromise, Action compromise, or unexplained
public-output injection triggers immediate review rather than waiting for planned maintenance.

## 11. Approved roadmap decisions

The user approved the original complete decision brief with 「ok」. Version 1.0 recorded these
proportionate roadmap decisions, and Version 1.1 preserves them:

- validate collection URLs as `http` or `https` in a separate implementation ticket;
- pin both workflows' Actions to full commit SHAs and add weekly `github-actions` Dependabot in
  the same follow-up ticket;
- serialize production generation with `cancel-in-progress: false` in that low-priority workflow
  hardening ticket;
- accept production checkout credential persistence in the current official-Actions and
  repository-code job because a later `git push` requires it;
- define secret rotation, incident response, published-output correction, and external-artifact
  handling in one compact `SECURITY_OPERATIONS.md` documentation ticket; this documentation is
  now completed by Version 1.0 of that document;
- use 90 days as the default for detailed raw request/response evaluation artifacts, retain
  summaries, manifests, and BL/SD decision evidence as needed, prohibit credentials and
  unnecessary local absolute paths, and document any longer exception per evaluation;
- complete GAP-010 through a read-only owner checklist before approval;
- integrate custom-domain security preflight into BL-007;
- accept the unofficial translation endpoint only for bounded public information;
- leave GAP-009 open for later prioritization; and
- defer a network response byte cap until its listed trigger.

These decisions approve follow-up scope, not implementation or production execution. The
"accept the unofficial translation endpoint only for bounded public information" decision above
is a historical record of the Version 1.0 baseline; it was superseded by [BL-030](BACKLOG.md#bl-030--取得元翻訳経路の緊急リスク低減),
which removed that endpoint and `docs/translate_cache.json` entirely (see GAP-012 and
[SD-029](DECISIONS.md#sd-029--temporarily-remove-the-unofficial-translation-path-and-suspend-crowdstrike-and-cloudflare-pending-source-terms-review)).
Version 1.5 additionally records these new roadmap items from BL-030/BL-031:

- treat CrowdStrike, Cloudflare, and Dark Reading as temporarily suspended
  (`enabled: false`) pending confirmation of their documented `activation_condition`, not as a
  final legal determination that they violated terms;
- record a per-source content usage mode audit for all 17 configured sources in
  [SOURCE_USAGE_POLICY.md](SOURCE_USAGE_POLICY.md) Approved 0.1, without implementing production
  enforcement of any mode (deferred to [BL-032](BACKLOG.md#bl-032--取得元別content-usage-policy-enforcement),
  registered as a 要件定義済み／未着手 ticket);
- require owner confirmation of Gemini API Paid/Unpaid Services status before sending
  publisher-derived content from `feed_summary`-classified sources to Gemini (GAP-017), without
  making that confirmation a condition of this Version's own approval;
- completed 2026-07-30: re-confirmed the Google Terms version that took effect that day for
  `google_tag` (and, indirectly, `mandiant`'s Google Cloud blog); classification and confidence
  were unchanged. Further re-confirmation is required only on a subsequent Google Terms
  revision, or on the source-specific recheck triggers recorded in
  [SOURCE_USAGE_POLICY.md](SOURCE_USAGE_POLICY.md) (official Feed URL/path change,
  Google Cloud Threat Intelligence or Security Blog/Blogger-specific condition change,
  machine-readable-instructions change, official RSS guidance change or termination).

## 12. Approval and maintenance

- Version 1.4 is approved as a maintenance update to the Version 1.0 baseline.
- Fable 5 review has been incorporated: Critical 0, High 0; accepted and modified findings are
  reflected, and the rejected F-004 consolidation was not applied. Fable 5 did not inspect `STATUS.md` or
  `test_security_requirements.py`; those files were independently checked at the PR head.
- The user answered 「ok」 to the complete decision brief that proposed the Version 1.0 policy,
  GAP-010 owner verification, proportional dispositions, and follow-up ticket boundaries.
- The user separately approved Security Operations Version 1.0 with 「ok」; Version 1.1 records
  SR-015, SR-020, SR-032, and SR-043 as Met and GAP-006, GAP-008, GAP-013, and GAP-014 as
  `Completed by documentation`, without claiming runtime implementation.
- The user separately accepted the completed BL-025 collection URL scheme validation with
  「ok」. Version 1.2 records SR-003 as Met and GAP-001 as `Implemented`. That acceptance is
  limited to the loader-time collection URL contract; it does not approve hostname allowlists,
  private-address, DNS, redirect, port, or TLS controls, new display-URL validation, or a
  production execution.
- The user separately accepted the corrected BL-026 GitHub Actions supply-chain and
  production-concurrency implementation with 「ok」 at [PR #50](https://github.com/matkei31/security-digest/pull/50)
  head `394dd157395b69e86928d98a376386131474b20f`. Version 1.3 records SR-025, SR-028, and
  SR-029 as Met and GAP-002, GAP-003, and GAP-004 as `Implemented`. That acceptance is limited
  to full-commit-SHA Action pinning, the weekly `github-actions`-only Dependabot configuration,
  and the workflow-level production concurrency group with `cancel-in-progress: false`; it does
  not approve future Action upgrades, new runtime dependencies, new third-party Actions,
  production execution, `workflow_dispatch`, or GitHub/Pages setting changes.
- The user separately accepted the BL-027 GitHub Actions major-version upgrade with 「ok」 at
  [PR #54](https://github.com/matkei31/security-digest/pull/54) head
  `d7461b9adfe474793a60f61cd6fe8b219153b499`, merged as
  `69f7da859e1856beffac9fa381f0f0cc92564e36`. Version 1.4 updates SR-025's and SR-028's evidence
  to `actions/checkout` v7.0.1 and `actions/setup-python` v7.0.0 and records that the user then
  separately and explicitly authorized a one-time production `workflow_dispatch` run (departing
  from the originally planned "wait for the next ordinary schedule" validation) to verify the
  checkout/commit/push path under v7. That run
  ([run 30147337332](https://github.com/matkei31/security-digest/actions/runs/30147337332))
  generated commit `226db6285021d9daf98fe2941248b7f5b20ba143` and pushed it successfully, and
  the automatic Pages deployment that followed succeeded. This acceptance is limited to the
  Action version upgrade and its one-time `workflow_dispatch` validation; it does not establish
  `workflow_dispatch` as a standing validation method, and it does not approve future Action
  upgrades, new runtime dependencies, new third-party Actions, or GitHub/Pages setting changes.
- This remains policy approval. It is not blanket preapproval
  for later security-control pull requests, production execution, or GitHub setting changes.
- Each implementation or documentation ticket still requires its normal approved scope, tests,
  review, and merge procedure.
- This document does not impose a mechanical annual-update cycle. Update it when a
  re-evaluation trigger occurs, an incident reveals a missing boundary, or the user approves a
  material security-policy change.
- [SD-024](DECISIONS.md#sd-024--approve-security-requirements-version-10-and-the-proportionate-security-roadmap)
  records the Version 1.0 baseline approval, and
  [SD-025](DECISIONS.md#sd-025--approve-security-operations-version-10-and-the-minimal-incident-and-correction-policy)
  records the Version 1.1 maintenance basis without replacing existing security decisions or
  implementation-agent boundaries. Version 1.2 was the BL-025 maintenance update, Version 1.3
  was the BL-026 maintenance update, and Version 1.4 is the BL-027 maintenance update, all under
  the already-approved SD-024 roadmap; none creates a new Stable Decision.
- **Version 1.5 is an Approved maintenance update, recorded by
  [SD-030](DECISIONS.md#sd-030--approve-source-usage-policy-version-01-and-defer-runtime-enforcement-to-bl-032).**
  It records: (1) the user-accepted [BL-030](BACKLOG.md#bl-030--取得元翻訳経路の緊急リスク低減) at
  [PR #66](https://github.com/matkei31/security-digest/pull/66), which removed the unofficial
  translation endpoint and `docs/translate_cache.json` (GAP-012 now `Resolved by BL-030`; see
  [SD-029](DECISIONS.md#sd-029--temporarily-remove-the-unofficial-translation-path-and-suspend-crowdstrike-and-cloudflare-pending-source-terms-review));
  and (2) the completed [BL-031](BACKLOG.md#bl-031--全取得元の公式規約監査とセキュリティ文書整合化)
  read-only audit of all 17 configured sources against their official terms, recorded in
  [SOURCE_USAGE_POLICY.md](SOURCE_USAGE_POLICY.md) Approved 0.1 (new SR-044–SR-046, new
  GAP-016–GAP-017), together with the resulting temporary suspension of Dark Reading. BL-031
  does not implement any production enforcement of a content usage mode; that remains the scope
  of the registered [BL-032](BACKLOG.md#bl-032--取得元別content-usage-policy-enforcement) ticket
  (要件定義済み／未着手). [PR #67](https://github.com/matkei31/security-digest/pull/67) accepted head
  `897fc9db365e890318fc694a7fbf9cd8eab65ae1` received a final ChatGPT independent review with no
  remaining implementation or documentation blockers; [Pull Request CI run
  30557479373](https://github.com/matkei31/security-digest/actions/runs/30557479373) succeeded;
  full unittest was 1391 tests OK; unresolved review threads were 0. The user then approved BL-031's
  acceptance, Ready status, and a regular merge-commit merge (merge commit
  `61feb679fad6bd2252c58cd8acb4696294032629`), and on 2026-07-31 approved this Version's own
  Approved status via [SD-030](DECISIONS.md#sd-030--approve-source-usage-policy-version-01-and-defer-runtime-enforcement-to-bl-032),
  without reopening SD-024, SD-025, SD-028, or SD-029. **This approval covers the audit and policy
  record described above; it is not a pre-approval of BL-032's runtime enforcement implementation,
  of production execution, of `workflow_dispatch`, or of any GitHub-side setting change** — those
  remain subject to their own separate review and acceptance when BL-032 is implemented.

## 13. Repository-owner verification

GAP-010 was completed read-only on 2026-07-24. The table records only non-sensitive setting
states; it contains no secret value, token, notification address, personal account name, or
platform-internal identifier.

| Area | Check | Result | Evidence boundary | Recheck trigger |
|---|---|---|---|---|
| Repository | Visibility (mandatory) | Verified — public | Repository settings and metadata | Visibility or ownership change |
| Repository | Default branch (mandatory) | Verified — `main` | Repository settings and metadata | Default-branch change |
| Repository | Main branch protection or ruleset (mandatory) | Not configured | Branch and ruleset settings | Protection/ruleset change |
| Repository | Force-push blocking (mandatory) | Not configured | No main protection or ruleset currently blocks it | Protection/ruleset change |
| Repository | Branch-deletion blocking (mandatory) | Not configured | No main protection or ruleset currently blocks it; platform default-branch constraints remain separate | Protection/ruleset or default-branch change |
| Repository | Required pull request | Not configured | Branch and ruleset settings | Protection/ruleset change |
| Repository | Required status checks | Not configured | Branch and ruleset settings | Protection/ruleset change |
| Repository | Administrator/ruleset bypass | Not applicable | No main protection or ruleset is configured | First protection/ruleset |
| Repository | Archive state | Verified — active | Repository metadata | Archive-state change |
| Repository | Management form | Verified — personal-account repository | Repository metadata; no individual name recorded | Ownership transfer |
| Actions | Allowed Actions and reusable workflows | Verified — all allowed | Repository Actions settings | Actions-policy change |
| Actions | Full-length SHA requirement | Not configured | Repository Actions settings | Actions-policy change |
| Actions | Default workflow token permission (mandatory) | Verified — read repository contents and packages | Repository Actions settings; production job separately requests `contents: write` | Permission or workflow change |
| Actions | Workflow pull-request creation/approval | Not configured | Repository Actions settings | Actions-policy change |
| Actions | Fork PR approval policy (mandatory) | Verified — first-time contributors require approval | Repository Actions settings | Fork-policy change |
| Actions | `workflow_dispatch` permission range (mandatory) | Verified — repository users with write access under the repository permission model | Repository access model and production workflow trigger | Role, permission, or trigger change |
| Actions | Log and default artifact retention (mandatory) | Verified — 90 days | Repository Actions settings | Retention-policy change |
| Actions | Environment | Verified — `github-pages`; selected deployment branch only | Environment settings | Environment/protection change |
| Actions | Required production secret `GEMINI_API_KEY` (mandatory) | Verified — configured as repository secret | Secret name and configuration state only | Secret inventory or workflow-reference change |
| Actions | Optional production secret `NVD_API_KEY` | Not configured — repository secret | Secret name and configuration state only; code permits absence | Requirement or workflow-reference change |
| Pages | Enabled and publication mode (mandatory) | Verified — branch publication | Pages settings | Pages mode change |
| Pages | Source branch/directory (mandatory) | Verified — `main` / `docs` | Pages settings | Branch, directory, or repository rename |
| Pages | HTTPS enforcement (mandatory) | Verified — enforced | Pages settings | Domain or HTTPS-setting change |
| Pages | Custom domain (mandatory) | Verified — configured as `monomidigest.com` (completed by [BL-007](BACKLOG.md#bl-007--monomidigestcomへの移行), [SD-028](DECISIONS.md#sd-028--migrate-github-pages-to-monomidigestcom-as-the-primary-custom-domain)); superseding the "Not configured" state recorded through Version 1.4 | Pages settings; `docs/CNAME` | Custom-domain, DNS, or Pages-source change |
| Pages | Domain verification | Verified — ownership-verification TXT confirmed and domain shows Verified in Pages settings (`protected_domain_state: verified`) | Pages settings; XServer DNS TXT record | Domain-verification or DNS-provider change |
| Pages | Visibility and public URL | Verified — public project site | Repository and Pages settings | Visibility, ownership, or repository rename |
| Notifications | Actions failure route | Verified — failed-workflow notification route enabled | Account settings; destination and delivery success are not recorded | Notification-policy or ownership change |
| Notifications | Pages failure recognition | Verified — Pages build/deploy appears in Actions and uses the failure route | Pages and notification settings | Pages publication-mode change |
| Security | Dependabot alerts | Not configured | Repository security settings; dependency graph is also disabled | Security-setting or dependency change |
| Security | Secret scanning | Verified — enabled | Repository security settings | Security-setting change |
| Security | Push protection | Verified — enabled | Repository security settings | Security-setting change |
| Security | Private vulnerability reporting | Not configured | Repository security settings | Reporting-policy change |
| Security | CodeQL default setup | Not configured | Repository security settings | Code-scanning change |
| Security | Organization code-security configuration | Not applicable | Personal-account repository; individual repository settings were reviewed | Ownership transfer |
| AI provider (non-mandatory, new in Version 1.5) | Gemini API Paid/Unpaid Services status (`gemini_data_use_status`) | Verified — `paid_verified` (confirmed 2026-07-29 via the Google AI Studio API Keys screen: the `security-digest` Google Cloud Project has active Cloud Billing, Tier 1 pay-as-you-go; no API key, Project ID, billing account ID, amount, or screenshot recorded) | Whether the Gemini API key used in production is associated with an active Cloud Billing account on its Project; only a yes/no is needed, not billing amounts or account identifiers (see GAP-017, [SOURCE_USAGE_POLICY.md](SOURCE_USAGE_POLICY.md) section 5) | Billing cancellation, Project change, or API key migration; re-verify if any occurs |

Mandatory checklist items contain no `Unverified — owner access required` result. The new
AI-provider row above is explicitly non-mandatory for this Version and does not block Version
1.5's own scope; it is recorded because BL-032 needs it before enabling `feed_summary` sources'
AI processing. Owner-specific notification destination, actual delivery, credential access
audit, and last-rotation evidence remain outside the recorded evidence boundary; this limited
remainder is not a Version 1.0 blocker.
