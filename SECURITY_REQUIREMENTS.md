# Security Digest Security Requirements

- **Version:** Draft 0.2
- **Status:** Fable 5 review incorporated; user approval pending
- **As of:** 2026-07-24
- **Scope:** Current static GitHub Pages site and its repository-backed generation pipeline
- **Out of scope:** Security-control implementation in this PR

This is an architecture security-requirements draft, not the GitHub vulnerability-reporting
policy normally placed in a `SECURITY.md` file. Draft 0.2 records requirements, repository
evidence, register entries, proportional exclusions, and review questions. It does not approve
or implement a gap response.

Fable 5 reviewed Draft 0.1 as proportional to the current architecture and suitable for
continued review, with no Critical or High findings. Draft 0.2 incorporates the user's
adjudication of F-001 through F-009. Fable 5 could not retrieve `STATUS.md` or
`test_security_requirements.py`; those two files were instead checked independently at the
PR head. This review incorporation is not user approval and does not implement any control.

## 1. Purpose and proportionality

Security Digest collects public cybersecurity information, produces daily JSON, and publishes
static HTML. The repository contains no application login, form submission, payment flow, or
personal-information database. Its risk profile is therefore different from an interactive
service that stores customer data.

The architecture nevertheless has boundaries that need protection:

- production GitHub Actions uses write permission and credentials;
- external RSS, Atom, JSON, translation, NVD, KEV, and Gemini inputs cross trust boundaries;
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
- the summary-translation call and `docs/translate_cache.json` cache in [`fetch.py`](fetch.py);
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
- the future `monomidigest.com` custom domain tracked by
  [BL-007](BACKLOG.md#bl-007--monomidigestcomへの移行), which is not implemented in this
  repository.

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
             +----> bounded public summary text ----> translation endpoint
             |                                        |
             |                                        v
             |                              docs/translate_cache.json
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
written to normal logs, daily JSON, generated HTML, or the translation cache.
Repository-external screening may retain requests, responses, evaluations, manifests, or
screenshots only under the separate artifact-handling requirements below.

## 4. Assets and data classification

| Asset | Classification | Repository storage | Public exposure and retention |
|---|---|---|---|
| GitHub and external-provider credentials | Secret | Prohibited | Never public; values, existence, access controls, and rotation state are not verifiable from this repository |
| Workflow write permission and checkout credential | Privileged capability | Workflow configuration is stored; credential value is not | Configuration is public; runtime credential must be limited to its workflow purpose and lifetime |
| Source configuration | Trusted configuration / public | Allowed in `source_definitions.json` | Public and versioned; changes require review because they control outbound inputs |
| Prompt, schema, validation, and fallback contracts | Integrity-sensitive source | Allowed and required | Public and versioned; changes require contract-specific review and tests |
| Daily JSON in `data/` | Public repository data, not Pages publication data | Allowed after validation | Visible in the public repository and history; not intentionally served from the `docs/` Pages tree |
| Generated HTML and translation cache in `docs/` | Public publication data | Allowed | Public through Pages and repository history |
| Feed descriptions and feed-native rich content | Untrusted public input | Only bounded description-derived `raw_excerpt` and approved projections may be stored | Full rich content must not be retained in daily JSON, HTML, normal logs, or translation cache |
| Raw Gemini responses | Untrusted transient processing data | Prohibited in production repository output | Must not be published or logged; repository-external evaluation retention requires explicit scope |
| Normal production and CI logs | Operational metadata | Held by GitHub, not committed by repository code | Must exclude secrets and raw content; platform retention and access are unverified outside the repository |
| Repository-external evaluation artifacts | Review-sensitive; may include raw request/response data | Prohibited unless separately approved for the repository | Store outside the repository, exclude credentials and local paths from committed documents, and define access/retention per evaluation |
| Public source URLs | Public configuration/provenance | Allowed | May be published after URL validation where rendered as a link |
| Future DNS and domain ownership | Administrative security asset | Not currently configured here | Re-evaluate before custom-domain activation; registrar, DNS, Pages, canonical, and redirect settings are outside current repository evidence |

## 5. Trust boundaries

1. **RSS, Atom, NVD, KEV, and translation responses are external.** Their content, structure,
   error text, and availability are not trusted merely because a source is configured.
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
| SR-001 | Treat feed, article, structured-source, translation, and API response content as untrusted input and fail closed or fall back at its parser boundary. | External content can be malformed, unavailable, or instruction-like. | Met | [`fetch.py`](fetch.py): `_parse_feed_items()`, `normalize_feed_body_text()`, `_fetch_feed_result()`; [`vulnerability_facts.py`](vulnerability_facts.py): normalization and cache validation; [`test_feed_fetch_status.py`](test_feed_fetch_status.py) | No current exception. | New source format, parser, provider, or article-page retrieval. |
| SR-002 | Escape every external or AI-generated string before inserting it into HTML; allow only `http` and `https` rendered links through `safe_url()`; add `rel="noopener noreferrer"` to external links opened with `target="_blank"`. | Prevents markup/script injection and unsafe navigation. | Met | [`fetch.py`](fetch.py): `esc()`, `safe_url()`, `build_html()`; [`test_fetch.py`](test_fetch.py): `HtmlEscapeTest`, `SafeUrlTest`, article-link tests; [`test_archive.py`](test_archive.py): `test_internal_and_external_links_are_safe` | Internal navigation intentionally does not use external-link attributes. | New renderer, HTML field, URL source, or client-side script. |
| SR-003 | Permit production outbound collection only to reviewed `http`/`https` endpoints and validate that scheme at the configuration boundary. | A trusted configuration error should not silently enable a non-web URL handler. | Partially met | All current URLs in [`source_definitions.json`](source_definitions.json) are HTTPS; [`fetch.py`](fetch.py): `load_source_definitions()` validates presence and collection method; [`test_source_definitions.py`](test_source_definitions.py) | `load_source_definitions()` does not enforce an `http`/`https` scheme for collection URLs. See GAP-001. | Any source-definition or collection-method change. |
| SR-004 | Do not fetch article pages for richer content. Use only feed-native content, select one bounded representation deterministically, and do not store the full rich body. | Limits new attack surface, data transfer, and unintended retention. | Met | [`fetch.py`](fetch.py): `build_article_body_text()`, `apply_article_body_char_limit()`; [`daily_json.py`](daily_json.py): `build_raw_excerpt()`; [`test_feed_rich_content.py`](test_feed_rich_content.py): `SafetyBoundaryTest`, `RawExcerptAndArticleEntryUnaffectedTest` | The separate summary translation endpoint receives a bounded public summary, not rich content. | Article-page scraping, full-content storage, or another content provider. |
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
| SR-015 | Classify every repository-external evaluation artifact, exclude credentials, define intended reviewers, and set an explicit retention/disposal decision before creation. | Raw requests, responses, screenshots, and local metadata may exceed public-output scope. | Partially met | [`AGENTS.md`](AGENTS.md): secret/raw-response and generated-output restrictions; [BACKLOG.md](BACKLOG.md) and [DECISIONS.md](DECISIONS.md) record external evidence by relative identifier | A common access and retention rule is not yet documented. See GAP-008. | Any new live evaluation, review bundle, or external artifact store. |
| SR-016 | Do not commit user-specific absolute paths or local credential-store details to project documents or artifacts intended for review. | Prevents local identity and filesystem disclosure. | Met | [`test_fetch.py`](test_fetch.py): `test_no_local_absolute_paths_leaked`; management-document conventions in [`AGENTS.md`](AGENTS.md) | Repository-external artifacts still require their own scan before sharing. | New artifact generator or imported local report. |

### 6.4 Secrets

| ID | Requirement | Rationale | Current state | Evidence | Gap / exception | Re-evaluation trigger |
|---|---|---|---|---|---|---|
| SR-017 | Never write credentials or authorization material to source, generated HTML, daily JSON, caches, logs, manifests, screenshots, or review bundles. | Credential leakage can permit API abuse or repository modification. | Partially met | [`.github/workflows/fetch.yml`](.github/workflows/fetch.yml) passes secrets through environment; [`test_article_analysis.py`](test_article_analysis.py): API-key and error-body non-persistence tests; [`AGENTS.md`](AGENTS.md) | Some general exception logging paths do not use the bounded sanitizer used by feed retrieval. See GAP-009. | Logging change, new provider SDK, or artifact capture. |
| SR-018 | Supply production secrets only to the production generation step; ordinary PR workflows must not receive or use them. | Untrusted PR code must not gain production credentials. | Met | [`.github/workflows/pr-ci.yml`](.github/workflows/pr-ci.yml): `pull_request`, `contents: read`, no secret references; [`test_pr_ci_workflow.py`](test_pr_ci_workflow.py); [`.github/workflows/fetch.yml`](.github/workflows/fetch.yml) | Repository/fork policy outside the workflow file is separately unverified. | New PR workflow, `pull_request_target`, reusable workflow, or secret-consuming job. |
| SR-019 | Keep the production secret inventory minimal and document purpose without recording values. Treat existence, access policy, and platform-side configuration as unverified until an owner checks them. | Minimizes credential exposure while avoiding false claims from repository-only evidence. | Unverified outside repository | [`.github/workflows/fetch.yml`](.github/workflows/fetch.yml) references only the Gemini and NVD secret names used by production code | Values, presence, environment restrictions, access audit, and last rotation cannot be confirmed from the repository. See GAP-010. | New credential, provider, environment, or repository visibility. |
| SR-020 | Define minimum rotation/revocation triggers: suspected disclosure, unexpected use, collaborator/access change, provider compromise, or replacement of a credential owner. | Fast revocation limits damage when preventive controls fail. | Not met | [`AGENTS.md`](AGENTS.md) prohibits reading or exposing secret values but does not define an operational rotation procedure | No repository document defines owner, steps, verification, or incident linkage. See GAP-006. | Before adding another secret, or immediately after suspected leakage. |

### 6.5 GitHub Actions

| ID | Requirement | Rationale | Current state | Evidence | Gap / exception | Re-evaluation trigger |
|---|---|---|---|---|---|---|
| SR-021 | Declare workflow permissions explicitly and grant only the minimum needed by each job. | Default or broad tokens increase impact if a step is compromised. | Met | PR CI declares `contents: read`; production job declares `contents: write` for generated-output commit in [`.github/workflows/`](.github/workflows); [`test_pr_ci_workflow.py`](test_pr_ci_workflow.py) | Platform-default metadata access is implicit; repository-level defaults are unverified. | New workflow/job or new API operation. |
| SR-022 | Keep ordinary PR validation separate from scheduled/manual production generation; PR CI must not fetch production data, call Gemini, commit, push, or publish Pages. | Separates untrusted code review from secret-bearing write operations. | Met | [`.github/workflows/pr-ci.yml`](.github/workflows/pr-ci.yml); [`test_pr_ci_workflow.py`](test_pr_ci_workflow.py); [BL-001](BACKLOG.md#bl-001--プルリクエストci) | No current exception. | Reusable workflows or new event types. |
| SR-023 | Disable checkout credential persistence where no push is needed; where production must push, make persistence and cleanup behavior explicit and review the least-privilege alternative. | A persisted token is available to later steps in that job. | Partially met | PR CI sets `persist-credentials: false`; production checkout omits the option and later runs `git push` in [`.github/workflows/fetch.yml`](.github/workflows/fetch.yml) | Production reliance on checkout's default credential persistence is implicit rather than documented. See GAP-005. | Checkout/action upgrade or change in publication method. |
| SR-024 | Treat `workflow_dispatch`, production generation, Pages operations, and manual edits to generated output as separately authorized actions. | A safe code change does not imply authorization to mutate production state. | Met | [`AGENTS.md`](AGENTS.md): Approval boundaries and Gemini/production safety; production workflow exposes only schedule and explicit dispatch | Who can dispatch and approve in GitHub settings is unverified outside the repository. | Permission, owner, or workflow-trigger change. |
| SR-025 | Prevent conflicting runs where concurrent writers could race; cancellation must not expose secrets or corrupt output. | Production commits and pushes shared generated paths. | Partially met | PR CI has per-PR concurrency and cancellation; production workflow has bounded timeout but no concurrency group | Scheduled and manual production runs can overlap. See GAP-004. | Any increase in run frequency, new write workflow, or observed push conflict. |
| SR-026 | Limit automated commits to intended `data/` and `docs/` paths, review generated content before publication where practicable, and verify the Pages result after relevant changes. | A secret-bearing writer publishes durable public content. | Partially met | Production explicitly stages `docs/ data/`; [`daily_json.py`](daily_json.py) validates JSON; [`fetch.py`](fetch.py) validates HTML; [STATUS.md](STATUS.md) records Pages behavior | Pages source/deployment settings and branch protections are unverified outside the repository. See GAP-010. | Generated scope expansion, Pages configuration change, or another writer. |

### 6.6 Dependencies and supply chain

| ID | Requirement | Rationale | Current state | Evidence | Gap / exception | Re-evaluation trigger |
|---|---|---|---|---|---|---|
| SR-027 | Prefer the Python standard library and local modules; require explicit approval and security review for new runtime dependencies. | A small static generator should avoid unnecessary supply-chain surface. | Met | Imports in [`fetch.py`](fetch.py), [`daily_json.py`](daily_json.py), and [`vulnerability_facts.py`](vulnerability_facts.py) are standard-library or local; no Python dependency manifest is present; [`AGENTS.md`](AGENTS.md) requires approval | GitHub Actions remain external build dependencies. | Any package manifest or third-party runtime import. |
| SR-028 | Review third-party Actions for publisher, purpose, permissions, update path, and immutable-reference trade-offs. Full commit SHA pinning is an evaluation item, not an approved mandatory control in Draft 0.2. | Major tags are readable and maintainable but mutable; immutable SHAs improve provenance and require an update process. | Partially met | Workflows currently use `actions/checkout@v4` and `actions/setup-python@v5`; [BACKLOG.md](BACKLOG.md) BL-015 records the open evaluation | Full SHA pinning is not used and has not been approved or rejected. See GAP-002 and Open review questions. | New Action, Action compromise/advisory, or accepted supply-chain policy. |
| SR-029 | Define how dependency and Action updates are discovered and reviewed, including publisher/ownership and official-mirror verification for source repositories. GitHub Actions Dependabot is an evaluation item, not an approved mandatory control in Draft 0.2. | Update automation can reduce stale dependencies but creates review volume and must fit the pinning policy; a mirror must not be trusted solely by name. | Partially met | PR CI provides tests for proposed updates; `.github/dependabot.yml` is absent; [`AGENTS.md`](AGENTS.md) requires explicit dependency approval; [`source_definitions.json`](source_definitions.json) identifies the current CISA KEV mirror under the `cisagov` organization | No documented update cadence/checklist and no Dependabot configuration. See GAP-003 and GAP-007. | First runtime dependency, new Action, source-repository change, or accepted update policy. |

### 6.7 Logging and artifacts

| ID | Requirement | Rationale | Current state | Evidence | Gap / exception | Re-evaluation trigger |
|---|---|---|---|---|---|---|
| SR-030 | Log bounded operational status, counts, error types, and HTTP status where useful; do not log raw feed/rich content, raw Gemini output, authorization headers, credentials, cookies, or response bodies. | Logs have a separate access and retention surface. | Partially met | [`fetch.py`](fetch.py): `_safe_fetch_error_text()` and response-length-only schema warnings; [`test_feed_rich_content.py`](test_feed_rich_content.py): rich-content log test; [`test_article_analysis.py`](test_article_analysis.py): error-body test | Translation and general Gemini exception paths print unsanitized exception text. See GAP-009. | New provider, SDK, debug mode, or tracing. |
| SR-031 | Sanitize exception messages before logging: remove local paths, control characters, request URLs containing content, headers, and overlong text. | Exceptions can include more context than intended. | Partially met | [`fetch.py`](fetch.py): `_safe_fetch_error_text()` implements bounded feed-error logging; [`test_feed_fetch_status.py`](test_feed_fetch_status.py) | The sanitizer is not consistently used by translation and Gemini general-exception handling. See GAP-009. | Any error-handling change. |
| SR-032 | Treat generated JSON/HTML as intentionally public; treat screenshots and evaluation bundles according to their contents, not merely their file extension. | Visual and evaluation artifacts can capture local or raw model data. | Partially met | `data/` and `docs/` roles are defined in [STATUS.md](STATUS.md); repository-external evidence is recorded without absolute paths in management documents | No common retention/access policy for external artifacts. See GAP-008. | New screenshot, review bundle, or external sharing destination. |
| SR-033 | Confirm Actions log/artifact visibility and retention through repository-owner review; do not infer platform settings from workflow YAML. | Repository configuration does not reveal every GitHub-side control. | Unverified outside repository | No `upload-artifact` step exists in repository workflows; workflow logs are platform-managed | Visibility, retention, manual rerun rights, and artifact policy are not repository-verifiable. See GAP-010. | Repository visibility, organization policy, or workflow artifact use. |

The Draft 0.2 exception-output audit covered `fetch.py`, `daily_json.py`,
`vulnerability_facts.py`, every local module imported by the production path, and shell output
from both workflows:

| Path | Observed handling at the PR head |
|---|---|
| RSS / Atom retrieval | `_safe_fetch_error_text()` bounds common HTTP/network failures; XML parse errors are logged separately without a response body. |
| Translation | `translate()` prints raw exception text; its request URL can contain bounded public article text in the query. |
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
| SR-037 | Detect scheduled-generation and Pages failures through existing Actions results and operator review; do not require 24/7 SOC monitoring for the current public static site. | Monitoring effort should reflect impact and architecture. | Partially met | Workflows have timeouts; [STATUS.md](STATUS.md) records run and Pages verification practices | Notification routing, Pages settings, and recovery ownership are unverified outside the repository. See GAP-010. | Paid service, confidential data, contractual uptime, forms/authentication, or critical operational dependency. |

The Draft 0.2 response-size audit found no consistent byte cap at the network `read()` boundary:

| External response | Network read | Later bound, which is not a network byte cap |
|---|---|---|
| RSS / Atom | Entire response is read before XML parsing. | At most three feed items are selected after parsing; ARTICLE feed-native body input is then limited to 4,000 characters and stored `raw_excerpt` to 200 characters. |
| Translation | Entire response is read before JSON parsing. | Request text is limited to 500 characters and cache keys to 300 characters; these do not cap provider response bytes. |
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
| SR-043 | Define a correction, withdrawal, regeneration, and record procedure for published daily JSON or HTML when a major factual error, unsupported claim, subject or scope shift, or prompt-injection-derived output is confirmed. Decide in advance which HTML, daily JSON, and repository history are affected; align the procedure with SD-014; record the correction reason and impact scope. | Published generated content is durable and can affect reader decisions and trust. | Not met | [SD-014](DECISIONS.md#sd-014--keep-daily-json-outside-the-github-pages-publication-tree-and-limit-stored-content) defines the current storage/history boundary; fixed BL-005 and BL-023 evaluations provide content-integrity evidence | No correction or withdrawal procedure is defined. See GAP-014. This Draft does not choose an implementation or correction format. | A confirmed published-output integrity issue, or before Version 1.0 if the user approves a minimum process. |

## 7. Current control mapping

| Area | Requirement IDs | Current implementation | Evidence | Aggregate status | SR state breakdown |
|---|---|---|---|---|---|
| Input and content handling | SR-001–SR-005 | Common parsers, HTML normalization, bounded rich-content selection, `esc()`, `safe_url()`, and source-definition review | [`fetch.py`](fetch.py), [`test_fetch.py`](test_fetch.py), [`test_feed_rich_content.py`](test_feed_rich_content.py) | Partially met | Met 4 / Partial 1 / Not met 0 / Unverified 0 |
| Prompt and AI boundary | SR-006–SR-011 | Separate verified/untrusted JSON, allowlist projection, ARTICLE validation/fallback, no BRIEF API | [`fetch.py`](fetch.py), [`daily_json.py`](daily_json.py), [`test_article_internal_identifier_leak.py`](test_article_internal_identifier_leak.py), [`test_todays_brief.py`](test_todays_brief.py) | Met | Met 6 / Partial 0 / Not met 0 / Unverified 0 |
| Storage and publication | SR-012–SR-016 | Validated atomic daily JSON in `data/`, escaped HTML in `docs/`, bounded stored content | [`daily_json.py`](daily_json.py), [`fetch.py`](fetch.py), [SD-014](DECISIONS.md#sd-014--keep-daily-json-outside-the-github-pages-publication-tree-and-limit-stored-content) | Partially met | Met 4 / Partial 1 / Not met 0 / Unverified 0 |
| Secrets | SR-017–SR-020 | Production-only secret references and persistence tests; no documented values | [`.github/workflows/fetch.yml`](.github/workflows/fetch.yml), [`.github/workflows/pr-ci.yml`](.github/workflows/pr-ci.yml), [`test_article_analysis.py`](test_article_analysis.py) | Partially met | Met 1 / Partial 1 / Not met 1 / Unverified 1 |
| GitHub Actions | SR-021–SR-026 | Explicit per-workflow permissions, isolated PR CI, production-only commit/push | [`.github/workflows/`](.github/workflows), [`test_pr_ci_workflow.py`](test_pr_ci_workflow.py), [BL-001](BACKLOG.md#bl-001--プルリクエストci) | Partially met | Met 3 / Partial 3 / Not met 0 / Unverified 0 |
| Dependencies and supply chain | SR-027–SR-029 | Standard-library runtime; official Actions referenced by major tags; no Dependabot file | Python imports and [`.github/workflows/`](.github/workflows) | Partially met | Met 1 / Partial 2 / Not met 0 / Unverified 0 |
| Logging and artifacts | SR-030–SR-033 | Bounded feed errors, no raw response persistence, external review artifacts kept outside repository | [`fetch.py`](fetch.py), related logging tests, [BACKLOG.md](BACKLOG.md) | Partially met | Met 0 / Partial 3 / Not met 0 / Unverified 1 |
| Availability and recovery | SR-034–SR-037 | Bounded timeouts/retries, explicit statuses, atomic writes, repository history, and offline regeneration; response-size limits remain open | [`fetch.py`](fetch.py), [`daily_json.py`](daily_json.py), related tests | Partially met | Met 2 / Partial 2 / Not met 0 / Unverified 0 |
| Change and review control | SR-038–SR-043 | Dedicated branches/PRs, full unittest and diff CI, scope review, separate production authorization, contract-specific tests; published-output correction remains undefined | [`AGENTS.md`](AGENTS.md), [`.github/workflows/pr-ci.yml`](.github/workflows/pr-ci.yml), [`test_pr_ci_workflow.py`](test_pr_ci_workflow.py) | Partially met | Met 4 / Partial 1 / Not met 1 / Unverified 0 |
| Forms, authentication, database, and payments | Re-evaluation triggers only | No such component exists in the current repository | [`AGENTS.md`](AGENTS.md), current static generator and HTML | Not applicable now | No current SR count |
| GitHub/Pages/DNS settings outside the repository | SR-019, SR-024, SR-026, SR-033, SR-037 | Must be checked by an owner; Draft makes no inferred claim | Repository evidence boundary in this document | Unverified outside repository | Cross-cutting owner checks; not counted again in domain totals |

## 8. Gap register

These are register entries, not a claim that every item is a confirmed security defect.
`Security gap`, `Hardening candidate`, `Policy decision`, `Owner verification`, and
`Future trigger` distinguish current gaps from optional hardening, pending choices,
repository-external checks, and future-only conditions. No entry is implemented or
automatically accepted by this Draft.

| Gap ID | Classification | Related requirement | Description | Risk | Proportionality | Recommended disposition | Separate ticket required? | Trigger / timing |
|---|---|---|---|---|---|---|---|---|
| GAP-001 | Security gap | SR-003 | Actual source URLs are HTTPS, but source-definition validation does not enforce `http`/`https` for outbound collection URLs. | A reviewed configuration error could select an unintended `urllib` handler. | Small deterministic validation; relevant to the existing boundary. | Review and, if accepted, add scheme validation with source-definition tests. | Yes, after Draft approval | Before adding or changing a collection endpoint. |
| GAP-002 | Policy decision | SR-028 | Actions use major-version tags, not full commit SHAs. | Mutable tags provide weaker immutable provenance for secret-bearing/write workflows. | SHA pinning increases update and review burden; benefit is strongest for production. | Fable 5 recommends full-SHA pinning for both workflows; user decision is pending. | Yes if accepted | Draft review or an Action supply-chain advisory. |
| GAP-003 | Policy decision | SR-029 | `.github/dependabot.yml` is absent, including GitHub Actions update automation. | Action updates may be noticed late; automation can also add unnecessary PR volume. | Only two official Actions are used and the runtime has no third-party package manifest. | Fable 5 recommends weekly GitHub Actions updates and one combined ticket with SHA pinning; user decision is pending. | Yes if accepted | Draft review, first runtime dependency, or Action expansion. |
| GAP-004 | Hardening candidate | SR-025 | Production generation has no concurrency group. | Scheduled and manual runs could race on generated files and `git push`. | A simple workflow control may be proportionate, but it changes production workflow behavior. | Fable 5 recommends production concurrency with `cancel-in-progress: false` at low priority; user decision is pending. | Yes | Before increasing frequency, or after an overlap/push conflict. |
| GAP-005 | Policy decision | SR-023 | Production checkout relies on default persisted credentials for its later push. | Credential availability is broader within the job than an explicitly documented push mechanism. | The job does require a push; eliminating persistence is not automatically safer without a replacement. | Fable 5 considers current persistence acceptable and recommends documentation only; user decision is pending. | Only if a workflow change is accepted | Checkout upgrade or publication redesign. |
| GAP-006 | Policy decision | SR-020 | No minimum secret rotation and revocation procedure is documented. | Response may be delayed or incomplete after suspected leakage. | A short owner/runbook section is proportionate; no new security product is implied. | Fable 5 recommends one compact operations document shared with incident response; user decision is pending. | Yes or an approved operations document | Before another secret is added; urgent on suspected leakage. |
| GAP-007 | Future trigger | SR-029 | Approval is required for new dependencies, but no concrete ownership/provenance/update review checklist exists. | A future dependency could be adopted without consistent supply-chain review. | No runtime third-party dependency exists today, so a compact just-in-time checklist is enough. | Define the checklist before accepting the first new dependency. | Not necessarily before that trigger | First new Python dependency or third-party Action. |
| GAP-008 | Policy decision | SR-015, SR-032 | Repository-external evaluation artifacts have no common retention, access, or disposal rule. | Raw model output, request data, screenshots, or local metadata may persist longer or be shared more broadly than intended. | Artifacts are occasional; per-evaluation classification plus a small default is preferable to a large archive system. | Decide whether to define a default retention period and exceptions. | Yes if a common policy is accepted | Before the next live evaluation bundle. |
| GAP-009 | Security gap | SR-017, SR-030, SR-031 | The Draft 0.2 audit found inconsistent exception handling: translation, standalone NVD, ARTICLE and legacy BRIEF Gemini, active NVD/KEV, cache, daily/archive, and uncaught loader/write paths can bypass `_safe_fetch_error_text()`. The source-definition loader raises rather than directly printing its path-bearing error. | Raw exception text or uncaught tracebacks can expose local paths, request URLs, public article text in a translation query, or validation context in Actions stderr. | Public source text limits confidentiality impact, but repository and provider paths remain log-hygiene concerns; no raw response-body logger was found. | Review a common bounded exception formatter and uncaught-error boundary in a separate accepted ticket; this Draft changes no sanitizer. | Yes if accepted | Before debug logging, another provider, or a confirmed sensitive diagnostic leak. |
| GAP-010 | Owner verification | SR-019, SR-024, SR-026, SR-033, SR-037 | Secret configuration, dispatch rights, branch protection, repository visibility controls, Pages source/deployment settings, log retention, and notification routing are not verifiable from repository files. | Repository-only documentation can otherwise overstate control coverage. | Owner confirmation is sufficient; no setting change is implied. | Fable 5 recommends completing a read-only owner checklist before Version 1.0; user decision is pending. | Possibly documentation-only | Before Version 1.0 approval and after relevant GitHub setting changes. |
| GAP-011 | Future trigger | SR-012, SR-037 | No approved custom-domain security preflight exists for Pages verified-domain/domain verification, dangling DNS or takeover prevention, safe Pages/DNS cutover and teardown order, registrar MFA, auto-renew, expiration protection, registrar/transfer lock, repository rename impact, rollback, and ownership. | A future custom-domain rollout or withdrawal could leave an unsafe binding or dangling CNAME. | This is not a current-site security gap because the custom domain is not implemented. | Prepare and approve the checklist within BL-007 before activation; include safe teardown and ownership. | Coordinate with BL-007 | Before any `monomidigest.com` DNS or Pages change. |
| GAP-012 | Policy decision | SR-001, SR-030 | The production summary translation path uses an unofficial endpoint and sends bounded public article text in a URL query. `docs/translate_cache.json` persists provider output in the repository and Pages across days; no cache TTL or provider-response integrity validation was found. | Provider behavior can change, request URLs can appear in intermediary logs, and inaccurate or malicious cached translations can be reused across days. | The text and cache are public, so confidentiality impact is low; continued provider use, cache invalidation, or replacement is a user decision. | Confirm continued acceptance or define cache invalidation/replacement only through a separate ticket; do not add a dependency in this Draft. | Yes if change is desired | Provider failure or policy change, incorrect cached output, private input, or new translation requirement. |
| GAP-013 | Policy decision | SR-020, SR-033 | No compact security-incident / credential-leakage response procedure is maintained. | Detection, containment, evidence preservation, and communication may be improvised. | A minimal procedure is proportionate; a 24/7 incident platform is not. | Fable 5 recommends one compact operations document shared with secret rotation; user decision is pending. | Yes if accepted | Before Version 1.0 or immediately after an incident. |
| GAP-014 | Security gap | SR-043 | Published generated content has no defined correction, withdrawal, regeneration, or repository-history procedure. | A major factual error, unsupported claim, subject/scope shift, or prompt-injection-derived output can harm content integrity and reader trust. | A minimum discovery-time procedure is proportionate; 24/7 monitoring is not required. | Decide the affected HTML/daily JSON/history treatment, reason/scope record, and SD-014 alignment in Version 1.0 or a later operations document. | User decision pending for a separate implementation ticket | Before Version 1.0 if accepted, or immediately after a confirmed issue. |
| GAP-015 | Hardening candidate | SR-034 | RSS/Atom, translation, ARTICLE and legacy BRIEF Gemini, standalone and active NVD, and KEV responses are read in full before parsing; no common network response byte cap was found. | An oversized or malformed provider response can increase memory use and delay or fail generation before later item/character limits apply. | Confidentiality impact is low and no incident was found; a proportionate per-endpoint cap or common bounded reader is a separate hardening choice. | Evaluate endpoint-specific limits or a common bounded reader without confusing downstream item, token, input-character, or excerpt limits with network bytes. | Yes if accepted | New source/provider, oversized response, or observed memory/time failure. |

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
| Paid secret-scanning features | Not required by Draft 0.2. Repository-owner settings and available platform controls must be reviewed without assuming a paid feature. |

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

## 11. Open review questions

Fable 5 and the user should decide:

1. Should GitHub Actions be pinned to full commit SHAs? If so, should the policy cover both
   workflows or prioritize the secret-bearing/write production workflow?
2. Should Dependabot for GitHub Actions be introduced, and how should it interact with any
   full-SHA policy?
3. How much of the secret rotation/revocation procedure belongs in repository documentation,
   and which owner-only details should remain outside it?
4. Should repository-external artifacts have a default retention period, and which evaluated
   evidence warrants a longer exception?
5. Which checks must be complete before custom-domain activation: ownership; GitHub Pages
   verified-domain/domain verification; dangling DNS and takeover prevention; safe ordering for
   Pages custom-domain configuration and DNS cutover; safe teardown without a dangling CNAME;
   registrar MFA, auto-renew, expiration protection, and registrar/transfer lock; repository
   rename impact; HTTPS enforcement, canonical URLs, redirects, rollback, and responsible owner?
6. Should the minimal security-incident and credential-leakage response be a standalone document
   or a short operations section?
7. Are any requirements disproportionate to a public static digest?
8. Is any major trust boundary missing, especially the translation endpoint, generated commits,
   or GitHub-side settings?
9. Are the `Met`, `Partially met`, `Not met`, and `Unverified outside repository`
   classifications supported by the cited evidence?
10. Should outbound source URL scheme validation and production concurrency be the first
    candidate implementation tickets after approval?

### Fable 5 recommendations — user decision pending

These recommendations are review input, not accepted requirements or implementation approval:

- pin both workflows' Actions to full commit SHAs;
- configure weekly Dependabot updates for GitHub Actions and, if accepted, handle that work with
  SHA pinning in one ticket;
- add production concurrency with `cancel-in-progress: false` at low priority;
- leave production checkout credential persistence as-is and document the rationale;
- use one compact operations document for secret rotation and incident response;
- complete the GAP-010 repository-owner checklist before Version 1.0.

## 12. Approval and maintenance

- Draft 0.2 is unapproved.
- Fable 5 review has been incorporated: Critical 0, High 0; accepted and modified findings are
  reflected, and the rejected F-004 consolidation was not applied. Fable 5 did not inspect `STATUS.md` or
  `test_security_requirements.py`; those files were independently checked at the PR head.
- User approval is pending.
- After review corrections and explicit user approval, the document may become Version 1.0.
- Only approved register entries, including accepted gaps or policy decisions, become separate
  implementation tickets.
- This document does not impose a mechanical annual-update cycle. Update it when a
  re-evaluation trigger occurs, an incident reveals a missing boundary, or the user approves a
  material security-policy change.
- A stable decision record, if needed, is deferred until Version 1.0 approval. Draft 0.2 does
  not add SD-024 or any later decision.
