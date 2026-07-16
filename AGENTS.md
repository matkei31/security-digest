# AGENTS.md

## Project

Security Digest is a daily cybersecurity news digest for cybersecurity practitioners, managers, and executives at financial institutions. It generates structured daily JSON and static HTML published through GitHub Pages.

Current prompt versions, schema version, source status, and known limitations are recorded in [STATUS.md](STATUS.md). The code-level sources of truth remain `daily_json.py`, `source_definitions.json`, and the prompt-building code in `fetch.py`.

## Architecture

- `fetch.py`
  - Collects enabled RSS, Atom, and structured sources
  - Builds trusted vulnerability context
  - Calls Gemini separately for ARTICLE analysis and BRIEF generation
  - Generates the top page and archive HTML
- `daily_json.py`
  - Owns the current ARTICLE prompt version, BRIEF prompt version, and daily schema version
  - Builds and validates daily JSON
  - Writes JSON atomically and rebuilds `data/index.json`
- `vulnerability_facts.py`
  - Extracts CVEs and obtains NVD/CISA KEV facts with bounded caching
- `source_definitions.json`
  - Is the canonical source definition and enablement configuration
- `docs/`
  - Contains generated GitHub Pages output, not project design documents
- `data/`
  - Contains generated daily data and facts cache
- `.github/workflows/fetch.yml`
  - Runs scheduled or explicitly dispatched production generation

## Scope discipline

- Implement only the approved ticket scope.
- Do not infer requirements or expand the design when the specification is ambiguous.
- If existing code or data conflicts with the ticket, report the conflict before changing behavior.
- Do not introduce title-, vendor-, threat-actor-, CVE-, or article-specific rules unless the approved requirement explicitly calls for them.
- Do not add semantic validation, generated-text rewriting, generic regex removal, or response discard behavior as a substitute for a defined requirement.
- Each ticket must identify its purpose, allowed files, prohibited files, acceptance criteria, and required tests.
- Preserve unrelated user changes and generated data.

## Approval boundaries

- Use a dedicated feature branch or worktree for each ticket. Do not change `main` directly.
- Editing and testing authorization does not automatically authorize commit, push, or PR creation.
- Commit, push, and PR creation require the authorization provided for that ticket.
- Merge, workflow enable/disable, `workflow_dispatch`, production generation, Pages operations, and manual edits to production `data/` or `docs/` require separate explicit authorization.
- Never force-push, rewrite shared history, or amend/rebase a pushed or shared branch without explicit approval.
- Before publishing changes, fetch `origin`, confirm the merge base, inspect the final diff, and verify that the branch contains only approved changes.
- If `origin/main` advances, do not silently rewrite branch history. Report or follow the ticket's approved synchronization method.

## Gemini and production safety

- Do not call the real Gemini API without explicit approval.
- Do not read, display, copy, or change API keys, secrets, Authorization headers, or credential-store values.
- Do not run `python3 fetch.py` as a harmless preview: it may perform external requests, call Gemini, and update generated files.
- Tests must mock Gemini and external failure paths unless a real diagnostic run has been explicitly approved.
- Do not run `workflow_dispatch`, scheduled-workflow substitutes, or diagnostic workflows without explicit approval.
- Do not commit raw Gemini responses, stack traces, credentials, or sensitive request data.

## Prompt and schema contracts

- ARTICLE and BRIEF are separate prompt contracts. Review and change them independently.
- The current ARTICLE prompt version, BRIEF prompt version, and daily schema version are defined in `daily_json.py` and summarized in `STATUS.md`; do not hard-code current values in this file.
- A prompt instruction, trusted-context contract, response schema, normalization rule, or validation change must be assessed for a corresponding prompt-version change.
- Do not bump an unrelated prompt version.
- The daily JSON schema is a separate contract. Prompt changes do not automatically require a schema-version change, and schema changes require explicit approval.
- Update current-version assertions, request-body tests, response-schema tests, and validation tests when their contracts change.
- Preserve historical fixtures and historical JSON values at their generation-time versions. Do not rewrite historical data to the current prompt version.
- Maintain the trusted-context and untrusted-article boundaries. Do not allow internal field names or raw response data to reach user-visible output.

## ARTICLE status, fallback, and validation

- Preserve the ARTICLE status contract: `success`, `fallback`, `failed`, and `not_attempted`.
- Strict validation determines `success`; recoverable partial output may use the existing `fallback` path.
- Fix validation false positives in the relevant validation rule. Do not replace the fix by deleting fallback, treating invalid output as success, or silently discarding required fields.
- Do not change fallback/failed/not_attempted behavior outside the approved ticket.
- Preserve importance and urgency as independent axes.

## Feed-native rich content

- Use only content already present in the fetched RSS/Atom response. Do not add article-page HTTP requests or source-specific scraping.
- Preserve the deterministic selection, sanitization, and bounded input behavior implemented in `fetch.py`.
- Do not store full rich content in daily JSON, HTML, normal logs, error logs, or translation cache.
- Keep `raw_excerpt` short and description-based; rich content must not replace its storage source.
- Preserve script/style/boilerplate exclusion and the untrusted prompt boundary.

## Security requirements

- Escape all external and AI-generated strings before inserting them into HTML.
- Only allow `http` and `https` links.
- External links must use `rel="noopener noreferrer"`.
- Do not add forms, authentication, a database, new external dependencies, or persistent storage without explicit approval.
- Use Python standard library and existing dependencies unless a ticket explicitly approves otherwise.
- Keep output compatible with static GitHub Pages.

## Testing and review

For implementation changes, the default verification set is:

1. Ticket-focused tests
2. Related regression tests
3. The entire unittest suite
4. `git diff --check`
5. A complete final-diff and scope review

Full test command:

```bash
python3 -m unittest discover -p "test_*.py"
```

Prompt or request-boundary changes also require actual request-body inspection using mocked transport. Fallback/validation changes require success, fallback, failed, and not-attempted regression coverage where relevant.

This repository currently has no ordinary `pull_request` or `push` CI workflow. When no PR checks exist, use scope-appropriate local verification and independent review as merge evidence. Do not describe absent checks as successful CI:

- For implementation changes, record the successful local full unittest result, confirmation that the PR diff matches the approved final diff, and an independent diff review.
- For documentation-only changes, first check whether any static test inspects the documents being changed. If such a test exists, update it with the document and run at least the related tests. If no relevant static test exists, the full unittest suite may be skipped when the reason is recorded. In either case, record Markdown-link verification, changed-file scope, `git diff --check`, and an independent diff review.

## Git and generated output

- GitHub Actions may create `digest:` commits on `main` while a feature branch is under development.
- Before push, run `git fetch origin`, inspect `git status`, and compare the branch with the latest `origin/main`.
- Stage only approved files; do not use broad staging in a mixed worktree.
- Do not modify or regenerate `data/` or `docs/` unless the ticket explicitly includes production/generated output.
- Do not embed credentials in Git remotes or extract tokens from the system keychain.
- Use the authenticated GitHub CLI for authorized GitHub operations.
