# AGENTS.md

## Project

Security Digest is a daily cybersecurity news digest for cybersecurity practitioners, managers, and executives at financial institutions.

The public site is generated as static HTML and published through GitHub Pages.

## Architecture

- `fetch.py`
  - Collects RSS/API items
  - Calls Gemini for article analysis
  - Calls Gemini for the executive summary
  - Generates HTML
- `daily_json.py`
  - Builds and validates daily JSON
  - Writes JSON atomically
  - Rebuilds `data/index.json`
- `source_definitions.json`
  - Canonical source definitions
- `docs/`
  - GitHub Pages output
- `data/`
  - Daily structured digest data
- `.github/workflows/fetch.yml`
  - Scheduled execution and automated digest commits

## Completed foundations

- HTML escaping and safe URL handling are implemented.
- Source definitions are centralized.
- Daily JSON storage is implemented.
- Gemini article analysis v2 is implemented.
- Article analysis includes:
  - `category`
  - `category_reason`
  - `importance`
  - `urgency`
  - `summary`
  - `financial_impact`
  - `recommended_actions`
  - `reason`
  - `tags`

## Security requirements

- Never commit API keys, tokens, Authorization headers, raw API responses, or stack traces.
- Escape all external and AI-generated strings before inserting them into HTML.
- Only allow `http` and `https` links.
- External links must use `rel="noopener noreferrer"`.
- Do not add forms, authentication, a database, or new external dependencies without explicit approval.
- Do not scrape and store full article bodies.
- `raw_excerpt` must remain short.

## Development rules

- Create one feature branch per ticket.
- Do not merge into `main` without review.
- Do not change unrelated files.
- Do not perform large refactors unless required by the ticket.
- Use Python standard library and existing dependencies only.
- Keep HTML generation compatible with static GitHub Pages.
- Run the entire unittest suite before push.

Test command:

```bash
python3 -m unittest discover -p "test_*.py"
```

## Git and automated digest commits

GitHub Actions may create new `digest:` commits on `main` while a feature branch is being developed.

Before pushing:

```bash
git fetch origin
git status
```

If `origin/main` has advanced, rebase the feature branch before pushing when appropriate.

Do not embed credentials in Git remotes.
Do not extract tokens from the system keychain.
Use the authenticated GitHub CLI where GitHub operations are needed.

## Scope discipline

Each ticket must state:

- Purpose
- Files allowed to change
- Files that must not change
- Acceptance criteria
- Required tests

If the existing implementation conflicts with the ticket, report the conflict instead of silently expanding scope.
