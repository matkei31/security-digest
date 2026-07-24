# Security Digest Security Operations

- **Version:** Draft 0.1
- **Status:** User and external review pending
- **As of:** 2026-07-24

## Scope

This runbook covers the current public static GitHub Pages site, the repository-backed
generation pipeline, GitHub Actions credentials, published daily JSON and HTML, and
repository-external review artifacts.

Runtime implementation, workflow changes, GitHub setting changes, actual secret rotation,
actual incident-response execution, and production execution are out of scope for this Draft.
This is a short runbook proportionate to a personally managed static site, not a general
enterprise incident-response plan.

This document implements the documentation scope approved by
[SECURITY_REQUIREMENTS.md](SECURITY_REQUIREMENTS.md) Version 1.0, especially SR-043,
GAP-006, GAP-008, GAP-013, and GAP-014. It also follows the GAP-010 owner-checklist evidence
boundary, [SD-014](DECISIONS.md#sd-014--keep-daily-json-outside-the-github-pages-publication-tree-and-limit-stored-content),
[SD-024](DECISIONS.md#sd-024--approve-security-requirements-version-10-and-the-proportionate-security-roadmap),
and the approval boundaries in [AGENTS.md](AGENTS.md).

## 1. Purpose and operating principles

Security Digest does not handle life-safety operations, payments, or customer data. Its
public-information accuracy, repository integrity, credentials, and published Pages still have
protection value.

- Combine rapid containment with a safe, reviewable evidence trail.
- Never preserve a secret value or unnecessary raw data merely as “evidence.”
- Do not force-push or rewrite Git history to hide a problem.
- Correct content with a new commit and an explicit record.
- Keep the normal approval boundaries for production execution and control changes.
- Do not require a 24-hour SOC or a large incident platform for the current architecture.

## 2. Roles and authorization boundaries

| Role | Responsibility |
|---|---|
| Repository owner | Controls provider credentials and GitHub repository secrets; performs approved revocation, replacement, and setting changes. |
| Operator | Assesses an event, prepares the smallest safe branch and pull request, runs authorized validation, and records non-sensitive evidence. |
| Reviewer | Independently checks scope, evidence, correction integrity, and residual risk without requesting secret values. |
| User approval owner | Approves material policy choices, production operations, emergency exceptions, Ready status, and merge where separately required. |

Only the Repository owner handles secret values. Work and AI reviewers must not request,
display, copy, or store them. Normal corrections use a branch, pull request, and CI. Production
workflow execution, GitHub setting changes, secret updates, Ready for review, and merge retain
their separate approval boundaries. Approval of Security Requirements Version 1.0 is not
unlimited advance approval for real incident actions.

## 3. Events covered by this runbook

Use this runbook for:

- confirmed or suspected exposure of a GitHub, Gemini, or external-provider credential;
- unauthorized repository or workflow changes;
- suspected compromise of a GitHub Action, dependency, or source repository;
- publication of a secret, credential, private data, or unnecessary local path;
- unintended storage or publication of a raw Gemini response, rich content, or similar data;
- prompt-injection-derived public output;
- a published material claim about facts, actor, scope, or impact that the source does not
  support;
- damaged or inconsistent published daily JSON or HTML; and
- repository-external artifacts that were shared incorrectly or retained beyond policy.

Minor typography, layout defects, non-material writing differences, and ordinary broken links
are normally bugs or editorial corrections. Escalate them to this runbook when they affect
security or content integrity.

## 4. Initial assessment and containment

Record, without sensitive values:

- what happened, detection time, and detector;
- affected asset and whether it is currently public;
- whether credentials are involved and whether misuse is continuing;
- affected date, page, JSON file, commit, pull request, workflow run, and URL;
- the difference between the source and public content; and
- whether immediate containment is urgent.

Do not paste secret values into chat, issues, pull requests, or logs. Do not broaden the
investigation without need, rewrite Git history in haste, or rerun Gemini, external retrieval,
or production merely to diagnose the event. Preserve existing safe evidence, but do not retain
evidence containing credentials. Before changing anything, record the affected identifiers in
a non-sensitive form.

The normal containment path is a dedicated branch and the smallest reviewable pull request.
A direct production rewrite that bypasses a pull request is not approved by Draft 0.1; the
need, authorizer, limits, and mandatory after-action record remain an open review question.

## 5. Secret and credential rotation

Rotation or revocation is triggered by suspected disclosure, unexpected use, access or
collaborator change, provider compromise, or replacement of the credential owner.

1. Identify the suspected credential by provider and secret name, never by value.
2. Review related workflows, runs, and sanitized logs.
3. If active misuse is suspected, have the Repository owner revoke or disable it at the
   provider.
4. Issue a replacement credential through the provider.
5. Have the Repository owner update the corresponding GitHub Actions repository secret.
6. Verify at the provider that the old credential can no longer be used.
7. Check the repository, logs, artifacts, and local files for the exposure scope without
   copying the value into evidence.
8. Perform only the separately authorized validation appropriate to that credential.
9. Record time, secret name, actions, and result without recording the value.

`GEMINI_API_KEY` is the required repository secret. `NVD_API_KEY` is optional and is currently
not configured. Both are long-lived provider credentials when configured. A local credential,
an environment secret, and a GitHub repository secret are distinct storage or delivery
contexts and must be checked separately.

The job-scoped `GITHUB_TOKEN` is issued by GitHub for a workflow run; it is not a long-lived
provider secret to be rotated using the procedure above. Respond instead by containing the
affected run or repository access and reviewing the workflow permissions and platform event.
This Draft performs no secret update, real API validation, or production execution.

## 6. Minimal incident response

Use only two response classes:

- **Immediate containment required:** active credential misuse, ongoing unauthorized change,
  sensitive publication, or a material public-integrity issue whose continued exposure causes
  substantial harm.
- **Normal documented response:** the event is contained or non-urgent and can follow the
  ordinary branch, pull request, CI, approval, and deployment path.

For either class: assess, contain, preserve safe evidence, eradicate or correct, validate,
restore, record, then close and identify follow-up.

The minimum incident record contains:

- incident ID or date-based identifier;
- detected at and event summary;
- affected assets and public dates or URLs;
- relevant commit, pull request, and workflow run;
- credential involvement: yes, no, or unknown;
- containment and correction or rotation;
- validation, residual risk, and follow-up ticket; and
- closure decision.

Do not record personal information, a secret value, raw authorization header, or cookie.

## 7. Published-output correction, withdrawal, and regeneration

Treat these as separate assets:

- `data/YYYY-MM-DD.json`;
- `data/index.json`;
- `docs/index.html`;
- `docs/archive/YYYY-MM-DD.html`;
- `docs/archive/index.html`;
- the translation cache;
- Git repository history; and
- repository-external screenshots and evaluation artifacts.

Material content-integrity problems include a fact absent from the source; changed actor or
scope; a material date, number, or product error; unsupported financial impact;
prompt-injection-derived output; or publication of an internal identifier or private data.

The Draft default is:

- correct the current published files;
- restore consistency between the affected daily JSON and the HTML generated from it;
- retain the original in Git history and do not force-push or rewrite history;
- record reason, scope, changed files, and validation in the commit, pull request, and BL or
  other approved record;
- never change only JSON or only HTML without a record;
- prefer deterministic offline regeneration from existing corrected daily JSON;
- do not rerun Gemini or external HTTP;
- require separate explicit approval and contract review if AI regeneration is necessary; and
- do not silently change ARTICLE or BRIEF versions, schema, or validation contracts.

### Correction

When a supported replacement is available, correct the affected `data/YYYY-MM-DD.json`, run
daily JSON validation, and regenerate every derived HTML surface from the corrected data.
Because manual changes to generated output are a separate approval boundary, the correction
pull request must identify the exact affected date and files.

### Withdrawal

Withdraw when a correct replacement cannot be produced promptly and continued publication has
material impact. The recommended future default is an explicit withdrawal or correction notice
that preserves navigation and makes the unavailable content clear. Blank output, article
deletion, and a dedicated notice can require schema or UI changes, so Draft 0.1 does not
unconditionally select or authorize one.

### Regeneration

1. Validate the corrected existing daily JSON.
2. Regenerate the affected daily Archive HTML offline.
3. Regenerate the current top page when the corrected date is represented there.
4. Rebuild the Archive index and confirm previous/next navigation did not regress.
5. Do not run the production workflow.
6. Do not call Gemini, RSS, NVD, or other external HTTP.

### Validation

Confirm daily JSON validation, HTML escaping, safe URLs, Archive consistency, top/Archive
consistency, relevant tests, full unittest, and `git diff --check`. After an authorized merge,
confirm the Pages deployment result and decide whether the public page requires direct
verification.

## 8. Repository-external artifact handling

Before creating an artifact, classify it, identify its intended reviewers, and set its
retention or disposal decision. Limit access and sharing to those identified reviewers.

Never store a secret, credential, authorization header, cookie, private key, unnecessary local
absolute path, unrelated personal information, or production-prohibited raw data without a
specific approved need.

Detailed artifacts normally expire 90 days after the evaluation is completed:

- raw requests and responses;
- model responses and detailed evaluation bundles;
- screenshots containing detailed local or raw context; and
- temporary debugging output.

At or before the deletion date, the artifact owner deletes the expiring detailed items and
records only a sanitized result if evidence is still needed. Evaluation summaries,
manifest or hash lists, approved BL or SD evidence, gate results, and the minimum basis for a
merge or No-Go decision may be retained for as long as that decision needs support.

A 90-day exception records the reason, retained items, owner, review or deletion date,
confirmation that secrets and unnecessary local paths are absent, and the approved decision
reference. The recommended approver is the User approval owner. Existing artifacts are not
deleted by this Draft, and no retention automation, cron job, or cleanup script is introduced.
GitHub Actions log and platform-artifact retention are platform settings and are not this
repository-external artifact policy.

## 9. Evidence preservation

Safe evidence includes a commit SHA, pull request URL, workflow or Pages run URL, file path,
affected date, screenshot reviewed for secrets and local paths, sanitized error category, and
artifact manifest or hash.

Do not preserve a secret value, full token, raw authorization header, cookie, unnecessary full
response body, unredacted local path, or unrelated user or account information. Evidence
preservation never justifies retaining a secret.

## 10. Validation and closure

Close an incident or correction only when:

- containment is complete;
- required credential revocation or rotation is complete;
- affected public output is corrected or withdrawn;
- JSON and HTML consistency is confirmed;
- relevant tests pass;
- the public deployment is confirmed;
- residual risk and a follow-up ticket are recorded;
- evidence is sanitized; and
- the responsible owner confirms closure.

A merged documentation or code pull request alone is not incident closure.

## 11. Open review questions

These recommendations are not approved decisions in Draft 0.1:

1. **Emergency hotfix:** allow a minimal direct hotfix only when immediate containment cannot
   safely wait for a pull request, with explicit Repository owner and User approval owner
   authorization, exact file limits, and a mandatory after-action branch, record, and review.
2. **Withdrawal display:** prefer an explicit notice that preserves the page and navigation;
   decide the schema and UI contract before adoption.
3. **Material daily JSON correction:** make correction of the affected daily JSON, followed by
   deterministic HTML regeneration, the normal default when a supported replacement exists.
4. **Correction notice contract:** add dedicated schema or UI only if repeated corrections show
   that commit and pull-request evidence is insufficient for readers.
5. **90-day start:** retain evaluation-completion date as the start because it is stable and
   reviewable, including when files were created incrementally.
6. **Longer retention:** require User approval owner approval and a recorded next review or
   deletion date.
7. **AGENTS.md reference:** after Version 1.0 approval, add only a concise pointer and preserve
   existing per-operation authorization boundaries.
8. **External review:** obtain Fable 5 review before Version 1.0.

## 12. Approval and maintenance

Draft 0.1 is unapproved. User approval and external review are pending. After both reviews and
the user's final decision, the document may become Version 1.0. Only after Version 1.0 is
merged should the project decide whether to update the state of GAP-006, GAP-008, GAP-013,
GAP-014, and SR-043 in SECURITY_REQUIREMENTS.md.

Review this runbook when an incident or architecture change exposes a missing boundary. A
mechanical annual update is not required.
