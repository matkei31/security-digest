# Monomi Digest Security Operations

- **Version:** 1.1
- **Status:** Draft
- **As of:** 2026-07-29

## Scope

This runbook covers the current public static GitHub Pages site, the repository-backed
generation pipeline, GitHub Actions credentials, published daily JSON and HTML, and
repository-external review artifacts.

Runtime implementation, workflow changes, GitHub setting changes, actual secret rotation,
actual incident-response execution, and production execution are out of scope for Version 1.0.
This is a short runbook proportionate to a personally managed static site, not a general
enterprise incident-response plan.

This document implements the documentation scope approved by
[SECURITY_REQUIREMENTS.md](SECURITY_REQUIREMENTS.md) Version 1.1, especially SR-043,
GAP-006, GAP-008, GAP-013, and GAP-014. It also follows the GAP-010 owner-checklist evidence
boundary, [SD-014](DECISIONS.md#sd-014--keep-daily-json-outside-the-github-pages-publication-tree-and-limit-stored-content),
[SD-024](DECISIONS.md#sd-024--approve-security-requirements-version-10-and-the-proportionate-security-roadmap),
[SD-025](DECISIONS.md#sd-025--approve-security-operations-version-10-and-the-minimal-incident-and-correction-policy),
and the approval boundaries in [AGENTS.md](AGENTS.md).

## 1. Purpose and operating principles

Monomi Digest does not handle life-safety operations, payments, or customer data. Its
public-information accuracy, repository integrity, credentials, and published Pages still have
protection value.

- Combine rapid containment with a safe, reviewable evidence trail.
- Apply the unconditional secret-value prohibition and evidence rules in section 9.
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

In this personally managed project, the same person may hold the Repository owner, Operator,
and User approval owner roles. Roles define responsibilities and approval boundaries, not a
required headcount. Keep the Reviewer independent from the change author where practicable.
Fable 5 or another agent review is supporting evidence and does not replace the User approval
owner's decision.

Only the Repository owner handles secret values, and only through approved secret stores.
Work and AI reviewers must not request or handle those values; see section 9. Normal
corrections use a branch, pull request, and CI. Production workflow execution, GitHub setting
changes, secret updates, Ready for review, and merge retain their separate approval boundaries.
Approval of Security Operations Version 1.0 is not unlimited advance approval for real
incident actions.

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

Follow the unconditional handling contract in section 9. Do not broaden the investigation
without need, rewrite Git history in haste, or rerun Gemini, external retrieval, or production
merely to diagnose the event. Before changing anything, record affected identifiers only in a
non-sensitive form.

If a credential value was published once in a commit, log, artifact, Pages output, or other
surface, a deletion commit alone is not containment: Git history, caches, logs, and copies may
retain it. The first response is immediate provider-side revocation or disablement. Removing
the value from files, HTML, or artifacts is secondary. History rewrite is not the normal
default.

If non-revocable private data or a legal deletion duty requires a history purge, do not treat
that as an automatic runbook step. Require incident-specific explicit approval, the current
GitHub or provider guidance, an impact assessment, and an after-action record.

The normal containment path is a dedicated branch and the smallest reviewable pull request:
prepare the smallest change, use a fast-track pull request, run relevant local tests and Pull
Request CI, complete a scope review, then obtain the normal approval and merge. Fast-track
never means skipping review or CI.

A direct public hotfix is an exceptional path only when continued publication creates
material public harm and the normal pull-request and CI path is clearly too slow. It requires
explicit approval from both the Repository owner and the User approval owner. If one person
holds both roles, record why the exception is necessary and record both approvals. The direct
change is normally limited to the affected public files in `docs/`; keep the diff minimal.
It must not change code, workflows, schemas, prompts, models, validation, secrets, or GitHub
settings, and it must not force-push or rewrite history. Do not call Gemini, RSS, NVD, other
external HTTP, or the production workflow. Run local validation when the available response
time permits.

Within 24 hours of a direct public hotfix, create an after-action branch and pull request that
reviews and, when needed, corrects the daily JSON; restores JSON/HTML consistency through
deterministic offline regeneration; runs relevant tests, the full unittest suite, and
`git diff --check`; records the incident and correction; receives an independent review; and
confirms the public Pages result. The exception is not a permanent bypass. (BL-030 removed the
unofficial translation endpoint and `docs/translate_cache.json`; no translation cache exists to
check in the current architecture.)

## 5. Secret, credential, and account response

Rotation or revocation is triggered by suspected disclosure, unexpected use, access or
collaborator change, provider compromise, or replacement of the credential owner.

Identify the credential by provider and secret name, review related runs and sanitized records,
and follow section 9 throughout. Use one of the following paths.

### Immediate revocation path

Use this path when active misuse or public exposure is suspected:

1. The Repository owner revokes or disables the affected credential at the provider first.
2. Accept temporary service interruption while containment takes priority.
3. Issue a replacement credential.
4. Update the approved secret store.
5. Perform only separately authorized validation.
6. Confirm explicitly that the old credential cannot be used.

### Controlled rotation path

Use this path when active misuse is not known but preventive rotation is required:

1. Issue a replacement credential.
2. Update the approved secret store.
3. Perform separately authorized minimal validation.
4. The Repository owner explicitly revokes the old credential.
5. Confirm explicitly that the old credential cannot be used.
6. Leave a non-sensitive record.

Never assume that issuing a new credential automatically invalidates the old one. This document
does not issue, update, validate, or revoke a real credential.

`GEMINI_API_KEY` is the required repository secret. `NVD_API_KEY` is optional and is currently
not configured at repository-secret scope according to the Security Requirements Version 1.1
owner verification completed on 2026-07-24. No value was inspected. Reverify this state after a
secret-inventory, workflow-reference, or provider-usage change. Both are long-lived provider
credentials when configured. A local credential, an environment secret, and a GitHub
repository secret are distinct storage or delivery contexts and must be checked separately.

The job-scoped `GITHUB_TOKEN` is issued by GitHub for a workflow run; it is not a long-lived
provider secret to be rotated using the procedure above. Respond instead by containing the
affected run or repository access and reviewing the workflow permissions and platform event.
This document performs no secret update, real API validation, or production execution.

### GitHub owner account or repository access compromise

For suspected compromise of a GitHub password or session, personal access token, SSH key,
OAuth or GitHub App authorization, recovery method, MFA, collaborator access, or repository
access:

1. Use GitHub's current account-security controls to inventory and revoke suspicious sessions,
   tokens, keys, and authorizations.
2. Check and recover the password, MFA, and recovery methods.
3. Review available security-log or audit information.
4. Review recent commits, branches, workflow runs, repository settings, and the secret
   inventory.
5. Identify unauthorized changes.
6. Record containment results without credential values, following section 9.
7. Route unauthorized public output through section 7.
8. Route unauthorized workflow or code changes through the smallest normal fix pull request
   and a complete scope review.
9. If the owner cannot access the account, use GitHub's current account-recovery or support
   route.

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

Apply section 9 to the incident record. Record no secret or authentication value.

## 7. Published-output correction, withdrawal, and regeneration

Treat these as separate assets:

- `data/YYYY-MM-DD.json`;
- `data/index.json`;
- `docs/index.html`;
- `docs/archive/YYYY-MM-DD.html`;
- `docs/archive/index.html`;
- Git repository history; and
- repository-external screenshots and evaluation artifacts.

Material content-integrity problems include a fact absent from the source; changed actor or
scope; a material date, number, or product error; unsupported financial impact;
prompt-injection-derived output; or publication of an internal identifier or private data.

The default is:

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

When a supported replacement is available, correct the affected `data/YYYY-MM-DD.json`, keep
`data/index.json` consistent, run daily JSON validation, and regenerate every derived HTML
surface from the corrected data offline. Run relevant tests and the full unittest suite, run
`git diff --check`, and after an authorized merge confirm Pages.
For a material correction, directly verify the public result. Because manual changes to
generated output are a separate approval boundary, the correction pull request must identify
the exact affected date and files.

Preserve the original in Git history. Do not force-push or rewrite history, rerun Gemini or
external HTTP, run production, change an unapproved contract, or leave JSON and HTML changed
on only one side without an explicit record. The canonical evidence is the BL correction
record, commit, pull request, affected dates and files, source-supported diff, validation
results, Pages result, and user acceptance when it is required. Version 1.0 does not add a
dedicated `INCIDENTS.md`.

### Withdrawal

Withdraw when a correct replacement cannot be produced promptly and continued publication has
material impact. First use an explicit withdrawal or correction notice that preserves
navigation and the Archive. If that is insufficient, use blank output; delete an article or
page only as a last resort.

Version 1.0 does not add a schema field, UI component, temporary ARTICLE text, schema change,
or renderer change. The first real withdrawal requires a separate ticket and user approval,
must preserve navigation, Archive, and daily-JSON contracts, and may use the direct-public-
hotfix exception only when section 4's emergency conditions are met. Reevaluate a dedicated
schema or UI contract if withdrawals recur.

### Regeneration

1. Validate the corrected existing daily JSON.
2. Regenerate the affected daily Archive HTML offline.
3. Regenerate the current top page when the corrected date is represented there.
4. Rebuild the Archive index and confirm previous/next navigation did not regress.
5. Do not run the production workflow.
6. Do not call Gemini, RSS, NVD, or other external HTTP.

### Source suspension (added in Version 1.1, from BL-030/BL-031)

BL-030 removed the unofficial translation endpoint and `docs/translate_cache.json`; no
translation-cache correction step applies to the current architecture.

Use this procedure when a source's official terms, license, robots.txt, or AI-provider
data-use condition changes, or when a new issue with an already-enabled source is identified
(distinct from the incident path in sections 5–6, which covers credentials and account
compromise, not source-terms review):

1. Confirm the specific term, license clause, robots.txt rule, or AI-provider condition that
   changed or was newly identified, and record its official URL and the date checked.
2. Set the affected source's `enabled` to `false` in `source_definitions.json` and record a
   specific `activation_condition` describing what must be confirmed before re-enabling it.
   Record `terms_url`, `checked_at`, and the recheck trigger in
   [SOURCE_USAGE_POLICY.md](SOURCE_USAGE_POLICY.md) alongside it.
3. This is a temporary, precautionary pause, not a determination that the source's terms were
   in fact violated. Do not represent it as a legal conclusion in the commit, pull request, or
   BACKLOG/STATUS/DECISIONS record.
4. Do not modify, delete, or regenerate any past `data/*.json` or `docs/archive/*.html` as part
   of a source suspension. Stopping future collection from a source and correcting or removing
   its past published articles are separate decisions; the latter follows the published-output
   correction/withdrawal procedure above (section 7) and requires its own explicit trigger and
   approval — suspending a source alone is never sufficient justification to rewrite or delete
   its past output.
5. Confirm the source is excluded from `RSS_FEEDS`/`build_footer_sources()` (via the
   `enabled` filter) and, for a JSON-API source, from its non-RSS collection path.
6. Do not call the source's live feed, API, or robots.txt to verify the suspension; rely on the
   already-recorded official information and read-only repository verification (tests, `enabled`
   state) instead.
7. Record the suspension in the same governance documents used for other tickets (BACKLOG.md,
   STATUS.md; DECISIONS.md only if the user separately accepts a Stable Decision), following the
   normal branch/PR/test/review path — not as a direct public hotfix under section 4 unless its
   emergency conditions are independently met.

If a takedown or correction request is received for a source's already-published articles
(from the source's publisher, a reader, or another party), route it through section 7
(published-output correction/withdrawal), not through this source-suspension procedure alone;
suspending future collection does not by itself satisfy a takedown request for existing
publication.

### Validation

Confirm daily JSON validation, HTML escaping, safe URLs, Archive consistency, top/Archive
consistency, relevant tests, full unittest, and `git diff --check`. After an authorized merge,
confirm the Pages deployment result and decide whether the public page requires direct
verification.

## 8. Repository-external artifact handling

Before creating an artifact, classify it, identify its intended reviewers, and set its
retention or disposal decision. Limit access and sharing to those identified reviewers. The
unconditional secret prohibition in section 9 always takes priority.

Only non-secret, minimized information can have a specific approved retention need:

- a raw public response;
- a sanitized local path;
- relevant personal or account metadata; or
- non-secret data beyond the normal production storage scope.

The exception record must state the reason, exact retained items, owner, access scope, review
or deletion date, secret-scan result, and approval reference.

Detailed artifacts normally expire 90 days after the evaluation is completed:

- raw requests and responses;
- model responses and detailed evaluation bundles;
- screenshots containing detailed local or raw context; and
- temporary debugging output.

At or before the deletion date, delete raw artifacts when a sanitized or minimized derivative,
manifest, hash list, gate summary, or approved BL, SD, user-acceptance, merge, or No-Go record
can preserve the decision evidence. Do not default to retaining raw artifacts long-term merely
because a decision needs evidence.

A screenshot may be designated for longer retention only when the screenshot itself is
necessary and contains no secret or credential value, unnecessary local path, or unrelated
personal information. Section 9 overrides every long-term evidence designation. An artifact
that cannot be sanitized because it contains a secret value is not retained; revoke the
credential and remove the artifact from the retained set.

Retention beyond 90 days requires the User approval owner's approval and a record of the
reason, exact retained items, owner, access scope, secret-scan result, approval reference, and
next review or deletion date. Prefer a sanitized summary, manifest, hash list, gate result, or
BL/SD/user-acceptance/merge/No-Go record for long-term evidence. Retain raw material long-term
only when it is indispensable and safe. Existing artifacts are not deleted by Version 1.0;
review them at the next artifact inventory. No retention automation, cron job, or cleanup
script is introduced. GitHub Actions log and platform-artifact retention are platform settings
and are not this repository-external artifact policy.

## 9. Canonical secret and sensitive-evidence contract

Never store a secret value, credential value, full token, authorization header, cookie, private
key, recovery code, or equivalent authentication material in incident evidence,
repository-external artifacts, screenshots, manifests, logs, documents, the repository, or
generated output. No approval can authorize storing these values in evidence or review
artifacts. Evidence preservation is never a reason to keep them.

Do not retain an unredacted copy before redaction. Do not retain a hash when it could be used to
verify, recover, or abuse a credential.

This prohibition does not prevent operational credential storage in approved secret stores,
including GitHub Actions Secrets, provider-managed secret storage, or an approved operating
system or credential manager. It prohibits copying the value from those stores into evidence,
artifacts, repository content, generated output, or logs.

Safe evidence includes a commit SHA, pull request URL, workflow or Pages run URL, non-sensitive
file path, affected date, screenshot that passed the section 8 review, sanitized error
category, and sanitized artifact manifest or hash list. Apply the section 8 approval and
retention record to any exceptional non-secret sensitive information.

## 10. Validation and closure

Close every incident or correction only when containment and all applicable validation are
complete, evidence is sanitized, residual risk or `none identified` is recorded, and the
responsible owner confirms closure.

Apply the remaining conditions only when relevant:

- complete credential revocation or rotation when credentials were involved;
- correct or withdraw affected public output when public content was affected;
- confirm JSON and HTML consistency when `data/` or `docs/` changed;
- confirm deployment when public output changed;
- directly verify the public result for a material public change, a security or
  content-integrity correction, or a display-contract change; and
- register a follow-up ticket when residual work or recurrence prevention remains. Otherwise,
  record `not required` and the reason in the incident record.

A merged documentation or code pull request alone is not incident closure.

## 11. Approved operational decisions

The user approved the following Version 1.0 decisions:

1. **Emergency hotfix:** default to a fast-track branch and pull request without skipping CI.
   Permit a direct public hotfix only under section 4's material-harm, dual-approval,
   constrained-scope, and 24-hour after-action requirements.
2. **Withdrawal:** prefer an explicit notice over blank output, and use article or page deletion
   only last. Preserve navigation, Archive, and daily-JSON contracts. Add no schema or UI now;
   use a separate ticket and user approval for the first real withdrawal and reconsider a
   dedicated contract if withdrawals recur.
3. **Material daily JSON correction:** when a supported replacement exists, correct daily JSON,
   deterministically regenerate HTML, retain the original in Git history, and use the BL entry,
   commit, pull request, validation, Pages result, and any required user acceptance as the
   normal evidence. Do not add a dedicated incident document now.
4. **Correction notice contract:** add no schema or UI now. Reevaluate if corrections recur and
   existing evidence is insufficient for readers.
5. **Artifact retention:** start the detailed-artifact 90 days at evaluation completion, let
   the User approval owner approve and record longer exceptions, and prefer sanitized decision
   evidence over raw artifacts for long-term retention.
6. **AGENTS.md reference:** add only a short paragraph directing
   incidents, secret rotation, and published-output correction or withdrawal to this runbook;
   do not change existing operation-specific approval boundaries.

Version 1.1 (Draft) adds:

7. **Translation-cache removal:** the "Translation cache" correction subsection is removed; it
   no longer applies after BL-030 deleted the unofficial translation endpoint and
   `docs/translate_cache.json`.
8. **Source suspension:** a source-terms change or newly identified issue is handled by
   temporarily setting `enabled: false` with a specific `activation_condition` and a
   [SOURCE_USAGE_POLICY.md](SOURCE_USAGE_POLICY.md) record, without asserting a legal
   determination, without calling the source's live feed/API/robots.txt to verify, and without
   modifying past `data/*.json` or `docs/archive/*.html` as a side effect. Correcting or
   withdrawing a source's already-published articles remains a separate decision under section
   7's published-output procedure.
9. **Gemini Paid/Unpaid Services verification:** the owner may confirm only a non-confidential
   yes/no ("is there an active Cloud Billing account associated with the Gemini API key's
   Project") to support BL-032's future content-usage-mode enforcement; API keys, billing
   amounts, account identifiers, and screenshots of billing/account screens must never be
   recorded in the repository, following the unconditional secret prohibition in section 9.
10. **BL-031 audit boundary:** the read-only official-terms audit recorded in
    [SOURCE_USAGE_POLICY.md](SOURCE_USAGE_POLICY.md) Draft 0.1 does not itself change runtime
    behavior beyond the Dark Reading suspension it also records; BL-032 remains the separate,
    later-approved implementation of any production content-usage-mode enforcement.

## 12. Approval and maintenance

Version 1.0 is approved. External Fable 5 review is complete:
Critical 0 and High 1 (F-001). The adjudication of F-001 through F-010 is incorporated into
Draft 0.2. Fable 5 could not retrieve `test_security_operations.py`; it did not review that
file. The test was independently inspected at the PR head and strengthened under F-011.

The user approved the complete final decision brief with 「ok」, including emergency public
hotfix limits, withdrawal priority, material daily-JSON correction, no correction-notice
schema or UI change now, the artifact-retention rule, and the minimal AGENTS reference. This
review and Version update make no runtime, workflow, schema, prompt, model, validation,
generated-output, or production change. [SECURITY_REQUIREMENTS.md](SECURITY_REQUIREMENTS.md)
Version 1.1 records the documentation completion of GAP-006, GAP-008, GAP-013, and GAP-014.

**Version 1.1 is a Draft, not an approved maintenance update.** It records the removal of the
translation-cache correction step (BL-030) and adds the source-suspension procedure, the
Gemini Paid/Unpaid Services owner-verification boundary, and the BL-031/BL-032 audit-versus-
enforcement boundary described above. It makes no runtime, workflow, schema, prompt, model,
validation, generated-output, or production change; `source_definitions.json`'s `enabled`
field for CrowdStrike, Cloudflare, and Dark Reading was changed by BL-030/BL-031 themselves,
not by this document. This Version remains Draft until the user reviews and accepts it.

Review this runbook when an incident or architecture change exposes a missing boundary. A
mechanical annual update is not required.
