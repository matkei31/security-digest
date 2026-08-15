# Monomi Digest Security Operations

- **Version:** 1.3
- **Status:** Approved
- **As of:** 2026-08-15

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
- a failed scheduled production run whose missed date has not been recovered;
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

### Scheduled production failure recovery (added in Version 1.3, from BL-040)

The Daily Security Digest workflow runs once per scheduled day. `fetch.py` collects with a
cutoff of `DAYS_BACK` days before the run, and the daily JSON and its Archive page are keyed to
the JST calendar date of the run itself. A later ordinary run therefore produces its own date,
not the date that was missed. **A failed run is not repaired by waiting.**

1. Confirm the failure before acting: identify the failed run ID and which step failed. Do not
   assume a notification arrived — notification delivery is platform behavior, not a contract of
   this repository.
2. Treat recovery within the same JST calendar date as the objective. Once the JST date has
   changed, an ordinary rerun no longer backfills the missed date.
3. Obtain the explicit approval that production execution already requires (section 2).
   Approving this runbook does not pre-approve `workflow_dispatch`, and this procedure does not
   change that approval boundary.
4. With that approval, rerun the workflow once via `workflow_dispatch`.
5. Verify after the rerun: run success; the expected `data/YYYY-MM-DD.json`; the matching
   `docs/archive/YYYY-MM-DD.html`; `data/index.json` and the Archive index; and the automatic
   Pages deployment.
6. If same-day recovery did not happen, record the missing date and the resulting content gap.
   **Do not treat the next ordinary run as recovering it.** Any backfill is a separate action
   with its own procedure and approval.

This procedure adds no automatic retry, automatic backfill, push retry or rebase, and no
additional schedule. It changes no workflow file.

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
6. Do not run production, the Gemini API, or routine automated collection against the source to
   verify the suspension, and do not scrape article bodies or perform bulk retrieval. A
   read-only check of the source's official terms, license, robots.txt, or official feed-
   guidance page is permitted as an approved investigation step to confirm the specific
   condition in step 1 — record the date checked, the official URL, and what was confirmed
   alongside the already-recorded official information and read-only repository verification
   (tests, `enabled` state). If the trigger is a rightsholder correction/removal/stop request,
   do not make re-checking the source a precondition of responding to it.
7. Record the suspension in the same governance documents used for other tickets (BACKLOG.md,
   STATUS.md; DECISIONS.md only if the user separately accepts a Stable Decision), following the
   normal branch/PR/test/review path — not as a direct public hotfix under section 4 unless its
   emergency conditions are independently met.

If a takedown or correction request is received for a source's already-published articles
(from the source's publisher, a reader, or another party), route it through section 7
(published-output correction/withdrawal), not through this source-suspension procedure alone;
suspending future collection does not by itself satisfy a takedown request for existing
publication.

### Content usage mode downgrade (`limited_feed_analysis`, added in Version 1.1, from BL-031; updated in Version 1.2 for BL-032 runtime enforcement)

`limited_feed_analysis` (defined in [SOURCE_USAGE_POLICY.md](SOURCE_USAGE_POLICY.md) section 3C)
is an explicit, bounded risk acceptance for a small number of sources, not a determination that
their terms permit reuse. Use this procedure to downgrade a `limited_feed_analysis` source (or
any other source's content usage mode) when any of the following occurs: its official terms or
license change; the machine-readable instructions (e.g. robots.txt) governing it change; its
feed path or availability changes; the source's publisher, a rightsholder, or another party
submits a correction, removal, or stop request; a confirmed output-similarity/quotation-control
violation or attribution failure is found in generated output; or source-specific terms are
discovered where none were previously identified.

BL-032 has implemented and merged per-source content-usage-mode runtime enforcement
([PR #69](https://github.com/matkei31/security-digest/pull/69)). `source_definitions.json`'s
`policy` object — specifically `policy.content_usage_mode` and its associated boolean fields
(`allow_network_fetch`, `allow_description`, `allow_rich_content`, `allow_ai_processing`,
`allow_excerpt_storage`, `allow_public_summary`) — is the runtime source of truth for what
`fetch.py` and `daily_json.py` actually do with a source's content at collection, Gemini-input,
storage, and publication time. [SOURCE_USAGE_POLICY.md](SOURCE_USAGE_POLICY.md) is the separate
policy/evidence source of truth: it records the audited mode, the official evidence, the
confidence, the unresolved issues, and the recheck trigger for each source. The two documents
must be kept in sync by the same change; updating only one does not produce the intended
runtime or evidentiary result.

1. Record the specific trigger (which of the above occurred), its official URL where
   applicable, and the date checked.
2. To actually change future collection, AI-processing, storage, or publication behavior for
   the source, update `source_definitions.json`'s `policy.content_usage_mode` for that source to
   `metadata_only` or `disabled_legal_review`, whichever the trigger and its severity warrant,
   together with the boolean fields that mode requires (see steps 3–4 below). A
   [SOURCE_USAGE_POLICY.md](SOURCE_USAGE_POLICY.md) change alone, without this
   `source_definitions.json` change, does not alter runtime behavior.
3. For a downgrade to `metadata_only`, set at minimum in `source_definitions.json`:
   - `policy.content_usage_mode: "metadata_only"`;
   - `policy.allow_description`, `policy.allow_ai_processing`, `policy.allow_excerpt_storage`,
     and `policy.allow_public_summary` all `false` (required by `metadata_only`'s validation
     contract in `fetch.py`); `policy.allow_network_fetch` may remain `true`, since
     `metadata_only` still fetches feed metadata (title, link, published date) without using
     description, AI processing, excerpt storage, or public summary.
4. For a downgrade to `disabled_legal_review`, also follow the source-suspension procedure above
   (set `enabled: false` in `source_definitions.json` with a specific `activation_condition`)
   and set at minimum in `source_definitions.json`:
   - `policy.content_usage_mode: "disabled_legal_review"`;
   - `policy.allow_network_fetch`, `policy.allow_description`, `policy.allow_ai_processing`,
     `policy.allow_excerpt_storage`, and `policy.allow_public_summary` all `false`.
5. In the same change, update the source's row in
   [SOURCE_USAGE_POLICY.md](SOURCE_USAGE_POLICY.md) — its `proposed_mode` column, `checked_at`,
   `unresolved_issue`, `recheck_trigger`, and evidence cells (`official_evidence_url`,
   `evidence_type`, `confidence`, `attribution_requirement`) — to match the new mode and the
   reason recorded in step 1, so the policy/evidence document does not go stale relative to
   `source_definitions.json`.
6. A mode change moves the source from one content-usage-mode bucket to another, so it also
   changes the per-mode count distribution recorded in
   [SOURCE_USAGE_POLICY.md](SOURCE_USAGE_POLICY.md) section 4 (the "件数集計" line, currently
   `structured_open 5, feed_summary 4, limited_feed_analysis 2, metadata_only 2,
   disabled_legal_review 4, 合計17`) and enforced at runtime by `fetch.py`'s
   `EXPECTED_CONTENT_USAGE_MODE_COUNTS` constant, which
   `validate_content_usage_mode_distribution()` checks against `source_definitions.json`'s
   actual counts at module load — including at the start of every production run — and fails
   closed with a `SourceDefinitionError` on any mismatch. In the same change:
   - update the "件数集計" line in [SOURCE_USAGE_POLICY.md](SOURCE_USAGE_POLICY.md) section 4 to
     the new distribution;
   - update `EXPECTED_CONTENT_USAGE_MODE_COUNTS` in `fetch.py` to the same new distribution
     (decrement the source's previous mode by 1, increment its new mode by 1; the total stays 17
     unless the source count itself changes);
   - update the tests that lock this distribution, at minimum
     `test_content_usage_policy.py`'s `EXPECTED_CONTENT_USAGE_MODE_COUNTS`-based assertions and
     `test_source_usage_policy.py`'s "合計17" check.
   Skipping this step does not silently succeed: leaving `EXPECTED_CONTENT_USAGE_MODE_COUNTS`
   unchanged means the very next `source_definitions.json` load — including the next scheduled
   production run — fails closed with a count-mismatch error.
7. Because this step changes a runtime constant in `fetch.py`, an actual mode-change ticket's
   scope must explicitly include that `fetch.py` change; it is not an incidental side effect of
   an otherwise documentation-only change.
8. This is a precautionary downgrade, not a legal determination that the source's terms were in
   fact violated; do not represent it as a legal conclusion in the commit, pull request, or
   BACKLOG/STATUS/DECISIONS record.
9. Do not modify, delete, or regenerate any past `data/*.json` or `docs/archive/*.html` as a
   side effect of a mode downgrade; a takedown or correction request for already-published
   articles is handled separately through section 7, following the same principle as the
   source-suspension procedure above.
10. Do not run production, the Gemini API, or routine automated collection against the source to
    verify the downgrade trigger, and do not scrape article bodies or perform bulk retrieval. A
    read-only check of the source's official terms, license, robots.txt, or official feed-
    guidance page is permitted as an approved investigation step to confirm the specific trigger
    in step 1 — record the date checked, the official URL, and what was confirmed alongside the
    already-recorded official information, the reported trigger, and read-only repository
    verification. If the trigger is a rightsholder correction/removal/stop request, do not make
    re-checking the source a precondition of responding to it.
11. Run source-definition validation (source load succeeds and the content-usage-mode
    distribution check against the updated `EXPECTED_CONTENT_USAGE_MODE_COUNTS` passes), the
    relevant `test_content_usage_policy.py`/`test_source_definitions.py`/
    `test_source_usage_policy.py` coverage, and the full unittest suite; run `git diff --check`;
    and complete a scope review confirming no unrelated file changed.
12. Record the downgrade through the normal branch/PR/test/review path (BACKLOG.md, STATUS.md;
    DECISIONS.md only if the user separately accepts a Stable Decision) — not as a direct public
    hotfix under section 4 unless its emergency conditions are independently met. Do not run
    production, the Gemini API, `workflow_dispatch`, or routine external collection as part of
    recording the downgrade without separate explicit approval.

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

Version 1.1 adds:

7. **Translation-cache removal:** the "Translation cache" correction subsection is removed; it
   no longer applies after BL-030 deleted the unofficial translation endpoint and
   `docs/translate_cache.json`.
8. **Source suspension:** a source-terms change or newly identified issue is handled by
   temporarily setting `enabled: false` with a specific `activation_condition` and a
   [SOURCE_USAGE_POLICY.md](SOURCE_USAGE_POLICY.md) record, without asserting a legal
   determination and without modifying past `data/*.json` or `docs/archive/*.html` as a side
   effect. Verification is limited to a read-only, dated, URL-recorded check of the source's
   official terms, license, robots.txt, or official feed-guidance page as an approved
   investigation step; no production run, Gemini API call, routine automated collection,
   article-body scraping, or bulk retrieval is performed to verify it, and a rightsholder
   correction/removal/stop request is never made contingent on re-checking the source first.
   Correcting or withdrawing a source's already-published articles remains a separate decision
   under section 7's published-output procedure.
9. **Gemini Paid/Unpaid Services verification:** the owner may confirm only a non-confidential
   yes/no ("is there an active Cloud Billing account associated with the Gemini API key's
   Project") to support BL-032's future content-usage-mode enforcement; API keys, billing
   amounts, account identifiers, and screenshots of billing/account screens must never be
   recorded in the repository, following the unconditional secret prohibition in section 9.
   **Completed 2026-07-29:** the owner confirmed, via the Google AI Studio API Keys screen,
   that the `security-digest` Google Cloud Project used for the Gemini API key has active
   Cloud Billing (Tier 1, pay-as-you-go); `gemini_data_use_status` is recorded as
   `paid_verified` in [SOURCE_USAGE_POLICY.md](SOURCE_USAGE_POLICY.md) section 5 and
   [SECURITY_REQUIREMENTS.md](SECURITY_REQUIREMENTS.md) SR-045/GAP-017. No API key, Project ID,
   billing account ID, amount, or screenshot was recorded. If the billing association is later
   cancelled, the Project changes, or the API key migrates to a different Project, this
   verification must be repeated before continuing to rely on `paid_verified`. **Version 1.2
   note:** BL-032's content-usage-mode enforcement referenced above is complete as of Version
   1.2 (see the updated "Content usage mode downgrade" procedure in section 7).
10. **BL-031 audit boundary:** the read-only official-terms audit recorded in
    [SOURCE_USAGE_POLICY.md](SOURCE_USAGE_POLICY.md) Approved 0.1 does not itself change runtime
    behavior beyond the Dark Reading suspension it also records; at Version 1.1 approval time,
    [BL-032](BACKLOG.md#bl-032--取得元別content-usage-policy-enforcement) (registered,
    要件定義済み／未着手) remained the separate, later-approved implementation of any production
    content-usage-mode enforcement. **Version 1.2 update:** BL-032 is now complete and merged
    ([PR #69](https://github.com/matkei31/security-digest/pull/69)); `source_definitions.json`'s
    `policy` object is the current runtime enforcement source of truth (see the updated "Content
    usage mode downgrade" procedure in section 7).
11. **`limited_feed_analysis` content usage mode:** a new fifth content usage mode is recorded
    for `the_hacker_news` and `krebs_on_security` — an explicit, bounded risk acceptance, not a
    determination that their terms permit reuse. A terms/machine-readable-instruction/feed-path
    change, a rightsholder correction/removal/stop request, a confirmed output-policy violation,
    or discovery of source-specific terms triggers a downgrade to `metadata_only` or
    `disabled_legal_review` under the new "Content usage mode downgrade" procedure in section 7,
    without asserting a legal determination and without modifying past `data/*.json` or
    `docs/archive/*.html` as a side effect.

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

**Version 1.1 is an Approved maintenance update, recorded by
[SD-030](DECISIONS.md#sd-030--approve-source-usage-policy-version-01-and-defer-runtime-enforcement-to-bl-032).**
It records the removal of the translation-cache correction step (BL-030) and adds the
source-suspension procedure, the Gemini Paid/Unpaid Services owner-verification boundary
(including its 2026-07-29 completion), the `limited_feed_analysis` content-usage-mode downgrade
procedure, and the BL-031/BL-032 audit-versus-enforcement boundary described above. It makes no
runtime, workflow, schema, prompt, model, validation, generated-output, or production change;
`source_definitions.json`'s `enabled` field for CrowdStrike, Cloudflare, and Dark Reading was
changed by BL-030/BL-031 themselves, not by this document. [PR #67](https://github.com/matkei31/security-digest/pull/67)
accepted head `897fc9db365e890318fc694a7fbf9cd8eab65ae1` received a final ChatGPT independent
review with no remaining implementation or documentation blockers; [Pull Request CI run
30557479373](https://github.com/matkei31/security-digest/actions/runs/30557479373) succeeded;
full unittest was 1391 tests OK; unresolved review threads were 0. The user approved BL-031's
acceptance, Ready status, and a regular merge-commit merge (merge commit
`61feb679fad6bd2252c58cd8acb4696294032629`), and on 2026-07-31 approved this Version's own
Approved status. **This approval makes no additional runtime, workflow, schema, prompt, model,
validation, generated-output, or production change beyond what BL-030/BL-031 already made; it
is not a pre-approval of BL-032's runtime enforcement implementation, of production execution,
of `workflow_dispatch`, or of any GitHub-side setting change.**

**Version 1.2 is an Approved maintenance update, approved as of 2026-08-03.** It synchronizes this runbook's
content-usage-mode downgrade procedure (section 7) with BL-032's runtime enforcement, which was
registered as future work when Version 1.1 was approved and has since been implemented and
merged ([PR #69](https://github.com/matkei31/security-digest/pull/69)). It replaces the
Version 1.1 premise that a `metadata_only` downgrade requires only a
[SOURCE_USAGE_POLICY.md](SOURCE_USAGE_POLICY.md) change with the current requirement to update
`source_definitions.json`'s `policy.content_usage_mode` and its associated boolean fields in the
same change, since that is what `fetch.py`/`daily_json.py` actually read at runtime. It also adds
the previously missing requirement to keep [SOURCE_USAGE_POLICY.md](SOURCE_USAGE_POLICY.md)
section 4's per-mode count tally, `fetch.py`'s `EXPECTED_CONTENT_USAGE_MODE_COUNTS` constant, and
the tests that lock that distribution in sync with an actual mode change (this Version does not
change `EXPECTED_CONTENT_USAGE_MODE_COUNTS`'s current values — it records the future requirement
to update them). It also corrects section 11 item 10's stale description of BL-032 as
"registered, 要件定義済み／未着手"
(accurate only as of the Version 1.1 approval date, and now labeled as such), and fixes
[AGENTS.md](AGENTS.md)'s and [STATUS.md](STATUS.md)'s references to this document's own Version,
to `.github/workflows/pr-ci.yml`'s existence and actual checkout target, and to
`.github/workflows/fetch.yml`'s actual triggers. Version 1.2 makes no runtime, workflow,
schema, prompt, model, validation, generated-output, source-definition, or production change;
`source_definitions.json`'s `policy.content_usage_mode` values were set by BL-032 itself, not by
this Version. This Version's scope is defined and tracked as
[BL-035](BACKLOG.md#bl-035--bl-032後の運用手順とagent統制文書を現在状態へ同期する).

**Version 1.2 was accepted via [PR #75](https://github.com/matkei31/security-digest/pull/75).**
Independent Fable 5 review found Blockers across two rounds and no remaining Blocker after the
second: round 1 identified the mode-downgrade procedure's missing count-distribution sync step
and AGENTS.md's stale "the only push/schedule workflow" description of `fetch.yml`; round 2
identified that AGENTS.md still misdescribed `pr-ci.yml`'s checkout target as the PR head rather
than GitHub's auto-generated merge candidate, and a self-contradiction between `fetch.yml`'s
commit/push and the GitHub Pages deployment description. Both rounds' Blockers were fixed on the
same branch and pull request. The user reviewed PR #75's final content, confirmed no remaining
Blockers after review round 2, and accepted: BL-035's implementation, this Version 1.2 as
Approved, Ready-for-review status for PR #75, and a regular merge-commit merge — at accepted
implementation head `43bc14c584c05ed6539e20b9cba000e784d70bd3`. Evidence: full unittest 1622
tests OK; Pull Request CI [run 30801691143](https://github.com/matkei31/security-digest/actions/runs/30801691143)
success; `git diff --check` success; changed files 9
(`AGENTS.md`, `BACKLOG.md`, `SECURITY_OPERATIONS.md`, `STATUS.md`, `test_fetch.py`,
`test_security_operations.py`, `test_security_requirements.py`, `test_source_definitions.py`,
`test_status.py`); unresolved review threads 0. **This approval makes no runtime, workflow,
schema, prompt, model, validation, generated-output, source-definition, policy-value, or
production change beyond BL-035's documentation/governance-only scope described above; it is
not a pre-approval of an actual content-usage-mode change, of production execution, of
`workflow_dispatch`, or of any GitHub-side setting change.**

**Version 1.3 is an Approved maintenance update.** It adds one procedure to section 7 —
scheduled production failure recovery — and the matching event to section 3, from
[BL-040](BACKLOG.md#bl-040--scheduled-production失敗時の同日回復手順), which was raised by the
[BL-008](BACKLOG.md#bl-008--fable-5による全体コードレビュー) whole-repository review on
2026-08-15. The procedure records something the pipeline already implied but no document stated:
because the daily JSON and Archive page are keyed to the run's own JST date, a run that fails is
not recovered by the next ordinary run. It therefore requires same-JST-day recovery, explicit
approval for the `workflow_dispatch` rerun, post-rerun verification, and an explicit record of
the gap when same-day recovery does not happen. It also records Version 1.2's approval date
(2026-08-03) inside this section, so that fact no longer depends on the document header, which
now names the current Version. Version 1.3 makes **no runtime, workflow, schema, prompt, model,
validation, generated-output, source-definition, or production change**, adds no automatic
retry/backfill mechanism, and **does not pre-approve production execution or
`workflow_dispatch`** — section 2's approval boundary is unchanged. **Version 1.3 was accepted by the user on 2026-08-15 (最終受入日 2026-08-15)** as part of [PR #131](https://github.com/matkei31/security-digest/pull/131), together with BL-040's and BL-041's implementations, after an independent review returned ACCEPT with Blocker 0 at reviewed head `42d1dbb0f34fcad29f011d5adc155907d24bd0ea` (exact-head [Pull Request CI run 31865317942](https://github.com/matkei31/security-digest/actions/runs/31865317942) success on Python 3.12.13, full unittest 2356 OK). **This approval is not unconditional advance approval of `workflow_dispatch`, not blanket approval of production execution, does not introduce automatic backfill, and changes no workflow file — section 2's approval boundaries stand unchanged.** Versions 1.2 and earlier keep their own records above unchanged.

Review this runbook when an incident or architecture change exposes a missing boundary. A
mechanical annual update is not required.
