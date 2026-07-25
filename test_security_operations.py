#!/usr/bin/env python3
"""Static contract tests for BL-024 SECURITY_OPERATIONS.md Version 1.0."""

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent
OPERATIONS_PATH = ROOT / "SECURITY_OPERATIONS.md"


def github_anchor(heading):
    lowered = heading.strip().lower()
    kept = [ch for ch in lowered if ch.isalnum() or ch in (" ", "-", "_")]
    return "".join(kept).replace(" ", "-")


def compact_whitespace(text):
    return re.sub(r"\s+", " ", text)


class SecurityOperationsContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.operations = OPERATIONS_PATH.read_text(encoding="utf-8")
        cls.backlog = (ROOT / "BACKLOG.md").read_text(encoding="utf-8")
        cls.status = (ROOT / "STATUS.md").read_text(encoding="utf-8")
        cls.decisions = (ROOT / "DECISIONS.md").read_text(encoding="utf-8")

    def section(self, start, end):
        return self.operations.split(start, 1)[1].split(end, 1)[0]

    def test_version_10_identity_review_record_and_user_approval(self):
        self.assertTrue(OPERATIONS_PATH.exists())
        self.assertIn("# Security Digest Security Operations", self.operations)
        self.assertIn("**Version:** 1.0", self.operations)
        self.assertIn("**Status:** Approved", self.operations)
        approval = self.section("## 12. Approval and maintenance", "\nReview this runbook")
        for contract in (
            "Critical 0",
            "High 1 (F-001)",
            "F-001 through F-010",
            "could not retrieve `test_security_operations.py`",
            "did not review that file",
            "independently inspected",
            "F-011",
            "Version 1.0 is approved",
            "complete final decision brief with 「ok」",
            "no runtime, workflow, schema, prompt, model, validation, "
            "generated-output, or production change",
        ):
            with self.subTest(contract=contract):
                self.assertIn(contract, compact_whitespace(approval))

    def test_requirements_and_decision_references(self):
        for reference in (
            "SECURITY_REQUIREMENTS.md",
            "SR-043",
            "GAP-006",
            "GAP-008",
            "GAP-013",
            "GAP-014",
            "GAP-010",
            "SD-014",
            "SD-024",
            "SD-025",
            "AGENTS.md",
        ):
            with self.subTest(reference=reference):
                self.assertIn(reference, self.operations)

    def test_canonical_secret_prohibition_is_unconditional(self):
        evidence = self.section(
            "## 9. Canonical secret and sensitive-evidence contract",
            "## 10. Validation and closure",
        )
        compact = compact_whitespace(evidence)
        for prohibited in (
            "secret value",
            "credential value",
            "full token",
            "authorization header",
            "cookie",
            "private key",
            "recovery code",
            "equivalent authentication material",
        ):
            with self.subTest(prohibited=prohibited):
                self.assertIn(prohibited, compact)
        for surface in (
            "incident evidence",
            "repository-external artifacts",
            "screenshots",
            "manifests",
            "logs",
            "documents",
            "repository",
            "generated output",
        ):
            with self.subTest(surface=surface):
                self.assertIn(surface, compact)
        self.assertIn("No approval can authorize", compact)
        self.assertIn("never a reason to keep them", compact)
        self.assertIn("Do not retain an unredacted copy", compact)
        self.assertIn("Do not retain a hash when it could be used", compact)

    def test_approved_secret_stores_are_not_mistaken_for_evidence(self):
        evidence = self.section(
            "## 9. Canonical secret and sensitive-evidence contract",
            "## 10. Validation and closure",
        )
        compact = compact_whitespace(evidence)
        self.assertIn("approved secret stores", compact)
        self.assertIn("GitHub Actions Secrets", compact)
        self.assertIn("provider-managed secret storage", compact)
        self.assertIn("operating system or credential manager", compact)
        self.assertIn("copying the value from those stores into evidence", compact)

    def test_only_non_secret_data_can_use_an_approved_artifact_exception(self):
        artifact = self.section(
            "## 8. Repository-external artifact handling",
            "## 9. Canonical secret and sensitive-evidence contract",
        )
        compact = compact_whitespace(artifact)
        self.assertIn("Only non-secret, minimized information", compact)
        for allowed in (
            "raw public response",
            "sanitized local path",
            "relevant personal or account metadata",
            "non-secret data beyond the normal production storage scope",
        ):
            with self.subTest(allowed=allowed):
                self.assertIn(allowed, compact)
        for record_field in (
            "reason",
            "exact retained items",
            "owner",
            "access scope",
            "review or deletion date",
            "secret-scan result",
            "approval reference",
        ):
            with self.subTest(record_field=record_field):
                self.assertIn(record_field, compact)

    def test_rotation_has_immediate_and_controlled_paths(self):
        response = self.section(
            "## 5. Secret, credential, and account response",
            "## 6. Minimal incident response",
        )
        immediate = response.split("### Immediate revocation path", 1)[1].split(
            "### Controlled rotation path", 1
        )[0]
        controlled = response.split("### Controlled rotation path", 1)[1].split(
            "### GitHub owner account", 1
        )[0]
        self.assertLess(immediate.index("revokes or disables"), immediate.index("replacement"))
        self.assertIn("temporary service interruption", immediate)
        self.assertIn("old credential cannot be used", immediate)
        self.assertLess(controlled.index("replacement"), controlled.index("explicitly revokes"))
        self.assertIn("old credential cannot be used", controlled)
        self.assertIn("non-sensitive record", controlled)
        self.assertIn("Never assume", response)
        self.assertIn("automatically invalidates the old one", response)

    def test_nvd_secret_state_has_owner_verification_evidence(self):
        response = self.section(
            "## 5. Secret, credential, and account response",
            "## 6. Minimal incident response",
        )
        compact = compact_whitespace(response)
        self.assertIn("`NVD_API_KEY` is optional", compact)
        self.assertIn("Security Requirements Version 1.1 owner verification", compact)
        self.assertIn("completed on 2026-07-24", compact)
        self.assertIn("not configured at repository-secret scope", compact)
        self.assertIn("No value was inspected", compact)
        self.assertIn("Reverify this state after", compact)
        self.assertIn("job-scoped `GITHUB_TOKEN`", compact)
        self.assertIn("not a long-lived provider secret", compact)

    def test_github_account_compromise_and_published_secret_containment(self):
        response = self.section(
            "### GitHub owner account or repository access compromise",
            "## 6. Minimal incident response",
        )
        for contract in (
            "sessions",
            "tokens",
            "keys",
            "authorizations",
            "password, MFA, and recovery methods",
            "security-log or audit information",
            "recent commits, branches, workflow runs, repository settings",
            "account-recovery or support",
        ):
            with self.subTest(contract=contract):
                self.assertIn(contract, compact_whitespace(response))

        containment = self.section(
            "## 4. Initial assessment and containment",
            "## 5. Secret, credential, and account response",
        )
        compact = compact_whitespace(containment)
        self.assertIn("deletion commit alone is not containment", compact)
        self.assertIn("first response is immediate provider-side revocation", compact)
        self.assertIn("Removing the value", compact)
        self.assertIn("is secondary", compact)
        self.assertIn("History rewrite is not the normal default", compact)
        self.assertIn("incident-specific explicit approval", compact)

    def test_translation_cache_correction_handles_recontamination(self):
        correction = self.section(
            "## 7. Published-output correction, withdrawal, and regeneration",
            "## 8. Repository-external artifact handling",
        )
        cache = correction.split("### Translation cache", 1)[1].split("### Validation", 1)[0]
        compact = compact_whitespace(cache)
        self.assertIn("`docs/translate_cache.json`", correction)
        self.assertIn("remove an erroneous, contaminated", compact)
        self.assertIn("source-supported value", compact)
        self.assertIn("cache, affected daily JSON, and derived HTML", compact)
        self.assertIn("Do not leave a contaminated entry", compact)
        self.assertIn("deleting an entry", compact)
        self.assertIn("not complete remediation by itself", compact)
        self.assertIn("separately approved ticket", compact)
        self.assertIn("changes no runtime or cache processing", compact)

    def test_closure_conditions_are_conditional(self):
        closure = self.section(
            "## 10. Validation and closure",
            "## 11. Approved operational decisions",
        )
        compact = compact_whitespace(closure)
        for always_required in (
            "containment",
            "applicable validation",
            "evidence is sanitized",
            "residual risk or `none identified`",
            "responsible owner confirms closure",
        ):
            with self.subTest(always_required=always_required):
                self.assertIn(always_required, compact)
        for conditional in (
            "when credentials were involved",
            "when public content was affected",
            "when `data/` or `docs/` changed",
            "when public output changed",
            "when residual work or recurrence prevention remains",
        ):
            with self.subTest(conditional=conditional):
                self.assertIn(conditional, compact)
        self.assertIn("record `not required` and the reason", compact)
        self.assertIn("pull request alone is not incident closure", compact)

    def test_artifact_evidence_priority_and_role_boundaries(self):
        artifact = self.section(
            "## 8. Repository-external artifact handling",
            "## 9. Canonical secret and sensitive-evidence contract",
        )
        compact_artifact = compact_whitespace(artifact)
        self.assertIn("90 days after the evaluation is completed", compact_artifact)
        for derivative in (
            "sanitized or minimized derivative",
            "manifest",
            "hash list",
            "gate summary",
            "approved BL, SD, user-acceptance, merge, or No-Go record",
        ):
            with self.subTest(derivative=derivative):
                self.assertIn(derivative, compact_artifact)
        self.assertIn("Do not default to retaining raw artifacts long-term", compact_artifact)
        self.assertIn("Section 9 overrides every long-term evidence designation", compact_artifact)
        self.assertIn("Existing artifacts are not deleted", compact_artifact)
        self.assertIn("not this repository-external artifact policy", compact_artifact)

        roles = self.section(
            "## 2. Roles and authorization boundaries",
            "## 3. Events covered by this runbook",
        )
        compact_roles = compact_whitespace(roles)
        self.assertIn("same person may hold", compact_roles)
        self.assertIn("Roles define responsibilities and approval boundaries", compact_roles)
        self.assertIn("Reviewer independent", compact_roles)
        self.assertIn("does not replace the User approval owner's decision", compact_roles)

    def test_approved_operational_decisions_and_emergency_boundaries(self):
        questions = self.section(
            "## 11. Approved operational decisions",
            "## 12. Approval and maintenance",
        )
        self.assertIn("user approved", questions)
        for question in (
            "Emergency hotfix",
            "Withdrawal",
            "Material daily JSON correction",
            "Correction notice contract",
            "Artifact retention",
            "AGENTS.md reference",
        ):
            with self.subTest(question=question):
                self.assertIn(question, questions)
        compact = compact_whitespace(questions)
        containment = self.section(
            "## 4. Initial assessment and containment",
            "## 5. Secret, credential, and account response",
        )
        compact_containment = compact_whitespace(containment)
        for contract in (
            "Fast-track never means skipping review or CI",
            "material public harm",
            "normal pull-request and CI path is clearly too slow",
            "Repository owner and the User approval owner",
            "normally limited to the affected public files in `docs/`",
            "must not change code, workflows, schemas, prompts, models, validation, "
            "secrets, or GitHub settings",
            "must not force-push or rewrite history",
            "Within 24 hours",
            "after-action branch and pull request",
            "not a permanent bypass",
        ):
            with self.subTest(contract=contract):
                self.assertIn(contract, compact_containment)

    def test_withdrawal_and_correction_policy_is_fixed_without_new_contract(self):
        correction = self.section(
            "## 7. Published-output correction, withdrawal, and regeneration",
            "## 8. Repository-external artifact handling",
        )
        compact = compact_whitespace(correction)
        self.assertLess(compact.index("explicit withdrawal or correction notice"), compact.index("blank output"))
        self.assertLess(compact.index("blank output"), compact.index("last resort"))
        for contract in (
            "first real withdrawal requires a separate ticket and user approval",
            "preserve navigation",
            "daily-JSON contracts",
            "does not add a schema field, UI component, temporary ARTICLE text",
            "`data/index.json` consistent",
            "deterministic offline regeneration",
            "translation cache",
            "Do not force-push or rewrite history",
            "canonical evidence",
            "does not add a dedicated `INCIDENTS.md`",
        ):
            with self.subTest(contract=contract):
                self.assertIn(contract, compact)

    def test_artifact_retention_exception_is_recorded_and_reviewed(self):
        artifact = self.section(
            "## 8. Repository-external artifact handling",
            "## 9. Canonical secret and sensitive-evidence contract",
        )
        compact = compact_whitespace(artifact)
        self.assertIn("beyond 90 days requires the User approval owner's approval", compact)
        for contract in (
            "reason",
            "exact retained items",
            "owner",
            "access scope",
            "secret-scan result",
            "approval reference",
            "next review or deletion date",
            "Retain raw material long-term only when it is indispensable and safe",
            "next artifact inventory",
        ):
            with self.subTest(contract=contract):
                self.assertIn(contract, compact)

    def test_bl024_is_closed_with_merge_and_deployment_evidence(self):
        backlog_section = self.backlog.split("## BL-024", 1)[1].split("## BL-025", 1)[0]
        for contract in (
            "**状態:** 完了",
            "Critical 0",
            "High 1（F-001）",
            "F-001〜F-011",
            "最終decision brief全体へ「ok」",
            "a04e3a3b6c5789d0a2e4de983054035080f0ce75",
            "047534601d8d15419a8d3b45142d8828bc655ad4",
            "Pull Request CI run 30102905467",
            "Pages deployment run 30103074821",
            "**残作業:** なし",
        ):
            with self.subTest(contract=contract):
                self.assertIn(contract, backlog_section)
        active = self.status.split("## Active work", 1)[1].split(
            "## 5. Recently completed work", 1
        )[0]
        self.assertNotIn("BL-024", active)
        self.assertNotIn("BL-025", active)
        self.assertNotIn("BL-026", active)
        self.assertNotIn("BL-027", active)
        self.assertIn("None", active)
        recently_completed = self.status.split("## 5. Recently completed work", 1)[1].split(
            "## 6. Known issues and limitations", 1
        )[0]
        self.assertIn("BL-024 Security Operations Version 1.0", recently_completed)
        self.assertIn("BL-025 source collection URL scheme validation", recently_completed)
        self.assertIn("completed", recently_completed)
        self.assertIn("no residual work", recently_completed)
        for unchanged in (
            "runtime",
            "workflow",
            "`data/`",
            "`docs/`",
            "production",
            "ARTICLE／BRIEF contract",
            "daily schema",
        ):
            with self.subTest(unchanged=unchanged):
                self.assertIn(unchanged, recently_completed)
        sd025 = self.decisions.split("## SD-025", 1)[1]
        self.assertIn("Accepted / Version 1.0 merged", sd025)
        self.assertIn("「ok」", sd025)
        self.assertIn("Completed by documentation", sd025)
        self.assertIn("a04e3a3b6c5789d0a2e4de983054035080f0ce75", sd025)
        self.assertIn("047534601d8d15419a8d3b45142d8828bc655ad4", sd025)
        self.assertIn("Pull Request CI run 30102905467", sd025)
        self.assertIn("Pages deployment run 30103074821", sd025)

    def test_no_local_absolute_path_or_credential_value_pattern(self):
        reviewed = "\n".join((self.operations, self.backlog, self.status))
        self.assertNotRegex(reviewed, r"/Users/[A-Za-z0-9._-]+/")
        self.assertNotRegex(reviewed, r"AKIA[0-9A-Z]{16}")
        self.assertNotRegex(reviewed, r"gh[opusr]_[A-Za-z0-9]{20,}")
        self.assertNotRegex(reviewed, r"AIza[0-9A-Za-z_-]{30,}")
        self.assertNotIn("-----BEGIN PRIVATE KEY-----", reviewed)

    def test_internal_markdown_links_resolve(self):
        files = {
            name: (ROOT / name).read_text(encoding="utf-8")
            for name in (
                "SECURITY_OPERATIONS.md",
                "SECURITY_REQUIREMENTS.md",
                "BACKLOG.md",
                "STATUS.md",
                "DECISIONS.md",
                "AGENTS.md",
            )
        }
        headings = {
            name: {
                github_anchor(match.group(1))
                for match in re.finditer(r"(?m)^#{1,6}\s+(.+?)\s*$", text)
            }
            for name, text in files.items()
        }
        link_pattern = re.compile(r"\]\((?!https?://)([^)#\s]+)(?:#([^)\s]+))?\)")
        for source_name in ("SECURITY_OPERATIONS.md", "BACKLOG.md", "STATUS.md"):
            for target_name, anchor in link_pattern.findall(files[source_name]):
                target_path = ROOT / target_name
                with self.subTest(source=source_name, target=target_name, anchor=anchor):
                    self.assertTrue(target_path.exists(), f"Missing link target: {target_name}")
                    if anchor:
                        self.assertIn(anchor, headings[target_name])


if __name__ == "__main__":
    unittest.main()
