#!/usr/bin/env python3
"""Static contract tests for BL-015 SECURITY_REQUIREMENTS.md Draft 0.1."""

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent
REQUIREMENTS_PATH = ROOT / "SECURITY_REQUIREMENTS.md"


class SecurityRequirementsDraftTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.requirements = REQUIREMENTS_PATH.read_text(encoding="utf-8")
        cls.backlog = (ROOT / "BACKLOG.md").read_text(encoding="utf-8")
        cls.status = (ROOT / "STATUS.md").read_text(encoding="utf-8")
        cls.decisions = (ROOT / "DECISIONS.md").read_text(encoding="utf-8")

    @staticmethod
    def _headings(text):
        return [
            match.group(2).strip()
            for line in text.splitlines()
            if (match := re.match(r"^(#{1,6})\s+(.*)$", line))
        ]

    @staticmethod
    def _slugify(heading_text):
        lowered = heading_text.strip().lower()
        kept = [ch for ch in lowered if ch.isalnum() or ch in (" ", "-", "_")]
        return "".join(kept).replace(" ", "-")

    def test_document_exists_and_is_unapproved_draft_01(self):
        self.assertTrue(REQUIREMENTS_PATH.is_file())
        self.assertIn("# Security Digest Security Requirements", self.requirements)
        self.assertIn("**Version:** Draft 0.1", self.requirements)
        self.assertIn(
            "**Status:** Fable 5 review and user approval pending",
            self.requirements,
        )
        self.assertIn("Draft 0.1 is unapproved.", self.requirements)
        self.assertIn("Fable 5 review is pending.", self.requirements)
        self.assertIn("User approval is pending.", self.requirements)

    def test_required_sections_are_present(self):
        for heading in (
            "## 1. Purpose and proportionality",
            "## 2. System scope and components",
            "## 3. Data flow",
            "## 4. Assets and data classification",
            "## 5. Trust boundaries",
            "## 6. Security requirements",
            "### 6.9 Change and review control",
            "## 7. Current control mapping",
            "## 8. Gap register",
            "## 9. Explicitly non-required controls for the current architecture",
            "## 10. Re-evaluation triggers",
            "## 11. Open review questions",
            "## 12. Approval and maintenance",
        ):
            with self.subTest(heading=heading):
                self.assertIn(heading, self.requirements)

    def test_sr_ids_are_stable_unique_and_contiguous(self):
        ids = re.findall(r"(?m)^\|\s*(SR-\d{3})\s*\|", self.requirements)
        self.assertEqual(len(ids), len(set(ids)), f"Duplicate SR IDs: {ids}")
        self.assertEqual(ids, [f"SR-{number:03d}" for number in range(1, 43)])

    def test_current_gaps_non_required_and_triggers_are_distinct(self):
        mapping = self.requirements.split("## 7. Current control mapping", 1)[1].split(
            "## 8. Gap register", 1
        )[0]
        gaps = self.requirements.split("## 8. Gap register", 1)[1].split(
            "## 9. Explicitly non-required controls for the current architecture", 1
        )[0]
        non_required = self.requirements.split(
            "## 9. Explicitly non-required controls for the current architecture", 1
        )[1].split("## 10. Re-evaluation triggers", 1)[0]
        triggers = self.requirements.split("## 10. Re-evaluation triggers", 1)[1].split(
            "## 11. Open review questions", 1
        )[0]

        for status in (
            "Met",
            "Partially met",
            "Not applicable now",
            "Unverified outside repository",
        ):
            self.assertIn(status, mapping)
        self.assertRegex(gaps, r"(?m)^\|\s*GAP-001\s*\|")
        self.assertIn("No gap below is implemented or automatically accepted", gaps)
        self.assertIn("WAF", non_required)
        self.assertIn("24/7 SOC monitoring", non_required)
        self.assertIn("introducing `monomidigest.com`", triggers)
        self.assertIn("adding forms, authentication, sessions", triggers)

    def test_supply_chain_options_are_not_preapproved(self):
        self.assertIn(
            "Full commit SHA pinning is an evaluation item, not an approved mandatory control",
            self.requirements,
        )
        self.assertIn(
            "GitHub Actions Dependabot is an evaluation item, not an approved mandatory control",
            self.requirements,
        )
        self.assertIn(
            "Full SHA pinning is not used and has not been approved or rejected",
            self.requirements,
        )
        self.assertIn(
            "Decide together with the pinning/update policy; do not add automatically",
            self.requirements,
        )

    def test_future_components_are_not_misstated_as_current(self):
        self.assertIn(
            "the future `monomidigest.com` custom domain",
            self.requirements,
        )
        self.assertRegex(
            self.requirements,
            r"which is not implemented in this\s+repository",
        )
        self.assertIn(
            "No component for forms, authentication, sessions, a database, payments",
            self.requirements,
        )
        self.assertIn(
            "Forms, authentication, database, and payments",
            self.requirements,
        )
        self.assertNotIn("custom domain is implemented", self.requirements)
        self.assertNotIn("forms are currently implemented", self.requirements)

    def test_no_secret_value_or_local_absolute_path_is_present(self):
        for text in (self.requirements, self.backlog, self.status):
            self.assertNotIn("/Users/", text)
            self.assertNotRegex(text, r"AIza[0-9A-Za-z_-]{20,}")
            self.assertNotRegex(text, r"ghp_[0-9A-Za-z]{20,}")
            self.assertNotRegex(text, r"github_pat_[0-9A-Za-z_]{20,}")
        self.assertIn("secret names used by production code", self.requirements)
        self.assertIn("Values, presence", self.requirements)

    def test_bl015_is_active_pending_and_not_complete(self):
        bl015 = self.backlog.split("## BL-015", 1)[1].split("## BL-016", 1)[0]
        self.assertIn(
            "**状態:** 進行中 / Draft 0.1 / Fable 5・ユーザー確認待ち",
            bl015,
        )
        self.assertIn("[SECURITY_REQUIREMENTS.md](SECURITY_REQUIREMENTS.md) Draft 0.1", bl015)
        self.assertIn("security-control実装", bl015)
        self.assertIn("**ユーザー受入証跡:** 未受入。", bl015)
        self.assertNotIn("**状態:** 完了", bl015)

        active = self.status.split("## Active work", 1)[1].split(
            "## 5. Recently completed work", 1
        )[0]
        recently_completed = self.status.split("## 5. Recently completed work", 1)[1].split(
            "## 6. Known issues and limitations", 1
        )[0]
        self.assertIn("BL-015", active)
        self.assertIn("Fable 5 review and user approval are pending", active)
        self.assertNotIn("BL-015", recently_completed)

    def test_no_unapproved_decision_was_added(self):
        self.assertNotIn("## SD-024", self.decisions)
        self.assertRegex(self.requirements, r"does\s+not add SD-024")

    def test_security_requirements_internal_markdown_links_resolve(self):
        docs = {
            name: (ROOT / name).read_text(encoding="utf-8")
            for name in (
                "SECURITY_REQUIREMENTS.md",
                "BACKLOG.md",
                "STATUS.md",
                "DECISIONS.md",
                "AGENTS.md",
                "test_fetch.py",
                "test_archive.py",
                "test_daily_json.py",
                "test_feed_fetch_status.py",
                "test_feed_rich_content.py",
                "test_article_analysis.py",
                "test_article_internal_identifier_leak.py",
                "test_todays_brief.py",
                "test_vulnerability_facts_prompt.py",
                "test_pr_ci_workflow.py",
                "test_source_definitions.py",
                "fetch.py",
                "daily_json.py",
                "vulnerability_facts.py",
                "source_definitions.json",
            )
        }
        anchors = {
            name: {self._slugify(heading) for heading in self._headings(text)}
            for name, text in docs.items()
            if name.endswith(".md")
        }
        link_pattern = re.compile(r"\]\((?!https?://)([^)#\s]+)(?:#([^)\s]+))?\)")

        for target, anchor in link_pattern.findall(self.requirements):
            with self.subTest(target=target, anchor=anchor):
                target_path = ROOT / target
                self.assertTrue(target_path.exists(), f"Missing link target: {target}")
                if anchor:
                    self.assertIn(target, anchors, f"Cannot resolve anchor in {target}")
                    self.assertIn(anchor, anchors[target], f"Missing anchor {target}#{anchor}")


if __name__ == "__main__":
    unittest.main()
