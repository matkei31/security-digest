#!/usr/bin/env python3
"""Static contract tests for SOURCE_USAGE_POLICY.md (BL-031).

BL-031は全17取得元の公式規約監査を`SOURCE_USAGE_POLICY.md`として記録する監査・
方針文書のみのTicketであり、ここでのcontent usage modeのproductionコードへの
強制実装(`source_definitions.json`への`content_usage_mode`等のfield追加、
`fetch.py`側の共通処理)はBL-032へ明示的に委譲される。本ファイルは文書の構造的
contract(17 source id一致、mode件数、allow_*の整合性等)のみを検証し、実装済み
enforcementの有無は検証しない。
"""

import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent
POLICY_PATH = ROOT / "SOURCE_USAGE_POLICY.md"
SOURCE_DEFINITIONS_PATH = ROOT / "source_definitions.json"


def markdown_rows(section):
    for line in section.splitlines():
        if line.startswith("| ") and not line.startswith("|---"):
            row = [cell.strip() for cell in line.strip().strip("|").split("|")]
            if row[0] == "source_id":
                continue
            yield row


class SourceUsagePolicyTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.policy = POLICY_PATH.read_text(encoding="utf-8")
        cls.source_ids = {
            s["id"]
            for s in json.loads(SOURCE_DEFINITIONS_PATH.read_text(encoding="utf-8"))["sources"]
        }
        cls.matrix = cls.policy.split(
            "## 4. Source-by-source audit matrix", 1
        )[1].split("## 5. Gemini data-use gate", 1)[0]

    def _mode_rows(self, heading, next_marker):
        return list(markdown_rows(self.matrix.split(heading, 1)[1].split(next_marker, 1)[0]))

    def test_document_is_draft_01(self):
        self.assertTrue(POLICY_PATH.is_file())
        self.assertIn("# Monomi Digest — Source Usage Policy", self.policy)
        self.assertIn("**Version:** 0.1", self.policy)
        self.assertIn("**Status:** Draft", self.policy)
        self.assertIn("**As of:** 2026-07-29", self.policy)
        self.assertIn("本文書は法律意見ではない", self.policy)
        self.assertIn(
            "特定の取得元が現行実装によって規約違反を犯していると断定するものではない",
            self.policy,
        )

    def test_required_chapters_are_present(self):
        for heading in (
            "## 1. Purpose",
            "## 2. Legal and policy framework",
            "## 3. Content usage modes",
            "## 4. Source-by-source audit matrix",
            "## 5. Gemini data-use gate",
            "## 6. Attribution requirements",
            "## 7. Output-similarity and quotation controls",
            "## 8. Recheck triggers",
            "## 9. Unknowns and owner verification",
            "## 10. Relationship to BL-032 and BL-009",
        ):
            with self.subTest(heading=heading):
                self.assertIn(heading, self.policy)

    def test_17_source_ids_match_source_definitions_exactly(self):
        # Collect every source_id cell across all four mode tables directly.
        ids_in_doc = [row[0] for row in markdown_rows(self.matrix)]
        self.assertEqual(len(ids_in_doc), len(set(ids_in_doc)), f"duplicate source_id: {ids_in_doc}")
        self.assertEqual(set(ids_in_doc), self.source_ids)
        self.assertEqual(len(ids_in_doc), 17)

    def test_mode_counts_are_5_4_4_4(self):
        structured_open = self._mode_rows("### structured_open (5件)", "### feed_summary (4件)")
        feed_summary = self._mode_rows("### feed_summary (4件)", "### metadata_only (4件)")
        metadata_only = self._mode_rows("### metadata_only (4件)", "### disabled_legal_review (4件)")
        disabled = list(markdown_rows(self.matrix.split("### disabled_legal_review (4件)", 1)[1]))

        self.assertEqual(len(structured_open), 5)
        self.assertEqual(len(feed_summary), 4)
        self.assertEqual(len(metadata_only), 4)
        self.assertEqual(len(disabled), 4)
        self.assertIn("合計17", self.matrix)

        self.assertEqual(
            {row[0] for row in structured_open},
            {"fsa", "nist", "ncsc", "cisa_kev", "nist_nvd"},
        )
        self.assertEqual(
            {row[0] for row in feed_summary},
            {"jpcert_cc", "ipa", "mandiant", "google_tag"},
        )
        self.assertEqual(
            {row[0] for row in metadata_only},
            {"microsoft_security", "cisco_talos", "the_hacker_news", "krebs_on_security"},
        )
        self.assertEqual(
            {row[0] for row in disabled},
            {"cisa", "crowdstrike", "cloudflare", "dark_reading"},
        )

    def test_all_17_sources_disallow_rich_content(self):
        # allow_rich_content is column index 5 in every mode table.
        rows = list(markdown_rows(self.matrix))
        self.assertEqual(len(rows), 17)
        for row in rows:
            with self.subTest(source_id=row[0]):
                self.assertEqual(row[5], "false")

    def test_metadata_only_disallows_ai_processing(self):
        metadata_only = self._mode_rows("### metadata_only (4件)", "### disabled_legal_review (4件)")
        for row in metadata_only:
            with self.subTest(source_id=row[0]):
                self.assertEqual(row[6], "false")  # allow_ai_processing

    def test_disabled_legal_review_disallows_network_fetch(self):
        disabled = list(markdown_rows(self.matrix.split("### disabled_legal_review (4件)", 1)[1]))
        for row in disabled:
            with self.subTest(source_id=row[0]):
                self.assertEqual(row[3], "false")  # allow_network_fetch

    def test_feed_summary_is_gated_by_gemini_paid_service_confirmation(self):
        feed_summary_section = self.matrix.split(
            "### feed_summary (4件)", 1
        )[1].split("### metadata_only (4件)", 1)[0]
        self.assertIn("Gemini Paid Service", feed_summary_section)
        gate = self.policy.split("## 5. Gemini data-use gate", 1)[1].split(
            "## 6. Attribution requirements", 1
        )[0]
        self.assertIn("paid_verified", gate)
        self.assertIn("`unpaid`または`unknown`の場合、`feed_summary`は`metadata_only`と同じ挙動", gate)

    def test_gemini_data_use_status_is_currently_unknown(self):
        gate = self.policy.split("## 5. Gemini data-use gate", 1)[1].split(
            "## 6. Attribution requirements", 1
        )[0]
        self.assertIn("gemini_data_use_status: unknown", gate)
        self.assertIn("paid_verified", gate)
        self.assertIn("unpaid", gate)
        self.assertIn("API key、請求情報、金額、アカウント画面のスクリーンショット", gate)

    def test_google_terms_2026_07_30_recheck_trigger_is_recorded(self):
        self.assertIn("2026-07-30", self.policy)
        recheck = self.policy.split("## 8. Recheck triggers", 1)[1].split(
            "## 9. Unknowns and owner verification", 1
        )[0]
        self.assertIn("2026-07-30以降、Google Terms", recheck)
        self.assertIn("google_tag", recheck)

    def test_attribution_requirements_are_recorded_for_each_group(self):
        attribution = self.policy.split("## 6. Attribution requirements", 1)[1].split(
            "## 7. Output-similarity and quotation controls", 1
        )[0]
        for marker in (
            "`fsa`",
            "`nist`",
            "`nist_nvd`",
            "`ncsc`",
            "`cisa_kev`",
            "jpcert_cc",
            "metadata_only",
            "disabled_legal_review",
        ):
            with self.subTest(marker=marker):
                self.assertIn(marker, attribution)

    def test_cisco_talos_and_krebs_uncertainty_is_not_asserted_as_definitive(self):
        metadata_only_section = self.matrix.split(
            "### metadata_only (4件)", 1
        )[1].split("### disabled_legal_review (4件)", 1)[0]
        self.assertIn("不明", metadata_only_section)
        self.assertIn("terms_not_found", metadata_only_section)
        self.assertIn("断定せず", metadata_only_section)
        unknowns = self.policy.split("## 9. Unknowns and owner verification", 1)[1].split(
            "## 10. Relationship to BL-032 and BL-009", 1
        )[0]
        self.assertIn("Cisco Talos", unknowns)
        self.assertIn("Krebs on Security", unknowns)
        self.assertIn("禁止と断定せず", unknowns)
        self.assertNotIn("規約違反であることが確定した", self.policy)
        self.assertNotIn("法的に禁止されていると断定", self.policy)

    def test_output_similarity_controls_are_recorded_as_bl032_scope_not_implemented(self):
        controls = self.policy.split(
            "## 7. Output-similarity and quotation controls", 1
        )[1].split("## 8. Recheck triggers", 1)[0]
        self.assertIn("BL-032の実装時に", controls)
        self.assertIn("本PR(BL-031)では実装しない", controls)

    def test_relationship_section_defers_enforcement_to_bl032(self):
        relationship = self.policy.split("## 10. Relationship to BL-032 and BL-009", 1)[1]
        self.assertIn("BL-032", relationship)
        self.assertIn("BL-009", relationship)
        self.assertIn(
            "本文書(BL-031)自体は、監査結果と方針の記録にとどまり、上記いずれの実装も行わない",
            relationship,
        )


if __name__ == "__main__":
    unittest.main()
