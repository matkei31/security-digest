#!/usr/bin/env python3
"""Static contract tests for SOURCE_USAGE_POLICY.md (BL-031).

BL-031は全17取得元の公式規約監査を`SOURCE_USAGE_POLICY.md`として記録する監査・
方針文書のみのTicketであり、ここでのcontent usage modeのproductionコードへの
強制実装(`source_definitions.json`への`content_usage_mode`等のfield追加、
`fetch.py`側の共通処理)はBL-032へ明示的に委譲される。本ファイルは文書の構造的
contract(17 source id一致、mode件数、allow_*の整合性等)のみを検証し、実装済み
enforcementの有無は検証しない。

列はheader名で解決する(固定column indexに依存しない)。表へ列を追加・並び替え
しても、対応する列名を参照しているテストは影響を受けない。
"""

import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent
POLICY_PATH = ROOT / "SOURCE_USAGE_POLICY.md"
SOURCE_DEFINITIONS_PATH = ROOT / "source_definitions.json"


def parse_rows(section):
    """Parse every markdown table row in `section` into header-keyed dicts.

    A row whose first cell is "source_id" is treated as a header row that
    applies to subsequent rows until the next header row is seen (the audit
    matrix contains four separate tables, one per mode).
    """
    header = None
    rows = []
    for line in section.splitlines():
        if not line.startswith("| ") or line.startswith("|---"):
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if cells and cells[0] == "source_id":
            header = cells
            continue
        if header is None:
            continue
        rows.append(dict(zip(header, cells)))
    return rows


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
        cls.rows = parse_rows(cls.matrix)
        cls.rows_by_id = {row["source_id"]: row for row in cls.rows}

    def test_gemini_gate_references_point_to_chapter_5(self):
        self.assertIn("後述5章のGemini Paid Service確認", self.policy)
        self.assertIn("conditional(5章Gemini Paid Service gate)", self.policy)
        self.assertIn("いずれも5章のGemini data-use gateに従属する", self.policy)
        self.assertNotIn("後述6章のGemini Paid Service確認", self.policy)
        self.assertNotIn("conditional(6章Gemini Paid Service gate)", self.policy)
        self.assertNotIn("いずれも6章のGemini data-use gateに従属する", self.policy)

    def test_attribution_references_point_to_chapter_6(self):
        self.assertIn("source固有のattribution(下記6章)", self.policy)
        self.assertEqual(self.policy.count("6章参照"), 13)
        self.assertNotIn("下記7章", self.policy)

    def test_no_stale_chapter_7_attribution_references_remain(self):
        self.assertNotIn("7章参照(PDL", self.policy)
        self.assertNotIn("7章参照(NIST source credit)", self.policy)
        self.assertNotIn("7章参照(OGL", self.policy)
        self.assertNotIn("7章参照(CC0)", self.policy)
        self.assertNotIn("7章参照(NVD notice)", self.policy)
        self.assertNotIn("7章参照(source名", self.policy)

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
        ids_in_doc = [row["source_id"] for row in self.rows]
        self.assertEqual(len(ids_in_doc), len(set(ids_in_doc)), f"duplicate source_id: {ids_in_doc}")
        self.assertEqual(set(ids_in_doc), self.source_ids)
        self.assertEqual(len(ids_in_doc), 17)

    def test_every_table_has_proposed_mode_and_checked_at_columns(self):
        for row in self.rows:
            with self.subTest(source_id=row["source_id"]):
                self.assertIn("proposed_mode", row)
                self.assertIn("checked_at", row)
                self.assertTrue(row["proposed_mode"])
                self.assertTrue(row["checked_at"])

    def test_all_17_checked_at_is_2026_07_29(self):
        for row in self.rows:
            with self.subTest(source_id=row["source_id"]):
                self.assertEqual(row["checked_at"], "2026-07-29")

    def test_mode_counts_are_5_4_4_4_by_proposed_mode_column(self):
        # Group by the proposed_mode column itself, not by which physical
        # table the row appears in, so the test does not silently pass if a
        # row is ever moved into the wrong table without updating its value.
        by_mode = {}
        for row in self.rows:
            by_mode.setdefault(row["proposed_mode"], []).append(row["source_id"])

        self.assertEqual(
            set(by_mode.get("structured_open", [])),
            {"fsa", "nist", "ncsc", "cisa_kev", "nist_nvd"},
        )
        self.assertEqual(
            set(by_mode.get("feed_summary", [])),
            {"jpcert_cc", "ipa", "mandiant", "google_tag"},
        )
        self.assertEqual(
            set(by_mode.get("metadata_only", [])),
            {"microsoft_security", "cisco_talos", "the_hacker_news", "krebs_on_security"},
        )
        self.assertEqual(
            set(by_mode.get("disabled_legal_review", [])),
            {"cisa", "crowdstrike", "cloudflare", "dark_reading"},
        )
        self.assertEqual(len(by_mode), 4)
        self.assertIn("合計17", self.matrix)

    def test_proposed_mode_matches_the_table_the_row_appears_in(self):
        # Cross-check: every row's own proposed_mode value must equal the
        # physical table section (structured_open/feed_summary/metadata_only/
        # disabled_legal_review) it was parsed from.
        section_markers = [
            ("structured_open", "### structured_open (5件)", "### feed_summary (4件)"),
            ("feed_summary", "### feed_summary (4件)", "### metadata_only (4件)"),
            ("metadata_only", "### metadata_only (4件)", "### disabled_legal_review (4件)"),
        ]
        for mode, start, end in section_markers:
            section_rows = parse_rows(self.matrix.split(start, 1)[1].split(end, 1)[0])
            for row in section_rows:
                with self.subTest(source_id=row["source_id"], expected_mode=mode):
                    self.assertEqual(row["proposed_mode"], mode)
        disabled_rows = parse_rows(self.matrix.split("### disabled_legal_review (4件)", 1)[1])
        for row in disabled_rows:
            with self.subTest(source_id=row["source_id"], expected_mode="disabled_legal_review"):
                self.assertEqual(row["proposed_mode"], "disabled_legal_review")

    def test_all_17_sources_disallow_rich_content(self):
        self.assertEqual(len(self.rows), 17)
        for row in self.rows:
            with self.subTest(source_id=row["source_id"]):
                self.assertEqual(row["allow_rich_content"], "false")

    def test_metadata_only_disallows_ai_processing(self):
        for row in self.rows:
            if row["proposed_mode"] != "metadata_only":
                continue
            with self.subTest(source_id=row["source_id"]):
                self.assertEqual(row["allow_ai_processing"], "false")

    def test_disabled_legal_review_disallows_network_fetch(self):
        for row in self.rows:
            if row["proposed_mode"] != "disabled_legal_review":
                continue
            with self.subTest(source_id=row["source_id"]):
                self.assertEqual(row["allow_network_fetch"], "false")

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
        cisco_talos = self.rows_by_id["cisco_talos"]
        krebs = self.rows_by_id["krebs_on_security"]
        self.assertIn("不明", cisco_talos["unresolved_issue"])
        self.assertTrue(krebs["evidence_type"].startswith("terms_not_found"))
        self.assertIn("terms_not_found", krebs["unresolved_issue"])
        self.assertIn("断定せず", krebs["unresolved_issue"])
        unknowns = self.policy.split("## 9. Unknowns and owner verification", 1)[1].split(
            "## 10. Relationship to BL-032 and BL-009", 1
        )[0]
        self.assertIn("Cisco Talos", unknowns)
        self.assertIn("Krebs on Security", unknowns)
        self.assertIn("禁止と断定せず", unknowns)
        self.assertNotIn("規約違反であることが確定した", self.policy)
        self.assertNotIn("法的に禁止されていると断定", self.policy)

    @staticmethod
    def _split_cell(value):
        return [part.strip() for part in value.split("；") if part.strip()]

    def test_official_evidence_url_contains_only_urls_or_a_bare_dash(self):
        for row in self.rows:
            for url in self._split_cell(row["official_evidence_url"]):
                with self.subTest(source_id=row["source_id"], token=url):
                    self.assertTrue(
                        url == "—" or url.startswith("http://") or url.startswith("https://"),
                        f"{row['source_id']}: non-URL token in official_evidence_url: {url!r}",
                    )

    def test_official_evidence_url_has_no_descriptive_text_mixed_in(self):
        forbidden_substrings = (
            "証跡",
            "supporting:",
            "URL未特定",
            "見つからなかった",
            "terms文書ではなく",
        )
        for row in self.rows:
            for forbidden in forbidden_substrings:
                with self.subTest(source_id=row["source_id"], forbidden=forbidden):
                    self.assertNotIn(forbidden, row["official_evidence_url"])

    def test_multi_url_rows_have_matching_evidence_type_count_when_types_differ(self):
        # When evidence_type lists more than one distinct type, the URL count
        # and type count must match 1:1 in the same order. A single shared
        # type may legitimately cover multiple URLs (e.g. two RSS-guidance
        # pages), so that case is exempt from the count-matching rule.
        for row in self.rows:
            urls = self._split_cell(row["official_evidence_url"])
            types = self._split_cell(row["evidence_type"])
            with self.subTest(source_id=row["source_id"]):
                if len(types) > 1:
                    self.assertEqual(
                        len(urls),
                        len(types),
                        f"{row['source_id']}: {len(urls)} URLs vs {len(types)} evidence_types",
                    )

    def test_krebs_about_page_is_recorded_as_supporting_source_page_not_a_terms_url(self):
        krebs = self.rows_by_id["krebs_on_security"]
        self.assertEqual(self._split_cell(krebs["evidence_type"]), ["terms_not_found", "source_page(supporting)"])
        urls = self._split_cell(krebs["official_evidence_url"])
        self.assertEqual(urls[0], "—")
        self.assertIn("about-this-blog", urls[1])
        self.assertIn("terms文書ではなく", krebs["unresolved_issue"])
        self.assertIn("source page", krebs["unresolved_issue"])

    def test_cisa_has_no_url_in_official_evidence_url_and_is_terms_not_identified(self):
        cisa = self.rows_by_id["cisa"]
        self.assertEqual(cisa["evidence_type"], "terms_not_identified")
        self.assertEqual(cisa["official_evidence_url"], "—")
        self.assertIn("URLが特定できていない", cisa["unresolved_issue"])

    def test_mandiant_distinguishes_rss_evidence_from_terms_evidence(self):
        mandiant = self.rows_by_id["mandiant"]
        urls = self._split_cell(mandiant["official_evidence_url"])
        types = self._split_cell(mandiant["evidence_type"])
        self.assertEqual(len(urls), 3)
        self.assertEqual(len(types), 3)
        self.assertIn("policies.google.com/terms", urls[0])
        self.assertTrue(types[0].startswith("terms("))
        self.assertIn("policies.google.com/terms/update/embedded", urls[1])
        self.assertTrue(types[1].startswith("terms_update_notice"))
        self.assertIn("cloud.google.com/blog/topics/threat-intelligence", urls[2])
        self.assertTrue(types[2].startswith("rss_usage_guidance"))
        self.assertIn("supporting", types[2])
        self.assertIn("それ自体はterms文書ではない", mandiant["unresolved_issue"])
        self.assertIn("両者を混同しない", mandiant["unresolved_issue"])

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
