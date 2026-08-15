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
        self.assertEqual(self.policy.count("6章参照"), 14)
        self.assertNotIn("下記7章", self.policy)

    def test_no_stale_chapter_7_attribution_references_remain(self):
        self.assertNotIn("7章参照(PDL", self.policy)
        self.assertNotIn("7章参照(NIST source credit)", self.policy)
        self.assertNotIn("7章参照(OGL", self.policy)
        self.assertNotIn("7章参照(CC0)", self.policy)
        self.assertNotIn("7章参照(NVD notice)", self.policy)
        self.assertNotIn("7章参照(source名", self.policy)

    def test_document_is_approved_01(self):
        self.assertTrue(POLICY_PATH.is_file())
        self.assertIn("# Monomi Digest — Source Usage Policy", self.policy)
        self.assertIn("**Version:** 0.1", self.policy)
        self.assertIn("**Status:** Approved", self.policy)
        self.assertIn("**As of:** 2026-07-31", self.policy)
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
        # NOTE: method名はBL-038 classification manifestのassertion IDを構成する。
        # BL-047でinventoryは17→18になったが、frozen shardへのadd/remove churnを
        # 避けるため名称は据え置き、検証値のみ18へ更新している。
        ids_in_doc = [row["source_id"] for row in self.rows]
        self.assertEqual(len(ids_in_doc), len(set(ids_in_doc)), f"duplicate source_id: {ids_in_doc}")
        self.assertEqual(set(ids_in_doc), self.source_ids)
        self.assertEqual(len(ids_in_doc), 18)

    def test_every_table_has_proposed_mode_and_checked_at_columns(self):
        for row in self.rows:
            with self.subTest(source_id=row["source_id"]):
                self.assertIn("proposed_mode", row)
                self.assertIn("checked_at", row)
                self.assertTrue(row["proposed_mode"])
                self.assertTrue(row["checked_at"])

    def test_checked_at_is_2026_07_29_except_google_terms_sources(self):
        # google_tag/mandiant were rechecked on 2026-07-30 against the newly
        # effective Google Terms; every other source keeps its original
        # 2026-07-29 ChatGPT confirmation date.
        updated = {"google_tag", "mandiant"}
        for row in self.rows:
            with self.subTest(source_id=row["source_id"]):
                # BL-047: securityweekは追加時(2026-08-15)に確認したため別日付。
                # 既存の2026-07-30/2026-07-29の判定式はそのまま維持する。
                if row["source_id"] == "securityweek":
                    expected = "2026-08-15"
                else:
                    expected = "2026-07-30" if row["source_id"] in updated else "2026-07-29"
                self.assertEqual(row["checked_at"], expected)

    def test_mode_counts_are_5_4_2_2_4_by_proposed_mode_column(self):
        # NOTE: 名称はmanifest ID安定のため据え置き。BL-047後の実際の分布は
        # structured_open 5 / feed_summary 4 / limited_feed_analysis 3 /
        # metadata_only 2 / disabled_legal_review 4。
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
            set(by_mode.get("limited_feed_analysis", [])),
            {"the_hacker_news", "krebs_on_security", "securityweek"},
        )
        self.assertEqual(
            set(by_mode.get("metadata_only", [])),
            {"microsoft_security", "cisco_talos"},
        )
        self.assertEqual(
            set(by_mode.get("disabled_legal_review", [])),
            {"cisa", "crowdstrike", "cloudflare", "dark_reading"},
        )
        self.assertEqual(len(by_mode), 5)
        self.assertIn("合計18", self.matrix)

    def test_proposed_mode_matches_the_table_the_row_appears_in(self):
        # Cross-check: every row's own proposed_mode value must equal the
        # physical table section it was parsed from.
        section_markers = [
            ("structured_open", "### structured_open (5件)", "### feed_summary (4件)"),
            ("feed_summary", "### feed_summary (4件)", "### limited_feed_analysis (3件)"),
            ("limited_feed_analysis", "### limited_feed_analysis (3件)", "### metadata_only (2件)"),
            ("metadata_only", "### metadata_only (2件)", "### disabled_legal_review (4件)"),
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
        # NOTE: 名称はmanifest ID安定のため据え置き(BL-047でinventoryは18)。
        self.assertEqual(len(self.rows), 18)
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
        )[1].split("### limited_feed_analysis (3件)", 1)[0]
        self.assertIn("Gemini Paid Service", feed_summary_section)
        gate = self.policy.split("## 5. Gemini data-use gate", 1)[1].split(
            "## 6. Attribution requirements", 1
        )[0]
        self.assertIn("paid_verified", gate)
        self.assertIn(
            "`unpaid`または`unknown`の場合、`feed_summary`および`limited_feed_analysis`は`metadata_only`と同じ挙動",
            gate,
        )

    def test_gemini_data_use_status_is_paid_verified(self):
        gate = self.policy.split("## 5. Gemini data-use gate", 1)[1].split(
            "## 6. Attribution requirements", 1
        )[0]
        self.assertIn("gemini_data_use_status: paid_verified", gate)
        self.assertNotIn("gemini_data_use_status: unknown", gate)
        self.assertIn("paid_verified", gate)
        self.assertIn("unpaid", gate)
        self.assertIn("API key、請求情報、金額、アカウント画面のスクリーンショット", gate)

    def test_gemini_owner_verification_is_recorded_without_secrets(self):
        gate = self.policy.split("## 5. Gemini data-use gate", 1)[1].split(
            "## 6. Attribution requirements", 1
        )[0]
        self.assertIn("checked_at:** 2026-07-29", gate)
        self.assertIn("checked_by:** repository owner", gate)
        self.assertIn("security-digest", gate)
        self.assertIn("active billing", gate)
        self.assertIn("Tier 1", gate)
        self.assertIn(
            "APIキー名・APIキー末尾・APIキー値・Project ID・請求先アカウントID・課金額・画面のスクリーンショットはいずれもrepositoryへ保存していない",
            gate,
        )
        # No actual secret-shaped values (Gemini/Google API keys) anywhere in the document.
        self.assertNotRegex(self.policy, r"AIza[0-9A-Za-z_-]{20,}")

    def test_gemini_gate_no_longer_lists_unknown_as_current_unresolved_issue(self):
        unknowns = self.policy.split("## 9. Unknowns and owner verification", 1)[1].split(
            "## 10. Relationship to BL-032 and BL-009", 1
        )[0]
        self.assertIn("Owner-verified", unknowns)
        self.assertIn("paid_verified", unknowns)
        self.assertIn("2026-07-29", unknowns)
        # Still-open items must remain.
        self.assertIn("Cisco Talos", unknowns)
        self.assertIn("Krebs on Security", unknowns)
        self.assertIn("2026-07-30", unknowns)
        self.assertIn("CISA", unknowns)

    def test_feed_summary_production_enforcement_still_deferred_to_bl032(self):
        # The gate being satisfied does not mean per-source enforcement is
        # implemented; that remains BL-032 scope.
        gate = self.policy.split("## 5. Gemini data-use gate", 1)[1].split(
            "## 6. Attribution requirements", 1
        )[0]
        self.assertIn("BL-032", gate)
        self.assertIn(
            "この文書更新だけで現在のproduction挙動が変わるものではない", gate
        )

    def test_google_terms_2026_07_30_recheck_is_recorded_as_completed(self):
        self.assertIn("2026-07-30", self.policy)
        recheck = self.policy.split("## 8. Recheck triggers", 1)[1].split(
            "## 9. Unknowns and owner verification", 1
        )[0]
        self.assertIn("Google Terms(2026-07-30発効版)のさらなる改定", recheck)
        self.assertIn("google_tag", recheck)
        # The recheck itself is completed, not still pending.
        self.assertIn("Google Terms再確認(2026-07-30発効版、完了)", recheck)
        self.assertIn("checked_at:** 2026-07-30", recheck)
        self.assertIn("一部の取得環境", recheck)
        self.assertIn("旧2024年版", recheck)
        self.assertIn(
            "規約が2026-07-30に発効し、その内容を確認できたという事実を否定するものではない",
            recheck,
        )
        self.assertNotIn("2026-07-30以降、Google Terms(新規約発効後)の公式再確認", recheck)
        # The display-discrepancy note must not assert an unconfirmed cause.
        self.assertIn("原因は特定していない", recheck)
        self.assertNotIn("一部の取得環境(cache・CDNエッジ等)では", recheck)

    def test_mandiant_and_google_tag_recheck_triggers_are_specific(self):
        mandiant = self.rows_by_id["mandiant"]
        google_tag = self.rows_by_id["google_tag"]
        for row, source_specific in (
            (mandiant, "Google Cloud Threat Intelligence固有の利用条件の変更"),
            (google_tag, "Google Security Blog/Blogger固有の利用条件の変更"),
        ):
            trigger = row["recheck_trigger"]
            self.assertIn("Google Terms(2026-07-30発効版)のさらなる改定", trigger)
            self.assertIn("公式Feed URL／Feed経路の変更", trigger)
            self.assertIn(source_specific, trigger)
            self.assertIn("robots.txt等machine-readable instructionsの変更", trigger)
            self.assertIn("公式RSS案内の変更・終了", trigger)

    def test_google_terms_recheck_moved_to_confirmed_in_unknowns_section(self):
        unknowns = self.policy.split("## 9. Unknowns and owner verification", 1)[1].split(
            "## 10. Relationship to BL-032 and BL-009", 1
        )[0]
        self.assertIn("確認完了(未解決事項から除外)", unknowns)
        self.assertIn("Google TAG / Mandiant", unknowns)
        self.assertNotIn(
            "2026-07-30発効の新しいGoogle利用規約の内容が最終確認されていない", unknowns
        )

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
            "limited_feed_analysis",
            "metadata_only",
            "disabled_legal_review",
        ):
            with self.subTest(marker=marker):
                self.assertIn(marker, attribution)
        self.assertIn("the_hacker_news", attribution)
        self.assertIn("krebs_on_security", attribution)
        self.assertIn("2source", attribution)

    def test_limited_feed_analysis_mode_definition_is_present(self):
        modes = self.policy.split("## 3. Content usage modes", 1)[1].split(
            "## 4. Source-by-source audit matrix", 1
        )[0]
        self.assertIn("### C. `limited_feed_analysis`", modes)
        self.assertIn("明示的な運用上のリスク受容分類", modes)
        self.assertIn("取得元が利用を明示的に許諾したと判断したものではない", modes)
        self.assertIn("記事ページへの追加HTTP取得(scraping)は禁止する", modes)
        self.assertIn("長い直接引用は禁止する", modes)
        self.assertIn("原見出しの日本語翻訳表示", modes)

    def test_limited_feed_analysis_rows_have_expected_allow_flags(self):
        for source_id in ("the_hacker_news", "krebs_on_security"):
            row = self.rows_by_id[source_id]
            with self.subTest(source_id=source_id):
                self.assertEqual(row["proposed_mode"], "limited_feed_analysis")
                self.assertEqual(row["allow_network_fetch"], "true")
                self.assertEqual(row["allow_description"], "true")
                self.assertEqual(row["allow_rich_content"], "false")
                self.assertIn("conditional", row["allow_ai_processing"])
                self.assertEqual(row["allow_excerpt_storage"], "false")

    def test_risk_acceptance_rationale_is_recorded_and_not_asserted_as_permission(self):
        modes = self.policy.split("## 3. Content usage modes", 1)[1].split(
            "## 4. Source-by-source audit matrix", 1
        )[0]
        self.assertIn("採用理由(リスク受容の明示)", modes)
        self.assertIn("the_hacker_news", modes)
        self.assertIn("krebs_on_security", modes)
        self.assertIn("microsoft_security", modes)
        self.assertIn("cisco_talos", modes)
        self.assertIn("利用条件を確認し許諾を得た", modes)
        self.assertIn("運用上のリスク受容", modes)
        self.assertIn(
            "この2 sourceについて規約上問題がないと断定するものではない", modes
        )
        self.assertNotIn("利用が許可されていることを確認した", modes)

    def test_metadata_only_allows_metadata_fetch_and_does_not_prohibit_human_browsing(self):
        modes = self.policy.split("## 3. Content usage modes", 1)[1].split(
            "## 4. Source-by-source audit matrix", 1
        )[0]
        # allow_network_fetch=true for metadata_only sources (min-metadata
        # fetch continues); the definition must not contradict that by
        # claiming automated fetch itself is prohibited.
        self.assertIn(
            "最小メタデータの取得・リンク掲載は継続する", modes
        )
        self.assertIn(
            "自動処理を完全に行わない区分ではなく", modes
        )
        self.assertIn(
            "人によるページ閲覧や当該source自体の独自の報道・論評を禁止する趣旨でもない",
            modes,
        )
        self.assertIn("Cisco Talosの残余リスク", modes)
        self.assertIn("`disabled_legal_review`への降格を含めて再評価する", modes)
        self.assertIn("Today's Brief", modes)
        self.assertIn("未判定", modes)
        self.assertIn("AI処理の失敗", modes)

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

    def test_output_similarity_controls_are_recorded_as_bl032_merged(self):
        # BL-032's implementation (PR #69, merged) enforces these controls in
        # daily_json.py/fetch.py, so section 7 no longer says "not
        # implemented by this PR" — it records the merged status.
        controls = self.policy.split(
            "## 7. Output-similarity and quotation controls", 1
        )[1].split("## 8. Recheck triggers", 1)[0]
        self.assertIn("実装済み、PR #69 merge済み", controls)
        self.assertIn("具体的な閾値", controls)
        self.assertNotIn("本PR(BL-031)では実装しない", controls)

    def test_output_similarity_controls_distinguish_mechanical_from_residual_risk(self):
        controls = self.policy.split(
            "## 7. Output-similarity and quotation controls", 1
        )[1].split("## 8. Recheck triggers", 1)[0]
        self.assertIn("### A. 機械的に強制可能なBL-032要件", controls)
        self.assertIn("### B. 自動的な完全検出を約束しない残余リスク", controls)
        mechanical = controls.split("### A. 機械的に強制可能なBL-032要件", 1)[1].split(
            "### B. 自動的な完全検出を約束しない残余リスク", 1
        )[0]
        residual = controls.split("### B. 自動的な完全検出を約束しない残余リスク", 1)[1]
        # Mechanically enforceable: deterministic, field/length/string checks.
        self.assertIn("rich content", mechanical)
        self.assertIn("記事ページへの追加HTTP取得", mechanical)
        self.assertIn("最大1000文字", mechanical)
        self.assertIn("文字数上限", mechanical)
        self.assertIn("永続保存しない", mechanical)
        self.assertIn("limited_feed_analysis", mechanical)
        self.assertIn("日本語翻訳タイトルを公開しない", mechanical)
        self.assertIn("長い連続完全一致", mechanical)
        self.assertIn("attributionとして出力に含まれることを必須検証する", mechanical)
        self.assertIn("metadata_only`相当の簡易表示へ自動的に降格する", mechanical)
        # Residual: semantic evaluation that isn't fully automatable.
        self.assertIn("近接翻訳", residual)
        self.assertIn("lead paragraph", residual)
        self.assertIn("意味的評価", residual)
        self.assertIn("自動検出のみに依存しない", residual)
        self.assertIn("spot review", residual)
        self.assertIn("訂正・削除申出窓口", residual)
        self.assertIn("降格・訂正手順", residual)
        # The doc explicitly disclaims full automatic detection (quoted and
        # negated), rather than asserting it as a capability.
        self.assertIn("と扱わない", controls)

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
