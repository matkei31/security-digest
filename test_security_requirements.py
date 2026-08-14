#!/usr/bin/env python3
"""Static contract tests for SECURITY_REQUIREMENTS.md Version 1.2."""

import re
import unittest
from collections import Counter
from pathlib import Path

import document_test_utils as dtu

ROOT = Path(__file__).resolve().parent
REQUIREMENTS_PATH = ROOT / "SECURITY_REQUIREMENTS.md"


class SecurityRequirementsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.requirements = REQUIREMENTS_PATH.read_text(encoding="utf-8")
        cls.backlog = (ROOT / "BACKLOG.md").read_text(encoding="utf-8")
        cls.status = (ROOT / "STATUS.md").read_text(encoding="utf-8")
        cls.decisions = (ROOT / "DECISIONS.md").read_text(encoding="utf-8")
        cls.agents = (ROOT / "AGENTS.md").read_text(encoding="utf-8")

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

    @staticmethod
    def _markdown_rows(section):
        for line in section.splitlines():
            if line.startswith("| ") and not line.startswith("|---"):
                yield [cell.strip() for cell in line.strip().strip("|").split("|")]

    def _section(self, start, end):
        return self.requirements.split(start, 1)[1].split(end, 1)[0]

    def test_document_is_approved_version_14_maintenance_update(self):
        # Version 1.7 (Approved, BL-034 user-accepted 2026-08-03) is the
        # current header, but the frozen Version 1.4 approval record
        # (section 12) must remain byte-identical below it.
        self.assertTrue(REQUIREMENTS_PATH.is_file())
        self.assertIn("# Monomi Digest Security Requirements", self.requirements)
        self.assertIn("**Version:** 1.7", self.requirements)
        self.assertIn("**Status:** Approved", self.requirements)
        self.assertIn("no Critical or High findings", self.requirements)
        self.assertIn("accepted and modified findings", self.requirements)
        self.assertIn("rejected F-004 consolidation was not applied", self.requirements)
        self.assertIn("Version 1.4 is approved as a maintenance update", self.requirements)
        self.assertIn("answered 「ok」 to the complete decision brief", self.requirements)
        self.assertIn("not blanket preapproval", self.requirements)
        self.assertIn("Completed by documentation", self.requirements)
        self.assertIn("SD-025", self.requirements)
        # BL-038: these two facts live in the document's preamble, before
        # its first "##" heading, so there is no dedicated section to scope
        # extract_markdown_section to; normalize_markdown_prose is used
        # instead to stop the assertion depending on exactly where the
        # source Markdown happens to wrap these sentences (the original
        # literals embedded a specific mid-sentence line break each).
        normalized_requirements = dtu.normalize_markdown_prose(self.requirements)
        self.assertIn(
            dtu.normalize_markdown_prose(
                "Fable 5 could not retrieve `STATUS.md` or `test_security_requirements.py`"
            ),
            normalized_requirements,
            "SECURITY_REQUIREMENTS.md no longer records that Fable 5 could not "
            "retrieve STATUS.md/test_security_requirements.py",
        )
        self.assertIn(
            dtu.normalize_markdown_prose("checked independently at the PR head"),
            normalized_requirements,
            "SECURITY_REQUIREMENTS.md no longer records that those two files "
            "were checked independently at the PR head",
        )

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
            "## 11. Approved roadmap decisions",
            "## 12. Approval and maintenance",
            "## 13. Repository-owner verification",
        ):
            with self.subTest(heading=heading):
                self.assertIn(heading, self.requirements)

    def test_sr_ids_are_stable_unique_and_contiguous_through_047(self):
        ids = re.findall(r"(?m)^\|\s*(SR-\d{3})\s*\|", self.requirements)
        self.assertEqual(len(ids), len(set(ids)), f"Duplicate SR IDs: {ids}")
        self.assertEqual(ids, [f"SR-{number:03d}" for number in range(1, 48)])
        self.assertLess(self.requirements.index("| SR-030 |"), self.requirements.index("| SR-031 |"))
        self.assertLess(self.requirements.index("| SR-031 |"), self.requirements.index("| SR-032 |"))
        self.assertLess(self.requirements.index("| SR-042 |"), self.requirements.index("| SR-043 |"))
        self.assertLess(self.requirements.index("| SR-043 |"), self.requirements.index("| SR-044 |"))
        self.assertLess(self.requirements.index("| SR-044 |"), self.requirements.index("| SR-045 |"))
        self.assertLess(self.requirements.index("| SR-045 |"), self.requirements.index("| SR-046 |"))
        self.assertLess(self.requirements.index("| SR-046 |"), self.requirements.index("| SR-047 |"))

    def test_published_output_correction_requirement_and_gap_are_recorded(self):
        self.assertRegex(
            self.requirements,
            r"\| SR-043 \|.*correction, withdrawal, regeneration, and record procedure",
        )
        self.assertRegex(
            self.requirements,
            r"\| SR-043 \|.*\| Met \|",
        )
        self.assertIn("daily JSON or HTML", self.requirements)
        self.assertIn("subject or scope shift", self.requirements)
        self.assertIn("prompt-injection-derived output", self.requirements)
        self.assertIn("align the procedure with SD-014", self.requirements)
        self.assertRegex(
            self.requirements,
            r"\| GAP-014 \| Security gap \| Completed by documentation \| SR-043 \|",
        )
        self.assertIn("24/7 monitoring is not required", self.requirements)

    def test_operations_requirements_are_met_by_documentation_only(self):
        requirements = self._section(
            "## 6. Security requirements",
            "## 7. Current control mapping",
        )
        for requirement_id in ("SR-015", "SR-020", "SR-032", "SR-043"):
            row = next(
                row
                for row in self._markdown_rows(requirements)
                if row[0] == requirement_id
            )
            with self.subTest(requirement_id=requirement_id):
                self.assertEqual(row[3], "Met")
                self.assertIn("SECURITY_OPERATIONS.md", row[4])
        self.assertIn("no real secret operation", requirements)
        self.assertIn("without adding a correction schema/UI", requirements)
        self.assertIn("no retention automation", requirements)

    def test_semantic_risk_is_evidenced_without_impossibility_generalization(self):
        self.assertIn("BL-005 and BL-023", self.requirements)
        self.assertIn("unsupported assertions", self.requirements)
        self.assertIn("subject or scope regressions", self.requirements)
        self.assertIn("article-analysis-v9 and article-analysis-v10", self.requirements)
        self.assertIn("production remains article-analysis-v8", self.requirements)
        self.assertIn(
            "not\nevidence that improvement in general is impossible",
            self.requirements,
        )
        self.assertNotIn("prompt improvement is impossible", self.requirements)
        self.assertIn("or that production v8 always fails", self.requirements)

    def test_gap_ids_and_classifications_are_complete_and_limited(self):
        gaps = self._section(
            "## 8. Gap register",
            "## 9. Explicitly non-required controls for the current architecture",
        )
        rows = {
            row[0]: row
            for row in self._markdown_rows(gaps)
            if re.fullmatch(r"GAP-\d{3}", row[0])
        }
        expected_ids = [f"GAP-{number:03d}" for number in range(1, 19)]
        self.assertEqual(list(rows), expected_ids)
        self.assertEqual(len(rows), len(set(rows)))

        allowed = {
            "Security gap",
            "Hardening candidate",
            "Policy decision",
            "Owner verification",
            "Future trigger",
        }
        self.assertEqual({row[1] for row in rows.values()}, allowed)
        expected = {
            "GAP-001": "Security gap",
            "GAP-002": "Policy decision",
            "GAP-003": "Policy decision",
            "GAP-004": "Hardening candidate",
            "GAP-005": "Policy decision",
            "GAP-006": "Policy decision",
            "GAP-007": "Future trigger",
            "GAP-008": "Policy decision",
            "GAP-009": "Security gap",
            "GAP-010": "Owner verification",
            "GAP-011": "Future trigger",
            "GAP-012": "Policy decision",
            "GAP-013": "Policy decision",
            "GAP-014": "Security gap",
            "GAP-015": "Hardening candidate",
            "GAP-016": "Security gap",
            "GAP-017": "Owner verification",
            "GAP-018": "Policy decision",
        }
        self.assertEqual({gap_id: row[1] for gap_id, row in rows.items()}, expected)
        allowed_dispositions = {
            "Completed by documentation",
            "Implemented",
            "Accepted current state",
            "Deferred until trigger",
            "Completed owner verification",
            "Remains open for later prioritization",
            "Resolved by BL-030",
        }
        self.assertEqual({row[2] for row in rows.values()}, allowed_dispositions)
        expected_dispositions = {
            "GAP-001": "Implemented",
            "GAP-002": "Implemented",
            "GAP-003": "Implemented",
            "GAP-004": "Implemented",
            "GAP-005": "Accepted current state",
            "GAP-006": "Completed by documentation",
            "GAP-007": "Deferred until trigger",
            "GAP-008": "Completed by documentation",
            "GAP-009": "Remains open for later prioritization",
            "GAP-010": "Completed owner verification",
            "GAP-011": "Deferred until trigger",
            "GAP-012": "Resolved by BL-030",
            "GAP-013": "Completed by documentation",
            "GAP-014": "Completed by documentation",
            "GAP-015": "Deferred until trigger",
            "GAP-016": "Implemented",
            "GAP-017": "Completed owner verification",
            "GAP-018": "Implemented",
        }
        self.assertEqual(
            {gap_id: row[2] for gap_id, row in rows.items()},
            expected_dispositions,
        )
        self.assertIn("not a claim that every item is a confirmed security defect", gaps)

    def test_current_control_mapping_breakdowns_match_individual_sr_states(self):
        requirement_states = {}
        for row in self._markdown_rows(
            self._section("## 6. Security requirements", "## 7. Current control mapping")
        ):
            if re.fullmatch(r"SR-\d{3}", row[0]):
                requirement_states[int(row[0][3:])] = row[3]

        area_ids = {
            "Input and content handling": range(1, 6),
            "Prompt and AI boundary": range(6, 12),
            "Storage and publication": range(12, 17),
            "Secrets": range(17, 21),
            "GitHub Actions": range(21, 27),
            "Dependencies and supply chain": range(27, 30),
            "Logging and artifacts": range(30, 34),
            "Availability and recovery": range(34, 38),
            "Change and review control": range(38, 44),
        }
        mapping = self._section("## 7. Current control mapping", "## 8. Gap register")
        mapping_rows = {row[0]: row for row in self._markdown_rows(mapping)}
        labels = {
            "Met": "Met",
            "Partially met": "Partial",
            "Not met": "Not met",
            "Unverified outside repository": "Unverified",
        }

        mapped_ids = []
        for area, ids in area_ids.items():
            with self.subTest(area=area):
                ids = list(ids)
                mapped_ids.extend(ids)
                counts = Counter(labels[requirement_states[number]] for number in ids)
                expected_breakdown = (
                    f"Met {counts['Met']} / Partial {counts['Partial']} / "
                    f"Not met {counts['Not met']} / Unverified {counts['Unverified']}"
                )
                row = mapping_rows[area]
                self.assertEqual(row[5], expected_breakdown)
                expected_aggregate = "Met" if counts == Counter({"Met": len(ids)}) else "Partially met"
                self.assertEqual(row[4], expected_aggregate)

        self.assertEqual(sorted(mapped_ids), list(range(1, 44)))
        self.assertEqual(
            mapping_rows["Secrets"][5],
            "Met 2 / Partial 2 / Not met 0 / Unverified 0",
        )
        self.assertEqual(
            mapping_rows["Input and content handling"][5],
            "Met 5 / Partial 0 / Not met 0 / Unverified 0",
        )
        self.assertEqual(
            mapping_rows["GitHub Actions"][5],
            "Met 5 / Partial 1 / Not met 0 / Unverified 0",
        )
        self.assertEqual(
            mapping_rows["Dependencies and supply chain"][5],
            "Met 3 / Partial 0 / Not met 0 / Unverified 0",
        )
        self.assertEqual(
            mapping_rows["Logging and artifacts"][5],
            "Met 1 / Partial 3 / Not met 0 / Unverified 0",
        )
        self.assertEqual(
            mapping_rows["Availability and recovery"][5],
            "Met 2 / Partial 2 / Not met 0 / Unverified 0",
        )
        self.assertEqual(
            mapping_rows["Change and review control"][5],
            "Met 5 / Partial 1 / Not met 0 / Unverified 0",
        )
        self.assertEqual(
            mapping_rows["GitHub/Pages/DNS settings outside the repository"][4],
            "Partially met",
        )

    def test_met_definition_is_repository_limited(self):
        self.assertIn(
            "`Met` means that the contract,\nimplementation, or test is satisfied only "
            "to the extent confirmed by repository evidence",
            self.requirements,
        )
        self.assertIn("does not attest to GitHub, Pages, DNS", self.requirements)
        self.assertIn("not\nperfect compliance in every future execution", self.requirements)

    def test_exception_output_inventory_is_comprehensive_and_precise(self):
        for marker in (
            "`fetch.py`",
            "`daily_json.py`",
            "`vulnerability_facts.py`",
            "`_safe_fetch_error_text()`",
            "`translate()`",
            "`fetch_nist_nvd()`",
            "`gemini_analyze()`",
            "`gemini_todays_brief()`",
            "`load_source_definitions()`",
            "Active NVD facts and KEV structured-source retrieval",
            "Workflow shell",
            "does not directly print",
            "uncaught failure can reach workflow stderr",
        ):
            with self.subTest(marker=marker):
                self.assertIn(marker, self.requirements)
        self.assertIn(
            "| GAP-009 | Security gap | Remains open for later prioritization |",
            self.requirements,
        )
        self.assertIn("No explicit traceback-printing helper", self.requirements)

    def test_external_response_size_audit_and_gap_are_recorded(self):
        # BL-031 removed the Translation row (BL-030 deleted the code path it
        # described); the audit table now covers only current code paths.
        for response in (
            "RSS / Atom",
            "ARTICLE Gemini",
            "Legacy BRIEF Gemini",
            "Standalone NIST NVD",
            "Active NVD facts",
            "CISA KEV structured source",
        ):
            with self.subTest(response=response):
                self.assertIn(f"| {response} |", self.requirements)
        self.assertNotIn("| Translation |", self.requirements)
        self.assertRegex(
            self.requirements,
            r"\| SR-034 \|.*resource-consumption limits.*\| Partially met \|",
        )
        self.assertRegex(
            self.requirements,
            r"\| GAP-015 \| Hardening candidate \| Deferred until trigger \| SR-034 \|",
        )
        self.assertIn("no consistent byte cap at the network `read()` boundary", self.requirements)
        self.assertIn("no incident was found", self.requirements)

    def test_custom_domain_preflight_is_future_only_and_complete(self):
        for marker in (
            "verified-domain/domain verification",
            "dangling DNS",
            "takeover prevention",
            "safe Pages/DNS cutover and teardown order",
            "registrar MFA",
            "auto-renew",
            "expiration protection",
            "registrar/transfer lock",
            "repository rename impact",
            "rollback",
            "ownership",
        ):
            with self.subTest(marker=marker):
                self.assertIn(marker, self.requirements)
        self.assertRegex(
            self.requirements,
            r"\| GAP-011 \| Future trigger \| Deferred until trigger \|",
        )
        # BL-031: the domain is now live (BL-007/SD-028); GAP-011 no longer claims
        # it is "not implemented" and instead records the preflight as repeatable.
        self.assertIn(
            "not a current-site security gap because the custom domain is now live",
            self.requirements,
        )
        self.assertNotIn(
            "not a current-site security gap because the custom domain is not implemented",
            self.requirements,
        )

    def test_dast_is_not_duplicated(self):
        non_required = self._section(
            "## 9. Explicitly non-required controls for the current architecture",
            "## 10. Re-evaluation triggers",
        )
        self.assertEqual(non_required.count("DAST"), 1)
        self.assertIn("Dynamic application scanning (DAST)", non_required)
        self.assertIn("Dedicated SAST product", non_required)
        self.assertNotIn("SAST/DAST", non_required)

    def test_translation_cache_gap_is_resolved_by_bl030(self):
        gap_012 = next(
            row
            for row in self._markdown_rows(
                self._section(
                    "## 8. Gap register",
                    "## 9. Explicitly non-required controls for the current architecture",
                )
            )
            if row[0] == "GAP-012"
        )
        text = " ".join(gap_012)
        self.assertIn("`docs/translate_cache.json`", text)
        self.assertIn("BL-030", text)
        self.assertIn("Resolved by BL-030", text)
        self.assertIn("#66", text)
        self.assertIn("SD-029", text)
        self.assertNotIn("Accepted residual risk", text)

    def test_approved_roadmap_decisions_are_bounded_and_not_implemented(self):
        review = self._section(
            "## 11. Approved roadmap decisions",
            "## 12. Approval and maintenance",
        )
        for marker in (
            "full commit SHAs",
            "weekly `github-actions` Dependabot",
            "`cancel-in-progress: false`",
            "checkout credential persistence",
            "`SECURITY_OPERATIONS.md`",
            "90 days",
            "GAP-009 open for later prioritization",
        ):
            with self.subTest(marker=marker):
                self.assertIn(marker, review)
        self.assertIn("approve follow-up scope, not implementation", review)

    def test_workflows_and_dependabot_reflect_bl026_implementation(self):
        # BL-026 implements the GAP-002/003/004 roadmap this section approved,
        # and Version 1.3 records SR-025/SR-028/SR-029 as Met and
        # GAP-002/003/004 as Implemented following user acceptance and merge.
        #
        # BL-027 (Draft, user implementation acceptance pending) has since
        # moved the *live* workflow files to actions/checkout v7.0.1 and
        # actions/setup-python v7.0.0, so the assertions below check the
        # current pinned SHAs rather than the v4.4.0/v5.6.0 pair BL-026
        # accepted. SECURITY_REQUIREMENTS.md itself is untouched by BL-027
        # until user acceptance, merge, and the next scheduled production
        # run validate it; its Version 1.3 text (checked via self.requirements
        # below) still documents the accepted BL-026 v4.4.0/v5.6.0 baseline.
        production = (ROOT / ".github/workflows/fetch.yml").read_text(encoding="utf-8")
        pull_request = (ROOT / ".github/workflows/pr-ci.yml").read_text(encoding="utf-8")
        self.assertRegex(
            production + pull_request,
            r"uses:\s*actions/checkout@[0-9a-f]{40} # v7\.0\.1",
        )
        self.assertRegex(
            production + pull_request,
            r"uses:\s*actions/setup-python@[0-9a-f]{40} # v7\.0\.0",
        )
        self.assertNotIn("actions/checkout@v4", production + pull_request)
        self.assertNotIn("actions/setup-python@v5", production + pull_request)
        self.assertNotIn("11d5960a326750d5838078e36cf38b85af677262", production + pull_request)
        self.assertNotIn("a26af69be951a213d495a4c3e4e4022e16d87065", production + pull_request)
        self.assertIn("concurrency:", production)
        self.assertIn("cancel-in-progress: false", production)
        self.assertTrue((ROOT / ".github/dependabot.yml").exists())
        self.assertIn(
            "the accepted BL-026 workflow hardening",
            self.requirements,
        )
        self.assertRegex(
            self.requirements,
            r"\| SR-025 \|.*\| Met \|",
        )
        self.assertRegex(
            self.requirements,
            r"\| SR-028 \|.*\| Met \|",
        )
        self.assertRegex(
            self.requirements,
            r"\| SR-029 \|.*\| Met \|",
        )
        self.assertRegex(
            self.requirements,
            r"\| GAP-002 \| Policy decision \| Implemented \| SR-028 \|",
        )
        self.assertRegex(
            self.requirements,
            r"\| GAP-003 \| Policy decision \| Implemented \| SR-029 \|",
        )
        self.assertRegex(
            self.requirements,
            r"\| GAP-004 \| Hardening candidate \| Implemented \| SR-025 \|",
        )

    def test_bl006_backlog_entry_records_completed_brand_migration(self):
        bl006 = self.backlog.split("## BL-006", 1)[1].split("\n## ", 1)[0]
        self.assertIn("Monomi Digestへのブランド変更", bl006)
        self.assertIn("**優先度:** P2", bl006)
        self.assertIn("**状態:** 完了", bl006)
        self.assertIn("claude/bl006-brand-monomi", bl006)
        self.assertIn("claude/bl006-close", bl006)
        self.assertIn("B案", bl006)
        self.assertIn("`generator.application`は内部識別子として`\"security-digest\"`を維持する", bl006)
        self.assertIn("repository名`matkei31/security-digest`は変更しない", bl006)
        self.assertIn(
            "workflow display name（`Daily Security Digest`）とconcurrency group（`daily-security-digest-production`）は変更しない",
            bl006,
        )
        self.assertIn("既存daily JSON（`data/*.json`）は遡及変更しない", bl006)
        self.assertIn("BL-007の範囲", bl006)
        self.assertIn("BL-009の範囲", bl006)
        self.assertIn("PC 1280px／390pxでのトップページ", bl006)
        self.assertIn("残作業:** なし。", bl006)

    def test_bl006_accepted_head_final_head_and_merge_commit_are_distinct(self):
        # Mirrors the BL-027 accepted-head vs final-head distinction: the head
        # the user actually reviewed (802781b...) must stay recorded as the
        # acceptance target, separate from PR #57's post-acceptance final head
        # (0bd70c4...) and the merge commit (ea79ae1...) produced by closure.
        bl006 = self.backlog.split("## BL-006", 1)[1].split("\n## ", 1)[0]
        self.assertIn("**受入日:** 2026-07-26", bl006)
        self.assertIn(
            "「6枚とも確認した。ブランド変更の表示は問題なし。BL-006として受入。」", bl006
        )
        self.assertIn(
            "**受入対象の実装head:** `802781b31b5cc381a5bc4438d025f9af1c3a32e4`", bl006
        )
        self.assertIn("final head `0bd70c4c22cb27c2705bf87e01fcbf0bb6c0362b`", bl006)
        self.assertIn("merge commit `ea79ae12f5ddca2b241420f0c06cdfe3c6badf27`", bl006)
        self.assertIn("[PR #57](https://github.com/matkei31/security-digest/pull/57)", bl006)
        self.assertNotIn("受入対象の実装head:** `0bd70c4", bl006)
        self.assertNotIn("final head `802781b", bl006)
        self.assertNotIn("merge commit `802781b", bl006)

    def test_bl028_is_recorded_verbatim_as_complete(self):
        bl028 = self.backlog.split("## BL-028", 1)[1].split("\n## ", 1)[0]
        self.assertIn("ダイジェストナビゲーションの配置を再設計する", bl028)
        self.assertIn("**優先度:** P2", bl028)
        self.assertIn("**状態:** 完了", bl028)
        self.assertIn(
            "「『前のダイジェスト』『最新のダイジェスト』を右に持っていってもらったけど、"
            "実際見ると違和感あるね。左側で二段で表示するとか、何かイケてるUI考えてほしい」",
            bl028,
        )
        self.assertIn(
            "ユーザーと確定した仕様(A案「左寄せ二段・ラベルなし」)は次のとおり。",
            bl028,
        )
        self.assertIn(
            "日別Archiveの2段目は`過去のダイジェスト`／`最新のダイジェスト`の順とする"
            "(左側を過去方向、右側を新しい方向へ統一)。",
            bl028,
        )
        self.assertIn("BL-022やSD-021を未完了扱いに戻さず", bl028)
        self.assertIn("implementation branch `claude/bl028-nav-two-row-left`", bl028)
        self.assertIn(
            "「10枚とも確認した。BL-028の左寄せ二段配置、前→次／過去→最新の順序、"
            "上部・下部ナビゲーション、単一方向ケース、PC 1280px／390pxの表示に問題なし。"
            "BL-028として受入。」",
            bl028,
        )
        self.assertIn("77b4106618c29b9220012fd10e9ff616d773fa56", bl028)
        self.assertIn("PR #62", bl028)
        self.assertIn("a723dadaa4282db98060e83ef981b776b5742445", bl028)
        self.assertIn("fae9b682c97106c4ff9b45507aebf18db09fd77a", bl028)
        self.assertIn("- **残作業:** なし。", bl028)
        self.assertIn(
            "**出所:** 2026-07-26 プロジェクト会話（BL-006実装着手後、ユーザー受入・closure前）。",
            bl028,
        )
        self.assertNotIn("BL-006 closure直後", bl028)

    def test_bl029_is_recorded_verbatim_as_complete(self):
        bl029 = self.backlog.split("## BL-029", 1)[1].split("\n## ", 1)[0]
        self.assertIn("「金融機関との関連」とARTICLE見出しの情報設計を再検討する", bl029)
        self.assertIn("**優先度:** P1", bl029)
        self.assertIn("**状態:** 完了", bl029)
        self.assertIn(
            "「『金融機関との関連』のところは、どういった事項について関連を記載しているのかが不明。"
            "このままだったら消した方がいい。使うなら、本文側の『何が起きた』『なぜ金融機関に関係する』"
            "をまとめた文章にする必要がある。」",
            bl029,
        )
        self.assertIn(
            "「あと、『何が起きた』『なぜ金融機関に関係する』というタイトルはダサい。"
            "他の文言を提案してほしい」",
            bl029,
        )
        self.assertIn(
            "「重要・優先事項」は、現行`discussion_points`の対象条件（`importance==\"高\"`"
            "または`urgency`が`\"本日確認\"`／`\"今週確認\"`）を維持して選定する。",
            bl029,
        )
        self.assertIn(
            "選定された記事ごとに同一記事の`analysis.summary`と`analysis.financial_impact`をverbatimで使用し、"
            "一項目一`<li>`・summaryとfinancial_impactを別`<p>`として表示する。",
            bl029,
        )
        self.assertIn("完了済みBL-021を再オープンしない", bl029)
        self.assertIn("prompt-only改善No-GoのBL-023とも統合せず", bl029)
        self.assertIn(
            "「8枚とも確認した。BL-029の見出し、重要・優先事項の2段落表示、"
            "過去Archiveへの適用、0記事日の表示に問題なし。BL-029として受入。」",
            bl029,
        )
        self.assertIn("c4ca053b176c93fba3588c1f0aaf4116ab3fbc33", bl029)
        self.assertIn("PR #60", bl029)
        self.assertIn("a458888f45ff1521a0eb59117994ac3122fb2b83", bl029)
        self.assertIn("2a191828462731bf5204cdd83e867c0d29aec6e8", bl029)
        self.assertIn("- **残作業:** なし。", bl029)
        self.assertIn(
            "**出所:** 2026-07-26 プロジェクト会話（BL-006実装着手後、ユーザー受入・closure前）。",
            bl029,
        )
        self.assertNotIn("BL-006 closure直後", bl029)
        self.assertIn("implementation branch `claude/bl029-priority-items`", bl029)

    def test_bl028_bl029_registration_does_not_reopen_or_merge_other_tickets(self):
        # This record-only registration must not touch DECISIONS.md, UI_SPEC.md,
        # or the completed/on-hold state of BL-021/BL-022/BL-023.
        bl021 = self.backlog.split("## BL-021", 1)[1].split("\n## ", 1)[0]
        bl022 = self.backlog.split("## BL-022", 1)[1].split("\n## ", 1)[0]
        self.assertIn("**状態:** 完了", bl021)
        self.assertIn("**状態:** 完了", bl022)
        active = self.status.split("## Active work", 1)[1].split(
            "## 5. Recently completed work", 1
        )[0]
        self.assertNotIn("BL-028", active)
        self.assertNotIn("BL-029", active)
        recently_completed = self.status.split("## 5. Recently completed work", 1)[1].split(
            "## 6. Known issues and limitations", 1
        )[0]
        self.assertIn("BL-028", recently_completed)
        self.assertIn("BL-029", recently_completed)
        next_candidates = self.status.split("## 7. Next candidates", 1)[1].split(
            "## 8. Sources of truth", 1
        )[0]
        self.assertIn("BL-028", next_candidates)
        self.assertIn("[BL-029](BACKLOG.md#bl-029--金融機関との関連とarticle見出しの情報設計を再検討する)", next_candidates)
        self.assertIn("are all complete", next_candidates)

    def test_sd027_partially_supersedes_sd021_and_preserves_its_other_contracts(self):
        decisions = self.decisions
        sd027 = decisions[decisions.index("## SD-027"):decisions.index("## SD-028")]
        self.assertIn(
            "SD-027 — Redesign digest navigation to a left-aligned two-row layout "
            "shared by PC and 390px",
            sd027,
        )
        self.assertIn("- **Status:** Accepted", sd027)
        self.assertNotIn("Draft PR implemented, user acceptance pending", sd027)
        self.assertIn("A案「左寄せ二段・ラベルなし」", sd027)
        self.assertIn(
            "Supersedes:** [SD-021](#sd-021--unify-digest-navigation-labels-and-separate-direction-from-global-navigation) "
            "only for (a) placing the direction-movement group on the left and the "
            "global-navigation group on the right in a single PC row, and (b) the "
            "daily-Archive global-navigation link order",
            sd027,
        )
        self.assertIn("the four exact navigation labels", sd027)
        self.assertIn("no dates in navigation-link text", sd027)
        self.assertIn(
            "leaving hrefs, `aria-label`, and the validated date-selection/broken-link-prevention "
            "rules from [SD-020]",
            sd027,
        )

        sd021 = decisions[decisions.index("## SD-021"):decisions.index("## SD-022")]
        self.assertIn(
            "- **Status:** Accepted / Implemented and verified in production", sd021
        )
        self.assertNotIn("superseded by SD-027", sd021)

    def test_bl028_kickoff_does_not_reopen_bl017_or_bl022(self):
        # BL-007 was implemented separately in its own ticket after this
        # snapshot, so it is no longer asserted frozen here.
        bl017 = self.backlog.split("## BL-017", 1)[1].split("\n## ", 1)[0]
        bl022 = self.backlog.split("## BL-022", 1)[1].split("\n## ", 1)[0]
        bl029 = self.backlog.split("## BL-029", 1)[1].split("\n## ", 1)[0]
        self.assertIn("- **状態:** 完了", bl017)
        self.assertIn("- **状態:** 完了", bl022)
        self.assertIn("- **状態:** 完了", bl029)

    def test_bl027_acceptance_head_is_distinct_from_pr54_final_head(self):
        # The explicit 「ok」 was given at PR #54 head d7461b9..., not at the
        # later final head 241e7f69... produced by the acceptance-recording
        # commit. SECURITY_REQUIREMENTS.md must not conflate the two.
        self.assertIn(
            "accepted by the user with 「ok」 at\n"
            "[PR #54](https://github.com/matkei31/security-digest/pull/54) head\n"
            "`d7461b9adfe474793a60f61cd6fe8b219153b499`",
            self.requirements,
        )
        self.assertIn(
            "the acceptance-recording commit produced final\n"
            "head `241e7f69c9c843fc212c1c590f3a328da5946579`, which passed Pull Request CI "
            "and merged as",
            self.requirements,
        )
        self.assertNotIn(
            "accepted by the user with 「ok」 at\n"
            "[PR #54](https://github.com/matkei31/security-digest/pull/54) head\n"
            "`241e7f69c9c843fc212c1c590f3a328da5946579`",
            self.requirements,
        )

    def test_bl027_backlog_entry_records_completed_workflow_dispatch_validation(self):
        bl027 = self.backlog.split("## BL-027", 1)[1].split("\n## ", 1)[0]
        self.assertIn(
            "GitHub Actions checkout／setup-pythonをv7系へmajor upgradeする", bl027
        )
        self.assertIn("**優先度:** P2", bl027)
        self.assertIn("**状態:** 完了", bl027)
        self.assertIn("3d3c42e5aac5ba805825da76410c181273ba90b1", bl027)
        self.assertIn("5fda3b95a4ea91299a34e894583c3862153e4b97", bl027)
        self.assertIn("v7.0.1", bl027)
        self.assertIn("v7.0.0", bl027)
        self.assertIn("PR #51", bl027)
        self.assertIn("PR #52", bl027)
        self.assertIn("11d5960a326750d5838078e36cf38b85af677262", bl027)
        self.assertIn("a26af69be951a213d495a4c3e4e4022e16d87065", bl027)
        self.assertIn("「ok」と個別実装受入した", bl027)
        self.assertIn("d7461b9adfe474793a60f61cd6fe8b219153b499", bl027)
        self.assertIn("241e7f69c9c843fc212c1c590f3a328da5946579", bl027)
        self.assertIn("69f7da859e1856beffac9fa381f0f0cc92564e36", bl027)
        self.assertIn("superseded close", bl027)
        self.assertIn("workflow_dispatch", bl027)
        self.assertIn("30147337332", bl027)
        self.assertIn("226db6285021d9daf98fe2941248b7f5b20ba143", bl027)
        self.assertIn("30147402699", bl027)
        self.assertIn("**残作業:** なし。", bl027)
        self.assertNotIn("通常scheduleで検証した", bl027)
        active = self.status.split("## Active work", 1)[1].split(
            "## 5. Recently completed work", 1
        )[0]
        recently_completed = self.status.split("## 5. Recently completed work", 1)[1].split(
            "## 6. Known issues and limitations", 1
        )[0]
        self.assertNotIn("BL-027", active)
        self.assertNotIn("BL-029", active)
        self.assertIn("BL-006", recently_completed)
        self.assertIn("BL-027", recently_completed)
        self.assertIn("BL-029", recently_completed)
        self.assertIn("workflow_dispatch", recently_completed)
        self.assertIn("30147337332", recently_completed)
        self.assertNotIn("通常scheduleで検証した", recently_completed)

    def test_bl026_closure_records_pending_run_limitation_and_leaves_other_gaps_unchanged(self):
        self.assertIn(
            "a new pending run can replace an existing pending run",
            self.requirements,
        )
        self.assertIn("independent durable queue", self.requirements)
        self.assertRegex(
            self.requirements,
            r"\| GAP-007 \| Future trigger \| Deferred until trigger \| SR-029 \|",
        )
        self.assertRegex(
            self.requirements,
            r"\| GAP-009 \| Security gap \| Remains open for later prioritization \|",
        )
        self.assertRegex(
            self.requirements,
            r"\| GAP-015 \| Hardening candidate \| Deferred until trigger \| SR-034 \|",
        )

    def test_current_gaps_non_required_and_triggers_are_distinct(self):
        mapping = self._section("## 7. Current control mapping", "## 8. Gap register")
        gaps = self._section(
            "## 8. Gap register",
            "## 9. Explicitly non-required controls for the current architecture",
        )
        non_required = self._section(
            "## 9. Explicitly non-required controls for the current architecture",
            "## 10. Re-evaluation triggers",
        )
        triggers = self._section(
            "## 10. Re-evaluation triggers",
            "## 11. Approved roadmap decisions",
        )

        for status in (
            "Met",
            "Partially met",
            "Not applicable now",
        ):
            self.assertIn(status, mapping)
        self.assertIn("does not mean the underlying control is implemented", gaps)
        self.assertIn("WAF", non_required)
        self.assertIn("24/7 SOC monitoring", non_required)
        self.assertIn("introducing `monomidigest.com`", triggers)
        self.assertIn("adding forms, authentication, sessions", triggers)

    def test_future_components_are_not_misstated_as_current(self):
        # BL-007 completed and the custom domain is live; BL-031 removed the stale
        # "future ... not implemented" phrasing (see GAP-011) and records it as live.
        self.assertIn("the live `monomidigest.com` custom domain (completed by", self.requirements)
        self.assertIn(
            "No component for forms, authentication, sessions, a database, payments",
            self.requirements,
        )
        self.assertIn(
            "Forms, authentication, database, and payments",
            self.requirements,
        )
        self.assertNotIn("the future `monomidigest.com` custom domain", self.requirements)
        self.assertNotIn("custom domain is implemented", self.requirements)
        self.assertNotIn("forms are currently implemented", self.requirements)

    def test_no_secret_value_or_local_absolute_path_is_present(self):
        for text in (
            self.requirements,
            self.backlog,
            self.status,
            self.decisions,
            self.agents,
        ):
            self.assertNotIn("/Users/", text)
            self.assertNotRegex(text, r"AIza[0-9A-Za-z_-]{20,}")
            self.assertNotRegex(text, r"ghp_[0-9A-Za-z]{20,}")
            self.assertNotRegex(text, r"github_pat_[0-9A-Za-z_]{20,}")
        self.assertIn("secret names", self.requirements)
        self.assertIn("No value was inspected", self.requirements)

    def test_bl015_is_complete_and_removed_from_active_work(self):
        bl015 = self.backlog.split("## BL-015", 1)[1].split("## BL-016", 1)[0]
        self.assertIn("**状態:** 完了", bl015)
        self.assertIn("[SECURITY_REQUIREMENTS.md](SECURITY_REQUIREMENTS.md) Draft 0.1", bl015)
        self.assertIn("Draft 0.2", bl015)
        self.assertIn("Version 1.0", bl015)
        self.assertIn("Critical 0、High 0", bl015)
        self.assertIn("F-001〜F-003およびF-005〜F-009", bl015)
        self.assertIn("F-004", bl015)
        self.assertIn("SR-043", bl015)
        self.assertIn("GAP-014", bl015)
        self.assertIn("GAP-015", bl015)
        self.assertIn("security-control実装", bl015)
        self.assertIn("GAP-010 repository-owner checklist", bl015)
        self.assertIn("「ok」", bl015)
        self.assertIn("BL-024", bl015)
        self.assertIn("BL-025", bl015)
        self.assertIn("BL-026", bl015)
        self.assertIn("PR #44", bl015)
        self.assertIn("eef80a3a589bbaee8dbb373c4a0ee0f75038546d", bl015)
        self.assertIn("3f1803388161495f9145150e760d91b03821ad80", bl015)
        self.assertIn("Pull Request CI run 30095261901", bl015)
        self.assertIn("BL-015自体はなし", bl015)

        active = self.status.split("## Active work", 1)[1].split(
            "## 5. Recently completed work", 1
        )[0]
        recently_completed = self.status.split("## 5. Recently completed work", 1)[1].split(
            "## 6. Known issues and limitations", 1
        )[0]
        self.assertNotIn("BL-015", active)
        self.assertIn("BL-015 Security Requirements Version 1.0", recently_completed)
        self.assertIn("GAP-010 repository-owner checklist", recently_completed)
        self.assertIn("「ok」", recently_completed)
        self.assertIn("PR #44", recently_completed)
        self.assertIn("3f1803388161495f9145150e760d91b03821ad80", recently_completed)
        self.assertIn("BL-015 itself has no residual work", recently_completed)

    def test_sd024_sd025_and_follow_up_tickets_are_recorded(self):
        self.assertIn(
            "## SD-024 — Approve Security Requirements Version 1.0 and the "
            "proportionate security roadmap",
            self.decisions,
        )
        sd024 = self.decisions.split("## SD-024", 1)[1].split("## SD-025", 1)[0]
        self.assertIn("「ok」", sd024)
        self.assertIn("PR #44", sd024)
        self.assertIn("**Status:** Accepted / Version 1.0 merged", sd024)
        self.assertIn("eef80a3a589bbaee8dbb373c4a0ee0f75038546d", sd024)
        self.assertIn("3f1803388161495f9145150e760d91b03821ad80", sd024)
        self.assertIn("Pull Request CI run 30095261901", sd024)
        bl024 = self.backlog.split("## BL-024", 1)[1].split("\n## ", 1)[0]
        self.assertIn("**状態:** 完了", bl024)
        self.assertIn("**残作業:** なし", bl024)
        self.assertIn("「ok」", bl024)
        self.assertIn(
            "## SD-025 — Approve Security Operations Version 1.0 and the "
            "minimal incident and correction policy",
            self.decisions,
        )
        sd025 = self.decisions.split("## SD-025", 1)[1].split("## SD-026", 1)[0]
        self.assertIn("Completed by documentation", sd025)
        self.assertIn("PR #46", sd025)
        self.assertIn("「ok」", sd025)
        self.assertIn("Accepted / Version 1.0 merged", sd025)
        self.assertIn("a04e3a3b6c5789d0a2e4de983054035080f0ce75", sd025)
        self.assertIn("047534601d8d15419a8d3b45142d8828bc655ad4", sd025)
        self.assertIn("Pull Request CI run 30102905467", sd025)
        self.assertIn("Pages deployment run 30103074821", sd025)
        bl025 = self.backlog.split("## BL-025", 1)[1].split("\n## ", 1)[0]
        self.assertIn("収集元URLをhttp／https schemeへ制限する", bl025)
        self.assertIn("**優先度:** P2", bl025)
        self.assertIn("**状態:** 完了", bl025)
        self.assertIn("完成実装へ「ok」", bl025)
        self.assertIn("hostname allowlist", bl025)
        self.assertIn("production実行を承認するものではない", bl025)
        self.assertIn("SR-003を`Met`、GAP-001を`Implemented`", bl025)
        self.assertIn("ffca290ba74f3002adf9f383bddfff80b42860b7", bl025)
        self.assertIn("Pull Request CI run 30107009791", bl025)
        self.assertIn("2f93556532c6600a0d650c93d388a237b98e7aaa", bl025)
        self.assertIn("**残作業:** なし", bl025)
        active = self.status.split("## Active work", 1)[1].split(
            "## 5. Recently completed work", 1
        )[0]
        self.assertNotIn("BL-025", active)
        self.assertNotIn("BL-026", active)
        self.assertNotIn("BL-027", active)
        self.assertNotIn("BL-029", active)
        recently_completed = self.status.split("## 5. Recently completed work", 1)[1].split(
            "## 6. Known issues and limitations", 1
        )[0]
        self.assertIn("BL-029", recently_completed)
        self.assertIn("BL-006", recently_completed)
        self.assertIn("BL-025 source collection URL scheme validation", recently_completed)
        self.assertIn("「ok」", recently_completed)
        self.assertIn("PR #48", recently_completed)
        self.assertIn("ffca290ba74f3002adf9f383bddfff80b42860b7", recently_completed)
        self.assertIn("Pull Request CI run 30107009791", recently_completed)
        self.assertIn("2f93556532c6600a0d650c93d388a237b98e7aaa", recently_completed)
        self.assertIn("no residual work", recently_completed)
        self.assertIn("BL-026 GitHub Actions supply-chain hardening and production concurrency", recently_completed)
        self.assertIn("PR #50", recently_completed)
        self.assertIn("4b1fcb3d940513e2b7407120d1953c029532f25c", recently_completed)
        self.assertIn("Pull Request CI run 30141453440", recently_completed)
        self.assertIn("5bfc73fcb4b814504906c0a224613426384aa144", recently_completed)
        self.assertIn("BL-026 has no residual work", recently_completed)
        self.assertIn("BL-027 GitHub Actions checkout／setup-python combined major upgrade to v7", recently_completed)
        self.assertIn("PR #54", recently_completed)
        self.assertIn("d7461b9adfe474793a60f61cd6fe8b219153b499", recently_completed)
        self.assertIn("241e7f69c9c843fc212c1c590f3a328da5946579", recently_completed)
        self.assertIn("69f7da859e1856beffac9fa381f0f0cc92564e36", recently_completed)
        self.assertIn("30147337332", recently_completed)
        self.assertIn("226db6285021d9daf98fe2941248b7f5b20ba143", recently_completed)
        self.assertIn("BL-027 has no residual work", recently_completed)
        next_candidates = self.status.split("## 7. Next candidates", 1)[1].split(
            "## 8. Sources of truth", 1
        )[0]
        self.assertNotIn("1. [BL-026]", next_candidates)
        self.assertIn("[BL-026]", next_candidates)
        self.assertIn("are all complete", next_candidates)
        self.assertIn("[BL-027]", next_candidates)
        self.assertIn(
            "so none is named as the ranked next candidate purely by priority number", next_candidates
        )
        self.assertNotIn("[BL-025]", next_candidates)
        self.assertRegex(
            self.requirements,
            r"\| SR-003 \|.*\| Met \|",
        )
        self.assertRegex(
            self.requirements,
            r"\| GAP-001 \| Security gap \| Implemented \| SR-003 \|",
        )
        bl026 = self.backlog.split("## BL-026", 1)[1].split("\n## ", 1)[0]
        self.assertIn(
            "GitHub Actions supply chainとproduction concurrencyを強化する", bl026
        )
        self.assertIn("**優先度:** P2", bl026)
        self.assertIn("**状態:** 完了", bl026)
        self.assertIn("11d5960a326750d5838078e36cf38b85af677262", bl026)
        self.assertIn("a26af69be951a213d495a4c3e4e4022e16d87065", bl026)
        self.assertIn("cancel-in-progress: false", bl026)
        self.assertIn("dependabot.yml", bl026)
        self.assertIn("production workflowとworkflow_dispatchは未実行", bl026)
        self.assertIn("「ok」", bl026)
        self.assertIn("394dd157395b69e86928d98a376386131474b20f", bl026)
        self.assertIn("5bfc73fcb4b814504906c0a224613426384aa144", bl026)
        self.assertIn("**残作業:** なし", bl026)
        self.assertIn("GAP-009", self.requirements)
        self.assertIn("Remains open for later prioritization", self.requirements)
        self.assertIn("GAP-015", self.requirements)
        self.assertIn("Deferred until trigger", self.requirements)

    def test_owner_checklist_mandatory_items_are_resolved_without_sensitive_data(self):
        owner = self.requirements.split("## 13. Repository-owner verification", 1)[1]
        rows = [
            row
            for row in self._markdown_rows(owner)
            if row[0] in {"Repository", "Actions", "Pages", "Notifications", "Security"}
        ]
        mandatory = [row for row in rows if "(mandatory)" in row[1]]
        self.assertGreaterEqual(len(mandatory), 13)
        allowed_results = (
            "Verified",
            "Not configured",
            "Not applicable",
            "Unverified — owner access required",
        )
        self.assertTrue(all(row[2].startswith(allowed_results) for row in rows))
        self.assertTrue(
            all(row[2] != "Unverified — owner access required" for row in mandatory)
        )
        for marker in (
            "Visibility (mandatory)",
            "Default branch (mandatory)",
            "Main branch protection or ruleset (mandatory)",
            "Force-push blocking (mandatory)",
            "Branch-deletion blocking (mandatory)",
            "Default workflow token permission (mandatory)",
            "Fork PR approval policy (mandatory)",
            "`workflow_dispatch` permission range (mandatory)",
            "Required production secret `GEMINI_API_KEY` (mandatory)",
            "Source branch/directory (mandatory)",
            "HTTPS enforcement (mandatory)",
            "Custom domain (mandatory)",
            "Log and default artifact retention (mandatory)",
        ):
            self.assertIn(marker, owner)
        self.assertIn("Mandatory checklist items contain no", owner)

    def test_agents_references_security_docs_without_blanket_authorization(self):
        # BL-035 (Fable 5 review R-03): AGENTS.md no longer hardcodes
        # SECURITY_REQUIREMENTS.md/SECURITY_OPERATIONS.md/UI_SPEC.md Version
        # numbers here -- all three delegate to each document's own header
        # instead, so this reference cannot go stale again on the next Version
        # bump of any of them. Round 1 of BL-035's own review replaced the
        # earlier Japanese-parenthetical delegation wording (which read
        # awkwardly butted against English words, e.g. "）is") with a plain
        # English clause, so this checks for that clause, not the Japanese text.
        DELEGATION_PHRASE = (
            "that file's own header, not this file, is the source of truth for "
            "its current Version and Status"
        )
        security = self.agents.split("## Security requirements", 1)[1].split(
            "## Testing and review", 1
        )[0]
        self.assertIn("SECURITY_REQUIREMENTS.md", security)
        self.assertIn("SECURITY_REQUIREMENTS.md](SECURITY_REQUIREMENTS.md)", security)
        self.assertIn("SECURITY_OPERATIONS.md](SECURITY_OPERATIONS.md)", security)
        self.assertEqual(security.count(DELEGATION_PHRASE), 2)
        self.assertNotRegex(security, r"SECURITY_REQUIREMENTS\.md\]\(SECURITY_REQUIREMENTS\.md\)\s*Version\s+\d+\.\d+")
        self.assertNotRegex(security, r"SECURITY_OPERATIONS\.md\]\(SECURITY_OPERATIONS\.md\)\s*Version\s+\d+\.\d+")
        self.assertIn("credential rotation or revocation", security)
        self.assertIn("published-output correction or withdrawal", security)
        self.assertIn("repository-external artifact handling", security)
        self.assertIn("re-evaluation triggers", security)
        self.assertIn("approved ticket", security)
        self.assertIn("not blanket authorization", security)

    def test_agents_ui_spec_reference_delegates_version_too(self):
        scope = self.agents.split("## Scope discipline", 1)[1].split(
            "## Backlog provenance and completion", 1
        )[0]
        self.assertIn("UI_SPEC.md](UI_SPEC.md)", scope)
        self.assertIn(
            "that file's own header, not this file, is the source of truth for "
            "its current Version and Status",
            scope,
        )
        self.assertNotRegex(scope, r"UI_SPEC\.md\]\(UI_SPEC\.md\)\s*Version\s+\d+\.\d+")

    def test_agents_describes_pr_ci_and_fetch_yml_triggers_accurately(self):
        # BL-035 round 1 (Fable 5 review): AGENTS.md previously called
        # fetch.yml "the only push/schedule workflow", which misdescribes it as
        # push-triggered. fetch.yml has no `push` trigger -- only `schedule` and
        # `workflow_dispatch` -- and the commit/push it performs after a
        # successful run is an action the run takes, not a triggering event.
        testing = self.agents.split("## Testing and review", 1)[1].split(
            "## Git and generated output", 1
        )[0]
        self.assertIn("pr-ci.yml", testing)
        self.assertIn("fetch.yml", testing)
        self.assertIn("`schedule`", testing)
        self.assertIn("`workflow_dispatch`", testing)
        self.assertIn("no `push` trigger", testing)
        self.assertNotIn("only push/schedule workflow", testing)
        self.assertNotIn("push/schedule workflow", testing)
        self.assertIn("GitHub Pages", testing)
        self.assertIn("not a PR CI check", testing)
        # BL-035 round 2 (Fable 5 review): fetch.yml's own commit/push must not
        # be described as re-triggering "any other workflow" -- that phrase was
        # too broad and contradicted the very next sentence, which says that
        # same push does trigger GitHub Pages' platform-managed deployment.
        self.assertNotIn("or any other workflow", testing)
        self.assertIn("re-triggers `fetch.yml` itself", testing)
        self.assertIn(
            "no other workflow defined in this repository is triggered by an ordinary push",
            testing,
        )
        self.assertIn("platform-managed", testing)
        self.assertIn("not a workflow defined in this repository", testing)

    def test_agents_pr_ci_checkout_target_is_the_merge_candidate_not_the_head(self):
        # BL-035 round 2 (Fable 5 review): pr-ci.yml's `actions/checkout` step
        # has no `ref`, so a `pull_request`-triggered run checks out GitHub's
        # auto-generated merge candidate (refs/pull/<PR>/merge), not the PR head
        # commit by itself. AGENTS.md previously said the workflow "checks out
        # the PR head," which is not what happens without an explicit `ref`.
        testing = self.agents.split("## Testing and review", 1)[1].split(
            "## Git and generated output", 1
        )[0]
        self.assertNotIn("checks out the PR head", testing)
        self.assertIn("does not set a `ref`", testing)
        self.assertIn("merge candidate", testing)
        self.assertIn("refs/pull/<PR>/merge", testing)
        self.assertIn("`persist-credentials: false`", testing)

    def test_agents_distinguishes_unittest_target_diff_check_range_and_head_association(self):
        # BL-035 round 2 (Fable 5 review): a reader must not come away thinking
        # "the full unittest suite ran on the PR head" -- it runs on the merge
        # candidate; `git diff --check` is the part that is scoped to
        # base...head; and which PR head a run is "for" is a separate fact read
        # from the run's own status-check head SHA.
        testing = self.agents.split("## Testing and review", 1)[1].split(
            "## Git and generated output", 1
        )[0]
        self.assertIn("full unittest suite", testing)
        self.assertIn("merge-candidate checkout", testing)
        self.assertIn("`base...head`", testing)
        self.assertIn("status-check head SHA", testing)
        self.assertIn("passed against that run's merge-candidate checkout", testing)
        self.assertIn("passed over that run's `base...head` range", testing)

    def test_agents_pr_ci_secret_and_token_wording_is_precise(self):
        # BL-035 round 1: "no secrets" must describe pr-ci.yml not referencing
        # any repository secret, and must not be conflated with (or read as
        # denying) the GitHub Actions job token: pr-ci.yml's workflow-level
        # `permissions:` scopes that job token (GITHUB_TOKEN) to `contents:
        # read`, it is not evidence that no token exists for the job.
        testing = self.agents.split("## Testing and review", 1)[1].split(
            "## Git and generated output", 1
        )[0]
        self.assertIn("does not reference any repository secret", testing)
        self.assertIn("`GITHUB_TOKEN`", testing)
        self.assertIn("`contents: read`", testing)
        self.assertIn("not a claim that GitHub withholds a token from the job", testing)

    def test_security_requirements_internal_markdown_links_resolve(self):
        docs = {
            name: (ROOT / name).read_text(encoding="utf-8")
            for name in (
                "SECURITY_REQUIREMENTS.md",
                "SECURITY_OPERATIONS.md",
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


class Bl031SecurityRequirementsReconciliationTest(unittest.TestCase):
    """BL-031: SECURITY_REQUIREMENTS.md Version 1.5 (Draft)がBL-030の変更・稼働中
    のカスタムドメイン・SOURCE_USAGE_POLICY.mdを整合的に反映していることを検証する。
    per-source policy enforcementは本Ticketでは実装されないため「Met」と記載
    されていないことも確認する。
    """

    @classmethod
    def setUpClass(cls):
        cls.requirements = REQUIREMENTS_PATH.read_text(encoding="utf-8")
        cls.backlog = (ROOT / "BACKLOG.md").read_text(encoding="utf-8")
        cls.status = (ROOT / "STATUS.md").read_text(encoding="utf-8")
        cls.decisions = (ROOT / "DECISIONS.md").read_text(encoding="utf-8")
        cls.policy = (ROOT / "SOURCE_USAGE_POLICY.md").read_text(encoding="utf-8")

    def _section(self, start, end):
        return self.requirements.split(start, 1)[1].split(end, 1)[0]

    @staticmethod
    def _markdown_rows(section):
        for line in section.splitlines():
            if line.startswith("| ") and not line.startswith("|---"):
                yield [cell.strip() for cell in line.strip().strip("|").split("|")]

    def test_version_and_status_are_16_draft(self):
        # Version 1.6 (BL-032 Draft implementation, pending user acceptance)
        # was the header at BL-031-registration time. Version 1.7 (BL-034)
        # was itself a Draft header at first, then the user accepted BL-034's
        # implementation on 2026-08-03 (PR #72 round 2), making Version 1.7
        # the current Approved header, layered on top of Version 1.6.
        self.assertIn("**Version:** 1.7", self.requirements)
        self.assertIn("**Status:** Approved", self.requirements)
        self.assertIn("**As of:** 2026-08-03", self.requirements)

    def test_no_current_architecture_mention_of_removed_translation_path(self):
        scope = self._section(
            "## 2. System scope and components", "## 3. Data flow"
        )
        self.assertNotIn("translate.googleapis.com", scope)
        self.assertNotIn("translate_cache.json", scope)
        assets = self._section(
            "## 4. Assets and data classification", "## 5. Trust boundaries"
        )
        self.assertNotIn("translate_cache.json", assets)
        # GAP-012 may still mention the removed endpoint/cache historically
        # ("Previously: ..."), so only assert it is marked resolved there.
        gaps = self._section(
            "## 8. Gap register",
            "## 9. Explicitly non-required controls for the current architecture",
        )
        self.assertIn("docs/translate_cache.json", gaps)
        self.assertIn("Resolved by BL-030", gaps)

    def test_current_state_sections_1_through_7_have_no_stale_translation_text(self):
        # Sections 1-7 describe the CURRENT architecture/requirements/control
        # mapping; they must not retain text describing the removed
        # translation endpoint as if it still exists. Historical mentions
        # (Version 1.5 history in the intro, GAP-012's "Previously: ..."
        # record, SD-029/PR #66 references in section 11/12) are explicitly
        # out of scope for this check and are covered by
        # test_no_current_architecture_mention_of_removed_translation_path
        # and test_translation_cache_gap_is_resolved_by_bl030 instead.
        current_state = self._section(
            "## 1. Purpose and proportionality", "## 8. Gap register"
        )
        self.assertNotIn("| Translation |", current_state)
        self.assertNotIn("Request text is limited to 500 characters", current_state)
        self.assertNotIn("cache keys to 300 characters", current_state)
        self.assertNotIn(
            "structured-source, translation, and API response content", current_state
        )
        self.assertNotIn(
            "external RSS, Atom, JSON, translation, NVD, KEV", current_state
        )
        self.assertNotIn("Translation and general Gemini exception paths", current_state)
        self.assertNotIn(
            "not consistently used by translation and Gemini", current_state
        )

    def test_historical_sections_may_still_reference_the_removed_translation_path(self):
        # Confirms the previous test's scrub was scoped correctly: the intro
        # (Version 1.5 history) and GAP-012 are allowed to describe the
        # removed translation path in the past tense, and still do.
        intro = self._section(
            "# Monomi Digest Security Requirements", "## 1. Purpose and proportionality"
        )
        self.assertIn("translation-endpoint removal", intro)
        gaps = self._section(
            "## 8. Gap register",
            "## 9. Explicitly non-required controls for the current architecture",
        )
        self.assertIn("the unofficial translation endpoint", gaps)

    def test_monomidigest_com_is_recorded_as_the_current_domain(self):
        scope = self._section(
            "## 2. System scope and components", "## 3. Data flow"
        )
        self.assertIn("the live `monomidigest.com` custom domain", scope)
        self.assertNotIn("the future `monomidigest.com` custom domain", scope)
        self.assertIn("Verified — configured as `monomidigest.com`", self.requirements)

    def test_source_usage_policy_is_referenced_as_audit_only(self):
        self.assertIn("SOURCE_USAGE_POLICY.md", self.requirements)
        scope = self._section(
            "## 2. System scope and components", "## 3. Data flow"
        )
        self.assertIn("SOURCE_USAGE_POLICY.md", scope)
        self.assertIn("audit-only", scope)

    def test_per_source_enforcement_is_implemented_and_no_longer_pending_acceptance(self):
        # BL-034 round 2 acceptance update (2026-08-03): BL-032's
        # implementation (accepted since PR #69) and BL-034's implementation
        # (accepted at this Version) are both now Implemented, not Draft --
        # the gap register must no longer claim either is pending user
        # acceptance. SR-046 (nist_nvd activation_condition, unrelated to
        # BL-032/BL-034) still must remain Partially met.
        self.assertNotRegex(
            self.requirements,
            r"SR-046[^\n|]*\|\s*Met\s*\|",
        )
        gaps = self._section(
            "## 8. Gap register",
            "## 9. Explicitly non-required controls for the current architecture",
        )
        self.assertNotIn("pending user acceptance", gaps)
        self.assertNotIn(
            "do not treat this Draft implementation as an approved control until acceptance is recorded",
            gaps,
        )
        self.assertIn("BL-032", gaps)
        self.assertIn("BL-034", gaps)

    def test_bl031_is_recorded_in_status_recently_completed_work(self):
        active = self.status.split("## Active work", 1)[1].split(
            "## 5. Recently completed work", 1
        )[0]
        active_lines = active.splitlines()
        self.assertFalse(any(line.startswith("- BL-031 ") for line in active_lines))
        # BL-032's PR #69 merged during post-merge closeout, so it moved out of
        # Active work into Recently completed alongside BL-031. BL-035's own
        # Active work entry legitimately names BL-032 as background context (the
        # enforcement work it is synchronizing), so this checks BL-032 does not
        # reappear as its own Active work bullet rather than banning the
        # substring "BL-032" outright.
        self.assertFalse(any(line.startswith("- BL-032 ") for line in active_lines))
        recently_completed = self.status.split("## 5. Recently completed work", 1)[1].split(
            "## 6. Known issues and limitations", 1
        )[0]
        self.assertIn("BL-031", recently_completed)
        self.assertIn("BL-032", recently_completed)

    def test_bl031_gemini_billing_confirmation_removed_from_backlog_residual_work(self):
        bl031 = self.backlog.split("## BL-031", 1)[1].split("\n## ", 1)[0]
        residual = bl031.split("**残作業:**", 1)[1].split("\n- **注記:**", 1)[0]
        self.assertNotIn("Gemini API課金状況のowner確認", residual)
        # Google TAG's post-effective-date recheck completed this round; it is
        # no longer residual work, so it must not still be listed here.
        self.assertNotIn("Google TAG利用規約の2026-07-30改定後の再確認", residual)
        self.assertIn("Cisco Talos", residual)
        self.assertIn("Krebs on Security", residual)
        self.assertIn("BL-032", bl031)
        self.assertIn("BL-009", bl031)

    def test_bl031_backlog_records_paid_verified_owner_confirmation(self):
        bl031 = self.backlog.split("## BL-031", 1)[1].split("\n## ", 1)[0]
        self.assertIn("paid_verified", bl031)
        self.assertIn("2026-07-29", bl031)
        self.assertIn("security-digest", bl031)
        self.assertIn("Tier 1", bl031)
        self.assertNotRegex(bl031, r"AIza[0-9A-Za-z_-]{20,}")

    def test_bl031_status_recently_completed_records_paid_verified(self):
        recently_completed = self.status.split("## 5. Recently completed work", 1)[1].split(
            "## 6. Known issues and limitations", 1
        )[0]
        bl031 = next(
            line for line in recently_completed.splitlines() if line.startswith("- BL-031 ")
        )
        self.assertIn("paid_verified", bl031)
        self.assertIn("2026-07-29", bl031)
        # The Google Terms 2026-07-30 recheck is now completed (not pending).
        self.assertIn("2026-07-30発効", bl031)
        self.assertIn("limited_feed_analysis", bl031)

    def test_status_as_of_is_2026_08_04_and_bl030_run_evidence_is_historical(self):
        # STATUS.md's "As of" is the document's own last-update date (BL-033
        # delegates volatile latest-publication values to data/index.json
        # instead), so this bumps whenever STATUS.md itself is edited -- most
        # recently to 2026-08-04 by BL-036's post-merge record fix (the
        # STATUS.md content itself was last substantively updated at BL-036's
        # 2026-08-04 final acceptance, but the "As of" field had gone stale at
        # 2026-08-03 until this fix). Separately, BL-030's own scheduled-run
        # evidence below is a fixed 2026-07-30 historical fact, not tied to
        # this "As of" date.
        # BL-038: scoped to the As-of section itself (see
        # document_test_utils.extract_markdown_section) instead of a
        # literal "## 1. As of\n\n2026-08-04" substring, which was brittle
        # to the exact blank-line formatting between the heading and its
        # value. The section body has explanatory prose after the date, so
        # this extracts just the first non-empty line and requires it to
        # equal "2026-08-04" exactly -- not merely start with it -- so a
        # near-miss value like "2026-08-04-old" still fails.
        as_of_section = dtu.extract_markdown_section(self.status, "## 1. As of")
        as_of_value = next(line.strip() for line in as_of_section.splitlines() if line.strip())
        # BL-038 closure (2026-08-14): this PR materially updates STATUS.md, and
        # "As of" is defined by STATUS itself as the document's own last-update
        # date, so the asserted value moves with it. The 2026-08-04 mentions above
        # are historical context (BL-036's post-merge fix) and stay as written; the
        # method name keeps its original date for identity continuity.
        self.assertEqual(
            as_of_value,
            "2026-08-14",
            f"STATUS.md's As of section's value must be exactly 2026-08-14: {as_of_value!r}",
        )
        recently_completed = self.status.split(
            "## 5. Recently completed work", 1
        )[1].split("## 6. Known issues and limitations", 1)[0]
        bl030 = next(
            line for line in recently_completed.splitlines() if line.startswith("- BL-030 ")
        )
        # The scheduled run's outcome is recorded as a confirmed past event
        # (it happened before BL-031 merged), not a future-tense prediction.
        self.assertIn("This actually occurred once, confirmed", bl030)
        self.assertIn("ran, and did so **before**", bl030)
        self.assertIn("pre-BL-031 13-source list", bl030)
        self.assertNotIn("the first ordinary scheduled production run after merge will", bl030)

    def test_5_mode_restructuring_is_consistent_across_requirements_backlog_status(self):
        # SR-044/GAP-016 (SECURITY_REQUIREMENTS.md), the BL-031 entry
        # (BACKLOG.md), and the Active-work summary (STATUS.md) must all
        # reflect the same 5-mode model, not the earlier 4-mode one.
        self.assertIn("limited_feed_analysis", self.requirements)
        sr044_row = next(
            row for row in self._markdown_rows(
                self._section("## 6. Security requirements", "## 7. Current control mapping")
            )
            if row[0] == "SR-044"
        )
        self.assertIn("limited_feed_analysis", " ".join(sr044_row))

        bl031 = self.backlog.split("## BL-031", 1)[1].split("\n## ", 1)[0]
        self.assertIn("limited_feed_analysis", bl031)
        self.assertIn("`structured_open`5", bl031)
        self.assertIn("`feed_summary`4", bl031)
        self.assertIn("`limited_feed_analysis`2", bl031)
        self.assertIn("`metadata_only`2", bl031)
        self.assertIn("`disabled_legal_review`4", bl031)

        recently_completed = self.status.split("## 5. Recently completed work", 1)[1].split(
            "## 6. Known issues and limitations", 1
        )[0]
        bl031_status = next(
            line for line in recently_completed.splitlines() if line.startswith("- BL-031 ")
        )
        self.assertIn("limited_feed_analysis", bl031_status)
        self.assertIn(
            "structured_open 5／feed_summary 4／limited_feed_analysis 2／metadata_only 2／disabled_legal_review 4",
            bl031_status,
        )

    def test_bl031_backlog_no_longer_references_old_4_mode_pending_wording(self):
        bl031 = self.backlog.split("## BL-031", 1)[1].split("\n## ", 1)[0]
        self.assertNotIn("metadata_only 4 source", bl031)
        self.assertNotIn("Google TAG利用規約の2026-07-30改定後の再確認", bl031)

    def test_no_secret_shaped_values_across_bl031_documents(self):
        for name, text in (
            ("SOURCE_USAGE_POLICY.md", self.policy),
            ("SECURITY_REQUIREMENTS.md", self.requirements),
            ("BACKLOG.md", self.backlog),
            ("STATUS.md", self.status),
        ):
            with self.subTest(document=name):
                self.assertNotRegex(text, r"AIza[0-9A-Za-z_-]{20,}")
                self.assertNotRegex(text, r"ghp_[0-9A-Za-z]{20,}")
                self.assertNotIn("/Users/", text)

    def test_sr_046_is_partially_met_not_met(self):
        # nist_nvd is disabled but its activation_condition field is an empty
        # string; SR-046 must not claim it is fully Met while that gap exists.
        self.assertRegex(
            self.requirements,
            r"\| SR-046 \|.*\| Partially met \|",
        )
        self.assertNotRegex(
            self.requirements,
            r"\| SR-046 \|.*\| Met \|",
        )
        sr046_row = next(
            row for row in self._markdown_rows(
                self._section("## 6. Security requirements", "## 7. Current control mapping")
            )
            if row[0] == "SR-046"
        )
        self.assertIn("nist_nvd", " ".join(sr046_row))
        self.assertIn("empty string", " ".join(sr046_row))

    def test_sr_045_is_met_after_gemini_owner_verification(self):
        self.assertRegex(
            self.requirements,
            r"\| SR-045 \|.*\| Met \|",
        )
        sr045_row = next(
            row for row in self._markdown_rows(
                self._section("## 6. Security requirements", "## 7. Current control mapping")
            )
            if row[0] == "SR-045"
        )
        joined = " ".join(sr045_row)
        self.assertIn("paid_verified", joined)
        self.assertIn("2026-07-29", joined)
        self.assertIn("security-digest", joined)
        self.assertIn("Tier 1", joined)
        self.assertIn("GAP-017", joined)
        self.assertNotIn("Unverified outside repository", joined)

    def test_gap_017_is_completed_owner_verification_with_no_secrets(self):
        self.assertRegex(
            self.requirements,
            r"\| GAP-017 \| Owner verification \| Completed owner verification \|",
        )
        gaps = self._section(
            "## 8. Gap register",
            "## 9. Explicitly non-required controls for the current architecture",
        )
        gap017_row = next(
            row for row in self._markdown_rows(gaps) if row[0] == "GAP-017"
        )
        joined = " ".join(gap017_row)
        self.assertIn("2026-07-29", joined)
        self.assertIn("security-digest", joined)
        self.assertIn("active Cloud Billing", joined)
        self.assertIn("Tier 1", joined)
        self.assertNotIn("AIza", joined)
        self.assertNotIn("Deferred until trigger", joined)

    def test_section_13_gemini_row_is_verified_paid_verified(self):
        section13 = self.requirements.split("## 13. Repository-owner verification", 1)[1]
        gemini_row = next(
            line for line in section13.splitlines() if "gemini_data_use_status" in line
        )
        self.assertIn("Verified — `paid_verified`", gemini_row)
        self.assertIn("2026-07-29", gemini_row)
        self.assertNotIn("Unverified — owner access required", gemini_row)

    def test_control_mapping_reflects_sr046_partial_state_and_sr045_owner_verified(self):
        # SR-046 stays Partially met (nist_nvd's empty activation_condition);
        # SR-045 became Met once the Gemini owner verification completed
        # (GAP-017); SR-044 became Met once BL-032's Draft implementation
        # enforced per-source content usage modes at runtime (pending user
        # acceptance), so the tally is 2 Met / 1 Partial / 0 Unverified.
        mapping = self._section(
            "## 7. Current control mapping", "## 8. Gap register"
        )
        self.assertIn(
            "Source content-usage policy and AI provider data-use boundary", mapping
        )
        self.assertIn("Met 2 / Partial 1 / Not met 0 / Unverified 0", mapping)
        self.assertNotIn("Met 0 / Partial 2 / Not met 0 / Unverified 1", mapping)
        self.assertNotIn("Met 1 / Partial 2 / Not met 0 / Unverified 0", mapping)

    def test_sr_045_no_longer_describes_google_terms_recheck_as_pending(self):
        sr045_row = next(
            row for row in self._markdown_rows(
                self._section("## 6. Security requirements", "## 7. Current control mapping")
            )
            if row[0] == "SR-045"
        )
        joined = " ".join(sr045_row)
        self.assertNotIn("pending 2026-07-30 Google Terms", joined)
        self.assertIn("confirmed effective 2026-07-30", joined)

    def test_trust_boundary_audit_date_follows_per_row_checked_at(self):
        boundaries = self._section("## 5. Trust boundaries", "## 6. Security requirements")
        compact = re.sub(r"\s+", " ", boundaries)
        self.assertIn("recorded per source", compact)
        self.assertIn("row-level `checked_at` column", compact)
        self.assertIn("2026-07-30 for `google_tag`/`mandiant`", compact)
        self.assertNotIn("point-in-time audit (2026-07-29)", compact)
        self.assertNotIn("the 2026-07-30 Google Terms re-confirmation", compact)
        self.assertIn(
            "any future Google Terms revision beyond the 2026-07-30 version already reviewed",
            compact,
        )

    def test_intro_clarifies_version_15_is_the_current_approved_baseline(self):
        # BL-034 round 2 acceptance update (2026-08-03): Version 1.7 (BL-034)
        # is now the most recent Approved baseline, superseding Version 1.5
        # in that role. Version 1.6 was a past Draft layer, never itself
        # promoted to Approved even though BL-032's own implementation was
        # later user-accepted and merged; its current-state material is now
        # carried forward and approved as part of Version 1.7.
        # BL-038 tranche 2: the section itself is still extracted via this
        # class's own local _section(start, end) (kept as-is -- migrating to
        # document_test_utils.extract_markdown_section was investigated and
        # rejected: that helper stops an H1 section only at the next H1,
        # and this document has exactly one H1, so it would return
        # essentially the whole rest of the document instead of just this
        # intro paragraph before "## 1. Purpose and proportionality"). The
        # brittle part was never the extraction -- it was locking the exact
        # mid-sentence line-wrap of several explanatory sentences; those are
        # now compared via normalize_markdown_prose so only wording (not an
        # incidental wrap column) is the contract.
        intro = self._section(
            "# Monomi Digest Security Requirements", "## 1. Purpose and proportionality"
        )
        normalized_intro = dtu.normalize_markdown_prose(intro)
        self.assertIn("Version 1.7 is now the most recent **Approved**", intro)
        self.assertIn(
            dtu.normalize_markdown_prose("Version 1.5 was the previous Approved baseline"),
            normalized_intro,
            "SECURITY_REQUIREMENTS.md intro must state Version 1.5 was the "
            "previous Approved baseline (Version history contract)",
        )
        self.assertIn(
            dtu.normalize_markdown_prose(
                "Version 1.6 was a **Draft** maintenance update layered on top of "
                "that Approved Version 1.5"
            ),
            normalized_intro,
            "SECURITY_REQUIREMENTS.md intro must describe Version 1.6 as a "
            "Draft maintenance update layered on Version 1.5 (Version history contract)",
        )
        self.assertIn("Version 1.6 was never itself independently promoted to Approved status", intro)
        self.assertIn(
            dtu.normalize_markdown_prose(
                "Version 1.7 (this Version) is a further maintenance update layered on top of Version 1.6"
            ),
            normalized_intro,
            "SECURITY_REQUIREMENTS.md intro must describe Version 1.7 (this "
            "Version) as a further maintenance update layered on Version 1.6 "
            "(Version history contract)",
        )
        self.assertIn("it is Approved, per the acceptance recorded in section 12", intro)
        self.assertIn(
            "SD-030](DECISIONS.md#sd-030--approve-source-usage-policy-version-01-and-defer-runtime-enforcement-to-bl-032)",
            intro,
        )
        self.assertNotIn("only Version 1.4 is approved", intro)
        self.assertNotIn(
            dtu.normalize_markdown_prose("Version 1.6 (this Version)"),
            normalized_intro,
            "SECURITY_REQUIREMENTS.md intro must not refer to Version 1.6 as "
            "'this Version' -- Version 1.7 is the current self-reference "
            "(Version history contract)",
        )
        self.assertNotIn("only Version 1.5 is approved policy", intro)

    def test_bl_and_sd_ids_referenced_are_unique_in_their_documents(self):
        bl_headings = re.findall(r"^## (BL-\d{3})\b", self.backlog, flags=re.MULTILINE)
        self.assertEqual(len(bl_headings), len(set(bl_headings)))
        sd_headings = re.findall(r"^## (SD-\d{3})\b", self.decisions, flags=re.MULTILINE)
        self.assertEqual(len(sd_headings), len(set(sd_headings)))
        self.assertIn("SD-030", sd_headings)

    def test_section_11_google_terms_roadmap_item_is_a_completed_record_not_future_tense(self):
        # The 2026-07-30 Google Terms recheck already happened; section 11's
        # roadmap item must record it as completed, not as a future action
        # gated on the terms "taking effect" on that date.
        roadmap = self._section(
            "## 11. Approved roadmap decisions", "## 12. Approval and maintenance"
        )
        compact = re.sub(r"\s+", " ", roadmap)
        self.assertNotIn("after the new terms take effect on 2026-07-30", compact)
        self.assertNotIn("re-confirm Google's Terms for", compact)
        self.assertIn(
            "completed 2026-07-30: re-confirmed the Google Terms version that took effect"
            " that day",
            compact,
        )
        self.assertIn("`google_tag`", compact)
        self.assertIn("`mandiant`", compact)
        self.assertIn("classification and confidence", compact)
        self.assertIn("were unchanged", compact)
        self.assertIn("Further re-confirmation is required only on a subsequent Google Terms",
                       compact)
        self.assertIn("revision, or on the source-specific recheck triggers recorded in", compact)
        self.assertIn("[SOURCE_USAGE_POLICY.md](SOURCE_USAGE_POLICY.md)", compact)


class Bl031AcceptanceAndBl032RegistrationTest(unittest.TestCase):
    """Historical point-in-time checks anchored to the 2026-07-31 BL-031
    acceptance round: BL-031's acceptance/merge is recorded as Completed, SD-030
    records the approval/enforcement-deferral boundary without marking SD-002 as
    already superseded, and per-source `checked_at` values were not bulk-changed
    by this approval round. At that time, all three security documents were
    Approved and BL-032 was registered exactly once and not yet started; these
    were true THEN, not necessarily now -- SECURITY_REQUIREMENTS.md has since
    moved to Version 1.7 (checked directly below) and SECURITY_OPERATIONS.md has
    since moved to Version 1.2 Draft under BL-035 (checked in
    test_security_operations.Bl035DraftSyncTest), and BL-032 itself has since
    been implemented and merged (checked throughout this file and in
    test_source_definitions.py). Do not read this class's test names as
    describing the documents' current state.
    """

    @classmethod
    def setUpClass(cls):
        cls.requirements = REQUIREMENTS_PATH.read_text(encoding="utf-8")
        cls.operations = (ROOT / "SECURITY_OPERATIONS.md").read_text(encoding="utf-8")
        cls.backlog = (ROOT / "BACKLOG.md").read_text(encoding="utf-8")
        cls.status = (ROOT / "STATUS.md").read_text(encoding="utf-8")
        cls.decisions = (ROOT / "DECISIONS.md").read_text(encoding="utf-8")
        cls.policy = (ROOT / "SOURCE_USAGE_POLICY.md").read_text(encoding="utf-8")
        cls.source_definitions = (ROOT / "source_definitions.json").read_text(encoding="utf-8")
        cls.fetch_source = (ROOT / "fetch.py").read_text(encoding="utf-8")

    def test_source_usage_policy_20260731_snapshot_and_security_requirements_current_version(self):
        # SOURCE_USAGE_POLICY.md remains Approved as of the 2026-07-31 BL-031
        # round and is unchanged since -- a historical snapshot, checked here.
        # SECURITY_REQUIREMENTS.md has since moved further: Draft Version 1.6
        # (BL-032 implementation, pending user acceptance at the time) was
        # superseded by Version 1.7 (BL-034 implementation), which the user
        # accepted on 2026-08-03 (PR #72 round 2) -- its CURRENT version, checked
        # below. SECURITY_OPERATIONS.md's history is not checked in this method:
        # it moved further still under BL-035 (Fable 5 review R-02) from the
        # 2026-07-31 Version 1.1 Approved snapshot to Version 1.2 Draft; see
        # test_version_11_approval_record_is_preserved_as_history (history) and
        # test_security_operations.Bl035DraftSyncTest (current state).
        for doc, version_marker in (
            (self.policy, "**Version:** 0.1"),
        ):
            with self.subTest(version_marker=version_marker):
                self.assertIn(version_marker, doc)
                self.assertIn("**Status:** Approved", doc)
                self.assertIn("**As of:** 2026-07-31", doc)
        self.assertIn("**Version:** 1.7", self.requirements)
        self.assertIn("**Status:** Approved", self.requirements)
        self.assertIn("**As of:** 2026-08-03", self.requirements)

    def test_bl031_backlog_status_is_completed(self):
        bl031 = self.backlog.split("## BL-031", 1)[1].split("\n## ", 1)[0]
        self.assertIn("- **状態:** 完了", bl031)
        self.assertNotIn("監査・文書Draft PR／レビュー待ち", bl031)
        self.assertNotIn("未受入", bl031)
        self.assertNotIn("まだCompletedではない", bl031)

    def test_bl031_backlog_acceptance_evidence_is_recorded(self):
        bl031 = self.backlog.split("## BL-031", 1)[1].split("\n## ", 1)[0]
        acceptance = bl031.split("**ユーザー受入証跡:**", 1)[1].split("\n- **残作業:**", 1)[0]
        self.assertIn("PR #67", acceptance)
        self.assertIn("897fc9db365e890318fc694a7fbf9cd8eab65ae1", acceptance)
        self.assertIn("61feb679fad6bd2252c58cd8acb4696294032629", acceptance)
        self.assertIn("30557479373", acceptance)
        self.assertIn("1391 tests", acceptance)
        self.assertIn("ok進もう", acceptance)

    def test_bl032_is_registered_exactly_once(self):
        # BL-032's status has since moved on from 要件定義済み／未着手 to
        # 実装Draft PR／レビュー待ち (feature/bl032-content-usage-enforcement);
        # this test only locks uniqueness/title, not the now-stale status text.
        bl032_headings = re.findall(r"^## (BL-032)\b", self.backlog, flags=re.MULTILINE)
        self.assertEqual(len(bl032_headings), 1)
        bl032 = self.backlog.split("## BL-032", 1)[1].split("\n## ", 1)[0]
        self.assertIn("取得元別content usage policy enforcement", bl032)

    def test_sd030_is_unique_and_records_approval_deferral_boundary(self):
        sd_headings = re.findall(r"^## (SD-030)\b", self.decisions, flags=re.MULTILINE)
        self.assertEqual(len(sd_headings), 1)
        sd030 = self.decisions.split("## SD-030", 1)[1].split("\n## ", 1)[0]
        self.assertIn("Policy approved; runtime enforcement deferred", sd030)
        self.assertIn("BL-032](BACKLOG.md#bl-032--取得元別content-usage-policy-enforcement)", sd030)
        self.assertIn("this decision itself does not implement any enforcement", sd030)

    def test_sd030_does_not_mark_sd002_as_implemented_superseded(self):
        sd030 = self.decisions.split("## SD-030", 1)[1].split("\n## ", 1)[0]
        supersedes = sd030.split("- **Supersedes:**", 1)[1]
        self.assertNotIn("SD-002", supersedes)
        sd002 = self.decisions.split("## SD-002", 1)[1].split("\n## ", 1)[0]
        self.assertIn("- **Status:** Accepted / Implemented", sd002)

    def test_source_usage_policy_checked_at_dates_are_not_bulk_changed(self):
        checked_at_values = set(re.findall(r"\| (2026-07-\d\d) \|", self.policy))
        self.assertTrue(checked_at_values)
        self.assertNotIn("2026-07-31", checked_at_values)
        self.assertEqual(checked_at_values, {"2026-07-29", "2026-07-30"})

    def test_bl032_residual_work_records_operational_observation_as_succeeded(self):
        # BL-033: BL-032's own 残作業 (residual-work) line must reflect that
        # its post-merge operational observation has already succeeded, not
        # describe it in future tense as still-pending work. Scoped to the
        # residual-work line itself, not a blanket ban across all of
        # BACKLOG.md -- other tickets may legitimately describe their own
        # upcoming scheduled-run confirmations in future tense.
        bl032 = self.backlog.split("## BL-032", 1)[1].split("\n## ", 1)[0]
        residual = next(
            line for line in bl032.splitlines() if line.startswith("- **残作業:**")
        )
        self.assertIn("BL-032の完了条件としての残作業はない", residual)
        self.assertIn("982a261b15afd695486fffe50fadf9209cc0faa5", residual)
        self.assertIn("成功済み", residual)
        self.assertNotIn(
            "次回scheduled production runでschema v2 enforcementが実際に稼働することの実挙動確認",
            residual,
        )
        self.assertIn("この確認はBL-032を再オープンするものではなく", residual)
        self.assertIn("別Ticketで扱う", residual)
        self.assertIn("BL-009", residual)
        self.assertIn("別Ticket", residual)

    def test_bl032_completion_condition_6_requires_changing_rich_content_not_preserving_it(self):
        # Condition 6 must not simultaneously require "no rich content for any
        # of the 17 sources" and "the current common rich-content processing
        # is unchanged by this ticket" -- those two claims contradict each
        # other, since the current common processing is what applies rich
        # content in the first place (SD-002). BL-032 must change or disable
        # that common processing; the concrete mechanism is decided in the
        # BL-032 implementation PR, not here.
        bl032 = self.backlog.split("## BL-032", 1)[1].split("\n## ", 1)[0]
        self.assertIn("全17 sourceについてrich contentがGemini入力・保存・公開のいずれにも使用されない", bl032)
        self.assertNotIn("現行の共通rich content処理自体は本Ticketで変更しない", bl032)
        self.assertIn("現行の共通rich-content利用", bl032)
        self.assertTrue(
            "変更または無効化" in bl032 or "変更・無効化" in bl032,
            "BL-032 entry must record that BL-032 changes or disables the "
            "current common rich-content usage, not merely leaves it as-is.",
        )
        self.assertIn(
            "具体的な実装方式", bl032, "the concrete implementation approach must be deferred"
        )
        self.assertIn("BL-032の実装PRでコードとテストとともに決定する", bl032)

    def test_sd030_records_that_mode_restrictions_are_not_yet_enforced_in_production(self):
        sd030 = self.decisions.split("## SD-030", 1)[1].split("\n## ", 1)[0]
        self.assertIn("because BL-032 is not yet implemented", sd030)
        self.assertIn("none of these mode-specific restrictions are enforced in current production", sd030)
        self.assertIn("as recorded in GAP-016", sd030)
        self.assertIn(
            "an enabled `metadata_only` or `limited_feed_analysis` source is currently "
            "processed through the same common pipeline as a `structured_open` source",
            sd030,
        )

    def test_sd030_describes_metadata_only_and_limited_feed_analysis_as_policy_requirements(self):
        sd030 = self.decisions.split("## SD-030", 1)[1].split("\n## ", 1)[0]
        consequences = sd030.split("- **Consequences:**", 1)[1].split("\n- **Evidence:**", 1)[0]
        self.assertIn("under the now-Approved policy, `metadata_only`", consequences)
        self.assertIn(
            "`limited_feed_analysis` (`the_hacker_news`, `krebs_on_security`) requires",
            consequences,
        )
        self.assertNotIn("continue to have only minimal metadata", consequences)
        self.assertNotIn("are approved to continue on bounded RSS description input only", consequences)

    def test_sd002_remains_accepted_implemented_and_not_marked_superseded_by_sd030(self):
        sd002 = self.decisions.split("## SD-002", 1)[1].split("\n## ", 1)[0]
        self.assertIn("- **Status:** Accepted / Implemented", sd002)
        sd030 = self.decisions.split("## SD-030", 1)[1].split("\n## ", 1)[0]
        supersedes = sd030.split("- **Supersedes:**", 1)[1]
        self.assertNotIn("SD-002", supersedes)

    def test_status_bl030_entry_no_longer_lists_bl031_as_a_follow_up_candidate(self):
        recently_completed = self.status.split("## 5. Recently completed work", 1)[1].split(
            "## 6. Known issues and limitations", 1
        )[0]
        bl030 = next(
            line for line in recently_completed.splitlines() if line.startswith("- BL-030 ")
        )
        self.assertNotIn("follow-up candidates BL-031", bl030)
        self.assertIn("BL-031", bl030)
        self.assertIn("completed, approved, and merged", bl030)
        # BL-032 merged during its own post-merge closeout, so this line no
        # longer describes it with the specific old phrase below. This checks
        # that exact old phrase, not the words "registered"/"Active work
        # item" in general, which a future unrelated ticket may legitimately
        # use elsewhere in this same BL-030 line.
        self.assertIn("BL-032", bl030)
        self.assertNotIn(
            "is registered and is the current Active work item, 要件定義済み／未着手",
            bl030,
        )
        self.assertIn("are both completed, approved, and merged", bl030)
        self.assertIn("BL-009", bl030)
        self.assertIn("separate, unstarted ticket", bl030)
        self.assertIn("None of these is BL-030 residual work", bl030)
        # The 2026-07-30 past-tense 13-source-footer fact must still be intact.
        self.assertIn("pre-BL-031 13-source list", bl030)
        self.assertIn("This actually occurred once, confirmed", bl030)


class Bl034Round1ReviewCorrectionsTest(unittest.TestCase):
    """BL-034 PR #72 round 1 independent review: locks the 7 corrections in
    place so a later edit cannot silently reintroduce the misstatements
    (footer destination confusion, BL-009/BL-034 state mismatch, merge-order
    conflation, an unconfirmed Search Console claim, GAP-018 misclassified as
    a security gap, and BL-032's current state shown as still-Draft).
    """

    @classmethod
    def setUpClass(cls):
        root = Path(__file__).resolve().parent
        cls.requirements = (root / "SECURITY_REQUIREMENTS.md").read_text(encoding="utf-8")
        cls.backlog = (root / "BACKLOG.md").read_text(encoding="utf-8")
        cls.status = (root / "STATUS.md").read_text(encoding="utf-8")

    @staticmethod
    def _section(text, start, end=None):
        after = text.split(start, 1)[1]
        return after.split(end, 1)[0] if end else after

    def test_bl009_is_an_in_progress_umbrella_not_completed(self):
        bl009 = self._section(self.backlog, "## BL-009", "\n## BL-010")
        self.assertIn("進行中（BL-034で閲覧計測基盤を先行）", bl009)
        self.assertNotIn("- **状態:** 完了", bl009)

    def test_bl034_is_complete_with_the_accepted_implementation_head_recorded(self):
        # Round 1/2 of independent review accepted the repository
        # implementation but left BL-034 not yet `完了`; BL-034 closeout
        # (2026-08-03) then confirmed Cloudflare dashboard data and Search
        # Console verification and moved BL-034 to `完了` -- see
        # Bl034CloseoutTest for the full closeout-fact assertions.
        bl034 = self._section(self.backlog, "## BL-034", "\n## 完了済み参照")
        self.assertIn("- **状態:** 完了", bl034)
        self.assertIn("6d032e702e1b118bc6da86b981a4189b4a85e15b", bl034)

    def test_dashboard_and_search_console_confirmation_are_post_merge_only(self):
        # The 完了条件 list's merge-before/merge-after sequencing contract
        # (round 1) remains a valid historical definition of what had to
        # happen; both have since happened (see Bl034CloseoutTest).
        bl034 = self._section(self.backlog, "## BL-034", "\n## 完了済み参照")
        self.assertIn("**merge後:**", bl034)
        self.assertIn("Cloudflare dashboardでの実データ受信確認", bl034)

    def test_gap_018_is_a_policy_decision_not_a_security_gap(self):
        gaps = self._section(
            self.requirements,
            "## 8. Gap register",
            "## 9. Explicitly non-required controls for the current architecture",
        )
        self.assertRegex(gaps, r"\| GAP-018 \| Policy decision \|")
        self.assertNotRegex(gaps, r"\| GAP-018 \| Security gap \|")

    def test_bl032_runtime_implementation_is_accepted_and_merged_not_draft(self):
        gaps = self._section(
            self.requirements,
            "## 8. Gap register",
            "## 9. Explicitly non-required controls for the current architecture",
        )
        self.assertIn("GAP-016", gaps)
        self.assertRegex(gaps, r"\| GAP-016 \| Security gap \| Implemented \|")
        gap016_row = next(
            line for line in gaps.splitlines() if line.startswith("| GAP-016 |")
        )
        self.assertIn("user-accepted and merged", gap016_row)
        self.assertNotIn("Draft, pending user acceptance", gap016_row)
        self.assertNotIn("not yet user-accepted", gap016_row)

    def test_requirements_document_itself_is_version_17_draft(self):
        # BL-034 round 2 acceptance update (2026-08-03): Version 1.7 was
        # Draft when this check was first written; the user has since
        # accepted BL-034's implementation, making Version 1.7 Approved.
        self.assertIn("**Version:** 1.7", self.requirements)
        self.assertIn("**Status:** Approved", self.requirements)

    def test_footer_and_beacon_destinations_are_distinguished_everywhere(self):
        # No sentence anywhere in the document should claim
        # static.cloudflareinsights.com is the only external destination —
        # the beacon separately POSTs measurement data to cloudflareinsights.com.
        # BL-038 tranche 2: kept document-global (per rule 7.4's exception for
        # a phrase that must not appear ANYWHERE, not just in one section),
        # but compared after normalize_markdown_prose so this no longer
        # depends on the exact line-wrap position of the stale phrase.
        stale = dtu.normalize_markdown_prose(
            "first external network destination (`static.cloudflareinsights.com`)"
        )
        normalized_requirements = dtu.normalize_markdown_prose(self.requirements)
        self.assertFalse(
            stale in normalized_requirements,
            "SECURITY_REQUIREMENTS.md must not globally describe "
            "static.cloudflareinsights.com as the first external network "
            "destination (document-global destination contract)",
        )
        self.assertIn("cloudflareinsights.com/cdn-cgi/rum", self.requirements)


class Bl034Round2ReviewCorrectionsTest(unittest.TestCase):
    """BL-034 PR #72 round 2 independent review: locks the 3 remaining
    document-consistency corrections in place (SECURITY_REQUIREMENTS.md's
    stale "Version 1.6 (this Version)" self-reference and leftover BL-032
    "still Draft"/"deferred"/"registered" current-state phrasing in
    SR-045/SR-046/GAP-017, and SD-032's Visits description in DECISIONS.md).
    Historical Version 1.6-era narrative text is intentionally left alone
    and must not be blanket-forbidden by these checks.
    """

    @classmethod
    def setUpClass(cls):
        root = Path(__file__).resolve().parent
        cls.requirements = (root / "SECURITY_REQUIREMENTS.md").read_text(encoding="utf-8")
        cls.decisions = (root / "DECISIONS.md").read_text(encoding="utf-8")

    @staticmethod
    def _section(text, start, end=None):
        after = text.split(start, 1)[1]
        return after.split(end, 1)[0] if end else after

    def _row(self, requirement_id):
        return next(
            line for line in self.requirements.splitlines()
            if line.startswith(f"| {requirement_id} |")
        )

    def test_version_17_is_the_current_draft_and_16_is_not_called_this_version(self):
        # BL-038 tranche 2: this "(this Version)" self-reference tag is a
        # single, specific phrase pattern that (per this class's own
        # docstring) is intentionally checked without blanket-forbidding
        # ordinary historical mentions of "Version 1.6" elsewhere in the
        # document -- scoping to the intro section (where this
        # self-reference tag actually lives; verified it does not appear
        # anywhere else) makes that intent explicit rather than relying on
        # the exact phrase "Version 1.6\n(this Version)" never accidentally
        # matching prose elsewhere. normalize_markdown_prose removes the
        # dependency on this phrase's exact line-wrap position.
        intro = self._section(
            self.requirements,
            "# Monomi Digest Security Requirements", "## 1. Purpose and proportionality",
        )
        normalized_intro = dtu.normalize_markdown_prose(intro)
        self.assertIn("**Version:** 1.7", self.requirements)
        self.assertNotIn(
            dtu.normalize_markdown_prose("Version 1.6 (this Version)"),
            normalized_intro,
            "SECURITY_REQUIREMENTS.md intro must not self-reference Version "
            "1.6 as 'this Version' (Version 1.7 current-self-reference contract)",
        )
        self.assertIn(
            dtu.normalize_markdown_prose("Version 1.7 (this Version)"),
            normalized_intro,
            "SECURITY_REQUIREMENTS.md intro must self-reference Version 1.7 "
            "as 'this Version' (Version 1.7 current-self-reference contract)",
        )

    def test_version_17_intro_does_not_deny_the_sr044_046_gap016_017_sync(self):
        intro = self._section(
            self.requirements,
            "# Monomi Digest Security Requirements", "## 1. Purpose and proportionality"
        )
        self.assertNotIn(
            dtu.normalize_markdown_prose("it does not change SR-001–SR-046, GAP-001–GAP-017"),
            dtu.normalize_markdown_prose(intro),
            "SECURITY_REQUIREMENTS.md intro must not deny the SR-044-046/"
            "GAP-016-017 sync (intro SR/GAP stale-denial contract)",
        )
        self.assertIn("synchronizes SR-044–SR-046", intro)
        self.assertIn("GAP-016–GAP-017", intro)
        self.assertIn("user-accepted and merged", intro)

    def test_sr045_no_longer_says_enforcement_remains_deferred_to_bl032(self):
        row = self._row("SR-045")
        self.assertNotIn("remains deferred to BL-032", row)
        self.assertIn("implemented, user-accepted, and merged", row)

    def test_sr046_trigger_no_longer_lists_completed_bl032(self):
        row = self._row("SR-046")
        trigger = row.rsplit("|", 2)[1].strip()
        self.assertNotIn("BL-032", trigger)
        self.assertIn("nist_nvd", trigger)

    def test_gap017_does_not_call_bl032_merely_registered(self):
        row = self._row("GAP-017")
        self.assertNotIn("BL-032](BACKLOG.md#bl-032--取得元別content-usage-policy-enforcement) (registered)", row)
        self.assertIn("user-accepted and merged", row)
        self.assertIn("PR #69", row)

    def test_sd032_visits_description_has_no_session_language(self):
        sd032 = self._section(self.decisions, "## SD-032", "\n## ")
        self.assertNotIn("session-style", sd032)
        self.assertNotIn("session count", sd032)
        self.assertNotIn("unique visitors", sd032)
        self.assertIn("external referrer or direct link", sd032)
        self.assertIn("one Visit may include multiple page views", sd032)
        self.assertIn("not a deduplicated unique-person count", sd032)


class Bl034ImplementationAcceptanceTest(unittest.TestCase):
    """BL-034 implementation acceptance (2026-08-03, PR #72 round 2 clean):
    the user accepted the repository implementation, approved SD-032 and
    SECURITY_REQUIREMENTS.md Version 1.7, and authorized Ready-for-review
    plus a regular merge-commit merge. Cloudflare Web Analytics dashboard
    data receipt and Google Search Console verification were unconfirmed
    at that moment; BL-034 closeout (same day) has since confirmed both
    and moved BL-034 to `完了` -- see Bl034CloseoutTest for the current
    record. These tests check the acceptance-round evidence that still
    appears verbatim in BACKLOG.md/DECISIONS.md/SECURITY_REQUIREMENTS.md.
    """

    ACCEPTED_HEAD = "6d032e702e1b118bc6da86b981a4189b4a85e15b"

    @classmethod
    def setUpClass(cls):
        root = Path(__file__).resolve().parent
        cls.requirements = (root / "SECURITY_REQUIREMENTS.md").read_text(encoding="utf-8")
        cls.backlog = (root / "BACKLOG.md").read_text(encoding="utf-8")
        cls.status = (root / "STATUS.md").read_text(encoding="utf-8")
        cls.decisions = (root / "DECISIONS.md").read_text(encoding="utf-8")

    @staticmethod
    def _section(text, start, end=None):
        after = text.split(start, 1)[1]
        return after.split(end, 1)[0] if end else after

    def test_bl034_is_complete_with_acceptance_round_evidence_preserved(self):
        # The implementation-acceptance round recorded here (accepted head,
        # test/CI evidence) was later followed by BL-034 closeout
        # (2026-08-03, same day): operational confirmation of the Cloudflare
        # dashboard and Search Console, moving BL-034 to `完了`; see
        # Bl034CloseoutTest for the closeout-specific assertions.
        bl034 = self._section(self.backlog, "## BL-034", "\n## 完了済み参照")
        self.assertIn("- **状態:** 完了", bl034)
        self.assertIn(self.ACCEPTED_HEAD, bl034)
        self.assertIn("1577 tests OK", bl034)
        self.assertIn("30765873879", bl034)
        self.assertIn("changed files 35件", bl034)
        self.assertIn("unresolved review threads 0", bl034)

    def test_bl034_has_no_residual_work_after_closeout(self):
        # The 完了条件 list (a historical contract definition, round 1) still
        # names Cloudflare dashboard/Search Console confirmation as
        # merge-after items; BL-034 closeout has since completed both, so
        # 残作業 itself now reads なし.
        bl034 = self._section(self.backlog, "## BL-034", "\n## 完了済み参照")
        self.assertIn("Cloudflare dashboardでの実データ受信確認", bl034)
        self.assertIn("Google Search Console verification結果の確認", bl034)
        self.assertIn("GitHub Pagesへの公開反映を確認", bl034)
        residual = self._section(bl034, "- **残作業:**")
        self.assertIn("なし", residual)

    def test_bl009_remains_the_in_progress_umbrella(self):
        bl009 = self._section(self.backlog, "## BL-009", "\n## BL-010")
        self.assertIn("進行中（BL-034で閲覧計測基盤を先行）", bl009)
        self.assertNotIn("- **状態:** 完了", bl009)

    def test_sd032_is_accepted(self):
        sd032 = self._section(self.decisions, "## SD-032", "\n## ")
        self.assertIn("- **Status:** Accepted", sd032)
        self.assertNotIn("implementation Draft, pending user acceptance", sd032)
        self.assertIn(self.ACCEPTED_HEAD, sd032)
        self.assertIn("PR #72", sd032)

    def test_security_requirements_version_17_is_approved_and_current_baseline(self):
        self.assertIn("**Version:** 1.7", self.requirements)
        self.assertIn("**Status:** Approved", self.requirements)
        self.assertIn("Version 1.7 is now the most recent **Approved**", self.requirements)

    def test_version_16_historical_draft_record_is_preserved(self):
        # The Version-1.6-era historical narrative (what BL-032's Draft
        # implementation recorded at the time) must survive this round's
        # edits verbatim -- this round approves Version 1.7, it does not
        # retroactively rewrite Version 1.6's own history.
        self.assertIn(
            "Version 1.6 is a Draft maintenance update. It records the BL-032 implementation (Draft, pending\n"
            "user acceptance, branch `feature/bl032-content-usage-enforcement`)",
            self.requirements,
        )
        self.assertIn(
            "Version 1.6 additionally records this new roadmap item from BL-032 (Draft, not yet approved):",
            self.requirements,
        )

    def test_sr047_is_met_and_gap018_is_policy_decision_implemented(self):
        # Row shape: | ID | Requirement | Rationale | Current state | Evidence | Gap/exception | Trigger |
        sr047 = next(
            line for line in self.requirements.splitlines() if line.startswith("| SR-047 |")
        )
        cells = [c.strip() for c in sr047.strip("|").split("|")]
        self.assertEqual(cells[3], "Met")
        # Row shape: | Gap ID | Classification | Current disposition | Related requirement | ...
        gap018 = next(
            line for line in self.requirements.splitlines() if line.startswith("| GAP-018 |")
        )
        gap_cells = [c.strip() for c in gap018.strip("|").split("|")]
        self.assertEqual(gap_cells[1], "Policy decision")
        self.assertEqual(gap_cells[2], "Implemented")

    def test_dashboard_and_search_console_are_confirmed_by_closeout(self):
        # SECURITY_REQUIREMENTS.md was later brought into BL-034 closeout's
        # scope (PR #73 round 1): GAP-018 no longer says dashboard/Search
        # Console are unconfirmed -- both are now recorded as confirmed.
        gap018 = next(
            line for line in self.requirements.splitlines() if line.startswith("| GAP-018 |")
        )
        self.assertNotIn("remain unconfirmed", gap018)
        self.assertIn("BL-034 is complete", gap018)
        self.assertIn("Cloudflare Web Analytics dashboard is receiving data", gap018)
        self.assertIn("Google Search Console Domain-property ownership verification succeeded", gap018)
        self.assertIn("TXT value is not stored in this repository", gap018)

    def test_acceptance_commit_touches_no_runtime_html_data_or_workflow_files(self):
        # This is a documentation assertion, not a git check (see the round's
        # `git status`/`git diff` verification instead) -- it records the
        # expectation in a way a future edit to this round's scope can be
        # checked against: fetch.py/docs/data/workflows must not be
        # mentioned as changed by this specific acceptance round.
        bl034 = self._section(self.backlog, "## BL-034", "\n## 完了済み参照")
        acceptance = self._section(bl034, "- **ユーザー受入証跡:**", "\n- **残作業:**")
        self.assertNotIn("fetch.py", acceptance)
        self.assertNotIn("docs/", acceptance)


class Bl034CloseoutTest(unittest.TestCase):
    """BL-034 closeout (2026-08-03): after the user confirmed Cloudflare Web
    Analytics dashboard data receipt and Google Search Console Domain
    property ownership verification, BL-034 moved from `実装受入済み／
    公開後確認待ち` to `完了`. Locks the closeout facts in place and
    confirms neither the Google verification TXT value nor
    SECURITY_REQUIREMENTS.md's Approved Version 1.7 status is disturbed.

    PR #73 round 1 additionally brought SECURITY_REQUIREMENTS.md's own
    current-state text (intro, SR-047, GAP-018, section 12) into scope, so
    this class also locks: those sections now say dashboard/Search Console
    are confirmed (not "remain unconfirmed"/"none of those have occurred"),
    while still preserving the historical, past-tense record of what was
    true at the moment Version 1.7's repository implementation was
    accepted (before the closeout confirmations happened).
    """

    MERGE_COMMIT = "8cd98e52bfe6164bffa8e10cdbf708eef76d43a1"

    @classmethod
    def setUpClass(cls):
        root = Path(__file__).resolve().parent
        cls.requirements = (root / "SECURITY_REQUIREMENTS.md").read_text(encoding="utf-8")
        cls.backlog = (root / "BACKLOG.md").read_text(encoding="utf-8")
        cls.status = (root / "STATUS.md").read_text(encoding="utf-8")
        cls.decisions = (root / "DECISIONS.md").read_text(encoding="utf-8")

    @staticmethod
    def _section(text, start, end=None):
        after = text.split(start, 1)[1]
        return after.split(end, 1)[0] if end else after

    def test_bl034_is_complete_with_no_residual_work(self):
        bl034 = self._section(self.backlog, "## BL-034", "\n## 完了済み参照")
        self.assertIn("- **状態:** 完了", bl034)
        residual = self._section(bl034, "- **残作業:**", "\n- **注記:**")
        self.assertIn("なし", residual)
        self.assertNotIn("公開後確認のみ", residual)

    def test_cloudflare_dashboard_and_search_console_are_confirmed(self):
        bl034 = self._section(self.backlog, "## BL-034", "\n## 完了済み参照")
        self.assertIn("Cloudflare Web Analytics dashboardで実データ受信を確認した", bl034)
        self.assertIn("Visits 3", bl034)
        self.assertIn("Page views 3", bl034)
        self.assertIn("217ms", bl034)
        self.assertIn("初期観測値であり、現在値や恒久的な基準値ではない", bl034)
        self.assertIn("Visitsはunique人数を意味しない", bl034)
        self.assertIn("Google Search Consoleで", bl034)
        self.assertIn("所有権確認成功", bl034)
        self.assertIn("monomidigest.com", bl034)

    def test_measurement_start_date_is_20260803(self):
        bl034 = self._section(self.backlog, "## BL-034", "\n## 完了済み参照")
        self.assertIn("計測開始日: `2026-08-03`", bl034)

    def test_google_verification_txt_value_is_not_present_anywhere(self):
        # Only the policy statement ("TXT value is not stored") may appear;
        # no actual TXT record value/content is ever written to any of
        # these four management documents.
        for name, text in (
            ("BACKLOG.md", self.backlog),
            ("STATUS.md", self.status),
            ("DECISIONS.md", self.decisions),
            ("SECURITY_REQUIREMENTS.md", self.requirements),
        ):
            with self.subTest(doc=name):
                self.assertNotIn("google-site-verification", text)
        self.assertIn("TXT値そのものはrepositoryへ保存していない", self.backlog)
        self.assertIn("TXT値自体はrepositoryへ保存していない", self.status)
        self.assertIn("value is not stored in this repository", self.decisions)

    def test_bl009_is_still_the_in_progress_umbrella_with_full_scope(self):
        bl009 = self._section(self.backlog, "## BL-009", "\n## BL-010")
        self.assertIn("進行中（BL-034で閲覧計測基盤を先行）", bl009)
        self.assertNotIn("- **状態:** 完了", bl009)
        residual = self._section(bl009, "- **残作業:**", "\n- **注記:**")
        for item in (
            "対象読者と目標",
            "技術/コンテンツSEO",
            "metadata",
            "robots.txt",
            "sitemap",
            "canonical",
            "OG／共有",
            "favicon",
            "About全体",
            "施策の優先順位付け",
            "個別実装",
            "成果測定の継続",
        ):
            with self.subTest(item=item):
                self.assertIn(item, residual)

    def test_status_active_work_no_longer_lists_bl034(self):
        # Active work returned to empty ("None.") immediately after BL-034's
        # closeout, then BL-035 (Fable 5 review R-02/R-03) became the new Active
        # work item -- see test_status.Bl035ActiveWorkTest for that current state.
        active = self._section(self.status, "## Active work", "\n## 5. Recently completed work")
        self.assertNotIn("BL-034", active)

    def test_status_recently_completed_records_bl034(self):
        recently_completed = self._section(
            self.status, "## 5. Recently completed work", "\n## 6. Known issues and limitations"
        )
        bl034 = next(
            line for line in recently_completed.splitlines() if line.startswith("- BL-034 ")
        )
        self.assertIn(self.MERGE_COMMIT, bl034)
        self.assertIn("30766650046", bl034)
        self.assertIn("Cloudflare Web Analytics dashboard", bl034)
        self.assertIn("Search Console", bl034)
        self.assertIn("2026-08-03", bl034)
        self.assertIn("BL-034に残作業はない", bl034)

    def test_sd032_status_is_still_accepted(self):
        sd032 = self._section(self.decisions, "## SD-032", "\n## ")
        self.assertIn("- **Status:** Accepted", sd032)
        self.assertIn(self.MERGE_COMMIT, sd032)

    def test_security_requirements_version_17_approved_is_unchanged_by_closeout(self):
        self.assertIn("**Version:** 1.7", self.requirements)
        self.assertIn("**Status:** Approved", self.requirements)

    def test_intro_no_longer_claims_no_external_confirmations_have_occurred(self):
        # BL-038 tranche 2: scoped to the intro section (all of these
        # checks are, per this test's own name and the class docstring,
        # specifically about what the intro currently says) and compared
        # with normalize_markdown_prose so the contract is the wording, not
        # the exact mid-sentence line-wrap several of these sentences
        # happened to have. The exact date (2026-08-03) is still asserted
        # separately as its own exact-value check.
        intro = self._section(
            self.requirements,
            "# Monomi Digest Security Requirements", "## 1. Purpose and proportionality",
        )
        normalized_intro = dtu.normalize_markdown_prose(intro)
        self.assertNotIn("none of those have occurred and none of them is claimed here", intro)
        self.assertNotIn(
            dtu.normalize_markdown_prose(
                "no DNS change, Cloudflare account operation, or Search Console "
                "verification had occurred"
            ),
            normalized_intro,
            "SECURITY_REQUIREMENTS.md intro must not claim no DNS/Cloudflare/"
            "Search Console confirmation had occurred (closeout confirmation contract)",
        )
        self.assertIn(
            dtu.normalize_markdown_prose(
                "on 2026-08-03 the user confirmed the Cloudflare Web Analytics "
                "dashboard is receiving data"
            ),
            normalized_intro,
            "SECURITY_REQUIREMENTS.md intro must record the 2026-08-03 "
            "Cloudflare Web Analytics dashboard confirmation (closeout confirmation contract)",
        )
        self.assertIn(
            "2026-08-03",
            intro,
            "SECURITY_REQUIREMENTS.md intro must record the exact confirmation "
            "date 2026-08-03 (closeout historical-exact date contract)",
        )
        self.assertIn(
            dtu.normalize_markdown_prose("Google Search Console verified Domain-property ownership"),
            normalized_intro,
            "SECURITY_REQUIREMENTS.md intro must record the Google Search "
            "Console Domain-property ownership verification (closeout confirmation contract)",
        )
        # The Cloudflare site/hostname registration and manual beacon
        # snippet retrieval genuinely happened before acceptance (the
        # implementation embeds that token) -- the intro must say so.
        self.assertIn("the user had already registered", intro)
        self.assertIn(
            dtu.normalize_markdown_prose("retrieved the manual beacon snippet"),
            normalized_intro,
            "SECURITY_REQUIREMENTS.md intro must record that the manual "
            "beacon snippet was already retrieved (closeout confirmation contract)",
        )
        self.assertIn("no DNS, proxy, or nameserver migration to Cloudflare was made", intro)
        # The historical framing (unconfirmed AT THE TIME of acceptance) must
        # be preserved, not deleted -- only the present-tense claim was wrong.
        self.assertIn("both tracked as BL-034's residual post-merge work", intro)
        self.assertIn("did not block this Version's own approval", intro)

    def test_sr047_and_gap018_confirm_dashboard_and_search_console_not_unconfirmed(self):
        sr047 = next(
            line for line in self.requirements.splitlines() if line.startswith("| SR-047 |")
        )
        self.assertNotIn("remain unconfirmed post-merge work", sr047)
        self.assertIn("confirmed as part of BL-034 closeout", sr047)
        gap018 = next(
            line for line in self.requirements.splitlines() if line.startswith("| GAP-018 |")
        )
        gap_cells = [c.strip() for c in gap018.strip("|").split("|")]
        self.assertEqual(gap_cells[1], "Policy decision")
        self.assertEqual(gap_cells[2], "Implemented")
        self.assertNotIn("remain unconfirmed", gap018)
        self.assertIn("BL-034 is complete", gap018)

    def test_section_12_records_closeout_without_reapproving_or_version_bumping(self):
        section12 = self._section(
            self.requirements, "## 12. Approval and maintenance", "## 13."
        )
        self.assertIn("BL-034 closeout (2026-08-03", section12)
        self.assertIn(self.MERGE_COMMIT, section12)
        self.assertIn(
            "does not re-approve Version 1.7 or bump its Version", section12
        )
        self.assertIn("BL-034 is now `完了`", section12)

    def test_cloudflare_site_registration_and_snippet_predate_acceptance(self):
        # PR #73 round 2: the Cloudflare site/hostname registration and
        # manual beacon snippet retrieval genuinely happened before Version
        # 1.7's repository implementation was accepted -- the intro must
        # not claim "no Cloudflare account operation had occurred".
        self.assertNotIn("no DNS change, Cloudflare account", self.requirements)
        self.assertIn("the user had already registered", self.requirements)
        self.assertIn("`monomidigest.com` as a site/hostname in Cloudflare Web Analytics", self.requirements)
        self.assertIn("retrieved the manual beacon", self.requirements)
        self.assertIn(
            "no DNS, proxy, or nameserver migration to Cloudflare was made", self.requirements
        )

    def test_sr047_distinguishes_dns_provider_unchanged_from_new_google_txt_record(self):
        sr047 = next(
            line for line in self.requirements.splitlines() if line.startswith("| SR-047 |")
        )
        self.assertIn("DNS registrar/manager (XServer) and nameservers are unchanged", sr047)
        self.assertIn("Cloudflare's manual/non-proxied beacon embed method itself makes no DNS record change", sr047)
        self.assertIn("a new Google verification TXT record was added at XServer DNS", sr047)
        self.assertIn("no existing DNS record was deleted or replaced", sr047)
        self.assertIn("the TXT value itself is not stored in this repository", sr047)
        # Must not read as a blanket "DNS never changed at all" claim.
        self.assertNotIn("DNS/nameservers are unchanged (Cloudflare's manual/non-proxied embed method)", sr047)
        cells = [c.strip() for c in sr047.strip("|").split("|")]
        self.assertEqual(cells[3], "Met")

    def test_bl032_control_mapping_no_longer_calls_documentation_gap_unresolved(self):
        # Section 5 (trust boundaries) and section 7 (current control
        # mapping) both previously said this document's own Approved
        # promotion of BL-032's current-state record "remains a separate,
        # unresolved documentation step", contradicting GAP-016 and Version
        # 1.7's own Approved status. Both must now say it was completed.
        self.assertNotIn("remains a separate, unresolved documentation step", self.requirements)
        self.assertNotIn("is a separate, unresolved documentation step", self.requirements)
        mapping_row = next(
            line for line in self.requirements.splitlines()
            if line.startswith("| Source content-usage policy and AI provider data-use boundary |")
        )
        self.assertIn("was completed by Version 1.7, consistent with GAP-016", mapping_row)
        trust_boundary_row = next(
            line for line in self.requirements.splitlines()
            if line.startswith("| Source-terms audit and content-usage policy |")
        )
        self.assertIn("was completed by Version 1.7", trust_boundary_row)
        gap016 = next(
            line for line in self.requirements.splitlines() if line.startswith("| GAP-016 |")
        )
        self.assertIn("documentation-maintenance gap is now resolved", gap016)

    def test_pr73_final_acceptance_is_recorded_in_backlog(self):
        # PR #73 closeout itself was independently reviewed (rounds 1-2) and
        # then finally accepted by the user; that final acceptance -- not
        # just the earlier BL-034 repository-implementation acceptance --
        # must be recorded in BACKLOG.md.
        bl034 = self._section(self.backlog, "## BL-034", "\n## 完了済み参照")
        self.assertIn("[PR #73](https://github.com/matkei31/security-digest/pull/73)", bl034)
        self.assertIn("10867e1ec4573ea83b7f9c4572a9243c923f8db5", bl034)
        self.assertIn("1601 tests OK", bl034)
        self.assertIn("30780371203", bl034)
        self.assertIn("changed files 6件", bl034)
        self.assertIn(
            "最終受入、PR #73のReady化、通常のmerge commit方式によるmergeを承認した", bl034
        )
        # Still 完了 / no residual work after this final-acceptance addition.
        self.assertIn("- **状態:** 完了", bl034)
        residual = self._section(bl034, "- **残作業:**")
        self.assertIn("なし", residual)

    def test_pr73_final_acceptance_is_recorded_in_status(self):
        recently_completed = self._section(
            self.status, "## 5. Recently completed work", "\n## 6. Known issues and limitations"
        )
        bl034 = next(
            line for line in recently_completed.splitlines() if line.startswith("- BL-034 ")
        )
        self.assertIn("[PR #73](https://github.com/matkei31/security-digest/pull/73)", bl034)
        self.assertIn("10867e1ec4573ea83b7f9c4572a9243c923f8db5", bl034)
        self.assertIn("1601 tests OK", bl034)
        self.assertIn("30780371203", bl034)
        self.assertIn("ユーザーが最終受入", bl034)

    def test_status_active_work_no_longer_lists_bl034_after_final_acceptance(self):
        # Active work was "None." immediately after PR #73's final acceptance;
        # BL-035 (Fable 5 review R-02/R-03) has since become the Active work item
        # -- see test_status.Bl035ActiveWorkTest for that current state. This test
        # keeps checking that BL-034 itself never regressed back into Active work.
        active = self._section(self.status, "## Active work", "\n## 5. Recently completed work")
        self.assertNotIn("BL-034", active)

    def test_final_acceptance_record_does_not_touch_out_of_scope_documents(self):
        # This round's own diff must be limited to BACKLOG.md/STATUS.md
        # (plus this test file) -- DECISIONS.md and SECURITY_REQUIREMENTS.md
        # keep the content already synced in prior rounds, unchanged here.
        self.assertNotIn("10867e1ec4573ea83b7f9c4572a9243c923f8db5", self.decisions)
        self.assertNotIn("30780371203", self.decisions)
        self.assertNotIn("PR #73", self.requirements)


class StatusSecurityRequirementsSourceOfTruthTest(unittest.TestCase):
    """STATUS.md's section 8 "Sources of truth" table previously hardcoded
    `SECURITY_REQUIREMENTS.md Version 1.1`, which went stale every time
    SECURITY_REQUIREMENTS.md's own Version advanced (it is now 1.7,
    Approved). The row now delegates the current Version/Status to
    SECURITY_REQUIREMENTS.md's own header instead of duplicating a number,
    so this staleness cannot recur on the next Version bump.
    """

    @classmethod
    def setUpClass(cls):
        root = Path(__file__).resolve().parent
        cls.status = (root / "STATUS.md").read_text(encoding="utf-8")
        cls.requirements = (root / "SECURITY_REQUIREMENTS.md").read_text(encoding="utf-8")

    def _sources_of_truth_row(self, label):
        section = self.status.split("## 8. Sources of truth", 1)[1].split("\n## 9.", 1)[0]
        return next(
            line for line in section.splitlines() if line.startswith(f"| {label} |")
        )

    def test_row_delegates_to_security_requirements_header_not_a_fixed_version(self):
        row = self._sources_of_truth_row("Approved security requirements and evidence mapping")
        self.assertIn("[SECURITY_REQUIREMENTS.md](SECURITY_REQUIREMENTS.md)", row)
        self.assertNotIn("Version 1.1", row)
        self.assertNotRegex(row, r"Version\s+\d+\.\d+")
        self.assertIn("同ファイル冒頭のheaderを正本とする", row)
        self.assertIn("特定のVersion番号を複製しない", row)

    def test_security_requirements_itself_is_unchanged_by_this_fix(self):
        # This documentation-only fix must not touch SECURITY_REQUIREMENTS.md
        # itself -- it stays Version 1.7, Approved (already covered in depth
        # by Bl034CloseoutTest; this is a narrow reuse of that same fact to
        # anchor this test class's own claim).
        self.assertIn("**Version:** 1.7", self.requirements)
        self.assertIn("**Status:** Approved", self.requirements)


if __name__ == "__main__":
    unittest.main()
