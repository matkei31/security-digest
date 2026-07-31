#!/usr/bin/env python3
"""
BL-007: monomidigest.comへのカスタムドメイン移行準備の回帰テスト。
docs/CNAMEの内容・永続性と、ドキュメント記録の整合性を検証する。
標準ライブラリunittestのみを使用する。
"""

import datetime
import json
import tempfile
import unittest
from pathlib import Path

import daily_json as dj
import fetch

JST = datetime.timezone(datetime.timedelta(hours=9))
REPOSITORY_ROOT = Path(__file__).resolve().parent


def make_digest(digest_date="2026-07-11", *, total_items=1, high_count=0):
    # BL-032: このfixtureは"items"を常に空配列のまま返す(CNAME永続性の検証には
    # 記事内容自体が不要なため)。generate_archive_outputs()がdaily_json.
    # validate_daily_digest()でrun.total_items/countsとitems件数の一致を
    # 検証するようになったため、total_items/high_countの引数値をrun/counts側
    # へ反映せず、実際のitems件数(0件)と一致させる(引数は呼び出し元の可読性
    # のためだけに残す)。
    del total_items, high_count
    return {
        "schema_version": 1,
        "digest_date": digest_date,
        "generated_at": f"{digest_date}T08:00:00+09:00",
        "generator": {
            "application": "security-digest",
            "model": "gemini-2.5-flash",
            "article_prompt_version": dj.ARTICLE_PROMPT_VERSION,
            "brief_prompt_version": dj.BRIEF_PROMPT_VERSION,
        },
        "run": {
            "status": "success",
            "overwrite_policy": "replace",
            "total_items": 0,
            "ai_attempted_count": 0,
            "ai_success_count": 0,
            "ai_fallback_count": 0,
            "ai_failed_count": 0,
            "ai_not_attempted_count": 0,
        },
        "counts": {
            "importance": {"高": 0, "中": 0, "低": 0, "未判定": 0},
            "urgency": {"本日確認": 0, "今週確認": 0, "参考": 0, "未判定": 0},
            "category": {"脆弱性・パッチ": 0, "未判定": 0},
        },
        "brief": {
            "status": "not_attempted",
            "model": "deterministic-extractive",
            "prompt_version": dj.BRIEF_PROMPT_VERSION,
            "overview": None,
            "important_highlights": [],
            "discussion_points": [],
            "check_items": [],
            "error_type": None,
        },
        "items": [],
    }


def write_digest(data_dir, digest):
    path = data_dir / f"{digest['digest_date']}.json"
    path.write_text(json.dumps(digest, ensure_ascii=False), encoding="utf-8")
    return path


class DocsCnameFileTest(unittest.TestCase):
    """既存repository内のdocs/CNAME自体の内容契約。"""

    def setUp(self):
        self.cname_path = REPOSITORY_ROOT / "docs" / "CNAME"

    def test_cname_file_exists(self):
        self.assertTrue(self.cname_path.is_file())

    def test_cname_content_is_exactly_the_apex_domain_with_trailing_newline(self):
        raw = self.cname_path.read_bytes()
        self.assertEqual(raw, b"monomidigest.com\n")

    def test_cname_does_not_contain_scheme_path_or_www(self):
        text = self.cname_path.read_text(encoding="utf-8")
        self.assertNotIn("http://", text)
        self.assertNotIn("https://", text)
        self.assertNotIn("/", text)
        self.assertNotIn("www.", text)
        self.assertNotIn("www", text.replace("monomidigest.com", ""))

    def test_cname_is_a_single_line(self):
        text = self.cname_path.read_text(encoding="utf-8")
        lines = text.splitlines()
        self.assertEqual(lines, ["monomidigest.com"])


class CnameSurvivesGenerationTest(unittest.TestCase):
    """日次production生成・全Archive offline再生成でdocs/CNAMEが削除されないこと。"""

    def test_cname_survives_generate_archive_outputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            data_dir = root / "data"
            docs_dir = root / "docs"
            data_dir.mkdir()
            docs_dir.mkdir()
            cname_path = docs_dir / "CNAME"
            cname_path.write_text("monomidigest.com\n", encoding="utf-8")

            write_digest(data_dir, make_digest("2026-07-10", total_items=0))
            write_digest(data_dir, make_digest("2026-07-11", total_items=2, high_count=1))
            dj.save_index(data_dir, datetime.datetime(2026, 7, 11, 8, 0, tzinfo=JST))

            fetch.generate_archive_outputs(
                data_dir, docs_dir, datetime.datetime(2026, 7, 11, 8, 0, tzinfo=JST)
            )

            self.assertTrue(cname_path.is_file())
            self.assertEqual(cname_path.read_bytes(), b"monomidigest.com\n")
            # sanity check that archive generation actually ran alongside it
            self.assertTrue((docs_dir / "archive" / "2026-07-11.html").exists())
            self.assertTrue((docs_dir / "archive" / "index.html").exists())

    def test_cname_survives_repeated_full_archive_regeneration(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            data_dir = root / "data"
            docs_dir = root / "docs"
            data_dir.mkdir()
            docs_dir.mkdir()
            cname_path = docs_dir / "CNAME"
            cname_path.write_text("monomidigest.com\n", encoding="utf-8")

            for day, total in (("2026-07-10", 1), ("2026-07-11", 2), ("2026-07-12", 0)):
                write_digest(data_dir, make_digest(day, total_items=total))
            dj.save_index(data_dir, datetime.datetime(2026, 7, 12, 8, 0, tzinfo=JST))

            # simulate offline full-archive regeneration running twice in a row
            fetch.generate_archive_outputs(data_dir, docs_dir, datetime.datetime(2026, 7, 12, 8, 0, tzinfo=JST))
            fetch.generate_archive_outputs(data_dir, docs_dir, datetime.datetime(2026, 7, 12, 8, 0, tzinfo=JST))

            self.assertTrue(cname_path.is_file())
            self.assertEqual(cname_path.read_bytes(), b"monomidigest.com\n")
            for day in ("2026-07-10", "2026-07-11", "2026-07-12"):
                self.assertTrue((docs_dir / "archive" / f"{day}.html").exists())

    def test_atomic_write_text_never_touches_sibling_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            docs_dir = Path(tmp)
            cname_path = docs_dir / "CNAME"
            cname_path.write_text("monomidigest.com\n", encoding="utf-8")

            fetch.atomic_write_text(docs_dir / "index.html", "<html><body>ok</body></html>")

            self.assertTrue(cname_path.is_file())
            self.assertEqual(cname_path.read_bytes(), b"monomidigest.com\n")


class ArticleBriefContractUnchangedTest(unittest.TestCase):
    """BL-007はARTICLE／BRIEF prompt・schema・versionを変更しない。"""

    def test_article_and_brief_prompt_versions_are_unchanged(self):
        self.assertEqual(dj.ARTICLE_PROMPT_VERSION, "article-analysis-v8")
        self.assertEqual(dj.BRIEF_PROMPT_VERSION, "today-brief-extractive-v2")

    def test_daily_json_schema_version_is_unchanged(self):
        # BL-032 bumped SCHEMA_VERSION from 1 to 2 for the policy_excluded_count/
        # ai_eligible_count contract; unrelated to custom-domain migration.
        self.assertEqual(dj.SCHEMA_VERSION, 2)


class Bl007DocumentationTest(unittest.TestCase):
    """BACKLOG／STATUS／DECISIONSの記録内容と、他Ticket状態の不変性。"""

    @classmethod
    def setUpClass(cls):
        cls.backlog = (REPOSITORY_ROOT / "BACKLOG.md").read_text(encoding="utf-8")
        cls.status = (REPOSITORY_ROOT / "STATUS.md").read_text(encoding="utf-8")
        cls.decisions = (REPOSITORY_ROOT / "DECISIONS.md").read_text(encoding="utf-8")

    def _section(self, text, marker, next_marker="\n## "):
        start = text.index(marker)
        rest = text[start + len(marker):]
        end = rest.find(next_marker)
        return rest if end == -1 else rest[:end]

    def test_bl007_is_recorded_as_complete_with_confirmed_policy(self):
        bl007 = self._section(self.backlog, "## BL-007")
        self.assertIn("- **状態:** 完了", bl007)
        self.assertIn("正規URLは`https://monomidigest.com/`とする", bl007)
        self.assertIn(
            "`https://www.monomidigest.com/`は正規URLへリダイレクトさせる", bl007
        )
        self.assertIn("GitHub Pagesを継続使用する", bl007)
        self.assertIn("DNS管理はXServerドメインで行う", bl007)
        self.assertIn("repository名`security-digest`は変更しない", bl007)
        self.assertIn("wildcard DNSは使用しない", bl007)
        self.assertIn("検証TXTは保持する", bl007)
        self.assertIn("検証用TXTは削除せず維持する", bl007)
        self.assertIn("implementation branch `claude/bl007-custom-domain`", bl007)
        self.assertIn("616d58e8a924338f596c54f9717f0ff96f48d9e6", bl007)
        self.assertIn("**残作業:** なし", bl007)

    def test_bl007_does_not_infer_domain_as_unacquired(self):
        bl007 = self._section(self.backlog, "## BL-007")
        self.assertIn("取得済み", bl007)
        self.assertIn("Verified", bl007)
        self.assertNotIn("ドメインが購入または設定済みであると推定しない", bl007)

    def test_bl009_scope_and_state_are_unchanged(self):
        bl009 = self._section(self.backlog, "## BL-009")
        self.assertIn("記録済み / 前提条件が整うまで保留", bl009)

    def test_bl006_completion_state_is_unchanged(self):
        bl006 = self._section(self.backlog, "## BL-006")
        self.assertIn("状態:** 完了", bl006)

    def test_sd011_status_is_unchanged(self):
        sd011 = self._section(self.decisions, "## SD-011", "\n## SD-012")
        self.assertIn("- **Status:** Accepted / Not implemented", sd011)
        self.assertIn("Use `monomidigest.com` as the primary domain", sd011)

    def test_sd028_records_the_implementation_decision(self):
        sd028 = self._section(self.decisions, "## SD-028")
        self.assertIn("- **Status:** Accepted", sd028)
        self.assertIn("apex", sd028)
        self.assertIn("no wildcard DNS records are used", sd028)
        self.assertIn("`security-digest` is not renamed", sd028)
        self.assertIn("docs/CNAME", sd028)
        self.assertIn("[BL-009]", sd028)

    def test_no_wildcard_dns_is_instructed_anywhere_in_bl007(self):
        bl007 = self._section(self.backlog, "## BL-007")
        self.assertNotIn("*.monomidigest.com", bl007)
        self.assertIn("wildcard DNSは使用しない", bl007)

    def test_status_active_work_no_longer_lists_bl007(self):
        # BL-007のclosure後、Active workは一時的に空(None.)になったが、その後
        # BL-030がActive workへ追加された。BL-007自体がActive workへ戻って
        # いないことだけを検証する(Active work自体が空である必要はない)。
        active = self._section(self.status, "## Active work", "\n## 5. Recently completed work")
        self.assertNotIn("BL-007", active)

    def test_status_records_bl007_as_recently_completed(self):
        recently_completed = self._section(
            self.status, "## 5. Recently completed work", "\n## 6. Known issues and limitations"
        )
        self.assertIn("BL-007", recently_completed)
        self.assertIn("616d58e8a924338f596c54f9717f0ff96f48d9e6", recently_completed)
        self.assertIn("monomidigest.com", recently_completed)

    def test_bl028_and_bl029_completion_states_are_unchanged(self):
        recently_completed = self._section(
            self.status, "## 5. Recently completed work", "\n## 6. Known issues and limitations"
        )
        self.assertIn("BL-028", recently_completed)
        self.assertIn("BL-029", recently_completed)


class ReadmePublicUrlTest(unittest.TestCase):
    """READMEは切替完了後の現在の公開状態と一致させる。"""

    @classmethod
    def setUpClass(cls):
        cls.readme = (REPOSITORY_ROOT / "README.md").read_text(encoding="utf-8")

    def test_readme_states_monomidigest_com_as_the_current_public_site(self):
        self.assertIn("公開サイト: https://monomidigest.com/", self.readme)

    def test_readme_notes_the_old_url_redirects_here(self):
        self.assertIn("https://matkei31.github.io/security-digest/", self.readme)
        self.assertIn("リダイレクト", self.readme)

    def test_readme_does_not_embed_runbook_or_dns_details(self):
        for forbidden in (
            "185.199.108.153",
            "185.199.109.153",
            "185.199.110.153",
            "185.199.111.153",
            "ns1.xdomain.ne.jp",
            "Custom domain",
            "dig +short",
            "runbook",
        ):
            self.assertNotIn(forbidden, self.readme)

    def test_readme_has_no_ticket_id_typo(self):
        self.assertNotIn("BL_007", self.readme)


class Bl007ClosureRecordTest(unittest.TestCase):
    """closure後のBACKLOG／SD-028の記録内容(cutover順序の履歴・観測事実・現状)を検証する。"""

    @classmethod
    def setUpClass(cls):
        cls.backlog = (REPOSITORY_ROOT / "BACKLOG.md").read_text(encoding="utf-8")
        cls.decisions = (REPOSITORY_ROOT / "DECISIONS.md").read_text(encoding="utf-8")
        cls.status = (REPOSITORY_ROOT / "STATUS.md").read_text(encoding="utf-8")

    def _section(self, text, marker, next_marker="\n## "):
        start = text.index(marker)
        rest = text[start + len(marker):]
        end = rest.find(next_marker)
        return rest if end == -1 else rest[:end]

    def test_status_latest_published_daily_json_reflects_the_latest_run(self):
        # This row tracks whichever ordinary production run is most recent;
        # it has since advanced past the 2026-07-30 08:00 JST run recorded by
        # BL-031, to the 2026-07-31 08:07 JST run recorded by BL-032's
        # post-merge closeout (this run predates the BL-032 merge itself, so
        # it is still schema v1; see the separate schema rows below it).
        row = self._section(self.status, "| Latest published daily JSON |", "\n|")
        self.assertIn("today-brief-extractive-v2", row)
        self.assertIn("2026-07-31 08:07 JST", row)
        self.assertIn("9記事", row)

    def test_status_current_versions_paragraph_reflects_the_latest_run(self):
        # The table row above is only half the picture -- the explanatory
        # paragraph right after "## 2. Current versions" independently
        # described the "current" production run in prose, and it lagged
        # behind the table (still narrating the 2026-07-30/13-source run as
        # current after the table had already moved to 2026-07-31/12-source).
        # This must stay in sync with the table row.
        section = self._section(self.status, "## 2. Current versions", "\n## 3.")
        self.assertIn("2026-07-31 08:07 JST", section)
        self.assertIn("bf0a1d2", section)
        self.assertIn("enabled sourceは12", section)
        self.assertIn("Archive footerも12-sourceである", section)
        # A historical contrast mentioning the earlier 2026-07-30/13-source
        # run is fine; it must not still be presented as the current state.
        self.assertNotIn("Archive footerも13-sourceのままである", section)
        self.assertNotIn("この時点でenabled sourceは13(`google_tag`", section)

    def test_bl007_distinguishes_its_own_work_from_the_scheduled_run(self):
        bl007 = self._section(self.backlog, "## BL-007")
        self.assertIn("本Ticketの実装・cutover・closure作業", bl007)
        self.assertIn("通常scheduleによって独立して実行された", bl007)
        self.assertNotIn("production／workflow_dispatchは実行していない。", bl007)

    def test_bl007_records_the_scheduled_run_commit_sha(self):
        bl007 = self._section(self.backlog, "## BL-007")
        self.assertIn("b8463c0f10734097c4a431ce69be808d371e4e3b", bl007)

    def test_sd028_context_is_historical_not_current(self):
        sd028 = self._section(self.decisions, "## SD-028")
        self.assertIn("At the time this decision was accepted", sd028)
        self.assertIn("had not yet been configured", sd028)

    def test_bl007_records_the_approved_plan_as_a_separate_history_item(self):
        bl007 = self._section(self.backlog, "## BL-007")
        self.assertIn("**承認済みの計画:**", bl007)
        plan_pos = bl007.index("**承認済みの計画:**")
        merge_pos = bl007.index("PR #64 merge", plan_pos)
        custom_domain_pos = bl007.index("repository Custom domain設定", merge_pos)
        dns_pos = bl007.index("XServer DNS設定", custom_domain_pos)
        self.assertLess(merge_pos, custom_domain_pos)
        self.assertLess(custom_domain_pos, dns_pos)

    def test_bl007_records_the_actual_automatic_activation_order_separately(self):
        bl007 = self._section(self.backlog, "## BL-007")
        self.assertIn("**実際に観測された順序:**", bl007)
        observed_pos = bl007.index("**実際に観測された順序:**")
        merge_pos = bl007.index("PR #64をmerge", observed_pos)
        activation_pos = bl007.index("手動のrepository Settings操作を待たずに", merge_pos)
        dns_pos = bl007.index("ユーザーがXServer DNS", activation_pos)
        self.assertLess(merge_pos, activation_pos)
        self.assertLess(activation_pos, dns_pos)

    def test_bl007_does_not_claim_the_plan_was_executed_as_planned(self):
        bl007 = self._section(self.backlog, "## BL-007")
        self.assertNotIn("この順で実施した", bl007)
        self.assertIn("計画どおりの順序で実施したとは記録しない", bl007)

    def test_bl007_records_no_unintended_commit_from_custom_domain_activation(self):
        bl007 = self._section(self.backlog, "## BL-007")
        self.assertIn("mainへの意図しない追加commitは発生していない", bl007)

    def test_bl007_records_the_transient_dns_error_resolved(self):
        bl007 = self._section(self.backlog, "## BL-007")
        self.assertIn("InvalidDNSError", bl007)
        self.assertIn("解消し", bl007)

    def test_bl007_and_sd028_observed_facts_do_not_contradict(self):
        bl007 = self._section(self.backlog, "## BL-007")
        sd028 = self._section(self.decisions, "## SD-028")
        for fact in (
            "InvalidDNSError",
            "手動",
        ):
            with self.subTest(fact=fact):
                self.assertIn(fact, bl007)
                self.assertIn(fact if fact != "手動" else "manual", sd028)
        # both records must agree the custom domain activated without a manual Settings step
        self.assertIn("手動のrepository Settings操作を待たずに", bl007)
        self.assertIn("without any separate manual Settings action", sd028)
        # both records must agree no unintended commit resulted from that activation
        self.assertIn("mainへの意図しない追加commitは発生していない", bl007)
        self.assertIn("No unintended additional commit was produced on `main`", sd028)

    def test_bl007_retains_ownership_txt_and_forbids_wildcard(self):
        bl007 = self._section(self.backlog, "## BL-007")
        self.assertIn("GitHub所有権確認用TXTは維持されている", bl007)
        self.assertNotIn("*.monomidigest.com", bl007)

    def test_bl007_does_not_retain_stale_pre_closure_wording(self):
        bl007 = self._section(self.backlog, "## BL-007")
        self.assertNotIn("DNS切替待ち", bl007)
        self.assertNotIn("DNSをrepository Custom domain設定より先に伝播", bl007)

    def test_sd028_records_https_enforced_and_certificate_approved(self):
        sd028 = self._section(self.decisions, "## SD-028")
        self.assertIn("Enforce HTTPS", sd028)
        self.assertIn("is enabled", sd028)
        self.assertIn("TLS certificate covers both", sd028)

    def test_sd028_records_cname_merge_activation_as_an_observation_not_a_guarantee(self):
        sd028 = self._section(self.decisions, "## SD-028")
        self.assertIn("Observed behavior for this repository", sd028)
        self.assertIn("not asserted as a universal GitHub Pages guarantee", sd028)

    def test_sd028_records_the_transient_dns_error_and_its_resolution(self):
        sd028 = self._section(self.decisions, "## SD-028")
        self.assertIn("InvalidDNSError", sd028)
        self.assertIn("resolved", sd028)

    def test_sd028_records_minimal_dns_with_no_wildcard(self):
        sd028 = self._section(self.decisions, "## SD-028")
        self.assertIn("no AAAA records were added and no wildcard DNS is used", sd028)

    def test_sd028_evidence_records_merge_commit_and_public_state(self):
        sd028 = self._section(self.decisions, "## SD-028")
        self.assertIn("616d58e8a924338f596c54f9717f0ff96f48d9e6", sd028)
        self.assertIn("protected_domain_state: verified", sd028)
        self.assertIn("https_enforced: true", sd028)


class TicketIdTypoTest(unittest.TestCase):
    """正式なTicket IDは常にBL-007であり、BL_007という誤記が残っていないこと。"""

    def test_no_bl007_underscore_typo_anywhere_in_tracked_markdown_or_python(self):
        # Excludes this test file itself: its own assertion strings
        # intentionally search for "BL_007" as the typo pattern to detect,
        # which is not a use of it as a real Ticket ID.
        for filename in (
            "README.md",
            "BACKLOG.md",
            "STATUS.md",
            "DECISIONS.md",
            "UI_SPEC.md",
            "fetch.py",
            "daily_json.py",
        ):
            path = REPOSITORY_ROOT / filename
            if not path.exists():
                continue
            text = path.read_text(encoding="utf-8")
            with self.subTest(filename=filename):
                self.assertNotIn("BL_007", text)


if __name__ == "__main__":
    unittest.main()
