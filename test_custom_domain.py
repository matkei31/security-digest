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
            "total_items": total_items,
            "ai_attempted_count": total_items,
            "ai_success_count": total_items,
            "ai_fallback_count": 0,
            "ai_failed_count": 0,
            "ai_not_attempted_count": 0,
        },
        "counts": {
            "importance": {"高": high_count, "中": 0, "低": 0, "未判定": 0},
            "urgency": {"本日確認": 0, "今週確認": 0, "参考": 0, "未判定": 0},
            "category": {"脆弱性・パッチ": total_items, "未判定": 0},
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
        self.assertEqual(dj.SCHEMA_VERSION, 1)


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

    def test_bl007_is_recorded_with_confirmed_spec_and_draft_pr(self):
        bl007 = self._section(self.backlog, "## BL-007")
        self.assertIn("仕様化済み / 実装済みDraft PR / DNS切替待ち", bl007)
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
        self.assertNotIn("**状態:** 完了", bl007)

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

    def test_status_active_work_records_bl007_dns_pending(self):
        active = self._section(self.status, "## Active work", "\n## 5. Recently completed work")
        self.assertIn("BL-007", active)
        self.assertIn("DNS", active)

    def test_bl028_and_bl029_completion_states_are_unchanged(self):
        recently_completed = self._section(
            self.status, "## 5. Recently completed work", "\n## 6. Known issues and limitations"
        )
        self.assertIn("BL-028", recently_completed)
        self.assertIn("BL-029", recently_completed)


class ReadmePublicUrlTest(unittest.TestCase):
    """READMEは現在の公開状態とだけ一致させ、切替完了を先取りしない。"""

    @classmethod
    def setUpClass(cls):
        cls.readme = (REPOSITORY_ROOT / "README.md").read_text(encoding="utf-8")

    def test_readme_states_the_current_live_url(self):
        self.assertIn("公開サイト: https://matkei31.github.io/security-digest/", self.readme)

    def test_readme_states_the_planned_domain_without_claiming_it_is_live(self):
        self.assertIn("切替予定ドメイン: https://monomidigest.com/", self.readme)
        self.assertNotIn("公開サイト: https://monomidigest.com/", self.readme)

    def test_readme_does_not_assert_the_switch_is_complete(self):
        self.assertNotIn("正規URLとなり", self.readme)
        self.assertNotIn("切替後", self.readme)
        self.assertNotIn("redirectされる", self.readme)

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


class RunbookOrderingTest(unittest.TestCase):
    """cutover runbookの記述順序(文字列の出現順)を検証する。"""

    @classmethod
    def setUpClass(cls):
        cls.backlog = (REPOSITORY_ROOT / "BACKLOG.md").read_text(encoding="utf-8")
        cls.decisions = (REPOSITORY_ROOT / "DECISIONS.md").read_text(encoding="utf-8")

    def _section(self, text, marker, next_marker="\n## "):
        start = text.index(marker)
        rest = text[start + len(marker):]
        end = rest.find(next_marker)
        return rest if end == -1 else rest[:end]

    def test_bl007_merge_is_ordered_before_custom_domain_and_dns_setup(self):
        bl007 = self._section(self.backlog, "## BL-007")
        merge_pos = bl007.index("PR #64 Ready化・通常merge")
        custom_domain_pos = bl007.index("repository Custom domain設定", merge_pos)
        dns_pos = bl007.index("XServer A×4追加", custom_domain_pos)
        self.assertLess(merge_pos, custom_domain_pos)
        self.assertLess(custom_domain_pos, dns_pos)

    def test_bl007_checks_for_github_generated_commit_after_custom_domain_save(self):
        bl007 = self._section(self.backlog, "## BL-007")
        self.assertIn("設定直後のGitHub生成commit有無確認", bl007)

    def test_bl007_retains_ownership_txt_and_forbids_wildcard(self):
        bl007 = self._section(self.backlog, "## BL-007")
        self.assertIn("ownership TXT保持", bl007)
        self.assertIn("wildcard禁止", bl007)

    def test_bl007_does_not_claim_dns_or_https_or_redirect_as_complete(self):
        bl007 = self._section(self.backlog, "## BL-007")
        self.assertIn("DNS切替待ち", bl007)
        self.assertNotIn("**状態:** 完了", bl007)

    def test_sd028_does_not_disable_enforce_https_proactively(self):
        sd028 = self._section(self.decisions, "## SD-028")
        self.assertIn("is not disabled proactively", sd028)
        self.assertIn("not yet enabled until GitHub issues the certificate", sd028)

    def test_sd028_records_dns_tls_https_redirect_as_unconfirmed(self):
        sd028 = self._section(self.decisions, "## SD-028")
        self.assertIn("are all unconfirmed and not represented as complete", sd028)

    def test_sd028_orders_merge_before_custom_domain_before_dns(self):
        sd028 = self._section(self.decisions, "## SD-028")
        merge_pos = sd028.index("merge")
        custom_domain_pos = sd028.index("Custom domain setting to", merge_pos)
        dns_pos = sd028.index("adds the XServer DNS records", custom_domain_pos)
        self.assertLess(merge_pos, custom_domain_pos)
        self.assertLess(custom_domain_pos, dns_pos)

    def test_bl007_backlog_does_not_retain_dns_before_custom_domain_wording(self):
        bl007 = self._section(self.backlog, "## BL-007")
        self.assertNotIn("DNSをrepository Custom domain設定より先に伝播", bl007)

    def test_bl007_backlog_records_merge_then_custom_domain_then_dns(self):
        bl007 = self._section(self.backlog, "## BL-007")
        merge_pos = bl007.index("PR #64 merge")
        custom_domain_pos = bl007.index("repository Custom domain設定", merge_pos)
        dns_pos = bl007.index("XServer DNS設定", custom_domain_pos)
        self.assertLess(merge_pos, custom_domain_pos)
        self.assertLess(custom_domain_pos, dns_pos)


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
