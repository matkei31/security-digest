#!/usr/bin/env python3
"""
日次JSON (data/YYYY-MM-DD.json, data/index.json) の回帰テスト (Ticket 3)
標準ライブラリの unittest のみを使用する。
"""

import datetime
import json
import tempfile
import unittest
from pathlib import Path

import daily_json as dj
import fetch

JST = dj.JST
NOW = datetime.datetime(2026, 7, 11, 7, 5, 32, tzinfo=JST)


SOURCE_DEFS = [
    {
        "id": "cisa", "name": "CISA", "source_type": "CERT・注意喚起",
        "source_tier": "Tier 1", "collection_method": "rss", "language": "en",
    },
    {
        "id": "cisa_kev", "name": "CISA KEV", "source_type": "CERT・注意喚起",
        "source_tier": "Tier 1", "collection_method": "cisa_kev_json", "language": "en",
    },
    {
        "id": "fsa", "name": "金融庁", "source_type": "規制・監督",
        "source_tier": "Tier 1", "collection_method": "rss", "language": "ja",
    },
]


def make_item(**overrides):
    item = {
        "source": "CISA",
        "lang": "en",
        "link": "https://example.com/article",
        "title": "表示タイトル",
        "raw_title": "Raw Title",
        "raw_summary": "<p>raw summary</p>",
        "date": None,
        "published_at_jst": None,
    }
    item.update(overrides)
    return item


def success_meta(generated_at=NOW):
    return {"status": "success", "error_type": None, "http_status": None,
            "generated_at": generated_at.isoformat()}


def failed_meta(error_type="resource_exhausted", http_status=429, generated_at=NOW):
    return {"status": "failed", "error_type": error_type, "http_status": http_status,
            "generated_at": generated_at.isoformat()}


def fallback_meta(generated_at=NOW):
    return {"status": "fallback", "error_type": "schema_parse_error", "http_status": None,
            "generated_at": generated_at.isoformat()}


SAMPLE_ANALYSIS = {
    "importance": "高", "summary": "要約", "financial_impact": "影響",
    "recommended_actions": ["対応1"],
}

# Ticket 4: category/category_reason/urgency/reason/tagsを含む新スキーマの分析結果
SAMPLE_ANALYSIS_V2 = {
    "importance": "高", "summary": "要約", "financial_impact": "影響",
    "recommended_actions": ["対応1"],
    "category": "脆弱性・パッチ", "category_reason": "CVEとKEV追加が主題のため。",
    "urgency": "本日確認", "reason": "悪用確認済みのため。",
    "tags": ["KEV", "悪用確認済み"],
}

# Ticket 8: Today's Brief (4要素) の戻り値サンプル。fetch.py の
# build_todays_brief()/gemini_todays_brief() が返す形をそのまま模す。
NOT_ATTEMPTED_BRIEF_RESULT = {
    "overview": None, "important_highlights": [], "discussion_points": [], "check_items": [],
    "status": "not_attempted", "error_type": None, "http_status": None,
}

SUCCESS_BRIEF_RESULT = {
    "overview": "本日は脆弱性関連の情報が中心で、金融機関に影響し得る内容が複数確認されました。",
    "important_highlights": ["重要情報ハイライト1", "重要情報ハイライト2"],
    "discussion_points": ["本日の注目論点1"],
    "check_items": ["確認事項1", "確認事項2"],
    "status": "success", "error_type": None, "http_status": None,
}

FAILED_BRIEF_RESULT = {
    "overview": None, "important_highlights": [], "discussion_points": [], "check_items": [],
    "status": "failed", "error_type": "schema_parse_error", "http_status": None,
}


# ── エラー分類 ────────────────────────────────────────────────────────────

class ErrorClassificationTest(unittest.TestCase):
    def test_403_is_permission_denied(self):
        self.assertEqual(dj.classify_gemini_error(http_status=403), "permission_denied")

    def test_429_is_resource_exhausted(self):
        self.assertEqual(dj.classify_gemini_error(http_status=429), "resource_exhausted")

    def test_402_is_billing_or_balance(self):
        self.assertEqual(dj.classify_gemini_error(http_status=402), "billing_or_balance")

    def test_other_http_status_is_api_error(self):
        for status in (400, 404, 500, 503):
            with self.subTest(status=status):
                self.assertEqual(dj.classify_gemini_error(http_status=status), "api_error")

    def test_url_error_is_network_error(self):
        import urllib.error
        self.assertEqual(
            dj.classify_gemini_error(exception=urllib.error.URLError("boom")),
            "network_error",
        )

    def test_other_exception_is_unknown(self):
        self.assertEqual(dj.classify_gemini_error(exception=ValueError("x")), "unknown")

    def test_valid_error_types_include_new_values(self):
        self.assertIn("resource_exhausted", dj.VALID_ERROR_TYPES)
        self.assertIn("permission_denied", dj.VALID_ERROR_TYPES)

    def test_digest_with_new_error_types_passes_validation(self):
        items = [
            make_item(link="https://example.com/a", ai_analysis=None, ai_analysis_meta=failed_meta(
                error_type="permission_denied", http_status=403)),
            make_item(link="https://example.com/b", ai_analysis=None, ai_analysis_meta=failed_meta(
                error_type="resource_exhausted", http_status=429)),
        ]
        digest = dj.build_daily_digest(
            items, NOT_ATTEMPTED_BRIEF_RESULT,
            SOURCE_DEFS, "gemini-2.5-flash", NOW, NOW,
        )
        dj.validate_daily_digest(digest)  # 例外が出なければOK
        error_types = {item["analysis"]["error_type"] for item in digest["items"]}
        self.assertEqual(error_types, {"permission_denied", "resource_exhausted"})


# ── スキーマ・メタ情報 ────────────────────────────────────────────────────

class SchemaMetaTest(unittest.TestCase):
    def test_generates_valid_daily_digest(self):
        item = make_item(ai_analysis=SAMPLE_ANALYSIS, ai_analysis_meta=success_meta())
        digest = dj.build_daily_digest([item], SUCCESS_BRIEF_RESULT, SOURCE_DEFS, "gemini-2.5-flash", NOW, NOW)
        dj.validate_daily_digest(digest)  # 例外が出なければOK

    def test_schema_version_is_1(self):
        digest = dj.build_daily_digest([], NOT_ATTEMPTED_BRIEF_RESULT,
                                        SOURCE_DEFS, "gemini-2.5-flash", NOW, NOW)
        self.assertEqual(digest["schema_version"], 1)
        self.assertIsInstance(digest["schema_version"], int)

    def test_digest_date_is_jst_based(self):
        # UTC 15:30 = JST 翌日00:30 となるケースでdigest_dateがJST日付になることを確認
        generated_at_jst = datetime.datetime(2026, 7, 12, 0, 30, tzinfo=JST)
        digest = dj.build_daily_digest([], NOT_ATTEMPTED_BRIEF_RESULT,
                                        SOURCE_DEFS, "gemini-2.5-flash", NOW, generated_at_jst)
        self.assertEqual(digest["digest_date"], "2026-07-12")

    def test_generated_at_has_timezone(self):
        digest = dj.build_daily_digest([], NOT_ATTEMPTED_BRIEF_RESULT,
                                        SOURCE_DEFS, "gemini-2.5-flash", NOW, NOW)
        parsed = datetime.datetime.fromisoformat(digest["generated_at"])
        self.assertIsNotNone(parsed.tzinfo)

    def test_generator_model_and_prompt_versions_are_set(self):
        digest = dj.build_daily_digest([], NOT_ATTEMPTED_BRIEF_RESULT,
                                        SOURCE_DEFS, "gemini-2.5-flash", NOW, NOW)
        self.assertEqual(digest["generator"]["model"], "gemini-2.5-flash")
        self.assertEqual(digest["generator"]["article_prompt_version"], dj.ARTICLE_PROMPT_VERSION)
        self.assertEqual(digest["generator"]["brief_prompt_version"], dj.BRIEF_PROMPT_VERSION)

    def test_total_items_matches_items_length(self):
        items = [make_item(ai_analysis=SAMPLE_ANALYSIS, ai_analysis_meta=success_meta()) for _ in range(3)]
        digest = dj.build_daily_digest(items, NOT_ATTEMPTED_BRIEF_RESULT,
                                        SOURCE_DEFS, "gemini-2.5-flash", NOW, NOW)
        self.assertEqual(digest["run"]["total_items"], len(digest["items"]))
        self.assertEqual(digest["run"]["total_items"], 3)


# ── status・件数 ──────────────────────────────────────────────────────────

class RunStatusTest(unittest.TestCase):
    def _digest(self, metas):
        items = [
            make_item(ai_analysis=(SAMPLE_ANALYSIS if m["status"] in ("success", "fallback") else None),
                      ai_analysis_meta=m)
            for m in metas
        ]
        return dj.build_daily_digest(items, NOT_ATTEMPTED_BRIEF_RESULT,
                                      SOURCE_DEFS, "gemini-2.5-flash", NOW, NOW)

    def test_all_success_is_success(self):
        digest = self._digest([success_meta(), success_meta()])
        self.assertEqual(digest["run"]["status"], "success")

    def test_mixed_with_at_least_one_success_or_fallback_is_partial(self):
        digest = self._digest([success_meta(), fallback_meta(), failed_meta()])
        self.assertEqual(digest["run"]["status"], "partial")

    def test_all_failed_is_failed(self):
        digest = self._digest([failed_meta(), failed_meta()])
        self.assertEqual(digest["run"]["status"], "failed")

    def test_all_not_attempted_is_not_attempted(self):
        items = [make_item() for _ in range(2)]  # ai_analysis_meta キーなし
        digest = dj.build_daily_digest(items, NOT_ATTEMPTED_BRIEF_RESULT,
                                        SOURCE_DEFS, "gemini-2.5-flash", NOW, NOW)
        self.assertEqual(digest["run"]["status"], "not_attempted")

    def test_zero_items_is_success(self):
        digest = dj.build_daily_digest([], NOT_ATTEMPTED_BRIEF_RESULT,
                                        SOURCE_DEFS, "gemini-2.5-flash", NOW, NOW)
        self.assertEqual(digest["run"]["status"], "success")

    def test_ai_counts_sum_to_total_items(self):
        digest = self._digest([success_meta(), fallback_meta(), failed_meta()])
        run = digest["run"]
        total = (run["ai_success_count"] + run["ai_fallback_count"]
                 + run["ai_failed_count"] + run["ai_not_attempted_count"])
        self.assertEqual(total, run["total_items"])
        self.assertEqual(
            run["ai_attempted_count"],
            run["ai_success_count"] + run["ai_fallback_count"] + run["ai_failed_count"],
        )


class CountsTest(unittest.TestCase):
    def test_importance_counts_are_correct(self):
        items = [
            make_item(ai_analysis={**SAMPLE_ANALYSIS, "importance": "高"}, ai_analysis_meta=success_meta()),
            make_item(ai_analysis={**SAMPLE_ANALYSIS, "importance": "中"}, ai_analysis_meta=success_meta()),
            make_item(ai_analysis=None, ai_analysis_meta=failed_meta()),
        ]
        digest = dj.build_daily_digest(items, NOT_ATTEMPTED_BRIEF_RESULT,
                                        SOURCE_DEFS, "gemini-2.5-flash", NOW, NOW)
        importance = digest["counts"]["importance"]
        self.assertEqual(importance["高"], 1)
        self.assertEqual(importance["中"], 1)
        self.assertEqual(importance["未判定"], 1)
        self.assertEqual(sum(importance.values()), 3)

    def test_missing_urgency_category_fields_fall_back_to_unclassified(self):
        # Ticket 3形式(urgency/categoryキーを持たない)のanalysisは、
        # statusがsuccessでも未判定に集計される(後方互換の確認)。
        items = [make_item(ai_analysis=SAMPLE_ANALYSIS, ai_analysis_meta=success_meta()) for _ in range(4)]
        digest = dj.build_daily_digest(items, NOT_ATTEMPTED_BRIEF_RESULT,
                                        SOURCE_DEFS, "gemini-2.5-flash", NOW, NOW)
        self.assertEqual(digest["counts"]["urgency"]["未判定"], 4)
        self.assertEqual(sum(digest["counts"]["urgency"].values()), 4)
        self.assertEqual(digest["counts"]["category"]["未判定"], 4)
        self.assertEqual(sum(digest["counts"]["category"].values()), 4)

    def test_urgency_and_category_are_tabulated_from_ticket4_analysis(self):
        # Ticket 4形式(category/urgency含む)のanalysisは、実際の値が集計される。
        items = [
            make_item(
                ai_analysis={**SAMPLE_ANALYSIS_V2, "category": "脆弱性・パッチ", "urgency": "本日確認"},
                ai_analysis_meta=success_meta(),
            ),
            make_item(
                ai_analysis={**SAMPLE_ANALYSIS_V2, "category": "規制・ガバナンス", "urgency": "今週確認"},
                ai_analysis_meta=success_meta(),
            ),
            make_item(ai_analysis=None, ai_analysis_meta=failed_meta()),
        ]
        digest = dj.build_daily_digest(items, NOT_ATTEMPTED_BRIEF_RESULT,
                                        SOURCE_DEFS, "gemini-2.5-flash", NOW, NOW)
        self.assertEqual(digest["counts"]["category"]["脆弱性・パッチ"], 1)
        self.assertEqual(digest["counts"]["category"]["規制・ガバナンス"], 1)
        self.assertEqual(digest["counts"]["category"]["未判定"], 1)
        self.assertEqual(digest["counts"]["urgency"]["本日確認"], 1)
        self.assertEqual(digest["counts"]["urgency"]["今週確認"], 1)
        self.assertEqual(digest["counts"]["urgency"]["未判定"], 1)


# ── 記事データ ────────────────────────────────────────────────────────────

class ArticleDataTest(unittest.TestCase):
    def test_source_name_resolves_to_source_meta(self):
        item = make_item(source="金融庁", ai_analysis=None, ai_analysis_meta=None)
        entry = dj.build_article_entry(item, SOURCE_DEFS, "gemini-2.5-flash", NOW)
        self.assertEqual(entry["source_id"], "fsa")
        self.assertEqual(entry["source_type"], "規制・監督")
        self.assertEqual(entry["source_tier"], "Tier 1")
        self.assertEqual(entry["collection_method"], "rss")
        self.assertEqual(entry["language"], "ja")

    def test_unknown_source_name_raises_clear_error(self):
        item = make_item(source="未定義のソース")
        with self.assertRaises(dj.DailyJsonError) as ctx:
            dj.build_article_entry(item, SOURCE_DEFS, "gemini-2.5-flash", NOW)
        self.assertIn("未定義のソース", str(ctx.exception))

    def test_raw_excerpt_strips_html_tags(self):
        item = make_item(raw_summary="<p>hello <b>world</b></p>")
        entry = dj.build_article_entry(item, SOURCE_DEFS, "gemini-2.5-flash", NOW)
        self.assertEqual(entry["raw_excerpt"], "hello world")

    def test_raw_excerpt_is_truncated_to_200_chars(self):
        item = make_item(raw_summary="x" * 500)
        entry = dj.build_article_entry(item, SOURCE_DEFS, "gemini-2.5-flash", NOW)
        self.assertEqual(len(entry["raw_excerpt"]), 200)

    def test_raw_excerpt_is_null_when_missing(self):
        item = make_item(raw_summary="")
        entry = dj.build_article_entry(item, SOURCE_DEFS, "gemini-2.5-flash", NOW)
        self.assertIsNone(entry["raw_excerpt"])

    def test_raw_title_is_preserved(self):
        item = make_item(title="翻訳後", raw_title="Original English Title")
        entry = dj.build_article_entry(item, SOURCE_DEFS, "gemini-2.5-flash", NOW)
        self.assertEqual(entry["raw_title"], "Original English Title")
        self.assertEqual(entry["title"], "翻訳後")

    def test_published_at_is_null_when_unparseable(self):
        item = make_item(published_at_jst=None)
        entry = dj.build_article_entry(item, SOURCE_DEFS, "gemini-2.5-flash", NOW)
        self.assertIsNone(entry["published_at"])


# ── ID・ハッシュ ──────────────────────────────────────────────────────────

class IdHashTest(unittest.TestCase):
    def test_same_canonical_url_gives_same_id(self):
        item_a = make_item(link="https://example.com/a")
        item_b = make_item(link="https://example.com/a")
        entry_a = dj.build_article_entry(item_a, SOURCE_DEFS, "gemini-2.5-flash", NOW)
        entry_b = dj.build_article_entry(item_b, SOURCE_DEFS, "gemini-2.5-flash", NOW)
        self.assertEqual(entry_a["id"], entry_b["id"])

    def test_fragment_difference_does_not_change_id(self):
        item_a = make_item(link="https://example.com/a")
        item_b = make_item(link="https://example.com/a#section2")
        entry_a = dj.build_article_entry(item_a, SOURCE_DEFS, "gemini-2.5-flash", NOW)
        entry_b = dj.build_article_entry(item_b, SOURCE_DEFS, "gemini-2.5-flash", NOW)
        self.assertEqual(entry_a["id"], entry_b["id"])

    def test_scheme_and_host_case_difference_does_not_change_id(self):
        item_a = make_item(link="https://example.com/a")
        item_b = make_item(link="HTTPS://EXAMPLE.COM/a")
        entry_a = dj.build_article_entry(item_a, SOURCE_DEFS, "gemini-2.5-flash", NOW)
        entry_b = dj.build_article_entry(item_b, SOURCE_DEFS, "gemini-2.5-flash", NOW)
        self.assertEqual(entry_a["id"], entry_b["id"])

    def test_fallback_id_generated_without_canonical_url(self):
        item = make_item(link="", raw_title="Some Title")
        entry = dj.build_article_entry(item, SOURCE_DEFS, "gemini-2.5-flash", NOW)
        self.assertIsNone(entry["canonical_url"])
        self.assertTrue(entry["id"].startswith("sha256:"))

    def test_content_hash_changes_when_title_or_excerpt_changes(self):
        item_a = make_item(raw_title="Title A", raw_summary="Excerpt A")
        item_b = make_item(raw_title="Title B", raw_summary="Excerpt A")
        entry_a = dj.build_article_entry(item_a, SOURCE_DEFS, "gemini-2.5-flash", NOW)
        entry_b = dj.build_article_entry(item_b, SOURCE_DEFS, "gemini-2.5-flash", NOW)
        self.assertEqual(entry_a["id"], entry_b["id"])  # 同一URLなのでIDは同じ
        self.assertNotEqual(entry_a["content_hash"], entry_b["content_hash"])

    def test_content_hash_format(self):
        item = make_item()
        entry = dj.build_article_entry(item, SOURCE_DEFS, "gemini-2.5-flash", NOW)
        self.assertRegex(entry["content_hash"], r"^sha256:[0-9a-f]{64}$")
        self.assertRegex(entry["id"], r"^sha256:[0-9a-f]{64}$")

    def test_cisa_kev_shared_url_does_not_cause_id_collision(self):
        # CISA KEVは全記事が同一の一覧ページURLを共有する(既存fetch_cisa_kev()の
        # 仕様)。canonical_urlのみでIDを決めると異なるCVEエントリ同士が
        # 衝突してしまうため、raw_title(CVE IDを含む)で一意性を確保できることを確認する。
        shared_link = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
        item_a = make_item(
            source="CISA KEV", link=shared_link,
            raw_title="CVE-2026-0001 — Example Vulnerability A",
        )
        item_b = make_item(
            source="CISA KEV", link=shared_link,
            raw_title="CVE-2026-0002 — Example Vulnerability B",
        )
        entry_a = dj.build_article_entry(item_a, SOURCE_DEFS, "gemini-2.5-flash", NOW)
        entry_b = dj.build_article_entry(item_b, SOURCE_DEFS, "gemini-2.5-flash", NOW)
        self.assertEqual(entry_a["canonical_url"], entry_b["canonical_url"])
        self.assertNotEqual(entry_a["id"], entry_b["id"])


# ── analysis ──────────────────────────────────────────────────────────────

class AnalysisSectionTest(unittest.TestCase):
    def test_analysis_object_always_present(self):
        for meta in (None, success_meta(), failed_meta()):
            item = make_item(ai_analysis=(SAMPLE_ANALYSIS if meta and meta["status"] == "success" else None),
                              ai_analysis_meta=meta)
            entry = dj.build_article_entry(item, SOURCE_DEFS, "gemini-2.5-flash", NOW)
            self.assertIn("analysis", entry)
            self.assertIsInstance(entry["analysis"], dict)

    def test_success_saves_current_analysis_fields(self):
        item = make_item(ai_analysis=SAMPLE_ANALYSIS, ai_analysis_meta=success_meta())
        entry = dj.build_article_entry(item, SOURCE_DEFS, "gemini-2.5-flash", NOW)
        analysis = entry["analysis"]
        self.assertEqual(analysis["status"], "success")
        self.assertEqual(analysis["importance"], "高")
        self.assertEqual(analysis["summary"], "要約")
        self.assertEqual(analysis["financial_impact"], "影響")
        self.assertEqual(analysis["recommended_actions"], ["対応1"])

    def test_failed_has_null_and_empty_ai_fields(self):
        item = make_item(ai_analysis=None, ai_analysis_meta=failed_meta())
        entry = dj.build_article_entry(item, SOURCE_DEFS, "gemini-2.5-flash", NOW)
        analysis = entry["analysis"]
        self.assertEqual(analysis["status"], "failed")
        self.assertIsNone(analysis["importance"])
        self.assertIsNone(analysis["summary"])
        self.assertIsNone(analysis["financial_impact"])
        self.assertEqual(analysis["recommended_actions"], [])

    def test_no_api_key_case_is_not_attempted(self):
        item = make_item()  # ai_analysis_meta キーなし = enrich_with_ai()未実行を模す
        entry = dj.build_article_entry(item, SOURCE_DEFS, "gemini-2.5-flash", NOW)
        self.assertEqual(entry["analysis"]["status"], "not_attempted")
        self.assertIsNone(entry["analysis"]["generated_at"])

    def test_fallback_path_is_identifiable(self):
        item = make_item(ai_analysis=SAMPLE_ANALYSIS, ai_analysis_meta=fallback_meta())
        entry = dj.build_article_entry(item, SOURCE_DEFS, "gemini-2.5-flash", NOW)
        self.assertEqual(entry["analysis"]["status"], "fallback")
        self.assertEqual(entry["analysis"]["error_type"], "schema_parse_error")

    def test_secrets_and_raw_response_are_not_saved(self):
        item = make_item(ai_analysis=SAMPLE_ANALYSIS, ai_analysis_meta=success_meta())
        entry = dj.build_article_entry(item, SOURCE_DEFS, "gemini-2.5-flash", NOW)
        serialized = json.dumps(entry, ensure_ascii=False)
        for forbidden in ("GEMINI_API_KEY", "Authorization", "Bearer", "x-goog-api-key", "Traceback"):
            self.assertNotIn(forbidden, serialized)


# ── brief ─────────────────────────────────────────────────────────────────

class BriefTest(unittest.TestCase):
    def test_four_fields_are_saved_from_brief_result(self):
        digest = dj.build_daily_digest([], SUCCESS_BRIEF_RESULT, SOURCE_DEFS, "gemini-2.5-flash", NOW, NOW)
        brief = digest["brief"]
        self.assertEqual(brief["overview"], SUCCESS_BRIEF_RESULT["overview"])
        self.assertEqual(brief["important_highlights"], SUCCESS_BRIEF_RESULT["important_highlights"])
        self.assertEqual(brief["discussion_points"], SUCCESS_BRIEF_RESULT["discussion_points"])
        self.assertEqual(brief["check_items"], SUCCESS_BRIEF_RESULT["check_items"])

    def test_extractive_composition_metadata_is_saved(self):
        digest = dj.build_daily_digest([], SUCCESS_BRIEF_RESULT, SOURCE_DEFS, "gemini-2.5-flash", NOW, NOW)
        self.assertEqual(digest["brief"]["model"], "deterministic-extractive")
        self.assertEqual(digest["brief"]["prompt_version"], "today-brief-extractive-v1")
        self.assertEqual(digest["generator"]["brief_prompt_version"], "today-brief-extractive-v1")
        self.assertEqual(dj.BRIEF_MODEL, "deterministic-extractive")
        self.assertEqual(dj.BRIEF_PROMPT_VERSION, "today-brief-extractive-v1")

    def test_schema_version_stays_1(self):
        digest = dj.build_daily_digest([], SUCCESS_BRIEF_RESULT, SOURCE_DEFS, "gemini-2.5-flash", NOW, NOW)
        self.assertEqual(digest["schema_version"], 1)

    def test_success_overview_is_a_string(self):
        digest = dj.build_daily_digest([], SUCCESS_BRIEF_RESULT, SOURCE_DEFS, "gemini-2.5-flash", NOW, NOW)
        self.assertIsInstance(digest["brief"]["overview"], str)
        self.assertTrue(digest["brief"]["overview"])

    def test_failed_overview_null_and_arrays_empty(self):
        digest = dj.build_daily_digest([], FAILED_BRIEF_RESULT, SOURCE_DEFS, "gemini-2.5-flash", NOW, NOW)
        brief = digest["brief"]
        self.assertEqual(brief["status"], "failed")
        self.assertIsNone(brief["overview"])
        self.assertEqual(brief["important_highlights"], [])
        self.assertEqual(brief["discussion_points"], [])
        self.assertEqual(brief["check_items"], [])
        self.assertEqual(brief["error_type"], "schema_parse_error")

    def test_not_attempted_without_api_key_or_valid_analysis(self):
        digest = dj.build_daily_digest([], NOT_ATTEMPTED_BRIEF_RESULT, SOURCE_DEFS, "gemini-2.5-flash", NOW, NOW)
        brief = digest["brief"]
        self.assertEqual(brief["status"], "not_attempted")
        self.assertIsNone(brief["overview"])
        self.assertEqual(brief["important_highlights"], [])
        self.assertEqual(brief["discussion_points"], [])
        self.assertEqual(brief["check_items"], [])

    def test_validation_passes_for_success(self):
        digest = dj.build_daily_digest([], SUCCESS_BRIEF_RESULT, SOURCE_DEFS, "gemini-2.5-flash", NOW, NOW)
        dj.validate_daily_digest(digest)  # 例外が出なければOK

    def test_validation_passes_for_failed_and_not_attempted(self):
        for brief_result in (FAILED_BRIEF_RESULT, NOT_ATTEMPTED_BRIEF_RESULT):
            with self.subTest(status=brief_result["status"]):
                digest = dj.build_daily_digest([], brief_result, SOURCE_DEFS, "gemini-2.5-flash", NOW, NOW)
                dj.validate_daily_digest(digest)  # 例外が出なければOK

    def test_validation_rejects_success_with_empty_overview(self):
        digest = dj.build_daily_digest([], SUCCESS_BRIEF_RESULT, SOURCE_DEFS, "gemini-2.5-flash", NOW, NOW)
        digest["brief"]["overview"] = ""
        with self.assertRaises(dj.DailyJsonError):
            dj.validate_daily_digest(digest)

    def test_validation_rejects_failed_with_non_null_overview(self):
        digest = dj.build_daily_digest([], FAILED_BRIEF_RESULT, SOURCE_DEFS, "gemini-2.5-flash", NOW, NOW)
        digest["brief"]["overview"] = "前日の概況を流用"
        with self.assertRaises(dj.DailyJsonError):
            dj.validate_daily_digest(digest)

    def test_validation_rejects_too_many_highlights(self):
        digest = dj.build_daily_digest([], SUCCESS_BRIEF_RESULT, SOURCE_DEFS, "gemini-2.5-flash", NOW, NOW)
        digest["brief"]["important_highlights"] = ["a", "b", "c", "d"]
        with self.assertRaises(dj.DailyJsonError):
            dj.validate_daily_digest(digest)

    def test_validation_rejects_too_many_discussion_points(self):
        digest = dj.build_daily_digest([], SUCCESS_BRIEF_RESULT, SOURCE_DEFS, "gemini-2.5-flash", NOW, NOW)
        digest["brief"]["discussion_points"] = ["a", "b", "c", "d"]
        with self.assertRaises(dj.DailyJsonError):
            dj.validate_daily_digest(digest)

    def test_validation_rejects_too_many_check_items(self):
        digest = dj.build_daily_digest([], SUCCESS_BRIEF_RESULT, SOURCE_DEFS, "gemini-2.5-flash", NOW, NOW)
        digest["brief"]["check_items"] = ["a", "b", "c", "d", "e"]
        with self.assertRaises(dj.DailyJsonError):
            dj.validate_daily_digest(digest)

    def test_validation_rejects_non_string_array_items(self):
        digest = dj.build_daily_digest([], SUCCESS_BRIEF_RESULT, SOURCE_DEFS, "gemini-2.5-flash", NOW, NOW)
        digest["brief"]["check_items"] = [123]
        with self.assertRaises(dj.DailyJsonError):
            dj.validate_daily_digest(digest)

    def test_validation_rejects_invalid_status(self):
        digest = dj.build_daily_digest([], SUCCESS_BRIEF_RESULT, SOURCE_DEFS, "gemini-2.5-flash", NOW, NOW)
        digest["brief"]["status"] = "fallback"
        with self.assertRaises(dj.DailyJsonError):
            dj.validate_daily_digest(digest)

    def test_old_ticket3_style_digest_file_still_scans(self):
        """scan_daily_digest_files()(index再構築)はbrief内容を検証しないため、
        Ticket 3時点の旧brief形式(overview固定null等)のファイルも引き続き読み取れる。
        """
        with tempfile.TemporaryDirectory() as tmp:
            data_dir = Path(tmp)
            data_dir.mkdir(parents=True, exist_ok=True)
            old_digest = {
                "schema_version": 1,
                "digest_date": "2026-07-01",
                "generated_at": "2026-07-01T07:00:00+09:00",
                "generator": {
                    "application": "security-digest", "model": "gemini-2.5-flash",
                    "article_prompt_version": "article-analysis-v2",
                    "brief_prompt_version": "executive-summary-v1",
                },
                "run": {"status": "not_attempted", "overwrite_policy": "replace", "total_items": 0,
                        "ai_attempted_count": 0, "ai_success_count": 0, "ai_fallback_count": 0,
                        "ai_failed_count": 0, "ai_not_attempted_count": 0},
                "counts": {
                    "importance": {k: 0 for k in dj.IMPORTANCE_KEYS},
                    "urgency": {k: 0 for k in dj.URGENCY_KEYS},
                    "category": {k: 0 for k in dj.CATEGORY_KEYS},
                },
                "brief": {
                    "status": "not_attempted", "model": "gemini-2.5-flash",
                    "prompt_version": "executive-summary-v1", "overview": None,
                    "important_highlights": [], "discussion_points": [], "check_items": [],
                    "error_type": None,
                },
                "items": [],
            }
            (data_dir / "2026-07-01.json").write_text(
                json.dumps(old_digest, ensure_ascii=False, indent=2), encoding="utf-8"
            )
            entries = dj.scan_daily_digest_files(data_dir)
            self.assertEqual(len(entries), 1)
            self.assertEqual(entries[0]["digest_date"], "2026-07-01")


# ── ファイル保存 ──────────────────────────────────────────────────────────

class FileSaveTest(unittest.TestCase):
    def test_data_dir_created_if_missing(self):
        with tempfile.TemporaryDirectory() as tmp:
            data_dir = Path(tmp) / "nested" / "data"
            self.assertFalse(data_dir.exists())
            digest = dj.build_daily_digest([], NOT_ATTEMPTED_BRIEF_RESULT,
                                            SOURCE_DEFS, "gemini-2.5-flash", NOW, NOW)
            dj.save_daily_digest(digest, data_dir)
            self.assertTrue(data_dir.exists())

    def test_saved_via_temp_file_no_leftover_tmp(self):
        with tempfile.TemporaryDirectory() as tmp:
            data_dir = Path(tmp)
            digest = dj.build_daily_digest([], NOT_ATTEMPTED_BRIEF_RESULT,
                                            SOURCE_DEFS, "gemini-2.5-flash", NOW, NOW)
            dj.save_daily_digest(digest, data_dir)
            leftover = [p for p in data_dir.iterdir() if p.suffix == ".tmp"]
            self.assertEqual(leftover, [])

    def test_same_day_rerun_fully_overwrites(self):
        with tempfile.TemporaryDirectory() as tmp:
            data_dir = Path(tmp)
            item1 = make_item(ai_analysis=SAMPLE_ANALYSIS, ai_analysis_meta=success_meta())
            digest1 = dj.build_daily_digest([item1], NOT_ATTEMPTED_BRIEF_RESULT,
                                             SOURCE_DEFS, "gemini-2.5-flash", NOW, NOW)
            path = dj.save_daily_digest(digest1, data_dir)
            self.assertEqual(json.loads(path.read_text())["run"]["total_items"], 1)

            digest2 = dj.build_daily_digest([], NOT_ATTEMPTED_BRIEF_RESULT,
                                             SOURCE_DEFS, "gemini-2.5-flash", NOW, NOW)
            dj.save_daily_digest(digest2, data_dir)
            self.assertEqual(json.loads(path.read_text())["run"]["total_items"], 0)

    def test_same_day_data_not_duplicated_on_disk(self):
        with tempfile.TemporaryDirectory() as tmp:
            data_dir = Path(tmp)
            digest = dj.build_daily_digest([], NOT_ATTEMPTED_BRIEF_RESULT,
                                            SOURCE_DEFS, "gemini-2.5-flash", NOW, NOW)
            dj.save_daily_digest(digest, data_dir)
            dj.save_daily_digest(digest, data_dir)
            files = [p.name for p in data_dir.glob("*.json")]
            self.assertEqual(files.count("2026-07-11.json"), 1)

    def test_saved_json_reloads_successfully(self):
        with tempfile.TemporaryDirectory() as tmp:
            data_dir = Path(tmp)
            item = make_item(ai_analysis=SAMPLE_ANALYSIS, ai_analysis_meta=success_meta())
            digest = dj.build_daily_digest([item], NOT_ATTEMPTED_BRIEF_RESULT,
                                            SOURCE_DEFS, "gemini-2.5-flash", NOW, NOW)
            path = dj.save_daily_digest(digest, data_dir)
            reloaded = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(reloaded["run"]["total_items"], 1)

    def test_validation_failure_does_not_corrupt_existing_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            data_dir = Path(tmp)
            good_digest = dj.build_daily_digest([], NOT_ATTEMPTED_BRIEF_RESULT,
                                                 SOURCE_DEFS, "gemini-2.5-flash", NOW, NOW)
            path = dj.save_daily_digest(good_digest, data_dir)
            original_content = path.read_text(encoding="utf-8")

            broken_digest = dict(good_digest)
            broken_digest["run"] = dict(good_digest["run"])
            broken_digest["run"]["total_items"] = 999  # items件数と不一致にする

            with self.assertRaises(dj.DailyJsonError):
                dj.save_daily_digest(broken_digest, data_dir)

            self.assertEqual(path.read_text(encoding="utf-8"), original_content)
            leftover = [p for p in data_dir.iterdir() if p.suffix == ".tmp"]
            self.assertEqual(leftover, [])


# ── facts (Ticket 12a) ──────────────────────────────────────────────────

SAMPLE_NVD_FOUND = {
    "status": "found", "retrieval": "live", "fetched_at": "2026-07-12T01:00:00Z",
    "url": "https://nvd.nist.gov/vuln/detail/CVE-2026-1234",
    "vuln_status": "Analyzed", "published_at": "2026-07-10T00:00:00Z",
    "last_modified_at": "2026-07-11T00:00:00Z",
    "cvss": {"version": "3.1", "base_score": 9.8, "base_severity": "CRITICAL",
             "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
             "source": "nvd@nist.gov", "type": "Primary"},
}

SAMPLE_KEV_LISTED = {
    "status": "listed", "retrieval": "live",
    "fetched_at": "2026-07-12T01:00:00Z", "date_added": "2026-07-11",
}

SAMPLE_NVD_NOT_FOUND = {
    "status": "not_found", "retrieval": "live", "fetched_at": "2026-07-12T01:00:00Z",
    "url": "https://nvd.nist.gov/vuln/detail/CVE-2026-9999",
    "vuln_status": None, "published_at": None, "last_modified_at": None, "cvss": None,
}

SAMPLE_KEV_NOT_LISTED = {
    "status": "not_listed", "retrieval": "live",
    "fetched_at": "2026-07-12T01:00:00Z", "date_added": None,
}

SAMPLE_NVD_UNAVAILABLE = {
    "status": "unavailable", "retrieval": "unavailable", "fetched_at": None,
    "url": "https://nvd.nist.gov/vuln/detail/CVE-2026-5555",
    "vuln_status": None, "published_at": None, "last_modified_at": None, "cvss": None,
}

SAMPLE_KEV_UNKNOWN = {
    "status": "unknown", "retrieval": "unavailable", "fetched_at": None, "date_added": None,
}


class FactsFieldTest(unittest.TestCase):
    def test_article_without_cve_gets_empty_cves_list(self):
        item = make_item(ai_analysis=SAMPLE_ANALYSIS, ai_analysis_meta=success_meta())
        entry = dj.build_article_entry(item, SOURCE_DEFS, "gemini-2.5-flash", NOW)
        self.assertEqual(entry["facts"], {"cves": []})

    def test_facts_key_is_never_omitted(self):
        item = make_item(ai_analysis=SAMPLE_ANALYSIS, ai_analysis_meta=success_meta())
        entry = dj.build_article_entry(item, SOURCE_DEFS, "gemini-2.5-flash", NOW)
        self.assertIn("facts", entry)

    def test_single_cve_facts_are_saved_as_is(self):
        item = make_item(
            ai_analysis=SAMPLE_ANALYSIS, ai_analysis_meta=success_meta(),
            facts={"cves": [{"cve_id": "CVE-2026-1234", "nvd": SAMPLE_NVD_FOUND, "kev": SAMPLE_KEV_LISTED}]},
        )
        entry = dj.build_article_entry(item, SOURCE_DEFS, "gemini-2.5-flash", NOW)
        self.assertEqual(len(entry["facts"]["cves"]), 1)
        self.assertEqual(entry["facts"]["cves"][0]["cve_id"], "CVE-2026-1234")
        self.assertEqual(entry["facts"]["cves"][0]["nvd"]["cvss"]["base_score"], 9.8)

    def test_multiple_cve_order_is_preserved(self):
        cves = [
            {"cve_id": "CVE-2026-0002", "nvd": SAMPLE_NVD_NOT_FOUND, "kev": SAMPLE_KEV_NOT_LISTED},
            {"cve_id": "CVE-2026-0001", "nvd": SAMPLE_NVD_FOUND, "kev": SAMPLE_KEV_LISTED},
        ]
        item = make_item(ai_analysis=SAMPLE_ANALYSIS, ai_analysis_meta=success_meta(), facts={"cves": cves})
        entry = dj.build_article_entry(item, SOURCE_DEFS, "gemini-2.5-flash", NOW)
        self.assertEqual([c["cve_id"] for c in entry["facts"]["cves"]], ["CVE-2026-0002", "CVE-2026-0001"])

    def test_not_found_nullable_fields_pass_validation(self):
        item = make_item(
            ai_analysis=SAMPLE_ANALYSIS, ai_analysis_meta=success_meta(),
            facts={"cves": [{"cve_id": "CVE-2026-9999", "nvd": SAMPLE_NVD_NOT_FOUND, "kev": SAMPLE_KEV_NOT_LISTED}]},
        )
        digest = dj.build_daily_digest([item], SUCCESS_BRIEF_RESULT, SOURCE_DEFS, "gemini-2.5-flash", NOW, NOW)
        dj.validate_daily_digest(digest)  # 例外が出なければOK

    def test_unavailable_nullable_fields_pass_validation(self):
        item = make_item(
            ai_analysis=SAMPLE_ANALYSIS, ai_analysis_meta=success_meta(),
            facts={"cves": [{"cve_id": "CVE-2026-5555", "nvd": SAMPLE_NVD_UNAVAILABLE, "kev": SAMPLE_KEV_UNKNOWN}]},
        )
        digest = dj.build_daily_digest([item], SUCCESS_BRIEF_RESULT, SOURCE_DEFS, "gemini-2.5-flash", NOW, NOW)
        dj.validate_daily_digest(digest)  # 例外が出なければOK

    def test_validation_rejects_missing_facts(self):
        item = make_item(ai_analysis=SAMPLE_ANALYSIS, ai_analysis_meta=success_meta())
        digest = dj.build_daily_digest([item], SUCCESS_BRIEF_RESULT, SOURCE_DEFS, "gemini-2.5-flash", NOW, NOW)
        digest["items"][0]["facts"] = None
        with self.assertRaises(dj.DailyJsonError):
            dj.validate_daily_digest(digest)

    def test_validation_rejects_non_list_cves(self):
        item = make_item(ai_analysis=SAMPLE_ANALYSIS, ai_analysis_meta=success_meta())
        digest = dj.build_daily_digest([item], SUCCESS_BRIEF_RESULT, SOURCE_DEFS, "gemini-2.5-flash", NOW, NOW)
        digest["items"][0]["facts"] = {"cves": "not-a-list"}
        with self.assertRaises(dj.DailyJsonError):
            dj.validate_daily_digest(digest)

    def test_validation_rejects_cve_entry_without_cve_id(self):
        item = make_item(ai_analysis=SAMPLE_ANALYSIS, ai_analysis_meta=success_meta())
        digest = dj.build_daily_digest([item], SUCCESS_BRIEF_RESULT, SOURCE_DEFS, "gemini-2.5-flash", NOW, NOW)
        digest["items"][0]["facts"] = {"cves": [{"nvd": SAMPLE_NVD_FOUND, "kev": SAMPLE_KEV_LISTED}]}
        with self.assertRaises(dj.DailyJsonError):
            dj.validate_daily_digest(digest)

    def test_schema_version_stays_1_with_facts_present(self):
        item = make_item(
            ai_analysis=SAMPLE_ANALYSIS, ai_analysis_meta=success_meta(),
            facts={"cves": [{"cve_id": "CVE-2026-1234", "nvd": SAMPLE_NVD_FOUND, "kev": SAMPLE_KEV_LISTED}]},
        )
        digest = dj.build_daily_digest([item], SUCCESS_BRIEF_RESULT, SOURCE_DEFS, "gemini-2.5-flash", NOW, NOW)
        self.assertEqual(digest["schema_version"], 1)

    def test_article_prompt_version_unaffected_by_facts(self):
        item = make_item(
            ai_analysis=SAMPLE_ANALYSIS, ai_analysis_meta=success_meta(),
            facts={"cves": [{"cve_id": "CVE-2026-1234", "nvd": SAMPLE_NVD_FOUND, "kev": SAMPLE_KEV_LISTED}]},
        )
        digest = dj.build_daily_digest([item], SUCCESS_BRIEF_RESULT, SOURCE_DEFS, "gemini-2.5-flash", NOW, NOW)
        self.assertEqual(digest["generator"]["article_prompt_version"], dj.ARTICLE_PROMPT_VERSION)
        self.assertEqual(digest["generator"]["article_prompt_version"], "article-analysis-v8")


# ── facts契約の強化 (Ticket 12a-review #4) ──────────────────────────────────

class FactsContractTest(unittest.TestCase):
    def test_falsy_but_present_facts_is_not_replaced_by_default(self):
        # item.get("facts") or {...} をやめたため、facts={}のような壊れた値が
        # 渡された場合はデフォルトへフォールバックせず、そのまま保持される
        # (validate_daily_digest側の検証で検出させる)。
        item = make_item(ai_analysis=SAMPLE_ANALYSIS, ai_analysis_meta=success_meta(), facts={})
        entry = dj.build_article_entry(item, SOURCE_DEFS, "gemini-2.5-flash", NOW)
        self.assertEqual(entry["facts"], {})

    def test_missing_facts_key_still_defaults_to_empty_cves(self):
        item = make_item(ai_analysis=SAMPLE_ANALYSIS, ai_analysis_meta=success_meta())
        self.assertNotIn("facts", item)
        entry = dj.build_article_entry(item, SOURCE_DEFS, "gemini-2.5-flash", NOW)
        self.assertEqual(entry["facts"], {"cves": []})

    def _digest_with_facts(self, facts):
        item = make_item(ai_analysis=SAMPLE_ANALYSIS, ai_analysis_meta=success_meta(), facts=facts)
        return dj.build_daily_digest([item], SUCCESS_BRIEF_RESULT, SOURCE_DEFS, "gemini-2.5-flash", NOW, NOW)

    def test_falsy_facts_dict_fails_validation(self):
        digest = self._digest_with_facts({})
        with self.assertRaises(dj.DailyJsonError):
            dj.validate_daily_digest(digest)

    def test_invalid_cve_id_format_is_rejected(self):
        digest = self._digest_with_facts({"cves": [
            {"cve_id": "NOT-A-CVE", "nvd": SAMPLE_NVD_NOT_FOUND, "kev": SAMPLE_KEV_NOT_LISTED},
        ]})
        with self.assertRaises(dj.DailyJsonError):
            dj.validate_daily_digest(digest)

    def test_nvd_not_a_dict_is_rejected(self):
        digest = self._digest_with_facts({"cves": [
            {"cve_id": "CVE-2026-0001", "nvd": "not-a-dict", "kev": SAMPLE_KEV_NOT_LISTED},
        ]})
        with self.assertRaises(dj.DailyJsonError):
            dj.validate_daily_digest(digest)

    def test_kev_not_a_dict_is_rejected(self):
        digest = self._digest_with_facts({"cves": [
            {"cve_id": "CVE-2026-0001", "nvd": SAMPLE_NVD_NOT_FOUND, "kev": "not-a-dict"},
        ]})
        with self.assertRaises(dj.DailyJsonError):
            dj.validate_daily_digest(digest)

    def test_nvd_status_out_of_range_is_rejected(self):
        bad_nvd = {**SAMPLE_NVD_NOT_FOUND, "status": "maybe_found"}
        digest = self._digest_with_facts({"cves": [
            {"cve_id": "CVE-2026-0001", "nvd": bad_nvd, "kev": SAMPLE_KEV_NOT_LISTED},
        ]})
        with self.assertRaises(dj.DailyJsonError):
            dj.validate_daily_digest(digest)

    def test_kev_status_out_of_range_is_rejected(self):
        bad_kev = {**SAMPLE_KEV_NOT_LISTED, "status": "maybe_listed"}
        digest = self._digest_with_facts({"cves": [
            {"cve_id": "CVE-2026-0001", "nvd": SAMPLE_NVD_NOT_FOUND, "kev": bad_kev},
        ]})
        with self.assertRaises(dj.DailyJsonError):
            dj.validate_daily_digest(digest)

    def test_retrieval_out_of_range_is_rejected(self):
        bad_nvd = {**SAMPLE_NVD_NOT_FOUND, "retrieval": "from_the_future"}
        digest = self._digest_with_facts({"cves": [
            {"cve_id": "CVE-2026-0001", "nvd": bad_nvd, "kev": SAMPLE_KEV_NOT_LISTED},
        ]})
        with self.assertRaises(dj.DailyJsonError):
            dj.validate_daily_digest(digest)

    def test_valid_facts_pass_validation(self):
        digest = self._digest_with_facts({"cves": [
            {"cve_id": "CVE-2026-1234", "nvd": SAMPLE_NVD_FOUND, "kev": SAMPLE_KEV_LISTED},
        ]})
        dj.validate_daily_digest(digest)  # 例外が出なければOK


# ── index.json ────────────────────────────────────────────────────────────

class IndexTest(unittest.TestCase):
    def _make_daily_file(self, data_dir, digest_date, total_items=1, high_count=0, status="success"):
        digest = {
            "schema_version": 1,
            "digest_date": digest_date,
            "generated_at": f"{digest_date}T07:00:00+09:00",
            "generator": {"application": "security-digest", "model": "gemini-2.5-flash",
                          "article_prompt_version": "v1", "brief_prompt_version": "v1"},
            "run": {"status": status, "overwrite_policy": "replace", "total_items": total_items,
                    "ai_attempted_count": 0, "ai_success_count": 0, "ai_fallback_count": 0,
                    "ai_failed_count": 0, "ai_not_attempted_count": total_items},
            "counts": {
                "importance": {"高": high_count, "中": 0, "低": 0, "未判定": total_items - high_count},
                "urgency": {"本日確認": 0, "今週確認": 0, "参考": 0, "未判定": total_items},
                "category": {k: 0 for k in dj.CATEGORY_KEYS[:-1]} | {"未判定": total_items},
            },
            "brief": {"status": "not_attempted", "model": "gemini-2.5-flash", "prompt_version": "v1",
                      "overview": None, "important_highlights": [], "discussion_points": [],
                      "check_items": [], "error_type": None},
            "items": [],
        }
        (data_dir / f"{digest_date}.json").write_text(
            json.dumps(digest, ensure_ascii=False, indent=2), encoding="utf-8"
        )

    def test_index_is_generated(self):
        with tempfile.TemporaryDirectory() as tmp:
            data_dir = Path(tmp)
            self._make_daily_file(data_dir, "2026-07-10")
            path = dj.save_index(data_dir, NOW)
            self.assertTrue(path.exists())

    def test_digest_date_descending_order(self):
        with tempfile.TemporaryDirectory() as tmp:
            data_dir = Path(tmp)
            self._make_daily_file(data_dir, "2026-07-09")
            self._make_daily_file(data_dir, "2026-07-11")
            self._make_daily_file(data_dir, "2026-07-10")
            index = dj.build_index(data_dir, NOW)
            dates = [d["digest_date"] for d in index["digests"]]
            self.assertEqual(dates, ["2026-07-11", "2026-07-10", "2026-07-09"])

    def test_no_duplicate_digest_dates(self):
        with tempfile.TemporaryDirectory() as tmp:
            data_dir = Path(tmp)
            self._make_daily_file(data_dir, "2026-07-11", total_items=1)
            # 同一日付を再実行(完全上書き)した状態を模す
            self._make_daily_file(data_dir, "2026-07-11", total_items=5)
            index = dj.build_index(data_dir, NOW)
            dates = [d["digest_date"] for d in index["digests"]]
            self.assertEqual(dates.count("2026-07-11"), 1)
            self.assertEqual(index["digests"][0]["total_items"], 5)

    def test_high_count_matches_daily_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            data_dir = Path(tmp)
            self._make_daily_file(data_dir, "2026-07-11", total_items=3, high_count=2)
            index = dj.build_index(data_dir, NOW)
            self.assertEqual(index["digests"][0]["high_count"], 2)

    def test_ai_run_status_matches_daily_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            data_dir = Path(tmp)
            self._make_daily_file(data_dir, "2026-07-11", status="partial")
            index = dj.build_index(data_dir, NOW)
            self.assertEqual(index["digests"][0]["ai_run_status"], "partial")

    def test_archive_path_is_null(self):
        with tempfile.TemporaryDirectory() as tmp:
            data_dir = Path(tmp)
            self._make_daily_file(data_dir, "2026-07-11")
            index = dj.build_index(data_dir, NOW)
            self.assertIsNone(index["digests"][0]["archive_path"])

    def test_invalid_existing_daily_json_raises_clear_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            data_dir = Path(tmp)
            bad_path = data_dir / "2026-07-11.json"
            data_dir.mkdir(parents=True, exist_ok=True)
            bad_path.write_text("{ not valid json", encoding="utf-8")
            with self.assertRaises(dj.DailyJsonError) as ctx:
                dj.scan_daily_digest_files(data_dir)
            self.assertIn("2026-07-11.json", str(ctx.exception))

    def test_missing_schema_version_in_existing_file_raises_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            data_dir = Path(tmp)
            data_dir.mkdir(parents=True, exist_ok=True)
            (data_dir / "2026-07-11.json").write_text(
                json.dumps({"digest_date": "2026-07-11", "generated_at": "x"}), encoding="utf-8"
            )
            with self.assertRaises(dj.DailyJsonError):
                dj.scan_daily_digest_files(data_dir)

    def test_vulnerability_facts_cache_file_excluded_from_index(self):
        # Ticket 12a: data/vulnerability_facts_cache.jsonは日別ダイジェストではない。
        # DAILY_FILENAME_REがYYYY-MM-DD.json形式のみに一致するため、この
        # キャッシュファイルはdata/index.jsonのdigestsへ混入してはならない。
        with tempfile.TemporaryDirectory() as tmp:
            data_dir = Path(tmp)
            self._make_daily_file(data_dir, "2026-07-11")
            (data_dir / "vulnerability_facts_cache.json").write_text(
                json.dumps({"schema_version": 1, "nvd": {}, "kev": {"fetched_at": None, "entries": {}}}),
                encoding="utf-8",
            )
            index = dj.build_index(data_dir, NOW)
            paths = [d["path"] for d in index["digests"]]
            self.assertEqual(len(index["digests"]), 1)
            self.assertNotIn("data/vulnerability_facts_cache.json", paths)

    def test_vulnerability_facts_cache_file_not_treated_as_daily_digest(self):
        self.assertFalse(dj.DAILY_FILENAME_RE.fullmatch("vulnerability_facts_cache.json"))

    def test_malformed_cache_file_does_not_break_index_rebuild(self):
        # キャッシュファイル自体が壊れていても(facts取得側の破損キャッシュ処理とは
        # 別に)、日次ダイジェストの走査対象外である以上、index再構築には影響しない。
        with tempfile.TemporaryDirectory() as tmp:
            data_dir = Path(tmp)
            self._make_daily_file(data_dir, "2026-07-11")
            (data_dir / "vulnerability_facts_cache.json").write_text("{ not valid json", encoding="utf-8")
            index = dj.build_index(data_dir, NOW)  # 例外が出なければOK
            self.assertEqual(len(index["digests"]), 1)


# ── 回帰: build_htmlは表示対象外の保存用メタデータを表示しない ────────────

class BuildHtmlRegressionTest(unittest.TestCase):
    def test_non_display_storage_metadata_keys_do_not_affect_build_html_output(self):
        base_item = {
            "title": "テスト記事", "link": "https://example.com/article",
            "summary": "概要文", "date": None, "source": "CISA", "lang": "ja",
        }
        html_without_new_keys = fetch.build_html([dict(base_item)])

        item_with_new_keys = dict(base_item)
        item_with_new_keys.update({
            "raw_summary": "<p>raw</p>",
            "ai_analysis_meta": {"status": "success", "error_type": None,
                                  "http_status": None, "generated_at": NOW.isoformat()},
        })
        html_with_new_keys = fetch.build_html([item_with_new_keys])

        self.assertEqual(html_without_new_keys, html_with_new_keys)

    def test_raw_title_is_used_as_primary_title_for_english_article(self):
        item = {
            "title": "日本語タイトル", "raw_title": "Raw English Title",
            "link": "https://example.com/article", "summary": "概要文",
            "date": None, "source": "CISA", "lang": "en",
        }
        html = fetch.build_html([item])

        self.assertIn("Raw English Title", html)
        self.assertIn("日本語タイトル", html)
        self.assertLess(html.index("Raw English Title"), html.index("日本語タイトル"))


if __name__ == "__main__":
    unittest.main()
