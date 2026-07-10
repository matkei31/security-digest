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
            items, {"lines": None, "status": "not_attempted", "error_type": None, "http_status": None},
            SOURCE_DEFS, "gemini-2.5-flash", NOW, NOW,
        )
        dj.validate_daily_digest(digest)  # 例外が出なければOK
        error_types = {item["analysis"]["error_type"] for item in digest["items"]}
        self.assertEqual(error_types, {"permission_denied", "resource_exhausted"})


# ── スキーマ・メタ情報 ────────────────────────────────────────────────────

class SchemaMetaTest(unittest.TestCase):
    def test_generates_valid_daily_digest(self):
        item = make_item(ai_analysis=SAMPLE_ANALYSIS, ai_analysis_meta=success_meta())
        exec_result = {"lines": ["行1", "行2"], "status": "success", "error_type": None, "http_status": None}
        digest = dj.build_daily_digest([item], exec_result, SOURCE_DEFS, "gemini-2.5-flash", NOW, NOW)
        dj.validate_daily_digest(digest)  # 例外が出なければOK

    def test_schema_version_is_1(self):
        digest = dj.build_daily_digest([], {"lines": None, "status": "not_attempted", "error_type": None, "http_status": None},
                                        SOURCE_DEFS, "gemini-2.5-flash", NOW, NOW)
        self.assertEqual(digest["schema_version"], 1)
        self.assertIsInstance(digest["schema_version"], int)

    def test_digest_date_is_jst_based(self):
        # UTC 15:30 = JST 翌日00:30 となるケースでdigest_dateがJST日付になることを確認
        generated_at_jst = datetime.datetime(2026, 7, 12, 0, 30, tzinfo=JST)
        digest = dj.build_daily_digest([], {"lines": None, "status": "not_attempted", "error_type": None, "http_status": None},
                                        SOURCE_DEFS, "gemini-2.5-flash", NOW, generated_at_jst)
        self.assertEqual(digest["digest_date"], "2026-07-12")

    def test_generated_at_has_timezone(self):
        digest = dj.build_daily_digest([], {"lines": None, "status": "not_attempted", "error_type": None, "http_status": None},
                                        SOURCE_DEFS, "gemini-2.5-flash", NOW, NOW)
        parsed = datetime.datetime.fromisoformat(digest["generated_at"])
        self.assertIsNotNone(parsed.tzinfo)

    def test_generator_model_and_prompt_versions_are_set(self):
        digest = dj.build_daily_digest([], {"lines": None, "status": "not_attempted", "error_type": None, "http_status": None},
                                        SOURCE_DEFS, "gemini-2.5-flash", NOW, NOW)
        self.assertEqual(digest["generator"]["model"], "gemini-2.5-flash")
        self.assertEqual(digest["generator"]["article_prompt_version"], dj.ARTICLE_PROMPT_VERSION)
        self.assertEqual(digest["generator"]["brief_prompt_version"], dj.BRIEF_PROMPT_VERSION)

    def test_total_items_matches_items_length(self):
        items = [make_item(ai_analysis=SAMPLE_ANALYSIS, ai_analysis_meta=success_meta()) for _ in range(3)]
        digest = dj.build_daily_digest(items, {"lines": None, "status": "not_attempted", "error_type": None, "http_status": None},
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
        return dj.build_daily_digest(items, {"lines": None, "status": "not_attempted", "error_type": None, "http_status": None},
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
        digest = dj.build_daily_digest(items, {"lines": None, "status": "not_attempted", "error_type": None, "http_status": None},
                                        SOURCE_DEFS, "gemini-2.5-flash", NOW, NOW)
        self.assertEqual(digest["run"]["status"], "not_attempted")

    def test_zero_items_is_success(self):
        digest = dj.build_daily_digest([], {"lines": None, "status": "not_attempted", "error_type": None, "http_status": None},
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
        digest = dj.build_daily_digest(items, {"lines": None, "status": "not_attempted", "error_type": None, "http_status": None},
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
        digest = dj.build_daily_digest(items, {"lines": None, "status": "not_attempted", "error_type": None, "http_status": None},
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
        digest = dj.build_daily_digest(items, {"lines": None, "status": "not_attempted", "error_type": None, "http_status": None},
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
    def test_current_summary_lines_go_into_important_highlights(self):
        exec_result = {"lines": ["行1", "行2", "行3"], "status": "success", "error_type": None, "http_status": None}
        digest = dj.build_daily_digest([], exec_result, SOURCE_DEFS, "gemini-2.5-flash", NOW, NOW)
        self.assertEqual(digest["brief"]["important_highlights"], ["行1", "行2", "行3"])

    def test_overview_is_null(self):
        exec_result = {"lines": ["行1", "行2"], "status": "success", "error_type": None, "http_status": None}
        digest = dj.build_daily_digest([], exec_result, SOURCE_DEFS, "gemini-2.5-flash", NOW, NOW)
        self.assertIsNone(digest["brief"]["overview"])

    def test_discussion_points_and_check_items_are_empty_arrays(self):
        exec_result = {"lines": ["行1", "行2"], "status": "success", "error_type": None, "http_status": None}
        digest = dj.build_daily_digest([], exec_result, SOURCE_DEFS, "gemini-2.5-flash", NOW, NOW)
        self.assertEqual(digest["brief"]["discussion_points"], [])
        self.assertEqual(digest["brief"]["check_items"], [])

    def test_not_attempted_without_api_key_or_high_items(self):
        exec_result = {"lines": None, "status": "not_attempted", "error_type": None, "http_status": None}
        digest = dj.build_daily_digest([], exec_result, SOURCE_DEFS, "gemini-2.5-flash", NOW, NOW)
        self.assertEqual(digest["brief"]["status"], "not_attempted")
        self.assertEqual(digest["brief"]["important_highlights"], [])


# ── ファイル保存 ──────────────────────────────────────────────────────────

class FileSaveTest(unittest.TestCase):
    def test_data_dir_created_if_missing(self):
        with tempfile.TemporaryDirectory() as tmp:
            data_dir = Path(tmp) / "nested" / "data"
            self.assertFalse(data_dir.exists())
            digest = dj.build_daily_digest([], {"lines": None, "status": "not_attempted", "error_type": None, "http_status": None},
                                            SOURCE_DEFS, "gemini-2.5-flash", NOW, NOW)
            dj.save_daily_digest(digest, data_dir)
            self.assertTrue(data_dir.exists())

    def test_saved_via_temp_file_no_leftover_tmp(self):
        with tempfile.TemporaryDirectory() as tmp:
            data_dir = Path(tmp)
            digest = dj.build_daily_digest([], {"lines": None, "status": "not_attempted", "error_type": None, "http_status": None},
                                            SOURCE_DEFS, "gemini-2.5-flash", NOW, NOW)
            dj.save_daily_digest(digest, data_dir)
            leftover = [p for p in data_dir.iterdir() if p.suffix == ".tmp"]
            self.assertEqual(leftover, [])

    def test_same_day_rerun_fully_overwrites(self):
        with tempfile.TemporaryDirectory() as tmp:
            data_dir = Path(tmp)
            item1 = make_item(ai_analysis=SAMPLE_ANALYSIS, ai_analysis_meta=success_meta())
            digest1 = dj.build_daily_digest([item1], {"lines": None, "status": "not_attempted", "error_type": None, "http_status": None},
                                             SOURCE_DEFS, "gemini-2.5-flash", NOW, NOW)
            path = dj.save_daily_digest(digest1, data_dir)
            self.assertEqual(json.loads(path.read_text())["run"]["total_items"], 1)

            digest2 = dj.build_daily_digest([], {"lines": None, "status": "not_attempted", "error_type": None, "http_status": None},
                                             SOURCE_DEFS, "gemini-2.5-flash", NOW, NOW)
            dj.save_daily_digest(digest2, data_dir)
            self.assertEqual(json.loads(path.read_text())["run"]["total_items"], 0)

    def test_same_day_data_not_duplicated_on_disk(self):
        with tempfile.TemporaryDirectory() as tmp:
            data_dir = Path(tmp)
            digest = dj.build_daily_digest([], {"lines": None, "status": "not_attempted", "error_type": None, "http_status": None},
                                            SOURCE_DEFS, "gemini-2.5-flash", NOW, NOW)
            dj.save_daily_digest(digest, data_dir)
            dj.save_daily_digest(digest, data_dir)
            files = [p.name for p in data_dir.glob("*.json")]
            self.assertEqual(files.count("2026-07-11.json"), 1)

    def test_saved_json_reloads_successfully(self):
        with tempfile.TemporaryDirectory() as tmp:
            data_dir = Path(tmp)
            item = make_item(ai_analysis=SAMPLE_ANALYSIS, ai_analysis_meta=success_meta())
            digest = dj.build_daily_digest([item], {"lines": None, "status": "not_attempted", "error_type": None, "http_status": None},
                                            SOURCE_DEFS, "gemini-2.5-flash", NOW, NOW)
            path = dj.save_daily_digest(digest, data_dir)
            reloaded = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(reloaded["run"]["total_items"], 1)

    def test_validation_failure_does_not_corrupt_existing_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            data_dir = Path(tmp)
            good_digest = dj.build_daily_digest([], {"lines": None, "status": "not_attempted", "error_type": None, "http_status": None},
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


# ── 回帰: build_htmlの出力がTicket 3前後で変わらない ────────────────────────

class BuildHtmlRegressionTest(unittest.TestCase):
    def test_new_item_keys_do_not_affect_build_html_output(self):
        base_item = {
            "title": "テスト記事", "link": "https://example.com/article",
            "summary": "概要文", "date": None, "source": "CISA", "lang": "ja",
        }
        html_without_new_keys = fetch.build_html([dict(base_item)])

        item_with_new_keys = dict(base_item)
        item_with_new_keys.update({
            "raw_title": "Raw Title", "raw_summary": "<p>raw</p>",
            "published_at_jst": NOW,
            "ai_analysis_meta": {"status": "success", "error_type": None,
                                  "http_status": None, "generated_at": NOW.isoformat()},
        })
        html_with_new_keys = fetch.build_html([item_with_new_keys])

        self.assertEqual(html_without_new_keys, html_with_new_keys)


if __name__ == "__main__":
    unittest.main()
