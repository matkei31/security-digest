#!/usr/bin/env python3
"""
Gemini個別記事分析プロンプト拡張の回帰テスト (Ticket 4)
標準ライブラリの unittest のみを使用する。実際のGemini APIは一切呼ばない
(urllib.request.urlopenをモックに差し替える)。
"""

import json
import os
import unittest
import urllib.error
from unittest.mock import patch

import daily_json as dj
import fetch


class FakeHTTPResponse:
    """urllib.request.urlopen()のコンテキストマネージャ互換フェイク。"""

    def __init__(self, body_bytes):
        self._body = body_bytes

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        return False


def make_candidate_body(analysis_dict):
    """Gemini generateContent の正常応答envelopeを組み立てる。"""
    return json.dumps({
        "candidates": [{
            "content": {
                "parts": [{"text": json.dumps(analysis_dict, ensure_ascii=False)}]
            }
        }]
    }).encode("utf-8")


def make_candidate_body_from_raw(raw_text):
    """意図的に壊れた/不完全なJSON文字列をそのままparts[0].textに埋め込んで
    envelopeを組み立てる(fallback/failed境界のテスト用)。"""
    return json.dumps({
        "candidates": [{
            "content": {
                "parts": [{"text": raw_text}]
            }
        }]
    }).encode("utf-8")


VALID_ANALYSIS_RESPONSE = {
    "category": "脆弱性・パッチ",
    "category_reason": "CVEとKEV追加が主題であり、製品脆弱性への対応を扱う記事のため。",
    "importance": "高",
    "urgency": "本日確認",
    "summary": "CISAが実際の悪用が確認された脆弱性をKEVカタログに追加した。",
    "financial_impact": "該当製品を利用する金融機関では、外部公開システムへの影響確認が必要になり得る。",
    "recommended_actions": ["該当製品の利用有無を確認する", "外部公開状況とパッチ適用状況を確認する"],
    "reason": "悪用確認済み脆弱性であり、外部公開システムに影響し得るため重要度を高、本日中の確認が望ましい。",
    "tags": ["KEV", "悪用確認済み", "パッチ"],
}


def call_gemini_analyze(text="source_name: CISA\ntitle: test\n", *, response_body=None,
                         side_effect=None, capture_requests=None):
    """GEMINI_API_KEYを一時設定し、urllib.request.urlopenをモックしてgemini_analyze()を呼ぶ。"""
    if capture_requests is None:
        capture_requests = []

    def fake_urlopen(req, timeout=None):
        capture_requests.append(req)
        if side_effect is not None:
            raise side_effect
        return FakeHTTPResponse(response_body)

    with patch.dict(os.environ, {"GEMINI_API_KEY": "test-key-not-real"}):
        with patch("fetch.urllib.request.urlopen", side_effect=fake_urlopen):
            with patch("fetch.time.sleep"):  # リトライ待機をスキップして高速化
                return fetch.gemini_analyze(text)


def get_request_body_json(text="source_name: CISA\ntitle: test\n", *, response_body=None):
    """gemini_analyze()が送信するリクエストボディ(JSON)を取得する。"""
    captured = []
    call_gemini_analyze(text, response_body=response_body or make_candidate_body(VALID_ANALYSIS_RESPONSE),
                         capture_requests=captured)
    return json.loads(captured[0].data)


# ── response_schema ───────────────────────────────────────────────────────

class ResponseSchemaTest(unittest.TestCase):
    def setUp(self):
        self.body = get_request_body_json()
        self.schema = self.body["generationConfig"]["response_schema"]
        self.properties = self.schema["properties"]

    def test_category_is_enum_of_7_categories(self):
        self.assertEqual(set(self.properties["category"]["enum"]), set(dj.CATEGORY_VALUES))
        self.assertEqual(len(dj.CATEGORY_VALUES), 7)

    def test_importance_is_enum_high_mid_low(self):
        self.assertEqual(self.properties["importance"]["enum"], list(dj.IMPORTANCE_VALUES))

    def test_urgency_is_enum_of_3_values(self):
        self.assertEqual(self.properties["urgency"]["enum"], list(dj.URGENCY_VALUES))

    def test_tags_is_enum_array_of_allowlist(self):
        self.assertEqual(self.properties["tags"]["type"], "ARRAY")
        self.assertEqual(set(self.properties["tags"]["items"]["enum"]), set(dj.TAG_ALLOWLIST))
        self.assertEqual(self.properties["tags"]["maxItems"], dj.MAX_TAGS)

    def test_recommended_actions_is_array(self):
        self.assertEqual(self.properties["recommended_actions"]["type"], "ARRAY")
        self.assertEqual(self.properties["recommended_actions"]["minItems"], 1)
        self.assertEqual(self.properties["recommended_actions"]["maxItems"], 3)

    def test_all_required_fields_are_declared(self):
        expected = {
            "category", "category_reason", "importance", "urgency", "summary",
            "financial_impact", "recommended_actions", "reason", "tags",
        }
        self.assertEqual(set(self.schema["required"]), expected)
        self.assertEqual(set(self.properties.keys()), expected)


# ── 正常分析 ──────────────────────────────────────────────────────────────

class NormalAnalysisTest(unittest.TestCase):
    def test_valid_v2_output_is_success(self):
        result = call_gemini_analyze(response_body=make_candidate_body(VALID_ANALYSIS_RESPONSE))
        self.assertEqual(result["status"], "success")
        self.assertIsNotNone(result["analysis"])

    def test_category_etc_are_saved_to_daily_json(self):
        result = call_gemini_analyze(response_body=make_candidate_body(VALID_ANALYSIS_RESPONSE))
        item = {
            "source": "CISA", "link": "https://example.com/a", "title": "t",
            "ai_analysis": result["analysis"],
            "ai_analysis_meta": {
                "status": result["status"], "error_type": result["error_type"],
                "http_status": result["http_status"], "generated_at": "2026-07-11T07:00:00+09:00",
            },
        }
        source_defs = [{"id": "cisa", "name": "CISA", "source_type": "CERT・注意喚起",
                        "source_tier": "Tier 1", "collection_method": "rss", "language": "en"}]
        entry = dj.build_article_entry(item, source_defs, "gemini-2.5-flash",
                                        __import__("datetime").datetime(2026, 7, 11, 7, 0, tzinfo=dj.JST))
        self.assertEqual(entry["analysis"]["category"], "脆弱性・パッチ")
        self.assertEqual(entry["analysis"]["urgency"], "本日確認")
        self.assertEqual(entry["analysis"]["tags"], ["KEV", "悪用確認済み", "パッチ"])
        self.assertTrue(entry["analysis"]["category_reason"])
        self.assertTrue(entry["analysis"]["reason"])

    def test_urgency_and_category_counts_are_tabulated(self):
        result = call_gemini_analyze(response_body=make_candidate_body(VALID_ANALYSIS_RESPONSE))
        entries = [{
            "analysis": {
                "status": result["status"],
                "importance": result["analysis"]["importance"],
                "urgency": result["analysis"]["urgency"],
                "category": result["analysis"]["category"],
            }
        }]
        counts = dj.compute_counts(entries)
        self.assertEqual(counts["category"]["脆弱性・パッチ"], 1)
        self.assertEqual(counts["urgency"]["本日確認"], 1)

    def test_prompt_version_is_v2(self):
        self.assertEqual(dj.ARTICLE_PROMPT_VERSION, "article-analysis-v2")

    def test_recommended_actions_is_html_compatible_array(self):
        result = call_gemini_analyze(response_body=make_candidate_body(VALID_ANALYSIS_RESPONSE))
        actions = result["analysis"]["recommended_actions"]
        self.assertIsInstance(actions, list)
        self.assertTrue(1 <= len(actions) <= 3)
        self.assertTrue(all(isinstance(a, str) for a in actions))
        # 既存のnormalize_ai_analysis()/build_html()がそのまま使える形式であること
        core = fetch.normalize_ai_analysis(result["analysis"])
        self.assertIsNotNone(core)
        self.assertEqual(core["recommended_actions"], actions)


# ── enum・タグ ────────────────────────────────────────────────────────────

class EnumTagValidationTest(unittest.TestCase):
    def test_invalid_category_is_detected(self):
        bad = {**VALID_ANALYSIS_RESPONSE, "category": "架空カテゴリ"}
        self.assertIsNone(fetch.normalize_article_analysis(bad))

    def test_invalid_importance_is_detected(self):
        bad = {**VALID_ANALYSIS_RESPONSE, "importance": "極高"}
        self.assertIsNone(fetch.normalize_article_analysis(bad))

    def test_invalid_urgency_is_detected(self):
        bad = {**VALID_ANALYSIS_RESPONSE, "urgency": "即時"}
        self.assertIsNone(fetch.normalize_article_analysis(bad))

    def test_disallowed_tag_is_rejected_or_falls_back(self):
        bad = {**VALID_ANALYSIS_RESPONSE, "tags": ["KEV", "架空タグ"]}
        self.assertIsNone(fetch.normalize_article_analysis(bad))  # strictはNone(fallback経路へ)
        # fallback側の緩い救済では許可外タグが除去される
        self.assertEqual(fetch.sanitize_tags_lenient(["KEV", "架空タグ"]), ["KEV"])

    def test_duplicate_tags_are_deduplicated(self):
        dup = {**VALID_ANALYSIS_RESPONSE, "tags": ["KEV", "KEV", "パッチ"]}
        result = fetch.normalize_article_analysis(dup)
        self.assertEqual(result["tags"], ["KEV", "パッチ"])

    def test_over_5_tags_are_limited_or_fall_back(self):
        too_many = {**VALID_ANALYSIS_RESPONSE, "tags": list(dj.TAG_ALLOWLIST[:6])}
        self.assertIsNone(fetch.normalize_article_analysis(too_many))  # strictはNone
        self.assertEqual(len(fetch.sanitize_tags_lenient(list(dj.TAG_ALLOWLIST[:6]))), dj.MAX_TAGS)

    def test_empty_tags_is_accepted_as_valid(self):
        empty = {**VALID_ANALYSIS_RESPONSE, "tags": []}
        result = fetch.normalize_article_analysis(empty)
        self.assertEqual(result["tags"], [])


# ── fallback ──────────────────────────────────────────────────────────────

class FallbackTest(unittest.TestCase):
    def test_missing_new_fields_results_in_fallback(self):
        # category/urgency/tags/reason/category_reasonを欠いた(v1相当の)応答
        v1_only = {
            "importance": "高", "summary": "テスト要約です。",
            "financial_impact": "影響があります。",
            "recommended_actions": ["対応1"],
        }
        result = call_gemini_analyze(response_body=make_candidate_body(v1_only))
        self.assertEqual(result["status"], "fallback")

    def test_fallback_nulls_invalid_enum_values(self):
        truncated = (
            '{"category": "架空カテゴリ", "importance": "高", '
            '"summary": "テスト要約です。", "financial_impact": "影響があります。", '
            '"recommended_actions": ["対応1"]'
        )
        fb = fetch.fallback_ai_analysis(truncated, "source_name: CISA\ntitle: test\n")
        self.assertIsNone(fb["category"])

    def test_missing_importance_does_not_default_to_medium(self):
        # importanceが抽出できない場合、コード側で「中」を自動設定しない。
        # financial_impact/recommended_actionsが揃っていても、importance欠落
        # 単独で主要4項目の条件を満たさずNone(=failed扱い)になることを確認する。
        truncated = (
            '{"summary": "テスト要約です。", "financial_impact": "影響があります。", '
            '"recommended_actions": ["対応1"]'
        )
        fb = fetch.fallback_ai_analysis(truncated, "source_name: CISA\ntitle: test\n")
        self.assertIsNone(fb)

    def test_missing_financial_impact_does_not_generate_fixed_text(self):
        # financial_impactが抽出できない場合、固定の一般論文を生成しない。
        # 主要4項目が揃わないため全体としてNone(=failed扱い)になることを確認する。
        truncated = (
            '{"importance": "高", "summary": "テスト要約です。", '
            '"recommended_actions": ["対応1"]'
        )
        fb = fetch.fallback_ai_analysis(truncated, "source_name: CISA\ntitle: test\n")
        self.assertIsNone(fb)

    def test_missing_recommended_actions_does_not_generate_fixed_items(self):
        # recommended_actionsが抽出できない場合、固定の一般的確認事項を生成しない。
        # 主要4項目が揃わないため全体としてNone(=failed扱い)になることを確認する。
        truncated = (
            '{"importance": "高", "summary": "テスト要約です。", '
            '"financial_impact": "影響があります。"'
        )
        fb = fetch.fallback_ai_analysis(truncated, "source_name: CISA\ntitle: test\n")
        self.assertIsNone(fb)

    def test_missing_any_core_field_results_in_failed_status(self):
        # 主要4項目のいずれかが欠ける場合、gemini_analyze()全体としてfailedになる
        # (fallbackにはならない)。
        truncated = '{"importance": "高", "summary": "テスト要約です。"'
        result = call_gemini_analyze(response_body=make_candidate_body_from_raw(truncated))
        self.assertEqual(result["status"], "failed")
        self.assertIsNone(result["analysis"])

    def test_all_four_core_fields_present_results_in_fallback(self):
        # 主要4項目(importance/summary/financial_impact/recommended_actions)が
        # すべて応答から取得できれば、category等が欠けていてもfallbackになる。
        v1_only = {
            "importance": "高", "summary": "テスト要約です。",
            "financial_impact": "影響があります。",
            "recommended_actions": ["対応1"],
        }
        result = call_gemini_analyze(response_body=make_candidate_body(v1_only))
        self.assertEqual(result["status"], "fallback")
        self.assertIsNone(result["analysis"]["category"])
        self.assertIsNone(result["analysis"]["urgency"])
        self.assertEqual(result["analysis"]["tags"], [])

    def test_failed_article_has_empty_recommended_actions_not_fixed_defaults(self):
        # failed時、recommended_actionsは(固定の定型文ではなく)空配列として
        # 日次JSONへ保存される。
        truncated = '{"importance": "高", "summary": "テスト要約です。"'
        result = call_gemini_analyze(response_body=make_candidate_body_from_raw(truncated))
        item = {
            "source": "CISA", "link": "https://example.com/a", "title": "t",
            "ai_analysis": result["analysis"],
            "ai_analysis_meta": {
                "status": result["status"], "error_type": result["error_type"],
                "http_status": result["http_status"], "generated_at": "2026-07-11T07:00:00+09:00",
            },
        }
        source_defs = [{"id": "cisa", "name": "CISA", "source_type": "CERT・注意喚起",
                        "source_tier": "Tier 1", "collection_method": "rss", "language": "en"}]
        entry = dj.build_article_entry(item, source_defs, "gemini-2.5-flash",
                                        __import__("datetime").datetime(2026, 7, 11, 7, 0, tzinfo=dj.JST))
        self.assertEqual(entry["analysis"]["status"], "failed")
        self.assertEqual(entry["analysis"]["recommended_actions"], [])
        self.assertIsNone(entry["analysis"]["financial_impact"])
        self.assertIsNone(entry["analysis"]["importance"])
        # 固定の一般論文・定型アクションが紛れ込んでいないことを確認する
        serialized = json.dumps(entry, ensure_ascii=False)
        self.assertNotIn("関連製品、業務、委託先との接点確認が必要です", serialized)
        self.assertNotIn("原文と公表元の最新情報を確認する", serialized)

    def test_html_generation_does_not_raise_on_failed_item(self):
        truncated = '{"importance": "高", "summary": "テスト要約です。"'
        result = call_gemini_analyze(response_body=make_candidate_body_from_raw(truncated))
        item = {
            "title": "テスト記事失敗ケース", "link": "https://example.com/article",
            "summary": "概要", "date": None, "source": "CISA", "lang": "ja",
            "ai_analysis": result["analysis"],
        }
        html = fetch.build_html([item])  # 例外が出なければOK
        self.assertIn("テスト記事失敗ケース", html)

    def test_fallback_error_type_is_schema_parse_error(self):
        v1_only = {
            "importance": "高", "summary": "テスト要約です。",
            "financial_impact": "影響があります。",
            "recommended_actions": ["対応1"],
        }
        result = call_gemini_analyze(response_body=make_candidate_body(v1_only))
        self.assertEqual(result["error_type"], "schema_parse_error")

    def test_fallback_keeps_article_in_daily_json(self):
        v1_only = {
            "importance": "高", "summary": "テスト要約です。",
            "financial_impact": "影響があります。",
            "recommended_actions": ["対応1"],
        }
        result = call_gemini_analyze(response_body=make_candidate_body(v1_only))
        item = {
            "source": "CISA", "link": "https://example.com/a", "title": "t",
            "ai_analysis": result["analysis"],
            "ai_analysis_meta": {
                "status": result["status"], "error_type": result["error_type"],
                "http_status": result["http_status"], "generated_at": "2026-07-11T07:00:00+09:00",
            },
        }
        source_defs = [{"id": "cisa", "name": "CISA", "source_type": "CERT・注意喚起",
                        "source_tier": "Tier 1", "collection_method": "rss", "language": "en"}]
        entry = dj.build_article_entry(item, source_defs, "gemini-2.5-flash",
                                        __import__("datetime").datetime(2026, 7, 11, 7, 0, tzinfo=dj.JST))
        self.assertIsNotNone(entry)
        self.assertEqual(entry["analysis"]["status"], "fallback")

    def test_html_generation_does_not_raise_on_fallback_item(self):
        v1_only = {
            "importance": "高", "summary": "テスト要約です。",
            "financial_impact": "影響があります。",
            "recommended_actions": ["対応1"],
        }
        result = call_gemini_analyze(response_body=make_candidate_body(v1_only))
        item = {
            "title": "テスト記事", "link": "https://example.com/article",
            "summary": "概要", "date": None, "source": "CISA", "lang": "ja",
            "ai_analysis": result["analysis"],
        }
        html = fetch.build_html([item])  # 例外が出なければOK
        self.assertIn("テスト記事", html)


# ── failed / not_attempted ────────────────────────────────────────────────

class FailedNotAttemptedTest(unittest.TestCase):
    def test_complete_failure_all_ai_fields_null_or_empty(self):
        result = call_gemini_analyze(
            side_effect=urllib.error.HTTPError("http://x", 500, "err", {}, None)
        )
        self.assertEqual(result["status"], "failed")
        self.assertIsNone(result["analysis"])

        item = {
            "source": "CISA", "link": "https://example.com/a", "title": "t",
            "ai_analysis": result["analysis"],
            "ai_analysis_meta": {
                "status": result["status"], "error_type": result["error_type"],
                "http_status": result["http_status"], "generated_at": "2026-07-11T07:00:00+09:00",
            },
        }
        source_defs = [{"id": "cisa", "name": "CISA", "source_type": "CERT・注意喚起",
                        "source_tier": "Tier 1", "collection_method": "rss", "language": "en"}]
        entry = dj.build_article_entry(item, source_defs, "gemini-2.5-flash",
                                        __import__("datetime").datetime(2026, 7, 11, 7, 0, tzinfo=dj.JST))
        a = entry["analysis"]
        self.assertIsNone(a["category"])
        self.assertIsNone(a["importance"])
        self.assertIsNone(a["urgency"])
        self.assertIsNone(a["summary"])
        self.assertEqual(a["recommended_actions"], [])
        self.assertEqual(a["tags"], [])

    def test_no_api_key_is_not_attempted(self):
        items = [{"source": "CISA", "title": "t", "summary": "s", "link": "https://x",
                  "date": None, "lang": "en"}]
        with patch.dict(os.environ, {}, clear=True):
            result_items = fetch.enrich_with_ai(items)
        self.assertNotIn("ai_analysis_meta", result_items[0])

    def test_counts_go_to_unclassified_on_failure(self):
        entries = [{"analysis": {"status": "failed", "importance": None, "urgency": None, "category": None}}]
        counts = dj.compute_counts(entries)
        self.assertEqual(counts["importance"]["未判定"], 1)
        self.assertEqual(counts["urgency"]["未判定"], 1)
        self.assertEqual(counts["category"]["未判定"], 1)

    def test_run_status_follows_ticket3_definition(self):
        entries = [{"analysis": {"status": "not_attempted"}}] * 3
        run = dj.compute_run_meta(entries)
        self.assertEqual(run["status"], "not_attempted")


# ── 判定例 (モック応答) ────────────────────────────────────────────────────

class JudgmentExampleTest(unittest.TestCase):
    def test_prompt_contains_all_four_few_shot_examples(self):
        body = get_request_body_json()
        prompt_text = body["contents"][0]["parts"][0]["text"]
        # 例1: KEV
        self.assertIn("KEV", prompt_text)
        self.assertIn("本日確認", prompt_text)
        # 例2: SWIFT CSCF
        self.assertIn("SWIFT", prompt_text)
        self.assertIn("CSCF", prompt_text)
        # 例3: AIエージェント
        self.assertIn("AIエージェント", prompt_text)
        self.assertIn("AI・新技術リスク", prompt_text)
        # 例4: マーケティング
        self.assertIn("マーケティング", prompt_text)
        self.assertIn("参考", prompt_text)

    def test_kev_example_mock_response_processed_as_expected(self):
        mock = {**VALID_ANALYSIS_RESPONSE, "category": "脆弱性・パッチ",
                "importance": "高", "urgency": "本日確認",
                "tags": ["KEV", "悪用確認済み", "パッチ"]}
        result = call_gemini_analyze(response_body=make_candidate_body(mock))
        self.assertEqual(result["status"], "success")
        self.assertEqual(result["analysis"]["category"], "脆弱性・パッチ")
        self.assertEqual(result["analysis"]["importance"], "高")
        self.assertEqual(result["analysis"]["urgency"], "本日確認")

    def test_swift_cscf_example_mock_response_processed_as_expected(self):
        mock = {**VALID_ANALYSIS_RESPONSE, "category": "規制・ガバナンス",
                "importance": "高", "urgency": "今週確認",
                "tags": ["SWIFT", "CSCF", "ガイドライン"]}
        result = call_gemini_analyze(response_body=make_candidate_body(mock))
        self.assertEqual(result["analysis"]["category"], "規制・ガバナンス")
        self.assertEqual(result["analysis"]["importance"], "高")
        self.assertEqual(result["analysis"]["urgency"], "今週確認")

    def test_ai_agent_report_example_mock_response_processed_as_expected(self):
        mock = {**VALID_ANALYSIS_RESPONSE, "category": "AI・新技術リスク",
                "importance": "中", "urgency": "今週確認",
                "tags": ["AI", "AIエージェント"]}
        result = call_gemini_analyze(response_body=make_candidate_body(mock))
        self.assertEqual(result["analysis"]["category"], "AI・新技術リスク")
        self.assertEqual(result["analysis"]["importance"], "中")
        self.assertEqual(result["analysis"]["urgency"], "今週確認")

    def test_marketing_article_example_mock_response_processed_as_expected(self):
        mock = {**VALID_ANALYSIS_RESPONSE, "category": "その他",
                "importance": "低", "urgency": "参考", "tags": []}
        result = call_gemini_analyze(response_body=make_candidate_body(mock))
        self.assertEqual(result["analysis"]["importance"], "低")
        self.assertEqual(result["analysis"]["urgency"], "参考")
        self.assertEqual(result["analysis"]["tags"], [])


# ── セキュリティ ──────────────────────────────────────────────────────────

class SecurityTest(unittest.TestCase):
    def test_api_key_not_saved_to_daily_json(self):
        result = call_gemini_analyze(response_body=make_candidate_body(VALID_ANALYSIS_RESPONSE))
        item = {
            "source": "CISA", "link": "https://example.com/a", "title": "t",
            "ai_analysis": result["analysis"],
            "ai_analysis_meta": {
                "status": result["status"], "error_type": result["error_type"],
                "http_status": result["http_status"], "generated_at": "2026-07-11T07:00:00+09:00",
            },
        }
        source_defs = [{"id": "cisa", "name": "CISA", "source_type": "CERT・注意喚起",
                        "source_tier": "Tier 1", "collection_method": "rss", "language": "en"}]
        entry = dj.build_article_entry(item, source_defs, "gemini-2.5-flash",
                                        __import__("datetime").datetime(2026, 7, 11, 7, 0, tzinfo=dj.JST))
        serialized = json.dumps(entry, ensure_ascii=False)
        self.assertNotIn("test-key-not-real", serialized)

    def test_raw_response_full_text_not_saved(self):
        weird_marker = "UNIQUE_RAW_RESPONSE_MARKER_ZZZ"
        response = make_candidate_body({**VALID_ANALYSIS_RESPONSE, "summary": weird_marker})
        result = call_gemini_analyze(response_body=response)
        # summaryとして保存された値以外に、応答全文がそのまま残っていないこと
        serialized = json.dumps(result, ensure_ascii=False)
        self.assertEqual(serialized.count(weird_marker), 1)

    def test_error_body_full_text_not_saved(self):
        result = call_gemini_analyze(
            side_effect=urllib.error.HTTPError("http://x", 500, "super secret internal error body", {}, None)
        )
        serialized = json.dumps(result, ensure_ascii=False)
        self.assertNotIn("super secret internal error body", serialized)

    def test_existing_html_escape_tests_still_pass(self):
        # 既存test_fetch.pyのHTMLエスケープ回帰は別ファイルで担保済みだが、
        # ここでも代表的なケースを確認する
        out = fetch.esc("<script>alert(1)</script>")
        self.assertNotIn("<script>", out)


if __name__ == "__main__":
    unittest.main()
