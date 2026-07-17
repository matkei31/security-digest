#!/usr/bin/env python3
"""
Gemini個別記事分析プロンプト拡張の回帰テスト (Ticket 4)
標準ライブラリの unittest のみを使用する。実際のGemini APIは一切呼ばない
(urllib.request.urlopenをモックに差し替える)。
"""

import datetime
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
    "title_ja": "CISA、実悪用が確認された脆弱性をKEVカタログへ追加",
    "category": "脆弱性・パッチ",
    "category_reason": "CVEとKEV追加が主題であり、製品脆弱性への対応を扱う記事のため。",
    "importance": "高",
    "urgency": "本日確認",
    "summary": "CISAが実際の悪用が確認された脆弱性をKEVカタログに追加した。",
    "financial_impact": "該当製品を利用する金融機関では、外部公開システムへの影響確認が必要になり得る。",
    "recommended_actions": ["該当製品の利用有無を確認する", "外部公開状況とパッチ適用状況を確認する"],
    # Ticket 15a: reasonは「重要度は…」「確認目安は…」の2文で、実際のimportance/urgencyラベルを含む。
    "reason": "重要度は、悪用が確認された広く利用される外部公開製品の脆弱性で適用性評価の優先度が高いため「高」です。確認目安は、CISA KEVに掲載され実悪用が継続しているため「本日確認」です。",
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

    def test_recommended_actions_is_array_and_allows_empty(self):
        # Ticket 11a: 記事固有の確認事項がなければ0件が正常値のため、
        # minItemsは設定しない(空配列を拒否しない)。
        self.assertEqual(self.properties["recommended_actions"]["type"], "ARRAY")
        self.assertNotIn("minItems", self.properties["recommended_actions"])
        self.assertEqual(self.properties["recommended_actions"]["maxItems"], 3)

    def test_all_required_fields_are_declared(self):
        # Ticket 15a: title_jaを必須フィールドとして追加した。
        expected = {
            "title_ja", "category", "category_reason", "importance", "urgency",
            "summary", "financial_impact", "recommended_actions", "reason", "tags",
        }
        self.assertEqual(set(self.schema["required"]), expected)
        self.assertEqual(set(self.properties.keys()), expected)


# ── prompt_versionの反映 (Ticket 11a) ───────────────────────────────────────

class PromptVersionPropagationTest(unittest.TestCase):
    def test_article_prompt_version_is_v5(self):
        self.assertEqual(dj.ARTICLE_PROMPT_VERSION, "article-analysis-v8")

    def test_brief_prompt_version_is_unchanged(self):
        self.assertEqual(dj.BRIEF_PROMPT_VERSION, "today-brief-v3")

    def test_generator_reflects_new_article_prompt_version(self):
        digest = dj.build_daily_digest(
            [], {"overview": None, "important_highlights": [], "discussion_points": [],
                 "check_items": [], "status": "not_attempted", "error_type": None, "http_status": None},
            [], "gemini-2.5-flash",
            datetime.datetime(2026, 7, 11, 7, 0, tzinfo=dj.JST),
            datetime.datetime(2026, 7, 11, 7, 0, tzinfo=dj.JST),
        )
        self.assertEqual(digest["generator"]["article_prompt_version"], "article-analysis-v8")
        self.assertEqual(digest["generator"]["brief_prompt_version"], "today-brief-v3")

    def test_each_article_analysis_reflects_new_prompt_version(self):
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
                                        datetime.datetime(2026, 7, 11, 7, 0, tzinfo=dj.JST))
        self.assertEqual(entry["analysis"]["prompt_version"], "article-analysis-v8")


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

    def test_prompt_version_is_v5(self):
        self.assertEqual(dj.ARTICLE_PROMPT_VERSION, "article-analysis-v8")

    def test_recommended_actions_is_html_compatible_array(self):
        result = call_gemini_analyze(response_body=make_candidate_body(VALID_ANALYSIS_RESPONSE))
        actions = result["analysis"]["recommended_actions"]
        self.assertIsInstance(actions, list)
        self.assertTrue(0 <= len(actions) <= 3)
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


# ── recommended_actionsの正規化 (Ticket 11a) ────────────────────────────────

class RecommendedActionsNormalizationTest(unittest.TestCase):
    def test_zero_recommended_actions_is_accepted_as_success(self):
        empty_actions = {**VALID_ANALYSIS_RESPONSE, "recommended_actions": []}
        result = fetch.normalize_article_analysis(empty_actions)
        self.assertIsNotNone(result)
        self.assertEqual(result["recommended_actions"], [])

    def test_tokuni_nashi_is_normalized_to_empty(self):
        self.assertEqual(fetch.normalize_recommended_actions(["特になし"]), [])

    def test_nashi_is_normalized_to_empty(self):
        self.assertEqual(fetch.normalize_recommended_actions(["なし"]), [])

    def test_gaitou_nashi_is_normalized_to_empty(self):
        self.assertEqual(fetch.normalize_recommended_actions(["該当なし"]), [])

    def test_taiou_fuyou_is_normalized_to_empty(self):
        self.assertEqual(fetch.normalize_recommended_actions(["対応不要"]), [])

    def test_null_none_and_empty_string_are_removed(self):
        self.assertEqual(
            fetch.normalize_recommended_actions(["null", "None", "", "   "]), []
        )

    def test_whitespace_case_and_width_differences_are_absorbed(self):
        # 前後空白、全角スペース、大文字小文字、文末の句読点差を安全に吸収する
        self.assertEqual(fetch.normalize_recommended_actions(["  特になし  "]), [])
        self.assertEqual(fetch.normalize_recommended_actions(["特になし。"]), [])
        self.assertEqual(fetch.normalize_recommended_actions(["ＮＵＬＬ"]), [])
        self.assertEqual(fetch.normalize_recommended_actions(["NONE"]), [])

    def test_valid_conditional_action_is_not_removed(self):
        actions = ["現時点ではパッチがないため、ベンダーの緩和策を確認してください"]
        self.assertEqual(fetch.normalize_recommended_actions(actions), actions)

    def test_sentence_mentioning_taiou_fuyou_is_not_removed_by_partial_match(self):
        # 「対応不要」を部分文字列として含むだけの記事固有の文まで削除しない
        actions = ["対応不要と判断する前に、該当バージョンの利用有無を確認してください"]
        self.assertEqual(fetch.normalize_recommended_actions(actions), actions)

    def test_mixed_placeholder_and_valid_actions_keeps_only_valid_ones(self):
        actions = ["特になし", "該当製品を利用している場合、パッチ適用状況を確認してください", "なし"]
        self.assertEqual(
            fetch.normalize_recommended_actions(actions),
            ["該当製品を利用している場合、パッチ適用状況を確認してください"],
        )

    def test_all_placeholder_actions_result_in_empty_list(self):
        actions = ["特になし", "現時点では特になし", "現時点で対応事項なし", "特段の対応なし"]
        self.assertEqual(fetch.normalize_recommended_actions(actions), [])

    def test_non_list_input_returns_empty_list(self):
        self.assertEqual(fetch.normalize_recommended_actions("特になし"), [])
        self.assertEqual(fetch.normalize_recommended_actions(None), [])


# ── recommended_actions: 「明示的な空配列」と「欠落/解析不能」の区別 (Ticket 11a-fix) ──

class RecommendedActionsKeyStateTest(unittest.TestCase):
    """normalize_ai_analysis()に対して直接、キーの有無・型・値のパターンを検証する。
    「明示的な空配列」だけを正常とし、キー欠落・null・文字列・配列として解析
    できない値は、抽出できても0件と同じ扱いにせず失敗として扱うことを確認する。
    """

    def _valid_core_fields(self):
        return {
            "importance": "高", "summary": "テスト要約です。",
            "financial_impact": "影響があります。",
        }

    # 1. strict JSON: recommended_actions=[] はsuccess ──────────────────────
    def test_strict_explicit_empty_array_is_accepted(self):
        value = {**self._valid_core_fields(), "recommended_actions": []}
        result = fetch.normalize_ai_analysis(value)
        self.assertIsNotNone(result)
        self.assertEqual(result["recommended_actions"], [])

    def test_strict_explicit_empty_array_end_to_end_is_success(self):
        mock = {**VALID_ANALYSIS_RESPONSE, "recommended_actions": []}
        result = call_gemini_analyze(response_body=make_candidate_body(mock))
        self.assertEqual(result["status"], "success")
        self.assertEqual(result["analysis"]["recommended_actions"], [])

    # 2. strict JSON: キー欠落は失敗 ─────────────────────────────────────────
    def test_strict_missing_key_is_rejected(self):
        value = self._valid_core_fields()  # recommended_actionsキーを含めない
        self.assertNotIn("recommended_actions", value)
        self.assertIsNone(fetch.normalize_ai_analysis(value))

    # 3. strict JSON: nullは失敗 ────────────────────────────────────────────
    def test_strict_null_value_is_rejected(self):
        value = {**self._valid_core_fields(), "recommended_actions": None}
        self.assertIsNone(fetch.normalize_ai_analysis(value))

    # 4. strict JSON: 文字列は失敗 ───────────────────────────────────────────
    def test_strict_string_value_is_rejected(self):
        value = {**self._valid_core_fields(), "recommended_actions": "対応不要"}
        self.assertIsNone(fetch.normalize_ai_analysis(value))

    # extract_partial_array_state()自体の3状態判定 ───────────────────────────
    def test_extract_state_found_for_explicit_empty_array(self):
        state, values = fetch.extract_partial_array_state(
            '{"recommended_actions": []}', "recommended_actions"
        )
        self.assertEqual(state, "found")
        self.assertEqual(values, [])

    def test_extract_state_found_for_populated_array(self):
        state, values = fetch.extract_partial_array_state(
            '{"recommended_actions": ["対応1", "対応2"]}', "recommended_actions"
        )
        self.assertEqual(state, "found")
        self.assertEqual(values, ["対応1", "対応2"])

    def test_extract_state_missing_when_key_absent(self):
        state, values = fetch.extract_partial_array_state(
            '{"importance": "高"}', "recommended_actions"
        )
        self.assertEqual(state, "missing")
        self.assertEqual(values, [])

    def test_extract_state_invalid_for_null_value(self):
        state, values = fetch.extract_partial_array_state(
            '{"recommended_actions": null}', "recommended_actions"
        )
        self.assertEqual(state, "invalid")

    def test_extract_state_invalid_for_string_value(self):
        state, values = fetch.extract_partial_array_state(
            '{"recommended_actions": "対応不要"}', "recommended_actions"
        )
        self.assertEqual(state, "invalid")

    def test_extract_state_invalid_for_unterminated_array(self):
        state, values = fetch.extract_partial_array_state(
            '{"recommended_actions": ["対応1"', "recommended_actions"
        )
        self.assertEqual(state, "invalid")

    # 5. fallback応答: recommended_actions=[]が明示されていれば受理 ────────────
    def test_fallback_explicit_empty_array_is_accepted(self):
        truncated = (
            '{"importance": "高", "summary": "テスト要約です。", '
            '"financial_impact": "影響があります。", "recommended_actions": []'
        )
        fb = fetch.fallback_ai_analysis(truncated, "source_name: CISA\ntitle: test\n")
        self.assertIsNotNone(fb)
        self.assertEqual(fb["recommended_actions"], [])

    # 6. fallback応答: キー欠落は失敗 (FallbackTest側で従来テストとして復元済み) ──

    # 7. fallback応答: 配列構文不正は失敗 ──────────────────────────────────────
    def test_fallback_unterminated_array_is_rejected(self):
        truncated = (
            '{"importance": "高", "summary": "テスト要約です。", '
            '"financial_impact": "影響があります。", "recommended_actions": ["対応1"'
        )
        fb = fetch.fallback_ai_analysis(truncated, "source_name: CISA\ntitle: test\n")
        self.assertIsNone(fb)

    def test_fallback_string_instead_of_array_is_rejected(self):
        truncated = (
            '{"importance": "高", "summary": "テスト要約です。", '
            '"financial_impact": "影響があります。", "recommended_actions": "対応不要"'
        )
        fb = fetch.fallback_ai_analysis(truncated, "source_name: CISA\ntitle: test\n")
        self.assertIsNone(fb)

    def test_fallback_null_is_rejected(self):
        truncated = (
            '{"importance": "高", "summary": "テスト要約です。", '
            '"financial_impact": "影響があります。", "recommended_actions": null'
        )
        fb = fetch.fallback_ai_analysis(truncated, "source_name: CISA\ntitle: test\n")
        self.assertIsNone(fb)

    # 8. ["特になし"]は明示配列として受理し、正規化後[] ───────────────────────
    def test_strict_placeholder_only_array_is_accepted_and_normalized_to_empty(self):
        value = {**self._valid_core_fields(), "recommended_actions": ["特になし"]}
        result = fetch.normalize_ai_analysis(value)
        self.assertIsNotNone(result)
        self.assertEqual(result["recommended_actions"], [])

    def test_fallback_placeholder_only_array_is_accepted_and_normalized_to_empty(self):
        truncated = (
            '{"importance": "高", "summary": "テスト要約です。", '
            '"financial_impact": "影響があります。", "recommended_actions": ["特になし"]'
        )
        fb = fetch.fallback_ai_analysis(truncated, "source_name: CISA\ntitle: test\n")
        self.assertIsNotNone(fb)
        self.assertEqual(fb["recommended_actions"], [])

    # 9. 有効アクションは従来どおり保持 ─────────────────────────────────────
    def test_fallback_valid_action_mixed_with_placeholder_keeps_only_valid(self):
        truncated = (
            '{"importance": "高", "summary": "テスト要約です。", '
            '"financial_impact": "影響があります。", '
            '"recommended_actions": ["特になし", "該当製品を利用している場合、パッチ適用状況を確認してください"]'
        )
        fb = fetch.fallback_ai_analysis(truncated, "source_name: CISA\ntitle: test\n")
        self.assertIsNotNone(fb)
        self.assertEqual(
            fb["recommended_actions"],
            ["該当製品を利用している場合、パッチ適用状況を確認してください"],
        )

    # 10. 固定アクションを生成しない ────────────────────────────────────────
    def test_no_fixed_action_text_is_ever_injected_on_key_absence(self):
        truncated = (
            '{"importance": "高", "summary": "テスト要約です。", '
            '"financial_impact": "影響があります。"'
        )
        fb = fetch.fallback_ai_analysis(truncated, "source_name: CISA\ntitle: test\n")
        self.assertIsNone(fb)  # 固定項目で埋めてNoneを回避したりしない


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
        # Ticket 11a-fix: recommended_actionsキー自体が応答から見つからない場合、
        # 固定の一般的確認事項を生成しないのはもちろん、「明示的な空配列」として
        # 黙って正常化もしない(=抽出失敗として全体がNone/failed扱いになる)。
        # 「記事固有の確認事項がなく明示的に[]が返った」場合とは区別する。
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
    def test_prompt_contains_facts_aware_few_shot_examples(self):
        # Ticket 15a: v5では7例を維持しつつ、例1へtitle_ja、例3=中×今週(KEV単独境界)、
        # 例4=中×参考(CVSS満点ニッチ)、例5=低×参考(他業界)、例6=低×参考(週次まとめ)、
        # 例7=高×本日(KEV新規追加)へ再構成した。
        body = get_request_body_json()
        prompt_text = body["contents"][0]["parts"][0]["text"]
        # 例1: 高×本日確認(KEV掲載+高CVSS)。title_jaを含む
        self.assertIn("# 例1: 高 × 本日確認", prompt_text)
        self.assertIn('"title_ja"', prompt_text)
        # 例2: 高×参考(重要だが短期対応のないガバナンス情報)
        self.assertIn("# 例2: 高 × 参考", prompt_text)
        # 例3: 中×今週確認(KEVのみで適用性不明の境界)
        self.assertIn("# 例3: 中 × 今週確認", prompt_text)
        self.assertIn("KEVのみで適用性不明の境界", prompt_text)
        # 例4: 中×参考(CVSS満点でもニッチ消費者向け製品。アンカリング防止)
        # 内部識別子漏出修正: cvss_score=/kev_status=という内部field=value表記
        # ではなく、人間可読な表現(CVSS10.0・KEV非掲載)を使う。
        self.assertIn("CVSS10.0のニッチ消費者向け製品", prompt_text)
        self.assertIn("KEV非掲載自体は根拠にしない", prompt_text)
        self.assertNotIn("cvss_score=", prompt_text)
        self.assertNotIn("kev_status=", prompt_text)
        self.assertNotIn("KEVにも未掲載のため", prompt_text)
        # 例5: 低×参考(他業界のサービス事業者への攻撃)
        self.assertIn("他業界(医療)事業者への攻撃", prompt_text)
        self.assertIn("参考情報にとどまります", prompt_text)
        # 例6: 低×参考(週次まとめ記事。合算して過大評価しない)
        self.assertIn("週次まとめ記事", prompt_text)
        # 例7: 高×本日確認(KEV新規追加。dateAddedが前日)
        self.assertIn("# 例7: 高 × 本日確認", prompt_text)
        self.assertIn("KEV新規追加", prompt_text)
        self.assertIn('"importance": "高", "urgency": "本日確認"', prompt_text)
        # 例8・例9は存在しない
        self.assertNotIn("# 例8", prompt_text)
        self.assertNotIn("# 例9", prompt_text)

    def test_prompt_defines_importance_without_time_axis(self):
        body = get_request_body_json()
        prompt_text = body["contents"][0]["parts"][0]["text"]
        self.assertIn("確認優先度", prompt_text)
        self.assertIn("時間軸", prompt_text)
        self.assertIn("時間軸はurgencyだけで判定し、importanceには", prompt_text)

    def test_prompt_instructs_importance_urgency_independence(self):
        body = get_request_body_json()
        prompt_text = body["contents"][0]["parts"][0]["text"]
        self.assertIn("独立して判定する", prompt_text)
        self.assertIn("高×参考", prompt_text)
        self.assertIn("低×本日確認", prompt_text)

    def test_prompt_prohibits_cvss_only_and_self_usage_assumption(self):
        body = get_request_body_json()
        prompt_text = body["contents"][0]["parts"][0]["text"]
        self.assertIn("CVSSが高いという理由だけで高にする", prompt_text)
        self.assertIn("自社での利用が確認済みと仮定する", prompt_text)
        self.assertIn("自社への影響が確定して", prompt_text)

    def test_prompt_allows_limited_or_unclear_financial_impact(self):
        body = get_request_body_json()
        prompt_text = body["contents"][0]["parts"][0]["text"]
        self.assertIn("直接的な影響は限定的です", prompt_text)
        # Ticket 15a: 適用に条件がある場合は条件を文頭に置く(applicability条件先行)。
        self.assertIn("適用に条件がある場合は、その条件を文の冒頭に置く", prompt_text)
        self.assertIn("記事にない委託関係・製品利用を仮定しない", prompt_text)
        self.assertIn("業界が異なるだけの記事を無理に金融", prompt_text)
        self.assertIn("接続しない", prompt_text)
        self.assertIn("記事にない規制義務・攻撃経路・影響範囲を作らない", prompt_text)

    def test_prompt_allows_zero_recommended_actions_and_bans_generic_ones(self):
        body = get_request_body_json()
        prompt_text = body["contents"][0]["parts"][0]["text"]
        self.assertIn("0〜3件", prompt_text)
        self.assertIn("0件を正常な結果として認め", prompt_text)
        self.assertIn("リスク評価を実施", prompt_text)
        # Ticket 15a: 定型文の禁止例は表現統合済み(「検討する」等の語尾を含めない)。
        self.assertIn("多要素認証・ゼロトラストを検討", prompt_text)

    def test_prompt_reason_distinguishes_event_and_applicability(self):
        # Ticket 15a: reasonは「重要度は…」「確認目安は…」の2文で、重要度側(適用性)と
        # 確認目安側(時間的根拠)を分けて述べる。循環説明・抽象論を禁止する。
        body = get_request_body_json()
        prompt_text = body["contents"][0]["parts"][0]["text"]
        self.assertIn("重要度は、", prompt_text)
        self.assertIn("確認目安は、", prompt_text)
        self.assertIn("両軸を混同しない", prompt_text)
        self.assertIn("重要な脆弱性であるため", prompt_text)  # 禁止例として言及

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


# ── ネガティブ例 (Ticket 11a) ────────────────────────────────────────────────
# 実APIは呼ばないため、モデルの実際の判定は検証できない。ここでは、各シナリオが
# 期待する出力の「形」(0件recommended_actions、限定的/不明なfinancial_impact、
# importance/urgencyの独立した組み合わせ)をスキーマ・正規化処理が正しく受理・
# 保存できることを確認する。

class NegativeExampleTest(unittest.TestCase):
    def test_other_industry_incident_example(self):
        # 例1: 他業界(医療)のサービス事業者への攻撃。金融機関との直接的な関係や
        # 共通利用製品は記事から確認できない。
        mock = {
            **VALID_ANALYSIS_RESPONSE, "category": "インシデント",
            "importance": "低", "urgency": "参考",
            "financial_impact": "金融機関への直接的な関係は確認できず、他業界のサプライチェーン事例として参考情報にとどまります。",
            # Ticket 15a: importance/urgencyに一致した2文reason。
            "reason": "重要度は、対象が他業界の事業者で金融機関との直接的な関係が確認できず参考にとどまるため「低」です。確認目安は、金融機関に具体的な短期対応事項がないため「参考」です。",
            "recommended_actions": [], "tags": [],
        }
        result = call_gemini_analyze(response_body=make_candidate_body(mock))
        self.assertEqual(result["status"], "success")
        self.assertEqual(result["analysis"]["importance"], "低")
        self.assertEqual(result["analysis"]["urgency"], "参考")
        self.assertEqual(result["analysis"]["recommended_actions"], [])
        self.assertIn("確認できず", result["analysis"]["financial_impact"])

    def test_high_cvss_niche_product_example(self):
        # 例2: CVSSは高いが、利用範囲が限定されたニッチな製品。
        mock = {
            **VALID_ANALYSIS_RESPONSE, "category": "脆弱性・パッチ",
            "importance": "中", "urgency": "参考",
            "recommended_actions": ["当該製品を利用している場合、貴社基準に基づく対応判断の対象になり得ます"],
            "tags": [],
        }
        result = call_gemini_analyze(response_body=make_candidate_body(mock))
        self.assertEqual(result["analysis"]["importance"], "中")
        self.assertIn("利用している場合", result["analysis"]["recommended_actions"][0])

    def test_vendor_marketing_with_high_cvss_citation_example(self):
        # 例3: 自社製品の販売促進を主目的とし、高いCVSSを一般論として引用する
        # ベンダー宣伝記事。
        mock = {
            **VALID_ANALYSIS_RESPONSE, "category": "その他",
            "importance": "低", "urgency": "参考",
            "recommended_actions": [], "tags": [],
        }
        result = call_gemini_analyze(response_body=make_candidate_body(mock))
        self.assertEqual(result["analysis"]["importance"], "低")
        self.assertEqual(result["analysis"]["urgency"], "参考")
        self.assertEqual(result["analysis"]["recommended_actions"], [])

    def test_widely_used_product_with_confirmed_exploitation_example(self):
        # 例4: 広く利用される製品の脆弱性で、実際の悪用が確認されている。
        mock = {
            **VALID_ANALYSIS_RESPONSE, "category": "脆弱性・パッチ",
            "importance": "高", "urgency": "本日確認",
            "recommended_actions": ["該当製品を利用している場合、影響バージョンと修正版の適用状況を確認してください"],
            "reason": "悪用が確認されている広く利用される製品の脆弱性であり、当該製品を利用する組織では適用性の優先確認対象となるため。",
            "tags": ["KEV", "悪用確認済み", "パッチ"],
        }
        result = call_gemini_analyze(response_body=make_candidate_body(mock))
        self.assertEqual(result["analysis"]["importance"], "高")
        self.assertEqual(result["analysis"]["urgency"], "本日確認")
        self.assertIn("利用している場合", result["analysis"]["recommended_actions"][0])

    def test_important_governance_topic_without_short_term_action_example(self):
        # 例5: 金融分野に直接関係する重要なガバナンス・規制上の論点だが、
        # 直近の対応期限や当日中の確認事項はない(importance=高でもurgency=参考)。
        mock = {
            **VALID_ANALYSIS_RESPONSE, "category": "規制・ガバナンス",
            "importance": "高", "urgency": "参考", "tags": ["規制", "ガイドライン"],
        }
        result = call_gemini_analyze(response_body=make_candidate_body(mock))
        self.assertEqual(result["analysis"]["importance"], "高")
        self.assertEqual(result["analysis"]["urgency"], "参考")

    def test_limited_scope_but_same_day_check_needed_example(self):
        # 例6: 対象組織は限定的だが、該当する場合には当日中の確認が必要
        # (importance=中/低でもurgency=本日確認)。
        mock = {
            **VALID_ANALYSIS_RESPONSE, "category": "脆弱性・パッチ",
            "importance": "中", "urgency": "本日確認",
            "recommended_actions": ["該当構成に該当する場合、当日中に緩和策の適用状況を確認してください"],
            "tags": [],
        }
        result = call_gemini_analyze(response_body=make_candidate_body(mock))
        self.assertEqual(result["analysis"]["importance"], "中")
        self.assertEqual(result["analysis"]["urgency"], "本日確認")


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
