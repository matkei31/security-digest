#!/usr/bin/env python3
"""
Today's Brief (Ticket 8) の生成・正規化・保存の回帰テスト。
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


def make_brief_body(brief_dict):
    """Gemini generateContent の正常応答envelopeを組み立てる。"""
    return json.dumps({
        "candidates": [{
            "content": {
                "parts": [{"text": json.dumps(brief_dict, ensure_ascii=False)}]
            }
        }]
    }).encode("utf-8")


def make_brief_body_from_raw(raw_text):
    """意図的に壊れた/JSONでないテキストをそのままparts[0].textに埋め込んで
    envelopeを組み立てる(failed境界のテスト用)。"""
    return json.dumps({
        "candidates": [{"content": {"parts": [{"text": raw_text}]}}]
    }).encode("utf-8")


VALID_BRIEF_RESPONSE = {
    "overview": (
        "本日は脆弱性関連の情報が中心で、複数の記事でCISA KEVへの追加が確認されました。"
        "金融機関に影響し得る内容が含まれるため、該当製品の利用状況確認が望まれます。"
    ),
    "important_highlights": ["A社製品の脆弱性が悪用確認済みとしてKEVに追加されました。"],
    "discussion_points": ["複数のCERTから同時期に注意喚起が出ています。"],
    "check_items": ["該当製品を利用している場合、パッチ適用状況を確認する。"],
}


def make_brief_item(title="記事1", source="CISA", status="success", **analysis_overrides):
    analysis = {
        "category": "脆弱性・パッチ", "importance": "高", "urgency": "本日確認",
        "summary": "要約", "financial_impact": "影響", "recommended_actions": ["対応1"],
        "reason": "理由", "tags": ["KEV"],
    }
    analysis.update(analysis_overrides)
    return {
        "title": title,
        "source": source,
        "ai_analysis": analysis,
        "ai_analysis_meta": {
            "status": status, "error_type": None, "http_status": None,
            "generated_at": "2026-07-11T07:00:00+09:00",
        },
    }


def call_gemini_todays_brief(brief_items=None, *, response_body=None, side_effect=None, capture_requests=None):
    """GEMINI_API_KEYを一時設定し、urllib.request.urlopenをモックしてgemini_todays_brief()を呼ぶ。"""
    if brief_items is None:
        brief_items = [make_brief_item()]
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
                return fetch.gemini_todays_brief(brief_items)


def get_request_body_json(brief_items=None, *, response_body=None):
    """gemini_todays_brief()が送信するリクエストボディ(JSON)を取得する。"""
    captured = []
    call_gemini_todays_brief(
        brief_items,
        response_body=response_body or make_brief_body(VALID_BRIEF_RESPONSE),
        capture_requests=captured,
    )
    return json.loads(captured[0].data)


# ── response_schema ───────────────────────────────────────────────────────

class ResponseSchemaTest(unittest.TestCase):
    def setUp(self):
        self.body = get_request_body_json()
        self.schema = self.body["generationConfig"]["response_schema"]
        self.properties = self.schema["properties"]

    def test_overview_is_string(self):
        self.assertEqual(self.properties["overview"]["type"], "STRING")

    def test_important_highlights_is_string_array(self):
        self.assertEqual(self.properties["important_highlights"]["type"], "ARRAY")
        self.assertEqual(self.properties["important_highlights"]["items"]["type"], "STRING")

    def test_discussion_points_is_string_array(self):
        self.assertEqual(self.properties["discussion_points"]["type"], "ARRAY")
        self.assertEqual(self.properties["discussion_points"]["items"]["type"], "STRING")

    def test_check_items_is_string_array(self):
        self.assertEqual(self.properties["check_items"]["type"], "ARRAY")
        self.assertEqual(self.properties["check_items"]["items"]["type"], "STRING")

    def test_all_four_fields_are_required(self):
        expected = {"overview", "important_highlights", "discussion_points", "check_items"}
        self.assertEqual(set(self.schema["required"]), expected)
        self.assertEqual(set(self.properties.keys()), expected)

    def test_array_max_items_are_declared_in_schema(self):
        self.assertEqual(self.properties["important_highlights"]["maxItems"], dj.BRIEF_MAX_HIGHLIGHTS)
        self.assertEqual(self.properties["discussion_points"]["maxItems"], dj.BRIEF_MAX_DISCUSSION_POINTS)
        self.assertEqual(self.properties["check_items"]["maxItems"], dj.BRIEF_MAX_CHECK_ITEMS)

    def test_response_mime_type_is_json_only(self):
        self.assertEqual(self.body["generationConfig"]["response_mime_type"], "application/json")


# ── 正規化 ────────────────────────────────────────────────────────────────

class NormalizeBriefResponseTest(unittest.TestCase):
    def test_accepts_valid_four_field_output(self):
        result = fetch.normalize_brief_response(dict(VALID_BRIEF_RESPONSE))
        self.assertEqual(result["overview"], VALID_BRIEF_RESPONSE["overview"])
        self.assertEqual(result["important_highlights"], VALID_BRIEF_RESPONSE["important_highlights"])
        self.assertEqual(result["discussion_points"], VALID_BRIEF_RESPONSE["discussion_points"])
        self.assertEqual(result["check_items"], VALID_BRIEF_RESPONSE["check_items"])

    def test_rejects_missing_overview(self):
        value = dict(VALID_BRIEF_RESPONSE)
        del value["overview"]
        self.assertIsNone(fetch.normalize_brief_response(value))

    def test_rejects_empty_overview(self):
        value = dict(VALID_BRIEF_RESPONSE)
        value["overview"] = "   "
        self.assertIsNone(fetch.normalize_brief_response(value))

    def test_rejects_non_list_array_field(self):
        value = dict(VALID_BRIEF_RESPONSE)
        value["check_items"] = "確認事項1"
        self.assertIsNone(fetch.normalize_brief_response(value))

    def test_removes_empty_strings_from_arrays(self):
        value = dict(VALID_BRIEF_RESPONSE)
        value["check_items"] = ["確認事項1", "", "   "]
        result = fetch.normalize_brief_response(value)
        self.assertEqual(result["check_items"], ["確認事項1"])

    def test_removes_null_and_none_string_literals(self):
        value = dict(VALID_BRIEF_RESPONSE)
        value["discussion_points"] = ["null", "None", "有効な論点"]
        result = fetch.normalize_brief_response(value)
        self.assertEqual(result["discussion_points"], ["有効な論点"])

    def test_removes_exact_duplicates_within_array(self):
        value = dict(VALID_BRIEF_RESPONSE)
        value["important_highlights"] = ["重複項目", "重複項目", "別項目"]
        result = fetch.normalize_brief_response(value)
        self.assertEqual(result["important_highlights"], ["重複項目", "別項目"])

    def test_truncates_arrays_exceeding_max_items_instead_of_accepting_all(self):
        value = dict(VALID_BRIEF_RESPONSE)
        value["check_items"] = ["確認1", "確認2", "確認3", "確認4", "確認5"]
        result = fetch.normalize_brief_response(value)
        self.assertEqual(len(result["check_items"]), dj.BRIEF_MAX_CHECK_ITEMS)
        self.assertEqual(result["check_items"], ["確認1", "確認2", "確認3", "確認4"])


# ── status: success / failed / not_attempted ────────────────────────────

class BriefStatusTest(unittest.TestCase):
    def test_valid_output_is_success(self):
        result = call_gemini_todays_brief(response_body=make_brief_body(VALID_BRIEF_RESPONSE))
        self.assertEqual(result["status"], "success")
        self.assertEqual(result["overview"], VALID_BRIEF_RESPONSE["overview"])
        self.assertIsNone(result["error_type"])

    def test_no_api_key_is_not_attempted(self):
        with patch.dict(os.environ, {}, clear=True):
            result = fetch.gemini_todays_brief([make_brief_item()])
        self.assertEqual(result["status"], "not_attempted")
        self.assertIsNone(result["overview"])
        self.assertEqual(result["important_highlights"], [])

    def test_build_todays_brief_is_not_attempted_when_no_valid_analysis(self):
        items = [
            {"title": "分析未実施", "source": "CISA", "ai_analysis": None, "ai_analysis_meta": None},
            {
                "title": "分析失敗", "source": "CISA", "ai_analysis": None,
                "ai_analysis_meta": {
                    "status": "failed", "error_type": "api_error",
                    "http_status": 500, "generated_at": "2026-07-11T07:00:00+09:00",
                },
            },
        ]
        result = fetch.build_todays_brief(items)
        self.assertEqual(result["status"], "not_attempted")
        self.assertIsNone(result["overview"])
        self.assertEqual(result["check_items"], [])

    def test_http_error_is_failed(self):
        result = call_gemini_todays_brief(
            side_effect=urllib.error.HTTPError("http://x", 500, "err", {}, None)
        )
        self.assertEqual(result["status"], "failed")
        self.assertIsNone(result["overview"])
        self.assertEqual(result["important_highlights"], [])

    def test_unparseable_response_is_failed(self):
        result = call_gemini_todays_brief(response_body=make_brief_body_from_raw("not json at all"))
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["error_type"], "schema_parse_error")
        self.assertIsNone(result["overview"])

    def test_failed_result_contains_no_boilerplate_text(self):
        result = call_gemini_todays_brief(
            side_effect=urllib.error.HTTPError("http://x", 500, "err", {}, None)
        )
        self.assertIsNone(result["overview"])
        self.assertEqual(result["important_highlights"], [])
        self.assertEqual(result["discussion_points"], [])
        self.assertEqual(result["check_items"], [])

    def test_select_brief_input_items_only_success_and_fallback(self):
        items = [
            make_brief_item("success-item", status="success"),
            make_brief_item("fallback-item", status="fallback"),
            {
                "title": "failed-item", "source": "CISA", "ai_analysis": None,
                "ai_analysis_meta": {
                    "status": "failed", "error_type": "api_error",
                    "http_status": 500, "generated_at": "2026-07-11T07:00:00+09:00",
                },
            },
            {"title": "not-attempted-item", "source": "CISA", "ai_analysis": None, "ai_analysis_meta": None},
        ]
        selected = fetch.select_brief_input_items(items)
        titles = [item["title"] for item in selected]
        self.assertEqual(titles, ["success-item", "fallback-item"])

    def test_each_call_regenerates_from_the_given_items_only(self):
        """同一日の再実行を模す: 直前の呼び出し結果が次の呼び出しへ引き継がれず、
        常にその時点で渡されたitemsだけから再生成されることを確認する
        (前日以前のBriefを流用しない)。
        """
        first = call_gemini_todays_brief(
            [make_brief_item("first-run-item")],
            response_body=make_brief_body(VALID_BRIEF_RESPONSE),
        )
        second_response = dict(VALID_BRIEF_RESPONSE)
        second_response["overview"] = (
            "本日2回目の実行時点の概況です。A社脆弱性の対応状況確認が引き続き必要です。"
            "他に大きな更新はありませんでした。"
        )
        second = call_gemini_todays_brief(
            [make_brief_item("second-run-item")],
            response_body=make_brief_body(second_response),
        )
        self.assertNotEqual(first["overview"], second["overview"])
        self.assertEqual(second["overview"], second_response["overview"])


if __name__ == "__main__":
    unittest.main()
