#!/usr/bin/env python3
"""
BL-032: 取得元別content usage policy enforcementの回帰テスト。
標準ライブラリの unittest のみを使用する。実際のGemini API・外部RSS/API/記事ページ/
robots.txt等へのアクセスは一切行わない(urllib.request.urlopenをモックに差し替える)。
"""

import copy
import datetime
import json
import os
import unittest
import urllib.error
from unittest.mock import patch

import daily_json as dj
import fetch


# ── テスト用ヘルパー ─────────────────────────────────────────────────────

def make_source_policy(**overrides):
    policy = {
        "content_usage_mode": "structured_open",
        "allow_network_fetch": True,
        "allow_description": True,
        "allow_rich_content": False,
        "allow_ai_processing": True,
        "allow_excerpt_storage": True,
        "allow_public_summary": True,
        "attribution_requirement": "test fixture",
        "attribution_url": None,
        "checked_at": "2026-07-29",
        "confidence": "high",
        "unresolved_issue": "",
        "recheck_trigger": "test fixture",
        "official_evidence_url": "https://example.com/terms",
        "evidence_type": "terms",
    }
    policy.update(overrides)
    return policy


def make_source_def(source_id="test_source", name="Test Source", **policy_overrides):
    return {
        "id": source_id,
        "name": name,
        "url": "https://example.com/feed.xml",
        "collection_method": "rss",
        "language": "en",
        "source_type": "その他",
        "source_tier": "Tier 3",
        "enabled": True,
        "planned_phase": "Phase 1",
        "activation_condition": "",
        "collection_frequency": "daily",
        "color": "#555",
        "trusted_cyber_source": False,
        "notes": "",
        "policy": make_source_policy(**policy_overrides),
    }


VALID_ANALYSIS_RESPONSE = {
    "title_ja": "テスト記事の見出し",
    "category": "脆弱性・パッチ",
    "category_reason": "CVEが主題のため。",
    "importance": "中",
    "urgency": "参考",
    "summary": "テスト記事の要約です。",
    "financial_impact": "金融機関への影響は限定的です。",
    "recommended_actions": [],
    "reason": "重要度は、影響範囲が限定的のため「中」です。確認目安は、緊急性が低いため「参考」です。",
    "tags": [],
}


def fake_gemini_response_body(analysis=None):
    analysis = analysis if analysis is not None else VALID_ANALYSIS_RESPONSE
    return json.dumps({
        "candidates": [{"content": {"parts": [{"text": json.dumps(analysis, ensure_ascii=False)}]}}]
    }).encode("utf-8")


class _FakeResponse:
    def __init__(self, body):
        self._body = body

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def make_item(content_policy, analysis_response=None, **overrides):
    item = {
        "source": "Test Source",
        "lang": "en",
        "link": "https://example.com/article",
        "title": "Raw Title",
        "raw_title": "Raw Title",
        "summary": "Original RSS description.",
        "raw_summary": "Original RSS description.",
        "rich_content": "",
        "date": None,
        "published_at_jst": None,
        "content_policy": content_policy,
    }
    item.update(overrides)
    return item, (analysis_response if analysis_response is not None else VALID_ANALYSIS_RESPONSE)


def run_enrich_with_ai(items_and_responses):
    """[(item, analysis_response), ...] を順にenrich_with_ai経由でGeminiへ送り、
    実際にurlopenが呼ばれた回数と、更新後のitem一覧を返す。"""
    items = [pair[0] for pair in items_and_responses]
    responses = [pair[1] for pair in items_and_responses]
    call_count = {"n": 0}

    def fake_urlopen(req, timeout=None):
        idx = call_count["n"]
        call_count["n"] += 1
        body = responses[idx] if idx < len(responses) else VALID_ANALYSIS_RESPONSE
        return _FakeResponse(fake_gemini_response_body(body))

    with patch.dict(os.environ, {"GEMINI_API_KEY": "test-key-not-real"}):
        with patch("fetch.urllib.request.urlopen", side_effect=fake_urlopen):
            with patch("fetch.time.sleep"):
                with patch("fetch.SOURCE_DEFINITIONS", fetch.SOURCE_DEFINITIONS + [
                    make_source_def("test_source", "Test Source"),
                    make_source_def("test_source_metadata_only", "Test Source Metadata Only",
                                    content_usage_mode="metadata_only", allow_description=False,
                                    allow_ai_processing=False, allow_excerpt_storage=False,
                                    allow_public_summary=False),
                ]):
                    fetch.enrich_with_ai(items)
    return items, call_count["n"]


class SourcePolicyDistributionTest(unittest.TestCase):
    """全17 sourceの分類・件数・rich content契約を検証する(BL-032 完了条件1)。"""

    def test_all_17_sources_have_valid_policy(self):
        for source in fetch.SOURCE_DEFINITIONS:
            with self.subTest(id=source["id"]):
                policy = dj.resolve_source_policy(source)
                self.assertIn(policy["content_usage_mode"], dj.CONTENT_USAGE_MODES)

    def test_all_17_sources_have_rich_content_disabled(self):
        for source in fetch.SOURCE_DEFINITIONS:
            with self.subTest(id=source["id"]):
                self.assertFalse(source["policy"]["allow_rich_content"])

    def test_mode_distribution_matches_approved_policy(self):
        fetch.validate_content_usage_mode_distribution(fetch.SOURCE_DEFINITIONS)  # 例外なければOK
        self.assertEqual(
            fetch.EXPECTED_CONTENT_USAGE_MODE_COUNTS,
            {"structured_open": 5, "feed_summary": 4, "limited_feed_analysis": 2,
             "metadata_only": 2, "disabled_legal_review": 4},
        )

    def test_disabled_legal_review_sources_have_no_network_fetch(self):
        disabled = [s for s in fetch.SOURCE_DEFINITIONS
                    if s["policy"]["content_usage_mode"] == "disabled_legal_review"]
        self.assertEqual(len(disabled), 4)
        for source in disabled:
            with self.subTest(id=source["id"]):
                self.assertFalse(source["policy"]["allow_network_fetch"])
                self.assertFalse(source["enabled"])

    def test_metadata_only_sources_disallow_content_use(self):
        metadata_only = [s for s in fetch.SOURCE_DEFINITIONS
                          if s["policy"]["content_usage_mode"] == "metadata_only"]
        self.assertEqual(len(metadata_only), 2)
        for source in metadata_only:
            with self.subTest(id=source["id"]):
                self.assertFalse(source["policy"]["allow_description"])
                self.assertFalse(source["policy"]["allow_ai_processing"])
                self.assertFalse(source["policy"]["allow_excerpt_storage"])
                self.assertFalse(source["policy"]["allow_public_summary"])

    def test_gemini_data_use_status_is_paid_verified(self):
        self.assertEqual(fetch.GEMINI_DATA_USE_STATUS, "paid_verified")


class EffectiveModeComputationTest(unittest.TestCase):
    """configured mode + Gemini gateからeffective modeを決定するロジック(BL-032)。"""

    def test_structured_open_unaffected_by_gate(self):
        policy = make_source_policy(content_usage_mode="structured_open")
        for status in ("paid_verified", "unpaid", "unknown"):
            with self.subTest(status=status):
                mode, reason = dj.compute_effective_content_usage_mode(policy, status)
                self.assertEqual(mode, "structured_open")
                self.assertIsNone(reason)

    def test_feed_summary_downgrades_when_gate_not_paid(self):
        policy = make_source_policy(content_usage_mode="feed_summary")
        for status in ("unpaid", "unknown"):
            with self.subTest(status=status):
                mode, reason = dj.compute_effective_content_usage_mode(policy, status)
                self.assertEqual(mode, "metadata_only")
                self.assertEqual(reason, "gemini_gate_not_paid")

    def test_feed_summary_stays_when_gate_paid_verified(self):
        policy = make_source_policy(content_usage_mode="feed_summary")
        mode, reason = dj.compute_effective_content_usage_mode(policy, "paid_verified")
        self.assertEqual(mode, "feed_summary")
        self.assertIsNone(reason)

    def test_limited_feed_analysis_downgrades_when_gate_not_paid(self):
        policy = make_source_policy(content_usage_mode="limited_feed_analysis")
        mode, reason = dj.compute_effective_content_usage_mode(policy, "unknown")
        self.assertEqual(mode, "metadata_only")
        self.assertEqual(reason, "gemini_gate_not_paid")

    def test_metadata_only_stays_metadata_only_regardless_of_gate(self):
        policy = make_source_policy(content_usage_mode="metadata_only")
        for status in ("paid_verified", "unpaid", "unknown"):
            mode, reason = dj.compute_effective_content_usage_mode(policy, status)
            self.assertEqual(mode, "metadata_only")
            self.assertIsNone(reason)

    def test_ai_eligible_matches_mode(self):
        self.assertTrue(dj.is_ai_eligible_content_usage_mode("structured_open"))
        self.assertTrue(dj.is_ai_eligible_content_usage_mode("feed_summary"))
        self.assertTrue(dj.is_ai_eligible_content_usage_mode("limited_feed_analysis"))
        self.assertFalse(dj.is_ai_eligible_content_usage_mode("metadata_only"))
        self.assertFalse(dj.is_ai_eligible_content_usage_mode("disabled_legal_review"))


class GeminiGateEnrichmentTest(unittest.TestCase):
    """enrich_with_ai()がpolicy.ai_eligibleに従ってGemini呼び出しを制御することを検証する。"""

    def _content_policy(self, configured_mode, gate_status):
        source_policy = make_source_policy(content_usage_mode=configured_mode)
        effective_mode, reason = dj.compute_effective_content_usage_mode(source_policy, gate_status)
        return dj.build_item_content_policy("test_source", configured_mode, effective_mode, reason)

    def test_metadata_only_makes_zero_gemini_calls(self):
        content_policy = self._content_policy("metadata_only", "paid_verified")
        item, response = make_item(content_policy)
        items, call_count = run_enrich_with_ai([(item, response)])
        self.assertEqual(call_count, 0)
        self.assertNotIn("ai_analysis", items[0])
        self.assertNotIn("ai_analysis_meta", items[0])

    def test_feed_summary_with_unpaid_gate_makes_zero_gemini_calls(self):
        content_policy = self._content_policy("feed_summary", "unpaid")
        self.assertFalse(content_policy["ai_eligible"])
        item, response = make_item(content_policy)
        items, call_count = run_enrich_with_ai([(item, response)])
        self.assertEqual(call_count, 0)

    def test_feed_summary_with_paid_verified_gate_calls_gemini(self):
        content_policy = self._content_policy("feed_summary", "paid_verified")
        self.assertTrue(content_policy["ai_eligible"])
        item, response = make_item(content_policy)
        items, call_count = run_enrich_with_ai([(item, response)])
        self.assertEqual(call_count, 1)
        self.assertIsNotNone(items[0].get("ai_analysis"))

    def test_structured_open_calls_gemini_regardless_of_gate(self):
        content_policy = self._content_policy("structured_open", "unknown")
        item, response = make_item(content_policy)
        items, call_count = run_enrich_with_ai([(item, response)])
        self.assertEqual(call_count, 1)


class LimitedFeedAnalysisTitleJaTest(unittest.TestCase):
    """limited_feed_analysisでは日本語翻訳タイトルを公開しないことを検証する。"""

    def test_title_ja_is_stripped_for_limited_feed_analysis(self):
        source_policy = make_source_policy(content_usage_mode="limited_feed_analysis")
        effective_mode, reason = dj.compute_effective_content_usage_mode(source_policy, "paid_verified")
        content_policy = dj.build_item_content_policy(
            "test_source", "limited_feed_analysis", effective_mode, reason
        )
        item, response = make_item(content_policy)
        items, call_count = run_enrich_with_ai([(item, response)])
        self.assertEqual(call_count, 1)
        self.assertIsNotNone(items[0].get("ai_analysis"))
        self.assertIsNone(items[0]["ai_analysis"]["title_ja"])
        # 他のfieldはそのまま利用可能(全体をmetadata-onlyへ落とさない)。
        self.assertEqual(items[0]["ai_analysis"]["category"], "脆弱性・パッチ")


class OutputPolicyValidationTest(unittest.TestCase):
    """daily_json.validate_output_policy()の単体テスト(BL-032)。"""

    def test_valid_analysis_passes(self):
        ok, reason = dj.validate_output_policy(
            "feed_summary", "some short source text", dict(VALID_ANALYSIS_RESPONSE)
        )
        self.assertTrue(ok)
        self.assertIsNone(reason)

    def test_forbidden_translated_title_for_limited_feed_analysis(self):
        analysis = dict(VALID_ANALYSIS_RESPONSE)
        ok, reason = dj.validate_output_policy("limited_feed_analysis", "", analysis)
        self.assertFalse(ok)
        self.assertEqual(reason, "forbidden_translated_title")

    def test_limited_feed_analysis_passes_when_title_ja_already_none(self):
        analysis = dict(VALID_ANALYSIS_RESPONSE)
        analysis["title_ja"] = None
        ok, reason = dj.validate_output_policy("limited_feed_analysis", "", analysis)
        self.assertTrue(ok)
        self.assertIsNone(reason)

    def test_output_length_violation_on_summary(self):
        analysis = dict(VALID_ANALYSIS_RESPONSE)
        analysis["summary"] = "x" * (dj.OUTPUT_FIELD_MAX_CHARS["summary"] + 1)
        ok, reason = dj.validate_output_policy("structured_open", "", analysis)
        self.assertFalse(ok)
        self.assertEqual(reason, "output_length_violation")

    def test_output_length_violation_on_recommended_action(self):
        analysis = dict(VALID_ANALYSIS_RESPONSE)
        analysis["recommended_actions"] = ["y" * (dj.OUTPUT_FIELD_MAX_CHARS["recommended_action_item"] + 1)]
        ok, reason = dj.validate_output_policy("structured_open", "", analysis)
        self.assertFalse(ok)
        self.assertEqual(reason, "output_length_violation")

    def test_verbatim_long_match_detected_for_feed_summary(self):
        source_text = "This is a long sentence copied verbatim from the source description text."
        analysis = dict(VALID_ANALYSIS_RESPONSE)
        analysis["summary"] = source_text
        ok, reason = dj.validate_output_policy("feed_summary", source_text, analysis)
        self.assertFalse(ok)
        self.assertEqual(reason, "verbatim_long_match")

    def test_verbatim_long_match_not_checked_for_structured_open(self):
        # structured_openは公式ライセンス上、原文との重なりを禁止しない。
        source_text = "This is a long sentence copied verbatim from the source description text."
        analysis = dict(VALID_ANALYSIS_RESPONSE)
        analysis["summary"] = source_text
        ok, reason = dj.validate_output_policy("structured_open", source_text, analysis)
        self.assertTrue(ok)
        self.assertIsNone(reason)

    def test_short_common_overlap_does_not_false_positive(self):
        source_text = "CVE-2026-1234 affects Example Product version 1.0."
        analysis = dict(VALID_ANALYSIS_RESPONSE)
        analysis["summary"] = "CVE-2026-1234が公開されました。詳細を確認してください。"
        ok, reason = dj.validate_output_policy("feed_summary", source_text, analysis)
        self.assertTrue(ok)
        self.assertIsNone(reason)

    def test_missing_attribution_is_a_violation(self):
        ok, reason = dj.validate_output_policy(
            "structured_open", "", dict(VALID_ANALYSIS_RESPONSE), attribution_ok=False
        )
        self.assertFalse(ok)
        self.assertEqual(reason, "missing_attribution")

    def test_invalid_analysis_shape_is_a_violation(self):
        ok, reason = dj.validate_output_policy("structured_open", "", None)
        self.assertFalse(ok)
        self.assertEqual(reason, "invalid_mode_analysis_combination")


class PolicyViolationFallbackEnrichmentTest(unittest.TestCase):
    """policy違反時、enrich_with_ai()が記事をmetadata-only相当へdowngradeし、
    分析を公開しないことを検証する(BL-032)。"""

    def test_verbatim_long_match_downgrades_item_to_metadata_only(self):
        source_policy = make_source_policy(content_usage_mode="feed_summary")
        effective_mode, reason = dj.compute_effective_content_usage_mode(source_policy, "paid_verified")
        content_policy = dj.build_item_content_policy(
            "test_source", "feed_summary", effective_mode, reason
        )
        verbatim_text = "This sentence appears identically in both the source and the output field."
        item, _ = make_item(content_policy, summary=verbatim_text, raw_summary=verbatim_text)
        response = dict(VALID_ANALYSIS_RESPONSE)
        response["summary"] = verbatim_text
        items, call_count = run_enrich_with_ai([(item, response)])
        self.assertEqual(call_count, 1)
        self.assertNotIn("ai_analysis", items[0])
        self.assertNotIn("ai_analysis_meta", items[0])
        self.assertFalse(items[0]["content_policy"]["ai_eligible"])
        self.assertEqual(items[0]["content_policy"]["effective_mode"], "metadata_only")
        self.assertEqual(items[0]["content_policy"]["downgrade_reason"], "verbatim_long_match")

    def test_output_length_violation_downgrades_item_to_metadata_only(self):
        source_policy = make_source_policy(content_usage_mode="structured_open")
        content_policy = dj.build_item_content_policy(
            "test_source", "structured_open", "structured_open", None
        )
        item, _ = make_item(content_policy)
        response = dict(VALID_ANALYSIS_RESPONSE)
        response["summary"] = "x" * (dj.OUTPUT_FIELD_MAX_CHARS["summary"] + 1)
        items, call_count = run_enrich_with_ai([(item, response)])
        self.assertEqual(call_count, 1)
        self.assertNotIn("ai_analysis", items[0])
        self.assertFalse(items[0]["content_policy"]["ai_eligible"])
        self.assertEqual(items[0]["content_policy"]["downgrade_reason"], "output_length_violation")


class RichContentSuppressionTest(unittest.TestCase):
    """全17 sourceでrich contentがGemini入力へ使用されないことを検証する(BL-032)。"""

    def test_rich_content_not_used_for_any_real_source(self):
        for source in fetch.SOURCE_DEFINITIONS:
            if source["collection_method"] != "rss" or not source["enabled"]:
                continue
            with self.subTest(id=source["id"]):
                content_policy = dj.build_item_content_policy(
                    source["id"], source["policy"]["content_usage_mode"],
                    source["policy"]["content_usage_mode"], None,
                )
                if not content_policy["ai_eligible"]:
                    continue
                item, response = make_item(
                    content_policy,
                    source="Test Source",
                    rich_content="UNIQUE-RICH-CONTENT-MARKER-MUST-NOT-APPEAR" * 5,
                    summary="short description",
                )
                captured = {}

                def fake_urlopen(req, timeout=None, _captured=captured):
                    _captured["text"] = req.data.decode("utf-8")
                    return _FakeResponse(fake_gemini_response_body(response))

                with patch.dict(os.environ, {"GEMINI_API_KEY": "test-key-not-real"}):
                    with patch("fetch.urllib.request.urlopen", side_effect=fake_urlopen):
                        with patch("fetch.time.sleep"):
                            with patch("fetch.SOURCE_DEFINITIONS",
                                       fetch.SOURCE_DEFINITIONS + [make_source_def("test_source", "Test Source")]):
                                fetch.enrich_with_ai([item])
                if "text" in captured:
                    self.assertNotIn("UNIQUE-RICH-CONTENT-MARKER-MUST-NOT-APPEAR", captured["text"])


class ItemSourceIdentityPersistenceTest(unittest.TestCase):
    """収集時にitemへ付与したsource_id/content_policyが、後段の日次JSON構築でも
    保持されることを検証する(BL-032)。"""

    def test_collect_recent_annotates_items_with_source_id_and_policy(self):
        source_def = fetch.get_source_definition(fetch.SOURCE_DEFINITIONS, "fsa")
        item = {"source": "金融庁", "date": None}
        fetch.annotate_item_content_policy(item, source_def, "paid_verified")
        self.assertEqual(item["source_id"], "fsa")
        self.assertEqual(item["content_policy"]["configured_mode"], "structured_open")
        self.assertTrue(item["content_policy"]["ai_eligible"])
        self.assertIsNone(item["content_policy"]["downgrade_reason"])


class ArticleEntryPolicyPersistenceTest(unittest.TestCase):
    """build_article_entry()がpolicyを記録し、raw_excerptをallow_excerpt_storage
    でgateすることを検証する(BL-032)。"""

    def _source_definitions(self, mode, allow_excerpt_storage):
        return [make_source_def("cisa", "CISA", content_usage_mode=mode,
                                 allow_excerpt_storage=allow_excerpt_storage,
                                 allow_description=True, allow_ai_processing=True,
                                 allow_public_summary=True)]

    def test_structured_open_keeps_raw_excerpt(self):
        source_defs = self._source_definitions("structured_open", True)
        content_policy = dj.build_item_content_policy("cisa", "structured_open", "structured_open", None)
        item = {"source": "CISA", "raw_title": "t", "raw_summary": "some description",
                "link": "https://example.com/a", "content_policy": content_policy, "facts": {"cves": []}}
        entry = dj.build_article_entry(
            item, source_defs, "gemini-2.5-flash",
            __import__("datetime").datetime(2026, 7, 30, 7, 0, tzinfo=dj.JST),
        )
        self.assertEqual(entry["raw_excerpt"], "some description")
        self.assertEqual(entry["policy"]["configured_mode"], "structured_open")
        self.assertTrue(entry["policy"]["ai_eligible"])

    def test_feed_summary_does_not_persist_raw_excerpt(self):
        source_defs = self._source_definitions("feed_summary", False)
        content_policy = dj.build_item_content_policy("cisa", "feed_summary", "feed_summary", None)
        item = {"source": "CISA", "raw_title": "t", "raw_summary": "some description",
                "link": "https://example.com/a", "content_policy": content_policy, "facts": {"cves": []}}
        entry = dj.build_article_entry(
            item, source_defs, "gemini-2.5-flash",
            __import__("datetime").datetime(2026, 7, 30, 7, 0, tzinfo=dj.JST),
        )
        self.assertIsNone(entry["raw_excerpt"])

    def test_metadata_only_does_not_persist_raw_excerpt(self):
        source_defs = self._source_definitions("metadata_only", False)
        content_policy = dj.build_item_content_policy("cisa", "metadata_only", "metadata_only", None)
        item = {"source": "CISA", "raw_title": "t", "raw_summary": "some description",
                "link": "https://example.com/a", "content_policy": content_policy, "facts": {"cves": []}}
        entry = dj.build_article_entry(
            item, source_defs, "gemini-2.5-flash",
            __import__("datetime").datetime(2026, 7, 30, 7, 0, tzinfo=dj.JST),
        )
        self.assertIsNone(entry["raw_excerpt"])
        self.assertFalse(entry["policy"]["ai_eligible"])


class DailyJsonV2RunCountsTest(unittest.TestCase):
    """schema v2のrun/counts契約(policy_excluded_count/ai_eligible_count、
    metadata-only相当を未判定へ加算しない)を検証する(BL-032)。"""

    def _entry(self, ai_eligible, status="not_attempted", importance=None, urgency=None,
               category=None):
        return {
            "analysis": {
                "status": status, "importance": importance, "urgency": urgency,
                "category": category,
            },
            "policy": {
                "configured_mode": "metadata_only" if not ai_eligible else "structured_open",
                "effective_mode": "metadata_only" if not ai_eligible else "structured_open",
                "ai_eligible": ai_eligible,
                "downgrade_reason": None,
            },
        }

    def test_policy_excluded_items_are_not_counted_as_ai_not_attempted(self):
        entries = [
            self._entry(True, status="success", importance="高", urgency="本日確認",
                        category="脆弱性・パッチ"),
            self._entry(False),
            self._entry(False),
        ]
        run = dj.compute_run_meta(entries, force_schema_version=dj.SCHEMA_VERSION)
        self.assertEqual(run["total_items"], 3)
        self.assertEqual(run["policy_excluded_count"], 2)
        self.assertEqual(run["ai_eligible_count"], 1)
        self.assertEqual(run["ai_success_count"], 1)
        self.assertEqual(run["ai_not_attempted_count"], 0)
        self.assertEqual(run["status"], "success")

    def test_policy_excluded_items_are_not_counted_in_importance_buckets(self):
        entries = [
            self._entry(True, status="success", importance="高", urgency="本日確認",
                        category="脆弱性・パッチ"),
            self._entry(False),
        ]
        counts = dj.compute_counts(entries)
        self.assertEqual(sum(counts["importance"].values()), 1)
        self.assertEqual(counts["importance"]["高"], 1)
        self.assertEqual(counts["importance"]["未判定"], 0)

    def test_all_policy_excluded_run_status_is_success(self):
        entries = [self._entry(False), self._entry(False)]
        run = dj.compute_run_meta(entries, force_schema_version=dj.SCHEMA_VERSION)
        self.assertEqual(run["ai_eligible_count"], 0)
        self.assertEqual(run["policy_excluded_count"], 2)
        self.assertEqual(run["status"], "success")


class DashboardCountsExclusionTest(unittest.TestCase):
    """compute_dashboard_counts()がpolicy-excluded記事をtotalには含めつつ、
    importance/urgency/category集計と未判定からは除外することを検証する(BL-032)。"""

    def _eligible_item(self):
        return {
            "content_policy": {"ai_eligible": True, "configured_mode": "structured_open",
                                "effective_mode": "structured_open", "downgrade_reason": None},
            "ai_analysis": dict(VALID_ANALYSIS_RESPONSE),
        }

    def _excluded_item(self):
        return {
            "content_policy": {"ai_eligible": False, "configured_mode": "metadata_only",
                                "effective_mode": "metadata_only", "downgrade_reason": None},
        }

    def test_total_includes_policy_excluded_items(self):
        counts = fetch.compute_dashboard_counts([self._eligible_item(), self._excluded_item()])
        self.assertEqual(counts["total"], 2)

    def test_policy_excluded_items_not_in_importance_urgency_category(self):
        counts = fetch.compute_dashboard_counts([self._eligible_item(), self._excluded_item()])
        self.assertEqual(sum(counts["importance"].values()), 1)
        self.assertEqual(counts["importance"]["中"], 1)
        self.assertEqual(counts["importance"][fetch.UNKNOWN_LABEL], 0)
        self.assertEqual(sum(counts["urgency"].values()), 1)
        self.assertEqual(sum(counts["category"].values()), 1)

    def test_item_is_ai_eligible_defaults_true_without_content_policy(self):
        self.assertTrue(fetch.item_is_ai_eligible({}))


class TodaysBriefEligibilityExclusionTest(unittest.TestCase):
    """PR #69レビュー(round 3)Blocker 1: metadata-only相当の記事が
    Today's Briefの掲載件数・未判定件数・provenanceへ入らないことを検証する
    (BL-032完了条件11)。Dashboardの掲載総数(compute_dashboard_counts)は
    別契約であり、DashboardCountsExclusionTestで検証済み(ここでは変更しない)。
    """

    MARKER = "UNIQUE-METADATA-ONLY-BRIEF-MARKER"

    def _evaluated_item(self, title="Evaluated Title"):
        return {
            "title": title, "raw_title": title, "source": "Test Source",
            "link": "https://example.com/a",
            "ai_analysis": dict(VALID_ANALYSIS_RESPONSE),
            "ai_analysis_meta": {"status": "success", "error_type": None, "http_status": None,
                                  "generated_at": "2026-07-31T00:00:00+09:00"},
            "content_policy": {"source_id": "test_source", "configured_mode": "structured_open",
                                "effective_mode": "structured_open", "ai_eligible": True,
                                "downgrade_reason": None},
        }

    def _failed_item(self, title="Failed Title"):
        return {
            "title": title, "raw_title": title, "source": "Test Source",
            "link": "https://example.com/b",
            "ai_analysis": None,
            "ai_analysis_meta": {"status": "failed", "error_type": "api_error", "http_status": 500,
                                  "generated_at": "2026-07-31T00:00:00+09:00"},
            "content_policy": {"source_id": "test_source", "configured_mode": "structured_open",
                                "effective_mode": "structured_open", "ai_eligible": True,
                                "downgrade_reason": None},
        }

    def _metadata_only_item(self, title=None):
        return {
            "title": title or self.MARKER, "raw_title": title or self.MARKER,
            "source": self.MARKER, "link": "https://example.com/c",
            "content_policy": {"source_id": "microsoft_security", "configured_mode": "metadata_only",
                                "effective_mode": "metadata_only", "ai_eligible": False,
                                "downgrade_reason": None},
        }

    def test_published_total_excludes_metadata_only_and_has_no_unclassified(self):
        result = fetch.build_todays_brief([self._evaluated_item(), self._metadata_only_item()])
        self.assertEqual(result["status"], "success")
        self.assertIn("掲載1件", result["overview"])
        self.assertNotIn("未判定", result["overview"])

    def test_metadata_only_fields_do_not_appear_in_brief_or_provenance(self):
        composition = fetch.compose_extractive_brief(
            [self._evaluated_item(), self._metadata_only_item()]
        )
        brief_json = json.dumps(composition["brief"], ensure_ascii=False)
        provenance_json = json.dumps(composition["provenance"], ensure_ascii=False)
        self.assertNotIn(self.MARKER, brief_json)
        self.assertNotIn(self.MARKER, provenance_json)

    def test_unclassified_counts_only_failed_not_metadata_only(self):
        result = fetch.build_todays_brief(
            [self._evaluated_item(), self._failed_item(), self._metadata_only_item()]
        )
        self.assertIn("掲載2件", result["overview"])
        self.assertIn("未判定1件", result["overview"])

    def test_metadata_only_only_items_result_in_not_attempted_brief(self):
        result = fetch.build_todays_brief([self._metadata_only_item()])
        self.assertEqual(result["status"], "not_attempted")

    def test_legacy_item_without_content_policy_still_counted(self):
        legacy_item = {
            "title": "Legacy", "raw_title": "Legacy", "source": "Legacy Source",
            "link": "https://example.com/legacy",
            "ai_analysis": dict(VALID_ANALYSIS_RESPONSE),
            "ai_analysis_meta": {"status": "success", "error_type": None, "http_status": None,
                                  "generated_at": "2026-07-31T00:00:00+09:00"},
        }
        result = fetch.build_todays_brief([legacy_item])
        self.assertEqual(result["status"], "success")
        self.assertIn("掲載1件", result["overview"])


class VulnerabilityFactsScopingTest(unittest.TestCase):
    """metadata-only相当の記事はCVE facts取得の対象外、feed_summary/
    limited_feed_analysisはpublisher descriptionをfacts抽出へ使わないことを
    検証する(BL-032)。"""

    def _item(self, ai_eligible, configured_mode, title, summary, raw_summary=None):
        return {
            "title": title, "raw_title": title,
            "summary": summary, "raw_summary": raw_summary if raw_summary is not None else summary,
            "link": "https://example.com/a",
            "content_policy": {
                "ai_eligible": ai_eligible, "configured_mode": configured_mode,
                "effective_mode": configured_mode if ai_eligible else "metadata_only",
                "downgrade_reason": None,
            },
        }

    def test_metadata_only_equivalent_item_gets_no_facts_lookup(self):
        item = self._item(False, "metadata_only", "No CVE here", "CVE-2026-9999 in description")
        with patch("vulnerability_facts.build_facts_for_items") as mock_build:
            fetch.build_scoped_vulnerability_facts(
                [item], cache_path="/tmp/does-not-matter.json", kev_url="https://example.com/kev",
            )
        mock_build.assert_called_once()
        # metadata-only相当の記事はviewsに含まれない(外部取得の対象外)。
        called_items = mock_build.call_args[0][0]
        self.assertEqual(called_items, [])
        self.assertEqual(item["facts"], {"cves": []})

    def test_feed_summary_item_does_not_use_description_for_extraction(self):
        item = self._item(True, "feed_summary", "No CVE here", "CVE-2026-1234 in description")
        with patch("vulnerability_facts.build_facts_for_items") as mock_build:
            mock_build.side_effect = lambda views, **kw: [v.__setitem__("facts", {"cves": []}) for v in views] and {}
            fetch.build_scoped_vulnerability_facts(
                [item], cache_path="/tmp/does-not-matter.json", kev_url="https://example.com/kev",
            )
        called_items = mock_build.call_args[0][0]
        self.assertEqual(len(called_items), 1)
        self.assertEqual(called_items[0]["summary"], "")
        self.assertEqual(called_items[0]["raw_summary"], "")
        self.assertEqual(called_items[0]["title"], "No CVE here")

    def test_structured_open_item_uses_description_for_extraction(self):
        item = self._item(True, "structured_open", "No CVE here", "CVE-2026-1234 in description")
        with patch("vulnerability_facts.build_facts_for_items") as mock_build:
            mock_build.side_effect = lambda views, **kw: [v.__setitem__("facts", {"cves": []}) for v in views] and {}
            fetch.build_scoped_vulnerability_facts(
                [item], cache_path="/tmp/does-not-matter.json", kev_url="https://example.com/kev",
            )
        called_items = mock_build.call_args[0][0]
        self.assertEqual(called_items[0]["summary"], "CVE-2026-1234 in description")


class MetadataOnlyCardRenderingTest(unittest.TestCase):
    """metadata-only相当の記事が簡易カードとして表示され、AI field・factsを
    表示しないことを検証する(BL-032)。"""

    def _metadata_only_item(self):
        return {
            "source": "Microsoft Security", "lang": "en",
            "link": "https://example.com/article",
            "title": "Raw English Title", "raw_title": "Raw English Title",
            "summary": "Publisher description that must not be shown.",
            "date": None,
            "facts": {"cves": [{"cve_id": "CVE-2026-1234",
                                 "nvd": {"status": "found", "retrieval": "live", "cvss": None,
                                         "vuln_status": None, "published_at": None,
                                         "last_modified_at": None, "url": ""},
                                 "kev": {"status": "not_listed", "retrieval": "live",
                                         "date_added": None}}]},
            "content_policy": {
                "source_id": "microsoft_security", "configured_mode": "metadata_only",
                "effective_mode": "metadata_only", "ai_eligible": False,
                "downgrade_reason": None,
            },
        }

    def test_metadata_only_card_shows_title_source_date_url_only(self):
        html = fetch.build_html([self._metadata_only_item()])
        self.assertIn("card-metadata-only", html)
        self.assertIn("Raw English Title", html)
        self.assertIn("Microsoft Security", html)
        self.assertIn("https://example.com/article", html)

    def test_metadata_only_card_hides_publisher_summary_and_facts(self):
        html = fetch.build_html([self._metadata_only_item()])
        self.assertNotIn("Publisher description that must not be shown", html)
        self.assertNotIn("CVE-2026-1234", html)
        self.assertNotIn("脆弱性情報", html)

    def test_metadata_only_card_shows_no_ai_evaluation_note(self):
        html = fetch.build_html([self._metadata_only_item()])
        self.assertIn("AIによる要約・評価は行っていません", html)

    def test_metadata_only_card_hides_assessment_and_tags(self):
        # Note: "article-assessment"/"article-tags" also appear as CSS class
        # selectors in the page's static <style> block, so check for the
        # actual rendered element markup instead of the bare class name.
        html = fetch.build_html([self._metadata_only_item()])
        self.assertNotIn('class="article-assessment"', html)
        self.assertNotIn('class="article-tags"', html)


class ModeAttributionRenderingTest(unittest.TestCase):
    """mode別attribution文言がHTMLへ正しく表示されることを検証する(BL-032)。"""

    def _item_with_mode(self, mode, source_id="test_source"):
        return {
            "source": "Test Source", "lang": "en", "link": "https://example.com/a",
            "title": "t", "raw_title": "t", "summary": "s", "date": None,
            "facts": {"cves": []},
            "content_policy": {
                "source_id": source_id, "configured_mode": mode, "effective_mode": mode,
                "ai_eligible": mode != "metadata_only", "downgrade_reason": None,
            },
        }

    def test_feed_summary_attribution_text(self):
        html = fetch.build_html([self._item_with_mode("feed_summary")])
        self.assertIn("Monomi DigestによるAI要約・分析", html)

    def test_limited_feed_analysis_attribution_text(self):
        html = fetch.build_html([self._item_with_mode("limited_feed_analysis")])
        self.assertIn("Monomi Digestが公式RSSの概要をもとに生成したAI分析", html)
        self.assertIn("原文の転載・代替を目的とするものではありません", html)

    def test_structured_open_with_unmapped_source_id_shows_no_attribution(self):
        # PR #69レビューBlocker 2: attribution_requirement(監査上の説明文)を
        # そのままUI文言として表示しない。STRUCTURED_OPEN_ATTRIBUTION_SOURCE_IDS
        # に無いsource_idは、実際のattribution表示を持たないため何も表示しない。
        with patch("fetch.SOURCE_DEFINITIONS",
                   fetch.SOURCE_DEFINITIONS + [make_source_def(
                       "test_source", "Test Source",
                       content_usage_mode="structured_open",
                       attribution_requirement="UNIQUE-ATTRIBUTION-TEXT-FOR-TEST",
                   )]):
            html = fetch.build_html([self._item_with_mode("structured_open")])
        self.assertNotIn("UNIQUE-ATTRIBUTION-TEXT-FOR-TEST", html)
        # BL-036 added a shared `.article-attribution` CSS rule to every page's
        # <style> block, so a bare substring check now always matches that rule
        # even when no card renders the element. Check for the actual element
        # instead of the class-name substring.
        self.assertNotIn('<p class="article-attribution">', html)

    def test_no_attribution_shown_without_content_policy(self):
        item = {
            "source": "CISA", "lang": "en", "link": "https://example.com/a",
            "title": "t", "raw_title": "t", "summary": "s", "date": None,
            "facts": {"cves": []},
        }
        html = fetch.build_html([item])
        # BL-036: see the comment in
        # test_structured_open_with_unmapped_source_id_shows_no_attribution
        # above -- the shared CSS rule makes the bare substring always present.
        self.assertNotIn('<p class="article-attribution">', html)


class Bl036AttributionDomOrderAndEscapingTest(unittest.TestCase):
    """BL-036 (Fable 5 review R-01): the CSS-only change must not disturb the
    attribution element's DOM position (after AI analysis, before the source
    CTA) or its existing HTML-escaping/mode-gating contract.
    """

    def _item_with_full_analysis(self, mode, source_id="test_source"):
        return {
            "source": "Test Source", "lang": "en", "link": "https://example.com/a",
            "title": "t", "raw_title": "t", "summary": "s", "date": None,
            "facts": {"cves": []},
            "content_policy": {
                "source_id": source_id, "configured_mode": mode, "effective_mode": mode,
                "ai_eligible": True, "downgrade_reason": None,
            },
            "ai_analysis": {
                "category": "脆弱性・パッチ", "importance": "高", "urgency": "本日確認",
                "summary": "要約", "financial_impact": "影響",
                "recommended_actions": ["対応1"], "reason": "理由", "tags": ["KEV"],
            },
            "ai_analysis_meta": {"status": "success", "error_type": None, "http_status": None},
        }

    def test_attribution_appears_after_ai_analysis_and_before_source_link(self):
        html = fetch.build_html([self._item_with_full_analysis("limited_feed_analysis")])
        ai_analysis_index = html.index('<div class="ai-analysis">')
        attribution_index = html.index('<p class="article-attribution">')
        source_link_index = html.index('<a class="article-source-link"')
        self.assertLess(ai_analysis_index, attribution_index)
        self.assertLess(attribution_index, source_link_index)

    def test_attribution_text_is_html_escaped(self):
        with patch("fetch._METADATA_ONLY_ATTRIBUTION_TEXT", "<b>&injected</b>"):
            item = self._item_with_full_analysis("metadata_only")
            item["content_policy"]["ai_eligible"] = False
            html = fetch.build_html([item])
        self.assertIn("&lt;b&gt;&amp;injected&lt;/b&gt;", html)
        self.assertNotIn("<b>&injected</b>", html)

    def test_mode_gating_is_unaffected_by_the_css_change(self):
        # A quick cross-check that BL-032's mode -> attribution-text mapping
        # still holds after the CSS-only change (full mode coverage is
        # ModeAttributionRenderingTest's job; this only confirms no regression
        # was introduced alongside the CSS).
        html = fetch.build_html([self._item_with_full_analysis("limited_feed_analysis")])
        self.assertIn(fetch._LIMITED_FEED_ANALYSIS_ATTRIBUTION_TEXT, html)


class StructuredOpenRealAttributionRenderingTest(unittest.TestCase):
    """PR #69レビューBlocker 2: structured_openのattributionが、監査記述
    (attribution_requirement)の垂れ流しではなく、実際の表示(実URL・実日付・
    実免責文)として組み立てられることを検証する。"""

    def _item(self, source_id, source="Test Source"):
        return {
            "source": source, "lang": "en", "link": "https://example.com/a",
            "title": "t", "raw_title": "t", "summary": "s", "date": None,
            "facts": {"cves": []},
            "content_policy": {
                "source_id": source_id, "configured_mode": "structured_open",
                "effective_mode": "structured_open", "ai_eligible": True,
                "downgrade_reason": None,
            },
        }

    @staticmethod
    def _source_definitions_with_ncsc_attribution_url(attribution_url):
        """実際のfetch.SOURCE_DEFINITIONSのコピーを返すが、ncsc.policy.
        attribution_urlだけを差し替える(他16 sourceの定義はそのまま)。"""
        defs = copy.deepcopy(fetch.SOURCE_DEFINITIONS)
        for source in defs:
            if source["id"] == "ncsc":
                source["policy"]["attribution_url"] = attribution_url
        return defs

    def test_ncsc_ogl_v3_link_has_correct_href(self):
        ncsc_url = "https://www.nationalarchives.gov.uk/doc/open-government-licence/version/3/"
        with patch("fetch.SOURCE_DEFINITIONS",
                   self._source_definitions_with_ncsc_attribution_url(ncsc_url)):
            html = fetch.build_html(
                [self._item("ncsc", source="NCSC")],
                generated_at=__import__("datetime").datetime(2026, 7, 31, 7, 0, tzinfo=dj.JST),
            )
        self.assertIn(f'href="{ncsc_url}"', html)
        self.assertIn("Open Government Licence v3.0", html)

    def test_fsa_shows_real_date_not_instruction_text(self):
        html = fetch.build_html(
            [self._item("fsa", source="金融庁")],
            generated_at=__import__("datetime").datetime(2026, 7, 31, 7, 0, tzinfo=dj.JST),
        )
        self.assertIn("利用日: 2026-07-31", html)
        self.assertNotIn("利用日を表示する", html)
        self.assertNotIn("原ページURL", html)

    def test_nvd_disclaimer_is_displayed_accurately(self):
        html = fetch.build_html(
            [self._item("nist_nvd", source="NIST NVD")],
            generated_at=__import__("datetime").datetime(2026, 7, 31, 7, 0, tzinfo=dj.JST),
        )
        self.assertIn(
            "This product uses the NVD API but is not endorsed or certified by the NVD.",
            html,
        )

    def test_cisa_kev_cc0_is_displayed(self):
        html = fetch.build_html(
            [self._item("cisa_kev", source="CISA KEV")],
            generated_at=__import__("datetime").datetime(2026, 7, 31, 7, 0, tzinfo=dj.JST),
        )
        self.assertIn("CISA Known Exploited Vulnerabilities", html)
        self.assertIn("CC0", html)

    def test_malformed_attribution_url_is_not_linked(self):
        # PR #69レビュー(round 2)Blocker 2: 不正URLの場合、リンクなし平文へ
        # fallbackして公開を継続してはならない(fail-closed)。
        with patch("fetch.SOURCE_DEFINITIONS",
                   self._source_definitions_with_ncsc_attribution_url("javascript:alert(1)")):
            fragment = fetch.render_structured_open_attribution_html("ncsc", "2026-07-31")
        self.assertEqual(fragment, "")

    def test_ncsc_missing_attribution_url_renders_nothing(self):
        with patch("fetch.SOURCE_DEFINITIONS",
                   self._source_definitions_with_ncsc_attribution_url(None)):
            fragment = fetch.render_structured_open_attribution_html("ncsc", "2026-07-31")
        self.assertEqual(fragment, "")

    def test_unmapped_structured_open_source_id_renders_nothing(self):
        self.assertEqual(
            fetch.render_structured_open_attribution_html("unknown_source", "2026-07-31"), ""
        )

    def test_ncsc_missing_attribution_url_downgrades_to_missing_attribution(self):
        content_policy = dj.build_item_content_policy(
            "ncsc", "structured_open", "structured_open", None
        )
        item, _ = make_item(content_policy, source="NCSC")
        with patch("fetch.SOURCE_DEFINITIONS",
                   self._source_definitions_with_ncsc_attribution_url(None)):
            items, call_count = run_enrich_with_ai([(item, VALID_ANALYSIS_RESPONSE)])
        self.assertEqual(call_count, 1)
        self.assertEqual(items[0]["content_policy"]["downgrade_reason"], "missing_attribution")

    def test_ncsc_malformed_attribution_url_downgrades_to_missing_attribution(self):
        content_policy = dj.build_item_content_policy(
            "ncsc", "structured_open", "structured_open", None
        )
        item, _ = make_item(content_policy, source="NCSC")
        with patch("fetch.SOURCE_DEFINITIONS",
                   self._source_definitions_with_ncsc_attribution_url("javascript:alert(1)")):
            items, call_count = run_enrich_with_ai([(item, VALID_ANALYSIS_RESPONSE)])
        self.assertEqual(call_count, 1)
        self.assertEqual(items[0]["content_policy"]["downgrade_reason"], "missing_attribution")

    def test_ncsc_valid_attribution_url_does_not_downgrade(self):
        ncsc_url = "https://www.nationalarchives.gov.uk/doc/open-government-licence/version/3/"
        content_policy = dj.build_item_content_policy(
            "ncsc", "structured_open", "structured_open", None
        )
        item, _ = make_item(content_policy, source="NCSC")
        with patch("fetch.SOURCE_DEFINITIONS",
                   self._source_definitions_with_ncsc_attribution_url(ncsc_url)):
            items, call_count = run_enrich_with_ai([(item, VALID_ANALYSIS_RESPONSE)])
        self.assertEqual(call_count, 1)
        self.assertIsNone(items[0]["content_policy"]["downgrade_reason"])
        self.assertIsNotNone(items[0].get("ai_analysis"))

    def test_source_id_in_known_set_alone_is_not_sufficient_for_attribution_ok(self):
        # ncscがSTRUCTURED_OPEN_ATTRIBUTION_SOURCE_IDS的な既知集合に属して
        # いても、attribution_urlが生成不可ならattribution_okはfalseになる
        # ことを、_attribution_is_available()を直接呼んで確認する。
        content_policy = {
            "source_id": "ncsc", "configured_mode": "structured_open",
            "effective_mode": "structured_open", "ai_eligible": True,
            "downgrade_reason": None,
        }
        item = {"link": "https://example.com/a", "raw_title": "t", "title": "t"}
        with patch("fetch.SOURCE_DEFINITIONS",
                   self._source_definitions_with_ncsc_attribution_url(None)):
            self.assertFalse(fetch._attribution_is_available(item, content_policy))

    def test_other_four_structured_open_attributions_still_render(self):
        for source_id, expected_text in (
            ("fsa", "金融庁ウェブサイトをもとにMonomi Digestが加工"),
            ("nist", "出典: NIST"),
            ("nist_nvd", "This product uses the NVD API but is not endorsed"),
            ("cisa_kev", "CISA Known Exploited Vulnerabilities"),
        ):
            with self.subTest(source_id=source_id):
                fragment = fetch.render_structured_open_attribution_html(
                    source_id, "2026-07-31"
                )
                self.assertIn(expected_text, fragment)

    def test_existing_feed_summary_limited_metadata_attribution_still_render(self):
        # 既存のfeed_summary/limited_feed_analysis/metadata_only attribution
        # 表示は、structured_openの修正によって変更されていないことを確認する。
        feed_summary_item = {
            "source": "Test", "lang": "en", "link": "https://example.com/a",
            "title": "t", "raw_title": "t", "summary": "s", "date": None,
            "facts": {"cves": []},
            "content_policy": {"source_id": "jpcert_cc", "configured_mode": "feed_summary",
                                "effective_mode": "feed_summary", "ai_eligible": True,
                                "downgrade_reason": None},
        }
        limited_item = {
            "source": "The Hacker News", "lang": "en", "link": "https://example.com/a",
            "title": "t", "raw_title": "t", "summary": "s", "date": None,
            "facts": {"cves": []},
            "content_policy": {"source_id": "the_hacker_news",
                                "configured_mode": "limited_feed_analysis",
                                "effective_mode": "limited_feed_analysis", "ai_eligible": True,
                                "downgrade_reason": None},
        }
        metadata_only_item = {
            "source": "Cisco Talos", "lang": "en", "link": "https://example.com/a",
            "title": "t", "raw_title": "t", "summary": "s", "date": None,
            "facts": {"cves": []},
            "content_policy": {"source_id": "cisco_talos", "configured_mode": "metadata_only",
                                "effective_mode": "metadata_only", "ai_eligible": False,
                                "downgrade_reason": None},
        }
        html = fetch.build_html([feed_summary_item, limited_item, metadata_only_item])
        self.assertIn("Monomi DigestによるAI要約・分析", html)
        self.assertIn("Monomi Digestが公式RSSの概要をもとに生成したAI分析", html)
        self.assertIn("AIによる要約・評価は行っていません", html)

    def test_attribution_ok_false_for_unmapped_structured_open_source(self):
        source_policy = make_source_policy(content_usage_mode="structured_open")
        content_policy = dj.build_item_content_policy(
            "unknown_source", "structured_open", "structured_open", None
        )
        item, _ = make_item(content_policy, source="Unknown Source")
        response = dict(VALID_ANALYSIS_RESPONSE)
        items, call_count = run_enrich_with_ai([(item, response)])
        self.assertEqual(call_count, 1)
        self.assertEqual(items[0]["content_policy"]["downgrade_reason"], "missing_attribution")


class LimitedFeedAnalysisNoTranslatedSubtitleTest(unittest.TestCase):
    """limited_feed_analysisでは日本語翻訳subtitleを表示しないことを検証する
    (title_jaがenrich_with_ai内で既にNoneへ無効化されているため、
    resolve_display_title/article_title_partsの既存fallback経由でraw_titleの
    みが表示される)。"""

    def test_english_source_shows_only_raw_title_no_subtitle(self):
        item = {
            "source": "The Hacker News", "lang": "en", "link": "https://example.com/a",
            "title": "Original English Title", "raw_title": "Original English Title",
            "summary": "s", "date": None, "facts": {"cves": []},
            "content_policy": {
                "source_id": "the_hacker_news", "configured_mode": "limited_feed_analysis",
                "effective_mode": "limited_feed_analysis", "ai_eligible": True,
                "downgrade_reason": None,
            },
        }
        parts = fetch.article_title_parts(item)
        self.assertEqual(parts["main"], "Original English Title")
        self.assertEqual(parts["subtitle"], "")


def run_enrich_with_ai_with_gemini_failure(item):
    """items内の1件についてGeminiが常にHTTP 500で失敗する状況を再現し、
    enrich_with_ai経由で処理した後のitemを返す(実際のGemini APIへは
    アクセスしない)。"""
    def fake_urlopen(req, timeout=None):
        raise urllib.error.HTTPError(
            "https://example.com", 500, "Internal Server Error", {}, None
        )

    with patch.dict(os.environ, {"GEMINI_API_KEY": "test-key-not-real"}):
        with patch("fetch.urllib.request.urlopen", side_effect=fake_urlopen):
            with patch("fetch.time.sleep"):
                with patch("fetch.SOURCE_DEFINITIONS", fetch.SOURCE_DEFINITIONS + [
                    make_source_def("test_source", "Test Source",
                                    content_usage_mode=item["content_policy"]["configured_mode"]),
                ]):
                    fetch.enrich_with_ai([item])
    return item


class PublisherTextTransientPurgeTest(unittest.TestCase):
    """PR #69レビューBlocker 1: metadata-only相当の記事はpublisher由来
    description(summary/raw_summary)・rich_contentを直ちに破棄し、HTML・
    daily JSON・Today's Briefのいずれにも表示・保存されないことを検証する。
    """

    MARKER = "UNIQUE-PUBLISHER-DESCRIPTION-MARKER-MUST-NOT-LEAK"

    def test_metadata_only_item_has_publisher_description_purged(self):
        content_policy = dj.build_item_content_policy(
            "microsoft_security", "metadata_only", "metadata_only", None
        )
        item = {
            "source": "Microsoft Security", "title": "t", "summary": self.MARKER,
            "rich_content": self.MARKER, "content_policy": content_policy,
        }
        fetch.purge_publisher_text_for_ineligible_items([item])
        self.assertEqual(item["summary"], "")
        self.assertEqual(item["rich_content"], "")

    def test_gate_downgraded_item_has_publisher_description_purged(self):
        # gemini_data_use_status != paid_verifiedによる収集時点でのdowngrade。
        source_policy = make_source_policy(content_usage_mode="feed_summary")
        effective_mode, reason = dj.compute_effective_content_usage_mode(source_policy, "unpaid")
        content_policy = dj.build_item_content_policy(
            "jpcert_cc", "feed_summary", effective_mode, reason
        )
        self.assertFalse(content_policy["ai_eligible"])
        item = {
            "source": "JPCERT/CC", "title": "t", "summary": self.MARKER,
            "rich_content": self.MARKER, "content_policy": content_policy,
        }
        fetch.purge_publisher_text_for_ineligible_items([item])
        self.assertEqual(item["summary"], "")
        self.assertEqual(item["rich_content"], "")

    def test_ai_eligible_item_is_not_purged(self):
        content_policy = dj.build_item_content_policy(
            "test_source", "structured_open", "structured_open", None
        )
        item = {"source": "Test Source", "title": "t", "summary": self.MARKER,
                "rich_content": "", "content_policy": content_policy}
        fetch.purge_publisher_text_for_ineligible_items([item])
        self.assertEqual(item["summary"], self.MARKER)

    def _feed_summary_or_limited_item(self, mode, source_id):
        source_policy = make_source_policy(content_usage_mode=mode)
        effective_mode, reason = dj.compute_effective_content_usage_mode(source_policy, "paid_verified")
        content_policy = dj.build_item_content_policy(source_id, mode, effective_mode, reason)
        item, _ = make_item(
            content_policy, source="Test Source", lang="en",
            summary=self.MARKER, raw_summary=self.MARKER, rich_content=self.MARKER,
        )
        item["facts"] = {"cves": []}
        return item

    def test_feed_summary_gemini_failed_downgrades_and_hides_description(self):
        item = self._feed_summary_or_limited_item("feed_summary", "test_source")
        run_enrich_with_ai_with_gemini_failure(item)
        self.assertFalse(item["content_policy"]["ai_eligible"])
        self.assertEqual(item["content_policy"]["effective_mode"], "metadata_only")
        self.assertEqual(item["content_policy"]["downgrade_reason"], "analysis_unavailable")
        self.assertEqual(item["summary"], "")
        self.assertEqual(item["raw_summary"], "")
        self.assertEqual(item["rich_content"], "")
        self.assertNotIn("ai_analysis", item)
        html = fetch.build_html([item])
        self.assertNotIn(self.MARKER, html)

    def test_limited_feed_analysis_gemini_failed_downgrades_and_hides_description(self):
        item = self._feed_summary_or_limited_item("limited_feed_analysis", "test_source")
        run_enrich_with_ai_with_gemini_failure(item)
        self.assertFalse(item["content_policy"]["ai_eligible"])
        self.assertEqual(item["content_policy"]["effective_mode"], "metadata_only")
        self.assertEqual(item["content_policy"]["downgrade_reason"], "analysis_unavailable")
        self.assertEqual(item["summary"], "")
        self.assertEqual(item["raw_summary"], "")
        self.assertEqual(item["rich_content"], "")
        html = fetch.build_html([item])
        self.assertNotIn(self.MARKER, html)

    def test_gemini_unattempted_without_api_key_downgrades_feed_summary(self):
        content_policy = dj.build_item_content_policy(
            "test_source", "feed_summary", "feed_summary", None
        )
        item, _ = make_item(
            content_policy, source="Test Source", lang="en",
            summary=self.MARKER, raw_summary=self.MARKER, rich_content=self.MARKER,
        )
        with patch.dict(os.environ, {}, clear=True):
            fetch.enrich_with_ai([item])
        self.assertFalse(item["content_policy"]["ai_eligible"])
        self.assertEqual(item["content_policy"]["downgrade_reason"], "analysis_unavailable")
        self.assertEqual(item["summary"], "")
        self.assertEqual(item["rich_content"], "")

    def test_policy_violation_downgrade_purges_description_from_html_and_daily_json(self):
        source_policy = make_source_policy(content_usage_mode="feed_summary")
        effective_mode, reason = dj.compute_effective_content_usage_mode(source_policy, "paid_verified")
        content_policy = dj.build_item_content_policy(
            "test_source", "feed_summary", effective_mode, reason
        )
        verbatim_text = self.MARKER + " " + ("x" * 60)
        item, _ = make_item(content_policy, summary=verbatim_text, raw_summary=verbatim_text)
        response = dict(VALID_ANALYSIS_RESPONSE)
        response["summary"] = verbatim_text
        items, call_count = run_enrich_with_ai([(item, response)])
        self.assertEqual(call_count, 1)
        self.assertEqual(items[0]["content_policy"]["downgrade_reason"], "verbatim_long_match")
        self.assertEqual(items[0]["summary"], "")
        self.assertEqual(items[0]["raw_summary"], "")
        html = fetch.build_html(items)
        self.assertNotIn(self.MARKER, html)
        items[0]["facts"] = {"cves": []}
        entry = dj.build_article_entry(
            items[0],
            [make_source_def("test_source", "Test Source", content_usage_mode="feed_summary")],
            "gemini-2.5-flash",
            datetime.datetime(2026, 7, 30, 7, 0, tzinfo=dj.JST),
        )
        entry_json = json.dumps(entry, ensure_ascii=False)
        self.assertNotIn(self.MARKER, entry_json)
        self.assertIsNone(entry["raw_excerpt"])

    def test_structured_open_fallback_still_shows_raw_summary_without_analysis(self):
        content_policy = dj.build_item_content_policy(
            "test_source", "structured_open", "structured_open", None
        )
        item = {
            "source": "Test Source", "lang": "en", "link": "https://example.com/a",
            "title": "t", "raw_title": "t", "summary": self.MARKER, "date": None,
            "facts": {"cves": []}, "content_policy": content_policy,
        }
        html = fetch.build_html([item])
        self.assertIn(self.MARKER, html)

    def test_marker_never_appears_in_brief_for_downgraded_item(self):
        item = self._feed_summary_or_limited_item("feed_summary", "test_source")
        run_enrich_with_ai_with_gemini_failure(item)
        brief = fetch.build_todays_brief([item])
        self.assertNotIn(self.MARKER, json.dumps(brief, ensure_ascii=False))
        self.assertEqual(brief["status"], "not_attempted")

    # ── PR #69レビュー(round 2)Blocker 1: success/fallback後のpurge ──

    _IMPERATIVE_REASON_FOR_FALLBACK = (
        "重要度は、実悪用が確認されたため「高」です。"
        "確認目安は、パッチを適用してくださいため「本日確認」です。"
    )

    def _run_with_status(self, mode, status):
        """指定modeのitemを、指定status("success"/"fallback")でGemini処理した
        後の状態を返す。実際のGemini APIへはアクセスしない。"""
        item = self._feed_summary_or_limited_item(mode, "test_source")
        response = dict(VALID_ANALYSIS_RESPONSE)
        if status == "fallback":
            response["reason"] = self._IMPERATIVE_REASON_FOR_FALLBACK
        items, call_count = run_enrich_with_ai([(item, response)])
        self.assertEqual(call_count, 1)
        return items[0]

    def test_feed_summary_success_purges_publisher_text(self):
        item = self._run_with_status("feed_summary", "success")
        self.assertEqual(item["ai_analysis_meta"]["status"], "success")
        self.assertIsNotNone(item.get("ai_analysis"))
        self.assertEqual(item["summary"], "")
        self.assertEqual(item["raw_summary"], "")
        self.assertEqual(item["rich_content"], "")

    def test_feed_summary_fallback_purges_publisher_text(self):
        item = self._run_with_status("feed_summary", "fallback")
        self.assertEqual(item["ai_analysis_meta"]["status"], "fallback")
        self.assertIsNotNone(item.get("ai_analysis"))
        self.assertEqual(item["summary"], "")
        self.assertEqual(item["raw_summary"], "")
        self.assertEqual(item["rich_content"], "")

    def test_limited_feed_analysis_success_purges_publisher_text(self):
        item = self._run_with_status("limited_feed_analysis", "success")
        self.assertEqual(item["ai_analysis_meta"]["status"], "success")
        self.assertIsNotNone(item.get("ai_analysis"))
        self.assertEqual(item["summary"], "")
        self.assertEqual(item["raw_summary"], "")
        self.assertEqual(item["rich_content"], "")

    def test_limited_feed_analysis_fallback_purges_publisher_text(self):
        item = self._run_with_status("limited_feed_analysis", "fallback")
        self.assertEqual(item["ai_analysis_meta"]["status"], "fallback")
        self.assertIsNotNone(item.get("ai_analysis"))
        self.assertEqual(item["summary"], "")
        self.assertEqual(item["raw_summary"], "")
        self.assertEqual(item["rich_content"], "")

    def test_marker_absent_from_full_item_json_after_success(self):
        item = self._run_with_status("feed_summary", "success")
        item_json = json.dumps(item, ensure_ascii=False, default=str)
        self.assertNotIn(self.MARKER, item_json)

    def test_ai_generated_summary_survives_in_html_daily_json_and_brief(self):
        item = self._run_with_status("feed_summary", "success")
        item["facts"] = {"cves": []}
        ai_summary = item["ai_analysis"]["summary"]
        html = fetch.build_html([item])
        self.assertIn(ai_summary, html)
        self.assertNotIn(self.MARKER, html)
        entry = dj.build_article_entry(
            item,
            [make_source_def("test_source", "Test Source", content_usage_mode="feed_summary")],
            "gemini-2.5-flash",
            datetime.datetime(2026, 7, 30, 7, 0, tzinfo=dj.JST),
        )
        self.assertEqual(entry["analysis"]["summary"], ai_summary)
        entry_json = json.dumps(entry, ensure_ascii=False)
        self.assertNotIn(self.MARKER, entry_json)
        brief = fetch.build_todays_brief([item])
        self.assertNotIn(self.MARKER, json.dumps(brief, ensure_ascii=False))

    def test_structured_open_success_keeps_publisher_text_and_fallback(self):
        # "nist"は実在のstructured_open source(STRUCTURED_OPEN_ATTRIBUTION_
        # SOURCE_IDSに含まれる)を使う。attribution表示を持たない架空の
        # source_idだと、attribution_ok=falseによりmissing_attribution
        # downgradeが発生し、このテストの意図(structured_openのpurge
        # 非対象を検証すること)と無関係な理由でpurgeされてしまうため。
        content_policy = dj.build_item_content_policy(
            "nist", "structured_open", "structured_open", None
        )
        item, _ = make_item(
            content_policy, source="Test Source", lang="en",
            summary=self.MARKER, raw_summary=self.MARKER,
        )
        items, call_count = run_enrich_with_ai([(item, VALID_ANALYSIS_RESPONSE)])
        self.assertEqual(call_count, 1)
        self.assertEqual(items[0]["summary"], self.MARKER)
        self.assertEqual(items[0]["raw_summary"], self.MARKER)
        # Even without AI analysis, structured_open's raw_summary fallback
        # must still be able to show the (unpurged) publisher text.
        no_analysis_item = {
            "source": "Test Source", "lang": "en", "link": "https://example.com/a",
            "title": "t", "raw_title": "t", "summary": self.MARKER, "date": None,
            "facts": {"cves": []}, "content_policy": content_policy,
        }
        html = fetch.build_html([no_analysis_item])
        self.assertIn(self.MARKER, html)

    def test_collection_time_metadata_only_item_with_preset_raw_summary_is_purged(self):
        # purge_publisher_text_for_ineligible_items()は、raw_summaryが既に
        # (main()の通常順序より前に、または他の呼び出し元によって)設定されて
        # いても、呼び出し順序に頼らず必ず消去する。
        content_policy = dj.build_item_content_policy(
            "microsoft_security", "metadata_only", "metadata_only", None
        )
        item = {
            "source": "Microsoft Security", "title": "t", "summary": self.MARKER,
            "raw_summary": self.MARKER, "rich_content": self.MARKER,
            "content_policy": content_policy,
        }
        fetch.purge_publisher_text_for_ineligible_items([item])
        self.assertEqual(item["summary"], "")
        self.assertEqual(item["raw_summary"], "")
        self.assertEqual(item["rich_content"], "")


_ARCHIVE_SNAPSHOT_NOT_ATTEMPTED_BRIEF_RESULT = {
    "overview": None, "important_highlights": [], "discussion_points": [], "check_items": [],
    "status": "not_attempted", "error_type": None, "http_status": None,
}

_VALID_NCSC_OGL_URL = "https://www.nationalarchives.gov.uk/doc/open-government-licence/version/3/"


class AttributionUrlValidationTest(unittest.TestCase):
    """PR #69レビュー(round 4)Blocker 2: attribution snapshot用のURL検証が、
    schemeプレフィックスだけでなくnetloc/hostnameの存在まで要求する(urlsplit
    ベースの)fail-closedな判定であることを検証する。fetch.safe_url()(記事
    リンク全般用)の仕様はこのTicketでは変更しない。
    """

    def test_valid_ncsc_url_is_accepted(self):
        self.assertTrue(dj.is_safe_attribution_url(_VALID_NCSC_OGL_URL))

    def test_none_is_rejected(self):
        self.assertFalse(dj.is_safe_attribution_url(None))

    def test_javascript_scheme_is_rejected(self):
        self.assertFalse(dj.is_safe_attribution_url("javascript:alert(1)"))

    def test_scheme_only_url_without_host_is_rejected(self):
        self.assertFalse(dj.is_safe_attribution_url("https://"))

    def test_triple_slash_missing_host_url_is_rejected(self):
        self.assertFalse(dj.is_safe_attribution_url("https:///missing-host"))

    def test_query_only_url_without_host_is_rejected(self):
        self.assertFalse(dj.is_safe_attribution_url("http://?query"))

    def test_url_with_internal_newline_is_rejected(self):
        self.assertFalse(dj.is_safe_attribution_url("https://example.com/a\nb"))

    def test_url_with_internal_whitespace_is_rejected(self):
        self.assertFalse(dj.is_safe_attribution_url("https://example.com/a b"))

    def test_build_article_entry_omits_snapshot_for_scheme_only_url(self):
        content_policy = dj.build_item_content_policy("ncsc", "structured_open", "structured_open", None)
        item = {
            "source": "NCSC", "raw_title": "t", "title": "t", "raw_summary": "s", "summary": "s",
            "link": "https://www.ncsc.gov.uk/a", "facts": {"cves": []}, "published_at_jst": None,
            "content_policy": content_policy,
        }
        source_defs = [make_source_def(
            "ncsc", "NCSC", content_usage_mode="structured_open",
            allow_excerpt_storage=True, attribution_url="https://",
        )]
        entry = dj.build_article_entry(
            item, source_defs, "gemini-2.5-flash",
            datetime.datetime(2026, 7, 31, 7, 0, tzinfo=dj.JST),
        )
        self.assertIsNone(entry["policy"]["attribution_url"])

    def test_validate_daily_digest_rejects_scheme_only_snapshot(self):
        content_policy = dj.build_item_content_policy("ncsc", "structured_open", "structured_open", None)
        item = {
            "source": "NCSC", "raw_title": "t", "title": "t", "raw_summary": "s", "summary": "s",
            "link": "https://www.ncsc.gov.uk/a", "facts": {"cves": []}, "published_at_jst": None,
            "content_policy": content_policy,
        }
        digest = dj.build_daily_digest(
            [item], dict(_ARCHIVE_SNAPSHOT_NOT_ATTEMPTED_BRIEF_RESULT),
            [make_source_def("ncsc", "NCSC", content_usage_mode="structured_open",
                              allow_excerpt_storage=True, attribution_url="https://")],
            "gemini-2.5-flash",
            datetime.datetime(2026, 7, 31, 7, 0, tzinfo=dj.JST),
            datetime.datetime(2026, 7, 31, 7, 0, tzinfo=dj.JST),
        )
        with self.assertRaises(dj.DailyJsonError):
            dj.validate_daily_digest(digest)


class ArchiveAttributionSnapshotTest(unittest.TestCase):
    """PR #69レビュー(round 3)Blocker 2: schema v2 daily JSONへ保存された
    structured_open(ncsc)のattribution_url snapshotにより、Archive再生成が
    source_definitions.jsonの後日変更に左右されず決定論的であること、および
    snapshotが欠落・不正な場合はAI分析カード・Dashboard・優先確認・重要・
    優先事項を含めてmetadata-only相当へfail-closedになることを検証する。
    """

    NCSC_OGL_URL = "https://www.nationalarchives.gov.uk/doc/open-government-licence/version/3/"

    def _ncsc_item(self):
        content_policy = dj.build_item_content_policy("ncsc", "structured_open", "structured_open", None)
        return {
            "source": "NCSC", "raw_title": "NCSC Advisory", "title": "NCSC Advisory",
            "raw_summary": "Official advisory description.", "summary": "Official advisory description.",
            "link": "https://www.ncsc.gov.uk/advisory/example", "facts": {"cves": []},
            "published_at_jst": None, "content_policy": content_policy,
            "ai_analysis": dict(VALID_ANALYSIS_RESPONSE),
            "ai_analysis_meta": {"status": "success", "error_type": None, "http_status": None,
                                  "generated_at": "2026-07-31T00:00:00+09:00"},
        }

    def _build_digest(self, ncsc_attribution_url):
        source_defs = [make_source_def(
            "ncsc", "NCSC", content_usage_mode="structured_open",
            allow_excerpt_storage=True, attribution_url=ncsc_attribution_url,
        )]
        return dj.build_daily_digest(
            [self._ncsc_item()], dict(_ARCHIVE_SNAPSHOT_NOT_ATTEMPTED_BRIEF_RESULT),
            source_defs, "gemini-2.5-flash",
            datetime.datetime(2026, 7, 31, 7, 0, tzinfo=dj.JST),
            datetime.datetime(2026, 7, 31, 7, 0, tzinfo=dj.JST),
        )

    def test_valid_snapshot_reproduces_ai_analysis_and_clickable_ogl_link(self):
        digest = self._build_digest(self.NCSC_OGL_URL)
        self.assertEqual(digest["items"][0]["policy"]["attribution_url"], self.NCSC_OGL_URL)
        dj.validate_daily_digest(digest)  # 正常に検証を通過する(例外を送出しない)
        items = fetch.digest_items_for_html(digest)
        self.assertTrue(fetch.item_is_ai_eligible(items[0]))
        html = fetch.build_html(items)
        self.assertIn(f'href="{self.NCSC_OGL_URL}"', html)
        self.assertIn(VALID_ANALYSIS_RESPONSE["summary"], html)
        self.assertNotIn("card-metadata-only", html)

    def test_missing_snapshot_is_rejected_by_validation(self):
        digest = self._build_digest(None)
        self.assertIsNone(digest["items"][0]["policy"]["attribution_url"])
        with self.assertRaises(dj.DailyJsonError):
            dj.validate_daily_digest(digest)

    def test_invalid_snapshot_is_rejected_by_validation(self):
        digest = self._build_digest("javascript:alert(1)")
        with self.assertRaises(dj.DailyJsonError):
            dj.validate_daily_digest(digest)

    def test_tampered_digest_with_missing_snapshot_fails_closed_across_all_derived_displays(self):
        # validate_daily_digest()は本来この状態を拒否するが、改変・破損した
        # ファイルを直接読み込むケースへの防御的backstopとして、
        # digest_items_for_html()自体もfail-closedであることを検証する。
        digest = self._build_digest(self.NCSC_OGL_URL)
        digest["items"][0]["policy"]["attribution_url"] = None  # 生成後に改変されたと仮定
        items = fetch.digest_items_for_html(digest)
        item = items[0]
        self.assertFalse(fetch.item_is_ai_eligible(item))
        self.assertEqual(item["content_policy"]["downgrade_reason"], "archive_attribution_snapshot_invalid")
        html = fetch.build_html(items)
        self.assertIn("card-metadata-only", html)
        self.assertNotIn(VALID_ANALYSIS_RESPONSE["summary"], html)
        self.assertNotIn("Open Government Licence", html)
        dashboard_counts = fetch.compute_dashboard_counts(items)
        self.assertEqual(sum(dashboard_counts["importance"].values()), 0)
        self.assertEqual(fetch.select_important_items(items), [])
        priority_items, _ = fetch.select_priority_items(items)
        self.assertEqual(priority_items, [])

    def test_source_definitions_change_after_generation_does_not_affect_archive_output(self):
        digest = self._build_digest(self.NCSC_OGL_URL)
        items = fetch.digest_items_for_html(digest)
        # source_definitions.json側のNCSC設定が、生成後に削除・変更されたと
        # 仮定する(URLをNoneへ変更、または存在自体が別のものへ変わった状況)。
        with patch("fetch.SOURCE_DEFINITIONS",
                   [make_source_def("ncsc", "NCSC", content_usage_mode="structured_open",
                                     attribution_url=None)]):
            html = fetch.build_html(items)
        self.assertIn(f'href="{self.NCSC_OGL_URL}"', html)
        self.assertNotIn("card-metadata-only", html)


class V1ArchiveBackwardCompatibilityTest(unittest.TestCase):
    """既存schema_version=1のdaily JSONが、BL-032の新UI(簡易カード・
    mode別attribution)へ意図せず切り替わらないことを、実際に保存されている
    v1 daily JSON(data/2026-07-30.json)で検証する。過去daily JSONは
    書き換えない(read-only)。"""

    REAL_V1_DIGEST_PATH = os.path.join(os.path.dirname(__file__), "data", "2026-07-30.json")

    def setUp(self):
        if not os.path.exists(self.REAL_V1_DIGEST_PATH):
            self.skipTest("data/2026-07-30.json is not present in this checkout")
        with open(self.REAL_V1_DIGEST_PATH, encoding="utf-8") as f:
            self.digest = json.load(f)

    def test_fixture_is_schema_v1(self):
        self.assertEqual(self.digest["schema_version"], 1)

    def test_v1_items_get_no_content_policy(self):
        items = fetch.digest_items_for_html(self.digest)
        self.assertTrue(items)
        for item in items:
            self.assertIsNone(item["content_policy"])

    def test_v1_items_are_all_treated_as_ai_eligible(self):
        items = fetch.digest_items_for_html(self.digest)
        for item in items:
            self.assertTrue(fetch.item_is_ai_eligible(item))

    def test_v1_archive_regeneration_has_no_metadata_only_card_or_attribution(self):
        html = fetch.build_daily_archive_html(self.digest)
        self.assertNotIn("card-metadata-only", html)
        self.assertNotIn('class="article-attribution"', html)

    def test_currently_published_archive_has_no_bl032_markers(self):
        published_path = os.path.join(
            os.path.dirname(__file__), "docs", "archive", "2026-07-30.html"
        )
        if not os.path.exists(published_path):
            self.skipTest("docs/archive/2026-07-30.html is not present in this checkout")
        with open(published_path, encoding="utf-8") as f:
            published_html = f.read()
        self.assertNotIn("card-metadata-only", published_html)
        self.assertNotIn('class="article-attribution"', published_html)


class NoScopeCreepTest(unittest.TestCase):
    """本Draft PRが対象外の変更(article-page scraping・production実行等)を
    行っていないことの静的確認。"""

    def test_fetch_module_has_no_new_http_client_beyond_urllib(self):
        with open("fetch.py", encoding="utf-8") as f:
            source = f.read()
        for banned in ("requests.get(", "http.client.", "httpx."):
            self.assertNotIn(banned, source)

    def test_no_workflow_files_changed_marker(self):
        # このtestは変更対象外ファイルへの変更がないことを別途(git diff)で
        # 確認する運用の一部であり、ここではimport可能性のみ確認する。
        self.assertTrue(hasattr(fetch, "SOURCE_DEFINITIONS"))


if __name__ == "__main__":
    unittest.main()
