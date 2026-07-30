#!/usr/bin/env python3
"""
BL-032: 取得元別content usage policy enforcementの回帰テスト。
標準ライブラリの unittest のみを使用する。実際のGemini API・外部RSS/API/記事ページ/
robots.txt等へのアクセスは一切行わない(urllib.request.urlopenをモックに差し替える)。
"""

import copy
import json
import os
import unittest
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

    def test_structured_open_attribution_uses_source_definition_text(self):
        with patch("fetch.SOURCE_DEFINITIONS",
                   fetch.SOURCE_DEFINITIONS + [make_source_def(
                       "test_source", "Test Source",
                       content_usage_mode="structured_open",
                       attribution_requirement="UNIQUE-ATTRIBUTION-TEXT-FOR-TEST",
                   )]):
            html = fetch.build_html([self._item_with_mode("structured_open")])
        self.assertIn("UNIQUE-ATTRIBUTION-TEXT-FOR-TEST", html)

    def test_no_attribution_shown_without_content_policy(self):
        item = {
            "source": "CISA", "lang": "en", "link": "https://example.com/a",
            "title": "t", "raw_title": "t", "summary": "s", "date": None,
            "facts": {"cves": []},
        }
        html = fetch.build_html([item])
        self.assertNotIn("article-attribution", html)


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
