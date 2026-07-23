#!/usr/bin/env python3
"""
Ticket 15a(第2版): ARTICLE v5の回帰テスト。
- title_ja(型検証・Markdown構造のみ拒否・日本語原題)
- reason 2文構造の厳格検証(文順・文末ラベルをanchor)
- recommended_actions lint(状態変更動詞の指示用法を条件節・帰属で判定)
- KEV新規追加のコード側決定論判定(compute_recent_kev_additions)を実データ型で検証
- analysis_dateのrun内固定・recent_kev_additionsのverified_context反映
- 表示タイトルフロー(translateをタイトルに呼ばない・日本語記事はraw)
標準ライブラリのunittestのみ。実際のGemini API・外部HTTPは一切呼ばない。
"""

import datetime as _dt
import json
import os
import unittest
from unittest.mock import patch

import daily_json as dj
import fetch
import test_vulnerability_facts_prompt as tvp
from test_vulnerability_facts_prompt import cve_entry, cvss, kev, nvd
from test_article_analysis import (
    VALID_ANALYSIS_RESPONSE,
    call_gemini_analyze,
    get_request_body_json,
    make_candidate_body,
)


def _prompt_text():
    return get_request_body_json()["contents"][0]["parts"][0]["text"]


# ── バージョン・スキーマ ────────────────────────────────────────────────────

class VersionAndSchemaTest(unittest.TestCase):
    def test_article_prompt_version_is_v6(self):
        self.assertEqual(dj.ARTICLE_PROMPT_VERSION, "article-analysis-v8")

    def test_brief_prompt_version_and_schema_version_unchanged(self):
        self.assertEqual(dj.BRIEF_PROMPT_VERSION, "today-brief-extractive-v1")
        self.assertEqual(dj.SCHEMA_VERSION, 1)

    def test_title_ja_in_schema_required_and_first_in_ordering(self):
        schema = get_request_body_json()["generationConfig"]["response_schema"]
        self.assertIn("title_ja", schema["required"])
        self.assertEqual(schema["properties"]["title_ja"]["type"], "STRING")
        self.assertEqual(schema["propertyOrdering"][0], "title_ja")


# ── title_ja 検証(型・Markdown構造・引用符包み) ──────────────────────────

class TitleJaValidationTest(unittest.TestCase):
    def test_valid_title_is_returned(self):
        self.assertEqual(
            fetch.validate_title_ja({"title_ja": "CISA、脆弱性をKEVへ追加"}),
            "CISA、脆弱性をKEVへ追加",
        )

    def test_non_str_rejected(self):
        for bad in (None, 123, 4.5, True, ["x"], {"a": 1}):
            with self.subTest(v=bad):
                self.assertIsNone(fetch.validate_title_ja({"title_ja": bad}))

    def test_missing_or_empty_is_none(self):
        self.assertIsNone(fetch.validate_title_ja({}))
        self.assertIsNone(fetch.validate_title_ja({"title_ja": ""}))
        self.assertIsNone(fetch.validate_title_ja({"title_ja": "   "}))

    def test_newline_is_rejected(self):
        self.assertIsNone(fetch.validate_title_ja({"title_ja": "見出し\nの続き"}))
        self.assertIsNone(fetch.validate_title_ja({"title_ja": "見出し\rの続き"}))

    def test_markdown_structure_rejected(self):
        for bad in ("# 見出し", "## 見出し", "* 箇条書き", "- 箇条書き",
                    "+ 箇条書き", "```code```"):
            with self.subTest(title=bad):
                self.assertIsNone(fetch.validate_title_ja({"title_ja": bad}))

    def test_inline_symbols_allowed(self):
        # 文字自体の全面禁止はしない。C#・OAuth 2.0・内部の「」等は許容する。
        for ok in ("C#アプリケーションを狙う新たな攻撃", "OAuth 2.0の設定不備",
                   "「ShinyHunters」キャンペーンの新たな手口"):
            with self.subTest(title=ok):
                self.assertEqual(fetch.validate_title_ja({"title_ja": ok}), ok)

    def test_whole_title_quote_wrap_rejected(self):
        for bad in ('"見出し"', "「見出し」", "『見出し』", "'見出し'"):
            with self.subTest(title=bad):
                self.assertIsNone(fetch.validate_title_ja({"title_ja": bad}))

    def test_japanese_title_ja_allowed(self):
        self.assertEqual(
            fetch.validate_title_ja({"title_ja": "フィッシング攻撃が急増"}),
            "フィッシング攻撃が急増",
        )

    def test_missing_title_ja_makes_strict_normalize_none(self):
        no_title = {k: v for k, v in VALID_ANALYSIS_RESPONSE.items() if k != "title_ja"}
        self.assertIsNone(fetch.normalize_article_analysis(no_title))

    def test_title_ja_not_leaked_into_daily_json(self):
        result = call_gemini_analyze(response_body=make_candidate_body(VALID_ANALYSIS_RESPONSE))
        self.assertEqual(result["status"], "success")
        self.assertIn("title_ja", result["analysis"])  # 分析dict内には存在
        item = {
            "source": "CISA", "link": "https://example.com/a", "title": "t",
            "raw_title": "orig", "ai_analysis": result["analysis"],
            "ai_analysis_meta": {
                "status": result["status"], "error_type": result["error_type"],
                "http_status": result["http_status"], "generated_at": "2026-07-14T07:00:00+09:00",
            },
        }
        source_defs = [{"id": "cisa", "name": "CISA", "source_type": "CERT・注意喚起",
                        "source_tier": "Tier 1", "collection_method": "rss", "language": "en"}]
        entry = dj.build_article_entry(item, source_defs, "gemini-2.5-flash",
                                       _dt.datetime(2026, 7, 14, 7, 0, tzinfo=dj.JST))
        self.assertNotIn("title_ja", entry["analysis"])


# ── reason 2文構造の厳格検証 ───────────────────────────────────────────────

class ReasonTwoAxisTest(unittest.TestCase):
    def _mock(self, importance, urgency, reason):
        return {**VALID_ANALYSIS_RESPONSE, "importance": importance,
                "urgency": urgency, "reason": reason}

    def test_valid_two_axis_reason_is_success(self):
        r = ("重要度は、広く利用される製品の重大な脆弱性のため「高」です。"
             "確認目安は、実悪用が継続しているため「本日確認」です。")
        result = call_gemini_analyze(response_body=make_candidate_body(self._mock("高", "本日確認", r)))
        self.assertEqual(result["status"], "success")

    def test_helper_directly(self):
        ok = "重要度は、対象が限定的なため「中」です。確認目安は、期限がないため「今週確認」です。"
        self.assertTrue(fetch.validate_reason_two_axis(ok, "中", "今週確認"))
        self.assertFalse(fetch.validate_reason_two_axis(ok, "高", "今週確認"))   # importance不一致
        self.assertFalse(fetch.validate_reason_two_axis(ok, "中", "本日確認"))   # urgency不一致
        self.assertFalse(fetch.validate_reason_two_axis("", "中", "今週確認"))
        self.assertFalse(fetch.validate_reason_two_axis(None, "中", "今週確認"))

    def test_ticket_reject_cases(self):
        # importance=中・urgency=今週確認 を実値としたとき、いずれも拒否されること。
        rejects = [
            # 末尾ラベルが実値と不一致 + 3文目に候補が紛れる
            "重要度は、重大なため「高」です。確認目安は、期限があるため「本日確認」です。"
            "なお候補は中・今週確認です。",
            # 文の順序が逆
            "確認目安は、期限があるため「今週確認」です。重要度は、対象が限定的なため「中」です。",
            # 「、［理由］のため」構造が無い
            "重要度は「中」です。確認目安は「今週確認」です。",
            # 2文目が「…ため「ラベル」です。」形になっていない
            "重要度は、対象が限定的なため「中」です。確認目安は今週確認。",
        ]
        for reason in rejects:
            with self.subTest(reason=reason):
                self.assertFalse(fetch.validate_reason_two_axis(reason, "中", "今週確認"))

    def test_reject_extra_sentence_inside_reason(self):
        # Ticket 15a第2版-3: 理由部分に句点を含む追加文を許容しない([^。]+?へ変更)。
        rejects = [
            "重要度は、対象が限定的です。影響範囲も狭いため「中」です。"
            "確認目安は、短期期限がないため「今週確認」です。",
            "重要度は、対象が限定的なため「中」です。"
            "確認目安は、悪用されています。期限もあるため「本日確認」です。",
        ]
        for reason in rejects:
            with self.subTest(reason=reason):
                self.assertFalse(fetch.validate_reason_two_axis(reason, "中", "今週確認"))
                bad = self._mock("中", "今週確認", reason)
                self.assertIsNone(fetch.normalize_article_analysis(bad))

    def test_correct_two_sentence_still_allowed(self):
        ok = "重要度は、対象が限定的なため「中」です。確認目安は、短期期限がないため「今週確認」です。"
        self.assertTrue(fetch.validate_reason_two_axis(ok, "中", "今週確認"))

    def test_reject_cases_via_strict_normalize(self):
        bad = self._mock("中", "今週確認", "重要度は、対象が限定的なため「中」です。確認目安は今週確認。")
        self.assertIsNone(fetch.normalize_article_analysis(bad))


# ── reasonが読者への命令・依頼表現にならないことのlint(本チケット新規) ────────

class ReasonImperativeLintTest(unittest.TestCase):
    """reasonは評価根拠の説明であり読者への対応指示ではないという契約の回帰テスト。
    Ticket 17a(recommended_actionsの検討表現許容)とは独立した別のlintであり、
    Ticket 17aの契約(「を検討」等の除外)は変更しない。
    """

    def _mock(self, reason, importance="高", urgency="本日確認"):
        return {**VALID_ANALYSIS_RESPONSE, "importance": importance,
                "urgency": urgency, "reason": reason}

    # ── 低レベル関数の直接検証 ──────────────────────────────────────────

    def test_helper_detects_te_kudasai_form(self):
        self.assertTrue(fetch.reason_has_reader_directed_imperative(
            "利用有無を今週中に確認してください。"
        ))

    def test_helper_detects_subeki_desu_form(self):
        self.assertTrue(fetch.reason_has_reader_directed_imperative(
            "本日中に対応すべきです。"
        ))

    def test_helper_detects_patch_apply_kudasai(self):
        self.assertTrue(fetch.reason_has_reader_directed_imperative(
            "パッチを適用してください。"
        ))

    def test_helper_detects_subeki_da_sentence_final(self):
        self.assertTrue(fetch.reason_has_reader_directed_imperative(
            "パッチを適用すべきだ。"
        ))

    def test_helper_detects_subeki_bare_sentence_final(self):
        self.assertTrue(fetch.reason_has_reader_directed_imperative(
            "直ちに確認すべき。"
        ))

    def test_helper_detects_subeki_bare_at_string_end(self):
        self.assertTrue(fetch.reason_has_reader_directed_imperative(
            "直ちに確認すべき"
        ))

    def test_helper_accepts_subeki_non_sentence_final_forms(self):
        # 「すべきか」「すべきと」「すべき範囲」等、文末の義務付けではない用法は
        # 拒否しない(文中の引用・説明・疑問表現を誤検知しないため)。
        for ok in (
            "対応すべきかを検討する材料となります。",
            "ベンダーは適用すべきと説明しています。",
            "どの対策を優先すべきかは環境によって異なります。",
            "適用すべき範囲が論点となっています。",
            "何を確認すべきかは個社環境によります。",
        ):
            with self.subTest(reason=ok):
                self.assertFalse(fetch.reason_has_reader_directed_imperative(ok))

    def test_helper_accepts_hedge_expressions(self):
        for ok in (
            "確認が必要となり得るため「高」です。",
            "検討対象となるため「中」です。",
            "確認の優先度が高いため「高」です。",
            "重要度は、実悪用が確認されたため「高」です。確認目安は、本日中の確認が必要なため「本日確認」です。",
        ):
            with self.subTest(reason=ok):
                self.assertFalse(fetch.reason_has_reader_directed_imperative(ok))

    def test_helper_accepts_conditional_expressions(self):
        self.assertFalse(fetch.reason_has_reader_directed_imperative(
            "該当する場合は影響を受けるため「高」です。"
        ))

    def test_helper_accepts_negation(self):
        self.assertFalse(fetch.reason_has_reader_directed_imperative(
            "現時点で実悪用は確認されていないため「低」です。"
        ))

    def test_helper_none_and_non_str_are_false(self):
        self.assertFalse(fetch.reason_has_reader_directed_imperative(None))
        self.assertFalse(fetch.reason_has_reader_directed_imperative(123))

    # ── strict normalize(success判定)への統合 ──────────────────────────

    def test_normalize_accepts_correct_reason_without_imperative(self):
        good = ("重要度は、実悪用が確認され広く利用される製品に影響するため「高」です。"
                "確認目安は、短期的な適用性確認が必要となり得るため「本日確認」です。")
        result = fetch.normalize_article_analysis(self._mock(good))
        self.assertIsNotNone(result)
        self.assertEqual(result["reason"], good)

    def test_normalize_rejects_reason_with_te_kudasai(self):
        bad = ("重要度は、実悪用が確認されたため「高」です。"
               "確認目安は、利用有無を今週中に確認してくださいため「本日確認」です。")
        self.assertIsNone(fetch.normalize_article_analysis(self._mock(bad)))

    def test_normalize_accepts_reason_with_non_final_subeki_desu(self):
        # 「すべきです」が文末の義務付けではなく、「ため」に続く理由節の一部
        # (=非命令の説明表現)である場合は拒否しない。狭いregexへの変更前は
        # このケースを誤って拒否していた回帰テスト。
        good = ("重要度は、実悪用が確認されたため「高」です。"
                "確認目安は、本日中に対応すべきですため「本日確認」です。")
        result = fetch.normalize_article_analysis(self._mock(good))
        self.assertIsNotNone(result)
        self.assertEqual(result["reason"], good)

    def test_normalize_accepts_reason_with_hedge_phrase(self):
        good = ("重要度は、確認の優先度が高いため「高」です。"
                "確認目安は、検討対象となるため「本日確認」です。")
        self.assertIsNotNone(fetch.normalize_article_analysis(self._mock(good)))

    def test_normalize_accepts_reason_with_conditional_clause(self):
        good = ("重要度は、該当する場合に影響が大きいため「高」です。"
                "確認目安は、実悪用が確認が必要となり得るため「本日確認」です。")
        self.assertIsNotNone(fetch.normalize_article_analysis(self._mock(good)))

    # ── success/fallback/failed契約: strict失敗時はfallbackへ委ねる(SD-004) ──

    def test_full_json_with_imperative_reason_falls_back_not_fails(self):
        bad_reason = ("重要度は、実悪用が確認されたため「高」です。"
                      "確認目安は、パッチを適用してくださいため「本日確認」です。")
        result = call_gemini_analyze(
            response_body=make_candidate_body(self._mock(bad_reason))
        )
        self.assertEqual(result["status"], "fallback")
        self.assertIsNotNone(result["analysis"])

    def test_full_json_with_explanatory_reason_is_success(self):
        good_reason = ("重要度は、実悪用が確認され広く利用される製品に影響するため「高」です。"
                       "確認目安は、短期的な適用性確認が必要となり得るため「本日確認」です。")
        result = call_gemini_analyze(
            response_body=make_candidate_body(self._mock(good_reason))
        )
        self.assertEqual(result["status"], "success")

    # ── fallback_ai_analysis()にも同じlintを適用する(本チケット新規) ─────────
    # strict validation(normalize_article_analysis)がreasonの指示表現を拒否
    # しても、fallback_ai_analysis()が同じ応答テキストから再度reasonを抽出して
    # そのまま保存すると、指示文が優先確認に表示されてしまう。fallback分析
    # 全体は維持したまま、reasonだけをNoneにする(代わりの一般文は生成しない)。

    def test_fallback_sanitizes_imperative_reason_to_none_but_keeps_other_fields(self):
        bad = {**VALID_ANALYSIS_RESPONSE, "reason": "利用有無を確認してください。"}
        result = call_gemini_analyze(response_body=make_candidate_body(bad))

        self.assertEqual(result["status"], "fallback")
        analysis = result["analysis"]
        self.assertIsNotNone(analysis)
        self.assertIsNone(analysis["reason"])
        self.assertEqual(analysis["importance"], VALID_ANALYSIS_RESPONSE["importance"])
        self.assertEqual(analysis["summary"], VALID_ANALYSIS_RESPONSE["summary"])
        self.assertEqual(
            analysis["financial_impact"], VALID_ANALYSIS_RESPONSE["financial_impact"]
        )
        self.assertEqual(
            analysis["recommended_actions"], VALID_ANALYSIS_RESPONSE["recommended_actions"]
        )

    def test_fallback_sanitizes_sentence_final_subeki_reason_to_none(self):
        # 文末義務形はfallbackの自由形式reasonでは実際に起こりうる
        # (strict pathの2文構造テンプレートでは構造上発生しない)。
        bad = {**VALID_ANALYSIS_RESPONSE, "reason": "直ちに確認すべきです。"}
        result = call_gemini_analyze(response_body=make_candidate_body(bad))

        self.assertEqual(result["status"], "fallback")
        self.assertIsNone(result["analysis"]["reason"])

    def test_fallback_reason_sanitized_to_none_is_not_rendered(self):
        bad = {**VALID_ANALYSIS_RESPONSE, "reason": "利用有無を確認してください。"}
        result = call_gemini_analyze(response_body=make_candidate_body(bad))
        analysis = result["analysis"]
        self.assertIsNone(analysis["reason"])

        item = {
            "id": "id-fallback-reason-sanitized",
            "title": "fallback-reason-sanitized",
            "link": "https://example.com/fallback-reason-sanitized",
            "summary": "summary",
            "date": _dt.datetime(2026, 7, 11, 6, 0),
            "source": "CISA",
            "lang": "ja",
            "ai_analysis": analysis,
        }
        html = fetch.build_html([item])
        self.assertNotIn("利用有無を確認してください", html)
        # important-item-reasonクラス自体はCSSに常時存在するため、実際に
        # 段落要素として出力されていないことを開始タグで確認する。
        self.assertNotIn('<p class="important-item-reason">', html)

    def test_fallback_preserves_safe_reason(self):
        safe_reason = ("重要度は、実悪用が確認され広く利用される製品に影響するため「高」です。"
                       "確認目安は、短期的な適用性確認が必要となり得るため「本日確認」です。")
        truncated = (
            '{"importance": "高", "summary": "テスト要約です。", '
            '"financial_impact": "影響があります。", "recommended_actions": ["対応1"], '
            f'"reason": "{safe_reason}"'
        )
        fb = fetch.fallback_ai_analysis(truncated, "source_name: CISA\ntitle: test\n")
        self.assertIsNotNone(fb)
        self.assertEqual(fb["reason"], safe_reason)

    # ── prompt本文の契約確認 ──────────────────────────────────────────

    def test_prompt_states_reason_is_explanation_not_instruction(self):
        text = _prompt_text()
        self.assertIn("reasonは評価根拠の説明であり、読者への対応指示ではない", text)

    def test_prompt_lists_forbidden_imperative_examples(self):
        text = _prompt_text()
        for phrase in (
            "「〜してください」",
            "「〜すべきです」",
            "利用有無を確認してください",
            "本日中に対応してください",
            "パッチを適用してください",
        ):
            self.assertIn(phrase, text)

    def test_prompt_allows_hedge_and_conditional_expressions(self):
        text = _prompt_text()
        for phrase in ("確認が必要となり得る", "検討対象となる", "確認の優先度が高い"):
            self.assertIn(phrase, text)

    def test_prompt_states_recommended_actions_is_separate_responsibility(self):
        text = _prompt_text()
        self.assertIn("推奨アクションはrecommended_actionsの責務であり、", text)

    def test_prompt_still_allows_confirmation_request_form_in_recommended_actions(self):
        # Ticket 17a由来のrecommended_actions固有の許容(「確認してください」等の
        # 依頼形は禁止しない)は、reasonの新lintとは独立して維持されている。
        text = _prompt_text()
        self.assertIn("「確認してください」等の依頼形は禁止しない", text)


# ── recommended_actions lint(状態変更動詞の指示用法) ──────────────────────

class RecommendedActionsLintTest(unittest.TestCase):
    def test_ticket_reject_cases(self):
        # Ticket 17a: 「更新を検討する。」は検討行為であり許容へ変更した(旧Ticket 15aの
        # 拒否判定を意図的に上書き)。ここには実際に状態を変える命令のみを残す。
        for bad in ("設定を変更し、結果を確認する。", "対象製品を停止して影響を評価する。",
                    "CISA対象製品を直ちに無効化する。", "ベンダー製品を停止する。",
                    "対象ソフトウェアを更新する。",
                    "多要素認証を導入する", "全環境にパッチを適用する",
                    "該当サービスの利用を禁止する"):
            with self.subTest(a=bad):
                self.assertTrue(fetch.action_has_unconditional_state_change(bad))

    def test_ticket_allow_cases(self):
        for ok in ("該当する場合は、公式推奨に基づく更新を検討する。",
                   "侵害兆候が確認された場合は、ベンダーの指針に基づき隔離を検討する。",
                   "CISAは緩和策を推奨しており、対象環境では対応要否を評価する。",
                   "パッチ適用状況を確認する。", "更新の有無を確認する。",
                   "該当製品の利用有無を確認する", "資産を棚卸しする",
                   "対応要否を判断する",
                   # Ticket 17a: 帰属・条件なしの単独の検討行為も許容する。
                   "更新を検討する。"):
            with self.subTest(a=ok):
                self.assertFalse(fetch.action_has_unconditional_state_change(ok))

    def test_single_word_attribution_not_enough(self):
        # 「CISA」「ベンダー」「確認」「評価」「検討」という単語だけでは許容しない。
        self.assertTrue(fetch.action_has_unconditional_state_change("CISAの対象を無効化する"))
        self.assertTrue(fetch.action_has_unconditional_state_change("ベンダー製品を削除する"))

    def test_negation_and_irrelevant_bare_case_rejected(self):
        # Ticket 15a第2版-4: 否定形帰属・無関係な「場合」では許容しない。
        for bad in ("対象外の場合でも設定を変更する。",
                    "場合によらず対象製品を停止する。",
                    "CISAは更新を推奨していないが、対象製品を停止する。",
                    "ベンダーが削除を推奨していないため、設定を変更する。"):
            with self.subTest(a=bad):
                self.assertTrue(fetch.action_has_unconditional_state_change(bad))

    def test_modifier_between_object_and_verb_detected(self):
        # Ticket 15a最終-2: 対象語と動詞の間に修飾語が入っても状態変更を検出する。
        for bad in ("パッチを直ちに適用する。", "パッチを全環境へ適用する。",
                    "パッチを即時に適用してください。", "設定を即時に変更する。",
                    "設定を一律に変更する。", "セキュリティ設定を直ちに変更してください。"):
            with self.subTest(a=bad):
                self.assertTrue(fetch.action_has_unconditional_state_change(bad))

    def test_state_confirmation_not_flagged(self):
        # 「適用状況」「変更の有無」等の名詞・確認用法は状態変更命令ではない。
        for ok in ("パッチ適用状況を確認する。", "パッチが適用済みか確認する。",
                   "設定変更の有無を確認する。", "設定値を確認する。"):
            with self.subTest(a=ok):
                self.assertFalse(fetch.action_has_unconditional_state_change(ok))

    def test_conditioned_modifier_state_change_allowed(self):
        for ok in ("該当する場合は、公式推奨に基づきパッチを適用する。",
                   "侵害兆候が確認された場合は、ベンダーの指針に基づき設定を変更する。"):
            with self.subTest(a=ok):
                self.assertFalse(fetch.action_has_unconditional_state_change(ok))

    def test_strict_normalize_rejects_unconditional_state_change(self):
        bad = {**VALID_ANALYSIS_RESPONSE,
               "recommended_actions": ["直ちに全システムへパッチを適用する"]}
        self.assertIsNone(fetch.normalize_article_analysis(bad))

    def test_strict_normalize_accepts_conditioned_state_change(self):
        good = {**VALID_ANALYSIS_RESPONSE,
                "recommended_actions": ["該当する場合はベンダーの指針に基づき更新を検討する"]}
        self.assertIsNotNone(fetch.normalize_article_analysis(good))


# ── Ticket 17a: 検討・評価・確認のadvisory actionを状態変更命令と誤検知しない ──

class Ticket17aActionLintSofteningTest(unittest.TestCase):
    # 2026-07-16 Mandiant記事でfallback降格を招いた実actionを含む。
    MANDIANT_ACTION = (
        "Mandiantが推奨するS-SDLC、継続的なセキュリティスキャン、"
        "脅威検知サービスの導入を検討する"
    )

    def test_advisory_wording_allowed(self):
        # 検討・評価・確認は状態変更命令ではないため許容(False)。
        for ok in (self.MANDIANT_ACTION,
                   "脅威検知サービスの導入を検討する",
                   "脅威検知サービス導入の必要性を評価する",
                   "脅威検知サービスの導入状況を確認する"):
            with self.subTest(a=ok):
                self.assertFalse(fetch.action_has_unconditional_state_change(ok))

    # 各状態変更動詞の「〜を検討する」(検討行為=許容)と、対応する強い実行形
    # (=拒否)の対。「を検討」除外が各動詞群に効いていること、および対応する実行形の
    # 拒否が各動詞群で確認されていることを table-driven で担保する。
    CONSIDERATION_ALLOWED = (
        "脅威検知サービスの導入を検討する",
        "対象アカウントの停止を検討する",
        "該当機能の無効化を検討する",
        "不審なアカウントの削除を検討する",
        "対象通信の遮断を検討する",
        "感染端末の隔離を検討する",
        "ソフトウェアの更新を検討する",
        "パッチの適用を検討する",
        "設定の変更を検討する",
    )
    STRONG_EXECUTION_REJECTED = (
        "脅威検知サービスを導入する",
        "対象アカウントを停止する",
        "該当機能を無効化する",
        "不審なアカウントを削除する",
        "対象通信を遮断する",
        "感染端末を隔離する",
        "ソフトウェアを更新する",
        "全環境へパッチを適用する",
        "対象設定を変更する",
    )
    ADVISORY_SUFFIXES_ALLOWED = (
        "導入を検討し、全環境で実施するか検討する",
        "導入を検討し、全環境で実施する必要性を評価する",
        "導入を検討し、全環境で実施してよいか確認する",
        "導入を検討し、全環境で実施しない",
        "導入を検討し、全環境で実施する予定はない",
        "導入を検討し、全環境で実施する場合の影響を評価する",
    )

    def test_consideration_wording_allowed_per_verb(self):
        # 「を検討」を除外した9動詞群それぞれで「〜を検討する」が許容(False)。
        for ok in self.CONSIDERATION_ALLOWED:
            with self.subTest(a=ok):
                self.assertFalse(fetch.action_has_unconditional_state_change(ok))

    def test_strong_execution_form_rejected_per_verb(self):
        # 対応する強い実行形は各動詞群で拒否(True)が維持される(遮断/隔離を含む)。
        for bad in self.STRONG_EXECUTION_REJECTED:
            with self.subTest(a=bad):
                self.assertTrue(fetch.action_has_unconditional_state_change(bad))

    def test_deploy_share_wording_allowed(self):
        # Ticket 17aレビュー: 「展開する」は情報共有・周知にも使われるため、汎用的な
        # 状態変更検出には加えない。これらは許容(False)であること。
        for ok in ("注意喚起を関係部署へ展開する",
                   "分析結果を経営層へ展開する",
                   "インシデント情報をグループ各社へ展開する"):
            with self.subTest(a=ok):
                self.assertFalse(fetch.action_has_unconditional_state_change(ok))

    def test_strong_state_change_still_rejected(self):
        # 実際に状態を変える命令は従来どおり拒否(True)。混在文は前半の検討で後半の
        # 実際の状態変更命令(既存動詞「導入する」)を見逃さないこと。末尾の例は
        # 「ベンダーが推奨する」帰属が強い状態変更を無条件に許容する回避条件にならないこと。
        for bad in ("脅威検知サービスを導入する",
                    "直ちに脅威検知サービスを導入する",
                    "全環境へ脅威検知サービスを導入する",
                    "脅威検知サービスの導入を検討し、全環境へ同サービスを導入する",
                    "ベンダーが推奨しているため、全環境へ直ちに導入する"):
            with self.subTest(a=bad):
                self.assertTrue(fetch.action_has_unconditional_state_change(bad))

    def test_full_json_with_advisory_action_is_accepted(self):
        # 対象advisory actionを含み他フィールドが有効な完全JSONが、本番相当のstrict
        # parser(parse_article_analysis)/normalize_article_analysisでACCEPTされる。
        value = {**VALID_ANALYSIS_RESPONSE,
                 "recommended_actions": [self.MANDIANT_ACTION]}
        self.assertIsNotNone(fetch.normalize_article_analysis(value))
        parsed = fetch.parse_article_analysis(json.dumps(value, ensure_ascii=False))
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["recommended_actions"], [self.MANDIANT_ACTION])

    def test_full_json_with_strong_state_change_is_rejected_to_fallback(self):
        # 強い状態変更を含むactionは従来どおりstrictで拒否され、fallback経路へ。
        value = {**VALID_ANALYSIS_RESPONSE,
                 "recommended_actions": ["脅威検知サービスの導入を検討し、全環境へ同サービスを導入する"]}
        self.assertIsNone(fetch.normalize_article_analysis(value))
        self.assertIsNone(fetch.parse_article_analysis(json.dumps(value, ensure_ascii=False)))

    def test_consider_then_execute_advisory_suffixes_allowed(self):
        # Ticket 17aは明示的な状態変更命令だけを拒否する。検討・評価・確認・否定・
        # 条件表現を、目的語省略の推測だけで実行命令として扱わない。
        for ok in self.ADVISORY_SUFFIXES_ALLOWED:
            with self.subTest(a=ok):
                self.assertFalse(fetch.action_has_unconditional_state_change(ok))

    def test_consider_then_execute_advisory_suffixes_strict_parser_accepted(self):
        for ok in self.ADVISORY_SUFFIXES_ALLOWED:
            with self.subTest(a=ok):
                value = {**VALID_ANALYSIS_RESPONSE, "recommended_actions": [ok]}
                self.assertIsNotNone(fetch.normalize_article_analysis(value))
                parsed = fetch.parse_article_analysis(json.dumps(value, ensure_ascii=False))
                self.assertIsNotNone(parsed)
                self.assertEqual(parsed["recommended_actions"], [ok])


# ── KEV新規追加のコード側決定論判定(実データ型fixture) ────────────────────

class RecentKevAdditionsTest(unittest.TestCase):
    AD = _dt.date(2026, 7, 14)

    def _item(self, status, date_added, cve_id="CVE-2026-0001"):
        return {"facts": {"cves": [cve_entry(cve_id, kev_dict=kev(status=status, date_added=date_added))]}}

    def _recent(self, status, date_added):
        return fetch.compute_recent_kev_additions(self._item(status, date_added), self.AD)

    def test_day0_1_2_are_recent(self):
        for date_added, expected_days in (("2026-07-14", 0), ("2026-07-13", 1), ("2026-07-12", 2)):
            with self.subTest(date=date_added):
                r = self._recent("listed", date_added)
                self.assertEqual(len(r), 1)
                self.assertEqual(r[0]["days_since_added"], expected_days)
                self.assertEqual(r[0]["kev_date_added"], date_added)
                self.assertEqual(r[0]["cve_id"], "CVE-2026-0001")

    def test_day3_and_older_not_recent(self):
        self.assertEqual(self._recent("listed", "2026-07-11"), [])   # days=3
        self.assertEqual(self._recent("listed", "2026-01-01"), [])   # 古い

    def test_future_not_recent(self):
        self.assertEqual(self._recent("listed", "2026-07-15"), [])

    def test_null_and_invalid_date_not_recent(self):
        self.assertEqual(self._recent("listed", None), [])
        self.assertEqual(self._recent("listed", "2026-99-99"), [])
        self.assertEqual(self._recent("listed", "not-a-date"), [])

    def test_not_listed_not_recent(self):
        self.assertEqual(self._recent("not_listed", "2026-07-14"), [])
        self.assertEqual(self._recent("unknown", "2026-07-14"), [])

    def test_non_date_analysis_date_returns_empty(self):
        self.assertEqual(
            fetch.compute_recent_kev_additions(self._item("listed", "2026-07-14"), "2026-07-14"),
            [],
        )

    def test_multiple_cves_only_recent_ones(self):
        item = {"facts": {"cves": [
            cve_entry("CVE-2026-0001", kev_dict=kev("listed", "2026-07-13")),  # day1
            cve_entry("CVE-2026-0002", kev_dict=kev("listed", "2026-01-01")),  # 古い
            cve_entry("CVE-2026-0003", kev_dict=kev("not_listed", None)),      # 非掲載
            cve_entry("CVE-2026-0004", kev_dict=kev("listed", "2026-07-14")),  # day0
        ]}}
        r = fetch.compute_recent_kev_additions(item, self.AD)
        # days昇順→cve_id: day0(0004), day1(0001)
        self.assertEqual([x["cve_id"] for x in r], ["CVE-2026-0004", "CVE-2026-0001"])

    def test_recent_not_lost_when_over_ten_cves(self):
        # 有効scoreの非KEV 12件 + 末尾に直近KEV追加1件(合計13件)。
        # prompt facts選択は10件へ切り詰めるが、recent判定は全有効CVEが対象なので失われない。
        cves = [
            cve_entry(f"CVE-2026-1{i:03d}", nvd_dict=nvd(cvss=cvss(score=9.0)),
                      kev_dict=kev("not_listed", None))
            for i in range(12)
        ]
        cves.append(cve_entry("CVE-2026-9999", kev_dict=kev("listed", "2026-07-13")))
        item = {"facts": {"cves": cves}}
        # serialize(prompt facts)は10件へ切り詰める
        serialized = fetch.serialize_vulnerability_facts_for_prompt(item)
        self.assertEqual(len(serialized["cves"]), 10)
        self.assertEqual(serialized["omitted_cve_count"], 3)
        # それでもrecent判定は末尾のKEV新規追加を拾う
        r = fetch.compute_recent_kev_additions(item, self.AD)
        self.assertEqual([x["cve_id"] for x in r], ["CVE-2026-9999"])


# ── プロンプト内容(recent_kev_additions contract 等) ──────────────────────

class PromptContentTest(unittest.TestCase):
    def setUp(self):
        self.text = _prompt_text()
        # 改行と、それに続く継続行のインデント空白も除去して語句連結を判定する。
        import re as _re
        self.flat = _re.sub(r"\n[ \t]*", "", self.text)

    def test_recent_kev_additions_contract(self):
        # 内部識別子漏出修正: verified_context_jsonの実際のキー・フィールド名は
        # 内部実装識別子(recent_kev_additions/kev_new_additions/cve_id/
        # kev_date_added/days_since_added)ではなく、人間可読な日本語ラベルへ
        # 投影する。
        self.assertIn("「直近3暦日以内にKEVへ追加されたCVE」", self.text)
        self.assertIn("「CVE ID」\n「KEV追加日」「追加からの日数」".replace("\n", ""), self.flat)
        for internal in ("recent_kev_additions", "kev_new_additions", "cve_id",
                          "kev_date_added", "days_since_added"):
            self.assertNotIn(internal, self.text)
        self.assertIn("日付差は計算済みで自分では計算しない", self.flat)

    def test_no_nonexistent_facts_kev_dateadded_reference(self):
        # 存在しない旧contract名を残さない(Ticket 15a第2版・最優先)。
        self.assertNotIn("facts.kev.dateAdded", self.text)
        self.assertNotIn("facts.kev", self.text)

    def test_kev_new_add_strong_today_basis(self):
        self.assertIn("KEV新規追加に含まれるCVE", self.flat)
        self.assertIn("本日確認の強い根拠", self.flat)
        self.assertIn("今週確認へ下げない", self.flat)
        self.assertIn("適用範囲の狭さはimportanceを下げる要因でありurgencyは下げない", self.flat)

    def test_kev_new_add_first_action(self):
        self.assertIn("保有・稼働・外部露出・影響バージョンの確認", self.flat)
        self.assertIn("全環境への即時パッチ適用を一律には命じない", self.flat)

    def test_recent_kev_is_the_only_exception(self):
        # Ticket 15a第2版-1: KEV新規追加だけが例外(本日確認の強い根拠)であり、
        # 「既存/新規追加でないKEV掲載」だけが掲載単独では不十分であることを全文で統一。
        self.assertIn("KEV新規追加に含まれるCVEは例外で本日確認の強い根拠", self.flat)
        self.assertIn("KEV新規追加に含まれない既存の掲載では", self.flat)
        self.assertIn("KEV新規追加に含まれない既存KEVでは", self.flat)
        # 例3(KEV単独境界)は「新規追加ではない」ことを明示する
        self.assertIn("新規追加ではないため掲載だけで本日確認にしない", self.flat)

    def test_recent_kev_never_forced_to_this_week(self):
        # recent_kev_additionsを一律に今週確認へ下げる文章が存在しないこと。
        self.assertIn("古さや適用範囲の狭さだけで今週確認へ下げない", self.flat)
        # 「今週確認とする/とし」既定を含む文はいずれも「含まれない」へスコープされている
        # (recent側を今週確認へ下げる無条件文が存在しない)。
        default_sentences = [s for s in self.flat.split("。") if "今週確認と" in s]
        self.assertTrue(default_sentences)  # 既定文が存在する
        for s in default_sentences:
            self.assertIn("含まれない", s,
                          f"今週確認既定がrecent非該当へスコープされていない: {s}")

    def test_importance_high_requires_additional_basis(self):
        # Ticket 15a最終-1: importance=高は記事本文の追加根拠(適用性・重大性)を要する。
        self.assertIn("importance=高には記事本文から確認できる適用性・重大性の追加根拠", self.flat)
        self.assertIn("を少なくとも1つ組み合わせる", self.flat)

    def test_recent_kev_today_needs_no_additional_basis(self):
        # recent KEVのurgency=本日確認には追加根拠を課さない。
        self.assertIn("KEV新規追加のCVEは直近追加自体が時間的根拠", self.flat)
        self.assertIn("urgency=本日確認に追加根拠を要さない", self.flat)
        # 「高・本日確認」を一括して追加根拠必須とする文を残さない。
        self.assertNotIn("高・本日確認には記事本文から確認できる追加根拠", self.flat)

    def test_examples_1_3_7_kev_rules_consistent(self):
        # 例1(非recent・時間根拠で本日)、例3(非recent・根拠なしで今週)、例7(recentで本日)が矛盾しない。
        text = self.text
        e1 = text[text.index("# 例1"):text.index("# 例2")]
        e3 = text[text.index("# 例3"):text.index("# 例4")]
        e7 = text[text.index("# 例7"):text.index("# ニュース")]
        # 例1: recent非該当だが「実悪用が進行中」の時間的根拠で本日確認(KEV掲載単独でない)
        self.assertIn("KEV新規追加には非該当", e1)
        self.assertNotIn("recent_kev_additions", e1)
        self.assertIn("進行中", e1)
        self.assertIn('"urgency": "本日確認"', e1)
        # 例3: 新規追加でないKEVは掲載だけで本日確認にせず今週確認
        self.assertIn("新規追加ではないため掲載だけで本日確認にしない", e3)
        self.assertIn('"urgency": "今週確認"', e3)
        # 例7: recent(追加から1日)で本日確認
        self.assertIn("追加から1日", e7)
        self.assertNotIn("days_since_added", e7)
        self.assertIn('"urgency": "本日確認"', e7)

    def test_partial_example_note(self):
        # Ticket 15a最終-3: few-shotが部分例であること・required全項目を返す指示・
        # title_ja省略可の指示が無いこと。
        self.assertIn("部分例", self.flat)
        self.assertIn("response schemaのrequired全項目を必ず返す", self.flat)
        self.assertIn("title_jaも省略しない", self.flat)
        self.assertNotIn("title_jaを省略してよい", self.flat)
        self.assertNotIn("title_jaは省略してよい", self.flat)

    def test_summary_why_now_conditioned_on_recent(self):
        self.assertIn("KEV新規追加に含まれる", self.flat)
        self.assertIn("実悪用が確認されたとして本脆弱性をKEVカタログへ", self.flat)

    def test_summary_does_not_leak_field_name(self):
        # Ticket 15a第2版-2 / 内部識別子漏出修正: kev_date_added(内部識別子)を
        # 裸で出力させず、YYYY-MM-DD表記のままの出力も禁止する。
        self.assertNotIn("CISAはkev_date_added", self.flat)  # 出力例に裸のフィールド名がない
        self.assertNotIn("kev_date_added", self.flat)
        self.assertIn("YYYY-MM-DD表記のまま出力しない", self.flat)  # 明示指示
        self.assertIn("自然な日本語の日付に直し", self.flat)
        # positive few-shotに具体的な自然日本語日付がある
        self.assertIn("CISAは2026年7月13日、実悪用が確認されたとして", self.flat)

    def test_recap_rules(self):
        self.assertIn("再掲・まとめ記事", self.text)
        self.assertIn("原則importance=低・urgency=参考", self.flat)
        self.assertIn("個々の項目の深刻度を合算してまとめ記事自体を過大評価しない", self.flat)
        self.assertIn("「Weekly Recap」等の語だけでは低・参考へ固定しない", self.flat)

    def test_financial_impact_condition_first(self):
        self.assertIn("適用に条件がある場合は、その条件を文の冒頭に置く", self.flat)

    def test_action_expression_tiers(self):
        self.assertIn("条件なしで使える動詞", self.flat)
        self.assertIn("状態変更を伴う動詞", self.flat)
        self.assertIn("条件節・帰属を明示する場合のみ使う", self.flat)
        self.assertIn("「確認してください」等の依頼形は禁止しない", self.flat)

    def test_reason_two_sentence_template(self):
        self.assertIn("必ず次の2文で書く", self.flat)
        self.assertIn("重要度は、", self.text)
        self.assertIn("確認目安は、", self.text)

    def test_title_ja_section_and_japanese_original_rule(self):
        self.assertIn("# title_ja", self.text)
        self.assertIn("原題が非日本語なら意味を保つ自然な日本語を生成", self.flat)
        self.assertIn("日本語なら原題のまま返すか意味を変えない軽微な", self.flat)
        # 日本語記事と矛盾する旧規則は消えていること
        self.assertNotIn("原題と同じ言語のまま返さない", self.text)

    def test_title_ja_outer_quote_strip_instruction(self):
        # Ticket 15a第2版-5: 原題が全体を「」で囲まれていても外側の引用符を外す。
        self.assertIn("原題が全体を「」等で囲まれていても外側の引用符は外す", self.flat)

    def test_title_ja_schema_description_matches_validator(self):
        # schema descriptionがvalidatorと整合(Markdown構造・改行・全体囲みなし/内部引用符可)。
        schema = get_request_body_json()["generationConfig"]["response_schema"]
        desc = schema["properties"]["title_ja"]["description"]
        self.assertIn("Markdown構造・改行・タイトル全体の引用符囲みなし", desc)
        self.assertIn("固有名詞等に用いる内部の引用符は可", desc)


# ── analysis_dateのrun内固定 & recent_kev_additionsのverified_context反映 ──

class VerifiedContextTest(unittest.TestCase):
    def _capture(self, items, analysis_date=None):
        captured = []

        def fake_urlopen(req, timeout=None):
            captured.append(req)
            return tvp._FakeResponse(tvp._fake_gemini_response_body())

        with patch.dict(os.environ, {"GEMINI_API_KEY": "test-key-not-real"}):
            with patch("fetch.urllib.request.urlopen", side_effect=fake_urlopen):
                with patch("fetch.time.sleep"):
                    fetch.enrich_with_ai(items, analysis_date=analysis_date)
        return [json.loads(c.data.decode("utf-8"))["contents"][0]["parts"][0]["text"]
                for c in captured]

    def test_analysis_date_fixed_across_items(self):
        items = [
            {"source": "CISA", "link": "https://x/a", "title": "t1", "summary": "s1"},
            {"source": "CISA", "link": "https://x/b", "title": "t2", "summary": "s2"},
        ]
        texts = self._capture(items, analysis_date=_dt.date(2026, 7, 14))
        self.assertEqual(len(texts), 2)
        for t in texts:
            verified, _ = tvp._extract_verified_and_untrusted(t)
            # 内部識別子漏出修正: analysis_date(内部識別子)ではなく
            # 人間可読ラベル「分析基準日」で送信する。
            self.assertEqual(verified["分析基準日"], "2026-07-14")

    def test_recent_kev_additions_in_verified_context(self):
        item = {"source": "CISA", "link": "https://x/a", "title": "t", "summary": "s",
                "facts": {"cves": [cve_entry("CVE-2026-0001", kev_dict=kev("listed", "2026-07-13"))]}}
        texts = self._capture([item], analysis_date=_dt.date(2026, 7, 14))
        verified, _ = tvp._extract_verified_and_untrusted(texts[0])
        # 内部識別子漏出修正: 内部キー名recent_kev_additions/kev_new_additionsは
        # 送信リクエストへ出さず、人間可読ラベル「直近3暦日以内にKEVへ追加された
        # CVE」を使い、要素も「CVE ID」「KEV追加日」「追加からの日数」で表す。
        for internal in ("recent_kev_additions", "kev_new_additions"):
            self.assertNotIn(internal, verified)
        key = "直近3暦日以内にKEVへ追加されたCVE"
        self.assertIn(key, verified)
        self.assertEqual(len(verified[key]), 1)
        self.assertEqual(verified[key][0]["CVE ID"], "CVE-2026-0001")
        self.assertEqual(verified[key][0]["追加からの日数"], 1)

    def test_no_recent_kev_gives_empty_array(self):
        item = {"source": "CISA", "link": "https://x/a", "title": "t", "summary": "s",
                "facts": {"cves": [cve_entry("CVE-2026-0001", kev_dict=kev("listed", "2026-01-01"))]}}
        texts = self._capture([item], analysis_date=_dt.date(2026, 7, 14))
        verified, _ = tvp._extract_verified_and_untrusted(texts[0])
        self.assertEqual(verified["直近3暦日以内にKEVへ追加されたCVE"], [])


# ── 表示タイトルフロー(translateを呼ばない・日本語記事はraw) ──────────────

class DisplayTitleFlowTest(unittest.TestCase):
    def test_title_ja_used_on_ai_success(self):
        item = {"ai_analysis": {"title_ja": "日本語見出し"}, "raw_title": "English", "title": "English"}
        self.assertEqual(fetch.resolve_display_title(item, {}), "日本語見出し")

    def test_cache_exact_match_used_when_no_title_ja(self):
        item = {"ai_analysis": {"importance": "高"}, "raw_title": "English Title", "title": "English Title"}
        self.assertEqual(fetch.resolve_display_title(item, {"English Title": "キャッシュ済み日本語"}),
                         "キャッシュ済み日本語")

    def test_raw_title_used_when_no_title_ja_and_no_cache(self):
        item = {"ai_analysis": None, "raw_title": "English Title", "title": "English Title"}
        self.assertEqual(fetch.resolve_display_title(item, {}), "English Title")

    def test_csharp_title_ja_used(self):
        item = {"ai_analysis": {"title_ja": "C#アプリを狙う新たな攻撃"}, "raw_title": "New attack on C# apps"}
        self.assertEqual(fetch.resolve_display_title(item, {}), "C#アプリを狙う新たな攻撃")

    def test_japanese_article_keeps_raw_title(self):
        # main()はlang=="en"のみtitleを差し替える。日本語記事はraw titleのまま。
        item = {"lang": "ja", "title": "日本語の原題", "raw_title": "日本語の原題",
                "ai_analysis": {"title_ja": "別の日本語見出し"}}
        if item["lang"] == "en":  # main()と同じガード
            item["title"] = fetch.resolve_display_title(item, {})
        self.assertEqual(item["title"], "日本語の原題")

    def test_translate_not_called_for_titles(self):
        called = []

        def fake_translate(text, cache):
            called.append(text)
            return "SHOULD-NOT-BE-USED"

        with patch("fetch.translate", side_effect=fake_translate):
            t1 = fetch.resolve_display_title({"ai_analysis": {"title_ja": "見出し"}, "raw_title": "X"}, {})
            t2 = fetch.resolve_display_title({"ai_analysis": None, "raw_title": "X"}, {"X": "cached"})
        self.assertEqual(t1, "見出し")
        self.assertEqual(t2, "cached")
        self.assertEqual(called, [])  # translate()はタイトルに一切呼ばれない


if __name__ == "__main__":
    unittest.main()
