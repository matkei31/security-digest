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
    def test_article_prompt_version_is_v5(self):
        self.assertEqual(dj.ARTICLE_PROMPT_VERSION, "article-analysis-v5")

    def test_brief_prompt_version_and_schema_version_unchanged(self):
        self.assertEqual(dj.BRIEF_PROMPT_VERSION, "today-brief-v3")
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


# ── recommended_actions lint(状態変更動詞の指示用法) ──────────────────────

class RecommendedActionsLintTest(unittest.TestCase):
    def test_ticket_reject_cases(self):
        for bad in ("設定を変更し、結果を確認する。", "対象製品を停止して影響を評価する。",
                    "CISA対象製品を直ちに無効化する。", "ベンダー製品を停止する。",
                    "対象ソフトウェアを更新する。", "更新を検討する。",
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
                   "対応要否を判断する"):
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
        self.assertIn("recent_kev_additions", self.text)
        self.assertIn("cve_id・kev_date_added", self.flat)
        self.assertIn("days_since_added", self.text)
        self.assertIn("日付差は計算済みで自分では計算しない", self.flat)

    def test_no_nonexistent_facts_kev_dateadded_reference(self):
        # 存在しない旧contract名を残さない(Ticket 15a第2版・最優先)。
        self.assertNotIn("facts.kev.dateAdded", self.text)
        self.assertNotIn("facts.kev", self.text)

    def test_kev_new_add_strong_today_basis(self):
        self.assertIn("recent_kev_additionsに含まれるCVE", self.flat)
        self.assertIn("本日確認の強い根拠", self.flat)
        self.assertIn("今週確認へ下げない", self.flat)
        self.assertIn("適用範囲の狭さはimportanceを下げる要因でありurgencyは下げない", self.flat)

    def test_kev_new_add_first_action(self):
        self.assertIn("保有・稼働・外部露出・影響バージョンの確認", self.flat)
        self.assertIn("全環境への即時パッチ適用を一律には命じない", self.flat)

    def test_recent_kev_is_the_only_exception(self):
        # Ticket 15a第2版-1: recent_kev_additionsだけが例外(本日確認の強い根拠)であり、
        # 「既存/新規追加でないKEV掲載」だけが掲載単独では不十分であることを全文で統一。
        self.assertIn("recent_kev_additionsに含まれるCVEは例外で本日確認の強い根拠", self.flat)
        self.assertIn("recent_kev_additionsに含まれない既存の掲載では", self.flat)
        self.assertIn("recent_kev_additionsに含まれない既存KEVでは", self.flat)
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
        self.assertIn("recent_kev_additionsのCVEは直近追加自体が時間的根拠", self.flat)
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
        self.assertIn("recent_kev_additions非該当", e1)
        self.assertIn("進行中", e1)
        self.assertIn('"urgency": "本日確認"', e1)
        # 例3: 新規追加でないKEVは掲載だけで本日確認にせず今週確認
        self.assertIn("新規追加ではないため掲載だけで本日確認にしない", e3)
        self.assertIn('"urgency": "今週確認"', e3)
        # 例7: recent(days_since_added=1)で本日確認
        self.assertIn("days_since_added=1", e7)
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
        self.assertIn("recent_kev_additionsに含まれる", self.flat)
        self.assertIn("実悪用が確認されたとして本脆弱性をKEVカタログへ", self.flat)

    def test_summary_does_not_leak_field_name(self):
        # Ticket 15a第2版-2: kev_date_addedを裸で出力させない。
        self.assertNotIn("CISAはkev_date_added", self.flat)  # 出力例に裸のフィールド名がない
        self.assertIn("フィールド名kev_date_added自体は出力しない", self.flat)  # 明示指示
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
            self.assertEqual(verified["analysis_date"], "2026-07-14")

    def test_recent_kev_additions_in_verified_context(self):
        item = {"source": "CISA", "link": "https://x/a", "title": "t", "summary": "s",
                "facts": {"cves": [cve_entry("CVE-2026-0001", kev_dict=kev("listed", "2026-07-13"))]}}
        texts = self._capture([item], analysis_date=_dt.date(2026, 7, 14))
        verified, _ = tvp._extract_verified_and_untrusted(texts[0])
        self.assertIn("recent_kev_additions", verified)
        self.assertEqual(len(verified["recent_kev_additions"]), 1)
        self.assertEqual(verified["recent_kev_additions"][0]["cve_id"], "CVE-2026-0001")
        self.assertEqual(verified["recent_kev_additions"][0]["days_since_added"], 1)

    def test_no_recent_kev_gives_empty_array(self):
        item = {"source": "CISA", "link": "https://x/a", "title": "t", "summary": "s",
                "facts": {"cves": [cve_entry("CVE-2026-0001", kev_dict=kev("listed", "2026-01-01"))]}}
        texts = self._capture([item], analysis_date=_dt.date(2026, 7, 14))
        verified, _ = tvp._extract_verified_and_untrusted(texts[0])
        self.assertEqual(verified["recent_kev_additions"], [])


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
