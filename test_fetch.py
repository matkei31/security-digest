#!/usr/bin/env python3
"""
HTMLエスケープ・URL検証の回帰テスト (Ticket 1)
標準ライブラリの unittest のみを使用する。
"""

import datetime
from html.parser import HTMLParser
import unittest
from pathlib import Path

import fetch


class AnchorParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.anchors = []
        self._stack = []
        self.nested_anchor = False

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "a":
            if "a" in self._stack:
                self.nested_anchor = True
            self.anchors.append(attrs)
        self._stack.append(tag)

    def handle_endtag(self, tag):
        for i in range(len(self._stack) - 1, -1, -1):
            if self._stack[i] == tag:
                del self._stack[i:]
                break


def parse_anchors(html):
    parser = AnchorParser()
    parser.feed(html)
    return parser


def important_segment(html):
    start = html.index('<section class="important-items">')
    end = html.index('<div class="cards">')
    return html[start:end]


def cards_segment(html):
    start = html.index('<div class="cards">')
    end = html.index('<div class="sources">')
    return html[start:end]


def anchors_with_class(parser, class_name):
    return [a for a in parser.anchors if a.get("class") == class_name]


class EscTest(unittest.TestCase):
    def test_script_tag_is_escaped(self):
        out = fetch.esc("<script>alert(1)</script>")
        self.assertNotIn("<script>", out)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", out)

    def test_all_five_chars_escaped(self):
        out = fetch.esc("""&<>"'""")
        self.assertEqual(out, "&amp;&lt;&gt;&quot;&#39;")

    def test_no_double_escaping(self):
        # 既にエスケープ済みの文字列に再度 esc() を通すケースは
        # 実装上発生しない前提だが、esc() 自体は一度分だけ変換することを確認する
        out = fetch.esc("&amp;")
        self.assertEqual(out, "&amp;amp;")  # esc()を1回だけ適用した結果として妥当


class SafeUrlTest(unittest.TestCase):
    def test_https_url_is_allowed(self):
        self.assertEqual(fetch.safe_url("https://example.com/a?b=1"),
                          "https://example.com/a?b=1")

    def test_http_url_is_allowed(self):
        self.assertEqual(fetch.safe_url("http://example.com"), "http://example.com")

    def test_leading_trailing_whitespace_is_stripped(self):
        self.assertEqual(fetch.safe_url("  https://example.com  "), "https://example.com")

    def test_javascript_scheme_is_rejected(self):
        self.assertIsNone(fetch.safe_url("javascript:alert(1)"))

    def test_data_scheme_is_rejected(self):
        self.assertIsNone(fetch.safe_url("data:text/html,<script>alert(1)</script>"))

    def test_control_char_inside_url_is_rejected(self):
        # タブ文字でスキームを分断し http(s) 判定を回避しようとするバイパス
        self.assertIsNone(fetch.safe_url("java\tscript:alert(1)"))

    def test_internal_whitespace_is_rejected(self):
        self.assertIsNone(fetch.safe_url("https://exa mple.com"))

    def test_protocol_relative_url_is_rejected(self):
        self.assertIsNone(fetch.safe_url("//evil.com"))

    def test_non_string_input_is_rejected(self):
        self.assertIsNone(fetch.safe_url(None))
        self.assertIsNone(fetch.safe_url(123))

    def test_empty_string_is_rejected(self):
        self.assertIsNone(fetch.safe_url(""))

    def test_does_not_silently_normalize_unsafe_url(self):
        # 不正なURLを加工して正常化せず、Noneを返すことを確認する
        # (制御文字を除去した上で受理する、といった変換は行わない)
        unsafe = "java\tscript:alert(1)"
        self.assertIsNone(fetch.safe_url(unsafe))


class BuildHtmlEscapeTest(unittest.TestCase):
    def _make_item(self, **overrides):
        item = {
            "title": "テスト記事",
            "link": "https://example.com/article",
            "summary": "概要文",
            "date": datetime.datetime.now(),
            "source": "CISA",
            "lang": "ja",
        }
        item.update(overrides)
        return item

    def test_script_tag_in_title_is_escaped_in_output(self):
        item = self._make_item(title="<script>alert(1)</script>")
        html = fetch.build_html([item])
        self.assertNotIn("<script>alert(1)</script>", html)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", html)

    def test_javascript_link_produces_no_href(self):
        item = self._make_item(link="javascript:alert(1)")
        html = fetch.build_html([item])
        self.assertNotIn("javascript:alert(1)", html)
        self.assertNotIn('<a class="article-title-link"', html)
        self.assertNotIn('<a class="article-source-link"', html)
        self.assertNotIn("元記事を読む", html)

    def test_normal_https_link_is_rendered_on_title_and_cta(self):
        item = self._make_item(link="https://example.com/article")
        html = fetch.build_html([item])
        parser = parse_anchors(html)
        hrefs = [a.get("href") for a in parser.anchors]

        self.assertIn('<a class="article-title-link" href="https://example.com/article"', html)
        self.assertIn('<a class="article-source-link" href="https://example.com/article"', html)
        self.assertIn("元記事を読む", html)
        self.assertEqual(hrefs.count("https://example.com/article"), 2)
        self.assertTrue(all(a.get("rel") == "noopener noreferrer" for a in parser.anchors))
        self.assertTrue(all(a.get("target") == "_blank" for a in parser.anchors))
        self.assertFalse(parser.nested_anchor)


class ArticleCardDisplayTest(unittest.TestCase):
    def _make_item(self, **overrides):
        item = {
            "title": "テスト記事",
            "link": "https://example.com/article",
            "summary": "取得時の概要文",
            "date": datetime.datetime(2026, 7, 11, 6, 0),
            "source": "CISA",
            "lang": "ja",
        }
        item.update(overrides)
        return item

    def _analysis(self, **overrides):
        analysis = {
            "category": "脆弱性・パッチ",
            "category_reason": "HTMLには表示しないカテゴリ理由",
            "importance": "高",
            "urgency": "本日確認",
            "summary": "CISAが悪用確認済み脆弱性をKEVへ追加した。",
            "financial_impact": "該当製品を利用する金融機関では確認が必要になり得る。",
            "recommended_actions": ["利用有無を確認する", "外部公開状況を確認する"],
            "reason": "HTMLには表示しない判定理由",
            "tags": ["KEV", "悪用確認済み", "パッチ"],
        }
        analysis.update(overrides)
        return analysis

    def test_article_card_displays_ticket5_analysis_fields(self):
        html = fetch.build_html([self._make_item(ai_analysis=self._analysis())])

        self.assertIn("重要度 高", html)
        self.assertIn("本日確認", html)
        self.assertIn("カテゴリ：脆弱性・パッチ", html)
        self.assertIn(
            '<div class="article-tags"><span class="article-tag">KEV</span>'
            '<span class="article-tag">悪用確認済み</span>'
            '<span class="article-tag">パッチ</span></div>',
            html,
        )
        self.assertIn("何が起きた", html)
        self.assertIn("CISAが悪用確認済み脆弱性をKEVへ追加した。", html)
        self.assertIn("なぜ金融機関に関係する", html)
        self.assertIn("該当製品を利用する金融機関では確認が必要になり得る。", html)
        self.assertIn("確認すべきこと", html)
        self.assertIn("<ul class=\"action-list\"><li>利用有無を確認する</li><li>外部公開状況を確認する</li></ul>", html)
        self.assertLess(html.index("利用有無を確認する"), html.index("外部公開状況を確認する"))
        self.assertNotIn("HTMLには表示しない判定理由", cards_segment(html))
        self.assertNotIn("HTMLには表示しないカテゴリ理由", html)

    def test_ticket5_badge_and_section_classes_are_rendered(self):
        html = fetch.build_html([self._make_item(ai_analysis=self._analysis())])

        self.assertIn("importance-badge importance-high", html)
        self.assertIn("urgency-badge urgency-today", html)
        self.assertIn("category-badge", html)
        self.assertIn("article-tags", html)
        self.assertIn("article-section", html)
        self.assertIn("action-list", html)
        self.assertIn('<meta name="viewport"', html)

    def test_empty_tags_do_not_render_tag_area(self):
        html = fetch.build_html([self._make_item(ai_analysis=self._analysis(tags=[]))])

        self.assertNotIn('<div class="article-tags">', html)
        self.assertIn("重要度 高", html)

    def test_missing_optional_analysis_fields_do_not_stop_html_generation(self):
        html = fetch.build_html([
            self._make_item(ai_analysis=self._analysis(
                urgency=None,
                category=None,
                tags=[],
                recommended_actions=[],
            ))
        ])

        self.assertIn("テスト記事", html)
        self.assertIn("重要度 高", html)
        self.assertNotIn("None", html)
        self.assertNotIn(">null<", html)
        self.assertNotIn("確認すべきこと", html)
        self.assertNotIn('<ul class="action-list">', html)

    def test_article_without_analysis_stays_visible_without_fixed_ai_text(self):
        html = fetch.build_html([self._make_item(ai_analysis=None)])

        self.assertIn("テスト記事", html)
        self.assertIn("取得時の概要文", html)
        self.assertNotIn("重要度 中", html)
        self.assertNotIn("金融機関への影響は不明", html)
        self.assertNotIn("原文を確認してください", html)

    def test_failed_article_with_empty_analysis_stays_visible(self):
        failed = {
            "status": "failed",
            "importance": None,
            "urgency": None,
            "category": None,
            "summary": None,
            "financial_impact": None,
            "recommended_actions": [],
            "tags": [],
        }
        html = fetch.build_html([self._make_item(ai_analysis=failed)])

        self.assertIn("テスト記事", html)
        self.assertNotIn("None", html)
        self.assertNotIn(">null<", html)
        self.assertNotIn("重要度 中", html)

    def test_ai_generated_ticket5_fields_are_escaped(self):
        html = fetch.build_html([
            self._make_item(
                title="<b>title</b>",
                source="<b>source</b>",
                ai_analysis=self._analysis(
                    category="<b>category</b>",
                    urgency="<b>urgency</b>",
                    summary="<b>summary</b>",
                    financial_impact="<b>impact</b>",
                    recommended_actions=["<b>action</b>"],
                    tags=["<b>tag</b>"],
                ),
            )
        ])

        self.assertIn("&lt;b&gt;title&lt;/b&gt;", html)
        self.assertIn("&lt;b&gt;source&lt;/b&gt;", html)
        self.assertIn("&lt;b&gt;category&lt;/b&gt;", html)
        self.assertIn("&lt;b&gt;urgency&lt;/b&gt;", html)
        self.assertIn("&lt;b&gt;summary&lt;/b&gt;", html)
        self.assertIn("&lt;b&gt;impact&lt;/b&gt;", html)
        self.assertIn("&lt;b&gt;action&lt;/b&gt;", html)
        self.assertIn("&lt;b&gt;tag&lt;/b&gt;", html)
        self.assertNotIn("<b>action</b>", html)

    def test_article_count_matches_input_items_when_analysis_missing_or_failed(self):
        items = [
            self._make_item(title="記事1", ai_analysis=self._analysis()),
            self._make_item(title="記事2", ai_analysis=None),
            self._make_item(title="記事3", ai_analysis={"status": "failed"}),
        ]
        html = fetch.build_html(items)
        parser = parse_anchors(html)

        self.assertEqual(html.count('class="card"'), 3)
        self.assertEqual(len(parser.anchors), 8)
        self.assertFalse(parser.nested_anchor)
        self.assertIn("記事1", html)
        self.assertIn("記事2", html)
        self.assertIn("記事3", html)

    def test_title_and_source_links_share_safe_url_and_rel(self):
        html = fetch.build_html([
            self._make_item(ai_analysis=self._analysis(importance="中", urgency="今週確認"))
        ])
        parser = parse_anchors(html)

        self.assertEqual(len(parser.anchors), 2)
        self.assertEqual(
            [a.get("href") for a in parser.anchors],
            ["https://example.com/article", "https://example.com/article"],
        )
        self.assertTrue(all(a.get("rel") == "noopener noreferrer" for a in parser.anchors))
        self.assertIn("元記事を読む", html)
        self.assertFalse(parser.nested_anchor)

    def test_invalid_url_does_not_link_title_or_cta(self):
        html = fetch.build_html([
            self._make_item(link="javascript:alert(1)", ai_analysis=self._analysis())
        ])
        parser = parse_anchors(html)

        self.assertEqual(parser.anchors, [])
        self.assertNotIn('<a class="article-title-link"', html)
        self.assertNotIn('<a class="article-source-link"', html)
        self.assertNotIn("元記事を読む", html)
        self.assertIn("<h2>テスト記事</h2>", html)
        self.assertIn("重要度 高", html)
        self.assertFalse(parser.nested_anchor)


class ImportantItemsTest(unittest.TestCase):
    def _make_item(self, title, **analysis_overrides):
        analysis = {
            "category": "脆弱性・パッチ",
            "category_reason": "カテゴリ理由は表示しない",
            "importance": "中",
            "urgency": "今週確認",
            "summary": f"{title}の要約は重要情報には出さない",
            "financial_impact": f"{title}の金融影響は重要情報には出さない",
            "recommended_actions": [f"{title}の確認事項は重要情報には出さない"],
            "reason": f"{title}の判定理由",
            "tags": [f"{title}タグ"],
        }
        analysis.update(analysis_overrides)
        return {
            "id": f"id-{title}",
            "title": title,
            "link": f"https://example.com/{title}",
            "summary": f"{title}の取得概要",
            "date": datetime.datetime(2026, 7, 11, 6, 0),
            "source": "CISA",
            "lang": "ja",
            "ai_analysis": analysis,
        }

    def _important_titles(self, items):
        return [item["title"] for item in fetch.select_important_items(items)]

    def test_selects_high_importance_or_today_urgency_once(self):
        high = self._make_item("high", importance="高", urgency="今週確認")
        today = self._make_item("today", importance="中", urgency="本日確認")
        both = self._make_item("both", importance="高", urgency="本日確認")
        mid_week = self._make_item("mid-week", importance="中", urgency="今週確認")
        low_ref = self._make_item("low-ref", importance="低", urgency="参考")

        self.assertEqual(
            set(self._important_titles([high, today, both, mid_week, low_ref])),
            {"high", "today", "both"},
        )
        self.assertEqual(self._important_titles([both, both]), ["both"])

    def test_same_id_is_deduplicated(self):
        first = self._make_item("first", importance="高", urgency="本日確認")
        second = self._make_item("second", importance="高", urgency="本日確認")
        first["id"] = "same-id"
        second["id"] = "same-id"

        self.assertEqual(self._important_titles([first, second]), ["first"])

    def test_same_composite_key_without_id_is_deduplicated(self):
        first = self._make_item("same", importance="高", urgency="本日確認")
        second = self._make_item("same", importance="高", urgency="本日確認")
        for item in (first, second):
            item.pop("id", None)
            item["link"] = "https://example.com/shared"
            item["source"] = "CISA KEV"
            item["date"] = datetime.datetime(2026, 7, 11, 6, 0)

        self.assertEqual(self._important_titles([first, second]), ["same"])

    def test_same_link_different_title_without_id_keeps_both(self):
        first = self._make_item("CVE-2026-0001", importance="高", urgency="本日確認")
        second = self._make_item("CVE-2026-0002", importance="高", urgency="本日確認")
        for item in (first, second):
            item.pop("id", None)
            item["link"] = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
            item["source"] = "CISA KEV"
            item["date"] = datetime.datetime(2026, 7, 11, 6, 0)

        self.assertEqual(
            self._important_titles([first, second]),
            ["CVE-2026-0001", "CVE-2026-0002"],
        )

    def test_cisa_kev_same_display_url_different_cve_titles_keep_both(self):
        first = self._make_item(
            "CVE-2026-56291 — Balbooa Forms unrestricted upload",
            importance="高",
            urgency="本日確認",
        )
        second = self._make_item(
            "CVE-2026-48939 — iCagenda unrestricted upload",
            importance="高",
            urgency="本日確認",
        )
        for item in (first, second):
            item.pop("id", None)
            item["link"] = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
            item["source"] = "CISA KEV"
            item["date"] = datetime.datetime(2026, 7, 11, 6, 0)

        html = fetch.build_html([first, second])

        self.assertEqual(len(fetch.select_important_items([first, second])), 2)
        self.assertIn("CVE-2026-56291", important_segment(html))
        self.assertIn("CVE-2026-48939", important_segment(html))
        self.assertEqual(cards_segment(html).count('class="card"'), 2)

    def test_missing_and_invalid_importance_urgency_are_not_selected(self):
        missing = self._make_item("missing", importance=None, urgency=None)
        invalid_importance = self._make_item("invalid-importance", importance="極高", urgency="本日確認")
        invalid_urgency = self._make_item("invalid-urgency", importance="高", urgency="即時")

        self.assertEqual(
            fetch.select_important_items([missing, invalid_importance, invalid_urgency]),
            [],
        )

    def test_fallback_valid_importance_or_urgency_is_selected(self):
        fallback = self._make_item(
            "fallback",
            status="fallback",
            importance="高",
            urgency=None,
            summary=None,
            financial_impact=None,
            recommended_actions=[],
        )

        self.assertEqual(self._important_titles([fallback]), ["fallback"])

    def test_failed_and_missing_analysis_are_not_selected_but_remain_in_cards(self):
        failed = self._make_item(
            "failed",
            status="failed",
            importance=None,
            urgency=None,
            category=None,
            summary=None,
            financial_impact=None,
            recommended_actions=[],
            reason=None,
            tags=[],
        )
        no_analysis = {**self._make_item("no-analysis"), "ai_analysis": None}
        html = fetch.build_html([failed, no_analysis])

        self.assertEqual(fetch.select_important_items([failed, no_analysis]), [])
        self.assertIn("本日、優先表示の対象となる情報はありません。", important_segment(html))
        self.assertEqual(cards_segment(html).count('class="card"'), 2)
        self.assertIn("failed", cards_segment(html))
        self.assertIn("no-analysis", cards_segment(html))

    def test_sort_order_is_urgency_then_importance_then_original_order(self):
        high_week = self._make_item("high-week", importance="高", urgency="今週確認")
        mid_today = self._make_item("mid-today", importance="中", urgency="本日確認")
        high_today_a = self._make_item("high-today-a", importance="高", urgency="本日確認")
        high_today_b = self._make_item("high-today-b", importance="高", urgency="本日確認")

        self.assertEqual(
            self._important_titles([high_week, mid_today, high_today_a, high_today_b]),
            ["high-today-a", "high-today-b", "mid-today", "high-week"],
        )

    def test_full_article_order_is_not_changed(self):
        items = [
            self._make_item("first", importance="高", urgency="今週確認"),
            self._make_item("second", importance="中", urgency="本日確認"),
            self._make_item("third", importance="低", urgency="参考"),
        ]
        html = fetch.build_html(items)
        cards = cards_segment(html)

        self.assertLess(cards.index("first"), cards.index("second"))
        self.assertLess(cards.index("second"), cards.index("third"))

    def test_important_items_section_displays_only_compact_fields(self):
        item = self._make_item("compact", importance="高", urgency="本日確認")
        html = fetch.build_html([item])
        important = important_segment(html)
        cards = cards_segment(html)

        self.assertIn("本日の重要情報", important)
        self.assertIn("重要度 高", important)
        self.assertIn("本日確認", important)
        self.assertIn("カテゴリ：脆弱性・パッチ", important)
        self.assertIn("compact", important)
        self.assertIn("compactの判定理由", important)
        self.assertNotIn("compactの要約は重要情報には出さない", important)
        self.assertNotIn("compactの金融影響は重要情報には出さない", important)
        self.assertNotIn("compactの確認事項は重要情報には出さない", important)
        self.assertNotIn("compactタグ", important)
        self.assertNotIn("compactの判定理由", cards)
        self.assertNotIn("カテゴリ理由は表示しない", html)

    def test_reason_missing_omits_reason_without_fixed_text(self):
        item = self._make_item("no-reason", importance="高", urgency="本日確認", reason=None)
        html = fetch.build_html([item])
        important = important_segment(html)

        self.assertIn("no-reason", important)
        self.assertNotIn("important-item-reason", important)
        self.assertNotIn("原文を確認してください", important)
        self.assertNotIn("金融機関への影響は不明", important)

    def test_empty_important_items_section_still_renders(self):
        item = self._make_item("ordinary", importance="中", urgency="今週確認")
        html = fetch.build_html([item])

        self.assertIn("本日の重要情報", important_segment(html))
        self.assertIn("本日、優先表示の対象となる情報はありません。", important_segment(html))
        self.assertEqual(cards_segment(html).count('class="card"'), 1)

    def test_important_item_links_use_safe_url_without_nested_anchors(self):
        item = self._make_item("linked", importance="高", urgency="本日確認")
        html = fetch.build_html([item])
        important_parser = parse_anchors(important_segment(html))
        hrefs = [a.get("href") for a in important_parser.anchors]

        self.assertEqual(hrefs, ["https://example.com/linked", "https://example.com/linked"])
        self.assertTrue(all(a.get("target") == "_blank" for a in important_parser.anchors))
        self.assertTrue(all(a.get("rel") == "noopener noreferrer" for a in important_parser.anchors))
        self.assertFalse(parse_anchors(html).nested_anchor)

    def test_important_item_does_not_link_unsafe_url(self):
        item = self._make_item("unsafe", importance="高", urgency="本日確認")
        item["link"] = "javascript:alert(1)"
        html = fetch.build_html([item])
        important = important_segment(html)

        self.assertEqual(parse_anchors(important).anchors, [])
        self.assertNotIn("javascript:alert(1)", html)
        self.assertNotIn("元記事を読む", important)

    def test_important_item_escapes_external_and_ai_text(self):
        item = self._make_item(
            "<b>title</b>",
            importance="高",
            urgency="本日確認",
            category="<b>category</b>",
            reason="<b>reason</b>",
        )
        html = fetch.build_html([item])
        important = important_segment(html)

        self.assertIn("&lt;b&gt;title&lt;/b&gt;", important)
        self.assertIn("&lt;b&gt;category&lt;/b&gt;", important)
        self.assertIn("&lt;b&gt;reason&lt;/b&gt;", important)
        self.assertNotIn("<b>reason</b>", html)

    def test_important_items_section_precedes_all_cards(self):
        html = fetch.build_html([self._make_item("ordered", importance="高", urgency="本日確認")])

        self.assertLess(html.index('<section class="important-items">'), html.index('<div class="cards">'))
        self.assertIn('<meta name="viewport"', html)
        self.assertIn("article-section", html)


class AgentsFileTest(unittest.TestCase):
    def test_agents_file_contains_required_handoff_notes(self):
        text = (Path(__file__).resolve().parent / "AGENTS.md").read_text(encoding="utf-8")

        self.assertIn('python3 -m unittest discover -p "test_*.py"', text)
        self.assertIn("Do not merge into `main` without review.", text)
        self.assertIn("digest", text)
        self.assertIn("rebase", text)
        self.assertIn("Never commit API keys", text)


if __name__ == "__main__":
    unittest.main()
