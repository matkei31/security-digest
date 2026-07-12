#!/usr/bin/env python3
"""
HTMLエスケープ・URL検証の回帰テスト (Ticket 1)
標準ライブラリの unittest のみを使用する。
"""

import datetime
import json
import os
import tempfile
from html.parser import HTMLParser
from pathlib import Path
from unittest.mock import patch
import unittest

import fetch
import vulnerability_facts as vf


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
    end = html.index('<section class="dashboard">')
    return html[start:end]


def dashboard_segment(html):
    start = html.index('<section class="dashboard">')
    end = html.index('<section class="article-list-header">')
    return html[start:end]


def cards_segment(html):
    start = html.index('<div class="cards">')
    end = html.index('<div class="sources">')
    return html[start:end]


def anchors_with_class(parser, class_name):
    return [a for a in parser.anchors if a.get("class") == class_name]


def article_link_anchors(parser):
    return [
        a for a in parser.anchors
        if a.get("class") in ("article-title-link", "article-source-link")
    ]


def brief_segment(html):
    start = html.index('<div class="todays-brief">')
    end = html.index('<section class="important-items">')
    return html[start:end]


SAMPLE_BRIEF = {
    "overview": "本日は脆弱性関連の情報が中心で、金融機関に影響し得る内容が複数確認されました。",
    "important_highlights": ["重要情報ハイライト1", "重要情報ハイライト2"],
    "discussion_points": ["本日の注目論点1"],
    "check_items": ["確認事項1", "確認事項2"],
}


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
        article_anchors = article_link_anchors(parser)
        hrefs = [a.get("href") for a in article_anchors]

        self.assertIn('<a class="article-title-link" href="https://example.com/article"', html)
        self.assertIn('<a class="article-source-link" href="https://example.com/article"', html)
        self.assertIn("元記事を読む", html)
        self.assertEqual(hrefs.count("https://example.com/article"), 2)
        self.assertTrue(all(a.get("rel") == "noopener noreferrer" for a in article_anchors))
        self.assertTrue(all(a.get("target") == "_blank" for a in article_anchors))
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

        self.assertIn("確認優先度 高", html)
        self.assertIn("確認目安 本日確認", html)
        self.assertIn("カテゴリ：脆弱性・パッチ", html)
        self.assertIn(
            '<div class="article-tags"><span class="article-tags-label">関連タグ：</span>'
            '<span class="article-tag">KEV</span>'
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
        self.assertIn("確認優先度 高", html)

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
        self.assertIn("確認優先度 高", html)
        self.assertNotIn("None", html)
        self.assertNotIn(">null<", html)
        self.assertNotIn("確認すべきこと", html)
        self.assertNotIn('<ul class="action-list">', html)

    def test_article_without_analysis_stays_visible_without_fixed_ai_text(self):
        html = fetch.build_html([self._make_item(ai_analysis=None)])

        self.assertIn("テスト記事", html)
        self.assertIn("取得時の概要文", html)
        self.assertNotIn("確認優先度 中", html)
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
        self.assertNotIn("確認優先度 中", html)

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
        self.assertEqual(len(article_link_anchors(parser)), 6)
        self.assertFalse(parser.nested_anchor)
        self.assertIn("記事1", html)
        self.assertIn("記事2", html)
        self.assertIn("記事3", html)

    def test_title_and_source_links_share_safe_url_and_rel(self):
        html = fetch.build_html([
            self._make_item(ai_analysis=self._analysis(importance="中", urgency="今週確認"))
        ])
        parser = parse_anchors(html)
        article_anchors = article_link_anchors(parser)

        self.assertEqual(len(article_anchors), 2)
        self.assertEqual(
            [a.get("href") for a in article_anchors],
            ["https://example.com/article", "https://example.com/article"],
        )
        self.assertTrue(all(a.get("rel") == "noopener noreferrer" for a in article_anchors))
        self.assertIn("元記事を読む", html)
        self.assertFalse(parser.nested_anchor)

    def test_invalid_url_does_not_link_title_or_cta(self):
        html = fetch.build_html([
            self._make_item(link="javascript:alert(1)", ai_analysis=self._analysis())
        ])
        parser = parse_anchors(html)

        self.assertEqual(article_link_anchors(parser), [])
        self.assertNotIn('<a class="article-title-link"', html)
        self.assertNotIn('<a class="article-source-link"', html)
        self.assertNotIn("元記事を読む", html)
        self.assertIn("テスト記事", html)
        self.assertIn("確認優先度 高", html)
        self.assertFalse(parser.nested_anchor)


class AllItemsDisplayOrderTest(unittest.TestCase):
    def _analysis(self, importance=None, urgency=None, status="success"):
        return {
            "status": status,
            "category": "その他",
            "importance": importance,
            "urgency": urgency,
            "summary": "表示用の要約",
            "financial_impact": "表示用の金融影響",
            "recommended_actions": ["確認する"],
            "reason": "通常カードには表示しない理由",
            "tags": [],
        }

    def _make_item(self, title, importance=None, urgency=None, **overrides):
        item = {
            "title": title,
            "link": f"https://example.com/{title}",
            "summary": f"{title}の概要",
            "date": datetime.datetime(2026, 7, 11, 6, 0),
            "source": "CISA",
            "lang": "ja",
            "ai_analysis": self._analysis(importance, urgency),
        }
        item.update(overrides)
        return item

    def _display_titles(self, items):
        return [item["title"] for item in fetch.sort_items_for_display(items)]

    def test_sort_items_for_display_orders_by_urgency_then_importance(self):
        items = [
            self._make_item("reference-high", "高", "参考"),
            self._make_item("today-low", "低", "本日確認"),
            self._make_item("week-high", "高", "今週確認"),
            self._make_item("today-high", "高", "本日確認"),
            self._make_item("today-medium", "中", "本日確認"),
        ]

        self.assertEqual(
            self._display_titles(items),
            ["today-high", "today-medium", "today-low", "week-high", "reference-high"],
        )

    def test_sort_items_for_display_keeps_same_condition_original_order(self):
        items = [
            self._make_item("first", "中", "今週確認"),
            self._make_item("second", "中", "今週確認"),
            self._make_item("third", "中", "今週確認"),
        ]

        self.assertEqual(self._display_titles(items), ["first", "second", "third"])

    def test_sort_items_for_display_does_not_mutate_input(self):
        items = [
            self._make_item("reference", "低", "参考"),
            self._make_item("today", "高", "本日確認"),
        ]
        original_titles = [item["title"] for item in items]
        ordered = fetch.sort_items_for_display(items)

        self.assertEqual([item["title"] for item in items], original_titles)
        self.assertIsNot(ordered, items)
        self.assertEqual([item["title"] for item in ordered], ["today", "reference"])

    def test_unknown_urgency_and_importance_are_ranked_independently(self):
        items = [
            self._make_item("missing-analysis", "高", "本日確認", ai_analysis=None),
            self._make_item("invalid-urgency-high", "高", "即時"),
            self._make_item("invalid-urgency-low", "低", "None"),
            self._make_item("reference-medium", "中", "参考"),
            self._make_item("empty-importance", "", ""),
            self._make_item("null-importance", "null", None),
        ]

        self.assertEqual(
            self._display_titles(items),
            [
                "reference-medium",
                "invalid-urgency-high",
                "invalid-urgency-low",
                "missing-analysis",
                "empty-importance",
                "null-importance",
            ],
        )

    def test_failed_and_not_attempted_analysis_are_unknown_for_display_order(self):
        items = [
            self._make_item("failed", "高", "本日確認", ai_analysis=self._analysis("高", "本日確認", status="failed")),
            self._make_item("normal", "低", "参考"),
            self._make_item("not-attempted", "高", "本日確認", ai_analysis=self._analysis("高", "本日確認", status="not_attempted")),
        ]

        self.assertEqual(self._display_titles(items), ["normal", "failed", "not-attempted"])

    def test_build_html_uses_display_order_and_sequential_numbers(self):
        items = [
            self._make_item("reference-high", "高", "参考"),
            self._make_item("today-low", "低", "本日確認"),
            self._make_item("week-high", "高", "今週確認"),
        ]
        html = fetch.build_html(items)
        cards = cards_segment(html)

        self.assertIn("本日の情報", html)
        self.assertNotIn("全記事一覧", html)
        self.assertIn("確認目安、確認優先度、元の収集順で表示しています。", html)
        self.assertLess(cards.index("today-low"), cards.index("week-high"))
        self.assertLess(cards.index("week-high"), cards.index("reference-high"))
        self.assertIn('<span class="article-index">1.</span>', cards)
        self.assertIn('<span class="article-index">2.</span>', cards)
        self.assertIn('<span class="article-index">3.</span>', cards)
        self.assertNotIn("No. 1", cards)
        self.assertEqual(cards.count('class="card"'), 3)
        self.assertEqual(cards.count('class="article-index"'), 3)

    def test_all_items_order_does_not_change_important_items_or_dashboard(self):
        important_today_low = self._make_item("important-today-low", "低", "本日確認")
        important_high_week = self._make_item("important-high-week", "高", "今週確認")
        ordinary_reference = self._make_item("ordinary-reference", "中", "参考")
        items = [important_high_week, ordinary_reference, important_today_low]
        html = fetch.build_html(items)

        self.assertEqual(
            [item["title"] for item in fetch.select_important_items(items)],
            ["important-today-low", "important-high-week"],
        )
        self.assertLess(
            important_segment(html).index("important-today-low"),
            important_segment(html).index("important-high-week"),
        )
        self.assertIn("<strong>3件</strong>", dashboard_segment(html))
        self.assertLess(
            cards_segment(html).index("important-today-low"),
            cards_segment(html).index("important-high-week"),
        )


class TodaysBriefHtmlTest(unittest.TestCase):
    def _make_item(self, title="記事"):
        return {
            "title": title,
            "link": f"https://example.com/{title}",
            "summary": f"{title}の概要",
            "date": datetime.datetime(2026, 7, 11, 6, 0),
            "source": "CISA",
            "lang": "ja",
        }

    def test_heading_todays_brief_is_shown(self):
        html = fetch.build_html([self._make_item()], SAMPLE_BRIEF)
        self.assertIn("Today's Brief", brief_segment(html))

    def test_overview_heading_and_paragraph_are_shown(self):
        html = fetch.build_html([self._make_item()], SAMPLE_BRIEF)
        segment = brief_segment(html)
        self.assertIn("本日の概況", segment)
        self.assertIn(
            f'<p class="brief-overview">{SAMPLE_BRIEF["overview"]}</p>', segment
        )

    def test_important_highlights_are_not_rendered_in_html(self):
        html = fetch.build_html([self._make_item()], SAMPLE_BRIEF)
        segment = brief_segment(html)
        self.assertNotIn("重要情報ハイライト", segment)
        for text in SAMPLE_BRIEF["important_highlights"]:
            self.assertNotIn(text, segment)

    def test_discussion_points_render_as_list(self):
        html = fetch.build_html([self._make_item()], SAMPLE_BRIEF)
        segment = brief_segment(html)
        self.assertIn("本日の注目論点", segment)
        for text in SAMPLE_BRIEF["discussion_points"]:
            self.assertIn(f"<li>{text}</li>", segment)

    def test_check_items_render_as_list(self):
        html = fetch.build_html([self._make_item()], SAMPLE_BRIEF)
        segment = brief_segment(html)
        self.assertIn("本日の確認事項", segment)
        for text in SAMPLE_BRIEF["check_items"]:
            self.assertIn(f"<li>{text}</li>", segment)

    def test_empty_array_section_is_not_rendered(self):
        brief = dict(SAMPLE_BRIEF, discussion_points=[])
        html = fetch.build_html([self._make_item()], brief)
        segment = brief_segment(html)
        self.assertNotIn("本日の注目論点", segment)
        overview = segment[segment.index("本日の概況"):segment.index("本日の確認事項")]
        self.assertNotIn("<ul", overview)  # overviewセクションにulがないこと

    def test_success_with_all_arrays_empty_still_shows_overview(self):
        brief = {
            "overview": "本日は特筆すべき高重要度の情報はありませんでした。通常運用を継続してください。",
            "important_highlights": [], "discussion_points": [], "check_items": [],
        }
        html = fetch.build_html([self._make_item()], brief)
        segment = brief_segment(html)
        self.assertIn(brief["overview"], segment)
        self.assertNotIn("重要情報ハイライト", segment)
        self.assertNotIn("本日の注目論点", segment)
        self.assertNotIn("本日の確認事項", segment)

    def test_brief_none_hides_section_entirely(self):
        html = fetch.build_html([self._make_item()], None)
        self.assertNotIn('<div class="todays-brief">', html)
        self.assertNotIn("Today's Brief", html)

    def test_brief_omitted_defaults_to_hidden(self):
        html = fetch.build_html([self._make_item()])
        self.assertNotIn('<div class="todays-brief">', html)

    def test_brief_section_precedes_dashboard(self):
        html = fetch.build_html([self._make_item()], SAMPLE_BRIEF)
        self.assertLess(
            html.index('<div class="todays-brief">'),
            html.index('<section class="dashboard">'),
        )

    def test_brief_section_precedes_important_items(self):
        html = fetch.build_html([self._make_item()], SAMPLE_BRIEF)
        self.assertLess(
            html.index('<div class="todays-brief">'),
            html.index('<section class="important-items">'),
        )

    def test_dashboard_content_unaffected_by_brief(self):
        items = [self._make_item("a"), self._make_item("b")]
        with_brief = dashboard_segment(fetch.build_html(items, SAMPLE_BRIEF))
        without_brief = dashboard_segment(fetch.build_html(items, None))
        self.assertEqual(with_brief, without_brief)

    def test_card_count_and_order_unaffected_by_brief(self):
        items = [self._make_item("a"), self._make_item("b"), self._make_item("c")]
        with_brief = cards_segment(fetch.build_html(items, SAMPLE_BRIEF))
        without_brief = cards_segment(fetch.build_html(items, None))
        self.assertEqual(with_brief, without_brief)

    def test_overview_is_html_escaped(self):
        brief = dict(SAMPLE_BRIEF, overview='<script>alert(1)</script>')
        html = fetch.build_html([self._make_item()], brief)
        segment = brief_segment(html)
        self.assertNotIn("<script>alert(1)</script>", segment)
        self.assertIn("&lt;script&gt;", segment)

    def test_array_items_are_html_escaped(self):
        brief = dict(
            SAMPLE_BRIEF,
            important_highlights=['<img src=x onerror=alert(1)>'],
            discussion_points=['<b>強調</b>'],
            check_items=['"quoted" & <tag>'],
        )
        html = fetch.build_html([self._make_item()], brief)
        segment = brief_segment(html)
        self.assertNotIn("<img src=x", segment)
        self.assertNotIn("<b>強調</b>", segment)
        self.assertNotIn('"quoted" & <tag>', segment)
        self.assertNotIn("&lt;img", segment)
        self.assertIn("&lt;b&gt;", segment)

    def test_no_html_comment_carries_brief_content(self):
        html = fetch.build_html([self._make_item()], SAMPLE_BRIEF)
        self.assertNotIn("<!--", html)

    def test_reason_and_category_reason_are_not_added_to_brief(self):
        html = fetch.build_html([self._make_item()], SAMPLE_BRIEF)
        segment = brief_segment(html)
        self.assertNotIn("category_reason", segment)


class DashboardTest(unittest.TestCase):
    def _make_item(self, title="記事", **analysis_overrides):
        item_overrides = {}
        for key in ("ai_analysis", "link", "summary", "date", "source", "lang"):
            if key in analysis_overrides:
                item_overrides[key] = analysis_overrides.pop(key)
        analysis = {
            "status": "success",
            "category": "脆弱性・パッチ",
            "category_reason": "Dashboardには表示しないカテゴリ理由",
            "importance": "高",
            "urgency": "本日確認",
            "summary": "Dashboardには使わない要約",
            "financial_impact": "Dashboardには使わない影響",
            "recommended_actions": ["Dashboardには使わない確認事項"],
            "reason": "Dashboardには表示しない判定理由",
            "tags": ["Dashboardには使わないタグ"],
        }
        analysis.update(analysis_overrides)
        item = {
            "title": title,
            "link": f"https://example.com/{title}",
            "summary": f"{title}の取得概要",
            "date": datetime.datetime(2026, 7, 11, 6, 0),
            "source": "CISA",
            "lang": "ja",
            "ai_analysis": analysis,
        }
        item.update(item_overrides)
        return item

    def test_compute_dashboard_counts_total_and_all_axes(self):
        items = [
            self._make_item("high-today-patch", importance="高", urgency="本日確認", category="脆弱性・パッチ"),
            self._make_item("medium-week-threat", importance="中", urgency="今週確認", category="攻撃・脅威動向"),
            self._make_item("low-reference-ai", importance="低", urgency="参考", category="AI・新技術リスク"),
            self._make_item("missing", importance=None, urgency=None, category=None),
            self._make_item("invalid", importance="極高", urgency="即時", category="未知カテゴリ"),
            self._make_item("failed", status="failed", importance="高", urgency="本日確認", category="その他"),
            self._make_item("not-attempted", status="not_attempted"),
            {**self._make_item("no-analysis"), "ai_analysis": None},
        ]

        counts = fetch.compute_dashboard_counts(items)

        self.assertEqual(counts["total"], len(items))
        self.assertEqual(counts["importance"]["高"], 1)
        self.assertEqual(counts["importance"]["中"], 1)
        self.assertEqual(counts["importance"]["低"], 1)
        self.assertEqual(counts["importance"]["未判定"], 5)
        self.assertEqual(sum(counts["importance"].values()), len(items))
        self.assertEqual(counts["urgency"]["本日確認"], 1)
        self.assertEqual(counts["urgency"]["今週確認"], 1)
        self.assertEqual(counts["urgency"]["参考"], 1)
        self.assertEqual(counts["urgency"]["未判定"], 5)
        self.assertEqual(sum(counts["urgency"].values()), len(items))
        self.assertEqual(counts["category"]["脆弱性・パッチ"], 1)
        self.assertEqual(counts["category"]["攻撃・脅威動向"], 1)
        self.assertEqual(counts["category"]["インシデント"], 0)
        self.assertEqual(counts["category"]["規制・ガバナンス"], 0)
        self.assertEqual(counts["category"]["クラウド・サプライチェーン"], 0)
        self.assertEqual(counts["category"]["AI・新技術リスク"], 1)
        self.assertEqual(counts["category"]["その他"], 0)
        self.assertEqual(counts["category"]["未判定"], 5)
        self.assertEqual(sum(counts["category"].values()), len(items))

    def test_fallback_counts_valid_values_and_missing_axis_independently(self):
        item = self._make_item(
            "fallback",
            status="fallback",
            importance="中",
            urgency=None,
            category="その他",
        )
        counts = fetch.compute_dashboard_counts([item])

        self.assertEqual(counts["importance"]["中"], 1)
        self.assertEqual(counts["importance"]["未判定"], 0)
        self.assertEqual(counts["urgency"]["未判定"], 1)
        self.assertEqual(counts["category"]["その他"], 1)
        self.assertEqual(counts["category"]["未判定"], 0)

    def test_none_and_null_strings_count_as_unknown(self):
        items = [
            self._make_item("none-string", importance="None", urgency="null", category=""),
            self._make_item("empty-analysis", ai_analysis={}),
        ]
        counts = fetch.compute_dashboard_counts(items)

        self.assertEqual(counts["importance"]["未判定"], 2)
        self.assertEqual(counts["urgency"]["未判定"], 2)
        self.assertEqual(counts["category"]["未判定"], 2)

    def test_empty_items_dashboard_counts(self):
        counts = fetch.compute_dashboard_counts([])

        self.assertEqual(counts["total"], 0)
        self.assertEqual(sum(counts["importance"].values()), 0)
        self.assertEqual(sum(counts["urgency"].values()), 0)
        self.assertEqual(sum(counts["category"].values()), 0)
        self.assertIn("高", counts["importance"])
        self.assertIn("本日確認", counts["urgency"])
        self.assertIn("脆弱性・パッチ", counts["category"])

    def test_dashboard_html_position_and_content(self):
        items = [
            self._make_item("first", importance="高", urgency="本日確認", category="脆弱性・パッチ"),
            self._make_item("second", importance="中", urgency="今週確認", category="その他"),
        ]
        html = fetch.build_html(items, SAMPLE_BRIEF)
        dashboard = dashboard_segment(html)

        self.assertIn("本日のダッシュボード", dashboard)
        self.assertIn("本日の収集", dashboard)
        self.assertIn("<strong>2件</strong>", dashboard)
        self.assertIn("<h3>確認優先度</h3>", dashboard)
        self.assertIn("<h3>確認目安</h3>", dashboard)
        self.assertIn("<h3>カテゴリ</h3>", dashboard)
        self.assertLess(html.index('<div class="todays-brief">'), html.index('<section class="important-items">'))
        self.assertLess(html.index('<section class="important-items">'), html.index('<section class="dashboard">'))
        self.assertLess(html.index('<section class="dashboard">'), html.index('<div class="cards">'))
        self.assertEqual(cards_segment(html).count('class="card"'), 2)

    def test_dashboard_renders_zero_values_and_omits_zero_category_and_unknown_zero(self):
        html = fetch.build_html([
            self._make_item("only-patch", importance="高", urgency="本日確認", category="脆弱性・パッチ")
        ])
        dashboard = dashboard_segment(html)

        self.assertIn("<span>高</span><strong>1</strong>", dashboard)
        self.assertIn("<span>中</span><strong>0</strong>", dashboard)
        self.assertIn("<span>低</span><strong>0</strong>", dashboard)
        self.assertIn("<span>本日確認</span><strong>1</strong>", dashboard)
        self.assertIn("<span>今週確認</span><strong>0</strong>", dashboard)
        self.assertIn("<span>参考</span><strong>0</strong>", dashboard)
        self.assertIn("<span>脆弱性・パッチ</span><strong>1</strong>", dashboard)
        self.assertNotIn("<span>攻撃・脅威動向</span><strong>0</strong>", dashboard)
        self.assertNotIn("未判定", dashboard)

    def test_dashboard_shows_unknown_when_present_and_category_order(self):
        items = [
            self._make_item("patch", category="脆弱性・パッチ"),
            self._make_item("incident", category="インシデント"),
            self._make_item("unknown", category="不正カテゴリ", importance="不正", urgency="不正"),
        ]
        dashboard = dashboard_segment(fetch.build_html(items))
        category_part = dashboard[dashboard.index("<h3>カテゴリ</h3>"):]

        self.assertIn("<span>未判定</span><strong>1</strong>", dashboard)
        self.assertLess(category_part.index("脆弱性・パッチ"), category_part.index("インシデント"))
        self.assertLess(category_part.index("インシデント"), category_part.index("未判定"))
        self.assertNotIn("不正カテゴリ", dashboard)

    def test_empty_items_dashboard_html(self):
        html = fetch.build_html([])
        dashboard = dashboard_segment(html)

        self.assertIn("本日のダッシュボード", dashboard)
        self.assertIn("<strong>0件</strong>", dashboard)
        self.assertIn("<span>高</span><strong>0</strong>", dashboard)
        self.assertIn("<span>中</span><strong>0</strong>", dashboard)
        self.assertIn("<span>低</span><strong>0</strong>", dashboard)
        self.assertIn("<span>本日確認</span><strong>0</strong>", dashboard)
        self.assertIn("<span>今週確認</span><strong>0</strong>", dashboard)
        self.assertIn("<span>参考</span><strong>0</strong>", dashboard)
        self.assertIn("該当する記事はありません。", dashboard)
        self.assertNotIn("未判定", dashboard)

    def test_dashboard_does_not_render_reason_category_reason_or_comments(self):
        html = fetch.build_html([
            self._make_item(
                "unsafe-dashboard",
                category="<script>alert(1)</script>",
                reason="<b>reason</b>",
                category_reason="<b>category_reason</b>",
            )
        ])
        dashboard = dashboard_segment(html)

        self.assertNotIn("<script>alert(1)</script>", html)
        self.assertNotIn("&lt;script&gt;alert(1)&lt;/script&gt;", dashboard)
        self.assertNotIn("<b>reason</b>", html)
        self.assertNotIn("&lt;b&gt;reason&lt;/b&gt;", dashboard)
        self.assertNotIn("category_reason", html)
        self.assertNotIn("<!--", dashboard)
        self.assertNotIn("None", html)
        self.assertNotIn(">null<", html)

    def test_dashboard_does_not_change_existing_sections_or_links(self):
        important = self._make_item("important", importance="高", urgency="本日確認")
        ordinary = self._make_item("ordinary", importance="低", urgency="参考")
        html = fetch.build_html([important, ordinary])
        parser = parse_anchors(html)
        article_anchors = article_link_anchors(parser)

        self.assertEqual([item["title"] for item in fetch.select_important_items([important, ordinary])], ["important"])
        self.assertIn("Dashboardには表示しない判定理由", important_segment(html))
        self.assertNotIn("Dashboardには表示しない判定理由", cards_segment(html))
        self.assertEqual(cards_segment(html).count('class="card"'), 2)
        self.assertLess(cards_segment(html).index("important"), cards_segment(html).index("ordinary"))
        self.assertTrue(all(a.get("rel") == "noopener noreferrer" for a in article_anchors))
        self.assertFalse(parser.nested_anchor)

    def test_dashboard_keeps_invalid_url_unlinked(self):
        html = fetch.build_html([
            self._make_item("bad-url", link="javascript:alert(1)")
        ])

        self.assertNotIn("javascript:alert(1)", html)
        self.assertEqual(article_link_anchors(parse_anchors(html)), [])


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
        self.assertIn("本日の優先確認対象はありません。", important_segment(html))
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

    def test_full_article_order_uses_ticket10_display_order(self):
        items = [
            self._make_item("first", importance="高", urgency="今週確認"),
            self._make_item("second", importance="中", urgency="本日確認"),
            self._make_item("third", importance="低", urgency="参考"),
        ]
        html = fetch.build_html(items)
        cards = cards_segment(html)

        self.assertLess(cards.index("second"), cards.index("first"))
        self.assertLess(cards.index("first"), cards.index("third"))

    def test_important_items_section_displays_only_compact_fields(self):
        item = self._make_item("compact", importance="高", urgency="本日確認")
        html = fetch.build_html([item])
        important = important_segment(html)
        cards = cards_segment(html)

        self.assertIn("優先確認", important)
        self.assertNotIn("確認優先度 高", important)
        self.assertNotIn("確認目安 本日確認", important)
        self.assertNotIn("カテゴリ：脆弱性・パッチ", important)
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

        self.assertIn("優先確認", important_segment(html))
        self.assertIn("本日の優先確認対象はありません。", important_segment(html))
        self.assertEqual(cards_segment(html).count('class="card"'), 1)

    def test_important_item_links_use_safe_url_without_nested_anchors(self):
        item = self._make_item("linked", importance="高", urgency="本日確認")
        html = fetch.build_html([item])
        important_parser = parse_anchors(important_segment(html))
        hrefs = [a.get("href") for a in important_parser.anchors]

        self.assertEqual(hrefs, ["#article-1", "#article-1"])
        self.assertTrue(all("target" not in a for a in important_parser.anchors))
        self.assertTrue(all("rel" not in a for a in important_parser.anchors))
        self.assertFalse(parse_anchors(html).nested_anchor)

    def test_important_item_does_not_link_unsafe_url(self):
        item = self._make_item("unsafe", importance="高", urgency="本日確認")
        item["link"] = "javascript:alert(1)"
        html = fetch.build_html([item])
        important = important_segment(html)

        self.assertEqual(
            [a.get("href") for a in parse_anchors(important).anchors],
            ["#article-1", "#article-1"],
        )
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
        self.assertNotIn("&lt;b&gt;category&lt;/b&gt;", important)
        self.assertIn("&lt;b&gt;reason&lt;/b&gt;", important)
        self.assertNotIn("<b>reason</b>", html)

    def test_reason_display_rewrites_importance_label_with_ha(self):
        item = self._make_item(
            "label-high",
            importance="高",
            urgency="本日確認",
            reason="被害が大きいため、重要度は高いと判断しました。",
        )
        html = fetch.build_html([item])
        important = important_segment(html)

        self.assertIn("確認優先度は高い", important)
        self.assertNotIn("重要度は高い", important)
        self.assertEqual(item["ai_analysis"]["reason"], "被害が大きいため、重要度は高いと判断しました。")

    def test_reason_display_rewrites_importance_label_with_colon(self):
        item = self._make_item(
            "label-medium",
            importance="高",
            urgency="本日確認",
            reason="重要度：中、追加調査が必要です。",
        )
        html = fetch.build_html([item])

        self.assertIn("確認優先度：中", important_segment(html))
        self.assertNotIn("重要度：中", important_segment(html))

    def test_reason_display_rewrites_urgency_label_with_ha(self):
        item = self._make_item(
            "label-urgency",
            importance="高",
            urgency="本日確認",
            reason="緊急度は本日確認、影響範囲を確認してください。",
        )
        html = fetch.build_html([item])

        self.assertIn("確認目安は本日確認", important_segment(html))
        self.assertNotIn("緊急度は本日確認", important_segment(html))

    def test_reason_display_keeps_general_importance_phrases(self):
        item = self._make_item(
            "general-importance",
            importance="高",
            urgency="本日確認",
            reason="脆弱性の重要度と重要度の高い脆弱性を確認する必要があります。",
        )
        html = fetch.build_html([item])
        important = important_segment(html)

        self.assertIn("脆弱性の重要度", important)
        self.assertIn("重要度の高い脆弱性", important)
        self.assertNotIn("確認優先度の高い脆弱性", important)

    def test_reason_display_escaping_after_label_rewrite(self):
        item = self._make_item(
            "escaped-label",
            importance="高",
            urgency="本日確認",
            reason="重要度は高い <script>alert(1)</script>",
        )
        html = fetch.build_html([item])
        important = important_segment(html)

        self.assertIn("確認優先度は高い &lt;script&gt;alert(1)&lt;/script&gt;", important)
        self.assertNotIn("<script>alert(1)</script>", html)

    def test_anchor_structure_and_scroll_margin_are_preserved(self):
        item = self._make_item("anchor", importance="高", urgency="本日確認")
        html = fetch.build_html([item])
        important = important_segment(html)
        cards = cards_segment(html)

        self.assertIn('href="#article-1"', important)
        self.assertIn('id="article-1"', cards)
        self.assertIn("--anchor-offset:112px", html)
        self.assertIn("--anchor-offset:168px", html)
        self.assertIn("scroll-margin-top:var(--anchor-offset)", html)

    def test_important_items_section_precedes_all_cards(self):
        html = fetch.build_html([self._make_item("ordered", importance="高", urgency="本日確認")])

        self.assertLess(html.index('<section class="important-items">'), html.index('<div class="cards">'))
        self.assertIn('<meta name="viewport"', html)
        self.assertIn("article-section", html)


class VulnerabilityFactsIntegrationTest(unittest.TestCase):
    """Ticket 12a/12b: factsの扱いに関する回帰テスト。

    Ticket 12aではfactsはGeminiプロンプト・HTMLのいずれにも一切影響しなかったが、
    Ticket 12bでHTML表示(記事カードへの脆弱性情報欄)を追加したため、HTML関連の
    2件はTicket 12bの新しい期待値へ更新されている(下のVulnerabilityFactsHtml*
    クラス群を参照)。Geminiプロンプトへfactsを一切渡さないという制約(Ticket 12b
    のスコープ外事項)は本クラスの残りのテストで引き続き検証する。
    実際のCVE/NVD/KEV取得ロジック自体はtest_vulnerability_facts.pyで検証する。
    """

    def _make_item(self, **overrides):
        item = {
            "title": "テスト記事", "link": "https://example.com/article",
            "summary": "取得時の概要文", "date": datetime.datetime(2026, 7, 11, 6, 0),
            "source": "CISA", "lang": "ja",
        }
        item.update(overrides)
        return item

    def _sample_facts(self):
        return {
            "cves": [
                {
                    "cve_id": "CVE-2026-1234",
                    "nvd": {
                        "status": "found", "retrieval": "live",
                        "fetched_at": "2026-07-12T01:00:00Z",
                        "url": "https://nvd.nist.gov/vuln/detail/CVE-2026-1234",
                        "vuln_status": "Analyzed", "published_at": "2026-07-10T00:00:00Z",
                        "last_modified_at": "2026-07-11T00:00:00Z",
                        "cvss": {"version": "3.1", "base_score": 9.8, "base_severity": "CRITICAL",
                                  "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                  "source": "nvd@nist.gov", "type": "Primary"},
                    },
                    "kev": {"status": "listed", "retrieval": "live",
                            "fetched_at": "2026-07-12T01:00:00Z", "date_added": "2026-07-11"},
                }
            ]
        }

    def test_html_without_facts_key_omits_vulnerability_section(self):
        # Ticket 12b: factsキーが無い記事(過去のdaily JSON互換)では、脆弱性情報欄
        # 自体が出力されないことを確認する(Ticket 12bで挙動が意図的に変わった点)。
        item_without = self._make_item()
        html_without = fetch.build_html([item_without])
        self.assertNotIn('class="vulnerability-facts"', html_without)

    def test_html_renders_cve_cvss_kev_when_facts_present(self):
        # Ticket 12b: factsが有効なCVEを含む場合、記事カードへCVE ID・CVSS・
        # KEV掲載表示を追加する(Ticket 12aでは非表示だったが、Ticket 12bで
        # 表示専用機能として意図的に反転した)。
        item = self._make_item(facts=self._sample_facts())
        html = fetch.build_html([item])
        for needle in (
            "CVE-2026-1234", "CVSS 9.8 / Critical", "v3.1", "NVD", "CISA KEV掲載",
            "https://nvd.nist.gov/vuln/detail/CVE-2026-1234",
        ):
            self.assertIn(needle, html)
        # 内部取得状態・生JSON構造由来の文字列は表示しない(Ticket 12b #11)。
        for internal_needle in ("live", "fetched_at", "\"nvd\"", "\"kev\"", "\"cve_id\""):
            self.assertNotIn(internal_needle, html)

    def test_gemini_prompt_does_not_reference_facts(self):
        # enrich_with_ai()が生成する記事分析プロンプトの入力テキストに、
        # facts由来の情報(CVE ID・CVSS・KEV)が含まれないことを確認する。
        # (gemini_analyze()の呼び出し自体はモックしない: プロンプト組み立てに
        # 使うテキストがitem["facts"]を一切参照していないことをソース側で確認する)
        import inspect
        source = inspect.getsource(fetch.enrich_with_ai)
        self.assertNotIn("facts", source)
        self.assertNotIn("cvss", source.lower())

    def test_collect_recent_no_longer_calls_gemini_enrichment_internally(self):
        # Ticket 12a: enrich_with_ai()はcollect_recent()から分離され、main()側で
        # facts取得の後に明示的に呼び出す設計になっている。
        import inspect
        source = inspect.getsource(fetch.collect_recent)
        self.assertNotIn("enrich_with_ai(", source)

    def test_gemini_request_body_does_not_leak_facts_data(self):
        # ソースコード上の静的確認(test_gemini_prompt_does_not_reference_facts)に
        # 加え、enrich_with_ai()が実際にGeminiへ送信するリクエストボディ(prompt
        # 本文を含む)を動的にキャプチャし、item["facts"]に混入させたCVE ID・
        # CVSS・KEV情報が漏れていないことを直接検証する。
        item = self._make_item(facts=self._sample_facts())
        item["raw_title"] = item["title"]
        item["raw_summary"] = item["summary"]

        captured = []

        def fake_urlopen(req, timeout=None):
            captured.append(req)
            analysis = {
                "category": "脆弱性・パッチ", "category_reason": "テスト理由",
                "importance": "中", "urgency": "参考",
                "summary": "テスト要約です。", "financial_impact": "テスト影響です。",
                "recommended_actions": [], "reason": "テスト理由です。", "tags": [],
            }
            body = json.dumps({
                "candidates": [{"content": {"parts": [{"text": json.dumps(analysis, ensure_ascii=False)}]}}]
            }).encode("utf-8")

            class FakeResponse:
                def read(self_inner):
                    return body

                def __enter__(self_inner):
                    return self_inner

                def __exit__(self_inner, *a):
                    return False

            return FakeResponse()

        with patch.dict(os.environ, {"GEMINI_API_KEY": "test-key-not-real"}):
            with patch("fetch.urllib.request.urlopen", side_effect=fake_urlopen):
                with patch("fetch.time.sleep"):
                    fetch.enrich_with_ai([item])

        self.assertEqual(len(captured), 1)
        sent_body = captured[0].data.decode("utf-8")
        sent_body_lower = sent_body.lower()

        # "facts"/"cves"はTicket 12aのJSON構造フィールド名であり、記事分析
        # プロンプトの固定文言には一切登場しない語のため、単純な部分一致で
        # 判定してよい。
        self.assertNotIn("facts", sent_body_lower)
        self.assertNotIn("cves", sent_body_lower)

        # "cvss"/"kev"は、記事分析プロンプトの固定文言(カテゴリ定義・importance
        # 判定の禁止事項)が一般語彙として元々使用しているため、語の有無ではなく、
        # item["facts"]に埋め込んだ具体的な値(CVE ID・スコア・重大度・NVD詳細
        # URL・ベクター文字列・KEV追加日)が実際に送信されていないことを確認する。
        for leaked_value in (
            "CVE-2026-1234", "9.8", "CRITICAL", "nvd.nist.gov/vuln/detail",
            "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "2026-07-11",
        ):
            self.assertNotIn(leaked_value, sent_body, f"{leaked_value!r} leaked into Gemini request body")

    def test_todays_brief_request_body_does_not_leak_facts_data(self):
        # Ticket 12a-review: Today's Brief生成(build_todays_brief() →
        # gemini_todays_brief())へもfactsを一切渡さないことを動的に確認する。
        # "cvss"/"kev"という語自体の有無ではなく(既存プロンプトが一般語彙として
        # 使用しているため)、item["facts"]に埋め込んだ一意なマーカー値が実際に
        # 送信されていないことを直接検証する。
        unique_cve = "CVE-2099-999999"
        unique_score = 9.7
        unique_severity = "CRITICAL-UNIQUE-FACTS-MARKER"
        unique_vector = "CVSS:4.0/UNIQUE-FACTS-MARKER"
        unique_url = "https://nvd.nist.gov/vuln/detail/CVE-2099-999999"
        unique_date_added = "2099-12-31"

        # Today's Briefの入力選定条件(analysis.statusがsuccess/fallbackで、
        # 利用可能なai_analysisを持つ)を満たす有効な記事として構成する。
        item = {
            "title": "テスト記事", "source": "CISA",
            "ai_analysis": {
                "category": "脆弱性・パッチ", "importance": "高", "urgency": "本日確認",
                "summary": "テスト要約文です。", "financial_impact": "テスト影響文です。",
                "recommended_actions": ["UNIQUE-RECOMMENDED-ACTION-MARKER"],
                "reason": "テスト理由文です。", "tags": ["KEV"],
            },
            "ai_analysis_meta": {
                "status": "success", "error_type": None, "http_status": None,
                "generated_at": "2026-07-11T07:00:00+09:00",
            },
            "facts": {"cves": [{
                "cve_id": unique_cve,
                "nvd": {
                    "status": "found", "retrieval": "live", "fetched_at": "2026-07-12T00:00:00Z",
                    "url": unique_url, "vuln_status": "Analyzed",
                    "published_at": "2026-07-01T00:00:00Z", "last_modified_at": "2026-07-02T00:00:00Z",
                    "cvss": {"version": "4.0", "base_score": unique_score,
                             "base_severity": unique_severity, "vector": unique_vector,
                             "source": "nvd@nist.gov", "type": "Primary"},
                },
                "kev": {"status": "listed", "retrieval": "live",
                        "fetched_at": "2026-07-12T00:00:00Z", "date_added": unique_date_added},
            }]},
        }

        captured = []

        def fake_urlopen(req, timeout=None):
            captured.append(req)
            brief_response = {
                "overview": "本日は脆弱性関連の情報が中心の一日でした。金融機関への影響確認が望まれる内容です。",
                "important_highlights": ["重要なハイライトのテスト文です。"],
                "discussion_points": ["注目論点のテスト文です。"],
                "check_items": ["確認事項のテスト文です。"],
            }
            body = json.dumps({
                "candidates": [{"content": {"parts": [{"text": json.dumps(brief_response, ensure_ascii=False)}]}}]
            }).encode("utf-8")

            class FakeResponse:
                def read(self_inner):
                    return body

                def __enter__(self_inner):
                    return self_inner

                def __exit__(self_inner, *a):
                    return False

            return FakeResponse()

        with patch.dict(os.environ, {"GEMINI_API_KEY": "test-key-not-real"}):
            with patch("fetch.urllib.request.urlopen", side_effect=fake_urlopen):
                with patch("fetch.time.sleep"):
                    result = fetch.build_todays_brief([item])

        # Today's Briefのリクエストが実際に発生したことを確認する
        self.assertEqual(len(captured), 1)
        self.assertEqual(result["status"], "success")

        sent_body = captured[0].data.decode("utf-8")
        # json.dumps()はデフォルトで非ASCII文字を\uXXXXへエスケープするため、
        # 日本語部分文字列の検証はデコード後のプロンプト本文に対して行う。
        sent_prompt_text = json.loads(sent_body)["contents"][0]["parts"][0]["text"]

        # 記事分析結果として必要な情報(ai_analysis由来)は含まれることを確認する
        self.assertIn("UNIQUE-RECOMMENDED-ACTION-MARKER", sent_body)
        self.assertIn("テスト要約文です。", sent_prompt_text)

        # item["facts"]内の固有値は1つも含まれないことを確認する
        for leaked_value in (
            unique_cve, str(unique_score), unique_severity, unique_vector,
            unique_url, unique_date_added,
        ):
            self.assertNotIn(
                leaked_value, sent_body,
                f"{leaked_value!r} leaked into Today's Brief request body",
            )

    def test_facts_extraction_uses_raw_snapshot_fields_not_mutated_title(self):
        # 注意: このテストは実際のfetch.main()を呼び出さない。main()の処理順
        # (collect_recent → raw_title/raw_summaryスナップショット →
        # build_facts_for_items → enrich_with_ai → build_todays_brief)自体は
        # fetch.pyの実装(main()のソース差分)で直接確認済みであり、ここでは
        # その順序が要求する契約——build_facts_for_items()呼び出し時点で
        # raw_title/raw_summaryが記事に存在し、CVE抽出がそれらraw値だけを見て
        # 翻訳後のtitle書き換えに影響されないこと、facts設定後もenrich_with_ai()
        # が問題なく動作すること——を単体テストとして検証する。
        item = {
            "title": "CVE-2026-4321 disclosed", "summary": "raw summary, no markers here",
            "link": "https://example.com/a", "source": "CISA", "lang": "en",
            "date": None,
        }
        items = [item]

        # main()のraw_title/raw_summaryスナップショット処理と同じ内容を再現する
        # (main()自体は呼び出していない)。
        for it in items:
            it["raw_title"] = it["title"]
            it["raw_summary"] = it["summary"]

        # build_facts_for_items()呼び出し時点で両フィールドが存在することを確認
        self.assertIn("raw_title", items[0])
        self.assertIn("raw_summary", items[0])

        with tempfile.TemporaryDirectory() as tmp:
            cache_path = Path(tmp) / "cache.json"

            def fake_urlopen(req, timeout=None):
                body = json.dumps({"vulnerabilities": []}).encode("utf-8")

                class FakeResponse:
                    def read(self_inner):
                        return body

                    def __enter__(self_inner):
                        return self_inner

                    def __exit__(self_inner, *a):
                        return False

                return FakeResponse()

            vf.build_facts_for_items(
                items, cache_path=cache_path, urlopen_fn=fake_urlopen, sleep_fn=lambda s: None,
            )

        # 翻訳等でtitleが書き換わった後でも、既に確定したfactsは変化しない
        # (extract_cve_ids_for_items()はraw_title/raw_summaryだけを見るため)。
        self.assertEqual(len(items[0]["facts"]["cves"]), 1)
        self.assertEqual(items[0]["facts"]["cves"][0]["cve_id"], "CVE-2026-4321")

        items[0]["title"] = "翻訳後のタイトル(CVEの記載なし)"
        self.assertEqual(items[0]["facts"]["cves"][0]["cve_id"], "CVE-2026-4321")

        # enrich_with_ai()がfacts取得の後でも問題なく呼び出せる(факtsが記事
        # オブジェクトの構造を壊していない)ことを確認する。
        with patch.dict(os.environ, {}, clear=True):  # GEMINI_API_KEYなし
            result_items = fetch.enrich_with_ai(items)
        self.assertIs(result_items, items)
        self.assertEqual(result_items[0]["facts"]["cves"][0]["cve_id"], "CVE-2026-4321")

    def test_fetch_cisa_kev_behavior_preserved_via_shared_catalog_memo(self):
        # Ticket 12a: fetch_cisa_kev()はvulnerability_facts.load_kev_catalog()経由の
        # 共有ローダーへ委譲するよう変更されたが、既存の記事構築ロジック
        # (cutoffフィルタ・dateAdded降順ソート・display_url使用)は変わらない。
        memo = {
            "https://x/kev.json": ([
                {"cveID": "CVE-2026-0001", "vulnerabilityName": "Test Vuln 1",
                 "shortDescription": "desc1", "dateAdded": "2026-07-11"},
                {"cveID": "CVE-2026-0002", "vulnerabilityName": "Test Vuln 2",
                 "shortDescription": "desc2", "dateAdded": "2026-07-10"},
                {"cveID": "CVE-2026-0003", "vulnerabilityName": "Old Vuln",
                 "shortDescription": "desc3", "dateAdded": "2020-01-01"},
            ], True)
        }
        cutoff = datetime.datetime(2026, 7, 1)
        items = fetch.fetch_cisa_kev(
            cutoff, "https://x/kev.json", "https://display/kev", "CISA KEV", kev_catalog_memo=memo,
        )
        self.assertEqual(len(items), 2)  # cutoffより古い2020年分は除外
        self.assertTrue(items[0]["title"].startswith("CVE-2026-0001"))  # dateAdded降順
        self.assertTrue(all(it["link"] == "https://display/kev" for it in items))

    def test_kev_catalog_memo_prevents_double_download_in_one_run(self):
        # 既存のKEVニュース収集(fetch_cisa_kev)とTicket 12aのfacts取得
        # (vulnerability_facts.load_kev_catalog)が、同一run内で同じmemo dictを
        # 共有すればHTTPリクエストが1回だけになることを確認する。
        calls = []

        class FakeResponse:
            def __init__(self, body):
                self._body = body

            def read(self):
                return self._body

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        def fake_urlopen(req, timeout=None):
            calls.append(req)
            body = json.dumps({"vulnerabilities": [
                {"cveID": "CVE-2026-0001", "dateAdded": "2026-07-11"},
            ]}).encode("utf-8")
            return FakeResponse(body)

        memo = {}
        vf.load_kev_catalog("https://x/kev.json", memo=memo, urlopen_fn=fake_urlopen)
        vf.load_kev_catalog("https://x/kev.json", memo=memo, urlopen_fn=fake_urlopen)
        self.assertEqual(len(calls), 1)

    def test_fetch_cisa_kev_skips_entries_with_unparseable_date_added(self):
        # Ticket 12a-review #3: dateAdded欠落・解析不能な要素は記事化しない。
        # None/文字列混在でのソート(key=lambda x: x.get("dateAdded") or "")が
        # 例外を出さないことも合わせて確認する。
        memo = {
            "https://x/kev.json": ([
                {"cveID": "CVE-2026-0001", "vulnerabilityName": "Good Vuln",
                 "shortDescription": "d1", "dateAdded": "2026-07-11"},
                {"cveID": "CVE-2026-0002", "vulnerabilityName": "Bad Date Vuln",
                 "shortDescription": "d2", "dateAdded": None},
            ], True)
        }
        cutoff = datetime.datetime(2026, 7, 1)
        items = fetch.fetch_cisa_kev(
            cutoff, "https://x/kev.json", "https://display/kev", "CISA KEV", kev_catalog_memo=memo,
        )
        self.assertEqual(len(items), 1)
        self.assertTrue(items[0]["title"].startswith("CVE-2026-0001"))


class VulnerabilityFactsHelperFunctionTest(unittest.TestCase):
    """Ticket 12b: 記事カードへの脆弱性情報表示で使う個別ヘルパーの単体テスト。"""

    def test_cve_id_is_normalized_stripped_and_uppercased(self):
        self.assertEqual(fetch._display_cve_id(" cve-2026-1234 "), "CVE-2026-1234")

    def test_cve_id_rejects_three_digit_sequence(self):
        self.assertIsNone(fetch._display_cve_id("CVE-2026-123"))

    def test_cve_id_rejects_non_cve_string(self):
        self.assertIsNone(fetch._display_cve_id("NOT-A-CVE"))

    def test_cve_id_rejects_non_string_types(self):
        self.assertIsNone(fetch._display_cve_id(None))
        self.assertIsNone(fetch._display_cve_id(12345))
        self.assertIsNone(fetch._display_cve_id(["CVE-2026-1234"]))

    def test_score_formats_to_one_decimal_place(self):
        self.assertEqual(fetch._display_cvss_score(9.8), "9.8")
        self.assertEqual(fetch._display_cvss_score(7), "7.0")
        self.assertEqual(fetch._display_cvss_score(4.3), "4.3")
        self.assertEqual(fetch._display_cvss_score(0), "0.0")
        self.assertEqual(fetch._display_cvss_score(10), "10.0")

    def test_score_rejects_out_of_range(self):
        self.assertIsNone(fetch._display_cvss_score(-0.1))
        self.assertIsNone(fetch._display_cvss_score(10.1))

    def test_score_rejects_huge_integers_without_overflow_error(self):
        # Ticket 12b-review: math.isfinite()はint(任意精度)に対して
        # OverflowErrorを送出しうるため、float型のみへ適用する。
        self.assertIsNone(fetch._display_cvss_score(10**1000))
        self.assertIsNone(fetch._display_cvss_score(-(10**1000)))

    def test_score_rejects_nan_and_infinity(self):
        self.assertIsNone(fetch._display_cvss_score(float("nan")))
        self.assertIsNone(fetch._display_cvss_score(float("inf")))
        self.assertIsNone(fetch._display_cvss_score(float("-inf")))

    def test_score_rejects_non_numeric_and_bool(self):
        self.assertIsNone(fetch._display_cvss_score("9.8"))
        self.assertIsNone(fetch._display_cvss_score(None))
        self.assertIsNone(fetch._display_cvss_score(True))
        self.assertIsNone(fetch._display_cvss_score(False))

    def test_severity_normalizes_known_values_case_insensitively(self):
        self.assertEqual(fetch._display_cvss_severity("CRITICAL"), "Critical")
        self.assertEqual(fetch._display_cvss_severity("high"), "High")
        self.assertEqual(fetch._display_cvss_severity("Medium"), "Medium")
        self.assertEqual(fetch._display_cvss_severity("low"), "Low")
        self.assertEqual(fetch._display_cvss_severity("none"), "None")

    def test_severity_rejects_unknown_values(self):
        self.assertIsNone(fetch._display_cvss_severity("SUPER_CRITICAL"))
        self.assertIsNone(fetch._display_cvss_severity(None))
        self.assertIsNone(fetch._display_cvss_severity(123))

    def test_version_normalizes_and_prevents_double_v_prefix(self):
        self.assertEqual(fetch._display_cvss_version("3.1"), "v3.1")
        self.assertEqual(fetch._display_cvss_version("v3.1"), "v3.1")
        self.assertEqual(fetch._display_cvss_version("V4.0"), "v4.0")

    def test_version_rejects_invalid_values(self):
        self.assertIsNone(fetch._display_cvss_version("<script>"))
        self.assertIsNone(fetch._display_cvss_version(""))
        self.assertIsNone(fetch._display_cvss_version(None))

    def test_version_is_limited_to_ticket12a_allowed_values(self):
        # Ticket 12b-review #3: vulnerability_facts.CVSS_VERSION_PRIORITYに
        # 無い値(選択ロジック上あり得ない値)は、数値形式として妥当に見えても
        # 表示しない。
        self.assertEqual(fetch._display_cvss_version("3.1"), "v3.1")
        self.assertEqual(fetch._display_cvss_version("v3.1"), "v3.1")
        self.assertEqual(fetch._display_cvss_version("V4.0"), "v4.0")
        self.assertIsNone(fetch._display_cvss_version("999.9"))
        self.assertIsNone(fetch._display_cvss_version("3.2"))
        self.assertIsNone(fetch._display_cvss_version("<script>"))
        self.assertIsNone(fetch._display_cvss_version(3.1))  # 数値型は文字列ではないため不正

    def test_invalid_version_does_not_hide_valid_score_or_provider(self):
        cvss = {"base_score": 7.5, "base_severity": "HIGH", "version": "999.9", "source": "nvd@nist.gov"}
        self.assertEqual(fetch._render_cvss_text(cvss), "CVSS 7.5 / High（NVD）")

    def test_provider_nvd_is_case_insensitive(self):
        self.assertEqual(fetch._display_cvss_provider("nvd@nist.gov"), "NVD")
        self.assertEqual(fetch._display_cvss_provider("NVD@NIST.GOV"), "NVD")

    def test_provider_other_source_becomes_other_organization(self):
        # Ticket 12b-review: 非NVDのsourceはCNAとは限らない(CISA-ADP等も
        # 含みうる)ため、一律「他機関」とする。
        self.assertEqual(fetch._display_cvss_provider("cve@mitre.org"), "他機関")
        self.assertEqual(fetch._display_cvss_provider("some-vendor@example.com"), "他機関")

    def test_provider_empty_or_invalid_is_omitted(self):
        self.assertIsNone(fetch._display_cvss_provider(""))
        self.assertIsNone(fetch._display_cvss_provider(None))
        self.assertIsNone(fetch._display_cvss_provider(123))

    def test_cvss_text_unassessed_when_cvss_missing(self):
        self.assertEqual(fetch._render_cvss_text(None), "CVSS未評価")
        self.assertEqual(fetch._render_cvss_text({}), "CVSS未評価")

    def test_cvss_text_full_combination(self):
        cvss = {"base_score": 9.8, "base_severity": "CRITICAL", "version": "3.1", "source": "nvd@nist.gov"}
        self.assertEqual(fetch._render_cvss_text(cvss), "CVSS 9.8 / Critical（v3.1・NVD）")

    def test_cvss_text_omits_missing_severity(self):
        cvss = {"base_score": 7.5, "base_severity": None, "version": "3.1", "source": "nvd@nist.gov"}
        self.assertEqual(fetch._render_cvss_text(cvss), "CVSS 7.5（v3.1・NVD）")

    def test_cvss_text_version_only(self):
        cvss = {"base_score": 8.7, "base_severity": "HIGH", "version": "4.0", "source": ""}
        self.assertEqual(fetch._render_cvss_text(cvss), "CVSS 8.7 / High（v4.0）")

    def test_cvss_text_provider_only(self):
        cvss = {"base_score": 8.7, "base_severity": "HIGH", "version": None, "source": "cve@mitre.org"}
        self.assertEqual(fetch._render_cvss_text(cvss), "CVSS 8.7 / High（他機関）")


class VulnerabilityFactsHtmlRenderTest(unittest.TestCase):
    """Ticket 12b: 記事カードの脆弱性情報欄のHTML描画テスト(#18の必須ケース)。"""

    def _make_item(self, **overrides):
        item = {
            "title": "テスト記事", "link": "https://example.com/article",
            "summary": "取得時の概要文", "date": datetime.datetime(2026, 7, 11, 6, 0),
            "source": "CISA", "lang": "ja",
        }
        item.update(overrides)
        return item

    def _sample_facts(self):
        return {
            "cves": [
                {
                    "cve_id": "CVE-2026-1234",
                    "nvd": {
                        "status": "found", "retrieval": "live",
                        "fetched_at": "2026-07-12T01:00:00Z",
                        "url": "https://nvd.nist.gov/vuln/detail/CVE-2026-1234",
                        "vuln_status": "Analyzed", "published_at": "2026-07-10T00:00:00Z",
                        "last_modified_at": "2026-07-11T00:00:00Z",
                        "cvss": {"version": "3.1", "base_score": 9.8, "base_severity": "CRITICAL",
                                  "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                  "source": "nvd@nist.gov", "type": "Primary"},
                    },
                    "kev": {"status": "listed", "retrieval": "live",
                            "fetched_at": "2026-07-12T01:00:00Z", "date_added": "2026-07-11"},
                }
            ]
        }

    # 18.1 factsなし
    def test_no_facts_key_renders_no_section_no_exception(self):
        item = self._make_item()
        self.assertNotIn("facts", item)
        html = fetch.build_html([item])
        self.assertNotIn('class="vulnerability-facts"', html)

    # 18.2 CVE空配列
    def test_empty_cves_array_renders_no_section_and_no_extra_blank(self):
        item_no_facts = self._make_item()
        item_empty_cves = self._make_item(facts={"cves": []})
        html_no_facts = fetch.build_html([item_no_facts])
        html_empty_cves = fetch.build_html([item_empty_cves])
        # 空配列は「facts自体が無い」場合とバイト単位で同一になるべき
        # (余分な余白・空枠が一切追加されない)。
        self.assertEqual(html_no_facts, html_empty_cves)
        self.assertNotIn('class="vulnerability-facts"', html_empty_cves)

    # 18.3 CVE1件・NVD・CVSS・KEV掲載
    def test_single_cve_nvd_cvss_kev_listed(self):
        item = self._make_item(facts=self._sample_facts())
        html = fetch.build_html([item])
        self.assertIn(
            '<a class="vulnerability-cve-link" '
            'href="https://nvd.nist.gov/vuln/detail/CVE-2026-1234" '
            'target="_blank" rel="noopener noreferrer">CVE-2026-1234</a>',
            html,
        )
        self.assertIn("CVSS 9.8 / Critical（v3.1・NVD）", html)
        self.assertIn('<span class="kev-badge">CISA KEV掲載</span>', html)
        self.assertIn("脆弱性情報", html)

    # 18.4 CVE1件・他機関(非NVD)・KEV非掲載
    def test_single_cve_other_organization_kev_not_listed(self):
        facts = {"cves": [{
            "cve_id": "CVE-2026-5678",
            "nvd": {
                "status": "found", "retrieval": "live", "fetched_at": "2026-07-12T01:00:00Z",
                "url": "https://nvd.nist.gov/vuln/detail/CVE-2026-5678",
                "vuln_status": "Analyzed", "published_at": None, "last_modified_at": None,
                "cvss": {"version": "4.0", "base_score": 8.7, "base_severity": "HIGH",
                          "vector": "x", "source": "cve@mitre.org", "type": "Secondary"},
            },
            "kev": {"status": "not_listed", "retrieval": "live",
                    "fetched_at": "2026-07-12T01:00:00Z", "date_added": None},
        }]}
        item = self._make_item(facts=facts)
        html = fetch.build_html([item])
        self.assertIn("CVSS 8.7 / High（v4.0・他機関）", html)
        self.assertNotIn("KEV非掲載", html)
        self.assertNotIn("not_listed", html)
        self.assertNotIn("cve@mitre.org", html)
        self.assertNotIn("CISA KEV掲載", html)
        self.assertNotIn('class="kev-badge"', html)

    # 18.5 CVSSなし
    def test_no_cvss_shows_unassessed_label_only(self):
        facts = {"cves": [{
            "cve_id": "CVE-2026-0001",
            "nvd": {"status": "not_found", "retrieval": "live", "fetched_at": "2026-07-12T01:00:00Z",
                    "url": "https://nvd.nist.gov/vuln/detail/CVE-2026-0001",
                    "vuln_status": None, "published_at": None, "last_modified_at": None, "cvss": None},
            "kev": {"status": "not_listed", "retrieval": "live",
                    "fetched_at": "2026-07-12T01:00:00Z", "date_added": None},
        }]}
        item = self._make_item(facts=facts)
        html = fetch.build_html([item])
        self.assertIn("CVSS未評価", html)
        self.assertNotIn("not_found", html)

    # 18.6 NVD unavailable
    def test_nvd_unavailable_shows_cve_id_and_unassessed_not_internal_state(self):
        facts = {"cves": [{
            "cve_id": "CVE-2026-0002",
            "nvd": {"status": "unavailable", "retrieval": "unavailable", "fetched_at": None,
                    "url": "https://nvd.nist.gov/vuln/detail/CVE-2026-0002",
                    "vuln_status": None, "published_at": None, "last_modified_at": None, "cvss": None},
            "kev": {"status": "unknown", "retrieval": "unavailable", "fetched_at": None, "date_added": None},
        }]}
        item = self._make_item(facts=facts)
        html = fetch.build_html([item])
        self.assertIn("CVE-2026-0002", html)
        self.assertIn("CVSS未評価", html)
        self.assertNotIn("unavailable", html)
        # "unknown"は既存CSS(.importance-unknown/.urgency-unknown)にも含まれる
        # ため、KEVバッジ自体が出力されないこと(status="unknown"はlisted以外
        # 一切表示しない)で内部状態の非表示を確認する。
        self.assertNotIn('class="kev-badge"', html)

    # 18.7 複数CVE
    def test_multiple_cves_all_shown_in_order_with_correct_count(self):
        cves = [
            {"cve_id": "CVE-2026-1001",
             "nvd": {"cvss": {"version": "3.1", "base_score": 9.8, "base_severity": "CRITICAL",
                               "source": "nvd@nist.gov"}},
             "kev": {"status": "listed"}},
            {"cve_id": "CVE-2026-1002",
             "nvd": {"cvss": {"version": "4.0", "base_score": 8.7, "base_severity": "HIGH",
                               "source": "cve@mitre.org"}},
             "kev": {"status": "not_listed"}},
            {"cve_id": "CVE-2026-1003",
             "nvd": {"cvss": {"version": "3.0", "base_score": 5.4, "base_severity": "MEDIUM",
                               "source": "nvd@nist.gov"}},
             "kev": {"status": "unknown"}},
            {"cve_id": "CVE-2026-1004",
             "nvd": {"cvss": {"version": "2.0", "base_score": 3.9, "base_severity": "LOW",
                               "source": "cve@example.org"}},
             "kev": {"status": "not_listed"}},
            {"cve_id": "CVE-2026-1005", "nvd": {"cvss": None}, "kev": {"status": "listed"}},
            {"cve_id": "CVE-2026-1006",
             "nvd": {"cvss": {"version": "3.1", "base_score": 0.0, "base_severity": "NONE",
                               "source": "nvd@nist.gov"}},
             "kev": {"status": "unknown"}},
            {"cve_id": "CVE-2026-1007",
             "nvd": {"cvss": {"version": "3.1", "base_score": 7.5, "base_severity": None, "source": ""}},
             "kev": {"status": "not_listed"}},
        ]
        item = self._make_item(facts={"cves": cves})
        html = fetch.build_html([item])

        self.assertIn("脆弱性情報（7件）", html)
        positions = [html.index(c["cve_id"]) for c in cves]
        self.assertEqual(positions, sorted(positions))  # JSON順を維持
        self.assertIn("CVSS 0.0 / None（v3.1・NVD）", html)
        self.assertIn("CVSS 7.5", html)
        self.assertIn("CVSS未評価", html)  # CVE-2026-1005分

    # 18.8 不正データ
    def test_malformed_entries_excluded_valid_ones_survive(self):
        cves = [
            {"cve_id": "NOT-A-CVE", "nvd": {}, "kev": {}},
            None,
            "just-a-string",
            {"cve_id": "CVE-2026-2001",
             "nvd": {"cvss": {"version": "3.1", "base_score": "not-a-number",
                               "base_severity": "CRITICAL", "source": "nvd@nist.gov"}}, "kev": {}},
            {"cve_id": "CVE-2026-2002",
             "nvd": {"cvss": {"version": "3.1", "base_score": 9999,
                               "base_severity": "WEIRD_VALUE", "source": "nvd@nist.gov"}}, "kev": {}},
            {"cve_id": "CVE-2026-2003",
             "nvd": {"cvss": {"version": "3.1", "base_score": float("nan"),
                               "base_severity": "HIGH", "source": "nvd@nist.gov"}}, "kev": {}},
            {"cve_id": "CVE-2026-2004",
             "nvd": {"cvss": {"version": "3.1", "base_score": 7.1, "base_severity": "HIGH",
                               "source": "nvd@nist.gov"}},
             "kev": {"status": "listed"}},
        ]
        item = self._make_item(facts={"cves": cves})
        html = fetch.build_html([item])

        self.assertNotIn("NOT-A-CVE", html)
        self.assertNotIn("just-a-string", html)
        self.assertIn("CVE-2026-2001", html)
        self.assertIn("CVE-2026-2002", html)
        self.assertIn("CVE-2026-2003", html)
        self.assertNotIn("WEIRD_VALUE", html)
        self.assertNotIn("9999", html)
        self.assertNotIn("nan", html.lower())
        self.assertIn("CVE-2026-2004", html)
        self.assertIn("CISA KEV掲載", html)
        self.assertIn("脆弱性情報（4件）", html)

    # 18.9 HTMLインジェクション
    def test_html_injection_payloads_excluded_valid_entry_still_shown(self):
        cves = [
            {"cve_id": "<script>alert(1)</script>", "nvd": {}, "kev": {}},
            {"cve_id": 'CVE-2026-3001"><script>alert(1)</script>', "nvd": {}, "kev": {}},
            {"cve_id": "javascript:alert(1)//CVE-2026-3002", "nvd": {}, "kev": {}},
            {"cve_id": "CVE-2026-3003",
             "nvd": {"cvss": {"version": "3.1", "base_score": 6.5, "base_severity": "MEDIUM",
                               "source": "nvd@nist.gov"}},
             "kev": {"status": "listed"}},
        ]
        item = self._make_item(facts={"cves": cves})
        html = fetch.build_html([item])

        self.assertNotIn("<script>", html)
        self.assertNotIn("javascript:", html)
        self.assertNotIn("alert(1)", html)
        self.assertIn("CVE-2026-3003", html)
        # 有効なCVEは1件のみ生き残るため、件数表示は付かない(#6: 1件の場合は
        # 「脆弱性情報」のみ)。
        self.assertIn('<h3 class="vulnerability-facts-title">脆弱性情報</h3>', html)

    # 18.10 トップページ・アーカイブ
    def test_top_page_and_archive_both_render_vulnerability_facts(self):
        item = self._make_item(facts=self._sample_facts())
        top_html = fetch.build_html([item])
        self.assertIn('class="vulnerability-facts"', top_html)
        self.assertIn("CVE-2026-1234", top_html)

        digest = {
            "digest_date": "2026-07-12",
            "generated_at": "2026-07-12T07:00:00+09:00",
            "items": [{
                "id": "sha256:test",
                "title": item["title"], "raw_title": item["title"],
                "url": item["link"],
                "source_name": item["source"], "language": item["lang"],
                "published_at": "2026-07-11T06:00:00+09:00",
                "analysis": {"status": "not_attempted"},
                "facts": self._sample_facts(),
            }],
        }
        archive_html = fetch.build_daily_archive_html(digest)
        self.assertIn('class="vulnerability-facts"', archive_html)
        self.assertIn("CVE-2026-1234", archive_html)

    # 18.11 生JSON非露出
    def test_raw_json_structure_not_exposed(self):
        item = self._make_item(facts=self._sample_facts())
        html = fetch.build_html([item])
        for needle in ('"facts":', '"nvd":', '"kev":', '"cve_id"', '"cache_fresh"', '"cache_stale"'):
            self.assertNotIn(needle, html)
        # CVE IDの表示文字列そのものは許容する
        self.assertIn("CVE-2026-1234", html)

    # Ticket 12b-review #1: 巨大整数スコアでbuild_html()が例外を出さないこと
    def test_huge_integer_score_does_not_raise_and_shows_unassessed(self):
        facts = {"cves": [{
            "cve_id": "CVE-2026-4001",
            "nvd": {"cvss": {"version": "3.1", "base_score": 10**1000,
                              "base_severity": "CRITICAL", "source": "nvd@nist.gov"}},
            "kev": {},
        }]}
        item = self._make_item(facts=facts)
        html = fetch.build_html([item])  # 例外が出なければOK
        self.assertIn("CVE-2026-4001", html)
        self.assertIn("CVSS未評価", html)

    # Ticket 12b-review #4: 不正なfacts型全般
    def test_malformed_facts_types_render_nothing_without_exception(self):
        malformed_facts_values = [
            None,
            [],
            "invalid",
            {"cves": None},
            {"cves": {}},
            {"cves": "invalid"},
        ]
        for facts_value in malformed_facts_values:
            with self.subTest(facts=facts_value):
                item = self._make_item(facts=facts_value)
                html = fetch.build_html([item])  # 例外が出なければOK
                self.assertNotIn('class="vulnerability-facts"', html)
                self.assertNotIn('class="vulnerability-facts-title"', html)

    # Ticket 12b-review #5: 挿入位置の固定
    def test_facts_position_between_summary_and_financial_impact(self):
        item = self._make_item(
            facts=self._sample_facts(),
            ai_analysis={
                "status": "success", "importance": "高", "urgency": "本日確認",
                "category": "脆弱性・パッチ", "category_reason": "x", "tags": [],
                "summary": "何が起きたの本文", "financial_impact": "なぜ金融機関に関係するの本文",
                "recommended_actions": ["確認すべきことの項目1"], "reason": "x",
            },
        )
        html = fetch.build_html([item])
        self.assertLess(html.index("何が起きた"), html.index("脆弱性情報"))
        self.assertLess(html.index("脆弱性情報"), html.index("なぜ金融機関に関係する"))
        self.assertLess(html.index("なぜ金融機関に関係する"), html.index("確認すべきこと"))

    def test_facts_position_after_raw_summary_when_no_analysis(self):
        item = self._make_item(facts=self._sample_facts())  # ai_analysis無し
        html = fetch.build_html([item])
        self.assertLess(html.index("取得時の概要文"), html.index("脆弱性情報"))


class KevUrlFromSourceDefinitionsTest(unittest.TestCase):
    def test_kev_url_matches_source_definition_and_prevents_double_download(self):
        # Ticket 12a-review #5: main()はKEV URLをsource_definitions.jsonの
        # cisa_kev定義から取得しbuild_facts_for_items(..., kev_url=...)へ渡す。
        # そのURLがKEVニュース収集処理(fetch_cisa_kev)が同一run内のmemoへ
        # 書き込むURLと一致していれば、build_facts_for_items側は追加のHTTP
        # 取得を行わずmemoを再利用できる。
        cisa_kev_def = fetch.get_source_definition(fetch.SOURCE_DEFINITIONS, "cisa_kev")
        self.assertIsNotNone(cisa_kev_def)
        kev_url = cisa_kev_def["url"]

        memo = {
            kev_url: ([{"cveID": "CVE-2026-0001", "dateAdded": "2026-07-01"}], True),
        }

        def urlopen_nvd_only(req, timeout=None):
            # KEV URL(cisa.gov)へのHTTP取得が発生した場合、memoが共有されて
            # いない(=kev_urlが一致していない)ことを意味するため失敗させる。
            if "cisa.gov" in req.full_url:
                raise AssertionError(f"想定外のKEV HTTP取得が発生しました: {req.full_url}")
            body = json.dumps({"vulnerabilities": []}).encode("utf-8")

            class FakeResponse:
                def read(self_inner):
                    return body

                def __enter__(self_inner):
                    return self_inner

                def __exit__(self_inner, *a):
                    return False

            return FakeResponse()

        items = [{"raw_title": "CVE-2026-0001", "raw_summary": "", "link": ""}]
        with tempfile.TemporaryDirectory() as tmp:
            cache_path = Path(tmp) / "cache.json"
            vf.build_facts_for_items(
                items, cache_path=cache_path, kev_url=kev_url, kev_catalog_memo=memo,
                urlopen_fn=urlopen_nvd_only, sleep_fn=lambda s: None,
            )

        self.assertEqual(items[0]["facts"]["cves"][0]["kev"]["status"], "listed")


class WorkflowStaticCheckTest(unittest.TestCase):
    """Ticket 12a #101-104: GitHub Actions workflow定義の静的確認。
    実際のworkflow実行(GitHub Actions上)は対象外。
    """

    def _workflow_text(self):
        return (Path(__file__).resolve().parent / ".github" / "workflows" / "fetch.yml").read_text(encoding="utf-8")

    def test_nvd_api_key_env_var_is_declared(self):
        text = self._workflow_text()
        self.assertIn("NVD_API_KEY: ${{ secrets.NVD_API_KEY }}", text)

    def test_gemini_api_key_env_var_still_present(self):
        text = self._workflow_text()
        self.assertIn("GEMINI_API_KEY: ${{ secrets.GEMINI_API_KEY }}", text)

    def test_git_add_docs_and_data_is_preserved(self):
        # data/配下に置くvulnerability_facts_cache.jsonは、既存の
        # `git add docs/ data/` によって自動的にstage対象へ含まれる
        # (キャッシュ専用のgit add行を新設する必要はない)。
        text = self._workflow_text()
        self.assertIn("git add docs/ data/", text)

    def test_commit_is_skipped_when_nothing_staged(self):
        # 既存のno-op commit防止ロジックは変更していない。save_cache()側も
        # 実質変更が無ければファイルへ書込まないため、二重に不要commitを防ぐ。
        text = self._workflow_text()
        self.assertIn("git diff --cached --quiet", text)
        self.assertIn("変更なし。スキップ。", text)

    def test_workflow_trigger_and_permissions_unchanged(self):
        text = self._workflow_text()
        self.assertIn("workflow_dispatch:", text)
        self.assertIn("cron: '0 22 * * *'", text)
        self.assertIn("contents: write", text)


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
