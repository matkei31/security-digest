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
