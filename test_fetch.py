#!/usr/bin/env python3
"""
HTMLエスケープ・URL検証の回帰テスト (Ticket 1)
標準ライブラリの unittest のみを使用する。
"""

import datetime
import json
import os
import re
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

        self.assertIn("重要度 高", html)
        self.assertIn("確認目安 本日確認", html)
        self.assertNotIn("カテゴリ：脆弱性・パッチ", html)
        self.assertIn(
            '<div class="article-tags"><span class="article-tags-label">関連タグ</span>'
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

    def test_ticket18_variant_b_classes_are_rendered_without_ellipse_badges(self):
        html = fetch.build_html([self._make_item(ai_analysis=self._analysis())])
        card = cards_segment(html)

        # 旧・楕円バッジclassは通常カードから完全に消える。
        self.assertNotIn("importance-badge", card)
        self.assertNotIn("urgency-badge", card)
        self.assertNotIn("category-badge", card)
        # 重要度／確認目安はプレーンテキスト中心の新classへ置き換わる。
        self.assertIn('<p class="article-assessment">', card)
        self.assertIn('class="assessment-item is-accent">重要度 高</span>', card)
        self.assertIn('class="assessment-item is-accent">確認目安 本日確認</span>', card)
        # 取得元・日時はプレーンテキストのメタ行。
        self.assertIn('<p class="article-meta">CISA ・ 07/11 06:00</p>', card)
        self.assertNotIn('class="card-meta"', card)
        self.assertNotIn('class="tag" style="background:', card)
        # 関連タグだけは丸い表示のまま維持する(B案)。
        self.assertIn('<div class="article-tags">', card)
        self.assertIn('class="article-tag">', card)
        self.assertIn("article-section", html)
        self.assertIn("action-list", html)
        self.assertIn('<meta name="viewport"', html)

    def test_ticket18_variant_b_non_accent_values_use_plain_strong_text(self):
        html = fetch.build_html([
            self._make_item(ai_analysis=self._analysis(importance="中", urgency="今週確認"))
        ])
        card = cards_segment(html)

        self.assertIn('<span class="assessment-item">重要度 <strong>中</strong></span>', card)
        self.assertIn('<span class="assessment-item">確認目安 <strong>今週確認</strong></span>', card)
        self.assertNotIn("is-accent", card)

    def test_ticket18_variant_b_tags_are_non_clickable_spans(self):
        html = fetch.build_html([self._make_item(ai_analysis=self._analysis())])
        card = cards_segment(html)
        style_block = html[html.index("<style>"):html.index("</style>")]
        tag_style = style_block[style_block.index(".article-tag{"):]
        tag_style = tag_style[:tag_style.index("}") + 1]

        self.assertNotIn("<a class=\"article-tag", card)
        self.assertNotIn("<button", card)
        self.assertNotIn("role=\"button\"", card)
        self.assertNotIn("onclick", card)
        self.assertNotIn("cursor", tag_style)

    def test_ticket18_variant_b_card_information_order(self):
        html = fetch.build_html([self._make_item(ai_analysis=self._analysis())])
        card = cards_segment(html)

        self.assertLess(card.index("article-heading"), card.index('class="article-meta"'))
        self.assertLess(card.index('class="article-meta"'), card.index('class="article-assessment"'))
        self.assertLess(card.index('class="article-assessment"'), card.index("何が起きた"))
        self.assertLess(card.index("何が起きた"), card.index("なぜ金融機関に関係する"))
        self.assertLess(card.index("なぜ金融機関に関係する"), card.index("確認すべきこと"))
        self.assertLess(card.index("確認すべきこと"), card.index('class="article-tags"'))

    def test_empty_tags_do_not_render_tag_area(self):
        html = fetch.build_html([self._make_item(ai_analysis=self._analysis(tags=[]))])

        self.assertNotIn('<div class="article-tags">', html)
        self.assertIn("重要度 高", html)

    def test_ticket18_variant_b_up_to_five_tags_all_render(self):
        five_tags = ["tag1", "tag2", "tag3", "tag4", "tag5"]
        html = fetch.build_html([self._make_item(ai_analysis=self._analysis(tags=five_tags))])
        card = cards_segment(html)

        for tag in five_tags:
            self.assertIn(f'<span class="article-tag">{tag}</span>', card)
        self.assertEqual(card.count('class="article-tag"'), 5)

    def test_ticket18_variant_b_category_text_never_leaks_into_card(self):
        html = fetch.build_html([
            self._make_item(ai_analysis=self._analysis(category="珍しいカテゴリ名"))
        ])
        card = cards_segment(html)

        self.assertNotIn("珍しいカテゴリ名", card)
        self.assertNotIn("カテゴリ", card)

    def test_ticket18_variant_b_missing_importance_and_urgency_omits_assessment(self):
        html = fetch.build_html([
            self._make_item(ai_analysis=self._analysis(importance=None, urgency=None))
        ])
        card = cards_segment(html)

        self.assertNotIn('class="article-assessment"', card)
        self.assertNotIn("None", card)
        self.assertNotIn(">null<", card)

    def test_ticket18_variant_b_legacy_priority_label_absent(self):
        html = fetch.build_html([self._make_item(ai_analysis=self._analysis())])

        self.assertNotIn("確認優先度", html)

    # ── article-metaの区切り文字(レビュー指摘対応) ─────────────────────────

    def test_meta_shows_source_and_date_joined_when_both_present(self):
        html = fetch.build_html([self._make_item()])
        card = cards_segment(html)

        self.assertIn('<p class="article-meta">CISA ・ 07/11 06:00</p>', card)

    def test_meta_shows_source_only_when_date_missing(self):
        html = fetch.build_html([self._make_item(date=None)])
        card = cards_segment(html)

        self.assertIn('<p class="article-meta">CISA</p>', card)
        self.assertNotIn("CISA ・", card)
        self.assertNotIn("・</p>", card)

    def test_meta_shows_date_only_when_source_missing(self):
        html = fetch.build_html([self._make_item(source="")])
        card = cards_segment(html)

        self.assertIn('<p class="article-meta">07/11 06:00</p>', card)
        self.assertNotIn("・ 07/11", card)

    def test_meta_area_absent_when_source_and_date_both_missing(self):
        html = fetch.build_html([self._make_item(source="", date=None)])
        card = cards_segment(html)

        self.assertNotIn('class="article-meta"', card)

    def test_meta_escapes_source_html(self):
        html = fetch.build_html([self._make_item(source="<b>source</b>", date=None)])
        card = cards_segment(html)

        self.assertIn('<p class="article-meta">&lt;b&gt;source&lt;/b&gt;</p>', card)
        self.assertNotIn("<b>source</b>", card)

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
        # categoryは通常記事カードから外れたため、ここでは表示されない
        # (daily JSON/dashboardのcategory契約はTicket18のスコープ外で別途維持)。
        self.assertNotIn("<b>category</b>", html)
        self.assertNotIn("&lt;b&gt;category&lt;/b&gt;", html)
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
        self.assertIn("重要度 高", html)
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
        self.assertIn("確認目安、重要度、元の収集順で表示しています。", html)
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
        self.assertIn("<strong>3</strong>件", dashboard_segment(html))
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

    def test_heading_honjitsu_no_youten_is_shown(self):
        html = fetch.build_html([self._make_item()], SAMPLE_BRIEF)
        self.assertIn("本日の要点", brief_segment(html))
        self.assertNotIn("Today's Brief", html)
        self.assertNotIn("Today’s Brief", html)

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

    def test_check_items_empty_section_is_not_rendered(self):
        brief = dict(SAMPLE_BRIEF, check_items=[])
        html = fetch.build_html([self._make_item()], brief)
        segment = brief_segment(html)
        self.assertNotIn("本日の確認事項", segment)
        self.assertIn("本日の注目論点", segment)

    def test_both_discussion_points_and_check_items_empty(self):
        brief = dict(SAMPLE_BRIEF, discussion_points=[], check_items=[])
        html = fetch.build_html([self._make_item()], brief)
        segment = brief_segment(html)
        self.assertNotIn("本日の注目論点", segment)
        self.assertNotIn("本日の確認事項", segment)
        self.assertNotIn("<ul", segment)
        self.assertNotIn('<ul class="brief-list"></ul>', segment)

    def test_only_discussion_points_present_check_items_section_absent(self):
        brief = dict(SAMPLE_BRIEF, check_items=[])
        html = fetch.build_html([self._make_item()], brief)
        segment = brief_segment(html)
        self.assertIn("本日の注目論点", segment)
        self.assertNotIn("本日の確認事項", segment)
        self.assertEqual(segment.count("<ul"), 1)

    def test_only_check_items_present_discussion_points_section_absent(self):
        brief = dict(SAMPLE_BRIEF, discussion_points=[])
        html = fetch.build_html([self._make_item()], brief)
        segment = brief_segment(html)
        self.assertNotIn("本日の注目論点", segment)
        self.assertIn("本日の確認事項", segment)
        self.assertEqual(segment.count("<ul"), 1)

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
        self.assertNotIn("Today’s Brief", html)
        self.assertNotIn("本日の要点", html)

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


class BriefStatusLineHtmlTest(unittest.TestCase):
    """Ticket 15c: overview先頭の決定論的状態行を専用要素へ分離する表示のテスト。"""

    def _make_item(self, title="記事"):
        return {
            "title": title,
            "link": f"https://example.com/{title}",
            "summary": f"{title}の概要",
            "date": datetime.datetime(2026, 7, 11, 6, 0),
            "source": "CISA",
            "lang": "ja",
        }

    def _brief_item(self, title, importance, urgency):
        return {
            "title": title,
            "source": "CISA",
            "ai_analysis": {
                "category": "脆弱性・パッチ",
                "importance": importance,
                "urgency": urgency,
                "summary": "要約",
                "financial_impact": "影響",
                "recommended_actions": ["対応1"],
                "reason": "理由",
                "tags": ["KEV"],
            },
            "ai_analysis_meta": {"status": "success", "error_type": None, "http_status": None},
        }

    def _unclassified_item(self, title):
        return {
            "title": title,
            "source": "CISA",
            "ai_analysis": None,
            "ai_analysis_meta": {"status": "failed", "error_type": "api_error", "http_status": 500},
        }

    def _brief_with_generated_overview(
        self, evaluated_specs, unclassified_count=0, gemini_overview="Geminiによる補足本文です。",
    ):
        """実際のcompute_brief_trusted_context/apply_deterministic_brief_contextを
        通して、状態行合成後のoverviewを持つbrief dictを組み立てる。
        """
        eval_items = [
            self._brief_item(f"item-{i}", importance, urgency)
            for i, (importance, urgency) in enumerate(evaluated_specs)
        ]
        unclassified_items = [
            self._unclassified_item(f"unclassified-{i}") for i in range(unclassified_count)
        ]
        items = eval_items + unclassified_items
        ctx = fetch.compute_brief_trusted_context(items)
        result = {
            "overview": gemini_overview,
            "important_highlights": [],
            "discussion_points": [],
            "check_items": [],
        }
        applied = fetch.apply_deterministic_brief_context(result, ctx)
        status_line = fetch.format_brief_status_line(ctx)
        return applied, status_line, ctx

    def test_state_a_status_line_is_in_dedicated_element(self):
        brief, status_line, ctx = self._brief_with_generated_overview(
            [("高", "本日確認"), ("中", "今週確認")]
        )
        self.assertEqual(ctx["temporal_state"], "A")
        html = fetch.build_html([self._make_item()], brief)
        segment = brief_segment(html)
        self.assertIn(f'<p class="brief-status-line">{status_line}</p>', segment)
        self.assertEqual(segment.count(status_line), 1)

    def test_state_b_status_line_is_in_dedicated_element(self):
        brief, status_line, ctx = self._brief_with_generated_overview(
            [("中", "今週確認")] * 3
        )
        self.assertEqual(ctx["temporal_state"], "B")
        html = fetch.build_html([self._make_item()], brief)
        segment = brief_segment(html)
        self.assertIn(f'<p class="brief-status-line">{status_line}</p>', segment)
        self.assertEqual(segment.count(status_line), 1)

    def test_state_c_status_line_is_in_dedicated_element(self):
        brief, status_line, ctx = self._brief_with_generated_overview(
            [("中", "参考")] * 3
        )
        self.assertEqual(ctx["temporal_state"], "C")
        html = fetch.build_html([self._make_item()], brief)
        segment = brief_segment(html)
        self.assertIn(f'<p class="brief-status-line">{status_line}</p>', segment)
        self.assertEqual(segment.count(status_line), 1)

    def test_incomplete_coverage_status_line_includes_unclassified_and_is_split(self):
        brief, status_line, ctx = self._brief_with_generated_overview(
            [("中", "今週確認")], unclassified_count=2
        )
        self.assertFalse(ctx["coverage_complete"])
        self.assertIn("未判定2件", status_line)
        html = fetch.build_html([self._make_item()], brief)
        segment = brief_segment(html)
        self.assertIn(f'<p class="brief-status-line">{status_line}</p>', segment)

    def test_rest_of_overview_is_in_separate_element_with_unchanged_wording(self):
        brief, status_line, ctx = self._brief_with_generated_overview(
            [("高", "本日確認")], gemini_overview="Geminiが生成した補足本文そのもの。"
        )
        expected_explanation = fetch.format_brief_state_explanation(ctx)
        expected_rest = expected_explanation + "Geminiが生成した補足本文そのもの。"
        # 分離しても、状態行+改行境界+残り本文を連結すれば元のoverviewと一字一句一致すること
        self.assertEqual(brief["overview"], status_line + "\n" + expected_rest)

        html = fetch.build_html([self._make_item()], brief)
        segment = brief_segment(html)
        self.assertIn(f'<p class="brief-overview">{expected_rest}</p>', segment)
        overview_start = segment.index('<p class="brief-overview">')
        self.assertNotIn(status_line, segment[overview_start:])

    def test_split_overview_rest_is_html_escaped(self):
        brief, status_line, ctx = self._brief_with_generated_overview(
            [("高", "本日確認")], gemini_overview="<script>alert(1)</script>"
        )
        html = fetch.build_html([self._make_item()], brief)
        segment = brief_segment(html)
        self.assertNotIn("<script>alert(1)</script>", segment)
        self.assertIn("&lt;script&gt;", segment)

    def test_unrecognized_legacy_overview_is_shown_in_full_without_split(self):
        legacy_brief = dict(
            SAMPLE_BRIEF,
            overview="2026-07-11の概況：記事が少数のため通常運用を継続してください。",
        )
        html = fetch.build_html([self._make_item()], legacy_brief)
        segment = brief_segment(html)
        self.assertNotIn("brief-status-line", segment)
        self.assertIn(f'<p class="brief-overview">{legacy_brief["overview"]}</p>', segment)

    def test_fullwidth_digit_lookalike_overview_is_shown_in_full_without_split(self):
        # 全角数字を含む酷似状態行はsplitされず、全文が従来通りbrief-overviewへ
        # fail-openされ、brief-status-lineは生成されないことをbuild_html経由で確認する
        lookalike_brief = dict(
            SAMPLE_BRIEF,
            overview=(
                "本日の状態（掲載３件）：重要度「高」１件、確認目安「本日確認」０件、"
                "確認目安「今週確認」１件。続く説明文です。"
            ),
        )
        html = fetch.build_html([self._make_item()], lookalike_brief)
        segment = brief_segment(html)
        self.assertNotIn("brief-status-line", segment)
        self.assertIn(
            f'<p class="brief-overview">{lookalike_brief["overview"]}</p>', segment
        )

    def test_empty_overview_produces_no_overview_section_without_exception(self):
        brief = dict(SAMPLE_BRIEF, overview="")
        html = fetch.build_html([self._make_item()], brief)
        segment = brief_segment(html)
        self.assertNotIn("本日の概況", segment)
        self.assertNotIn("brief-status-line", segment)

    def test_none_overview_produces_no_overview_section_without_exception(self):
        brief = dict(SAMPLE_BRIEF, overview=None)
        html = fetch.build_html([self._make_item()], brief)
        segment = brief_segment(html)
        self.assertNotIn("本日の概況", segment)
        self.assertNotIn("brief-status-line", segment)

    def test_legacy_overview_from_json_is_converted_to_current_format_in_html(self):
        # BL-016: 既存data/JSONに保存されている旧形式のoverviewからHTMLを
        # 構築しても、生成されるHTMLに旧文言「本日の状態」が残らず、現行の
        # ｜区切り形式で表示されること。
        legacy_overview = (
            "本日の状態（掲載3件）：重要度「高」1件、確認目安「本日確認」1件、"
            "確認目安「今週確認」1件。続く説明文です。"
        )
        brief = dict(SAMPLE_BRIEF, overview=legacy_overview)
        html = fetch.build_html([self._make_item()], brief)
        segment = brief_segment(html)
        self.assertNotIn("本日の状態", segment)
        self.assertIn(
            '<p class="brief-status-line">掲載3件｜重要度「高」1件｜本日確認1件｜今週確認1件</p>',
            segment,
        )
        self.assertIn('<p class="brief-overview">続く説明文です。</p>', segment)

    def test_legacy_label_never_appears_in_generated_html(self):
        brief, status_line, ctx = self._brief_with_generated_overview([("高", "本日確認")])
        html = fetch.build_html([self._make_item()], brief)
        self.assertNotIn("本日の状態", html)


class SplitBriefOverviewStatusLineTest(unittest.TestCase):
    """Ticket 15c: split_brief_overview_status_line()単体のpure helperテスト。"""

    def test_returns_none_for_unrecognized_free_text(self):
        self.assertIsNone(
            fetch.split_brief_overview_status_line("見慣れない形式の概況文です。")
        )

    def test_returns_none_for_empty_string(self):
        self.assertIsNone(fetch.split_brief_overview_status_line(""))

    def test_returns_none_for_none(self):
        self.assertIsNone(fetch.split_brief_overview_status_line(None))

    def test_returns_none_when_no_period_present(self):
        self.assertIsNone(fetch.split_brief_overview_status_line("句点のない文字列"))

    def test_matches_current_deterministic_format_exactly(self):
        ctx = {
            "published_total": 12, "importance_high": 3,
            "urgency_today": 2, "urgency_week": 4, "unclassified": 0,
        }
        status_line = fetch.format_brief_status_line(ctx)
        overview = status_line + "\n続く説明文。"
        split = fetch.split_brief_overview_status_line(overview)
        self.assertEqual(split, (status_line, "続く説明文。"))

    def test_matches_with_unclassified_segment(self):
        ctx = {
            "published_total": 12, "importance_high": 3,
            "urgency_today": 2, "urgency_week": 4, "unclassified": 5,
        }
        status_line = fetch.format_brief_status_line(ctx)
        overview = status_line + "\n続く説明文。"
        split = fetch.split_brief_overview_status_line(overview)
        self.assertEqual(split, (status_line, "続く説明文。"))

    def test_current_format_without_newline_boundary_is_not_split(self):
        # BL-016: 現行形式であっても、直後が改行または文字列末尾でない場合
        # (数字列の途中など、自由文と地続きになっているケース)は分離しない。
        ctx = {
            "published_total": 12, "importance_high": 3,
            "urgency_today": 2, "urgency_week": 4, "unclassified": 0,
        }
        status_line = fetch.format_brief_status_line(ctx)
        overview = status_line + "続く説明文。"  # 改行を挟まない
        self.assertIsNone(fetch.split_brief_overview_status_line(overview))

    def test_status_line_only_with_no_trailing_text_splits_to_empty_rest(self):
        ctx = {
            "published_total": 1, "importance_high": 0,
            "urgency_today": 0, "urgency_week": 0, "unclassified": 0,
        }
        status_line = fetch.format_brief_status_line(ctx)
        split = fetch.split_brief_overview_status_line(status_line)
        self.assertEqual(split, (status_line, ""))

    def test_similar_but_not_exact_format_is_not_split(self):
        # 件数の桁や句読点が微妙に異なる、酷似した非決定論的文字列は誤って分離しない
        almost = "本日の状態（掲載3件）:重要度「高」1件、確認目安「本日確認」0件、確認目安「今週確認」1件。"
        self.assertIsNone(fetch.split_brief_overview_status_line(almost))

    def test_fullwidth_digit_counts_are_not_split(self):
        # format_brief_status_line()はintからASCII数字のみを生成するため、
        # 全角数字を含む酷似文字列はPythonの\dがUnicode数字も受理する
        # 副作用で誤って厳密一致しないことを確認する
        fullwidth = "本日の状態（掲載３件）：重要度「高」１件、確認目安「本日確認」０件、確認目安「今週確認」１件。"
        self.assertIsNone(fetch.split_brief_overview_status_line(fullwidth))

    def test_fullwidth_digit_in_unclassified_segment_is_not_split(self):
        mixed = (
            "本日の状態（掲載5件）：重要度「高」1件、確認目安「本日確認」0件、"
            "確認目安「今週確認」1件、未判定２件。"
        )
        self.assertIsNone(fetch.split_brief_overview_status_line(mixed))

    def test_matches_legacy_deterministic_format_and_converts_to_current(self):
        # BL-016: Ticket 15b/15c時点の旧形式(句点終端)は既存data/JSONへ
        # そのまま保存されている。表示時に限り、数値を保ったまま現行の
        # ｜区切り形式へ変換されることを確認する。
        legacy = (
            "本日の状態（掲載12件）：重要度「高」3件、確認目安「本日確認」2件、"
            "確認目安「今週確認」4件。続く説明文。"
        )
        split = fetch.split_brief_overview_status_line(legacy)
        self.assertEqual(
            split,
            ("掲載12件｜重要度「高」3件｜本日確認2件｜今週確認4件", "続く説明文。"),
        )

    def test_matches_legacy_format_with_unclassified_segment(self):
        legacy = (
            "本日の状態（掲載12件）：重要度「高」3件、確認目安「本日確認」2件、"
            "確認目安「今週確認」4件、未判定5件。続く説明文。"
        )
        split = fetch.split_brief_overview_status_line(legacy)
        self.assertEqual(
            split,
            ("掲載12件｜重要度「高」3件｜本日確認2件｜今週確認4件｜未判定5件", "続く説明文。"),
        )

    def test_legacy_format_only_with_no_trailing_text_splits_to_empty_rest(self):
        legacy = (
            "本日の状態（掲載1件）：重要度「高」0件、確認目安「本日確認」0件、"
            "確認目安「今週確認」0件。"
        )
        split = fetch.split_brief_overview_status_line(legacy)
        self.assertEqual(split, ("掲載1件｜重要度「高」0件｜本日確認0件｜今週確認0件", ""))

    def test_legacy_format_fullwidth_digits_are_not_converted(self):
        # 旧形式であっても全角数字を含む酷似文字列は誤って変換・分離しない
        fullwidth = "本日の状態（掲載３件）：重要度「高」１件、確認目安「本日確認」０件、確認目安「今週確認」１件。"
        self.assertIsNone(fetch.split_brief_overview_status_line(fullwidth))

    def test_current_format_status_line_has_no_legacy_label_or_punctuation(self):
        # BL-016: 「本日の状態」ラベル、括弧、コロン、文末の句点を含まない。
        ctx = {
            "published_total": 12, "importance_high": 3,
            "urgency_today": 2, "urgency_week": 4, "unclassified": 5,
        }
        status_line = fetch.format_brief_status_line(ctx)
        self.assertNotIn("本日の状態", status_line)
        self.assertNotIn("（", status_line)
        self.assertNotIn("）", status_line)
        self.assertNotIn("：", status_line)
        self.assertFalse(status_line.endswith("。"))
        self.assertEqual(
            status_line,
            "掲載12件｜重要度「高」3件｜本日確認2件｜今週確認4件｜未判定5件",
        )


class BriefStatusLineCssTest(unittest.TestCase):
    """Ticket 15c: 状態行専用要素のCSSが控えめで、警告色/状態別色分け/JSを
    追加していないこと、既存モバイル対応が変更されていないことの回帰テスト。
    """

    def _make_item(self, title="記事"):
        return {
            "title": title,
            "link": f"https://example.com/{title}",
            "summary": f"{title}の概要",
            "date": datetime.datetime(2026, 7, 11, 6, 0),
            "source": "CISA",
            "lang": "ja",
        }

    def test_todays_brief_container_max_width_and_mobile_media_query_unchanged(self):
        html = fetch.build_html([self._make_item()], SAMPLE_BRIEF)
        self.assertIn(".todays-brief{max-width:680px", html)
        self.assertIn("@media (max-width:600px)", html)

    def test_brief_status_line_css_exists_and_has_no_inline_js_or_color_coding(self):
        html = fetch.build_html([self._make_item()], SAMPLE_BRIEF)
        style_start = html.index("<style>")
        style_end = html.index("</style>")
        style = html[style_start:style_end]
        self.assertIn(".brief-status-line{", style)
        rule_start = style.index(".brief-status-line{")
        rule_end = style.index("}", rule_start)
        rule = style[rule_start:rule_end]
        # 警告色(赤・オレンジ系)を使わず、既存の控えめなグレー系配色に馴染ませる
        self.assertNotIn("#da3633", rule)
        self.assertNotIn("#9e6a03", rule)
        self.assertNotIn("#f0b429", rule)

    def test_no_javascript_is_emitted_anywhere_in_the_page(self):
        html = fetch.build_html([self._make_item()], SAMPLE_BRIEF)
        self.assertNotIn("<script", html)
        self.assertNotIn("onclick", html)


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
        self.assertIn("掲載", dashboard)
        self.assertIn("<strong>2</strong>件", dashboard)
        self.assertIn("<h3>重要度</h3>", dashboard)
        self.assertIn("<h3>確認目安</h3>", dashboard)
        self.assertIn("<h3>主なカテゴリ</h3>", dashboard)
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
        category_part = dashboard[dashboard.index("<h3>主なカテゴリ</h3>"):]

        self.assertIn("<span>未判定</span><strong>1</strong>", dashboard)
        self.assertLess(category_part.index("脆弱性・パッチ"), category_part.index("インシデント"))
        self.assertLess(category_part.index("インシデント"), category_part.index("未判定"))
        self.assertNotIn("不正カテゴリ", dashboard)

    def test_empty_items_dashboard_html(self):
        html = fetch.build_html([])
        dashboard = dashboard_segment(html)

        self.assertIn("本日のダッシュボード", dashboard)
        self.assertIn("<strong>0</strong>件", dashboard)
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

    def test_dashboard_axes_and_category_values_do_not_cross_leak(self):
        # dashboard v2: 重要度・確認目安・カテゴリはそれぞれ独立したリストへ描画され、
        # 一方の軸の値がもう一方のリスト側へ混ざらないことを確認する。
        items = [
            self._make_item("only-patch", importance="高", urgency="本日確認", category="脆弱性・パッチ"),
        ]
        dashboard = dashboard_segment(fetch.build_html(items))
        importance_part = dashboard[
            dashboard.index("<h3>重要度</h3>"):dashboard.index("<h3>確認目安</h3>")
        ]
        urgency_part = dashboard[
            dashboard.index("<h3>確認目安</h3>"):dashboard.index("<h3>主なカテゴリ</h3>")
        ]
        category_part = dashboard[dashboard.index("<h3>主なカテゴリ</h3>"):]

        self.assertNotIn("脆弱性・パッチ", importance_part)
        self.assertNotIn("本日確認", importance_part)
        self.assertNotIn("脆弱性・パッチ", urgency_part)
        self.assertNotIn("高", urgency_part)
        self.assertNotIn("<span>高</span>", category_part)
        self.assertNotIn("<span>本日確認</span>", category_part)

    def test_dashboard_never_shows_source_count_or_kev_count_or_multiple_cards(self):
        html = fetch.build_html([self._make_item("solo")])
        dashboard = dashboard_segment(html)

        self.assertNotIn("ソース", dashboard)
        self.assertNotIn("収集元", dashboard)
        self.assertNotIn("CISA KEV", dashboard)
        # dashboard v2は単一の<section class="dashboard">ブロックであり、
        # 旧3カード構造(複数の<section class="dashboard-group">)を持たない。
        self.assertEqual(dashboard.count('<section class="dashboard'), 1)
        self.assertNotIn('class="dashboard-group', dashboard)

    def test_confirmation_priority_wording_does_not_appear_in_generated_html(self):
        # 「確認優先度」は用語統一により生成HTMLへ一切残らない
        # (ARTICLE promptの評価定義文はfetch.py内に残るが、生成HTML出力には含めない)。
        items = [
            self._make_item("term-check", importance="高", urgency="本日確認", category="脆弱性・パッチ"),
        ]
        html = fetch.build_html(items, SAMPLE_BRIEF)
        self.assertNotIn("確認優先度", html)


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
        # 重要度・確認目安は優先確認の必須表示項目として簡潔なテキストで示す
        # (通常カードのような楕円バッジ<span class="importance-badge">等は使わない)。
        self.assertIn("重要度 高", important)
        self.assertIn("確認目安 本日確認", important)
        self.assertNotIn("importance-badge", important)
        self.assertNotIn("urgency-badge", important)
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

    def test_empty_important_items_section_does_not_show_selection_condition_note(self):
        # 選定条件の説明文は、優先確認対象がある場合だけ表示する。
        item = self._make_item("ordinary", importance="中", urgency="今週確認")
        important = important_segment(fetch.build_html([item]))

        self.assertNotIn("important-items-note", important)
        self.assertNotIn("重要度が高い、または確認目安が本日確認の記事です。", important)

    def test_non_empty_important_items_section_shows_selection_condition_note(self):
        item = self._make_item("selected", importance="高", urgency="本日確認")
        important = important_segment(fetch.build_html([item]))

        self.assertIn("important-items-note", important)
        self.assertIn("重要度が高い、または確認目安が本日確認の記事です。", important)

    def test_importance_only_item_shows_importance_meta_without_urgency(self):
        item = self._make_item("importance-only", importance="高", urgency="参考")
        important = important_segment(fetch.build_html([item]))

        self.assertIn("重要度 高", important)
        self.assertIn("確認目安 参考", important)

    def test_urgency_only_item_shows_urgency_meta(self):
        item = self._make_item("urgency-only", importance="低", urgency="本日確認")
        important = important_segment(fetch.build_html([item]))

        self.assertIn("重要度 低", important)
        self.assertIn("確認目安 本日確認", important)

    def test_high_and_today_combined_item_shows_both_meta_values(self):
        item = self._make_item("combined", importance="高", urgency="本日確認")
        important = important_segment(fetch.build_html([item]))

        self.assertIn("重要度 高", important)
        self.assertIn("確認目安 本日確認", important)

    def test_multiple_priority_items_share_numbering_with_full_list(self):
        first = self._make_item("first-priority", importance="高", urgency="本日確認")
        second = self._make_item("second-priority", importance="高", urgency="本日確認")
        html = fetch.build_html([first, second])
        important = important_segment(html)

        self.assertIn('href="#article-1"', important)
        self.assertIn('href="#article-2"', important)
        self.assertIn('id="article-1"', cards_segment(html))
        self.assertIn('id="article-2"', cards_segment(html))

    def test_card_target_css_rule_exists_with_accent_color(self):
        html = fetch.build_html([self._make_item("target-check", importance="高", urgency="本日確認")])
        self.assertIn(".card:target{", html)

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

    def test_reason_display_keeps_importance_label_with_ha_unchanged(self):
        # promptのreasonラベルは既に表示名「重要度」と一致しているため、
        # normalize_reason_display_labels()は重要度側を書き換えない
        # (確認優先度への変換は廃止した)。
        item = self._make_item(
            "label-high",
            importance="高",
            urgency="本日確認",
            reason="被害が大きいため、重要度は高いと判断しました。",
        )
        html = fetch.build_html([item])
        important = important_segment(html)

        self.assertIn("重要度は高い", important)
        self.assertNotIn("確認優先度", important)
        self.assertEqual(item["ai_analysis"]["reason"], "被害が大きいため、重要度は高いと判断しました。")

    def test_reason_display_keeps_importance_label_with_colon_unchanged(self):
        item = self._make_item(
            "label-medium",
            importance="高",
            urgency="本日確認",
            reason="重要度：中、追加調査が必要です。",
        )
        html = fetch.build_html([item])

        self.assertIn("重要度：中", important_segment(html))
        self.assertNotIn("確認優先度", important_segment(html))

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
        self.assertNotIn("確認優先度", important)

    def test_reason_display_escaping_after_label_rewrite(self):
        item = self._make_item(
            "escaped-label",
            importance="高",
            urgency="本日確認",
            reason="重要度は高い <script>alert(1)</script>",
        )
        html = fetch.build_html([item])
        important = important_segment(html)

        self.assertIn("重要度は高い &lt;script&gt;alert(1)&lt;/script&gt;", important)
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

    def test_gemini_prompt_references_facts_only_via_serializer(self):
        # Ticket 12c: enrich_with_ai()はTicket 12aのfacts生構造(cvss・
        # retrieval等)を直接参照せず、serialize_vulnerability_facts_for_prompt()
        # 経由でのみフィルタ済みのvulnerability_facts行をプロンプト入力へ渡す
        # (Ticket 12aでは一切facts/cvssを参照しなかったが、Ticket 12cで
        # 意図的にserializer経由の参照のみを追加した)。
        # 内部識別子漏出修正: verified_context_jsonの組み立ては
        # build_verified_context_for_prompt()のallowlist projectionへ一元化した
        # ため、enrich_with_ai()はそちらを呼ぶだけで、serializer参照自体は
        # build_verified_context_for_prompt()側にある。
        import inspect
        enrich_source = inspect.getsource(fetch.enrich_with_ai)
        self.assertIn("build_verified_context_for_prompt(item, analysis_date, rule_flags)", enrich_source)
        # enrich_with_ai()自体はfacts生フィールド名を直接参照しない。
        self.assertNotIn("cvss", enrich_source.lower())
        self.assertNotIn("retrieval", enrich_source.lower())

        # 脆弱性情報の人間可読ラベルへの投影は_project_vulnerability_facts_for_prompt()
        # が担い、そちらがserialize_vulnerability_facts_for_prompt()を呼ぶ。
        projection_source = inspect.getsource(fetch.build_verified_context_for_prompt)
        vuln_projection_source = inspect.getsource(fetch._project_vulnerability_facts_for_prompt)
        self.assertIn("_project_vulnerability_facts_for_prompt(item)", projection_source)
        self.assertIn("serialize_vulnerability_facts_for_prompt(item)", vuln_projection_source)
        # allowlist projection自体もfactsの生フィールドを直接読み書きしない
        # (すべてserialize_vulnerability_facts_for_prompt()側に閉じ込める)。
        self.assertNotIn("retrieval", projection_source.lower())
        self.assertNotIn("retrieval", vuln_projection_source.lower())

    def test_collect_recent_no_longer_calls_gemini_enrichment_internally(self):
        # Ticket 12a: enrich_with_ai()はcollect_recent()から分離され、main()側で
        # facts取得の後に明示的に呼び出す設計になっている。
        import inspect
        source = inspect.getsource(fetch.collect_recent)
        self.assertNotIn("enrich_with_ai(", source)

    def test_gemini_request_body_includes_filtered_facts_but_not_raw_fields(self):
        # Ticket 12c: enrich_with_ai()が実際にGeminiへ送信するリクエストボディに、
        # serialize_vulnerability_facts_for_prompt()がフィルタしたCVE ID・
        # CVSSスコア/severity・KEV状態は含まれる一方、Ticket 12aの運用情報
        # (retrieval・fetched_at・CVSS vector/source/type・vuln_status・
        # published_at・last_modified_at・NVD詳細URL)は一切含まれないことを
        # 動的に検証する。
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
        # sent_bodyはjson.dumps()のensure_ascii既定(True)でエンコードされており、
        # 日本語は\uXXXXエスケープされる。日本語の意味値を素の文字列として
        # 検証するため、一度JSONとしてdecodeしたprompt本文を使う。
        prompt_text = json.loads(sent_body)["contents"][0]["parts"][0]["text"]

        # Ticket 12c: フィルタ済みfacts(CVE ID・スコア・severity・KEV状態・
        # KEV追加日)は意図的に送信される。内部識別子漏出修正: KEV掲載状態は
        # 機械値"listed"ではなく人間可読な意味値"掲載あり"で送信される。
        for included_value in ("CVE-2026-1234", "9.8", "CRITICAL", "2026-07-11"):
            self.assertIn(included_value, sent_body, f"{included_value!r} was expected in Gemini request body")
        self.assertIn("掲載あり", prompt_text)
        self.assertNotIn("listed", prompt_text)

        # Ticket 12aの運用情報・生フィールドは一切送信しない。last_modified_at/
        # published_at/fetched_atはフルタイムスタンプ(T00:00:00Z等)で判定し、
        # kev_date_added用の素の日付("2026-07-11")との誤検知を避ける。
        for leaked_value in (
            "retrieval", "fetched_at", "nvd.nist.gov/vuln/detail",
            "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  # cvss vector
            "nvd@nist.gov",  # cvss source(生のメールアドレス形式)
            "Primary",  # cvss type
            "Analyzed",  # vuln_status
            "2026-07-10T00:00:00Z",  # published_at
            "2026-07-11T00:00:00Z",  # last_modified_at
            "2026-07-12T01:00:00Z",  # nvd/kevのfetched_at
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
    def test_agents_file_contains_current_safety_guardrails(self):
        text = (Path(__file__).resolve().parent / "AGENTS.md").read_text(encoding="utf-8")

        for required_text in (
            "## Approval boundaries",
            "## Gemini and production safety",
            "## Testing and review",
            "BACKLOG.md",
            "BL-014",
            "original user comment",
            "user acceptance",
            'python3 -m unittest discover -p "test_*.py"',
        ):
            with self.subTest(required_text=required_text):
                self.assertIn(required_text, text)

        lines = text.splitlines()

        def assert_policy_line(*terms):
            self.assertTrue(
                any(all(term in line for term in terms) for line in lines),
                f"AGENTS.md must keep one policy line containing: {terms}",
            )

        assert_policy_line("real Gemini API", "explicit approval")
        assert_policy_line("Never force-push", "shared history", "explicit approval")
        assert_policy_line(
            "workflow_dispatch",
            "production generation",
            "separate explicit authorization",
        )
        assert_policy_line(
            "Do not modify or regenerate",
            "`data/`",
            "`docs/`",
            "explicitly",
        )

    def test_backlog_file_contains_required_structure(self):
        backlog_path = Path(__file__).resolve().parent / "BACKLOG.md"
        self.assertTrue(backlog_path.is_file())
        text = backlog_path.read_text(encoding="utf-8")

        for required_text in (
            "## 状態の定義",
            "BL-001",
            "BL-002",
            "BL-005",
            "BL-006",
            "BL-009",
            "BL-014",
            "BL-015",
            "BL-016",
            "BL-017",
            "BL-018",
            "## 完了済み参照",
            "Ticket 14a-3",
            "Ticket 14a-4",
        ):
            with self.subTest(required_text=required_text):
                self.assertIn(required_text, text)

        required_fields = (
            "**ID:**",
            "**タイトル:**",
            "**優先度:**",
            "**状態:**",
            "**出所種別:**",
            "**ユーザー原文:**",
            "**ユーザー確認済み要約:**",
            "**解釈:**",
            "**完了条件:**",
            "**依存関係:**",
            "**実装証跡:**",
            "**ユーザー受入証跡:**",
            "**残作業:**",
            "**注記:**",
        )
        item_ids = [f"BL-{number:03d}" for number in range(1, 19)]
        for index, item_id in enumerate(item_ids):
            start = text.index(f"## {item_id}")
            if index + 1 < len(item_ids):
                end = text.index(f"## {item_ids[index + 1]}", start)
            else:
                end = text.index("## 完了済み参照", start)
            item_text = text[start:end]
            for field in required_fields:
                with self.subTest(item_id=item_id, field=field):
                    self.assertIn(field, item_text)

    def test_backlog_follow_up_provenance_and_decisions(self):
        root = Path(__file__).resolve().parent
        backlog_text = (root / "BACKLOG.md").read_text(encoding="utf-8")
        decisions_text = (root / "DECISIONS.md").read_text(encoding="utf-8")

        def section(text, heading, next_heading):
            start = text.index(heading)
            end = text.index(next_heading, start)
            return text[start:end]

        bl006 = section(backlog_text, "## BL-006", "## BL-007")
        bl007 = section(backlog_text, "## BL-007", "## BL-008")
        bl014 = section(backlog_text, "## BL-014", "## BL-015")
        bl015 = section(backlog_text, "## BL-015", "## 完了済み参照")
        sd008 = section(decisions_text, "## SD-008", "## SD-009")

        verbatim = (
            "「うん。他に未対応と見られる私のコメントある？同じように汎化してるなら私自身のコメントに立ち返って確認して。"
            "本来、指摘コメントを勝手に書き換えて対応済み扱いするのありえないから。ちゃんとバックログ管理して」"
        )
        self.assertIn(f"- **ユーザー原文:** {verbatim}", bl014)

        self.assertIn("- **出所種別:** ユーザー確認済み要約", bl006)
        self.assertIn("- **ユーザー原文:** 原文未回収。", bl006)
        self.assertIn("SD-010", bl006)

        # BL-014 batch 1 (BL014-A) added the verbatim original comment recovered
        # for BL-007; BL-006 (a distinct, still-unrecovered request) is unaffected.
        # The quote and its provenance (date) are kept in separate fields — the
        # date is not appended inline to the Original user comment quote.
        self.assertIn(
            "- **出所種別:** ユーザー原文 / ユーザー確認済み要約", bl007
        )
        self.assertIn(
            "- **ユーザー原文:** 「URLがgithubのユーザー名なのが気になる」",
            bl007,
        )
        self.assertNotIn(
            "「URLがgithubのユーザー名なのが気になる」（2026-07-09", bl007
        )
        self.assertIn("- **出所:** 2026-07-09 プロジェクト会話。", bl007)
        self.assertIn("SD-011", bl007)

        # BL-014 batch 1 (BL014-C) added BL-015 with two separate verbatim
        # comments in separate fields, kept distinct rather than merged into
        # one paraphrase or mixed with English management commentary.
        self.assertIn("- **出所種別:** ユーザー原文", bl015)
        self.assertIn(
            "- **ユーザー原文:** 「セキュリティ要件みたいなのも後で決めよう」",
            bl015,
        )
        self.assertIn(
            "- **追加のユーザー原文:** "
            "「OK.ここはfable5にもレビューしてもらおう。"
            "公開情報を扱うものだから厳しいセキュリティ対策をする必要はないと思うが、"
            "必要なものは網羅しつつ過剰じゃないように整理して、fable5にレビューさせられる形にして。」",
            bl015,
        )

        self.assertIn("## SD-010", decisions_text)
        self.assertIn("## SD-011", decisions_text)
        self.assertIn("## SD-014", decisions_text)

        # SD-014's Accepted wording preserves its original 3-line structure
        # (recorded as a Markdown blockquote) rather than being collapsed
        # into one paraphrased line.
        sd014_start = decisions_text.index("## SD-014")
        sd014_text = decisions_text[sd014_start:sd014_start + 3000]
        self.assertIn("> 「daily JSONはサイト利用者へ公開する必要はない。", sd014_text)
        self.assertIn(
            "> GitHub Pagesの公開対象であるdocs/には置かず、生成・履歴管理用としてdata/に保存する。",
            sd014_text,
        )
        self.assertIn(
            "> public repository内で閲覧可能であることは許容するが、"
            "秘密情報、raw AI response、記事全文など公開不適切な情報を保存しない。」",
            sd014_text,
        )

        # A local, user-specific absolute path used only during out-of-repo
        # audit research must not be recorded as a permanent repository
        # artifact.
        for doc_name, doc_text in (
            ("BACKLOG_AUDIT.md", (root / "BACKLOG_AUDIT.md").read_text(encoding="utf-8")),
            ("BACKLOG.md", backlog_text),
            ("DECISIONS.md", decisions_text),
            ("STATUS.md", (root / "STATUS.md").read_text(encoding="utf-8")),
        ):
            with self.subTest(doc=doc_name):
                self.assertNotIn("/Users/", doc_text)
        for required_text in (
            "documentation-only changes",
            "static test",
            "related tests",
            "no relevant static test exists",
            "Markdown-link verification",
            "changed-file scope",
            "git diff --check",
            "independent diff review",
        ):
            with self.subTest(required_text=required_text):
                self.assertIn(required_text, sd008)


class Batch2DocumentationConsistencyTest(unittest.TestCase):
    """BL-014 Batch 2 (docs/bl014-batch2-classification): static consistency
    checks over BACKLOG.md / DECISIONS.md / STATUS.md / BACKLOG_AUDIT.md.
    Documentation-only; does not exercise fetch.py/daily_json.py behavior.
    """

    ROOT = Path(__file__).resolve().parent

    def _read(self, name):
        return (self.ROOT / name).read_text(encoding="utf-8")

    @staticmethod
    def _headings(text):
        headings = []
        for line in text.splitlines():
            match = re.match(r"^(#{1,6})\s+(.*)$", line)
            if match:
                headings.append(match.group(2).strip())
        return headings

    @staticmethod
    def _slugify(heading_text):
        # Mirrors GitHub's heading-anchor algorithm closely enough for this
        # repository's headings: lowercase, drop characters that are not
        # alphanumeric (any script)/space/hyphen/underscore, then turn each
        # remaining space into a hyphen (adjacent removed punctuation can
        # therefore produce a double hyphen, matching existing anchors like
        # "#bl-002--記事カードの楕円バッジ多用を見直す").
        lowered = heading_text.strip().lower()
        kept = [ch for ch in lowered if ch.isalnum() or ch in (" ", "-", "_")]
        return "".join(kept).replace(" ", "-")

    def test_bl_ids_are_unique_and_cover_bl001_to_bl018(self):
        text = self._read("BACKLOG.md")
        bl_headings = [h for h in self._headings(text) if re.match(r"^BL-\d{3}\b", h)]
        ids = [re.match(r"^(BL-\d{3})", h).group(1) for h in bl_headings]
        self.assertEqual(len(ids), len(set(ids)), f"Duplicate BL section headings: {ids}")
        self.assertEqual(set(ids), {f"BL-{n:03d}" for n in range(1, 19)})

    def test_sd_ids_are_unique_and_cover_sd001_to_sd016(self):
        text = self._read("DECISIONS.md")
        sd_headings = [h for h in self._headings(text) if re.match(r"^SD-\d{3}\b", h)]
        ids = [re.match(r"^(SD-\d{3})", h).group(1) for h in sd_headings]
        self.assertEqual(len(ids), len(set(ids)), f"Duplicate SD section headings: {ids}")
        self.assertEqual(set(ids), {f"SD-{n:03d}" for n in range(1, 17)})

    def test_bl_001_completion_status_and_evidence(self):
        text = self._read("BACKLOG.md")
        start = text.index("## BL-001")
        end = text.index("## BL-002", start)
        bl001_text = text[start:end]
        self.assertIn("- **状態:** 完了", bl001_text)
        self.assertIn("[PR #26](https://github.com/matkei31/security-digest/pull/26)", bl001_text)
        self.assertIn("f5bbd04f42643d4a87f999d01f538d574fe39f17", bl001_text)
        self.assertIn("- **残作業:** なし。", bl001_text)

        status_text = self._read("STATUS.md")
        recently_completed = status_text[
            status_text.index("## 5. Recently completed work"):status_text.index("## 6. Known issues and limitations")
        ]
        known_issues = status_text[
            status_text.index("## 6. Known issues and limitations"):status_text.index("## 7. Next candidates")
        ]
        next_candidates = status_text[
            status_text.index("## 7. Next candidates"):status_text.index("## 8. Sources of truth")
        ]
        self.assertIn("BL-001", recently_completed)
        self.assertIn("[PR #26](https://github.com/matkei31/security-digest/pull/26)", recently_completed)
        self.assertNotIn("BL-001", known_issues)
        self.assertNotIn("BL-001", next_candidates)
        self.assertIn("1. [BL-005]", next_candidates)

    def test_bl_016_status_and_evidence(self):
        text = self._read("BACKLOG.md")
        start = text.index("## BL-016")
        end = text.index("## BL-017", start)
        bl016_text = text[start:end]
        self.assertIn("- **状態:** 完了", bl016_text)
        self.assertIn("[PR #9](https://github.com/matkei31/security-digest/pull/9)", bl016_text)
        self.assertIn("82b23c720b5871c5f46d068813defc12af164e4a", bl016_text)
        self.assertIn("[PR #23](https://github.com/matkei31/security-digest/pull/23)", bl016_text)
        self.assertIn("b8c0ab0fa5411930fc55b1b9f97cfda016c29373", bl016_text)
        self.assertIn("「新しい表示もPC・390px・過去ダイジェストとも問題なし」", bl016_text)
        self.assertIn("- **残作業:** なし。", bl016_text)

    def test_bl_017_completion_status_scope_and_user_wording(self):
        text = self._read("BACKLOG.md")
        start = text.index("## BL-017")
        end = text.index("## BL-018", start)
        bl017_text = text[start:end]
        self.assertIn("## BL-017 — 過去ダイジェストの回遊性と一覧表示を改善する", bl017_text)
        self.assertIn("- **状態:** 完了", bl017_text)
        self.assertIn(
            "- **ユーザー原文:** 「あと、過去のダイジェストについて、ワンクリックで前日分とかに行き来できる改修はこれから？」",
            bl017_text,
        )
        self.assertIn(
            "- **追加のユーザー原文:** 「だけど、この画面で「本日の要点あり」の記載は必要かな？不要な気がする」",
            bl017_text,
        )
        self.assertIn("`brief_status`生成を削除", bl017_text)
        self.assertIn("[PR #24](https://github.com/matkei31/security-digest/pull/24)", bl017_text)
        self.assertIn("8cb8e95639d125fec31057737bb4c445252433f7", bl017_text)
        expected_acceptance = (
            "「読み直したらできたわ。以下どちらも完了でOK\n"
            "\n"
            "\n"
            "過去ダイジェスト一覧\n"
            "「本日の要点あり／なし」が消え、日付・記事数・重要度だけになっているか\n"
            "7月14日など途中の日別ページ\n"
            "上部と最下部に「前のダイジェスト」「次のダイジェスト」があり、実際に移動できるか」"
        )
        self.assertIn(expected_acceptance, bl017_text)
        self.assertIn("- **残作業:** なし。", bl017_text)

        status_text = self._read("STATUS.md")
        recently_completed = status_text[
            status_text.index("## 5. Recently completed work"):status_text.index("## 6. Known issues and limitations")
        ]
        known_issues = status_text[
            status_text.index("## 6. Known issues and limitations"):status_text.index("## 7. Next candidates")
        ]
        next_candidates = status_text[
            status_text.index("## 7. Next candidates"):status_text.index("## 8. Sources of truth")
        ]
        self.assertIn("BL-017", recently_completed)
        self.assertIn("[PR #24](https://github.com/matkei31/security-digest/pull/24)", recently_completed)
        self.assertNotIn("BL-017", known_issues)
        self.assertNotIn("BL-017", next_candidates)
        self.assertIn("1. [BL-005]", next_candidates)
        self.assertNotRegex(next_candidates, r"(?m)^2\. ")

    def test_bl_018_completion_status_and_evidence(self):
        text = self._read("BACKLOG.md")
        start = text.index("## BL-018")
        end = text.index("## 完了済み参照", start)
        bl018_text = text[start:end]
        self.assertIn("- **状態:** 完了", bl018_text)
        self.assertIn("- **出所種別:** 技術上の発見事項", bl018_text)
        self.assertIn("UTC-naive", bl018_text)
        self.assertIn("JST aware", bl018_text)
        self.assertIn("`normalize_datetime_for_display()`", bl018_text)
        self.assertIn("`format_article_meta_time()`", bl018_text)
        self.assertIn("[PR #28](https://github.com/matkei31/security-digest/pull/28)", bl018_text)
        self.assertIn("196c77bcc2b71f8aecd9d0c6aef03388ffd5edf1", bl018_text)
        self.assertIn(
            "「トップページの時刻はWP2Shellが07/18 06:20、Gold Eagle Clearinghouseが07/17 22:00で、記事順・本文も問題なし。」",
            bl018_text,
        )
        self.assertIn("- **残作業:** なし。", bl018_text)

        status_text = self._read("STATUS.md")
        recently_completed = status_text[
            status_text.index("## 5. Recently completed work"):status_text.index("## 6. Known issues and limitations")
        ]
        known_issues = status_text[
            status_text.index("## 6. Known issues and limitations"):status_text.index("## 7. Next candidates")
        ]
        next_candidates = status_text[
            status_text.index("## 7. Next candidates"):status_text.index("## 8. Sources of truth")
        ]
        self.assertIn("BL-018", recently_completed)
        self.assertIn("[PR #28](https://github.com/matkei31/security-digest/pull/28)", recently_completed)
        self.assertNotIn("BL-018", known_issues)
        self.assertNotIn("BL-018", next_candidates)

    def test_sd_015_records_trusted_context_allowlist_decision(self):
        text = self._read("DECISIONS.md")
        start = text.index("## SD-015")
        sd015_text = text[start:]
        self.assertIn("- **Status:** Accepted / Implemented", sd015_text)
        self.assertIn("recent_kev_additions", sd015_text)
        self.assertIn("allowlist", sd015_text)
        self.assertIn("[PR #8](https://github.com/matkei31/security-digest/pull/8)", sd015_text)
        self.assertIn("d1518910cd1a685cffc5d526ec65f6e708a4d535", sd015_text)

    def test_bl_005_original_wording_still_not_recovered(self):
        text = self._read("BACKLOG.md")
        start = text.index("## BL-005")
        end = text.index("## BL-006", start)
        bl005_text = text[start:end]
        self.assertIn("- **状態:** 仕様化済み / 未実装", bl005_text)
        self.assertIn("- **ユーザー原文:** 原文未回収。", bl005_text)

    def test_completed_reference_covers_batch2_prs(self):
        text = self._read("BACKLOG.md")
        start = text.index("## 完了済み参照")
        completed_text = text[start:]
        for merge_sha in (
            "d1518910cd1a685cffc5d526ec65f6e708a4d535",  # PR #8
            "8f6c5dfdcfc2113cba410a7059d230026d6d1a7a",  # PR #1
            "a8b551818443f2ca9deb2df160fc661aab8faf77",  # PR #2
            "d90fa3986a541aafbdf76bc6e6b4d8f0130ed19c",  # PR #3
        ):
            with self.subTest(merge_sha=merge_sha):
                self.assertIn(merge_sha, completed_text)
        # PR #6 (Ticket 15a) is intentionally not a Completed reference entry
        # (recorded instead as Historical/Superseded in BACKLOG_AUDIT.md).
        self.assertNotIn("4daab96b6e78a3fcf9bfb30c1d3dc0a2d7c424c3", completed_text)

    def test_backlog_audit_batch2_section_present(self):
        text = self._read("BACKLOG_AUDIT.md")
        for required_text in (
            "## Batch 2 — 2026-07-18",
            "149",
            "PRE-00",
            "PRE-20",
            "Ticket 15a / PR #6",
            "Ticket 5 / Ticket 7 / Ticket 11b",
        ):
            with self.subTest(required_text=required_text):
                self.assertIn(required_text, text)

    def test_no_local_absolute_paths_leaked(self):
        for doc_name in ("BACKLOG.md", "STATUS.md", "DECISIONS.md", "BACKLOG_AUDIT.md", "AGENTS.md"):
            text = self._read(doc_name)
            with self.subTest(doc=doc_name):
                self.assertNotIn("/Users/", text)
                self.assertNotIn("bl014-audit-batch2", text)

    def test_internal_markdown_anchors_resolve(self):
        doc_names = ("BACKLOG.md", "STATUS.md", "DECISIONS.md", "BACKLOG_AUDIT.md")
        docs = {name: self._read(name) for name in doc_names}
        anchor_sets = {
            name: {self._slugify(h) for h in self._headings(text)}
            for name, text in docs.items()
        }
        link_pattern = re.compile(r"\]\((?:([A-Za-z0-9_.\-]+\.md))?#([^)\s]+)\)")
        for name, text in docs.items():
            for match in link_pattern.finditer(text):
                target_file = match.group(1) or name
                anchor = match.group(2)
                with self.subTest(doc=name, link=f"{target_file}#{anchor}"):
                    self.assertIn(
                        target_file, anchor_sets,
                        f"{name} links to unknown file {target_file}",
                    )
                    self.assertIn(
                        anchor, anchor_sets[target_file],
                        f"{name} links to #{anchor} in {target_file}, which has no matching heading",
                    )


if __name__ == "__main__":
    unittest.main()
