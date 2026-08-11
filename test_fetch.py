#!/usr/bin/env python3
"""
HTMLエスケープ・URL検証の回帰テスト (Ticket 1)
標準ライブラリの unittest のみを使用する。
"""

import datetime
import hashlib
import json
import os
import re
import tempfile
from html.parser import HTMLParser
from pathlib import Path
from unittest.mock import patch
import unittest

import document_test_history as dth
import document_test_inventory as dti
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
        self.assertIn("概要", html)
        self.assertIn("CISAが悪用確認済み脆弱性をKEVへ追加した。", html)
        self.assertIn("金融機関との関連", html)
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
        self.assertLess(card.index('class="article-assessment"'), card.index("概要"))
        self.assertLess(card.index("概要"), card.index("金融機関との関連"))
        self.assertLess(card.index("金融機関との関連"), card.index("確認すべきこと"))
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
        self.assertIn('<h3 class="brief-section-title">概況</h3>', segment)
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
        # itemsが未評価のため、保存済みdiscussion_pointsをlegacy見出し
        # 「注目論点」でverbatim表示する(BL-029のfallback経路)。
        html = fetch.build_html([self._make_item()], SAMPLE_BRIEF)
        segment = brief_segment(html)
        self.assertIn('<h3 class="brief-section-title">注目論点</h3>', segment)
        for text in SAMPLE_BRIEF["discussion_points"]:
            self.assertIn(f"<li>{text}</li>", segment)

    def test_extractive_brief_uses_financial_relevance_heading(self):
        # BL-029: 重要・優先事項はitems[].ai_analysisから常に再構成するため、
        # 保存済みprompt_versionが旧today-brief-extractive-v1でも、記事分析が
        # 有効な限り新しい「重要・優先事項」見出しと2段落構造が再現される。
        item = dict(
            self._make_item(),
            ai_analysis={
                "status": "success", "importance": "高", "urgency": "本日確認",
                "summary": "SUMMARY_X", "financial_impact": "IMPACT_X",
                "recommended_actions": [],
            },
            ai_analysis_meta={"status": "success"},
        )
        brief = dict(SAMPLE_BRIEF)
        brief["prompt_version"] = "today-brief-extractive-v1"
        html = fetch.build_html([item], brief)
        segment = brief_segment(html)
        self.assertIn('<h3 class="brief-section-title">重要・優先事項</h3>', segment)
        self.assertIn('<p class="brief-priority-summary">SUMMARY_X</p>', segment)
        self.assertIn('<p class="brief-priority-impact">IMPACT_X</p>', segment)
        self.assertNotIn(
            '<h3 class="brief-section-title">注目論点</h3>',
            segment,
        )
        self.assertNotIn("金融機関との関連", segment)

    def test_unreconstructable_archive_falls_back_to_legacy_heading_without_mutation(self):
        # BL-029: items[].ai_analysisが評価済みでない(=再構成不能)場合だけ、
        # 保存済みdiscussion_pointsを見出し「注目論点」でverbatim表示する。
        # prompt_versionの値には依存しない(v3・extractive-v1いずれでも同じ)。
        brief = dict(SAMPLE_BRIEF)
        brief["prompt_version"] = "today-brief-v3"
        before = json.dumps(brief, ensure_ascii=False, sort_keys=True)
        html = fetch.build_html([self._make_item()], brief)
        segment = brief_segment(html)
        self.assertIn('<h3 class="brief-section-title">注目論点</h3>', segment)
        for text in brief["discussion_points"]:
            self.assertIn(f"<li>{text}</li>", segment)
        self.assertNotIn('<h3 class="brief-section-title">重要・優先事項</h3>', segment)
        self.assertNotIn("金融機関との関連", segment)
        self.assertEqual(
            json.dumps(brief, ensure_ascii=False, sort_keys=True),
            before,
        )

    def test_check_items_render_as_list(self):
        html = fetch.build_html([self._make_item()], SAMPLE_BRIEF)
        segment = brief_segment(html)
        self.assertIn('<h3 class="brief-section-title">確認事項</h3>', segment)
        for text in SAMPLE_BRIEF["check_items"]:
            self.assertIn(f"<li>{text}</li>", segment)

    def test_empty_array_section_is_not_rendered(self):
        brief = dict(SAMPLE_BRIEF, discussion_points=[])
        html = fetch.build_html([self._make_item()], brief)
        segment = brief_segment(html)
        self.assertNotIn("注目論点", segment)
        self.assertNotIn("重要・優先事項", segment)
        overview = segment[segment.index("概況"):segment.index("確認事項")]
        self.assertNotIn("<ul", overview)  # overviewセクションにulがないこと

    def test_check_items_empty_section_is_not_rendered(self):
        brief = dict(SAMPLE_BRIEF, check_items=[])
        html = fetch.build_html([self._make_item()], brief)
        segment = brief_segment(html)
        self.assertNotIn("確認事項", segment)
        self.assertIn('<h3 class="brief-section-title">注目論点</h3>', segment)

    def test_both_discussion_points_and_check_items_empty(self):
        brief = dict(SAMPLE_BRIEF, discussion_points=[], check_items=[])
        html = fetch.build_html([self._make_item()], brief)
        segment = brief_segment(html)
        self.assertNotIn("注目論点", segment)
        self.assertNotIn("重要・優先事項", segment)
        self.assertNotIn("確認事項", segment)
        self.assertNotIn("<ul", segment)
        self.assertNotIn('<ul class="brief-list"></ul>', segment)

    def test_only_discussion_points_present_check_items_section_absent(self):
        brief = dict(SAMPLE_BRIEF, check_items=[])
        html = fetch.build_html([self._make_item()], brief)
        segment = brief_segment(html)
        self.assertIn('<h3 class="brief-section-title">注目論点</h3>', segment)
        self.assertNotIn("確認事項", segment)
        self.assertEqual(segment.count("<ul"), 1)

    def test_only_check_items_present_discussion_points_section_absent(self):
        brief = dict(SAMPLE_BRIEF, discussion_points=[])
        html = fetch.build_html([self._make_item()], brief)
        segment = brief_segment(html)
        self.assertNotIn("注目論点", segment)
        self.assertNotIn("重要・優先事項", segment)
        self.assertIn('<h3 class="brief-section-title">確認事項</h3>', segment)
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
        self.assertNotIn("注目論点", segment)
        self.assertNotIn("重要・優先事項", segment)
        self.assertNotIn("確認事項", segment)

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
        # BL-034: 唯一許容するコメントはCloudflare Web Analyticsの静的な
        # documentedコメントのみであり、BRIEF由来の内容が(意図せず)コメント
        # として紛れ込んでいないことを確認する。
        html = fetch.build_html([self._make_item()], SAMPLE_BRIEF)
        comments = re.findall(r"<!--(.*?)-->", html, re.DOTALL)
        self.assertEqual(
            comments,
            [" Cloudflare Web Analytics ", " End Cloudflare Web Analytics "],
        )

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
        self.assertNotIn("概況", segment)
        self.assertNotIn("brief-status-line", segment)

    def test_none_overview_produces_no_overview_section_without_exception(self):
        brief = dict(SAMPLE_BRIEF, overview=None)
        html = fetch.build_html([self._make_item()], brief)
        segment = brief_segment(html)
        self.assertNotIn("概況", segment)
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

    def test_only_the_documented_cloudflare_beacon_script_is_emitted(self):
        # BL-034: Cloudflare Web Analyticsのmanual beaconのみを許容する。
        # inline JS(onclick等)や、それ以外のscriptタグは引き続き無い。
        html = fetch.build_html([self._make_item()], SAMPLE_BRIEF)
        self.assertEqual(html.count("<script"), 1)
        self.assertIn(
            "src='https://static.cloudflareinsights.com/beacon.min.js'", html
        )
        self.assertIn(fetch.CLOUDFLARE_WEB_ANALYTICS_BEACON_TOKEN, html)
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
        # BL-028: anchor-offset raised for the two-row nav on both PC and 390px.
        self.assertIn("--anchor-offset:218px", html)
        self.assertIn("--anchor-offset:226px", html)
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

    def test_extractive_brief_makes_no_request_and_does_not_project_facts(self):
        # BL-021: BRIEF production経路はHTTP request自体を発生させず、
        # ARTICLE分析の許可fieldだけをpublic resultへprojectする。
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

        with patch.dict(os.environ, {"GEMINI_API_KEY": "test-key-not-real"}):
            with patch(
                "fetch.urllib.request.urlopen",
                side_effect=AssertionError("BRIEF HTTP must be unreachable"),
            ):
                result = fetch.build_todays_brief([item])

        self.assertEqual(result["status"], "success")
        self.assertEqual(result["important_highlights"], ["テスト要約文です。"])
        self.assertEqual(result["discussion_points"], ["テスト要約文です。\nテスト影響文です。"])
        self.assertEqual(result["check_items"], ["UNIQUE-RECOMMENDED-ACTION-MARKER"])
        public_result = json.dumps(result, ensure_ascii=False)

        # item["facts"]内の固有値は1つも含まれないことを確認する
        for leaked_value in (
            unique_cve, str(unique_score), unique_severity, unique_vector,
            unique_url, unique_date_added,
        ):
            self.assertNotIn(
                leaked_value, public_result,
                f"{leaked_value!r} leaked into extractive Brief result",
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

    def test_timeout_and_python_version_unchanged(self):
        text = self._workflow_text()
        self.assertIn("timeout-minutes: 20", text)
        self.assertIn("python-version: '3.12'", text)

    def test_production_checkout_and_setup_python_are_pinned_to_v7(self):
        # BL-027: combined major upgrade, both Actions pinned to the same
        # verified full commit SHA used in pr-ci.yml.
        text = self._workflow_text()
        self.assertIn(
            "uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1",
            text,
        )
        self.assertIn(
            "uses: actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97 # v7.0.0",
            text,
        )

    def test_production_has_workflow_level_serialized_concurrency(self):
        # BL-026 / GAP-004: scheduled and manual production runs must not race,
        # and an in-flight production run must not be cancelled by a new one.
        text = self._workflow_text()
        self.assertRegex(
            text,
            r"(?m)^concurrency:\n  group: daily-security-digest-production\n"
            r"  cancel-in-progress: false$",
        )
        # The concurrency block must be workflow-level (before `jobs:`), not job-level.
        self.assertLess(text.index("concurrency:"), text.index("jobs:"))
        self.assertEqual(text.count("concurrency:"), 1)
        # The group must not vary by branch or run id, so scheduled and
        # workflow_dispatch runs always share the same serialization queue.
        self.assertNotIn("github.ref", text.split("concurrency:", 1)[1].split("jobs:", 1)[0])
        self.assertNotIn("github.run_id", text.split("concurrency:", 1)[1].split("jobs:", 1)[0])

    def test_production_concurrency_group_differs_from_pr_ci(self):
        production = self._workflow_text()
        pull_request = (
            Path(__file__).resolve().parent / ".github" / "workflows" / "pr-ci.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("group: daily-security-digest-production", production)
        self.assertIn("group: pr-ci-${{ github.event.pull_request.number }}", pull_request)


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
            "BL-019",
            "BL-020",
            "BL-021",
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
        item_ids = [f"BL-{number:03d}" for number in range(1, 22)]
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

    def test_bl_ids_are_unique_and_cover_bl001_to_bl038(self):
        text = self._read("BACKLOG.md")
        bl_headings = [h for h in self._headings(text) if re.match(r"^BL-\d{3}\b", h)]
        ids = [re.match(r"^(BL-\d{3})", h).group(1) for h in bl_headings]
        self.assertEqual(len(ids), len(set(ids)), f"Duplicate BL section headings: {ids}")
        self.assertEqual(set(ids), {f"BL-{n:03d}" for n in range(1, 39)})

    def test_sd_ids_are_unique_and_cover_sd001_to_sd033(self):
        text = self._read("DECISIONS.md")
        sd_headings = [h for h in self._headings(text) if re.match(r"^SD-\d{3}\b", h)]
        ids = [re.match(r"^(SD-\d{3})", h).group(1) for h in sd_headings]
        self.assertEqual(len(ids), len(set(ids)), f"Duplicate SD section headings: {ids}")
        self.assertEqual(set(ids), {f"SD-{n:03d}" for n in range(1, 34)})

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
        self.assertNotIn("[BL-022]", next_candidates)

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
        self.assertNotIn("[BL-022]", next_candidates)
        self.assertNotRegex(next_candidates, r"(?m)^1\. \[BL-026\]")
        self.assertIn("[BL-026]", next_candidates)
        self.assertIn("are all complete", next_candidates)
        self.assertIn("so none is named as the ranked next candidate purely by priority number", next_candidates)
        self.assertIn("[BL-027]", next_candidates)
        self.assertNotIn("[BL-025]", next_candidates)

    def test_bl_018_completion_status_and_evidence(self):
        text = self._read("BACKLOG.md")
        start = text.index("## BL-018")
        end = text.index("## BL-019", start)
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

    def test_bl_019_and_bl_020_completion_records(self):
        text = self._read("BACKLOG.md")
        start = text.index("## BL-019")
        end = text.index("## BL-020", start)
        bl019_text = text[start:end]
        self.assertIn("- **状態:** 完了", bl019_text)
        self.assertIn("- **出所種別:** 技術上の発見事項", bl019_text)
        self.assertIn("- **ユーザー原文:** 該当なし — 技術上の発見事項", bl019_text)
        self.assertIn("[PR #32](https://github.com/matkei31/security-digest/pull/32)", bl019_text)
        self.assertIn("d08a1b00d43488892ba6ef74b184340ab14a72c0", bl019_text)
        self.assertIn("「うん。バックログに入れるなりしてどこかで直せるように管理しよう。んで、次進もう」", bl019_text)
        self.assertIn("- **残作業:** なし。", bl019_text)

        bl020_text = text[text.index("## BL-020"):text.index("## BL-021", text.index("## BL-020"))]
        self.assertIn("- **状態:** 完了", bl020_text)
        self.assertIn("- **出所種別:** ユーザー原文 / ユーザー確認済み要約", bl020_text)
        self.assertIn("「なんで色分けしてるんだっけ？」", bl020_text)
        self.assertIn("「うん。バックログに入れるなりしてどこかで直せるように管理しよう。んで、次進もう」", bl020_text)
        self.assertIn("取得元別inline backgroundを削除", bl020_text)
        self.assertIn("[UI_SPEC.md](UI_SPEC.md) Version 1.3", bl020_text)
        self.assertIn("[SD-023]", bl020_text)
        self.assertIn("enabledな15ソースの集合、定義順", bl020_text)
        self.assertIn("repository-external `BL-020/neutral-source-footer/`", bl020_text)
        self.assertIn("[PR #41](https://github.com/matkei31/security-digest/pull/41)", bl020_text)
        self.assertIn("関連33 tests、full unittest 1156 tests", bl020_text)
        self.assertIn("f6990564de8f84dabdd2e614a7fe72996cf961fe", bl020_text)
        self.assertIn("1d55897e1241138d6bbb0bd2bd2381e10bc05f2e", bl020_text)
        self.assertIn("d16a2ce28c05a2381d98ed3dbb28599ebd317b7b", bl020_text)
        self.assertIn("Pull Request CI run 30068786053", bl020_text)
        self.assertIn("Pages deployment run 30068840298", bl020_text)
        self.assertIn("productionの表示変更は完了", bl020_text)
        self.assertIn("「この表示でOK、進めて」", bl020_text)
        self.assertIn("ユーザーが確認したのはmerge前の生成screenshots", bl020_text)
        self.assertIn("公開PagesはWorkが客観確認", bl020_text)
        self.assertIn("公開表示が受入済みscreenshotsと一致", bl020_text)
        self.assertIn("browser標準focus表示", bl020_text)
        self.assertIn("ユーザーが公開サイトを目視したとは記録しない", bl020_text)
        self.assertIn("- **残作業:** なし。", bl020_text)

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
        self.assertIn("BL-019", recently_completed)
        self.assertIn("without reopening BL-019", recently_completed)
        self.assertNotIn("BL-019", known_issues)
        self.assertNotIn("BL-019", next_candidates)
        self.assertNotIn("BL-020", known_issues)
        self.assertNotRegex(next_candidates, r"(?m)^\d+\. \[BL-020\]")
        self.assertNotIn("[BL-022]", next_candidates)
        self.assertNotIn("BL-020", next_candidates)
        self.assertRegex(recently_completed, r"(?m)^- BL-020 neutral source-footer list")
        self.assertIn("Pull Request CI run 30068786053", recently_completed)
        self.assertIn("Pages deployment run 30068840298", recently_completed)
        self.assertIn("the user did not review the public site", recently_completed)
        self.assertIn("No residual work remains", recently_completed)
        self.assertIn("| ARTICLE prompt | `article-analysis-v8` |", status_text)
        self.assertIn("| BRIEF composition contract on `main` | `today-brief-extractive-v2` |", status_text)
        self.assertIn("| BRIEF model on `main` | `deterministic-extractive` |", status_text)

        decisions = self._read("DECISIONS.md")
        sd023 = decisions[decisions.index("## SD-023"):]
        self.assertIn("- **Status:** Accepted / Implemented and verified in production", sd023)
        self.assertIn("same achromatic, low-emphasis plain-text `ul`／`li` contract", sd023)
        self.assertIn("`SOURCE_COLORS` and its compatibility builder are removed", sd023)
        self.assertIn("[PR #41](https://github.com/matkei31/security-digest/pull/41)", sd023)
        self.assertIn("Pull Request CI run 30068786053", sd023)
        self.assertIn("Pages deployment run 30068840298", sd023)
        self.assertIn("「この表示でOK、進めて」", sd023)
        self.assertIn("Work objectively verified the public top page", sd023)
        self.assertIn("The user did not review the public site", sd023)
        self.assertIn("does not supersede SD-013's ordinary-card variant B", sd023)
        self.assertIn("any part of BL-019's count, enabled-source set, or definition-order contract", sd023)

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
        self.assertIn("- **状態:** 実装試行済み（v4/v5/v6）／No-Go／main未反映", bl005_text)
        self.assertIn("- **ユーザー原文:** 原文未回収。", bl005_text)

    def test_bl_005_no_go_closure_records_experiments_and_bl021_handoff(self):
        text = self._read("BACKLOG.md")
        start = text.index("## BL-005")
        end = text.index("## BL-006", start)
        bl005_text = text[start:end]
        for experiment_commit in (
            "2f35df1ead9255b441bfa17fb80f337ce4649052",
            "b2061d6f54005d16f19bc3838c95996f89b313b5",
            "a722d5471c91ba17e700b7fdb53133ad0f1f43bb",
            "a97a9e9c2de05346ae0f1855b6d92143db21739e",
        ):
            with self.subTest(commit=experiment_commit):
                self.assertIn(experiment_commit, bl005_text)
        self.assertIn("local-only", bl005_text)
        self.assertIn("[BL-021]", bl005_text)
        self.assertIn("[SD-017]", bl005_text)
        self.assertNotIn("/Users/", bl005_text)

    def test_bl_021_records_phase1_no_go_and_completed_extractive_state(self):
        backlog = self._read("BACKLOG.md")
        bl021 = backlog[backlog.index("## BL-021"):backlog.index("## BL-022")]
        self.assertIn("- **状態:** 完了", bl021)
        self.assertIn("v1/v2を本番採用しない", bl021)
        self.assertIn("追加prompt調整は終了", bl021)
        self.assertIn("today-brief-extractive-v1", bl021)
        self.assertIn("[PR #35](https://github.com/matkei31/security-digest/pull/35)", bl021)
        self.assertIn("d1755d413cd554d6905715af26521e9e3169001c", bl021)
        self.assertIn("30012552188", bl021)
        self.assertIn("1afbd0e7f5b008ea3051af676e57fb2951b648ed", bl021)
        self.assertIn("30012791302", bl021)
        self.assertIn("BL-021を正式完了として扱い、次の作業へ進む整理", bl021)
        self.assertIn("ユーザーは「ok」、続けて「ok,go」と応答した", bl021)
        self.assertNotIn("ユーザー受入済みとして『完了』へ更新する", bl021)
        self.assertIn("- **残作業:** なし。", bl021)

        decisions = self._read("DECISIONS.md")
        sd018 = decisions[decisions.index("## SD-018"):decisions.index("## SD-019")]
        self.assertIn(
            "- **Status:** Accepted / Implemented and verified in production",
            sd018,
        )
        self.assertIn("semantic validator as a blocking production gate", sd018)
        self.assertIn("does not newly guarantee that the ARTICLE analysis itself is factually correct", sd018)
        self.assertIn("d1755d413cd554d6905715af26521e9e3169001c", sd018)
        self.assertIn("user acceptance were completed on 2026-07-23", sd018)

        status = self._read("STATUS.md")
        self.assertIn("| BRIEF composition contract on `main` | `today-brief-extractive-v2` |", status)
        self.assertIn("| BRIEF model on `main` | `deterministic-extractive` |", status)
        self.assertIn("| ARTICLE Gemini model | `gemini-2.5-flash` |", status)
        self.assertIn("BL-021は2026-07-23にユーザー受入済みとして完了", status)

    def test_bl_022_and_bl_023_preserve_requested_scope(self):
        backlog = self._read("BACKLOG.md")
        bl022 = backlog[backlog.index("## BL-022"):backlog.index("## BL-023")]
        self.assertIn(
            "- **状態:** 完了",
            bl022,
        )
        self.assertIn("現在の「過去のダイジェストを見る」に加え", bl022)
        self.assertIn("日付欠落時のリンク先仕様は実装前に整理", bl022)
        self.assertIn("UIの小規模Ticketとして扱う", bl022)
        self.assertIn("左上に「←　前日のダイジェスト」", bl022)
        self.assertIn("「前のダイジェスト」に統一でいいんじゃないかな", bl022)
        self.assertIn("うん。いいと思うよ。他の修正の方向性もok", bl022)
        self.assertIn("前方向「← 前のダイジェスト」", bl022)
        self.assertIn("次方向「次のダイジェスト →」", bl022)
        self.assertIn("最新ページ「最新のダイジェスト」", bl022)
        self.assertIn("一覧「過去のダイジェスト」", bl022)
        self.assertIn("改訂後画面をユーザーが目視済みとは記録しない", bl022)
        self.assertIn("[PR #38](https://github.com/matkei31/security-digest/pull/38)", bl022)
        self.assertIn("85e1b3e3cd4bb3c8927c9b1608652c77a9ebb6e9", bl022)
        self.assertIn("[Pages deployment run 30061770611]", bl022)
        self.assertIn("- **残作業:** なし。", bl022)

        bl023 = backlog[backlog.index("## BL-023"):backlog.index("## 完了済み参照")]
        self.assertIn("- **状態:** 保留／prompt-only改善No-Go／production変更なし", bl023)
        self.assertIn("自明な断り書きを出力しない", bl023)
        self.assertIn("recommended_actionsにはCVE IDを原則含めない", bl023)
        self.assertIn("CVE IDはtitle、summary、facts等の識別用途では維持", bl023)
        self.assertIn("Brief側の後処理やCVE文字列削除は行わない", bl023)
        self.assertIn("単純な禁止語・語彙ルールにはしない", bl023)
        self.assertIn("固定15 fixture", bl023)
        self.assertIn("2 logical runs・30 attempts・retry 0", bl023)
        self.assertIn("Technical GateはPASS", bl023)
        self.assertIn("`article-analysis-v10`固定候補", bl023)
        self.assertIn("17 fixture", bl023)
        self.assertIn("2 logical runs・34 attempts・retry 0", bl023)
        self.assertIn("HTTP 200およびschema parseは34/34", bl023)
        self.assertIn("financial_impact Gate、Safety／Non-regression Gate", bl023)
        self.assertIn("mandatory Zimbra／NCSC記事はFAIL", bl023)
        self.assertIn("technical error・field欠落・内部識別子漏えいは0件", bl023)
        self.assertIn("v10候補は採用・実装せず、repository変更は0件", bl023)
        self.assertIn("評価結果を受けた追加prompt調整も行わない", bl023)
        self.assertIn("今回固定したv10候補に限定", bl023)
        self.assertIn("promptによる改善一般を不可能とは判断しない", bl023)
        self.assertIn("BL-023/article-financial-impact-v10-screening/", bl023)
        self.assertIn("productionは`article-analysis-v8`を維持", bl023)

        decisions = self._read("DECISIONS.md")
        sd019 = decisions[decisions.index("## SD-019"):decisions.index("## SD-020")]
        self.assertIn("- **Status:** Accepted / No-Go", sd019)
        self.assertIn("15 fixtures in 2 logical runs (30 attempts, no retry)", sd019)
        self.assertIn("Production remains on `article-analysis-v8`", sd019)
        self.assertIn("generic regex deletion", sd019)
        self.assertIn("facts-based, narrowly bounded deterministic composition", sd019)

        status = self._read("STATUS.md")
        self.assertIn("BL-022 digest navigation wording and layout", status)
        self.assertIn("[BL-023]", status)
        recently_completed = status[
            status.index("## 5. Recently completed work"):
            status.index("## 6. Known issues and limitations")
        ]
        known_issues = status[
            status.index("## 6. Known issues and limitations"):
            status.index("## 7. Next candidates")
        ]
        next_candidates = status[
            status.index("## 7. Next candidates"):
            status.index("## 8. Sources of truth")
        ]
        self.assertIn("BL-022 digest navigation wording and layout", recently_completed)
        self.assertNotIn("[BL-022]", known_issues)
        self.assertNotIn("[BL-022]", next_candidates)
        self.assertIn("prompt-only改善はNo-Goとして保留", status)
        self.assertIn("`article-analysis-v10`固定候補は17 fixture", status)
        self.assertIn("2 logical runs・34 attempts・retry 0", status)
        self.assertIn("HTTP 200／schema parseが34/34", status)
        self.assertIn("mandatory Zimbra／NCSC記事はFAIL", status)
        self.assertIn("v10結果を受けた追加prompt調整は行わず", status)
        self.assertIn("今回固定した候補に限定", status)
        self.assertIn("prompt改善一般を不可能とは判断しない", status)
        self.assertIn("v9 and fixed-v10 prompt-only No-Go evaluations", next_candidates)
        self.assertNotIn("[BL-023]", recently_completed)

        sd020 = decisions[decisions.index("## SD-020"):decisions.index("## SD-021")]
        self.assertIn("Accepted / Implemented and verified in production", sd020)
        sd021 = decisions[decisions.index("## SD-021"):decisions.index("## SD-022")]
        self.assertIn("← 前のダイジェスト", sd021)
        self.assertIn("次のダイジェスト →", sd021)
        self.assertIn("最新のダイジェスト", sd021)
        self.assertIn("過去のダイジェスト", sd021)
        self.assertIn("validated earlier-date selection", sd021)
        self.assertIn("Accepted / Implemented and verified in production", sd021)
        self.assertIn("Pages deployment run 30061770611", sd021)

        sd022 = decisions[decisions.index("## SD-022"):decisions.index("## SD-023")]
        self.assertIn("- **Status:** Accepted / No-Go", sd022)
        self.assertIn("17 fixtures in 2 logical runs (34 attempts, no retry)", sd022)
        self.assertIn("HTTP 200 34/34", sd022)
        self.assertIn("schema parse 34/34", sd022)
        self.assertIn("Technical Gate PASS", sd022)
        self.assertIn("financial_impact Gate FAIL", sd022)
        self.assertIn("Safety／Non-regression Gate FAIL", sd022)
        self.assertIn("mandatory Zimbra／NCSC articles FAIL", sd022)
        self.assertIn("Production remains on `article-analysis-v8`", sd022)
        self.assertIn("no additional prompt adjustment", sd022)
        self.assertIn(
            "does not establish that simplification or prompt-based improvement is generally impossible",
            sd022,
        )
        self.assertIn("BL-023/article-financial-impact-v10-screening/", sd022)
        self.assertIn("SD-019を置換せず", sd022)

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


class Bl036ArticleAttributionCssTest(unittest.TestCase):
    """BL-036 (Fable 5 review R-01): `.article-attribution` gained a low-emphasis
    CSS rule in the shared <style> block. These tests check the specific rule
    values and the absence of pill/badge/alert-box styling, not the whole
    style block verbatim -- a future unrelated CSS edit elsewhere in the block
    should not need to touch this test.
    """

    @staticmethod
    def _style_block(html):
        return html.split("<style>", 1)[1].split("</style>", 1)[0]

    def test_article_attribution_rule_exists_exactly_once_with_expected_values(self):
        html = fetch.build_html([])
        style = self._style_block(html)
        self.assertEqual(style.count(".article-attribution{"), 1)
        rule = style.split(".article-attribution{", 1)[1].split("}", 1)[0]
        self.assertIn("margin-top:10px", rule)
        self.assertIn("font-size:10px", rule)
        self.assertIn("color:#768496", rule)
        self.assertIn("line-height:1.6", rule)
        self.assertIn("overflow-wrap:anywhere", rule)

    def test_article_attribution_link_rule_and_hover_exist(self):
        html = fetch.build_html([])
        style = self._style_block(html)
        self.assertEqual(style.count(".article-attribution a{"), 1)
        link_rule = style.split(".article-attribution a{", 1)[1].split("}", 1)[0]
        self.assertIn("color:#8b949e", link_rule)
        self.assertIn("text-decoration:underline", link_rule)

        self.assertEqual(style.count(".article-attribution a:hover{"), 1)
        hover_rule = style.split(".article-attribution a:hover{", 1)[1].split("}", 1)[0]
        self.assertIn("color:#79c0ff", hover_rule)

    def test_article_attribution_is_not_a_pill_badge_or_alert_box(self):
        html = fetch.build_html([])
        style = self._style_block(html)
        attribution_rules = "".join(
            style.split(selector, 1)[1].split("}", 1)[0]
            for selector in (
                ".article-attribution{", ".article-attribution a{",
                ".article-attribution a:hover{",
            )
        )
        for forbidden in ("background", "border", "border-radius", "padding", "font-weight:700"):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, attribution_rules)


class Bl037FinalAcceptanceRecordTest(unittest.TestCase):
    """BL-037 (Fable 5 whole-repository review R-13, pipeline E2E and
    repository data validation) final-acceptance documentation record:
    BACKLOG.md's BL-037 section and STATUS.md's Recently completed entry.
    Documentation-only; does not exercise fetch.py/daily_json.py behavior.
    These checks use substring/structural assertions, not full-paragraph
    verbatim locks.
    """

    ROOT = Path(__file__).resolve().parent

    def _read(self, name):
        return (self.ROOT / name).read_text(encoding="utf-8")

    def _bl037_section(self):
        backlog = self._read("BACKLOG.md")
        marker = "## BL-037 "
        start = backlog.index(marker)
        end = backlog.find("\n## ", start + len(marker))
        return backlog[start:] if end == -1 else backlog[start:end]

    def test_backlog_bl037_state_is_complete(self):
        bl037 = self._bl037_section()
        self.assertIn("- **状態:** 完了", bl037)
        self.assertNotIn("実装中／独立レビュー待ち", bl037)

    def test_backlog_bl037_records_final_acceptance_original_and_date(self):
        bl037 = self._bl037_section()
        self.assertIn("「ok」", bl037)
        self.assertIn("2026-08-04", bl037)
        # 着手時原文「おk」と最終受入原文「ok」は別発言として区別されている。
        self.assertIn("「おk」", bl037)
        self.assertIn("別の発言", bl037)

    def test_backlog_bl037_records_accepted_implementation_head_and_ci(self):
        bl037 = self._bl037_section()
        self.assertIn("d53e04a474d166144f28a50c07e656e27ed56192", bl037)
        self.assertIn("30886560785", bl037)
        self.assertIn("1670 tests OK", bl037)

    def test_backlog_bl037_records_round1_and_round2_evidence(self):
        bl037 = self._bl037_section()
        self.assertIn("5f30e1d04e9d48a9a6a1a9780e3bab4905a65842", bl037)
        self.assertIn("ef6964ed881dc48934a91a60e4c5c223b2fea20a", bl037)
        self.assertIn("30870986858", bl037)
        self.assertIn("30885281618", bl037)

    def test_backlog_bl037_residual_work_is_none(self):
        bl037 = self._bl037_section()
        self.assertIn("- **残作業:** なし。", bl037)
        self.assertNotIn(
            "独立レビュー待ち。最終受入前に完了扱いしない。", bl037,
        )

    def test_backlog_bl037_does_not_claim_final_acceptance_pending(self):
        bl037 = self._bl037_section()
        self.assertNotIn("final acceptance pending", bl037)

    def test_backlog_bl037_does_not_guess_a_merge_commit_sha(self):
        bl037 = self._bl037_section()
        for stale_phrase in ("merge待ち", "merge pending", "Ready化待ち", "次回closeoutで記録"):
            with self.subTest(stale_phrase=stale_phrase):
                self.assertNotIn(stale_phrase, bl037)
        self.assertIn("GitHub", bl037)
        self.assertIn("正本", bl037)

    def test_status_active_work_does_not_list_bl037_as_its_own_item(self):
        # Matches the established pattern in test_status.Bl035ActiveWorkTest:
        # Active work may legitimately hold a later, unrelated ticket that
        # mentions BL-037 in passing (e.g. as "after BL-037 completed"
        # context); what must never recur is BL-037 reappearing as its own
        # Active work line item after its own final acceptance.
        status = self._read("STATUS.md")
        active = status.split("## Active work", 1)[1].split(
            "\n## 5. Recently completed work", 1
        )[0]
        self.assertFalse(
            any(line.startswith("- BL-037 ") for line in active.splitlines()),
            "BL-037 must not reappear as its own Active work item after final acceptance",
        )

    def test_status_recently_completed_bl037_entry_records_required_content(self):
        status = self._read("STATUS.md")
        recently_completed = status.split("## 5. Recently completed work", 1)[1]
        bl037_line = next(
            line for line in recently_completed.splitlines() if line.startswith("- BL-037 ")
        )
        for required in (
            "Fable 5",
            "R-13",
            "pipeline integration E2E",
            "d53e04a474d166144f28a50c07e656e27ed56192",
            "30886560785",
            "1670 tests OK",
            "[PR #79](https://github.com/matkei31/security-digest/pull/79)",
            "「おk」",
            "「ok」",
            "残作業はない",
        ):
            with self.subTest(required=required):
                self.assertIn(required, bl037_line)
        self.assertNotIn("final acceptance pending", bl037_line)


class Bl038Tranche1RecordSyncTest(unittest.TestCase):
    """BL-038 (Fable 5 whole-repository review R-04, tranche 1) round 2
    independent review found round 1's confirmed head/CI/test-count
    evidence was missing from BACKLOG.md/STATUS.md, and that BACKLOG.md's
    round 1 record described the fenced-code-block fix backwards ("no
    fenced code block support was added" instead of "fenced code block
    support was added"). These tests check the record-sync fix without
    locking the full surrounding prose verbatim; they do not assert
    BL-038 is complete (it remains an incomplete umbrella ticket).
    """

    ROOT = Path(__file__).resolve().parent

    def _read(self, name):
        return (self.ROOT / name).read_text(encoding="utf-8")

    def _bl038_section(self):
        backlog = self._read("BACKLOG.md")
        marker = "## BL-038 "
        start = backlog.index(marker)
        end = backlog.find("\n## ", start + len(marker))
        return backlog[start:] if end == -1 else backlog[start:end]

    def test_backlog_bl038_records_round1_confirmed_evidence(self):
        bl038 = self._bl038_section()
        for required in (
            "87d9511ababcd200f5418b7421b40288301554e4",
            "30903691728",
            "1706 tests OK",
            "changed files累計8件",
            "unresolved review threads 0",
        ):
            with self.subTest(required=required):
                self.assertIn(required, bl038)

    def test_backlog_bl038_state_not_complete_and_current_residual_names_tranche3(self):
        # This test predates tranche 2; the state field has since moved from
        # "tranche 2以降継続" to "tranche 2実装中" as tranche 2 itself began.
        # Bl038Tranche2RecordSyncTest below covers the current state string.
        #
        # BL-038 tranche 2 round 1 review: the residual-work check below is
        # scoped to the CURRENT "- **残作業:**" field, not the whole BL-038
        # section -- a document-global "tranche 2以降" substring search would
        # keep passing on historical prose mentions (e.g. tranche 1's own
        # evidence record) even after the current residual work moved on to
        # "tranche 3以降", producing a false positive that no longer detects
        # a regression in what BL-038 actually still owes.
        bl038 = self._bl038_section()
        self.assertIn("tranche 1・2・3a", bl038)
        own_state_line = next(
            line for line in bl038.splitlines() if line.startswith("- **状態:**")
        )
        self.assertNotEqual(own_state_line.strip(), "- **状態:** 完了")
        # Anchor on the actual bullet (line-start "- **残作業:**"), not any
        # prose elsewhere in the section that merely quotes that label.
        residual_match = re.search(r"^- \*\*残作業:\*\* .*$", bl038, re.MULTILINE)
        self.assertIsNotNone(residual_match, "BL-038 section must have a current 残作業 bullet")
        residual = residual_match.group(0)
        self.assertIn("tranche 3", residual)
        self.assertIn("約1593件", residual)
        self.assertIn("BL-038全体の最終受入", residual)
        self.assertNotEqual(residual.strip(), "- **残作業:** なし。")

    def test_backlog_bl038_round1_fix_record_no_longer_claims_fenced_code_is_unsupported(self):
        # The stale phrase is legitimately still quoted inside round 2's own
        # finding description ("round 1's record said X, which was
        # backwards") -- what must not happen is the round 1修正 bullet
        # ITSELF still describing its own fix that way. Scope the check to
        # that one bullet, not the whole BL-038 section.
        bl038 = self._bl038_section()
        round1_fix_start = bl038.index("**round 1修正:**")
        round1_fix_end = bl038.index("**round 1修正確定証跡:**", round1_fix_start)
        round1_fix_bullet = bl038[round1_fix_start:round1_fix_end]
        self.assertNotIn("fenced code block非対応の言及を追加した", round1_fix_bullet)
        self.assertNotIn("fenced code blockには対応していない", round1_fix_bullet)
        self.assertIn("fenced code block内のheading風の行を無視する対応", round1_fix_bullet)

    def test_status_active_work_lists_bl038_with_round1_confirmed_evidence(self):
        status = self._read("STATUS.md")
        active = status.split("## Active work", 1)[1].split(
            "\n## 5. Recently completed work", 1
        )[0]
        bl038_line = next(
            line for line in active.splitlines() if line.startswith("- BL-038 ")
        )
        for required in (
            "87d9511ababcd200f5418b7421b40288301554e4",
            "30903691728",
            "1706 tests OK",
            "f1b6121e54b7f92b1dac0796723af9da1a28931d",
            "30905147771",
            "1712 tests OK",
        ):
            with self.subTest(required=required):
                self.assertIn(required, bl038_line)

    def test_status_active_work_no_longer_has_the_vague_pr_reference(self):
        status = self._read("STATUS.md")
        active = status.split("## Active work", 1)[1].split(
            "\n## 5. Recently completed work", 1
        )[0]
        self.assertNotIn("修正後のhead・CI・test件数はPR上で確認可能", active)

    def test_status_recently_completed_bl037_record_is_unchanged(self):
        # Round 2 must not touch BL-037's own Recently completed record.
        status = self._read("STATUS.md")
        recently_completed = status.split("## 5. Recently completed work", 1)[1]
        bl037_line = next(
            line for line in recently_completed.splitlines() if line.startswith("- BL-037 ")
        )
        self.assertIn("d53e04a474d166144f28a50c07e656e27ed56192", bl037_line)
        self.assertIn("30886560785", bl037_line)

    def test_backlog_bl038_state_reflects_tranche1_accepted_not_complete(self):
        # See Bl038Tranche2RecordSyncTest for the current tranche 1+2 state
        # string; this test only checks the state field was never re-marked
        # complete or reverted to the pre-tranche-1 phrasing.
        bl038 = self._bl038_section()
        self.assertIn("実装中(", bl038)
        self.assertIn("tranche 1・2・3a", bl038)
        own_state_line = next(
            line for line in bl038.splitlines() if line.startswith("- **状態:**")
        )
        self.assertNotEqual(own_state_line.strip(), "- **状態:** 完了")
        self.assertNotIn("- **状態:** 実装中／独立レビュー待ち", bl038)

    def test_backlog_bl038_records_tranche1_final_acceptance_quote_and_date(self):
        bl038 = self._bl038_section()
        self.assertIn("「おk」", bl038)
        self.assertIn("2026-08-04", bl038)
        # 着手時原文「ok」とtranche 1最終受入原文「おk」の両方が区別されて存在する。
        self.assertIn("「ok」", bl038)
        self.assertIn("tranche 1最終受入原文", bl038)
        self.assertIn("着手時ユーザー原文", bl038)

    def test_backlog_bl038_records_round2_accepted_implementation_evidence(self):
        bl038 = self._bl038_section()
        self.assertIn("f1b6121e54b7f92b1dac0796723af9da1a28931d", bl038)
        self.assertIn("30905147771", bl038)
        self.assertIn("1712 tests OK", bl038)
        self.assertIn("changed files 8件", bl038)

    def test_backlog_bl038_residual_work_still_names_tranche2_scope(self):
        bl038 = self._bl038_section()
        self.assertIn("tranche 2以降", bl038)
        self.assertIn("Bl031SecurityRequirementsReconciliationTest", bl038)

    def test_backlog_bl038_does_not_claim_overall_final_acceptance_pending_state(self):
        # The stale-state phrases from before tranche 1's acceptance must not
        # remain as the CURRENT state field; historical mentions elsewhere
        # (e.g. quoting round 1/round 2 findings) are not what this checks.
        bl038 = self._bl038_section()
        self.assertNotIn("- **状態:** 実装中／独立レビュー待ち", bl038)

    def test_status_active_work_records_tranche1_final_acceptance(self):
        status = self._read("STATUS.md")
        active = status.split("## Active work", 1)[1].split(
            "\n## 5. Recently completed work", 1
        )[0]
        bl038_line = next(
            line for line in active.splitlines() if line.startswith("- BL-038 ")
        )
        for required in (
            "「おk」",
            "f1b6121e54b7f92b1dac0796723af9da1a28931d",
            "30905147771",
            "1712 tests OK",
            "tranche 2以降",
        ):
            with self.subTest(required=required):
                self.assertIn(required, bl038_line)

    def test_status_active_work_still_lists_bl038_not_moved_to_recently_completed(self):
        status = self._read("STATUS.md")
        active = status.split("## Active work", 1)[1].split(
            "\n## 5. Recently completed work", 1
        )[0]
        self.assertNotIn("None.", active)
        self.assertTrue(
            any(line.startswith("- BL-038 ") for line in active.splitlines()),
            "BL-038 must remain in Active work after tranche 1 final acceptance "
            "(BL-038 overall is not complete)",
        )
        recently_completed = status.split("## 5. Recently completed work", 1)[1]
        self.assertFalse(
            any(line.startswith("- BL-038 ") for line in recently_completed.splitlines()),
            "BL-038 must not be listed in Recently completed work "
            "(tranche 1 acceptance is not BL-038's overall completion)",
        )


class Bl038Tranche2RecordSyncTest(unittest.TestCase):
    """BL-038 tranche 2 (individual A/B/C/D re-classification of the
    tranche-1-recorded brittle candidates, and Category C conversion)
    kickoff, review, and final-acceptance record-sync checks. Tranche 2's
    kickoff quote "「ok」" and final acceptance quote "「おk」" are each
    textually identical to an earlier BL-038 quote (the initial kickoff
    "「ok」" and tranche 1's own final acceptance "「おk」" respectively) but
    are distinct, later statements; these tests check BACKLOG.md/STATUS.md
    keep all four user statements distinguishable by role and order, and
    that BL-038 overall is still not recorded as complete even though both
    tranche 1 and tranche 2 are now individually accepted.
    """

    ROOT = Path(__file__).resolve().parent

    def _read(self, name):
        return (self.ROOT / name).read_text(encoding="utf-8")

    def _bl038_section(self):
        backlog = self._read("BACKLOG.md")
        marker = "## BL-038 "
        start = backlog.index(marker)
        end = backlog.find("\n## ", start + len(marker))
        return backlog[start:] if end == -1 else backlog[start:end]

    def _status_bl038_line(self):
        status = self._read("STATUS.md")
        active = status.split("## Active work", 1)[1].split(
            "\n## 5. Recently completed work", 1
        )[0]
        return next(
            line for line in active.splitlines() if line.startswith("- BL-038 ")
        )

    def test_backlog_bl038_state_reflects_tranche1_and_tranche2_accepted(self):
        # See Bl038Tranche3aRecordSyncTest for the current tranche 3a state
        # string; this test only checks tranche 1/2 acceptance is still
        # named and the state was never re-marked complete.
        bl038 = self._bl038_section()
        self.assertIn("tranche 1・2・3a", bl038)
        own_state_line = next(
            line for line in bl038.splitlines() if line.startswith("- **状態:**")
        )
        self.assertNotEqual(own_state_line.strip(), "- **状態:** 完了")
        # The pre-final-acceptance "tranche 2実装中" phrasing must not remain
        # as the current state field (it may still legitimately appear in
        # historical round 1/round 2 review-record prose elsewhere).
        state_match = re.search(r"^- \*\*状態:\*\* .*$", bl038, re.MULTILINE)
        self.assertIsNotNone(state_match, "BL-038 section must have a current 状態 bullet")
        self.assertNotIn("tranche 2実装中", state_match.group(0))

    def test_backlog_bl038_still_records_tranche1_final_acceptance(self):
        bl038 = self._bl038_section()
        self.assertIn("「おk」", bl038)
        self.assertIn("tranche 1最終受入", bl038)
        self.assertIn("f1b6121e54b7f92b1dac0796723af9da1a28931d", bl038)

    def test_backlog_bl038_distinguishes_the_four_user_statements_by_role(self):
        # BL-038 tranche 2 final acceptance: a 4th numbered entry (tranche 2
        # final acceptance, "「おk」") was added alongside the pre-existing 3.
        # A 5th entry (tranche 3 kickoff) was later added on top of these 4
        # -- see Bl038Tranche3aRecordSyncTest for the full 5-entry check;
        # this test only checks entries 1-4 are still present and correctly
        # role-distinguished, regardless of how many entries follow them.
        # Only the numbered history entries (the actual quote records) are
        # contract-checked here -- the heading's own descriptive prose is
        # NOT counted, since it is not itself historical evidence. Entries
        # are distinguished by role/order, not by how many times each raw
        # quote string happens to occur.
        bl038 = self._bl038_section()
        history_start = bl038.index("ユーザー原文の履歴")
        history_end = bl038.index("着手時ユーザー原文:", history_start)
        history = bl038[history_start:history_end]
        entries = re.findall(
            r"^\s*(\d)\.\s+(.*?)(?=^\s*\d\.\s|\Z)", history, re.MULTILINE | re.DOTALL
        )
        self.assertEqual([number for number, _ in entries][:4], ["1", "2", "3", "4"])
        entry1, entry2, entry3, entry4 = (text for _, text in entries[:4])
        self.assertIn("BL-038 initial kickoff original", entry1)
        self.assertIn("「ok」", entry1)
        self.assertIn("tranche 1 final acceptance original", entry2)
        self.assertIn("「おk」", entry2)
        self.assertIn("tranche 2 kickoff original", entry3)
        self.assertIn("「ok」", entry3)
        self.assertIn("同一文字列だが別の発言", entry3)
        self.assertIn("tranche 2 final acceptance original", entry4)
        self.assertIn("「おk」", entry4)
        self.assertIn("同一文字列だが", entry4)

    def test_backlog_bl038_records_tranche2_kickoff_date_branch_and_scope(self):
        bl038 = self._bl038_section()
        self.assertIn("tranche 2 kickoff日:** 2026-08-04", bl038)
        self.assertIn("test/bl038-tranche2-brittle-assertions", bl038)
        self.assertIn("tranche 2 kickoff原文の解釈", bl038)
        self.assertIn("BL-038全体の完了承認ではない", bl038)

    def test_backlog_bl038_records_corrected_classification_counts_and_sd030_as_d(self):
        # BL-038 tranche 2 round 2 review: round 1's A->D correction on the
        # SD-030 candidate was a content fix, but the record test only ever
        # checked the classification table's header and the C-conversion
        # count/total -- it never pinned each individual A/B/C/D count or
        # the corrected candidate's own row, so BACKLOG.md could silently
        # regress to A 1/D 1 and this test would still pass. Pin each count
        # individually (not a whole-paragraph verbatim lock) and check the
        # SD-030 row itself carries D, not A.
        bl038 = self._bl038_section()
        self.assertIn("| File | Class | Candidate概要 | 分類 | 対応 | 理由 |", bl038)

        counts_match = re.search(
            r"\(A (\d+)／B (\d+)／C (\d+)／D (\d+)\)", bl038
        )
        self.assertIsNotNone(
            counts_match, "BL-038 section must record an (A n／B n／C n／D n) count summary"
        )
        a_count, b_count, c_count, d_count = (int(g) for g in counts_match.groups())
        self.assertEqual(a_count, 0)
        self.assertEqual(b_count, 1)
        self.assertEqual(c_count, 12)
        self.assertEqual(d_count, 2)
        self.assertEqual(a_count + b_count + c_count + d_count, 15)
        self.assertIn("計15 candidateすべてを個別に分類した", bl038)

        row_match = re.search(
            r"^\s*\|.*Bl031AcceptanceAndBl032RegistrationTest.*\|\s*$",
            bl038,
            re.MULTILINE,
        )
        self.assertIsNotNone(
            row_match,
            "classification table must have a row for "
            "Bl031AcceptanceAndBl032RegistrationTest's SD-030 candidate",
        )
        sd030_row = row_match.group(0)
        self.assertIn("| D |", sd030_row)
        self.assertIn("historical", sd030_row)
        self.assertNotIn("| A |", sd030_row)

    def test_backlog_bl038_names_full_1593_classification_as_residual(self):
        bl038 = self._bl038_section()
        self.assertIn("約1593件", bl038)
        self.assertIn("classification", bl038)
        self.assertIn("BL-038全体の最終受入", bl038)

    def test_backlog_bl038_records_tranche2_final_acceptance_evidence(self):
        bl038 = self._bl038_section()
        for required in (
            "tranche 2最終受入日:** 2026-08-04",
            "「おk」",
            "e4a5da5c5edb4f45b3d031a6e60e5307cf3199a5",
            "30915285624",
            "1729 tests OK",
            "tranche 2最終受入原文の解釈",
            "BL-038全体の完了承認ではない",
            "tranche 3以降の着手",
        ):
            with self.subTest(required=required):
                self.assertIn(required, bl038)
        # Tranche 2 final acceptance must no longer be recorded as pending,
        # and BL-038 overall must not be recorded as complete.
        self.assertNotIn("tranche 2 final acceptance:** 未実施(pending)", bl038)
        own_state_line = next(
            line for line in bl038.splitlines() if line.startswith("- **状態:**")
        )
        self.assertNotEqual(own_state_line.strip(), "- **状態:** 完了")

    def test_status_active_work_records_tranche2_kickoff_and_progress(self):
        bl038_line = self._status_bl038_line()
        for required in (
            "tranche 2着手",
            "test/bl038-tranche2-brittle-assertions",
            "「おk」",
            "tranche 2 kickoff原文「ok」",
            "着手時ユーザー原文「ok」",
        ):
            with self.subTest(required=required):
                self.assertIn(required, bl038_line)

    def test_status_active_work_records_tranche2_final_acceptance(self):
        bl038_line = self._status_bl038_line()
        for required in (
            "tranche 2最終受入(2026-08-04)",
            "e4a5da5c5edb4f45b3d031a6e60e5307cf3199a5",
            "30915285624",
            "1729 tests OK",
            "tranche 3以降継続",
            "BL-038全体の完了承認ではなく",
        ):
            with self.subTest(required=required):
                self.assertIn(required, bl038_line)
        # "final acceptance pending" must not remain as the current tranche 2
        # state in Active work; the line explicitly says it is complete.
        self.assertNotIn("tranche 2 final acceptance pending。", bl038_line)
        self.assertIn("tranche 2 final acceptanceはpendingではなく完了している", bl038_line)

    def test_status_active_work_still_lists_bl038_not_recently_completed(self):
        status = self._read("STATUS.md")
        active = status.split("## Active work", 1)[1].split(
            "\n## 5. Recently completed work", 1
        )[0]
        self.assertNotIn("None.", active)
        self.assertTrue(
            any(line.startswith("- BL-038 ") for line in active.splitlines()),
            "BL-038 must remain in Active work during tranche 2 "
            "(BL-038 overall is not complete)",
        )
        recently_completed = status.split("## 5. Recently completed work", 1)[1]
        self.assertFalse(
            any(line.startswith("- BL-038 ") for line in recently_completed.splitlines()),
            "BL-038 must not be listed in Recently completed work during tranche 2",
        )

    def test_status_recently_completed_bl037_record_still_unchanged(self):
        status = self._read("STATUS.md")
        recently_completed = status.split("## 5. Recently completed work", 1)[1]
        bl037_line = next(
            line for line in recently_completed.splitlines()
            if line.startswith("- BL-037 ")
        )
        self.assertIn("d53e04a474d166144f28a50c07e656e27ed56192", bl037_line)


class Bl038Tranche3aRecordSyncTest(unittest.TestCase):
    """BL-038 tranche 3a (assertion inventory/fingerprint/manifest-validator
    infrastructure only -- no repository classification manifest, no pilot
    classification) kickoff record-sync checks. The original 3-file pilot
    plan (test_custom_domain.py/test_content_usage_policy.py/test_ui_spec.py)
    was split into 3a (this PR, infrastructure)/3b (test_custom_domain.py
    97-assertion classification)/3c (test_ui_spec.py 185-assertion
    classification) after packaging measurements showed infrastructure and
    pilot classification could not fit the diff-size cap in one PR; these
    tests check that split is recorded, not silently dropped.
    """

    ROOT = Path(__file__).resolve().parent

    def _read(self, name):
        return (self.ROOT / name).read_text(encoding="utf-8")

    def _bl038_section(self):
        backlog = self._read("BACKLOG.md")
        marker = "## BL-038 "
        start = backlog.index(marker)
        end = backlog.find("\n## ", start + len(marker))
        return backlog[start:] if end == -1 else backlog[start:end]

    def _status_bl038_line(self):
        status = self._read("STATUS.md")
        active = status.split("## Active work", 1)[1].split(
            "\n## 5. Recently completed work", 1
        )[0]
        return next(
            line for line in active.splitlines() if line.startswith("- BL-038 ")
        )

    def test_backlog_bl038_state_reflects_tranche3a_implementing(self):
        # tranche 3a's own acceptance ("tranche 1・2・3a") remains a true
        # substring of the current 状態 field regardless of how later
        # tranches (3b, 3c, ...) are described alongside it.
        bl038 = self._bl038_section()
        self.assertIn("実装中(", bl038)
        self.assertIn("tranche 1・2・3a", bl038)
        own_state_line = next(
            line for line in bl038.splitlines() if line.startswith("- **状態:**")
        )
        self.assertNotEqual(own_state_line.strip(), "- **状態:** 完了")

    def test_backlog_bl038_records_six_user_statements_with_entry6_as_tranche3a_final(self):
        bl038 = self._bl038_section()
        history_start = bl038.index("ユーザー原文の履歴")
        history_end = bl038.index("着手時ユーザー原文:", history_start)
        history = bl038[history_start:history_end]
        entries = re.findall(
            r"^\s*(\d)\.\s+(.*?)(?=^\s*\d\.\s|\Z)", history, re.MULTILINE | re.DOTALL
        )
        self.assertEqual(
            [number for number, _ in entries][:6], ["1", "2", "3", "4", "5", "6"]
        )
        entry5 = entries[4][1]
        self.assertIn("tranche 3 kickoff original", entry5)
        self.assertIn("「ok」", entry5)
        self.assertIn("最終受入ではなく", entry5)
        entry6 = entries[5][1]
        self.assertIn("tranche 3a final acceptance original", entry6)
        self.assertIn("「おk」", entry6)
        self.assertIn("PR #82", entry6)
        self.assertIn("tranche 3b", entry6)
        self.assertIn("BL-038全体またはtranche 3全体の完了承認でもない", entry6)

    def test_backlog_bl038_records_3a_3b_3c_split_plan_and_excludes_content_usage_policy(self):
        bl038 = self._bl038_section()
        self.assertIn("tranche 3a", bl038)
        self.assertIn("tranche 3b", bl038)
        self.assertIn("tranche 3c", bl038)
        self.assertIn("test_custom_domain.py", bl038)
        self.assertIn("97", bl038)
        self.assertIn("test_ui_spec.py", bl038)
        self.assertIn("185", bl038)
        self.assertIn("test_content_usage_policy.py", bl038)
        self.assertIn("約1593件", bl038)
        self.assertIn("classification", bl038)
        self.assertIn("BL-038全体の最終受入", bl038)

    def test_backlog_records_no_manifest_or_pilot_classification_as_of_tranche3a_acceptance(self):
        # This is a HISTORICAL contract about what was true when tranche 3a
        # itself was accepted (no manifest, no pilot classification yet) --
        # it reads BACKLOG's own accepted-implementation evidence text, not
        # the current filesystem (which now legitimately has a manifest,
        # added later by tranche 3b; round 1 review, section 7.5: the
        # current-filesystem scope check belongs in
        # Bl038Tranche3bRecordSyncTest instead, not here).
        bl038 = self._bl038_section()
        self.assertIn("repository classification manifestなし", bl038)
        self.assertIn("pilot classificationなし", bl038)

    def test_backlog_bl038_records_tranche3a_final_acceptance_evidence(self):
        bl038 = self._bl038_section()
        for required in (
            "tranche 3a最終受入日:** 2026-08-05",
            "tranche 3a最終受入原文:** 「おk」",
            "a430860ff4637f63814557398f4d48093787a511",
            "31009684331",
            "1818 tests OK",
            "80 tests",
            "changed files 5件",
            "2292 insertions／11 deletions",
            "BL-038全体またはtranche 3全体の受入条件がすべて完了したとは記録しない",
        ):
            with self.subTest(required=required):
                self.assertIn(required, bl038)
        self.assertNotIn("tranche 3a final acceptance:** 未実施(pending)", bl038)

    def test_status_active_work_records_tranche3a_kickoff_and_still_lists_bl038(self):
        status = self._read("STATUS.md")
        active = status.split("## Active work", 1)[1].split(
            "\n## 5. Recently completed work", 1
        )[0]
        self.assertNotIn("None.", active)
        bl038_line = self._status_bl038_line()
        for required in (
            "tranche 3着手",
            "test/bl038-tranche3a-inventory-infrastructure",
            "tranche 3 kickoff原文「ok」",
            "tranche 3a最終受入",
            "a430860ff4637f63814557398f4d48093787a511",
            "tranche 3a final acceptanceはpendingではなく完了している",
        ):
            with self.subTest(required=required):
                self.assertIn(required, bl038_line)
        recently_completed = status.split("## 5. Recently completed work", 1)[1]
        self.assertFalse(
            any(line.startswith("- BL-038 ") for line in recently_completed.splitlines()),
            "BL-038 must not be listed in Recently completed work during tranche 3a",
        )

    def test_backlog_bl038_records_round1_review_evidence_and_revised_cap(self):
        bl038 = self._bl038_section()
        for required in (
            "独立レビューround 1(tranche 3a)",
            "9e49be8642a2583809569dc64e612fc14257b5f4",
            "30924720700",
            "1766 tests OK",
            "custom assertion helper",
            "schema",
            "async",
            "unknown-method",
            "2000行",
            "独立レビューround 2(tranche 3a)",
            "8fdee066a5e0875ae6ccfb20f2cd9db5937f1999",
            "31006649767",
            "1793 tests OK",
            "transitive",
            "invalid-entry-shape",
            "2300行",
            "宣言済み",
        ):
            with self.subTest(required=required):
                self.assertIn(required, bl038)

    def test_status_active_work_records_round1_review_note(self):
        bl038_line = self._status_bl038_line()
        for required in (
            "独立レビューround 1(tranche 3a",
            "9e49be8642a2583809569dc64e612fc14257b5f4",
            "round 1修正済み",
            "独立レビューround 2(tranche 3a",
            "8fdee066a5e0875ae6ccfb20f2cd9db5937f1999",
            "round 2修正済み",
            "2300行",
        ):
            with self.subTest(required=required):
                self.assertIn(required, bl038_line)


class Bl038Tranche3bRecordSyncTest(unittest.TestCase):
    """BL-038 tranche 3b (test_custom_domain.py classification manifest +
    declared-scope/count structural guard) kickoff record-sync checks."""

    ROOT = Path(__file__).resolve().parent
    MANIFEST_PATH = ROOT / "document_test_classification.json"

    def _read(self, name):
        return (self.ROOT / name).read_text(encoding="utf-8")

    def _bl038_section(self):
        backlog = self._read("BACKLOG.md")
        marker = "## BL-038 "
        start = backlog.index(marker)
        end = backlog.find("\n## ", start + len(marker))
        return backlog[start:] if end == -1 else backlog[start:end]

    def _status_bl038_line(self):
        status = self._read("STATUS.md")
        active = status.split("## Active work", 1)[1].split(
            "\n## 5. Recently completed work", 1
        )[0]
        return next(
            line for line in active.splitlines() if line.startswith("- BL-038 ")
        )

    def test_backlog_bl038_state_reflects_tranche3b_accepted(self):
        bl038 = self._bl038_section()
        # tranche 3b's own acceptance is a permanent historical fact even
        # after the state string's later-tranche suffix moves forward --
        # check the invariant prefix, not the exact full string, since
        # "3b受入済み" also legitimately appears inside "3a・3b・3c受入済み".
        self.assertIn("- **状態:** 実装中(tranche 1・2・3a・3b", bl038)
        self.assertIn("受入済み", bl038)
        own_state_line = next(
            line for line in bl038.splitlines() if line.startswith("- **状態:**")
        )
        self.assertNotEqual(own_state_line.strip(), "- **状態:** 完了")

    def test_backlog_bl038_records_nine_user_statements_with_entry8_as_tranche3b_final(self):
        bl038 = self._bl038_section()
        history_start = bl038.index("ユーザー原文の履歴")
        history_end = bl038.index("着手時ユーザー原文:", history_start)
        history = bl038[history_start:history_end]
        entries = re.findall(
            r"^\s*(\d)\.\s+(.*?)(?=^\s*\d\.\s|\Z)", history, re.MULTILINE | re.DOTALL
        )
        self.assertEqual(
            [number for number, _ in entries],
            ["1", "2", "3", "4", "5", "6", "7", "8", "9"],
        )
        entry7 = entries[6][1]
        for required in (
            "tranche 3b kickoff original",
            "2026-08-05",
            "「ok」",
            "test_custom_domain.py",
            "97 assertion",
        ):
            with self.subTest(required=required):
                self.assertIn(required, entry7)
        for forbidden in (
            "tranche 3b実装内容の最終受入ではなく",
            "tranche 3c着手承認でも",
            "BL-038全体またはtranche 3全体の完了承認でもない",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertIn(forbidden, entry7)
        entry8 = entries[7][1]
        for required in (
            "tranche 3b final acceptance original",
            "2026-08-06",
            "「おk」",
            "PR #83",
            "Category C 41件のsource conversion承認ではなく",
            "tranche 3c着手承認でも",
            "BL-038全体またはtranche 3全体の完了承認でもない",
        ):
            with self.subTest(required=required):
                self.assertIn(required, entry8)
        entry9 = entries[8][1]
        for required in (
            "tranche 3c kickoff original",
            "2026-08-06",
            "「ok」",
            "test_ui_spec.py",
            "185 assertion",
            "2-file scope",
            "Category C",
            "BL-038全体またはtranche 3全体の完了承認でもない",
        ):
            with self.subTest(required=required):
                self.assertIn(required, entry9)

    def test_manifest_custom_domain_portion_still_matches_tranche3b_corrected_counts(self):
        self.assertTrue(self.MANIFEST_PATH.is_file())
        manifest = json.loads(self.MANIFEST_PATH.read_text(encoding="utf-8"))
        self.assertEqual(manifest["schema_version"], 1)
        # tranche 3c expanded scope to 2 files; test_custom_domain.py's own
        # declared scope entry and its 97 assertions must remain unchanged.
        custom_domain_scope = next(
            s for s in manifest["scope"] if s["file"] == "test_custom_domain.py"
        )
        self.assertEqual(
            custom_domain_scope["classes"],
            [
                "DocsCnameFileTest",
                "CnameSurvivesGenerationTest",
                "ArticleBriefContractUnchangedTest",
                "Bl007DocumentationTest",
                "ReadmePublicUrlTest",
                "Bl007ClosureRecordTest",
                "TicketIdTypoTest",
            ],
        )
        custom_domain_entries = [
            a for a in manifest["assertions"] if a["file"] == "test_custom_domain.py"
        ]
        self.assertEqual(len(custom_domain_entries), 97)
        from collections import Counter

        counts = Counter(a["category"] for a in custom_domain_entries)
        # round 2 review corrected this tally further: 11 more B entries
        # (raw `.index()` ordering anchors and short-but-brittle prose
        # fragments) moved to C (see BACKLOG round 2 evidence). tranche 3c
        # must not have touched this file's classification.
        self.assertEqual(dict(counts), {"A": 8, "B": 37, "C": 41, "D": 11})
        self.assertEqual(sum(counts.values()), 97)
        # every entry uses `targets` (round 1 fix, Blocker 2), never the
        # old single-string `target`
        for entry in custom_domain_entries:
            self.assertIn("targets", entry)
            self.assertNotIn("target", entry)

    def test_manifest_line_count_is_within_budget(self):
        lines = self.MANIFEST_PATH.read_text(encoding="utf-8").splitlines()
        self.assertLessEqual(len(lines), 1000)

    def test_backlog_records_tranche3b_kickoff_evidence_and_no_source_conversion(self):
        bl038 = self._bl038_section()
        for required in (
            "tranche 3b着手",
            "test/bl038-tranche3b-custom-domain-classification",
            "bfa6c7281c760597b865a425de2f3df6759c1a3d",
            "8435dcc32518037b96b736ad7f81e4a1b951c348",
            "A 8／B 48／C 30／D 11",
            "97",
            "validate_manifest",
            "test_document_test_classification.py",
        ):
            with self.subTest(required=required):
                self.assertIn(required, bl038)

    def test_backlog_records_round1_review_findings_and_corrected_classification(self):
        bl038 = self._bl038_section()
        for required in (
            "独立レビューround 1(tranche 3b、2026-08-05)",
            "43f4619dc1f168998da206f5e0699b547da2b3e2",
            "31017444090",
            "1841 tests OK",
            "single-line／short",
            "targets",
            "structural guard",
            "rationale全件一意",
            "round 1修正",
            "C 30件",
            "refactor_later",
            "21 tests",
            "target style",
        ):
            with self.subTest(required=required):
                self.assertIn(required, bl038)
        self.assertNotIn("A→`keep`は誤り、正しくはA→`keep`", bl038)

    def test_backlog_records_round2_review_findings_and_final_classification(self):
        bl038 = self._bl038_section()
        for required in (
            "独立レビューround 2(tranche 3b、2026-08-05)",
            "065f6892b3435070a53a81a95208c72ddcd53d27",
            "31023760604",
            "1848 tests OK",
            ".index()",
            "ValueError",
            "count-preserving",
            "EXPECTED_A_IDS",
            "A 8／B 37／C 41／D 11",
            "round 2修正",
        ):
            with self.subTest(required=required):
                self.assertIn(required, bl038)
        # the round 1 kickoff-time manifest/structural-test/source-conversion
        # bullets (Blocker 4) must not remain as current evidence
        self.assertNotIn("target`単数形、`targets`不使用", bl038)
        self.assertNotIn("Category C該当が0件のため変換対象自体が無い", bl038)

    def test_status_records_round2_review_and_correct_classification_vs_conversion(self):
        bl038_line = self._status_bl038_line()
        for required in (
            "独立レビューround 2(tranche 3b、2026-08-05)",
            "065f6892b3435070a53a81a95208c72ddcd53d27",
            "A 8／B 37／C 41／D 11",
            "targets",
            "pilot classification(97件の分類とmanifest記録)は実施済みだが、Category C 41件のsource conversion",
            "未実施",
            "23 tests",
            "exact category membership guard",
        ):
            with self.subTest(required=required):
                self.assertIn(required, bl038_line)

    def test_backlog_residual_work_names_category_c_conversion_still_pending(self):
        bl038 = self._bl038_section()
        residual_match = re.search(r"^- \*\*残作業:\*\* .*$", bl038, re.MULTILINE)
        self.assertIsNotNone(residual_match)
        residual = residual_match.group(0)
        for required in (
            "Category C conversion",
            "tranche 3bの41件",
            "tranche 3cの84件",
            "約1593件",
            "BL-038全体の最終受入",
        ):
            with self.subTest(required=required):
                self.assertIn(required, residual)
        # tranche 3b itself is accepted -- it must not still be listed as
        # pending residual work
        self.assertNotIn("tranche 3b final acceptance", residual)
        # tranche 3c has since been finally accepted (PR #84 merged) -- it
        # must not still read as not-yet-started or in-progress
        self.assertNotIn("tranche 3c(`test_ui_spec.py` 185 assertionのclassification manifestとrecord test、未着手", residual)
        self.assertNotIn("tranche 3cは実装中", residual)

    def test_status_active_work_records_tranche3b_and_tranche3c_kickoff_and_still_lists_bl038(self):
        status = self._read("STATUS.md")
        active = status.split("## Active work", 1)[1].split(
            "\n## 5. Recently completed work", 1
        )[0]
        self.assertNotIn("None.", active)
        bl038_line = self._status_bl038_line()
        for required in (
            "tranche 3b着手",
            "test/bl038-tranche3b-custom-domain-classification",
            "tranche 3b kickoff原文「ok」",
            "A 8／B 37／C 41／D 11",
            "tranche 3c着手",
            "test/bl038-tranche3c-ui-spec-classification",
        ):
            with self.subTest(required=required):
                self.assertIn(required, bl038_line)
        recently_completed = status.split("## 5. Recently completed work", 1)[1]
        self.assertFalse(
            any(line.startswith("- BL-038 ") for line in recently_completed.splitlines()),
            "BL-038 must not be listed in Recently completed work during tranche 3c",
        )

    def test_backlog_and_status_record_tranche3b_final_acceptance_evidence(self):
        bl038 = self._bl038_section()
        for required in (
            "tranche 3b最終受入日:** 2026-08-06",
            "tranche 3b最終受入原文:** 「おk」",
            "9bd592331e2d97bcfdda23cfa6578a0128d924bd",
            "31063037468",
            "1851 tests OK",
            "changed files 5件、diff 800 insertions／30 deletions",
            "BL-038全体・tranche 3全体・Category C conversionの受入条件が完了したとは記録しない",
        ):
            with self.subTest(required=required):
                self.assertIn(required, bl038)
        bl038_line = self._status_bl038_line()
        for required in (
            "tranche 3b最終受入(2026-08-06)",
            "9bd592331e2d97bcfdda23cfa6578a0128d924bd",
            "31063037468",
            "tranche 3b final acceptanceはpendingではなく完了している",
        ):
            with self.subTest(required=required):
                self.assertIn(required, bl038_line)


class Bl038Tranche3cRecordSyncTest(unittest.TestCase):
    """BL-038 tranche 3c (test_ui_spec.py classification manifest expansion
    to a 2-file declared scope) kickoff record-sync checks."""

    ROOT = Path(__file__).resolve().parent
    MANIFEST_PATH = ROOT / "document_test_classification.json"
    CLASSIFICATION_TEST_PATH = ROOT / "test_document_test_classification.py"

    def _read(self, name):
        return (self.ROOT / name).read_text(encoding="utf-8")

    def _bl038_section(self):
        backlog = self._read("BACKLOG.md")
        marker = "## BL-038 "
        start = backlog.index(marker)
        end = backlog.find("\n## ", start + len(marker))
        return backlog[start:] if end == -1 else backlog[start:end]

    def _status_bl038_line(self):
        status = self._read("STATUS.md")
        active = status.split("## Active work", 1)[1].split(
            "\n## 5. Recently completed work", 1
        )[0]
        return next(
            line for line in active.splitlines() if line.startswith("- BL-038 ")
        )

    def test_backlog_bl038_state_reflects_tranche3c_accepted(self):
        # tranche 3c's own acceptance is a permanent historical fact even as
        # later tranches (3d, 3e, ...) get appended to the accepted list
        # before "受入済み" -- extract the accepted-tranche list itself
        # rather than a fixed substring immediately before "受入済み", which
        # every later tranche's own acceptance would otherwise break.
        bl038 = self._bl038_section()
        own_state_line = next(
            line for line in bl038.splitlines() if line.startswith("- **状態:**")
        )
        accepted_part = own_state_line.split("(", 1)[1].split("受入済み", 1)[0]
        accepted_tranches = accepted_part.split("・")
        self.assertIn("3c", accepted_tranches)
        self.assertNotEqual(own_state_line.strip(), "- **状態:** 完了")

    def test_backlog_records_entry9_as_tranche3c_kickoff(self):
        bl038 = self._bl038_section()
        history_start = bl038.index("ユーザー原文の履歴")
        history_end = bl038.index("着手時ユーザー原文:", history_start)
        history = bl038[history_start:history_end]
        entries = re.findall(
            r"^\s*(\d+)\.\s+(.*?)(?=^\s*\d+\.\s|\Z)", history, re.MULTILINE | re.DOTALL)
        # entry 9's own historical content does not change as later entries
        # are appended; the overall entry-count/quote-tally checks belong to
        # whichever tranche's record-sync test owns the CURRENT history state.
        entry9 = next(text for number, text in entries if number == "9")
        for required in (
            "tranche 3c kickoff original",
            "2026-08-06",
            "「ok」",
            "test_ui_spec.py",
            "185 assertion",
        ):
            with self.subTest(required=required):
                self.assertIn(required, entry9)

    def test_backlog_records_tranche3c_kickoff_and_implementation_evidence(self):
        bl038 = self._bl038_section()
        for required in (
            "tranche 3c着手(2026-08-06)",
            "test/bl038-tranche3c-ui-spec-classification",
            "540b3380e412bc35a2086ca5d3a581b7098c1443",
            "実装証跡(tranche 3c)",
            "独立レビューround 1(tranche 3c",
            "独立レビューround 2(tranche 3c",
            "A 10／B 59／C 84／D 32",
            "282 entries",
            "combined: A 18／B 96／C 125／D 43",
            "23→26 tests",
            "CUSTOM_DOMAIN_EXPECTED_A_IDS",
            "UI_SPEC_EXPECTED_A_IDS",
        ):
            with self.subTest(required=required):
                self.assertIn(required, bl038)
        # neither the pre-review initial-implementation snapshot nor
        # round 1's superseded corrected counts may remain as the current
        # record
        self.assertNotIn("A 10／B 62／C 73／D 40", bl038)
        self.assertNotIn("combined A=18 B=99 C=114 D=51", bl038)
        self.assertNotIn("**A 10／B 61／C 80／D 34(total 185)**", bl038)

    def test_backlog_residual_work_no_longer_calls_tranche3c_in_progress(self):
        # tranche 3c has since been finally accepted and merged (PR #84);
        # the residual-work field must not still describe it as in-progress
        # now that tranche 3d owns that description.
        bl038 = self._bl038_section()
        residual_match = re.search(r"^- \*\*残作業:\*\* .*$", bl038, re.MULTILINE)
        self.assertIsNotNone(residual_match)
        residual = residual_match.group(0)
        self.assertNotIn("tranche 3cは実装中", residual)
        # round 1 review Blocker 3 (kept narrow, not a generic "未着手" ban):
        # the specific stale tranche 3c wording this test originally existed
        # to catch must not reappear.
        self.assertNotIn(
            "tranche 3c(`test_ui_spec.py` 185 assertionのclassification manifestとrecord test、未着手",
            residual,
        )

    def test_status_active_work_records_tranche3c_kickoff_evidence(self):
        bl038_line = self._status_bl038_line()
        for required in (
            "tranche 3c着手(2026-08-06)",
            "test/bl038-tranche3c-ui-spec-classification",
            "tranche 3c kickoff原文「ok」",
            "独立レビューround 2(tranche 3c",
            "A 10／B 59／C 84／D 32",
            "282 entries",
        ):
            with self.subTest(required=required):
                self.assertIn(required, bl038_line)
        self.assertNotIn("A 10／B 62／C 73／D 40", bl038_line)
        self.assertNotIn("**A 10／B 61／C 80／D 34(total 185)**", bl038_line)

    def test_manifest_ui_spec_portion_still_matches_tranche3c_corrected_counts(self):
        # tranche 3d expanded scope to 3 files; test_ui_spec.py's own
        # declared scope entry and its 185 (round-2-corrected) assertions
        # must remain unchanged.
        manifest = json.loads(self.MANIFEST_PATH.read_text(encoding="utf-8"))
        self.assertEqual(manifest["schema_version"], 1)
        ui_spec_scope = next(s for s in manifest["scope"] if s["file"] == "test_ui_spec.py")
        self.assertEqual(
            ui_spec_scope["classes"],
            ["UiSpecDocumentTest", "Bl036ArticleAttributionUiSpecTest"],
        )
        ui_spec_entries = [a for a in manifest["assertions"] if a["file"] == "test_ui_spec.py"]
        self.assertEqual(len(ui_spec_entries), 185)
        from collections import Counter

        ui_spec_counts = Counter(a["category"] for a in ui_spec_entries)
        # round 1 review corrected this tally: 7 mixed-contract D/B entries
        # moved to C. round 2 review found 4 more and moved those to C too.
        self.assertEqual(dict(ui_spec_counts), {"A": 10, "B": 59, "C": 84, "D": 32})
        for entry in ui_spec_entries:
            self.assertIn("targets", entry)
            self.assertNotIn("target", entry)

    def test_manifest_validates_with_zero_failures_via_document_test_inventory(self):
        import document_test_inventory as dti

        manifest = json.loads(self.MANIFEST_PATH.read_text(encoding="utf-8"))
        failures, summary = dti.validate_manifest(manifest, root=self.ROOT)
        self.assertEqual(failures, [])
        self.assertEqual(summary["unclassified"], 0)
        self.assertEqual(summary["stale"], 0)
        self.assertEqual(summary["fingerprint_mismatch"], 0)

    def test_classification_test_file_has_not_shrunk_below_26_tests(self):
        # Later tranches only ADD guards, so this tranche guards its own
        # floor; the exact current count is pinned by the newest tranche.
        source = self.CLASSIFICATION_TEST_PATH.read_text(encoding="utf-8")
        method_count = len(re.findall(r"^    def test_", source, re.MULTILINE))
        self.assertGreaterEqual(method_count, 26)

    def test_backlog_and_status_record_tranche3c_final_acceptance_evidence(self):
        # tranche 3c's own final-acceptance evidence is a permanent
        # historical fact, unaffected by tranche 3d's own progress.
        bl038 = self._bl038_section()
        for required in (
            "tranche 3c最終受入日:** 2026-08-06",
            "tranche 3c最終受入原文:** 「おk」",
            "567449062c87f7eca8f16a02f6b30595df221370",
            "31078691601",
            "1867 tests OK",
            "35367dd1506376776e0aa726ded6f8a31ce3a939",
            "31081419147",
        ):
            with self.subTest(required=required):
                self.assertIn(required, bl038)
        bl038_line = self._status_bl038_line()
        for required in (
            "tranche 3c最終受入(2026-08-06)",
            "567449062c87f7eca8f16a02f6b30595df221370",
            "35367dd1506376776e0aa726ded6f8a31ce3a939",
            "tranche 3c final acceptanceはpendingではなく完了している",
        ):
            with self.subTest(required=required):
                self.assertIn(required, bl038_line)

    def test_tranche3c_final_acceptance_diff_evidence_is_880_172_not_868(self):
        # PR #85 round 1 review Blocker 1: the tranche 3c final-acceptance
        # diff evidence had been recorded as 868/172 (the round-2-reviewed
        # HEAD's diff, correct only for that historical review record) when
        # it should be 880/172 (the actual diff of accepted implementation
        # head `567449062c87f7eca8f16a02f6b30595df221370` vs origin/main at
        # kickoff, per PR #84's own final body and GitHub's own record --
        # independently reconfirmed here via `git diff --shortstat`).
        # The round 2 "reviewed head `d1b1b150...`" record's own 868/172 is
        # correct and must NOT be touched by this test.
        bl038 = self._bl038_section()
        self.assertIn("- **diff:** 880 insertions／172 deletions", bl038)
        self.assertNotIn("- **diff:** 868 insertions／172 deletions", bl038)
        # the round 2 reviewed-head historical record must still read 868
        self.assertIn("reviewed diff 868 insertions／172 deletions", bl038)

        bl038_line = self._status_bl038_line()
        self.assertIn(
            "changed files 5件、diff 880 insertions／172 deletions、unresolved",
            bl038_line,
        )
        self.assertNotIn(
            "changed files 5件、diff 868 insertions／172 deletions、unresolved",
            bl038_line,
        )

    def test_status_active_work_still_lists_bl038_not_recently_completed(self):
        status = self._read("STATUS.md")
        active = status.split("## Active work", 1)[1].split(
            "\n## 5. Recently completed work", 1
        )[0]
        self.assertNotIn("None.", active)
        recently_completed = status.split("## 5. Recently completed work", 1)[1]
        self.assertFalse(
            any(line.startswith("- BL-038 ") for line in recently_completed.splitlines()),
            "BL-038 must not be listed in Recently completed work while BL-038 overall is incomplete",
        )


class Bl038Tranche3dRecordSyncTest(unittest.TestCase):
    """BL-038 tranche 3d (tranche 3c closeout sync + test_status.py
    classification manifest expansion to a 3-file declared scope) kickoff
    record-sync checks."""

    ROOT = Path(__file__).resolve().parent
    MANIFEST_PATH = ROOT / "document_test_classification.json"
    CLASSIFICATION_TEST_PATH = ROOT / "test_document_test_classification.py"

    def _read(self, name):
        return (self.ROOT / name).read_text(encoding="utf-8")

    def _bl038_section(self):
        backlog = self._read("BACKLOG.md")
        marker = "## BL-038 "
        start = backlog.index(marker)
        end = backlog.find("\n## ", start + len(marker))
        return backlog[start:] if end == -1 else backlog[start:end]

    def _status_bl038_line(self):
        status = self._read("STATUS.md")
        active = status.split("## Active work", 1)[1].split(
            "\n## 5. Recently completed work", 1
        )[0]
        return next(
            line for line in active.splitlines() if line.startswith("- BL-038 ")
        )

    def test_backlog_bl038_state_reflects_tranche3d_accepted(self):
        # tranche 3d itself is now accepted (tranche 3e is the in-progress
        # suffix); matches the same accepted-list-extraction approach as
        # test_backlog_bl038_state_reflects_tranche3c_accepted, which every
        # later tranche's own acceptance would otherwise break if this
        # checked a fixed substring immediately before "受入済み".
        bl038 = self._bl038_section()
        own_state_line = next(
            line for line in bl038.splitlines() if line.startswith("- **状態:**")
        )
        accepted_part = own_state_line.split("(", 1)[1].split("受入済み", 1)[0]
        accepted_tranches = accepted_part.split("・")
        self.assertIn("3d", accepted_tranches)
        # scope the negative check to BL-038's own state field line, not the
        # whole section -- later evidence/rationale text legitimately
        # mentions OTHER tickets' "- **状態:** 完了" field values (e.g.
        # BL-036's Category A rationale in the tranche 3d implementation
        # evidence paragraph).
        self.assertNotEqual(own_state_line.strip(), "- **状態:** 完了")

    def test_backlog_records_entries_ten_and_eleven_as_tranche3c_closeout_and_tranche3d_kickoff(self):
        # The running total-entry-count/per-string-occurrence check this
        # test used to make (an aggregate over ALL history entries) is an
        # evolving-state check that later tranches' own new entries make
        # stale by construction (matching the tranche-3d-manifest-line-count
        # precedent) -- narrowed to specifically entries 10/11's own content,
        # which tranche 3d itself added and which remain true regardless of
        # how many later entries get appended. See
        # Bl038Tranche3eRecordSyncTest for the current running totals.
        bl038 = self._bl038_section()
        history_start = bl038.index("ユーザー原文の履歴")
        history_end = bl038.index("着手時ユーザー原文:", history_start)
        history = bl038[history_start:history_end]
        entries = re.findall(
            r"^\s*(\d+)\.\s+(.*?)(?=^\s*\d+\.\s|\Z)", history, re.MULTILINE | re.DOTALL
        )
        entry10 = next(text for number, text in entries if number == "10")
        for required in (
            "tranche 3c final acceptance original",
            "2026-08-06",
            "「おk」",
            "PR #84",
            "Draft解除・Ready化",
            "tranche 3全体またはBL-038全体の完了承認でもなく",
        ):
            with self.subTest(required=required):
                self.assertIn(required, entry10)
        entry11 = next(text for number, text in entries if number == "11")
        for required in (
            "tranche 3d kickoff original",
            "2026-08-06",
            "「次へ進めて」",
            "test_status.py",
            "tranche 3d実装内容の最終受入ではなく",
        ):
            with self.subTest(required=required):
                self.assertIn(required, entry11)

    def test_backlog_records_tranche3d_kickoff_and_implementation_evidence(self):
        bl038 = self._bl038_section()
        for required in (
            "tranche 3d着手(2026-08-06)",
            "test/bl038-tranche3d-status-classification",
            "35367dd1506376776e0aa726ded6f8a31ce3a939",
            "実装証跡(tranche 3d)",
            "独立レビューround 1(tranche 3d",
            "独立レビューround 2(tranche 3d",
            "round 2修正(tranche 3d)",
            "A 0／B 31／C 39／D 28",
            "380 entries",
            "combined: **A 18／B 127／C 164／D 71",
            "STATUS_EXPECTED_C_IDS",
            "STATUS_EXPECTED_D_IDS",
            "class-shrink-within-status",
            "file-shrink-drop-status-entirely",
            # round 2's explicit framing: the reconfirmed count is not a
            # blind restoration of a superseded value
            "単なる無効化ではない",
        ):
            with self.subTest(required=required):
                self.assertIn(required, bl038)
        # round 1's temporarily-incorrect Category A reclassification must
        # not remain as current evidence anywhere in the section
        self.assertNotIn("最終分類: **test_status.py: A 5／B 28／C 39／D 26", bl038)

    def test_backlog_residual_work_names_category_c_conversion_from_tranche3d(self):
        # The residual-work bullet is a single evolving field that later
        # tranches append to; the "tranche 3dは実装中" in-progress-state
        # substring this test used to check is now stale (3d has since been
        # accepted) -- narrowed to the permanent Category C candidate counts
        # tranche 3d itself contributed, which remain true regardless of
        # what later tranches append. See Bl038Tranche3eRecordSyncTest for
        # the current in-progress state.
        bl038 = self._bl038_section()
        residual_match = re.search(r"^- \*\*残作業:\*\* .*$", bl038, re.MULTILINE)
        self.assertIsNotNone(residual_match)
        residual = residual_match.group(0)
        for required in (
            "Category C conversion",
            "tranche 3bの41件",
            "tranche 3cの84件",
            "tranche 3dの39件",
            "約1593件",
            "BL-038全体の最終受入",
        ):
            with self.subTest(required=required):
                self.assertIn(required, residual)

    def test_status_active_work_records_tranche3d_kickoff_evidence(self):
        bl038_line = self._status_bl038_line()
        for required in (
            "tranche 3d着手(2026-08-06)",
            "test/bl038-tranche3d-status-classification",
            "tranche 3d kickoff原文「次へ進めて」",
            "独立レビューround 1(tranche 3d",
            "独立レビューround 2(tranche 3d",
            "A 0／B 31／C 39／D 28",
            "combined: **A 18／B 127／C 164／D 71",
            "380 entries",
            "単なる無効化された値の復元ではない",
        ):
            with self.subTest(required=required):
                self.assertIn(required, bl038_line)
        # round 1's temporarily-incorrect Category A reclassification must
        # not remain as current evidence anywhere in this line
        self.assertNotIn("最終分類: **test_status.py: A 5／B 28／C 39／D 26", bl038_line)

    def test_manifest_status_portion_still_matches_tranche3d_corrected_counts(self):
        # tranche 3e expanded scope to 4 files; test_status.py's own
        # declared scope entry and its 98 (round-2-corrected) assertions
        # must remain unchanged. (Matches the analogous tranche-3c-portion
        # test in Bl038Tranche3cRecordSyncTest, applied one tranche later.)
        manifest = json.loads(self.MANIFEST_PATH.read_text(encoding="utf-8"))
        self.assertEqual(manifest["schema_version"], 1)
        status_scope = next(s for s in manifest["scope"] if s["file"] == "test_status.py")
        self.assertEqual(
            status_scope["classes"],
            [
                "StatusSourceOfTruthTest",
                "Sd031DecisionTest",
                "Bl035ActiveWorkTest",
                "StatusSecurityOperationsSourceOfTruthTest",
                "Bl036PostMergeRecordFixTest",
                "Bl036ProductionEvidenceSyncTest",
            ],
        )
        from collections import Counter

        # PR #85 round 1 review had (incorrectly) moved 5 fixed Version/
        # Status/enum/machine-readable-key entries in test_status.py to A,
        # based on a misreading of the classification definition. Round 2
        # review determined round 1's instructed definition was itself a
        # misapplication of BL-038's established Category A policy (a
        # repeated structural pattern with shared-helper consolidation
        # value is required, not merely a fixed/exact value) and reverted
        # those 5 entries to B/D.
        status_entries = [a for a in manifest["assertions"] if a["file"] == "test_status.py"]
        self.assertEqual(len(status_entries), 98)
        status_counts = Counter(a["category"] for a in status_entries)
        self.assertEqual(dict(status_counts), {"B": 31, "C": 39, "D": 28})
        for entry in status_entries:
            self.assertIn("targets", entry)
            self.assertNotIn("target", entry)

    def test_status_py_fixed_version_status_fields_are_b_or_d_not_a(self):
        # PR #85 round 2 review: round 1 had misread the classification
        # definition as "any fixed Version/Status/enum/machine-readable
        # value is automatically Category A", which is not BL-038's
        # established policy. Category A requires a repeated structural/
        # assertion pattern across multiple methods with clear shared-
        # helper consolidation value -- a single-occurrence exact Version/
        # Status field is B (already structural/semantic, an enum-like
        # parsed value) or D (the exactness itself is the durable contract),
        # never A merely for being fixed/exact/enum-shaped. Pin the correct
        # category for the 5 entries round 1 had mistakenly moved to A.
        import document_test_inventory as dti

        manifest = json.loads(self.MANIFEST_PATH.read_text(encoding="utf-8"))
        by_id = {a["id"]: a for a in manifest["assertions"]}
        expected_categories = {
            "test_status.py::StatusSourceOfTruthTest::test_current_generator_schema_on_main_is_still_2::assert-01": "D",
            "test_status.py::Sd031DecisionTest::test_sd031_records_date_and_status::assert-02": "B",
            "test_status.py::StatusSecurityOperationsSourceOfTruthTest::test_security_operations_itself_reflects_bl035_final_acceptance::assert-01": "D",
            "test_status.py::StatusSecurityOperationsSourceOfTruthTest::test_security_operations_itself_reflects_bl035_final_acceptance::assert-02": "B",
            "test_status.py::Bl036ProductionEvidenceSyncTest::test_backlog_bl036_still_complete_with_no_remaining_work::assert-01": "B",
        }
        for entry_id, expected_category in expected_categories.items():
            with self.subTest(id=entry_id):
                self.assertIn(entry_id, by_id)
                self.assertEqual(by_id[entry_id]["category"], expected_category)
                self.assertNotEqual(by_id[entry_id]["category"], "A")
                self.assertEqual(
                    by_id[entry_id]["action"], dti.CATEGORY_TO_ACTION[expected_category]
                )

    def test_status_py_has_no_category_a_entries_without_helper_consolidation_rationale(self):
        # Category A in this manifest requires a repeated structural/
        # assertion pattern with clear shared-helper consolidation value
        # (see CUSTOM_DOMAIN_EXPECTED_A_IDS/UI_SPEC_EXPECTED_A_IDS' own
        # rationale text for the established pattern). test_status.py has
        # no fingerprint duplicates (confirmed at kickoff) and no entries
        # meeting that bar, so it must have zero Category A entries.
        manifest = json.loads(self.MANIFEST_PATH.read_text(encoding="utf-8"))
        status_a_entries = [
            a for a in manifest["assertions"]
            if a["file"] == "test_status.py" and a["category"] == "A"
        ]
        self.assertEqual(status_a_entries, [])

    def test_backlog_still_records_tranche3d_own_manifest_line_count_as_390(self):
        # tranche 3d's own budget/exact-line-count guards checked the LIVE
        # manifest file, which was correct while tranche 3d was the latest
        # tranche -- tranche 3e's own growth (390 -> 534 lines) makes that
        # no longer meaningful to check against the live file here. What
        # remains checkable, and worth guarding, is that BACKLOG.md's own
        # frozen tranche 3d round 2 evidence paragraph still records the
        # historical fact "390行" (the manifest's line count AT tranche 3d's
        # own closure), matching this class's other historical-evidence
        # checks. tranche 3e's own current line count gets its own guard in
        # Bl038Tranche3eRecordSyncTest.
        bl038 = self._bl038_section()
        self.assertIn("manifest line countは訂正後も390行", bl038)

    def test_manifest_validates_with_zero_failures_via_document_test_inventory(self):
        import document_test_inventory as dti

        manifest = json.loads(self.MANIFEST_PATH.read_text(encoding="utf-8"))
        failures, summary = dti.validate_manifest(manifest, root=self.ROOT)
        self.assertEqual(failures, [])
        self.assertEqual(summary["unclassified"], 0)
        self.assertEqual(summary["stale"], 0)
        self.assertEqual(summary["fingerprint_mismatch"], 0)

    def test_classification_test_file_has_not_shrunk_below_26_tests(self):
        # Later tranches only ADD guards, so this tranche guards its own
        # floor; the exact current count is pinned by the newest tranche.
        source = self.CLASSIFICATION_TEST_PATH.read_text(encoding="utf-8")
        method_count = len(re.findall(r"^    def test_", source, re.MULTILINE))
        self.assertGreaterEqual(method_count, 26)

    def test_tranche3d_final_acceptance_recorded_and_bl038_overall_still_incomplete(self):
        # This test originally (during tranche 3d's own Draft-PR phase)
        # asserted tranche 3d had NOT yet been finally accepted/merged --
        # that negative was always meant to flip once tranche 3d actually
        # closed (a natural progression, not a regression). tranche 3e's
        # own closeout-sync work makes it flip now: assert the acceptance/
        # merge records ARE present, while BL-038 overall remains
        # incomplete (still true and still worth guarding).
        bl038 = self._bl038_section()
        self.assertIn("tranche 3d最終受入日", bl038)
        self.assertIn("tranche 3d merge記録", bl038)
        self.assertIn(
            "BL-038全体の最終受入は上記残作業が完了するまで行わない", bl038
        )

    def test_status_active_work_still_lists_bl038_not_recently_completed(self):
        status = self._read("STATUS.md")
        active = status.split("## Active work", 1)[1].split(
            "\n## 5. Recently completed work", 1
        )[0]
        self.assertNotIn("None.", active)
        recently_completed = status.split("## 5. Recently completed work", 1)[1]
        self.assertFalse(
            any(line.startswith("- BL-038 ") for line in recently_completed.splitlines()),
            "BL-038 must not be listed in Recently completed work during tranche 3d",
        )


class Bl038Tranche3eRecordSyncTest(unittest.TestCase):
    """BL-038 tranche 3e (PR #85/tranche 3d closeout sync + next
    document/static-contract classification scope selection and
    classification) kickoff/implementation record-sync checks."""

    ROOT = Path(__file__).resolve().parent
    MANIFEST_PATH = ROOT / "document_test_classification.json"
    CLASSIFICATION_TEST_PATH = ROOT / "test_document_test_classification.py"

    def _read(self, name):
        return (self.ROOT / name).read_text(encoding="utf-8")

    def _bl038_section(self):
        backlog = self._read("BACKLOG.md")
        marker = "## BL-038 "
        start = backlog.index(marker)
        end = backlog.find("\n## ", start + len(marker))
        return backlog[start:] if end == -1 else backlog[start:end]

    def _status_bl038_line(self):
        status = self._read("STATUS.md")
        active = status.split("## Active work", 1)[1].split(
            "\n## 5. Recently completed work", 1
        )[0]
        return next(
            line for line in active.splitlines() if line.startswith("- BL-038 ")
        )

    def test_backlog_bl038_state_reflects_tranche3e_accepted(self):
        # 3e's OWN durable fact: once accepted it stays in the ACCEPTED list.
        bl038 = self._bl038_section()
        own_state_line = next(
            line for line in bl038.splitlines() if line.startswith("- **状態:**")
        )
        self.assertIn("実装中(", own_state_line)
        accepted_part = own_state_line.split("(", 1)[1].split("受入済み", 1)[0]
        accepted_tranches = accepted_part.split("・")
        for tranche in ("tranche 1", "2", "3a", "3b", "3c", "3d", "3e"):
            with self.subTest(tranche=tranche):
                self.assertIn(tranche, accepted_tranches)
        # Accepted and in-progress must stay disjoint.
        in_progress = own_state_line.split("／", 1)[1].split("実装中", 1)[0]
        self.assertNotIn(in_progress.replace("tranche ", ""), accepted_tranches)
        self.assertNotEqual(own_state_line.strip(), "- **状態:** 完了")

    def test_backlog_records_entries_twelve_and_thirteen_with_updated_totals(self):
        bl038 = self._bl038_section()
        history_start = bl038.index("ユーザー原文の履歴")
        history_end = bl038.index("着手時ユーザー原文:", history_start)
        history = bl038[history_start:history_end]
        # 3e-anchored tallies only; the full header is the current tranche's.
        # 「はい」 was 1 at tranche 3e; entry 24 repeated the same string, so
        # the header tally moved to 2 while entry 13 itself is untouched.
        self.assertIn("「おk」7回", history)
        # Entry 13 is one of the 「はい」; 3j/3k/3m/3n/3o/3p added entries 24, 26,
        # 30, 33, 35 and 37, so the running tally is now 7.
        self.assertIn("「はい」12回", history)
        self.assertNotIn("「はい」6回", history)
        entries = re.findall(
            r"^\s*(\d+)\.\s+(.*?)(?=^\s*\d+\.\s|\Z)", history, re.MULTILINE | re.DOTALL
        )
        # tranche 3f appended 14/15/16; later tranches may only APPEND.
        numbers = [number for number, _ in entries]
        self.assertGreaterEqual(len(numbers), 16)
        self.assertEqual(numbers, [str(i) for i in range(1, len(numbers) + 1)])
        entry12 = next(text for number, text in entries if number == "12")
        for required in (
            "tranche 3d final acceptance original",
            "2026-08-06",
            "「おk」",
            "PR #85",
            "Draft解除・Ready化",
            "tranche 3全体またはBL-038全体の完了承認でもなく",
        ):
            with self.subTest(required=required):
                self.assertIn(required, entry12)
        entry13 = next(text for number, text in entries if number == "13")
        for required in (
            "tranche 3e kickoff original",
            "2026-08-06",
            "「はい」",
            "tranche 3e実装内容の最終受入ではなく",
        ):
            with self.subTest(required=required):
                self.assertIn(required, entry13)

    def test_backlog_records_tranche3d_final_acceptance_and_merge_evidence(self):
        bl038 = self._bl038_section()
        for required in (
            "tranche 3d最終受入日:** 2026-08-06",
            "tranche 3d最終受入原文:** 「おk」",
            "c53fa7b2c5a0602f98e7eaf6bda43f8b2ffb931f",
            "31093226011",
            "1880 tests OK",
            "7efd1086a7f3034442d040f52da329be8a0c1eb0",
            "35367dd1506376776e0aa726ded6f8a31ce3a939",
            "31095253243",
        ):
            with self.subTest(required=required):
                self.assertIn(required, bl038)

    def test_backlog_bl034_original_wording_is_intact_not_mutation_residue(self):
        # PR #86 round 2 review Blocker 1: round 1's mutation-style
        # verification for the 所有権確認成功 -> 所有権の確認に成功 reword left
        # residue committed in BL-034's own historical record (the first
        # mutation attempt was never reverted -- a LATER backup was taken
        # from the already-mutated state, so the "revert" only restored to
        # that mutated baseline). test_security_requirements.py's own
        # test_cloudflare_dashboard_and_search_console_are_confirmed scopes
        # to "## BL-034" through "\n## 完了済み参照" -- which also contains
        # this PR's own BACKLOG.md round 1 review paragraphs (further down
        # the document, before "## 完了済み参照"), so a duplicate mention of
        # the ORIGINAL phrase in that later prose can mask a genuine
        # regression in BL-034's own body. Scope tightly to BL-034's own
        # section only (## BL-034 through the next ## BL-035 heading) to
        # close that gap.
        backlog = self._read("BACKLOG.md")
        bl034 = backlog.split("## BL-034", 1)[1].split("\n## BL-035", 1)[0]
        self.assertIn("所有権確認成功", bl034)
        self.assertNotIn("所有権の確認に成功", bl034)

    def test_backlog_records_tranche3e_kickoff_and_implementation_evidence(self):
        bl038 = self._bl038_section()
        for required in (
            "tranche 3e着手(2026-08-06)",
            "test/bl038-tranche3e-next-classification",
            "実装証跡(tranche 3e)",
            "候補実測(tranche 3e)",
            "選択(tranche 3e)",
            "test_security_requirements.py",
            "Bl034Round2ReviewCorrectionsTest",
            "Bl034ImplementationAcceptanceTest",
            "Bl034CloseoutTest",
            "StatusSecurityRequirementsSourceOfTruthTest",
            "A 0／B 37／C 71／D 35",
            "523 entries",
            "combined: **A 18／B 164／C 235／D 106",
        ):
            with self.subTest(required=required):
                self.assertIn(required, bl038)

    def test_manifest_security_requirements_tranche3e_portion_is_unchanged(self):
        # tranche 3f added a fifth class to the same scope entry, so the
        # combined-count guard moved to Bl038Tranche3fRecordSyncTest. What
        # stays checkable here is that tranche 3e's OWN four classes and
        # their 143 round-1-corrected entries are unchanged.
        manifest = json.loads(self.MANIFEST_PATH.read_text(encoding="utf-8"))
        self.assertEqual(manifest["schema_version"], 1)
        self.assertEqual(
            [s["file"] for s in manifest["scope"]],
            ["test_custom_domain.py", "test_ui_spec.py", "test_status.py", "test_security_requirements.py"],
        )
        tranche3e_classes = [
            "Bl034Round2ReviewCorrectionsTest",
            "Bl034ImplementationAcceptanceTest",
            "Bl034CloseoutTest",
            "StatusSecurityRequirementsSourceOfTruthTest",
        ]
        sr_scope = next(
            s for s in manifest["scope"] if s["file"] == "test_security_requirements.py"
        )
        self.assertEqual(
            [c for c in sr_scope["classes"] if c in tranche3e_classes], tranche3e_classes
        )
        from collections import Counter

        # PR #86 round 1 review corrected 12 test_security_requirements.py
        # entries misclassified B: 9 to C (raw negative multi-token
        # substrings, a stylistic ID-range embedded in prose, a raw noun
        # compound not extracted to a field, a multi-word phrase with a
        # common-noun suffix, a mixed atomic/noun-phrase loop check) and 3
        # to D (bare "PR #NN" mentions -- substrings of this document's
        # always-fully-linked PR references, matching this manifest's own
        # established PR-reference precedent of C/D, never B).
        sr_entries = [
            a for a in manifest["assertions"]
            if a["file"] == "test_security_requirements.py" and a["class"] in tranche3e_classes
        ]
        self.assertEqual(len(sr_entries), 143)
        sr_counts = Counter(a["category"] for a in sr_entries)
        self.assertEqual(dict(sr_counts), {"B": 37, "C": 71, "D": 35})
        for entry in sr_entries:
            self.assertIn("targets", entry)
            self.assertNotIn("target", entry)

    def test_security_requirements_five_reviewer_flagged_ids_are_correctly_classified(self):
        # PR #86 round 1 review Blocker 2: 5 specific entries were
        # misclassified B and are pinned here to their corrected category
        # (2 to C: raw negative multi-token substrings/noun compounds not
        # extracted to a field; 3 to D: bare PR-number mentions that are
        # part of a historical-acceptance-evidence bundle alongside a
        # sibling SHA/CI-run-ID assertion in the same method).
        manifest = json.loads(self.MANIFEST_PATH.read_text(encoding="utf-8"))
        by_id = {a["id"]: a for a in manifest["assertions"]}
        expected_categories = {
            "test_security_requirements.py::Bl034ImplementationAcceptanceTest::"
            "test_dashboard_and_search_console_are_confirmed_by_closeout::assert-01": "C",
            "test_security_requirements.py::Bl034CloseoutTest::"
            "test_sr047_and_gap018_confirm_dashboard_and_search_console_not_unconfirmed::assert-05": "C",
            "test_security_requirements.py::Bl034CloseoutTest::"
            "test_cloudflare_dashboard_and_search_console_are_confirmed::assert-08": "C",
            "test_security_requirements.py::Bl034ImplementationAcceptanceTest::"
            "test_sd032_is_accepted::assert-04": "D",
            "test_security_requirements.py::Bl034CloseoutTest::"
            "test_final_acceptance_record_does_not_touch_out_of_scope_documents::assert-03": "D",
        }
        import document_test_inventory as dti

        for entry_id, expected_category in expected_categories.items():
            with self.subTest(id=entry_id):
                self.assertIn(entry_id, by_id)
                self.assertEqual(by_id[entry_id]["category"], expected_category)
                self.assertNotEqual(by_id[entry_id]["category"], "B")
                self.assertEqual(
                    by_id[entry_id]["action"], dti.CATEGORY_TO_ACTION[expected_category]
                )

    def test_backlog_still_records_tranche3e_own_manifest_line_count_as_534(self):
        # Same re-anchoring as tranche 3d's: tranche 3f's growth (534 -> 596
        # lines) makes an exact LIVE check meaningless here, so this guards
        # that BACKLOG.md still records the historical "534行". The live
        # count is guarded in Bl038Tranche3fRecordSyncTest.
        bl038 = self._bl038_section()
        self.assertIn("534行", bl038)
        self.assertLessEqual(len(self.MANIFEST_PATH.read_text(encoding="utf-8").splitlines()), 600)

    def test_manifest_validates_with_zero_failures_via_document_test_inventory(self):
        import document_test_inventory as dti

        manifest = json.loads(self.MANIFEST_PATH.read_text(encoding="utf-8"))
        failures, summary = dti.validate_manifest(manifest, root=self.ROOT)
        self.assertEqual(failures, [])
        self.assertEqual(summary["unclassified"], 0)
        self.assertEqual(summary["stale"], 0)
        self.assertEqual(summary["fingerprint_mismatch"], 0)

    def test_classification_test_file_has_not_shrunk_below_26_tests(self):
        # Later tranches only ADD guards, so this tranche guards its own
        # floor; the exact current count is pinned by the newest tranche.
        source = self.CLASSIFICATION_TEST_PATH.read_text(encoding="utf-8")
        method_count = len(re.findall(r"^    def test_", source, re.MULTILINE))
        self.assertGreaterEqual(method_count, 26)

    def test_tranche3e_four_classes_have_no_category_a_entries(self):
        # Same policy as test_status.py: Category A requires a repeated
        # structural pattern across multiple methods with clear shared-
        # helper consolidation value, not merely a recurring exact/fixed
        # value re-anchored at different historical checkpoints (the 17
        # fingerprint-duplicate groups in THIS tranche's scope are all of
        # the latter kind). Scoped to tranche 3e's own four classes: tranche
        # 3f's added class has a duplicated METHOD PAIR that does satisfy the
        # policy and is correctly Category A, guarded in the 3f class.
        manifest = json.loads(self.MANIFEST_PATH.read_text(encoding="utf-8"))
        tranche3e_classes = {
            "Bl034Round2ReviewCorrectionsTest",
            "Bl034ImplementationAcceptanceTest",
            "Bl034CloseoutTest",
            "StatusSecurityRequirementsSourceOfTruthTest",
        }
        sr_a_entries = [
            a for a in manifest["assertions"]
            if a["file"] == "test_security_requirements.py"
            and a["class"] in tranche3e_classes
            and a["category"] == "A"
        ]
        self.assertEqual(sr_a_entries, [])

    def test_backlog_residual_work_still_names_tranche3e_category_c_count(self):
        # tranche 3e's 71 Category C entries stay in the residual-work list
        # after acceptance -- deferred conversions, not work acceptance
        # closed. Anchored on 3e's own count and its place on the accepted side.
        bl038 = self._bl038_section()
        residual_match = re.search(r"^- \*\*残作業:\*\* .*$", bl038, re.MULTILINE)
        self.assertIsNotNone(residual_match)
        residual = residual_match.group(0)
        for required in (
            "tranche 3eの71件",
            "BL-038全体の最終受入は上記残作業が完了するまで行わない",
        ):
            with self.subTest(required=required):
                self.assertIn(required, residual)
        # The compact current acceptance summary now includes accepted tranche 3q.
        self.assertIn("tranche 1〜3qは受入済み", residual)

    def test_tranche3e_final_acceptance_original_and_evidence_are_recorded(self):
        # PR #88 round 1 Blocker 1: PR #86 records the tranche 3e acceptance
        # original as `- **User original (2026-08-06):** 「おk」`. Pin the
        # quote, its PR and role -- an earlier revision claimed there was none.
        bl038 = self._bl038_section()
        for required in (
            "tranche 3e最終受入日:** 2026-08-06",
            "70f1e79aae5185de910d9fac1f1bdf39ccad36ef",
            "31105180228",
            "1894 tests OK",
            "ae1cfa2c462024063df84ea8f1cca547c4e96b2d",
        ):
            with self.subTest(required=required):
                self.assertIn(required, bl038)
        acceptance_quote_line = next(
            line for line in bl038.splitlines()
            if line.startswith("- **tranche 3e最終受入原文:**")
        )
        self.assertIn("「おk」", acceptance_quote_line)
        self.assertIn("PR #86", acceptance_quote_line)
        self.assertIn("上記14", acceptance_quote_line)
        # The superseded "no original was supplied" wording must be gone.
        for banned in ("記録しない", "捏造しない", "提示されなかった", "推測"):
            with self.subTest(banned=banned):
                self.assertNotIn(banned, acceptance_quote_line)
        # Entry 14 carries the quote AND its role, distinct from the six
        # identical 「おk」 originals before it.
        history = bl038[bl038.index("ユーザー原文の履歴"):bl038.index("着手時ユーザー原文:")]
        entry14 = next(
            text for number, text in re.findall(
                r"^\s*(\d+)\.\s+(.*?)(?=^\s*\d+\.\s|\Z)", history, re.MULTILINE | re.DOTALL
            ) if number == "14"
        )
        for required in (
            "tranche 3e final acceptance original",
            "2026-08-06",
            "「おk」",
            "PR #86",
            "Ready化",
            "tranche 3全体またはBL-038全体の完了承認でもなく",
        ):
            with self.subTest(required=required):
                self.assertIn(required, entry14)
        self.assertIn(
            "BL-038全体の最終受入は上記残作業が完了するまで行わない", bl038
        )

    def test_backlog_history_no_longer_claims_a_missing_tranche3e_original(self):
        # Scoped to the history header: the count must show seven 「おk」
        # originals, without the withdrawn "original unavailable" claim.
        bl038 = self._bl038_section()
        header = next(
            line for line in bl038.splitlines()
            if line.startswith("- **ユーザー原文の履歴")
        )
        self.assertIn("「おk」7回", header)
        self.assertNotIn("「おk」6回", header)
        for banned in ("提示されなかった", "捏造", "登録しない"):
            with self.subTest(banned=banned):
                self.assertNotIn(banned, header)

    def test_status_active_work_records_tranche3e_kickoff_evidence(self):
        bl038_line = self._status_bl038_line()
        for required in (
            "tranche 3d最終受入(2026-08-06)",
            "c53fa7b2c5a0602f98e7eaf6bda43f8b2ffb931f",
            "7efd1086a7f3034442d040f52da329be8a0c1eb0",
            "31095253243",
            "tranche 3e着手(2026-08-06)",
            "test/bl038-tranche3e-next-classification",
            "実装証跡(tranche 3e)",
            "A 0／B 37／C 71／D 35",
            "combined: **A 18／B 164／C 235／D 106",
        ):
            with self.subTest(required=required):
                self.assertIn(required, bl038_line)

    def test_status_active_work_still_lists_bl038_not_recently_completed(self):
        status = self._read("STATUS.md")
        active = status.split("## Active work", 1)[1].split(
            "\n## 5. Recently completed work", 1
        )[0]
        self.assertNotIn("None.", active)
        recently_completed = status.split("## 5. Recently completed work", 1)[1]
        self.assertFalse(
            any(line.startswith("- BL-038 ") for line in recently_completed.splitlines()),
            "BL-038 must not be listed in Recently completed work during tranche 3e",
        )


class Bl038Tranche3fRecordSyncTest(unittest.TestCase):
    """BL-038 tranche 3f (PR #86/tranche 3e closeout sync + classification
    of test_security_requirements.py::Bl031AcceptanceAndBl032RegistrationTest)
    kickoff/implementation record-sync checks. The BACKLOG/STATUS/manifest
    readers are the tranche 3e class's, reused rather than re-typed."""

    ROOT = Path(__file__).resolve().parent
    MANIFEST_PATH = ROOT / "document_test_classification.json"
    CLASSIFICATION_TEST_PATH = ROOT / "test_document_test_classification.py"
    TRANCHE_3F_CLASS = "Bl031AcceptanceAndBl032RegistrationTest"

    _read = Bl038Tranche3eRecordSyncTest._read
    _bl038_section = Bl038Tranche3eRecordSyncTest._bl038_section
    _status_bl038_line = Bl038Tranche3eRecordSyncTest._status_bl038_line

    def _manifest(self):
        return json.loads(self.MANIFEST_PATH.read_text(encoding="utf-8"))

    def test_backlog_bl038_state_reflects_tranche3f_accepted(self):
        # Re-anchored at tranche 3g: 3f is on the ACCEPTED side, after 3e.
        bl038 = self._bl038_section()
        own_state_line = next(
            line for line in bl038.splitlines() if line.startswith("- **状態:**")
        )
        self.assertIn("実装中(", own_state_line)
        accepted_part = own_state_line.split("(", 1)[1].split("受入済み", 1)[0]
        accepted_tranches = accepted_part.split("・")
        self.assertIn("3e", accepted_tranches)
        self.assertIn("3f", accepted_tranches)
        self.assertLess(accepted_tranches.index("3e"), accepted_tranches.index("3f"))
        in_progress = own_state_line.split("／", 1)[1].split("実装中", 1)[0]
        self.assertNotIn(in_progress.replace("tranche ", ""), accepted_tranches)
        self.assertNotEqual(own_state_line.strip(), "- **状態:** 完了")

    def test_backlog_records_entries_fifteen_and_sixteen_for_tranche3f(self):
        bl038 = self._bl038_section()
        history_start = bl038.index("ユーザー原文の履歴")
        history_end = bl038.index("着手時ユーザー原文:", history_start)
        history = bl038[history_start:history_end]
        entries = re.findall(
            r"^\s*(\d+)\.\s+(.*?)(?=^\s*\d+\.\s|\Z)", history, re.MULTILINE | re.DOTALL
        )
        # Later tranches append only: entries 1-16 stay contiguous from 1.
        numbers = [number for number, _ in entries]
        self.assertGreaterEqual(len(numbers), 16)
        self.assertEqual(numbers, [str(i) for i in range(1, len(numbers) + 1)])
        entry15 = next(text for number, text in entries if number == "15")
        for required in (
            "tranche 3f kickoff original",
            "2026-08-07",
            "test/bl038-tranche3f-next-classification",
            self.TRANCHE_3F_CLASS,
            "tranche 3f実装内容の最終受入ではなく",
        ):
            with self.subTest(required=required):
                self.assertIn(required, entry15)
        # PR #88 round 2 Blocker 1: entry 15 still said 過去13件 after entry 14
        # was inserted before it; an entries-exist check could not catch that.
        self.assertIn("過去14件のいずれとも異なる", entry15)
        self.assertNotIn("過去13件", entry15)
        # The 62-vs-62 tie was resolved by this separate, explicit 「A」 answer
        # AFTER disclosure -- not by the kickoff. Pin it as its own original.
        entry16 = next(text for number, text in entries if number == "16")
        for required in (
            "tranche 3f candidate selection original",
            "2026-08-07",
            "「A」",
            self.TRANCHE_3F_CLASS,
            "Bl031SecurityOperationsReconciliationTest",
            "tranche 3f実装内容の最終受入ではなく",
        ):
            with self.subTest(required=required):
                self.assertIn(required, entry16)

    def test_backlog_records_tranche3e_merge_and_pages_outcome_without_rewriting_runs(self):
        # PR #86's merge-triggered Pages run FAILED (build ok, deploy queue
        # timeout). The green run is PR #87's, and only after re-running its
        # failed deploy job -- not a retroactive success for 31108037248.
        bl038 = self._bl038_section()
        merge_line = next(
            line for line in bl038.splitlines()
            if line.startswith("- **tranche 3e merge記録:**")
        )
        for required in (
            "ae1cfa2c462024063df84ea8f1cca547c4e96b2d",
            "7efd1086a7f3034442d040f52da329be8a0c1eb0",
            "70f1e79aae5185de910d9fac1f1bdf39ccad36ef",
            "31108037248",
            "31111371109",
            "PR #87",
            "deployment_queued",
            "attempt 2",
            "Pull Request CI run 31105180228",
        ):
            with self.subTest(required=required):
                self.assertIn(required, merge_line)
        self.assertIn("failure", merge_line)
        self.assertIn("遡及的にsuccessへ変えるものではない", merge_line)
        self.assertIn("run 31108037248はfailureのまま維持する", merge_line)

    def test_backlog_and_status_record_the_pr87_branch_point_not_the_pr86_merge(self):
        # PR #88 round 1 Blocker 2: cut from main at PR #87's merge commit
        # a00ef0eb..., not PR #86's ae1cfa2... PR #86/tranche 3e is what
        # this tranche syncs closeout FOR, not the branch point.
        start_line = next(
            line for line in self._bl038_section().splitlines()
            if line.startswith("- **tranche 3f着手(2026-08-07):**")
        )
        status_line = self._status_bl038_line()
        for text in (start_line, status_line):
            with self.subTest(scope=text[:40]):
                self.assertIn("a00ef0ebaea37edb583c99acaaf475f13ff65f50", text)
                self.assertIn("PR #87", text)
                self.assertIn("直接", text)
        self.assertIn("branchの起点commitではない", start_line)
        self.assertIn("branchの起点commitではない", status_line)

    def test_backlog_records_tranche3f_measurement_selection_and_tie(self):
        bl038 = self._bl038_section()
        for required in (
            "候補実測(tranche 3f)",
            "選択(tranche 3f)",
            "実装証跡(tranche 3f)",
            "13 methods",
            "assertIn 45／assertNotIn 12／assertEqual 3／assertTrue 2",
            # The 62-vs-62 tie must be recorded, not silently resolved: it
            # was resolved by the explicit 「A」 answer after disclosure.
            "Bl031SecurityOperationsReconciliationTest",
            "candidate selection非一意",
            "A 4／B 11／C 33／D 14(total 62)",
        ):
            with self.subTest(required=required):
                self.assertIn(required, bl038)
        selection_line = next(
            line for line in bl038.splitlines()
            if line.startswith("- **選択(tranche 3f):**")
        )
        self.assertIn("候補Aを明示的に選択する発言「A」(上記16)", selection_line)
        self.assertIn(
            "tieはkickoff指示(上記15)の時点で解決されていたわけではなく", selection_line
        )
        self.assertIn("最終受入・Ready化・merge承認ではない", selection_line)

    def test_manifest_is_scoped_to_four_files_with_tranche3f_combined_counts(self):
        manifest = self._manifest()
        self.assertEqual(manifest["schema_version"], 1)
        self.assertEqual(
            [s["file"] for s in manifest["scope"]],
            ["test_custom_domain.py", "test_ui_spec.py", "test_status.py", "test_security_requirements.py"],
        )
        sr_scope = next(
            s for s in manifest["scope"] if s["file"] == "test_security_requirements.py"
        )
        # Source order: the tranche 3f class is declared FIRST because its
        # `class` statement precedes tranche 3e's four in the source file.
        self.assertEqual(
            sr_scope["classes"],
            [
                self.TRANCHE_3F_CLASS,
                "Bl034Round2ReviewCorrectionsTest",
                "Bl034ImplementationAcceptanceTest",
                "Bl034CloseoutTest",
                "StatusSecurityRequirementsSourceOfTruthTest",
            ],
        )
        self.assertEqual(len(manifest["assertions"]), 585)
        from collections import Counter

        counts = Counter(a["category"] for a in manifest["assertions"])
        self.assertEqual(dict(counts), {"A": 22, "B": 175, "C": 268, "D": 120})
        sr_entries = [a for a in manifest["assertions"] if a["file"] == "test_security_requirements.py"]
        self.assertEqual(len(sr_entries), 205)
        new_entries = [a for a in sr_entries if a["class"] == self.TRANCHE_3F_CLASS]
        self.assertEqual(len(new_entries), 62)
        self.assertEqual(
            dict(Counter(a["category"] for a in new_entries)),
            {"A": 4, "B": 11, "C": 33, "D": 14},
        )
        for entry in new_entries:
            with self.subTest(id=entry["id"]):
                self.assertIn("targets", entry)
                self.assertNotIn("target", entry)

    def test_tranche3f_entries_are_appended_without_disturbing_the_existing_523(self):
        # The 523 entries accepted through tranche 3e must survive verbatim and
        # in order: inserting the 3f class moves where the new block lands only.
        manifest = self._manifest()
        existing = [
            a for a in manifest["assertions"] if a["class"] != self.TRANCHE_3F_CLASS
        ]
        self.assertEqual(len(existing), 523)
        by_file = [a["file"] for a in existing]
        self.assertEqual(
            [by_file[0], by_file[96], by_file[97], by_file[281], by_file[282], by_file[379], by_file[380], by_file[522]],
            [
                "test_custom_domain.py", "test_custom_domain.py",
                "test_ui_spec.py", "test_ui_spec.py",
                "test_status.py", "test_status.py",
                "test_security_requirements.py", "test_security_requirements.py",
            ],
        )

    def test_tranche3f_category_a_is_a_duplicated_method_pair_not_a_recurring_value(self):
        # The four Category A entries are the one substantive difference from
        # the provisional A 0/B 19/C 30/D 13 tally, so pin exactly which.
        manifest = self._manifest()
        a_ids = sorted(
            a["id"] for a in manifest["assertions"]
            if a["file"] == "test_security_requirements.py" and a["category"] == "A"
        )
        prefix = "test_security_requirements.py::" + self.TRANCHE_3F_CLASS + "::"
        self.assertEqual(
            a_ids,
            [
                prefix + "test_sd002_remains_accepted_implemented_and_not_marked_superseded_by_sd030::assert-01",
                prefix + "test_sd002_remains_accepted_implemented_and_not_marked_superseded_by_sd030::assert-02",
                prefix + "test_sd030_does_not_mark_sd002_as_implemented_superseded::assert-01",
                prefix + "test_sd030_does_not_mark_sd002_as_implemented_superseded::assert-02",
            ],
        )
        import document_test_inventory as dti

        by_id = {a["id"]: a for a in manifest["assertions"]}
        for entry_id in a_ids:
            with self.subTest(id=entry_id):
                self.assertEqual(by_id[entry_id]["action"], dti.CATEGORY_TO_ACTION["A"])
        # Demonstrate the duplication from the live source: the two methods
        # must carry the identical pair of fingerprints.
        records = dti.enumerate_assertions(
            self._read("test_security_requirements.py"),
            "test_security_requirements.py",
            [self.TRANCHE_3F_CLASS],
        )
        fingerprints = {}
        for record in records:
            if record.id in set(a_ids):
                fingerprints.setdefault(record.method, set()).add(record.fingerprint)
        self.assertEqual(len(fingerprints), 2)
        first, second = fingerprints.values()
        self.assertEqual(len(first), 2)
        self.assertEqual(first, second)

    def test_tranche2_sd030_d_classification_is_carried_forward_unchanged(self):
        # BL-038 tranche 2 classified the SD-030 146-character sentence as D
        # and locked it in BACKLOG.md; tranche 3f's entry must agree.
        manifest = self._manifest()
        entry = next(
            a for a in manifest["assertions"]
            if a["id"].endswith(
                "::test_sd030_records_that_mode_restrictions_are_not_yet_enforced_in_production::assert-04"
            )
        )
        self.assertEqual(entry["category"], "D")
        self.assertEqual(entry["action"], "historical_keep")

    def test_manifest_line_count_is_within_the_600_line_cap(self):
        lines = self.MANIFEST_PATH.read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(lines), 596)
        self.assertLessEqual(len(lines), 600)

    def test_manifest_validates_with_zero_failures_via_document_test_inventory(self):
        import document_test_inventory as dti

        failures, summary = dti.validate_manifest(self._manifest(), root=self.ROOT)
        self.assertEqual(failures, [])
        self.assertEqual(summary["unclassified"], 0)
        self.assertEqual(summary["stale"], 0)
        self.assertEqual(summary["fingerprint_mismatch"], 0)
        self.assertEqual(
            summary["category_counts"], {"A": 22, "B": 175, "C": 268, "D": 120}
        )

    def test_classification_scope_guard_class_has_32_tests(self):
        # 26 before tranche 3f, 28 after its round 1; round 2 added four (two
        # guards, each with its mutation test). Re-anchored at tranche 3g on
        # the tranche 3f guard CLASS, not the whole file.
        source = self.CLASSIFICATION_TEST_PATH.read_text(encoding="utf-8")
        block = next(
            b for b in re.split(r"^class ", source, flags=re.MULTILINE)
            if b.startswith("DocumentTestClassificationScopeTest")
        )
        method_count = len(re.findall(r"^    def test_", block, re.MULTILINE))
        self.assertEqual(method_count, 32)

    def test_round2_structural_guards_are_present_in_the_classification_suite(self):
        # These guards are narrow: one loop binding, one Category A method
        # pair. They do NOT change document_test_inventory's per-assertion
        # fingerprint, asserted here so the record cannot overclaim.
        source = self.CLASSIFICATION_TEST_PATH.read_text(encoding="utf-8")
        for required in (
            "def _assert_version_marker_loop_contract",
            "def test_version_marker_loop_literal_mutation_is_caught_only_by_the_new_guard",
            "def _assert_category_a_methods_are_whole_method_duplicates",
            "def test_category_a_extraction_change_in_one_method_is_caught_only_by_the_new_guard",
            # the pre-existing fingerprint-only proof must survive alongside
            "def test_security_requirements_category_a_entries_are_a_real_duplicated_method_pair",
        ):
            with self.subTest(required=required):
                self.assertIn(required, source)
        inventory = (self.ROOT / "document_test_inventory.py").read_text(encoding="utf-8")
        self.assertIn("def canonical_fingerprint(node):", inventory)
        self.assertIn("return _hash_dumps([node])", inventory)

    def test_security_requirements_source_module_is_unchanged_by_this_tranche(self):
        # Category C is refactor_later only: the module must still hold the
        # exact raw assertions the manifest names.
        source = self._read("test_security_requirements.py")
        for literal in (
            'self.assertIn("ok進もう", acceptance)',
            'self.assertNotIn("未受入", bl031)',
            'self.assertIn("成功済み", residual)',
        ):
            with self.subTest(literal=literal):
                self.assertIn(literal, source)

    def test_no_category_c_source_conversion_and_bl038_overall_incomplete(self):
        # 3f's acceptance closed 3f ONLY: its 33 Category C entries are still
        # unconverted residual work and BL-038 as a whole is still open. (The
        # 3f closeout evidence itself is pinned by the tranche 3g class, the
        # tranche that synced it -- the same hand-off 3e/3f used.)
        bl038 = self._bl038_section()
        self.assertIn("tranche 3fの33件", bl038)
        self.assertIn(
            "BL-038全体の最終受入は上記残作業が完了するまで行わない", bl038
        )
        own_state_line = next(
            line for line in bl038.splitlines() if line.startswith("- **状態:**")
        )
        self.assertNotEqual(own_state_line.strip(), "- **状態:** 完了")

    def test_status_active_work_records_tranche3f_evidence(self):
        bl038_line = self._status_bl038_line()
        for required in (
            "tranche 3e最終受入・merge(2026-08-06)",
            "tranche 3e最終受入原文は「おk」",
            "70f1e79aae5185de910d9fac1f1bdf39ccad36ef",
            "ae1cfa2c462024063df84ea8f1cca547c4e96b2d",
            "a00ef0ebaea37edb583c99acaaf475f13ff65f50",
            "Pull Request CI run 31105180228",
            "31108037248",
            "31111371109",
            "tranche 3f着手(2026-08-07)",
            "test/bl038-tranche3f-next-classification",
            "実装証跡(tranche 3f)",
            "A 4／B 11／C 33／D 14(total 62)",
            "combined: **A 22／B 175／C 268／D 120(total 585)**",
            "596行",
        ):
            with self.subTest(required=required):
                self.assertIn(required, bl038_line)

    def test_status_active_work_still_lists_bl038_not_recently_completed(self):
        status = self._read("STATUS.md")
        active = status.split("## Active work", 1)[1].split(
            "\n## 5. Recently completed work", 1
        )[0]
        self.assertNotIn("None.", active)
        recently_completed = status.split("## 5. Recently completed work", 1)[1]
        self.assertFalse(
            any(line.startswith("- BL-038 ") for line in recently_completed.splitlines()),
            "BL-038 must not be listed in Recently completed work while it is in progress",
        )


class Bl038Tranche3gRecordSyncTest(unittest.TestCase):
    """BL-038 tranche 3g record-sync checks, re-anchored by tranche 3h to
    HISTORICAL facts: tranche 3g is accepted (PR #89, merged), it came after
    3f and before 3h, and it shipped the sharding infrastructure with zero
    classification -- including the fact that NO additional shard existed
    yet at that time. Nothing here asserts a current state; the current
    shard count and combined totals belong to Bl038Tranche3hRecordSyncTest
    and to the classification suite."""

    ROOT = Bl038Tranche3eRecordSyncTest.ROOT
    _read = Bl038Tranche3eRecordSyncTest._read
    _bl038_section = Bl038Tranche3eRecordSyncTest._bl038_section
    _status_bl038_line = Bl038Tranche3eRecordSyncTest._status_bl038_line

    def test_tranche3g_is_recorded_as_accepted_after_3f_and_before_3h(self):
        bl038 = self._bl038_section()
        own_state_line = next(l for l in bl038.splitlines() if l.startswith("- **状態:**"))
        accepted = own_state_line.split("(", 1)[1].split("受入済み", 1)[0].split("・")
        self.assertIn("3f", accepted)
        self.assertIn("3g", accepted)  # 3g is now accepted, not in progress
        self.assertIn("3i", accepted)  # accepted since PR #91 merged
        self.assertIn("3j", accepted)  # accepted since PR #92 merged
        self.assertIn("3k", accepted)  # accepted since PR #93 merged
        self.assertIn("3l", accepted)  # accepted since PR #94 merged
        self.assertIn("3m", accepted)  # accepted since PR #95 merged
        self.assertIn("3n", accepted)  # accepted since PR #96 merged
        self.assertIn("3o", accepted)  # accepted since PR #97 merged
        self.assertIn("3q", accepted)  # accepted by PR #99 final acceptance
        self.assertNotIn("tranche 3g実装中", own_state_line)
        # 3g sits strictly between 3f and 3h in the record.
        self.assertLess(bl038.index("tranche 3f最終受入日:"), bl038.index("tranche 3g最終受入日:"))
        self.assertLess(bl038.index("tranche 3g最終受入日:"), bl038.index("tranche 3h着手(2026-08-07)"))

    def test_backlog_records_the_tranche3g_final_acceptance_and_merge_evidence(self):
        lines = self._bl038_section().splitlines()
        for prefix, requirements in (
            ("- **tranche 3g最終受入日:**", ("2026-08-07",)),
            ("- **tranche 3g最終受入原文:**", ("「ok」", "上記19", "別の発言")),
            ("- **tranche 3g最終受入原文の解釈:**",
             ("PR #89", "Ready化", "通常のmerge commit方式",
              "Category C source conversion承認ではなく", "BL-038全体の完了承認でもなく")),
            ("- **tranche 3g最終受入証跡:**",
             ("c4d467f8e69f99e8a5f9bf5bf403980560b4e150", "31173107249", "Accept／Blocker 0",
              "1939 tests OK", "156 tests OK", "classification 34・inventory 95・utils 27",
              "104 tests OK", "111 tests OK", "120 tests OK",
              "962 insertions／37 deletions", "999 changed lines")),
            ("- **tranche 3g merge記録:**",
             ("0f8acc24355262c9325d8dea6a7b86960fb53615",
              "66ef88e54ab6245f83af44c696834569af2b58f2",
              "c4d467f8e69f99e8a5f9bf5bf403980560b4e150",
              "31173887656", "attempt 1", "dynamic", "success",
              "automatic run")),
        ):
            line = next(l for l in lines if l.startswith(prefix))
            for required in requirements:
                with self.subTest(prefix=prefix, required=required):
                    self.assertIn(required, line)

    def test_backlog_records_entries_seventeen_and_eighteen(self):
        bl038 = self._bl038_section()
        history_start = bl038.index("ユーザー原文の履歴")
        history = bl038[history_start : bl038.index("着手時ユーザー原文:", history_start)]
        entries = re.findall(
            r"^\s*(\d+)\.\s+(.*?)(?=^\s*\d+\.\s|\Z)", history, re.MULTILINE | re.DOTALL
        )
        for number, requirements in (
            ("17", ("tranche 3f final acceptance original", "2026-08-07", "「ok」", "PR #88",
                    "Ready化と通常のmerge commit方式によるmerge",
                    "tranche 3全体またはBL-038全体の完了承認でもなく")),
            ("18", ("tranche 3g kickoff original", "2026-08-07", "「次へ」", "「次へ進めて」とは別文字列・別発言",
                    "tranche 3g実装内容の最終受入ではなく", "Category C source conversionの承認でもなく")),
        ):
            entry = next(text for n, text in entries if n == number)
            for required in requirements:
                with self.subTest(entry=number, required=required):
                    self.assertIn(required, entry)

    def test_records_carry_the_tranche3f_closeout_and_tranche3g_evidence(self):
        for text, requirements in (
            (self._bl038_section(), (
                "tranche 3f最終受入日:** 2026-08-07", "tranche 3f最終受入原文:** 「ok」", "attempt 1",
                "962d53bbc94f4f4918334c47750f0badc350926a", "31139149826", "1918 tests OK",
                "139 tests OK", "100 tests OK", "120 tests OK", "111 tests OK", "31139677534",
                "937 insertions／49 deletions", "986 changed lines", "Accept／Blocker 0",
                "66ef88e54ab6245f83af44c696834569af2b58f2", "3d813cc262822c0fdc2582ee5fcf78cf70fffacc",
                "独立レビューround 3・round 3修正(tranche 3g", "shard-discovery-error", "iterdir")),
            (self._status_bl038_line(), (
                "tranche 3f最終受入・merge(2026-08-07)", "Pull Request CI run 31139149826",
                "tranche 3g着手(2026-08-07)", "test/bl038-tranche3g-manifest-sharding",
                "容量問題(tranche 3g)", "実装証跡(tranche 3g、infrastructure only)", "invalid UTF-8",
                "新規classification entryは0件", "tranche 3g時点のcurrent shard countは1",
                "BL-038全体は未完了",
                "round 1修正(tranche 3g", "round 2修正(tranche 3g", "symlink", "raw-file format",
                "index directory entry自身のsymlinkも禁止", "round 3修正(tranche 3g", "shard-discovery-error")),
        ):
            for required in requirements:
                with self.subTest(required=required):
                    self.assertIn(required, text)

    def test_status_no_longer_claims_tranche3g_is_the_current_shard_state(self):
        status = self._status_bl038_line()
        # The one-shard state is history now, explicitly dated to tranche 3g.
        self.assertIn("tranche 3g時点のcurrent shard countは1で(tranche 3hで2へ増えた)", status)
        self.assertNotIn("current shard countは1で、combined summary", status)
        self.assertIn("この時点で追加classification shardはrepositoryへまだ作成していなかった", status)
        self.assertIn("この時点でadditional repository shardは未作成", status)
        self.assertNotIn("追加classification shardはrepositoryへまだ作成していない。", status)

    def test_backlog_records_the_capacity_problem_and_the_shard_contract(self):
        lines = self._bl038_section().splitlines()
        for prefix, requirements in (
            ("- **容量問題(tranche 3g):**",
             ("596行", "残りは4行", "8 assertions", "DependabotConfigurationTest",
              "600行上限を単純に引き上げる", "1 entry 1 line形式を崩す", "既存585 entriesを移動",
              "明示的なshard indexを導入", "新規classificationを一切行わない")),
            ("- **実装証跡(tranche 3g):**",
             ("document_test_classification_index.json", '"schema_version": 1', "fail closed",
              "document_test_classification_NNN.json", "globによる自動採用は行わず",
              "cross-shard assertion ID重複", "ownership重複", "byte-identical",
              "640585ca03d7836cbdd66edcc8e2b21df7ea1de946b767ae20fa5c12e0c5f15a")),
            ("- **独立レビューround 1・round 1修正(tranche 3g",
             ("symlink", "lstat", "raw-file format", "全listed shard", "validate_manifest",
              "byte-identical", "infrastructure only")),
            ("- **独立レビューround 2・round 2修正(tranche 3g",
             ("index-is-a-symlink", "index-not-a-file", "index directory entry自身のsymlink禁止",
              "UnicodeError", "index-load-error", "shard-load-error", "byte-identical",
              "infrastructure only", "まだ作成していない")),
        ):
            line = next(l for l in lines if l.startswith(prefix))
            for required in requirements:
                with self.subTest(prefix=prefix, required=required):
                    self.assertIn(required, line)


class Bl038Tranche3hRecordSyncTest(unittest.TestCase):
    """BL-038 tranche 3h, re-anchored to HISTORICAL accepted fact: PR #90 was
    accepted, merged, published; 136/144/2d03c748 is history, not now."""

    ROOT = Bl038Tranche3eRecordSyncTest.ROOT
    _read = Bl038Tranche3eRecordSyncTest._read
    _bl038_section = Bl038Tranche3eRecordSyncTest._bl038_section
    _status_bl038_line = Bl038Tranche3eRecordSyncTest._status_bl038_line

    def test_backlog_records_tranche3h_final_acceptance_merge_and_pages(self):
        """PR #90's acceptance, head/CI/review, merge, and Pages run."""
        bl038 = self._bl038_section()
        acceptance = next(
            l for l in bl038.splitlines() if l.startswith("- **tranche 3h最終受入(2026-08-07):**")
        )
        for required in (
            "「ok」", "PR #90", "6cfbb9ef0efd35e798e36b77340ecca0a0287ec0",
            "4883781125", "Accept／Blocker 0", "31187909402",
            "full unittest 1960 OK", "BL-038 record-sync 112 OK",
            "shards 2・total 721・A22 B213 C359 D127",
            "byte-identical", "997 changed lines",
            "A 0／B 38／C 91／D 7(total 136)",
            "136 entries・144行",
            "2d03c748b9136f324d597e9f539ba4738abfdd05e30d0cd69bd51081168442c4",
            "historical snapshotであり、tranche 3i append後の現在値ではない",
            "tranche 3hではCategory C source conversionを行っていない",
            "tranche 3i implementationの先行受入でも",
        ):
            with self.subTest(required=required):
                self.assertIn(required, acceptance)
        merge = next(
            l for l in bl038.splitlines() if l.startswith("- **tranche 3h merge・Pages(2026-08-07):**")
        )
        for required in (
            "通常のmerge commit方式",
            "95d97f731841dedc4e456363cc35920fa602f5a3",
            "0f8acc24355262c9325d8dea6a7b86960fb53615",
            "6cfbb9ef0efd35e798e36b77340ecca0a0287ec0",
            "31188676481", "attempt 1", "`dynamic`", "completed・success",
            "merge-triggered automatic run",
            "手動Pages・`workflow_dispatch`ではない",
        ):
            with self.subTest(required=required):
                self.assertIn(required, merge)
        self.assertNotIn("tranche 3h実装中", bl038)

    def test_backlog_records_entries_nineteen_and_twenty(self):
        """Entries 19/20 survive unchanged; header counts live in 3i."""
        bl038 = self._bl038_section()
        history_start = bl038.index("ユーザー原文の履歴")
        history = bl038[history_start : bl038.index("着手時ユーザー原文:", history_start)]
        entries = re.findall(
            r"^\s*(\d+)\.\s+(.*?)(?=^\s*\d+\.\s|\Z)", history, re.MULTILINE | re.DOTALL
        )
        for number, requirements in (
            ("19", ("tranche 3g final acceptance original", "2026-08-07", "「ok」", "PR #89",
                    "Draft解除・Ready化", "通常のmerge commit方式によるmerge",
                    "Category C source conversionの承認ではなく",
                    "tranche 3h implementationの先行受入でもなく",
                    "tranche 3全体またはBL-038全体の完了承認でもなく",
                    "workflow_dispatch")),
            ("20", ("tranche 3h kickoff original", "2026-08-07", "「次へ」",
                    "tranche 3g closeout", "再測定", "document_test_classification_001.json",
                    "「次へ進めて」とは別文字列・別発言",
                    "tranche 3h実装内容の最終受入ではなく", "Ready化・merge承認でもなく",
                    "Category C source conversionの承認でもなく",
                    "tranche 3全体またはBL-038全体の完了承認でもない")),
        ):
            entry = next(text for n, text in entries if n == number)
            for required in requirements:
                with self.subTest(entry=number, required=required):
                    self.assertIn(required, entry)

    def test_backlog_records_the_candidate_remeasurement_and_the_unique_maximum(self):
        lines = self._bl038_section().splitlines()
        kickoff = next(l for l in lines if l.startswith("- **tranche 3h着手(2026-08-07):**"))
        for required in (
            "test/bl038-tranche3h-first-classification-shard",
            "0f8acc24355262c9325d8dea6a7b86960fb53615",
            "document_test_classification_001.json",
            "Category C source conversionは行わない",
        ):
            with self.subTest(required=required):
                self.assertIn(required, kickoff)
        survey = next(l for l in lines if l.startswith("- **候補実測(tranche 3h):**"))
        for required in (
            "test_security_operations.py", "108", "28", "34",
            "test_security_requirements.py", "403", "123", "17",
            "test_pr_ci_workflow.py", "27", "test_workflow_action_pinning.py", "23",
            "test_source_usage_policy.py", "177",
            "runtime-behavioral test除外", "150 assertions",
        ):
            with self.subTest(required=required):
                self.assertIn(required, survey)
        selection = next(l for l in lines if l.startswith("- **選択(tranche 3h):**"))
        for required in (
            "最大は136で一意である", "tieなし", "次点は123",
            "SecurityOperationsContractTest", "Bl031SecurityOperationsReconciliationTest",
            "2 classes・24 methods・136 assertions",
            "assertIn 115／assertNotIn 10／assertNotRegex 5／assertLess 4／assertTrue 2",
            "custom assertion helperは3 classいずれにも存在せず",
            "Bl035DraftSyncTest", "170件で上限超過",
            "stop condition", "いずれも該当しない",
        ):
            with self.subTest(required=required):
                self.assertIn(required, selection)

    def test_backlog_records_the_classification_result_and_the_untouched_base_manifest(self):
        lines = self._bl038_section().splitlines()
        evidence = next(l for l in lines if l.startswith("- **実装証跡(tranche 3h):**"))
        for required in (
            "**分類結果(round 1訂正後): A 0／B 38／C 91／D 7(total 136)**",
            "document_test_classification_001.json",
            "136 entries・144行",
            "document_test_classification_index.json",
            '["document_test_classification.json", "document_test_classification_001.json"]',
            "byte-identical",
            "640585ca03d7836cbdd66edcc8e2b21df7ea1de946b767ae20fa5c12e0c5f15a",
            "585 entries、596行、A22/B175/C268/D120",
            "document_test_inventory.py`と`test_document_test_inventory.py`は変更していない",
            "shards 2", "combined 721 entries", "A=22 B=213 C=359 D=127",
            "unclassified/stale/fingerprint mismatch いずれも0",
            "Tranche3hClassificationShardTest",
            "TRANCHE_3G_HISTORICAL_SHARD_COUNT",
            "Category C 91件はこのPRでのsource変換対象ではない",
            "carry-forwardによる機械的決定は行っていない",
        ):
            with self.subTest(required=required):
                self.assertIn(required, evidence)
        # Category A is 0 for this tranche and both fingerprint duplicate
        # groups were reviewed and rejected as Category A candidates.
        self.assertIn("Category A該当なし", evidence)
        self.assertIn("spurious duplicate", evidence)

    def test_status_line_carries_the_tranche3g_closeout_and_tranche3h_scope(self):
        status = self._status_bl038_line()
        for required in (
            "tranche 3g最終受入・merge(2026-08-07)",
            "c4d467f8e69f99e8a5f9bf5bf403980560b4e150",
            "31173107249", "0f8acc24355262c9325d8dea6a7b86960fb53615",
            "31173887656", "merge-triggered automatic run",
            "999 changed lines", "Accept／Blocker 0",
            "tranche 3h着手(2026-08-07)",
            "test/bl038-tranche3h-first-classification-shard",
            "候補実測・選択(tranche 3h)", "最大は136の一意選択(tieなし)",
            "実装証跡(tranche 3h)", "**A 0／B 38／C 91／D 7**(round 1訂正後)",
            "document_test_classification_001.json",
            "current shard countは2", "combined 721 entries",
            "A 22／B 213／C 359／D 127",
            "tranche 3hではCategory C source conversionを行っていない",
            "BL-038全体は未完了",
        ):
            with self.subTest(required=required):
                self.assertIn(required, status)
        self.assertIn(
            "tranche 1・2・3a・3b・3c・3d・3e・3f・3gはいずれも受入済みとなり", status
        )
        for required in (
            "**tranche 3h最終受入・merge(2026-08-07):**",
            "6cfbb9ef0efd35e798e36b77340ecca0a0287ec0",
            "31187909402", "95d97f731841dedc4e456363cc35920fa602f5a3",
            "31188676481", "merge-triggered automatic run",
            "tranche 1・2・3a・3b・3c・3d・3e・3f・3g・3hはいずれも受入済みとなり",
        ):
            with self.subTest(required=required):
                self.assertIn(required, status)

    def test_tranche3h_shard_subset_survives_the_tranche3i_append(self):
        """Tranche 3h's 136 are still shard 001's FIRST 136, unchanged."""
        from collections import Counter

        shard = json.loads((self.ROOT / "document_test_classification_001.json").read_text(encoding="utf-8"))
        subset = [e for e in shard["assertions"] if e["file"] == "test_security_operations.py"]
        self.assertEqual(len(subset), 136)
        self.assertEqual(subset, shard["assertions"][:136])
        self.assertEqual(shard["scope"][0]["file"], "test_security_operations.py")
        self.assertEqual(
            shard["scope"][0]["classes"],
            ["SecurityOperationsContractTest", "Bl031SecurityOperationsReconciliationTest"],
        )
        counts = Counter(e["category"] for e in subset)
        self.assertEqual(dict(counts), {"B": 38, "C": 91, "D": 7})
        self.assertEqual(counts["A"], 0)
        # 136/144 is tranche 3h HISTORY, not the file today.
        self.assertNotEqual(len(shard["assertions"]), 136)


class Bl038Tranche3iRecordSyncTest(unittest.TestCase):
    """BL-038 tranche 3i, re-anchored to its ACCEPTED historical state: PR #91
    was accepted, merged, and its Pages run succeeded. The 123-assertion
    classification and shard 001's post-append statistics are history that
    tranche 3j must not disturb."""

    ROOT = Bl038Tranche3eRecordSyncTest.ROOT
    _read = Bl038Tranche3eRecordSyncTest._read
    _bl038_section = Bl038Tranche3eRecordSyncTest._bl038_section
    _status_bl038_line = Bl038Tranche3eRecordSyncTest._status_bl038_line

    ACCEPTED_HEAD = "d463e293138f70fa7ab3963a52da0af006e32147"
    MERGE_COMMIT = "db694fae3b81d824c61efd7b213eb9f6fc935f8c"
    SHARD_001_SHA = "0e1893593594daf44fb52e32ea610f2f7deb572148338faf90f2edfa7949b2cd"

    def test_backlog_records_the_tranche3i_final_acceptance_evidence(self):
        line = next(
            l for l in self._bl038_section().splitlines()
            if l.startswith("- **tranche 3i最終受入(2026-08-08):**")
        )
        for required in (
            "tranche 3i final acceptance原文「ok」(上記23)",
            "https://github.com/matkei31/security-digest/pull/91",
            self.ACCEPTED_HEAD,
            "4884945641", "Accept／Blocker 0", "4884966872",
            "31200066914", "completed・success",
            "`test_document_test_classification.py` 59 OK",
            "BL-038 record-sync 118 OK", "full unittest 1978 OK",
            "shards 2・total 844・A22 B284 C403 D135",
            "unclassified 0／stale 0／fingerprint mismatch 0",
            "5 files・903 insertions・94 deletions(997 changed lines)",
            "259 entries・268行", self.SHARD_001_SHA,
            "A 0／B 71／C 44／D 8(total 123)",
            "tranche 3iではCategory C source conversionを行っていない",
            "tranche 3j implementationの先行受入でも",
        ):
            with self.subTest(required=required):
                self.assertIn(required, line)

    def test_backlog_records_the_tranche3i_merge_and_pages_run(self):
        line = next(
            l for l in self._bl038_section().splitlines()
            if l.startswith("- **tranche 3i merge・Pages(2026-08-08):**")
        )
        for required in (
            "通常のmerge commit方式でmerge", self.MERGE_COMMIT,
            "parent 1: `95d97f731841dedc4e456363cc35920fa602f5a3`",
            "parent 2: `" + self.ACCEPTED_HEAD + "`",
            "31200620099", "attempt 1", "event `dynamic`", "completed・success",
            "merge-triggered automatic run",
            "手動Pages・`workflow_dispatch`ではない",
        ):
            with self.subTest(required=required):
                self.assertIn(required, line)

    def test_tranche3i_classification_and_shard_state_are_recorded_as_history(self):
        from collections import Counter

        evidence = next(
            l for l in self._bl038_section().splitlines()
            if l.startswith("- **実装証跡(tranche 3i):**")
        )
        for required in (
            "**分類結果: A 0／B 71／C 44／D 8(total 123)**",
            "document_test_classification_001.json`へのappend",
            "259 entries・268行(600行上限内)",
            "Category C 44件はこのPRでのsource変換対象ではない",
        ):
            with self.subTest(required=required):
                self.assertIn(required, evidence)
        # The accepted shard 001 is still exactly what 3i left behind.
        shard = self.ROOT / "document_test_classification_001.json"
        raw = shard.read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), self.SHARD_001_SHA)
        text = raw.decode("utf-8")
        self.assertEqual(len(text.splitlines()), 268)
        parsed = json.loads(text)
        self.assertEqual(len(parsed["assertions"]), 259)
        self.assertEqual(
            dict(Counter(e["category"] for e in parsed["assertions"])),
            {"B": 109, "C": 135, "D": 15},
        )
        self.assertEqual(
            [s["file"] for s in parsed["scope"]],
            ["test_security_operations.py", "test_security_requirements.py"],
        )
        self.assertNotIn("Bl035DraftSyncTest", text)

    def test_status_line_records_the_tranche3i_closeout(self):
        status = self._status_bl038_line()
        for required in (
            "**tranche 3i最終受入・merge(2026-08-08):**",
            "tranche 3i最終受入原文「ok」(entry 23)",
            self.ACCEPTED_HEAD, "4884945641", "4884966872", "31200066914",
            self.MERGE_COMMIT, "31200620099", "merge-triggered automatic run",
            "full unittest 1978 OK", "997 changed lines",
            "shards 2／total 844／A22 B284 C403 D135",
            "分類A 0／B 71／C 44／D 8",
            "tranche 1・2・3a・3b・3c・3d・3e・3f・3g・3h・3iはいずれも受入済みとなった",
        ):
            with self.subTest(required=required):
                self.assertIn(required, status)


class Bl038Tranche3jRecordSyncTest(unittest.TestCase):
    """BL-038 tranche 3j (PR #91 closeout sync + 34 assertions classified into
    a NEW shard 002) record-sync, RE-ANCHORED to its accepted history after
    PR #92 merged. Tranche 3j's own numbers (34 / 42 / SHA 3772b37f) are the
    ACCEPTED state, not the current shard 002 file, which tranche 3k appended
    to; the current state is asserted in Bl038Tranche3kRecordSyncTest."""

    ROOT = Bl038Tranche3eRecordSyncTest.ROOT
    _read = Bl038Tranche3eRecordSyncTest._read
    _bl038_section = Bl038Tranche3eRecordSyncTest._bl038_section
    _status_bl038_line = Bl038Tranche3eRecordSyncTest._status_bl038_line

    SHARD_002 = "document_test_classification_002.json"
    # 34 / 42 / this SHA describe shard 002 AS ACCEPTED at PR #92's merge.
    SHARD_002_SHA = "3772b37ff4de747a594ec2bef2025e199f9ee967c5dc83a9cae550663c924dbb"
    TRANCHE_3J_HISTORICAL_CONTENT_SHA = \
        "d4d7f9324f6630e105b695a61f3d649e7779f4e17e47275ebd8cdd9cd31d7295"

    def test_backlog_records_tranche3j_final_acceptance_with_its_evidence(self):
        acceptance = next(
            l for l in self._bl038_section().splitlines()
            if l.startswith("- **tranche 3j最終受入(2026-08-08):**")
        )
        for required in (
            "「ok」(上記25)", "PR #92", "pull/92", "Accept／Blocker 0",
            "0cf85f348e8269a51fffc347d076d6d9412fe3c7",
            "4887813590", "4887840356", "31233395709", "completed・success",
            "test_security_operations.py` 31 OK", "classification 74 OK",
            "inventory 95 OK", "utils 27 OK", "record-sync 122 OK",
            "full unittest 1997 OK", "A 0／B 12／C 14／D 8", "34 entries・42行",
            "shards 3・total 878・A22 B296 C417 D143",
            "3772b37ff4de747a594ec2bef2025e199f9ee967c5dc83a9cae550663c924dbb",
            "6 files・971 changed lines", "Category C source conversionは行っていない",
        ):
            with self.subTest(required=required):
                self.assertIn(required, acceptance)

    def test_backlog_records_the_merge_commit_its_parents_and_the_pages_run(self):
        merge = next(
            l for l in self._bl038_section().splitlines()
            if l.startswith("- **tranche 3j merge・Pages(2026-08-08):**")
        )
        for required in (
            "通常のmerge commit方式", "f068270e5ed5c8a453371f0b6d63cde9f0f84d53",
            "parent 1 `df201dca91c4b35837d4a441dbdefd97c3f5aa06`",
            "parent 2 `0cf85f348e8269a51fffc347d076d6d9412fe3c7`",
            # The scheduled production commit that landed on main mid-PR is
            # recorded as a SEPARATE automatic commit, not a tranche artefact.
            "scheduled production digest commit", "PR #92とは別系統の自動production commit",
            "31234081342", "attempt 1", "event `dynamic`", "merge-triggered automatic run",
            "手動Pages・`workflow_dispatch`ではない",
            "tranche 1・2・3a・3b・3c・3d・3e・3f・3g・3h・3i・3jはいずれも受入済み",
        ):
            with self.subTest(required=required):
                self.assertIn(required, merge)

    def test_backlog_records_entries_twentythree_and_twentyfour_with_updated_counts(self):
        bl038 = self._bl038_section()
        history_start = bl038.index("ユーザー原文の履歴")
        history = bl038[history_start : bl038.index("着手時ユーザー原文:", history_start)]
        entries = re.findall(
            r"^\s*(\d+)\.\s+(.*?)(?=^\s*\d+\.\s|\Z)", history, re.MULTILINE | re.DOTALL
        )
        # Entries 23 and 24 keep their meaning verbatim after tranches 3k-3p
        # appended 25-37; the header tally is asserted in the 3p class.
        self.assertEqual([number for number, _ in entries], [str(i) for i in range(1, 48)])
        for number, requirements in (
            ("23", ("tranche 3i final acceptance original", "2026-08-08", "「ok」", "PR #91",
                    "Draft解除・Ready化", "通常のmerge commit方式によるmerge",
                    "Category C source conversionの承認ではなく",
                    "tranche 3j implementationの先行受入でもなく",
                    "tranche 3全体またはBL-038全体の完了承認でもなく",
                    "workflow_dispatch")),
            ("24", ("tranche 3j kickoff original", "2026-08-08", "「はい」",
                    "tranche 3i closeout", "再測定", "measurement-driven",
                    "#13(tranche 3e kickoff original)と同一文字列だが",
                    "tranche 3j実装内容の最終受入ではなく", "Ready化・merge承認でもなく",
                    "Category C source conversionの承認でもなく",
                    "document_test_classification_002.json`を作ることの無条件な先行承認でもなく",
                    "tranche 3全体またはBL-038全体の完了承認でもない")),
        ):
            entry = next(text for n, text in entries if n == number)
            for required in requirements:
                with self.subTest(entry=number, required=required):
                    self.assertIn(required, entry)

    def test_backlog_records_the_candidate_remeasurement_and_the_unique_maximum(self):
        lines = self._bl038_section().splitlines()
        kickoff = next(l for l in lines if l.startswith("- **tranche 3j着手(2026-08-08):**"))
        for required in (
            "test/bl038-tranche3j-security-operations-bl035",
            "db694fae3b81d824c61efd7b213eb9f6fc935f8c",
            "diff 0", "baseline full unittest 1978 OK",
            "Category C source conversionは行わない",
        ):
            with self.subTest(required=required):
                self.assertIn(required, kickoff)
        survey = next(l for l in lines if l.startswith("- **候補実測(tranche 3j):**"))
        for required in (
            "test_security_operations.py", "Bl035DraftSyncTest", "34",
            "test_pr_ci_workflow.py", "27",
            "test_workflow_action_pinning.py", "15件+`DependabotConfigurationTest` 8件", "23",
            "test_security_requirements.py", "403", "17",
            "test_source_usage_policy.py", "177",
            "runtime-behavioral test除外", "150 assertions",
            "無関係fileのbin-pack禁止",
        ):
            with self.subTest(required=required):
                self.assertIn(required, survey)
        selection = next(l for l in lines if l.startswith("- **選択(tranche 3j):**"))
        for required in (
            "最大は34で一意である", "tieなし", "次点は27",
            "1 class・7 methods・34 assertions",
            "assertIn 33／assertNotIn 1",
            "custom assertion helperはこのclassに存在せず",
            "pure document/static-contract test",
            "stop condition", "いずれも該当しない",
        ):
            with self.subTest(required=required):
                self.assertIn(required, selection)

    def test_backlog_records_the_classification_and_why_shard_002_was_needed(self):
        evidence = next(
            l for l in self._bl038_section().splitlines()
            if l.startswith("- **実装証跡(tranche 3j):**")
        )
        for required in (
            "**分類結果: A 0／B 12／C 14／D 8(total 34)**",
            "carry-forwardやkeywordだけによる機械的決定は行っていない",
            "scope内fingerprint duplicate groupは0件",
            "cross-shard fingerprint一致はbase manifestに対して2件、shard001に対して2件",
            "既存分類(D 1件・B 1件)と一致",
            "fingerprint一致だけでAへ昇格させていない",
            "**shard allocationは実測にもとづき新規`document_test_classification_002.json`の作成とした**",
            "kickoffで002を先行承認したからではなく",
            "duplicate-scope-file",
            "1f0156b671555c9af25f0943fa06f458679d2020f141a14255794f39401d8489",
            "600行cap自体は制約になっていない",
            "268行で、34件を足しても302行",
            "capacityではなくscope構造上の必要性",
            "`(file, class)`単位",
            "34 assertions・source順・1行1 assertion・42行(600行上限内)・trailing newline・固定key order",
            self.SHARD_002_SHA,
            "byte-identicalで保持した(259 entries・268行",
            "0e1893593594daf44fb52e32ea610f2f7deb572148338faf90f2edfa7949b2cd",
            "640585ca03d7836cbdd66edcc8e2b21df7ea1de946b767ae20fa5c12e0c5f15a",
            "base→`_001`→`_002`の3 shard順",
            "shards 3、combined 878 entries、A=22 B=296 C=417 D=143",
            "unclassified/stale/fingerprint mismatch いずれも0",
            "Tranche3jClassificationShard002Test",
            "Category C 14件はこのPRでのsource変換対象ではない",
            # PR #92 round 1 correction, recorded in the same evidence line.
            "803923028b480d531f71c299d2bdcf3a39c0c807", "31204274104",
            "`Ready-for-review`)を**B→C**へ訂正した",
            "GitHub公式の表記は`Ready for review`",
            "**A 0／B 12／C 14／D 8(total 34)**",
            "combinedはA 22／B 296／C 417／D 143(total 878)",
            "shard allocation decision(shard002新規作成)・index順",
            "Category C source conversionも行っていない",
        ):
            with self.subTest(required=required):
                self.assertIn(required, evidence)

    def test_status_line_carries_the_tranche3i_closeout_and_tranche3j_scope(self):
        status = self._status_bl038_line()
        self.assertIn("**tranche 3j最終受入・merge・Pages(2026-08-08):**", status)
        for required in (
            "**tranche 3j着手(2026-08-08):**",
            "test/bl038-tranche3j-security-operations-bl035",
            "**候補実測・選択(tranche 3j):**",
            "最大は34の一意選択(tieなし、次点27)",
            "**実装証跡(tranche 3j):**", "**A 0／B 12／C 14／D 8**",
            "**shard allocationは実測にもとづき新規`document_test_classification_002.json`の作成とした**",
            "line cap起因ではなくscope構造上の必要性",
            "combined 878 entries(585+136+123+34)",
            "A 22／B 296／C 417／D 143",
            "shard002は34 entries・42行(600行上限内)",
            self.SHARD_002_SHA,
            "tranche 3jではCategory C source conversionを行っていない",
            "**独立レビューround 1(tranche 3j、2026-08-08):**",
            "803923028b480d531f71c299d2bdcf3a39c0c807", "31204274104",
            "assert-06)をB→Cへ訂正した",
            "A 0／B 12／C 14／D 8", "combined A 22／B 296／C 417／D 143",
            "BL-038全体は未完了",
        ):
            with self.subTest(required=required):
                self.assertIn(required, status)
        # Tranche 3j IS accepted now; what must not appear is a claim that
        # the in-progress tranche 3k or BL-038 as a whole is.
        self.assertNotIn("tranche 3kは受入済み", status)
        self.assertNotIn("BL-038は完了", status)

    def test_shard_002_still_carries_the_accepted_tranche3j_subset_exactly(self):
        """Tranche 3j's accepted 34 are pinned as a SUBSET of the current
        shard 002, by canonical parsed-content digest derived from the file as
        accepted at merge commit f068270e5e... -- not regenerated from the
        appended file."""
        from collections import Counter

        raw = (self.ROOT / self.SHARD_002).read_bytes()
        shard_002 = json.loads(raw.decode("utf-8"))
        historical, scope_0 = shard_002["assertions"][:34], shard_002["scope"][0]
        self.assertEqual((scope_0["file"], scope_0["classes"]),
                         ("test_security_operations.py", ["Bl035DraftSyncTest"]))
        self.assertTrue(all(e["file"] == scope_0["file"] for e in historical))
        digest = hashlib.sha256(
            json.dumps({"scope": scope_0, "assertions": historical}, ensure_ascii=False,
                       sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
        self.assertEqual(digest, self.TRANCHE_3J_HISTORICAL_CONTENT_SHA)
        self.assertEqual(dict(Counter(e["category"] for e in historical)),
                         {"B": 12, "C": 14, "D": 8})
        # 34 / 42 / SHA 3772b37f describe the ACCEPTED file, not today's.
        self.assertNotEqual(hashlib.sha256(raw).hexdigest(), self.SHARD_002_SHA)
        self.assertNotEqual(len(raw.decode("utf-8").splitlines()), 42)
        self.assertNotEqual(len(shard_002["assertions"]), 34)
        # The selected source test file itself was NOT modified.
        source = (self.ROOT / "test_security_operations.py").read_text(encoding="utf-8")
        self.assertIn("class Bl035DraftSyncTest", source)


class Bl038Tranche3kRecordSyncTest(unittest.TestCase):
    """BL-038 tranche 3k (PR #92 closeout sync + the 27 assertions of
    `test_pr_ci_workflow.py::PullRequestCIWorkflowTest` APPENDED to shard 002)
    record-sync, RE-ANCHORED to its accepted history after PR #93 merged.
    Tranche 3k's own numbers (61 / 70 / SHA 1aee40fd) are the ACCEPTED state,
    not the current shard 002 file, which tranche 3l appended to; the current
    state is asserted in Bl038Tranche3lRecordSyncTest."""

    ROOT = Bl038Tranche3eRecordSyncTest.ROOT
    _read = Bl038Tranche3eRecordSyncTest._read
    _bl038_section = Bl038Tranche3eRecordSyncTest._bl038_section
    _status_bl038_line = Bl038Tranche3eRecordSyncTest._status_bl038_line

    SHARD_002 = "document_test_classification_002.json"
    # 61 / 70 / this SHA describe shard 002 AS ACCEPTED at PR #93's merge.
    SHARD_002_ACCEPTED_SHA = "1aee40fda499ac4308daa24fbd6fe622daab0dabd9390ecdb3014f36c7ae9da1"
    TRANCHE_3K_HISTORICAL_CONTENT_SHA = \
        "233c98393937c21e7890270c6cd7b8478272e010c4299177344d0b1099164a1e"
    SHARD_001_SHA = "0e1893593594daf44fb52e32ea610f2f7deb572148338faf90f2edfa7949b2cd"
    BASE_SHA = "640585ca03d7836cbdd66edcc8e2b21df7ea1de946b767ae20fa5c12e0c5f15a"

    def test_backlog_records_the_tranche3k_acceptance_merge_and_pages_run(self):
        """PR #93's closeout, now that it has merged: the final-acceptance
        record with its accepted-head evidence, and the merge commit with both
        parents and the merge-triggered Pages run."""
        lines = self._bl038_section().splitlines()
        for prefix, requirements in (
            ("- **tranche 3k最終受入(2026-08-08):**",
             ("「ok」(上記27)", "PR #93", "pull/93", "Accept／Blocker 0",
              "f2a22d21aff46dad7da514db6f29a61e34e173a4", "4888047972", "4888057435",
              "31238186048", "completed・success", "A 0／B 22／C 5／D 0(total 27)",
              "61 entries・70行・A0/B34/C19/D8", self.SHARD_002_ACCEPTED_SHA,
              "shards 3・total 905・A22 B318 C422 D143", "BL-038 record-sync 130 OK",
              "classification 90 OK", "full unittest 2021 OK", "5 files・999 changed lines",
              "未解決review thread 0件", "Category C source conversionは行っていない")),
            ("- **tranche 3k merge・Pages(2026-08-08):**",
             ("通常のmerge commit方式", "764da66947a9b480ee2f074d553111a8e5bb278c",
              "parent 1 `f068270e5ed5c8a453371f0b6d63cde9f0f84d53`",
              "parent 2 `f2a22d21aff46dad7da514db6f29a61e34e173a4`", "31238943401",
              "attempt 1", "event `dynamic`", "merge-triggered automatic run",
              "手動Pages・`workflow_dispatch`ではない",
              "tranche 1・2・3a・3b・3c・3d・3e・3f・3g・3h・3i・3j・3kはいずれも受入済み")),
        ):
            record = next(l for l in lines if l.startswith(prefix))
            for required in requirements:
                with self.subTest(record=prefix[:28], required=required):
                    self.assertIn(required, record)

    def test_the_accepted_tranche3k_shard_state_is_history_not_the_current_file(self):
        """61 / 70 / SHA 1aee40fd describe shard 002 as ACCEPTED, and the
        parsed-content digest was derived from the accepted file rather than
        regenerated here. The live file has moved on -- tranche 3l appended."""
        raw = (self.ROOT / self.SHARD_002).read_bytes()
        self.assertNotEqual(hashlib.sha256(raw).hexdigest(), self.SHARD_002_ACCEPTED_SHA)
        shard_002 = json.loads(raw.decode("utf-8"))
        self.assertGreater(len(shard_002["assertions"]), 61)
        accepted = shard_002["assertions"][:61]
        payload = {"scope": shard_002["scope"][:2], "assertions": accepted}
        self.assertEqual(
            hashlib.sha256(json.dumps(payload, ensure_ascii=False, sort_keys=True,
                                      separators=(",", ":")).encode("utf-8")).hexdigest(),
            self.TRANCHE_3K_HISTORICAL_CONTENT_SHA)
        from collections import Counter
        self.assertEqual(dict(Counter(e["category"] for e in accepted)),
                         {"B": 34, "C": 19, "D": 8})
        self.assertEqual([(e["file"], e["classes"]) for e in shard_002["scope"][:2]],
                         [("test_security_operations.py", ["Bl035DraftSyncTest"]),
                          ("test_pr_ci_workflow.py", ["PullRequestCIWorkflowTest"])])

    def test_backlog_records_entries_twentyfive_and_twentysix_with_updated_counts(self):
        bl038 = self._bl038_section()
        history_start = bl038.index("ユーザー原文の履歴")
        history = bl038[history_start : bl038.index("着手時ユーザー原文:", history_start)]
        # Entries 25 and 26 keep their meaning verbatim after tranche 3l
        # appended 27 and 28; the header tally is asserted in the 3l class.
        entries = re.findall(
            r"^\s*(\d+)\.\s+(.*?)(?=^\s*\d+\.\s|\Z)", history, re.MULTILINE | re.DOTALL
        )
        self.assertEqual([number for number, _ in entries], [str(i) for i in range(1, 48)])
        for number, requirements in (
            ("25", ("tranche 3j final acceptance original", "2026-08-08", "「ok」", "PR #92",
                    "Draft解除・Ready化", "通常のmerge commit方式によるmerge", "workflow_dispatch",
                    "Category C source conversionの承認ではなく", "tranche 3k implementationの先行受入でもなく",
                    "tranche 3全体またはBL-038全体の完了承認でもなく")),
            ("26", ("tranche 3k kickoff original", "2026-08-08", "「はい」",
                    "tranche 3j closeout", "再測定", "measurement-driven",
                    "#13(tranche 3e kickoff original)・#24(tranche 3j kickoff original)と同一文字列だが",
                    "tranche 3k実装内容の最終受入ではなく", "Ready化・merge承認でもなく",
                    "Category C source conversionの承認でもなく", "tranche 3全体またはBL-038全体の完了承認でもなく",
                    "`document_test_classification_003.json`を作ることの先行承認でもなく")),
        ):
            entry = next(text for n, text in entries if n == number)
            for required in requirements:
                with self.subTest(entry=number, required=required):
                    self.assertIn(required, entry)

    def test_backlog_records_the_candidate_remeasurement_and_the_unique_maximum(self):
        lines = self._bl038_section().splitlines()
        kickoff = next(l for l in lines if l.startswith("- **tranche 3k着手(2026-08-08):**"))
        for required in (
            "test/bl038-tranche3k-pr-ci-workflow", "diff 0",
            "f068270e5ed5c8a453371f0b6d63cde9f0f84d53", "baseline full unittest 1997 OK",
            "Category C source conversionは行わない",
        ):
            with self.subTest(required=required):
                self.assertIn(required, kickoff)
        survey = next(l for l in lines if l.startswith("- **候補実測(tranche 3k):**"))
        for required in (
            "test_pr_ci_workflow.py", "27", "test_workflow_action_pinning.py", "23",
            "15件+`DependabotConfigurationTest` 8件", "test_source_usage_policy.py", "177",
            "test_security_requirements.py", "403", "17", "test_security_operations.py",
            "remaining eligibleなし", "runtime-behavioral test除外", "150 assertions",
            "無関係fileのbin-pack禁止",
        ):
            with self.subTest(required=required):
                self.assertIn(required, survey)
        selection = next(l for l in lines if l.startswith("- **選択(tranche 3k):**"))
        for required in (
            "最大は27で一意である", "tieなし", "次点は23", "1 class・7 methods・27 assertions",
            "assertTrue 1／assertIn 7／assertNotIn 9／assertRegex 7／assertNotRegex 3",
            "custom assertion helperはこのclassに存在せず", "pure static workflow-contract test",
            ".github/workflows/pr-ci.yml", "stop condition", "いずれも該当しない"):
            with self.subTest(required=required):
                self.assertIn(required, selection)

    def test_backlog_records_the_classification_and_why_shard_002_was_chosen(self):
        evidence = next(
            l for l in self._bl038_section().splitlines()
            if l.startswith("- **実装証跡(tranche 3k):**")
        )
        for required in (
            "**分類結果: A 0／B 22／C 5／D 0(total 27)**", "duplicate-scope-file",
            "carry-forwardやkeywordだけによる機械的決定は行っていない", "過去classificationの変更は生じていない",
            "scope内fingerprint duplicate groupは0件",
            "base manifest・shard001・tranche 3j accepted 34のいずれに対してもcross-shard fingerprint一致は0件",
            "**shard allocationは実測にもとづき既存`document_test_classification_002.json`へのappendとした**",
            "恒久的なallocator policyではなく", "61 entries・70行(600行上限内)",
            "d4d7f9324f6630e105b695a61f3d649e7779f4e17e47275ebd8cdd9cd31d7295",
            "3772b37ff4de747a594ec2bef2025e199f9ee967c5dc83a9cae550663c924dbb",
            self.SHARD_002_ACCEPTED_SHA, self.SHARD_001_SHA, self.BASE_SHA,
            "byte-identicalで保持した(259 entries・268行", "`_003`は作成していない",
            "`document_test_classification_index.json`は変更していない",
            "shards 3、combined 905 entries、A=22 B=318 C=422 D=143",
            "unclassified/stale/fingerprint mismatch いずれも0",
            "Tranche3kClassificationShard002AppendTest", "Category C 5件はこのPRでのsource変換対象ではない",
            "`test_pr_ci_workflow.py`・`.github/workflows/pr-ci.yml`は変更していない",
            "74b58a05d93fa8ed777c3e2a23045251576a11d4", "31236264527",
            'assert-05`(`python-version: "3.12"`)を**B→C**へ訂正した',
            "double quoteというpresentationの固定までは構造契約ではない",  # round 1
        ):
            with self.subTest(required=required):
                self.assertIn(required, evidence)

    # PR #93 round 2 (Blocker 1): the tranche 3k CURRENT records must not
    # carry pre-round-1 numbers. Scoped so historical snapshots stay allowed.
    STALE_IN_CURRENT_3K = ("A 22／B 319／C 421／D 143", "A0/B35/C18/D8",
                           "Category C(4件、代表2形)", "A 0／B 23／C 4／D 0")

    def test_current_tranche3k_records_carry_no_pre_round1_values(self):
        prefixes = ("- **実装証跡(tranche 3k):**", "- **検証(tranche 3k):**",
                    "- **mutation-style verification(tranche 3k")
        lines = [l for l in self._bl038_section().splitlines() if l.startswith(prefixes)]
        self.assertEqual(len(lines), 3)  # not vacuous: all three records exist
        for line in lines:
            for stale in self.STALE_IN_CURRENT_3K:
                with self.subTest(stale=stale, rec=line[:24]):
                    self.assertNotIn(stale, line)

    def test_status_line_carries_the_tranche3k_scope_and_its_closeout(self):
        status = self._status_bl038_line()
        for required in (
            "**tranche 3k着手(2026-08-08):**", "f068270e5ed5c8a453371f0b6d63cde9f0f84d53",
            "test/bl038-tranche3k-pr-ci-workflow", "**候補実測・選択(tranche 3k):**",
            "最大は27の一意選択(tieなし、次点23)", "**実装証跡(tranche 3k):**", "**A 0／B 22／C 5／D 0**",
            "**shard allocationは実測にもとづき既存`document_test_classification_002.json`へのappendとした**",
            "combined 905 entries(585+136+123+34+27)", "shard002は61 entries・70行(600行上限内)",
            self.SHARD_002_ACCEPTED_SHA, "tranche 3kではCategory C source conversionを行っていない",
            # The closeout, now that PR #93 has merged.
            "**tranche 3k最終受入・merge・Pages(2026-08-08):**", "31238186048", "31238943401",
            "f2a22d21aff46dad7da514db6f29a61e34e173a4",
            "764da66947a9b480ee2f074d553111a8e5bb278c",
            "これによりtranche 1〜3kはいずれも受入済みとなった。"):
            with self.subTest(required=required):
                self.assertIn(required, status)

    def test_repository_state_still_matches_the_recorded_tranche3k_append(self):
        from collections import Counter

        shard_002 = json.loads((self.ROOT / self.SHARD_002).read_text(encoding="utf-8"))
        appended = shard_002["assertions"][34:61]
        self.assertEqual(len(appended), 27)
        self.assertEqual(dict(Counter(e["category"] for e in appended)), {"B": 22, "C": 5})
        self.assertEqual({e["targets"][0] for e in appended}, {".github/workflows/pr-ci.yml"})
        self.assertEqual(shard_002["scope"][1],
                         {"file": "test_pr_ci_workflow.py",
                          "classes": ["PullRequestCIWorkflowTest"]})
        # Neither the selected source test nor its workflow was modified.
        self.assertIn("class PullRequestCIWorkflowTest",
                      (self.ROOT / "test_pr_ci_workflow.py").read_text(encoding="utf-8"))
        self.assertIn("name: Pull Request CI",
                      (self.ROOT / ".github/workflows/pr-ci.yml").read_text(encoding="utf-8"))


# SHA-256 digests the tranche 3l implementation record must carry verbatim:
# shard 002's accepted and current whole-file hashes, the tranche 3k and 3j
# historical parsed-content digests, and the two untouched older manifests.
TRANCHE_3L_RS_DIGESTS = ("233c98393937c21e7890270c6cd7b8478272e010c4299177344d0b1099164a1e",
    "d4d7f9324f6630e105b695a61f3d649e7779f4e17e47275ebd8cdd9cd31d7295",
    "c0f81d1489109e1fe9a6a8dcef497496b7c3b39ad435a84ca06944a43409aaa2",
    "1aee40fda499ac4308daa24fbd6fe622daab0dabd9390ecdb3014f36c7ae9da1",
    "0e1893593594daf44fb52e32ea610f2f7deb572148338faf90f2edfa7949b2cd",
    "640585ca03d7836cbdd66edcc8e2b21df7ea1de946b767ae20fa5c12e0c5f15a", )


class Bl038Tranche3lRecordSyncTest(unittest.TestCase):
    """BL-038 tranche 3l (PR #93 closeout sync + the 23 assertions of
    `test_workflow_action_pinning.py`'s two source-order contiguous classes
    APPENDED to shard 002) record-sync. Tranche 3l is itself accepted as of
    PR #94's merge, so its whole-file shard 002 figures are HISTORY here;
    1-3l accepted, 3m is not, BL-038 open."""

    ROOT = Bl038Tranche3eRecordSyncTest.ROOT
    _read = Bl038Tranche3eRecordSyncTest._read
    _bl038_section = Bl038Tranche3eRecordSyncTest._bl038_section
    _status_bl038_line = Bl038Tranche3eRecordSyncTest._status_bl038_line

    SOURCE_FILE = "test_workflow_action_pinning.py"
    CLASSES = ("WorkflowActionPinningTest", "DependabotConfigurationTest")
    TARGETS = (".github/workflows/fetch.yml", ".github/workflows/pr-ci.yml",
               ".github/dependabot.yml")
    SHARD_002 = "document_test_classification_002.json"
    SHARD_002_CURRENT_SHA = "c0f81d1489109e1fe9a6a8dcef497496b7c3b39ad435a84ca06944a43409aaa2"
    SHARD_002_ACCEPTED_SHA = "1aee40fda499ac4308daa24fbd6fe622daab0dabd9390ecdb3014f36c7ae9da1"
    TRANCHE_3K_HISTORICAL_CONTENT_SHA = \
        "233c98393937c21e7890270c6cd7b8478272e010c4299177344d0b1099164a1e"
    TRANCHE_3J_HISTORICAL_CONTENT_SHA = \
        "d4d7f9324f6630e105b695a61f3d649e7779f4e17e47275ebd8cdd9cd31d7295"
    SHARD_001_SHA = "0e1893593594daf44fb52e32ea610f2f7deb572148338faf90f2edfa7949b2cd"
    BASE_SHA = "640585ca03d7836cbdd66edcc8e2b21df7ea1de946b767ae20fa5c12e0c5f15a"
    # What shard 002 became once tranche 3m appended its 17.
    SHARD_002_TRANCHE_3M_SHA = \
        "d86d521627dabfed4b4555b8759a50c9a3538a9d89d55c8f2e5d928845e39f46"

    def test_backlog_state_records_tranche3l_as_accepted_not_in_progress(self):
        """Tranche 3l is accepted as of PR #94's merge, 3m as of PR #95's and 3n
        as of PR #96's; tranche 3o is the one in progress. The 3l-specific
        residual items are gone, and this class keeps what stays true about 3l."""
        bl038 = self._bl038_section()
        own_state_line = next(l for l in bl038.splitlines() if l.startswith("- **状態:**"))
        self.assertNotIn("tranche 3l実装中", own_state_line)
        self.assertIn("3q・3r・3s・3t受入済み／document・static-contract assertion classificationは全件分類済み", own_state_line)
        accepted = own_state_line.split("(", 1)[1].split("受入済み", 1)[0].split("・")
        self.assertEqual(accepted, ["tranche 1", "2", "3a", "3b", "3c", "3d", "3e", "3f", "3g",
                                    "3h", "3i", "3j", "3k", "3l", "3m", "3n", "3o", "3p", "3q", "3r", "3s", "3t"])
        self.assertIn("3l", accepted)
        self.assertIn("3q", accepted)
        self.assertNotEqual(own_state_line.strip(), "- **状態:** 完了")
        residual = re.search(r"^- \*\*残作業:\*\* .*$", bl038, re.MULTILINE).group(0)
        # 3l's own Category C count survives in the conversion inventory, with
        # the round-1-corrected A 6 -- but its review/merge item is done.
        for required in ("tranche 3lの6件", "tranche 3l 6件",
                         "BL-038全体の最終受入は上記残作業が完了するまで行わない", ):
            with self.subTest(required=required):
                self.assertIn(required, residual)
        for gone in ("tranche 3lのDraft PR独立レビュー・最終受入・Ready化・merge",
                     "tranche 3l 4件)のhelper consolidation要否判断",
                     "tranche 3kのDraft PR独立レビュー", ):
            with self.subTest(gone=gone):
                self.assertNotIn(gone, residual)
        # No pre-committed FUTURE shard filename, only the generic pattern.
        for premature in ("document_test_classification_003.json",
                          "document_test_classification_004.json"):
            with self.subTest(premature=premature):
                self.assertNotIn(premature, residual)
        self.assertIn("document_test_classification_NNN.json", residual)

    def test_backlog_records_entries_twentyseven_and_twentyeight_with_updated_counts(self):
        bl038 = self._bl038_section()
        history_start = bl038.index("ユーザー原文の履歴")
        history = bl038[history_start : bl038.index("着手時ユーザー原文:", history_start)]
        # Entries 27/28 took 「ok」 to 11 and introduced 「うん」; 29/30, 32/33,
        # 34/35 and 36/37 took them on to 15 and 7, so the CURRENT header is the
        # tranche 3p one and the 3l-era tally is history.
        self.assertIn("「ok」19回・「おk」7回・「次へ進めて」1回・「次へ」2回・「はい」12回・"
                      "「進んで」1回・「うん」1回・「うん。進めて」1回", history)
        for stale in ("「ok」14回", "「ok」13回", "「ok」12回", "「ok」11回", "「ok」10回", "「ok」9回",
                      "「はい」6回", "「はい」5回", "「はい」4回", "「はい」3回"):
            with self.subTest(stale=stale):
                self.assertNotIn(stale, history)
        self.assertIn("長文の作業指示2回", history)
        self.assertNotIn("長文の作業指示1回", history)
        self.assertIn("「A」1回", history)  # unchanged by 27/28
        entries = re.findall(r"^\s*(\d+)\.\s+(.*?)(?=^\s*\d+\.\s|\Z)", history,
                             re.MULTILINE | re.DOTALL)
        self.assertEqual([number for number, _ in entries], [str(i) for i in range(1, 48)])
        for number, requirements in (
            ("27", ("tranche 3k final acceptance original", "2026-08-08", "「ok」", "PR #93",
                    "Draft解除・Ready化", "通常のmerge commit方式によるmerge",
                    "#1・#3・#5・#7・#9・#17・#19・#21・#23・#25と同一文字列だが",
                    "Category C source conversionの承認ではなく", "tranche 3l implementationの先行受入でもなく",
                    "tranche 3全体またはBL-038全体の完了承認でもなく", "workflow_dispatch")),
            ("28", ("tranche 3l kickoff original", "2026-08-08", "「うん」", "tranche 3k closeout",
                    "再測定", "measurement-driven", "この履歴で唯一の「うん」であり",
                    "tranche 3l実装内容の最終受入ではなく", "Ready化・merge承認でもなく",
                    "Category C source conversionの承認でもなく",
                    "`document_test_classification_003.json`を作ることの先行承認でもなく",
                    "tranche 3全体またはBL-038全体の完了承認でもなく")), ):
            entry = next(text for n, text in entries if n == number)
            for required in requirements:
                with self.subTest(entry=number, required=required):
                    self.assertIn(required, entry)

    def test_backlog_records_the_survey_selection_classification_and_verification(self):
        """One record line per tranche step, each pinned to what it must carry:
        the unique maximum, the selected scope, the A/B/C/D result with the
        whole-method evidence behind A, the shard allocation, and the
        verification and mutation evidence."""
        lines = self._bl038_section().splitlines()
        for prefix, requirements in (("- **tranche 3l着手(2026-08-08):**",
             ("test/bl038-tranche3l-workflow-action-pinning", "diff 0",
              "764da66947a9b480ee2f074d553111a8e5bb278c", "baseline full unittest 2021 OK",
              "shards 3・total 905・A22 B318 C422 D143", "Category C source conversionは行わない")),
            ("- **候補実測(tranche 3l):**", ("test_workflow_action_pinning.py", "23件",
              "`WorkflowActionPinningTest` 15件+`DependabotConfigurationTest` 8件",
              "test_source_usage_policy.py", "177", "test_security_requirements.py", "403", "17",
              "test_pr_ci_workflow.py", "test_security_operations.py", "remaining eligibleなし",
              "runtime-behavioral test除外", "150 assertions", "無関係fileのbin-pack禁止",
              "期待値(23・17・403・177)は最新source上の実測と完全に一致")), ("- **選択(tranche 3l):**",
             ("最大は23で一意である", "tieなし", "次点は17", "2 classes・14 methods・23 assertions",
              "assertTrue 5／assertEqual 3／assertRegex 7／assertIn 2／assertNotIn 4／assertNotRegex 2",
              "custom assertion helperは両classとも存在せず", "pure static contract test",
              ".github/dependabot.yml", "scope内fingerprint duplicate groupは2件",
              "stop condition", "いずれも該当しない")), ("- **実装証跡(tranche 3l):**",
             ("**分類結果: A 6／B 11／C 6／D 0(total 23)**", "carry-forwardやkeywordだけによる機械的決定は行っていない",
              "過去classificationの変更は生じていない",
              # Category A rests on whole-method evidence, not a hash tie.
              "**Category Aは6件**", "node-type skeletonが完全一致(各86 node)", "byte-identical",
              "_assert_action_pinned_to_full_sha", "base manifestには36 duplicate groupがあり",
              "うち26 groupはB・C・Dのmemberを含む", "A 6件は当該2 methodの全assertionである",
              "fingerprint identityはAの必要条件ではない",
              # Category C shapes, and why the negative checks stayed B.
              "**Category Cの6件**", "quote-style lock 3件",
              "ordinary English wordのraw absence check 1件",
              "non-prose structural tokenであった点で明確に区別される", "過去classificationとの矛盾は生じていない",
              "`$` anchorが`version: 20`との識別のためにload-bearing", "**Category Dは0件**",
              "**base manifest・shard001・accepted shard002の61件のいずれに対しても"
              "cross-shard fingerprint一致は0件**",
              "**shard allocationは実測にもとづき既存`document_test_classification_002.json`"
              "へのappendとした**", "恒久的なallocator policyではなく", "84 entries・94行(600行上限内)",
              TRANCHE_3L_RS_DIGESTS[0], TRANCHE_3L_RS_DIGESTS[1], TRANCHE_3L_RS_DIGESTS[2],
              TRANCHE_3L_RS_DIGESTS[3], TRANCHE_3L_RS_DIGESTS[4], TRANCHE_3L_RS_DIGESTS[5],
              "accepted main `764da66947a9b480ee2f074d553111a8e5bb278c`上の",
              "byte-identicalで保持した(259 entries・268行", "`_003`は作成していない",
              "`document_test_classification_index.json`は変更していない",
              "shards 3、combined 928 entries、A=28 B=329 C=428 D=143",
              "unclassified/stale/fingerprint mismatch いずれも0",
              "Tranche3lClassificationShard002AppendTest", "Category C 6件はこのPRでのsource変換対象ではない",
              "`.github/dependabot.yml`は変更していない",
              # Round 1: the A correction and the source-binding guards.
              "**独立レビューround 1・round 1修正(tranche 3l、2026-08-08):**",
              "571bcc930e032444476b8bc0e31a59ab082a30c0", "31242277343",
              "**Blocker 1:** Category Aを4件→**6件**へ訂正した",
              "「duplicate fingerprint groupsのunion == A set」という誤ったguardを",
              "assert-01をBとしていたguardとcommentは削除した",
              "**Blocker 2:** ordinary per-assertion fingerprintがassertion nodeしかcoverしないblind spot",
              "`setUpClass`の`cls.workflows`", "`DEPENDABOT_PATH`のPath式",
              "2つのsubTest iterableのexact binding", "blind-spot mutation",
              "新guardのみがfailすることを実証し", "residue 0")), ("- **検証(tranche 3l):**",
             ("`test_workflow_action_pinning.py` 14 OK(source無変更)",
              "`test_document_test_classification.py` 99 OK", "BL-038 record-sync 136 OK",
              "full unittest 2021→2036 OK", "shard002単独validation(84 entries・A6/B45/C25/D8)",
              "combined 928", "unclassified/stale/fingerprint mismatchはいずれも0",
              "`git diff --check`成功")), ("- **diff上限例外(tranche 3l、2026-08-08):**",
             # The cap was raised for THIS tranche only, on explicit user
             # authorization, after the stop condition was honoured -- and the
             # default for every later tranche stays 1000.
             ("1118 changed lines(948 insertions/170 deletions・5 files)",
              "原則上限**1000 changed lines**を超過した", "いったんcommitもpushもせず停止して実測値を報告した",
              "既存guardを一切削らずに6回の圧縮", "1118が下限であった",
              "2 classes(tranche 3kは1 class)", "`.github/dependabot.yml`。3kは1件",
              "whole-method AST skeleton/normalized byte-identity guardの新規導入(3kはA 0件)",
              "accepted 61-entry historical pin(3kは34-entry)", "structural guardの削減とPR分割は",
              "**ユーザーの明示的な承認により、tranche 3l限定でcapを1150 changed linesへ緩和した。**",
              "恒久的なdiff上限変更でもshard allocator policyの変更でもない",
              "**次tranche以降のdefault capは引き続き1000 changed linesとする。**",
              "A 6／B 11／C 6／D 0、shard002 append、combined 928のまま")),
            ("- **mutation-style verification(tranche 3l",
             ("commitしない一時変更、検証後に完全復元", "3 file", "# pinned to v7.0.1",
              "single quote化およびplain scalar化",
              "no custom labels, reviewers or assignees are configured", "39 hexへの切り詰め",
              "`uses: actions/cache@main`", "meaning-preserving変更ではすべてpassした",
              "cbf573b50a0ee860759c4d86298d11c7634eb34a081912efd0f0a050783af919",
              "ab375400199a9efae3105c2967a40ffd3b73dd8287ef1ea4f5012bacdf97b670",
              "883b95e3be554fbadd92b315e4a8c6ea6ca688b64924e22dd61222b07f683507",
              "residueは0", "Category Dは該当なし", "6種のmanifest mutation", "非空振り確認")), ):
            record = next(l for l in lines if l.startswith(prefix))
            for required in requirements:
                with self.subTest(record=prefix[:28], required=required):
                    self.assertIn(required, record)

    def test_status_line_carries_the_tranche3k_closeout_and_tranche3l_scope(self):
        status = self._status_bl038_line()
        for required in (
            "**tranche 3k最終受入・merge・Pages(2026-08-08):**", "31238186048", "31238943401",
            "f2a22d21aff46dad7da514db6f29a61e34e173a4",
            "764da66947a9b480ee2f074d553111a8e5bb278c", "**tranche 3l着手(2026-08-08):**",
            "test/bl038-tranche3l-workflow-action-pinning", "**候補実測・選択(tranche 3l):**",
            "最大は23の一意選択(tieなし、次点17)", "**実装証跡(tranche 3l):**",
            "**A 6／B 11／C 6／D 0**", "**Aの6件**はfingerprint duplicateだけを根拠にしていない",
            "**shard allocationは実測にもとづき既存`document_test_classification_002.json`"
            "へのappendとした**",
            "combined 928 entries(585+136+123+34+27+23)", "A 28／B 329／C 428／D 143",
            "shard002は84 entries・94行(600行上限内)", self.SHARD_002_CURRENT_SHA,
            "shard001はbyte-identical", "indexは3 shardsのまま変更なし", "BL-038全体は未完了",
            "tranche 3lではCategory C source conversionを行っていない",
            # The tranche-specific diff cap, recorded as an exception.
            "**diff上限例外(tranche 3l、2026-08-08):**", "1118 changed lines",
            "**tranche 3l限定でcapを1150 changed linesへ緩和**", "**次tranche以降のdefault capは1000のまま**",
            "**独立レビューround 1(tranche 3l、2026-08-08):**", "Category Aを4→**6件**へ訂正",
            "**A 6／B 11／C 6／D 0**", "shard002 A6/B45/C25/D8・SHA `c0f81d14…`",
            "combined A 28／B 329／C 428／D 143", ):
            with self.subTest(required=required):
                self.assertIn(required, status)
        # Historical 3l acceptance remains true; current state has advanced through 3q.
        self.assertIn("tranche 1〜3lはいずれも受入済み", status)
        self.assertIn("**tranche 3qは最終受入・merge・自動Pagesまで完了**", status)
        self.assertNotIn("**tranche 3oは未受入**", status)

    def test_repository_state_matches_the_recorded_append_and_combined_totals(self):
        """The numbers the record claims are the numbers on disk. Per-entry and
        per-manifest contracts live in the classification tests."""
        from collections import Counter

        raw = (self.ROOT / self.SHARD_002).read_bytes()
        text = raw.decode("utf-8")
        shard_002 = json.loads(text)
        # Tranche 3m appended 17 more, so tranche 3l's whole-file numbers are
        # HISTORY: 84 entries / 94 lines / SHA c0f81d14... is a subset boundary
        # now, not the file. The accepted-84 digest is pinned in the 3m class.
        self.assertEqual((hashlib.sha256(raw).hexdigest(), len(text.splitlines()),
                          len(shard_002["assertions"])),
                         (self.SHARD_002_TRANCHE_3M_SHA, 112, 101))
        for superseded in (self.SHARD_002_CURRENT_SHA, self.SHARD_002_ACCEPTED_SHA):
            with self.subTest(superseded=superseded):
                self.assertNotEqual(hashlib.sha256(raw).hexdigest(), superseded)
        # Tranche 3l added no shard; the `_003` that exists today is tranche 3o's
        # and carries neither 3l's file nor 3l's classes.
        third = json.loads((self.ROOT / "document_test_classification_003.json").read_text(encoding="utf-8"))
        self.assertEqual([e["file"] for e in third["scope"]], ["test_security_requirements.py"])
        self.assertEqual([(e["file"], e["classes"]) for e in shard_002["scope"]],
                         [("test_security_operations.py", ["Bl035DraftSyncTest"]),
                          ("test_pr_ci_workflow.py", ["PullRequestCIWorkflowTest"]),
                          (self.SOURCE_FILE, list(self.CLASSES)),
                          ("test_security_requirements.py",
                           ["Bl034Round1ReviewCorrectionsTest"])])
        appended = shard_002["assertions"][61:84]
        self.assertEqual(len(appended), 23)
        self.assertEqual(dict(Counter(e["category"] for e in appended)), {"A": 6, "B": 11, "C": 6})
        self.assertEqual({e["file"] for e in appended}, {self.SOURCE_FILE})
        self.assertEqual({t for e in appended for t in e["targets"]}, set(self.TARGETS))
        # The accepted 61 are preserved exactly, parsed-content digest included.
        payload = {"scope": shard_002["scope"][:2], "assertions": shard_002["assertions"][:61]}
        self.assertEqual(hashlib.sha256(json.dumps(payload, ensure_ascii=False, sort_keys=True,
                                      separators=(",", ":")).encode("utf-8")).hexdigest(),
            self.TRANCHE_3K_HISTORICAL_CONTENT_SHA)
        # Both older manifests are byte-identical to their accepted states, and
        # the recorded combined total is the real one.
        base_raw = (self.ROOT / "document_test_classification.json").read_bytes()
        shard_001_raw = (self.ROOT / "document_test_classification_001.json").read_bytes()
        self.assertEqual((hashlib.sha256(shard_001_raw).hexdigest(),
                          hashlib.sha256(base_raw).hexdigest()),
                         (self.SHARD_001_SHA, self.BASE_SHA))
        total = (json.loads(base_raw)["assertions"] + json.loads(shard_001_raw)["assertions"]
                 + shard_002["assertions"])
        # 928 / A28 B329 C428 D143 was the tranche 3l combined total; tranche 3m
        # moved it to 945, so this class asserts the 3l figure is now history.
        self.assertEqual((len(total), len({e["id"] for e in total})), (945, 945))
        self.assertEqual(dict(Counter(e["category"] for e in total)),
                         {"A": 28, "B": 337, "C": 435, "D": 145})
        self.assertNotEqual(len(total), 928)
        # Neither the selected source test nor any of its three targets moved.
        source = (self.ROOT / self.SOURCE_FILE).read_text(encoding="utf-8")
        self.assertTrue(all(f"class {c}" in source for c in self.CLASSES))
        for target, marker in zip(self.TARGETS, ("name: Daily Security Digest",
                                                 "name: Pull Request CI", "package-ecosystem")):
            with self.subTest(target=target):
                self.assertIn(marker, (self.ROOT / target).read_text(encoding="utf-8"))


# SHA-256 digests the tranche 3m implementation record must carry verbatim: the
# accepted-84 parsed-content digest derived from PR #94's merge commit, shard
# 002's accepted and current whole-file hashes, the older historical digests,
# and the two untouched manifests.
TRANCHE_3M_RS_DIGESTS = ("47fa2d11c1aae9bf298db175ddbd76c8776bad00491ae034e85d4bee441e8391",
    "d86d521627dabfed4b4555b8759a50c9a3538a9d89d55c8f2e5d928845e39f46", "0e1893593594daf44fb52e32ea610f2f7deb572148338faf90f2edfa7949b2cd",
    "640585ca03d7836cbdd66edcc8e2b21df7ea1de946b767ae20fa5c12e0c5f15a", )


class Bl038Tranche3mRecordSyncTest(unittest.TestCase):
    """BL-038 tranche 3m (PR #94 closeout sync + the 17 assertions of
    `test_security_requirements.py::Bl034Round1ReviewCorrectionsTest` APPENDED
    to shard 002 as scope[3]) record-sync. 1-3l accepted, 3m is not, BL-038
    open. Owns shard 002's CURRENT whole-file figures."""

    ROOT = Bl038Tranche3eRecordSyncTest.ROOT
    _read = Bl038Tranche3eRecordSyncTest._read
    _bl038_section = Bl038Tranche3eRecordSyncTest._bl038_section
    _status_bl038_line = Bl038Tranche3eRecordSyncTest._status_bl038_line

    SOURCE_FILE = "test_security_requirements.py"
    CLASS = "Bl034Round1ReviewCorrectionsTest"
    TARGET_DOCUMENTS = ("BACKLOG.md", "SECURITY_REQUIREMENTS.md")
    SHARD_002 = "document_test_classification_002.json"
    SHARD_002_CURRENT_SHA = TRANCHE_3M_RS_DIGESTS[1]
    SHARD_002_ACCEPTED_3L_SHA = \
        "c0f81d1489109e1fe9a6a8dcef497496b7c3b39ad435a84ca06944a43409aaa2"
    TRANCHE_3L_HISTORICAL_CONTENT_SHA = TRANCHE_3M_RS_DIGESTS[0]
    SHARD_001_SHA = TRANCHE_3M_RS_DIGESTS[2]
    BASE_SHA = TRANCHE_3M_RS_DIGESTS[3]
    ACCEPTED_MERGE = "48cc4fdf38303e9693cf870fb2f73a595d4908b2"
    ACCEPTED_HEAD_3L = "e27b60e3dc47938606b35d17f88e4c2469f98b3c"

    def test_backlog_records_entries_twentynine_and_thirty_with_updated_counts(self):
        bl038 = self._bl038_section()
        history_start = bl038.index("ユーザー原文の履歴")
        history = bl038[history_start : bl038.index("着手時ユーザー原文:", history_start)]
        # 「ok」 11->12 (entry 29); 「はい」 3->4 (entry 30). Entries 32/33 took
        # them to 13 and 5, and 34/35 to 14 and 6, which is the header now.
        self.assertIn("「ok」19回・「おk」7回・「次へ進めて」1回・「次へ」2回・「はい」12回・" "「進んで」1回・「うん」1回・「うん。進めて」1回", history)
        for stale in ("「ok」14回", "「ok」13回", "「ok」12回", "「はい」6回", "「はい」5回", "「はい」4回"):
            with self.subTest(stale=stale): self.assertNotIn(stale, history)
        self.assertIn("長文の作業指示2回", history)
        self.assertNotIn("長文の作業指示1回", history)
        self.assertIn("「A」1回", history)  # unchanged by 29/30, 32/33 and 34/35
        entries = re.findall(r"^\s*(\d+)\.\s+(.*?)(?=^\s*\d+\.\s|\Z)", history, re.MULTILINE | re.DOTALL)
        self.assertEqual([number for number, _ in entries], [str(i) for i in range(1, 48)])
        for number, requirements in (("29", ("tranche 3l final acceptance original", "2026-08-08", "「ok」", "PR #94",
                    "Draft解除・Ready化", "通常のmerge commit方式によるmerge", "#1・#3・#5・#7・#9・#17・#19・#21・#23・#25・#27と同一文字列だが",
                    "Category C source conversionの承認ではなく", "tranche 3m implementationの先行受入でもなく",
                    "tranche 3全体またはBL-038全体の完了承認でもなく", "workflow_dispatch")),
            ("31", ("tranche 3m diff上限例外承認original", "2026-08-08", "長文の技術指示", "changed-lines stop capを **1000 → 1200** へ明示的に緩和",
                    "実装内容(selected scope・classification・guard・manifest scope)をそのまま維持",
                    "#15(tranche 3f kickoff original)と同じく短い承認語ではない長文指示だが", "別の時点・別の目的(scope着手ではなくdiff cap例外の技術承認)の別発言",
                    "tranche 3m final acceptanceの承認ではなく", "Ready化・merge承認でもなく", "Category C source conversion・Category A helper conversionの承認でもなく",
                    "assertion/class splitting ruleの変更承認でもなく", "BL-038全体の完了承認でもなく",
                    "実Gemini／実NVD実行・手動Pagesの承認でもない", "general/default capは1000のまま", "次フェーズのrule再評価は別途の承認事項")),
            ("30", ("tranche 3m kickoff original", "2026-08-08", "「はい」", "tranche 3l closeout",
                    "再測定", "measurement-driven", "#13(tranche 3e kickoff original)・#24(tranche 3j kickoff original)・"
                    "#26(tranche 3k kickoff original)と同一文字列だが", "別の時点・別のtrancheに対する別の発言であり、混同・上書きしない",
                    "tranche 3m実装内容の最終受入ではなく", "Ready化・merge承認でもなく", "Category C source conversionの承認でもなく",
                    "`document_test_classification_003.json`を作ることの先行承認でもなく",
                    "Category A helper conversionの承認でもなく", "tranche 3全体またはBL-038全体の完了承認でもなく")), ):
            entry = next(text for n, text in entries if n == number)
            for required in requirements:
                with self.subTest(entry=number, required=required): self.assertIn(required, entry)

    def test_backlog_records_the_tranche3l_closeout_merge_and_pages(self):
        lines = self._bl038_section().splitlines()
        for prefix, requirements in (("- **tranche 3l最終受入(2026-08-08):**",
             ("tranche 3l final acceptance原文「ok」(上記29)", "PR #94", self.ACCEPTED_HEAD_3L,
              "Accept／Blocker 0", "4888322422", "4888334067", "31243840890", "completed・success", "**A 6／B 11／C 6／D 0**", "84 entries／94行",
              "**A 6／B 45／C 25／D 8**", self.SHARD_002_ACCEPTED_3L_SHA, "combined 928件", "**A 28／B 329／C 428／D 143**", "full unittest 2036 OK",
              "classification structural tests 99", "BL-038 record-sync tests 136", "5 files／1150 changed lines", "tranche 3l限定で明示承認された例外cap",
              "tranche 3m以降へ持ち越さない", "未解決review thread 0", "tranche 3lではCategory C source conversionを行っていない")),
            ("- **tranche 3l merge・Pages(2026-08-08):**", ("通常のmerge commit方式(squash・rebase不使用)", self.ACCEPTED_MERGE,
              "764da66947a9b480ee2f074d553111a8e5bb278c", self.ACCEPTED_HEAD_3L,
              "31244383101", "attempt 1", "event `dynamic`", "completed・success", "merge契機の自動runであり、手動Pages・`workflow_dispatch`ではない")), ):
            record = next(l for l in lines if l.startswith(prefix))
            for required in requirements:
                with self.subTest(record=prefix[:30], required=required): self.assertIn(required, record)

    def test_backlog_records_the_survey_selection_classification_and_verification(self):
        """One record line per tranche step: the unique eligible candidate, the
        selected scope, the A/B/C/D result with the measured basis for A 0 and
        for the one divergent collision, the shard allocation, the accepted-84
        re-anchor, and the verification and mutation evidence."""
        lines = self._bl038_section().splitlines()
        for prefix, requirements in (("- **tranche 3m着手(2026-08-08):**", ("test/bl038-tranche3m-security-requirements-bl034-round1", "diff 0",
              self.ACCEPTED_MERGE, "baseline full unittest 2036 OK", "928件", "**A 28／B 329／C 428／D 143**",
              "unclassified／stale／fingerprint mismatchいずれも0", "shards 3", "1150例外を持ち越さず既定の1000 changed linesへ戻した")), ("- **候補実測(tranche 3m):**",
             ("selection unit", "上限150 assertions", "class内部分割不可", "runtime-behavioral test除外", "無関係fileのbin-pack禁止",
              "`SecurityRequirementsTest` 403件", "`Bl034Round1ReviewCorrectionsTest` 17件",
              "eligibleは`Bl034Round1ReviewCorrectionsTest`単独17件", "`SourceUsagePolicyTest` 177件のみ", "remaining eligibleなし",
              "候補universe自体もtranche 3e round 1で全23 fileを実測して確定", "`fetch.py`／`daily_json.py`をimportするruntime-behavioral test",
              "期待値(17・403・177)は最新source上の実測と完全に一致")), ("- **選択(tranche 3m):**", ("eligible candidateは17件のみ", "最大は17で一意である", "同数のtieなし",
              "他にeligible candidateが存在しない", "1 class・7 methods・17 assertions",
              "assertIn 10／assertNotIn 3／assertRegex 2／assertNotRegex 1／assertFalse 1",
              "custom assertion helperなし", "source test自体は変更していない")), ("- **実装証跡(tranche 3m):**",
             ("**A 0／B 8／C 7／D 2**(total 17)", "category countsを固定せず1件ずつ判断",
              # A 0 is measured, not asserted from the class docstring.
              "A 0の理由をclass docstringのhistorical性ではなく実測で記録する", "arity(2/2/2/2/5/2/2)", "AST node-type skeletonが一致するのは3 method",
              "node typeは`assertIn`と`assertNotIn`を区別しない", "独立した2つ以上のliteralが異なり", "tranche 3lのA基準(1 tokenのnormalizeでmethodがbyte-identicalになる)を満たさない",
              "`Bl034ImplementationAcceptanceTest::test_bl009_remains_the_in_progress_umbrella`", "base manifestは変更していない",
              # The C shapes, measured.
              "Category C 7件は4形", "1行197文字", "`**merge後:**`", "`Cloudflare dashboardでの実データ受信確認`", "`user-accepted and merged`",
              "`normalize_markdown_prose()`済みでもreword brittlenessが残る", "197文字。C precedentのBL-007 label items 177・811文字と同規模",
              "B precedentのUI_SPEC.md standalone marker 17文字とは規模が異なる",
              # D keeps precedent; Status stays B.
              "6d032e702e1b118bc6da86b981a4189b4a85e15b", "`**Version:** 1.7`",
              "既存precedent 6件と整合", "`**Status:** Approved`は既存precedent 5件と整合させBのまま維持",
              # Collisions, including the one documented divergence.
              "17件内のduplicate group 0", "accepted 84件とのcollision 0", "6件のcollision", "5件は衝突先の既存categoryが全て今回の判断と一致",
              "既存divergenceであり、今回は同file precedentのCへ整合させた", "既存entryは1件も変更していない",
              # Allocation, measured -- including why not shard 001.
              "shard allocationは実測で決めた", "scope[3]として追加でき",
              "duplicate-scope-file 0", "cross-shard (file,class) ownership重複0", "101 entries／112行で600行cap内",
              "2つ目の同-file scope entry追加は`duplicate-scope-file`となることをmutationで実証",
              "byte-frozenなshard001の書き換えを要するため採らない", "600行capは判断要因ではない(268+17もcap内)",
              TRANCHE_3M_RS_DIGESTS[1], "84→101 entries／94→112行", "**A 6／B 53／C 32／D 10**",
              "accepted 84件はIDs・categories・順序・parsed object content", "raw byte単位では完全同一ではない", "raw一致は83行で、差分はこのカンマのみ", "「byte単位で無変更」という記述を撤回した",
              "raw-byte identityとparsed-content identityを混同しないよう別値として区別", TRANCHE_3M_RS_DIGESTS[2], TRANCHE_3M_RS_DIGESTS[3],
              "`document_test_classification_index.json`も3 shardsのまま無変更", "`document_test_classification_003.json`は作成していない",
              "combined 945件", "**A 28／B 337／C 435／D 145**", "tranche 3mではCategory C source conversionを行っていない")),
            ("- **accepted tranche 3l state固定(tranche 3m):**", (self.ACCEPTED_MERGE, "accepted scope[0:3]", "accepted first 84 entries",
              "修正後のcurrent shardからは自己生成していない", "TRANCHE_3L_HISTORICAL_CONTENT_SHA256", TRANCHE_3M_RS_DIGESTS[0],
              "scope順・84 IDs・file/class/method/ordinal・assertion_api・fingerprint・" "targets・category・action・contract_summary・rationale・assertion順",
              "いずれか1 fieldが動けばdigestも動くことをtestで実証", "84 entries／94行／SHA `c0f81d14...`／A 6 B 45 C 25 D 8",
              "101／112／`d86d5216...`／A 6 B 53 C 32 D 10", "tranche 3h accepted 136件digest `1f0156b6...`",
              "tranche 3j accepted 34件digest `d4d7f932...`", "tranche 3k accepted 61件digest `233c9839...`")), ("- **検証(tranche 3m):**",
             ("`test_security_requirements.py` 120 tests OK(source無変更)", "`test_document_test_classification.py` 118 OK", "BL-038 record-sync 143 OK",
              "full unittest 2062 OK", "945件", "**A 28／B 337／C 435／D 145**", "shards 3",
              "legacy base単体", "shard001単体成功", "shard002単体成功", "byte identityをSHA-256で再確認",
              "tranche 3h／3j／3k accepted 61／3l accepted 84の各historical digestが一致")), ("- **fingerprint blind-spot guard(tranche 3m):**",
             ("assertion call nodeのみをcover", "`cls.requirements`", "`cls.backlog`", "選択17件が実際に読む2件だけ**をpathへpin", "exactly `backlog`・`requirements`",
              "path・存在・不在のいずれもtranche 3m contractとしては固定していない", "retargetしても削除してもこのguardはPASS", "`_section(text, start, end=None)`",
              # PR #95 round 2: the current record must not re-pin cls.status.
              "`cls.status`はsetUpClassで代入されるが選択17件のいずれも読まない",
              "whole-source hashではなくbody単位", "method-local section binding 5件", "`## BL-009`〜`\\n## BL-010`", "`## BL-034`〜`\\n## 完了済み参照`",
              "`## 8. Gap register`", "`gap016_row`", 'line.startswith("| GAP-016 |")',
              "downstream assertion 3件", "`stale`", "`normalized_requirements`", "`stale in normalized_requirements`という比較そのもの")),
            ("- **blind-spot mutation verification(tranche 3m", ("commitしない一時変更、検証後に完全復元",
              "03f17fc3cbcecb7991ee30b7d67c2eb8469ecf008a7c3481dd1a31d6a0df86aa", "`\\n## BL-010`→`\\n## BL-011`", "選択class内の該当1行のみをAST行範囲で特定",
              "同fileの他2箇所の同一行は変更していない", "17件のassertion IDと17件すべてのfingerprintは完全に不変", "`| GAP-016 |`→`| GAP-017 |`", "first outbound network endpoint",
              "新規のstale-phrase binding guardのみがFAIL", "復元後のSHA-256はpreと一致し、mutation residueは0")),
            ("- **独立レビューround 1・round 2(tranche 3m、2026-08-08):**", ("baffb9f1559475d5490e64ea196ffd4bf5e3d05c", "4888746668", "Blocker 3件",
              "`cls.status`→`STATUS.md`まで**over-pin**", "shard002 `94/600行`", "「残420件／17件のみeligible」", "「byte単位で無変更」と記録していた",
              "f16cc663d85f8d2937f478aa9b2b6b2b2444ee22", "4888815691", "Blocker 1件", "`cls.status`の**存在**をtranche 3m contractにする3 assertionが残っていた",
              "path・存在・不在のいずれのcontractも課さない形へ狭めた", "assignment削除**のいずれでもguardがPASS", "復元後source SHA一致、residue 0", "いずれのroundでも変更していない")),
            ("- **diff上限例外(tranche 3m、2026-08-08):**", ("default capは1000 changed lines",
              "**1347 changed lines**", "停止条件どおり一度commitもpushもせず実測値を報告した", "tranche 3lの1150例外は自動継承していない", "AST等価性を毎回検証した行再パック",
              "guard・coverage・manifest entry・selected scopeを一切削らずに**9回の圧縮**", "**1142 changed lines**が実用上のfloorであった", "structural guardの削減とPR分割は採らず",
              "**tranche 3m限定でcapを1200 changed linesへ緩和した**", "1150ではなく1200", "恒久的なdiff上限変更ではなく", "eligible candidateが0となる見込み",
              "**tranche 3m merge後のgeneral/default capは引き続き1000 changed linesとする。**", "150 assertion cap", "class内分割禁止", "別途の承認事項として本trancheでは先取りしない",
              "classification(A 0／B 8／C 7／D 2)・combined 945・shard allocation・" "selected scopeは一切変更していない")),
            ("- **mutation-style verification(tranche 3m", ("commitしない一時変更、検証後に完全復元",
              "bec9a307feaf290cccc3d6390a047471439eeaf5fed89f3412bb674d5a930e6b", "dd857b098775ffc48f6eadea0029b32b5abdc5ac0b1ea3b8bd1cf3253017a36e",
              "manifest・shard・source testは一切変更していない", "`進行中（閲覧計測基盤をBL-034で先行）`", "`Cloudflare dashboardでの実データ受信の確認`",
              "`**merge完了後:**`", "`is accepted by the user and merged`",
              "negative normalized checkについては", "assertionはPASSし続けることを実証した", "failするのではなく黙って保護しなくなるというCの失敗様態そのもの",
              "`Policy decision`→`Security gap`", "`Implemented`→`Deferred`",
              "`**Status:** Approved`→`**Status:** Draft`", "`/cdn-cgi/rum`→`/cdn-cgi/beacon`",
              "5件がいずれも正しく失敗した", "`**Version:** 1.7`→`**Version:** 1.8`", "Category A該当は0件のためA mutationは対象外",
              "**wide-span masking(tranche 3mで判明・対処済み):**", "`## BL-034`〜`## 完了済み参照`という広い範囲", "BL-034本文では各1件のまま、wide spanでは2〜4件",
              "tranche 3e round 2が指摘したmaskingと同じ性質", "narrow-range guardを`test_fetch.py`へ追加", "両documentのSHA-256はpreと一致し、`git diff`residueは0")), ):
            record = next(l for l in lines if l.startswith(prefix))
            for required in requirements:
                with self.subTest(record=prefix[:32], required=required): self.assertIn(required, record)

    def test_status_line_carries_the_tranche3l_closeout_and_tranche3m_scope(self):
        status = self._status_bl038_line()
        for required in ("**tranche 3l最終受入・merge・Pages(2026-08-08):**", "entry 29", "4888322422",
            "4888334067", "31243840890", self.ACCEPTED_HEAD_3L, self.ACCEPTED_MERGE, "31244383101", "1150はtranche 3l限定で明示承認された例外capであり",
            "tranche 3m以降へは持ち越さない", "これによりtranche 1〜3lはいずれも受入済みとなった", "**tranche 3m着手(2026-08-08):**",
            "test/bl038-tranche3m-security-requirements-bl034-round1", "**候補実測・選択(tranche 3m):**", "**17の一意選択、tieなし、他候補なし**", "**実装証跡(tranche 3m):**",
            "**A 0／B 8／C 7／D 2(total 17)**", "A 0は実測根拠つき", "combined **945・A 28／B 337／C 435／D 145**",
            "shard002は101 entries・112行", self.SHARD_002_CURRENT_SHA, "accepted 84件はIDs・categories・順序・parsed object contentを不変のまま先頭に保持",
            "raw byteでは84件目entry行とscope[2]行に行末カンマが付くため完全同一ではなく", TRANCHE_3M_RS_DIGESTS[0], "修正後のcurrent shardからは自己生成していない",
            "`_003`は作成していない", "**検証(tranche 3m):**", "full unittest 2062 OK", "BL-038全体は未完了",
            # PR #95 merged, so 3m's own line is now history, not current state.
            "tranche 3mではCategory C source conversionを行っていない", "**tranche 3mはPR #95で受入・merge済み**",
            "eligible candidateは**tranche 3m時点で0件**", "その方針決定と実装がtranche 3nである",
            "**diff上限例外(tranche 3m、2026-08-08):**", "**1347 changed lines**",
            "**9回圧縮して1142 changed lines**", "**tranche 3m限定でcapを1200 changed linesへ緩和**",
            "**tranche 3m merge後のgeneral/default capは1000のまま**", "**post-3m候補実測(tranche 3m時点):**",
            "eligible candidateは **0件**だった", "当時のルールではclassification継続不可", "next-phase rule decisionを要した", ):
            with self.subTest(required=required): self.assertIn(required, status)
        for stale in ("**tranche 3mは未受入**", "tranche 3nは受入済み", "BL-038は完了"):
            with self.subTest(stale=stale): self.assertNotIn(stale, status)

    def test_current_residual_work_line_keeps_the_durable_tranche3m_facts(self):
        """PR #95 round 1 (Blocker 2) put the CURRENT residual bullet under test.
        Tranche 3o now owns that bullet's current-state wording, so this class
        keeps only what stays true about 3m once 3m is accepted: its own C count
        and the fact that BL-038 is still open."""
        residual = re.search(r"^- \*\*残作業:\*\* .*$", self._bl038_section(), re.MULTILINE).group(0)
        for required in ("tranche 3mの7件", "BL-038全体の最終受入は上記残作業が完了するまで行わない"):
            with self.subTest(required=required): self.assertIn(required, residual)
        # 3l-, 3m- and 3n-era current-state wording is all stale in this bullet.
        for stale in ("shard002は94/600行", "残420件", "tranche 3lは実装中", "tranche 3mは実装中",
                "tranche 3lのDraft PR独立レビュー", "tranche 3mのDraft PR独立レビュー",
                "tranche 3nのDraft PR独立レビュー", "現行ruleでのeligible candidateは0件"):
            with self.subTest(stale=stale): self.assertNotIn(stale, residual)
        # 3l's and 3m's own history survive in the section.
        bl038 = self._bl038_section()
        self.assertIn("tranche 3lの6件", residual)
        self.assertIn("- **diff上限例外(tranche 3l、2026-08-08):**", bl038)
        self.assertIn("- **diff上限例外(tranche 3m、2026-08-08):**", bl038)

    def test_classification_targets_are_intact_in_their_own_narrow_sections(self):
        """Three of the 17 read BL-034 through the WIDE `## BL-034`..`## 完了済み参照` span,
        which also holds the BL-038 records -- and tranche 3m's own records quote those
        literals, so the wide span would satisfy them even if the BL-034 body lost them
        (the masking tranche 3e round 2 hit). These guards pin the BODIES instead."""
        backlog = self._read("BACKLOG.md")
        bl034 = backlog.split("## BL-034", 1)[1].split("\n## BL-035", 1)[0]
        bl009 = backlog.split("## BL-009", 1)[1].split("\n## BL-010", 1)[0]
        for literal in ("12. **merge後:**", "Cloudflare dashboardでの実データ受信確認", "6d032e702e1b118bc6da86b981a4189b4a85e15b", "- **状態:** 完了"):
            with self.subTest(literal=literal): self.assertIn(literal, bl034)
        self.assertIn("- **状態:** 進行中（BL-034で閲覧計測基盤を先行）", bl009)
        self.assertNotIn("- **状態:** 完了", bl009)
        # The masking is real and measured: the wide span now holds extra copies
        # that the BL-034 body itself does not.
        wide = backlog.split("## BL-034", 1)[1].split("\n## 完了済み参照", 1)[0]
        for literal in ("Cloudflare dashboardでの実データ受信確認", "**merge後:**", "6d032e702e1b118bc6da86b981a4189b4a85e15b"):
            with self.subTest(masked=literal):
                self.assertEqual(bl034.count(literal), 1)
                self.assertGreater(wide.count(literal), 1)

    def test_repository_state_matches_the_recorded_append_and_combined_totals(self):
        """The numbers the record claims are the numbers on disk, including the
        accepted-84 parsed-content digest derived from PR #94's merge."""
        from collections import Counter

        raw = (self.ROOT / self.SHARD_002).read_bytes()
        text = raw.decode("utf-8")
        shard_002 = json.loads(text)
        self.assertEqual((hashlib.sha256(raw).hexdigest(), len(text.splitlines()),
                          len(shard_002["assertions"])), (self.SHARD_002_CURRENT_SHA, 112, 101))
        self.assertNotEqual(hashlib.sha256(raw).hexdigest(), self.SHARD_002_ACCEPTED_3L_SHA)
        # Tranche 3m created no `_003`: today's is tranche 3o's method-range shard,
        # and 3m's 17 stay in shard 002 where 3m put them.
        third = json.loads((self.ROOT / "document_test_classification_003.json").read_text(encoding="utf-8"))
        self.assertEqual([e["classes"] for e in third["scope"]], [["SecurityRequirementsTest"]])
        self.assertNotIn(self.CLASS, {e["class"] for e in third["assertions"]})
        self.assertEqual([(e["file"], e["classes"]) for e in shard_002["scope"]], [("test_security_operations.py", ["Bl035DraftSyncTest"]),
                          ("test_pr_ci_workflow.py", ["PullRequestCIWorkflowTest"]), ("test_workflow_action_pinning.py",
                           ["WorkflowActionPinningTest", "DependabotConfigurationTest"]), (self.SOURCE_FILE, [self.CLASS])])
        appended = shard_002["assertions"][84:]
        self.assertEqual(len(appended), 17)
        self.assertEqual(dict(Counter(e["category"] for e in appended)), {"B": 8, "C": 7, "D": 2})
        self.assertEqual({e["file"] for e in appended}, {self.SOURCE_FILE})
        self.assertEqual({e["class"] for e in appended}, {self.CLASS})
        self.assertEqual({t.split("#")[0] for e in appended for t in e["targets"]}, set(self.TARGET_DOCUMENTS))
        self.assertEqual({e["action"] for e in appended if e["category"] == "C"}, {"refactor_later"})
        # The accepted 84 are preserved exactly, parsed-content digest included,
        # and the digest was derived from the accepted file at PR #94's merge.
        payload = {"scope": shard_002["scope"][:3], "assertions": shard_002["assertions"][:84]}
        self.assertEqual(hashlib.sha256(json.dumps(payload, ensure_ascii=False, sort_keys=True,
                                      separators=(",", ":")).encode("utf-8")).hexdigest(), self.TRANCHE_3L_HISTORICAL_CONTENT_SHA)
        # Both older manifests are byte-identical to their accepted states, and
        # the recorded combined total is the real one.
        base_raw = (self.ROOT / "document_test_classification.json").read_bytes()
        shard_001_raw = (self.ROOT / "document_test_classification_001.json").read_bytes()
        self.assertEqual((hashlib.sha256(shard_001_raw).hexdigest(), hashlib.sha256(base_raw).hexdigest()), (self.SHARD_001_SHA, self.BASE_SHA))
        total = (json.loads(base_raw)["assertions"] + json.loads(shard_001_raw)["assertions"] + shard_002["assertions"])
        self.assertEqual((len(total), len({e["id"] for e in total})), (945, 945))
        self.assertEqual(dict(Counter(e["category"] for e in total)), {"A": 28, "B": 337, "C": 435, "D": 145})
        # Neither the selected source test nor either target document moved.
        source = (self.ROOT / self.SOURCE_FILE).read_text(encoding="utf-8")
        self.assertIn(f"class {self.CLASS}(unittest.TestCase):", source)
        for document, marker in zip(self.TARGET_DOCUMENTS, ("## BL-034", "## 8. Gap register")):
            with self.subTest(document=document): self.assertIn(marker, (self.ROOT / document).read_text(encoding="utf-8"))


TRANCHE_3N_RS_SHAS = ("640585ca03d7836cbdd66edcc8e2b21df7ea1de946b767ae20fa5c12e0c5f15a",
    "0e1893593594daf44fb52e32ea610f2f7deb572148338faf90f2edfa7949b2cd",
    "d86d521627dabfed4b4555b8759a50c9a3538a9d89d55c8f2e5d928845e39f46",
    "79af09f33a4118090bb1991e77a0184847a89a0fcae7f9095455135ca1337246", )
# (file, class, methods, assertions, window start, window end, window methods,
#  window assertions, next method, its assertions, the total that overflows 150)
TRANCHE_3N_CANDIDATES = (
    ("test_security_requirements.py", "SecurityRequirementsTest", 39, 403,
     "test_document_is_approved_version_14_maintenance_update",
     "test_bl028_is_recorded_verbatim_as_complete", 19, 146,
     "test_bl029_is_recorded_verbatim_as_complete", 18, 164),
    ("test_source_usage_policy.py", "SourceUsagePolicyTest", 36, 177,
     "test_gemini_gate_references_point_to_chapter_5",
     "test_cisa_has_no_url_in_official_evidence_url_and_is_terms_not_identified", 32, 140,
     "test_mandiant_distinguishes_rss_evidence_from_terms_evidence", 11, 151), )


class Bl038Tranche3nRecordSyncTest(unittest.TestCase):
    """BL-038 tranche 3n (PR #95 closeout sync + method-scope INFRASTRUCTURE
    only) record-sync. 1-3m accepted, 3n is not, BL-038 open. No assertion was
    classified: this class owns the CURRENT residual bullet and the claim that
    all four manifest/index files are untouched."""

    ROOT = Bl038Tranche3eRecordSyncTest.ROOT
    _read = Bl038Tranche3eRecordSyncTest._read
    _bl038_section = Bl038Tranche3eRecordSyncTest._bl038_section
    _status_bl038_line = Bl038Tranche3eRecordSyncTest._status_bl038_line

    BRANCH = "test/bl038-tranche3n-method-scope-infrastructure"
    ACCEPTED_HEAD_3M = "8eadabc9bff4cd81a5d7f31cd4e7dfc9bcab4017"
    ACCEPTED_MERGE = "80fe54b3621746cad21868c480f83a4f02b5a439"
    ACCEPTED_84_DIGEST = "47fa2d11c1aae9bf298db175ddbd76c8776bad00491ae034e85d4bee441e8391"
    MANIFESTS = ("document_test_classification.json", "document_test_classification_001.json", "document_test_classification_002.json", "document_test_classification_index.json")

    def test_backlog_records_entries_thirtytwo_and_thirtythree_with_updated_counts(self):
        bl038 = self._bl038_section()
        history_start = bl038.index("ユーザー原文の履歴")
        history = bl038[history_start : bl038.index("着手時ユーザー原文:", history_start)]
        # 「ok」 12->13 (entry 32); 「はい」 4->5 (entry 33). Entries 34/35 then
        # took them to 14 and 6, which is the header this now reads.
        self.assertIn("「ok」19回・「おk」7回・「次へ進めて」1回・「次へ」2回・「はい」12回・" "「進んで」1回・「うん」1回・「うん。進めて」1回", history)
        for stale in ("「ok」14回", "「ok」13回", "「はい」6回", "「はい」5回"):
            with self.subTest(stale=stale): self.assertNotIn(stale, history)
        self.assertIn("長文の作業指示2回", history)  # unchanged by 32/33 and 34/35
        entries = re.findall(r"^\s*(\d+)\.\s+(.*?)(?=^\s*\d+\.\s|\Z)", history, re.MULTILINE | re.DOTALL)
        self.assertEqual([number for number, _ in entries], [str(i) for i in range(1, 48)])
        for number, requirements in (("32", ("tranche 3m final acceptance original", "2026-08-08", "** `ok` —", "PR #95",
                    "Draft解除・Ready化", "通常のmerge commit方式によるmerge", "#1・#3・#5・#7・#9・#17・#19・#21・#23・#25・#27・#29と同一文字列だが", "Category C source conversionの承認ではなく",
                    "Category A helper conversionの承認でもなく", "method-scope rule変更の承認でもなく", "tranche 3n implementationの先行受入でもなく", "tranche 3全体またはBL-038全体の完了承認でもなく", "workflow_dispatch")),
            ("33", ("tranche 3n kickoff original", "2026-08-08", "** `はい` —", "tranche 3m closeout", "post-3mに残る403件・177件の再確認", "next-phase selection ruleの設計",
                    "method-boundary partial-class scope infrastructureの実装", "synthetic validation", "#13・#24・#26・#30と同一文字列だが", "別の時点・別のtrancheに対する別の発言であり、混同・上書きしない",
                    "tranche 3n final acceptanceの承認ではなく", "Ready化・merge承認でもなく", "403件／177件の実際のclassification開始の承認でもなく", "150 assertion capの引き上げ承認でもなく", "assertion内分割の承認でもなく")), ):
            entry = next(text for n, text in entries if n == number)
            for required in requirements:
                with self.subTest(entry=number, required=required): self.assertIn(required, entry)

    def test_backlog_records_the_tranche3m_closeout_merge_and_pages(self):
        lines = self._bl038_section().splitlines()
        for prefix, requirements in (("- **tranche 3m最終受入(2026-08-08):**", ("tranche 3m final acceptance原文は raw `ok`(上記32", "PR #95", self.ACCEPTED_HEAD_3M,
              "Accept／Blocker 0", "4888836090", "4888838598", "31257981308", "completed・success", "**A 0／B 8／C 7／D 2**(total 17)", "combined 945件",
              "**A 28／B 337／C 435／D 145**", "101 entries／112行／**A 6／B 53／C 32／D 10**", TRANCHE_3N_RS_SHAS[2], self.ACCEPTED_84_DIGEST, "full unittest 2062 OK",
              "classification structural tests 118", "BL-038 record-sync tests 143", "5 files／1200 changed lines", "tranche 3m限定で明示承認された例外capであり", "tranche 3n以降へ持ち越さない", "未解決review thread 0",
              "tranche 3mではCategory C source conversionを行っていない")), ("- **tranche 3m merge・Pages(2026-08-08):**", ("通常のmerge commit方式(squash・rebase不使用)", self.ACCEPTED_MERGE,
                "48cc4fdf38303e9693cf870fb2f73a595d4908b2", self.ACCEPTED_HEAD_3M,
              "31258331780", "attempt 1", "event `dynamic`", "completed・success", "merge契機の自動runであり、手動Pages・`workflow_dispatch`ではない", "general/default diff capは1000 changed linesへ戻る")), ):
            record = next(l for l in lines if l.startswith(prefix))
            for required in requirements:
                with self.subTest(record=prefix[:30], required=required): self.assertIn(required, record)

    def test_backlog_records_the_rule_the_schema_the_invariants_and_the_measurement(self):
        """One record line per tranche 3n step. The tranche classified nothing,
        so the records that matter are the RULE, the schema extension, the two
        ownership invariants, the synthetic evidence, and the measurement."""
        lines = self._bl038_section().splitlines()
        for prefix, requirements in (("- **tranche 3n着手(2026-08-08):**", (self.BRANCH, "diff 0", self.ACCEPTED_MERGE,
              "baseline full unittest 2062 OK", "combined 945件", "**A 28／B 337／C 435／D 145**", "shards 3", "unclassified／stale／fingerprint mismatchいずれも0",
              "585 entries・596行", "259 entries・268行",
              "101 entries・112行", TRANCHE_3N_RS_SHAS[0], TRANCHE_3N_RS_SHAS[1], TRANCHE_3N_RS_SHAS[2], "tranche 3mの1200例外を持ち越さず既定の1000 changed linesである",
              "**tranche 3nはmethod-scope infrastructure専用であり、残る403件／177件のclassification自体は行わない。**")), ("- **next-phase selection rule確定(tranche 3n):**", ("remaining eligible candidateが0となった",
              "**150 assertion capは引き上げず**", "oversized classに限り", "source順で連続するtest method range", "1 file・1 class・`test_*` method単位", "method内assertionは全件含む",
              "**method内部をassertion境界で分割することは絶対に禁止**", "total <=150 assertions", "class内の飛び飛びmethod結合禁止", "最初の未分類test methodから開始", "150を超える直前で停止したprefix", "最初の未分類method単独で150超ならstop finding",
              "**tieの場合は自動tie-breakせずcandidate selection非一意として停止しユーザー判断を求める**", "arbitrary sliding windowもcherry-pickも構造的に不可能", "既存のwhole-class selectionはそのまま有効")),
            ("- **method-range manifest extension(tranche 3n):**", ("`schema_version` 1", "backward-compatible extension", "schema_version bumpは行っていない",
                "既存whole-class形", "意味もvalidationも完全維持", '"method_range":{"start":"test_...","end":"test_..."}', "`invalid-scope-shape`", "**closed exact key setを持つのはmethod-range形だけである**",
              "legacy validationを狭めない", "`method_range` keyを持たないlegacy whole-class scope entryはaccepted mainどおり`file`・`classes`のみを検証", "その他のotherwise-ignored extra keyは従来どおりrejectしない",
              "formはkeyの**存在**で判定するため", "`method_range` keyを持つscope entryのkeysはexactly `file`・`classes`・`method_range`",
              "`method_range: null`はlegacy whole-class扱いにならずmalformed windowとしてfail close", "keysはexactly `start`・`end`(この順序)", "source order上`start <= end`", "start/end inclusive",
              "**rangeはmethod名の列挙ではなく2つの境界で定義されるため、range内の全test methodが自動的にscopeへ入る**",
              "manifest entryがなければ`unclassified`", "explicit method-name list方式", "は採用していない", "`<file>::<class>::<method>::assert-NN`", "fingerprint algorithmはいずれも一切変更していない",
              "method_ranges=None", "records・known_methodsとも完全に不変", "`unknown-method`", "`MethodRangeError`", "`InventoryError`のsubclass",
              "`invalid-method-range`")), ("- **cross-shard ownership・contiguous-prefix invariant(tranche 3n):**", (
              # The class-level unit is load-bearing: "method units only" would
              # describe a validator letting a zero-test-method class be claimed
              # twice (PR #96 final review).
              "**class自身を表す1つのclass-level ownership unitと、各test methodのunit**", "**whole-class scopeはclass-level unitとそのclassの全test-method unitの両方をownする**",
              "**class-level unitはload-bearingなcontractである**", "`test_*` methodを1件も持たないclass", "**zero-test-method classでもaccepted mainの`(file,class)` exclusivityがそのまま維持される**",
              "conflictはshard pair単位で1件に集約", "method-range scopeはclass-level unitをownせず", "range内の各test-method unit`(file,class,method)`のみをownership", "必ず競合する", "disjointな場合のみ",
              "`cross-shard-duplicate-ownership`", "`cross-shard-duplicate-id`", "従来どおり維持", "**contiguous-prefix invariant**", "gapもoverlapもない1つの連続prefix", "`method-range-prefix-gap`",
              "range1 = method 1〜N・range2 = method N+1〜MはOK", "**最後までclass全体をcoverする必要はなく、未分類tailは次trancheの正当な残作業である。**", "構造的に起こり得ない", "prefix invariantはcombined validation側にのみ置いており")),
            ("- **synthetic validation(tranche 3n):**", ("repository manifestを一切変更せず", "temporary directory", "30 tests追加、合計125 tests",
                "`method_ranges`をomit／`None`／`{}`／無関係classのいずれでもbaselineと",
              "945件・A28 B337 C435 D145", "start=test_a／end=test_bがa+bだけをinventory", "start=end=test_aも有効", "whole-class scanと完全一致", "`test_inserted`",
              "`unclassified`でFAIL", "unknown start／unknown end／reversed start-end", "classes != exactly one", "a→b + c→d = PASS", "a→c + c→d = overlap FAIL", "a→a + c→d = internal gap FAIL",
              "b→c as first range = prefix-start FAIL", "whole class + range = ownership conflict FAIL", "同一fileの別class ownershipは従来どおりPASS", "rename／delete／順序逆転はいずれもFAIL",
              "**現分類prefixより後ろへのinsertはPASSし続けfuture unclassified tailとして扱われる**")), ("- **post-infra候補実測(tranche 3n、classificationは行わない):**", ("manifestは1件も変更していない",
              "39 test methods・403 assertions", "36 test methods・177 assertions", "既分類method 0", "**19 methods・146 assertions**", "**32 methods・140 assertions**", "164となり150を超えるため停止",
              "151となり150を超えるため停止", "**candidate間にtieはない(146 > 140であり、winnerはSecurityRequirementsTest側で一意)。**", "単独で150 assertionsを超えるtest methodは両class合わせて0件",
              "最大は", "の81件", "**新ruleでのstop findingは発生していない**",
              "**このwinnerはtranche 3nではclassificationしない。**")), ("- **独立レビューround 1(tranche 3n、2026-08-08):**", ("bb18f500e07c0ef8c926664bb991533ee28aa19c",
              "4888913853", "Blocker 2件", "accepted mainのlegacy whole-class semanticsを弱めていた", "legacy whole-class scope validationのnarrowing", "extra keyを持つlegacy scope entryを新たにreject",
              "**`method_range` keyが存在するscope entryに限定**", "keyの**存在**で判定するため", "`_scope_claims()`も同じpresence-based判定へ揃えた", "`SCOPE_KEYS_WHOLE_CLASS`定数は不要になったため削除",
              "zero-test-method classでのownership喪失", "`range(len(method_names))`へ展開していたため", "`cross-shard-duplicate-ownership`がsilent PASS", "ownership unitに**class自身を表すunit**を追加",
              "conflictをshard pair単位で1件に集約", "新method-range semantics", "いずれも弱めていない", "inventory tests 122→125", "`EmptyTest`", "他の123 testsは全てPASSのままである", "residue 0")),
            ("- **検証(tranche 3n):**", ("`test_document_test_inventory.py` 125 OK(うちmethod-range新規30)", "`test_document_test_classification.py` 118 OK",
                "full unittest 2101 OK", "945件", "shards 3", "legacy base単体", "shard001単体成功", "shard002単体成功", "`origin/main`とbyte-identicalであることをSHA-256で再確認", "`_003`・`_004`は作成していない",
              self.ACCEPTED_84_DIGEST, "classification 0件・combined 945件のまま変更なし", "Category C source conversionもCategory A helper conversionも行っていない")), ):
            record = next(l for l in lines if l.startswith(prefix))
            for required in requirements:
                with self.subTest(record=prefix[:34], required=required): self.assertIn(required, record)
        measurement = next(l for l in lines if l.startswith("- **post-infra候補実測(tranche 3n"))
        for name, cls, _m, _a, start, end, _n, _c, nxt, _nc, _t in TRANCHE_3N_CANDIDATES:
            for required in (f"`{name}::{cls}`", f"`{start}`", f"`{end}`", f"`{nxt}`"):
                with self.subTest(cls=cls, required=required): self.assertIn(required, measurement)

    def test_current_schema_record_states_the_post_round1_key_contract(self):
        """PR #96 round 2. The CURRENT schema record must describe the contract as
        it shipped -- a closed key set for the method-range form ONLY. The
        pre-round-1 wording belongs to the round 1 record, which keeps it."""
        lines = self._bl038_section().splitlines()
        current = next(l for l in lines if l.startswith("- **method-range manifest extension(tranche 3n):**"))
        for stale in ("exactly 2形のみ", "scope entry keysはwhole-class形が`file`・`classes`"):
            with self.subTest(stale=stale): self.assertNotIn(stale, current)
        history = next(l for l in lines if l.startswith("- **独立レビューround 1(tranche 3n"))
        for kept in ("legacy whole-class scope validationのnarrowing", "extra keyを持つlegacy scope entryを新たにreject", "**`method_range` keyが存在するscope entryに限定**"):
            with self.subTest(kept=kept): self.assertIn(kept, history)

    def test_current_ownership_record_names_the_class_level_unit(self):
        """PR #96 final review. Describing ownership as test-method units alone
        describes a validator that misses a duplicated whole-class claim on a class
        with no `test_*` methods, so the current records must name the class-level
        unit; the round 1 record keeps its own account of the fix."""
        lines = self._bl038_section().splitlines()
        current = next(l for l in lines if l.startswith("- **cross-shard ownership・contiguous-prefix invariant(tranche 3n):**"))
        history = next(l for l in lines if l.startswith("- **独立レビューround 1(tranche 3n"))
        for stale, text in (("従来の`(file,class)` exclusive ownershipを**test method単位**へ拡張した", current), ("whole-class scopeはそのclassの全test methodsをownershipするため", current),
                            ("ownershipを`(file,class)`から**test method単位**へ拡張し", self._status_bl038_line())):
            with self.subTest(stale=stale): self.assertNotIn(stale, text)
        for kept in ("ownership unitに**class自身を表すunit**を追加", "zero-test-method classでのownership喪失"):
            with self.subTest(kept=kept): self.assertIn(kept, history)

    def test_status_line_carries_the_tranche3m_closeout_and_tranche3n_scope(self):
        status = self._status_bl038_line()
        for required in ("**tranche 3m最終受入・merge・Pages(2026-08-08):**", "entry 32", "4888836090", "4888838598", "31257981308", self.ACCEPTED_HEAD_3M, self.ACCEPTED_MERGE, "31258331780",
            "**1200はtranche 3m限定で明示承認された例外capであり、tranche 3n以降へは持ち越さない。**", "**これによりtranche 1〜3mはいずれも受入済みとなり、general/default diff capは1000 changed linesへ戻った。**",
            "**tranche 3n着手(2026-08-08):**", self.BRANCH, "entry 33", "**tranche 3nはmethod-scope infrastructure専用であり、残る403件／177件のclassificationは行っていない。**",
            "**next-phase rule(tranche 3n):**", "**150 assertion capは引き上げず**", "**assertion単位では絶対に分割しない(method内assertionは全件含む)。**",
            "自動tie-breakせず停止してユーザー判断を求める", "**method-range manifest extension(tranche 3n):**", "backward-compatible extension(bumpなし)",
            "**rangeはmethod名の列挙ではなく2境界で定義されるためrange内の全test methodが自動的にscopeへ入る**",
            "silent skipしない", "assertion ID・ordinal・fingerprint algorithmはいずれも無変更", "**ownership・prefix invariant(tranche 3n):**",
            "**class自身のunit＋各test methodのunit**へ分解", "**whole-class scopeはclass-level unitと全test-method unitの両方を**",
            "**class-level unitはload-bearing**", "`test_*` 0件のclassでもaccepted mainの`(file,class)` exclusivityが維持される", "method-range scopeはrange内のtest-method unitのみをown",
            "**gapなしoverlapなしの連続prefix**", "`method-range-prefix-gap`", "**class全体をcoverする必要はなく、未分類tailは次trancheの正当な残作業である。**",
            "**synthetic validation(tranche 3n):**", "inventory tests 125、うち新規30",
            "**post-infra候補実測(tranche 3n、classificationなし):**", "**19 methods／146 assertions**", "**32 methods／140 assertions**", "**tieなし(146 > 140)で前者が一意のwinner**",
            "単独150超のtest methodは0件(最大81件)であり**stop findingは発生していない**", "**このwinnerはtranche 3nではclassificationしない。**", "**検証(tranche 3n):**",
            "full unittest 2101 OK", "**独立レビューround 1(tranche 3n、2026-08-08):**", "review `4888913853`", "Blocker 2件", "**`method_range` keyが存在するentryに限定**",
            "ownership unitに**class自身のunit**を追加", "conflict報告もshard pair単位で1件へ集約", "regression tests 4件を追加・再編(inventory 122→125)", "修正前コードを再現する2 mutationで該当testのみがFAILすることを実証", "いずれも変更していない",
            "**4つのmanifest/index fileはいずれも`origin/main`とbyte-identicalで、`_003`・`_004`は作成していない。" "classification 0件・combined 945は無変更。**", "BL-038全体は未完了",
            # PR #96 merged, so 3n's own line is now history, not current state.
            "**tranche 3nはPR #96で受入・merge済み**", ):
            with self.subTest(required=required): self.assertIn(required, status)
        for stale in ("**tranche 3nは未受入**", "tranche 3oは受入済み", "BL-038は完了",
                      "eligible candidateは現時点で0件"):
            with self.subTest(stale=stale): self.assertNotIn(stale, status)

    def test_current_residual_work_line_keeps_the_durable_tranche3n_facts(self):
        """Tranche 3o owns the CURRENT residual bullet now. What stays true about
        3n is that it classified nothing and that the candidates it MEASURED are
        the ones the rule produced -- 3o classified the winner's prefix, so the
        bullet must still name both figures while no longer calling 3n current."""
        residual = re.search(r"^- \*\*残作業:\*\* .*$", self._bl038_section(), re.MULTILINE).group(0)
        for required in ("19 methods", "146", "32 methods",
                         "次trancheの候補再測定・着手"):
            with self.subTest(required=required): self.assertIn(required, residual)
        for stale in ("tranche 3nのDraft PR独立レビュー", "tranche 3oのDraft PR独立レビュー",
                      "現行ruleでのeligible candidateは0件", "tranche 3nは実装中"):
            with self.subTest(stale=stale): self.assertNotIn(stale, residual)

    def test_the_three_manifests_tranche_3n_left_untouched_are_still_untouched(self):
        """Tranche 3n classified nothing, so the three CLASSIFICATION manifests it
        inherited had to come out byte-identical -- and they still are. What
        tranche 3o changed is the index (a fourth shard) and nothing else: the
        945/A28-B337-C435-D145 those three still hold is exactly 3n's total, now
        a proper subset of the combined classification rather than all of it."""
        from collections import Counter

        self.assertEqual(tuple(hashlib.sha256((self.ROOT / name).read_bytes()).hexdigest()
                               for name in self.MANIFESTS[:3]), TRANCHE_3N_RS_SHAS[:3])
        total = [e for name in self.MANIFESTS[:3] for e in json.loads((self.ROOT / name).read_text(encoding="utf-8"))["assertions"]]
        self.assertEqual((len(total), len({e["id"] for e in total})), (945, 945))
        self.assertEqual(dict(Counter(e["category"] for e in total)), {"A": 28, "B": 337, "C": 435, "D": 145})
        # The index is the one file tranche 3o touched: same three shards first,
        # in the same order, plus `_003`. No `_004`.
        index = json.loads((self.ROOT / self.MANIFESTS[3]).read_text(encoding="utf-8"))
        self.assertEqual(index["shards"][:3], list(self.MANIFESTS[:3]))
        # 3o appended `_003` and 3p `_004`; 3n's own three still lead the index.
        self.assertEqual(index["shards"][:4], list(self.MANIFESTS[:3]) + ["document_test_classification_003.json"])
        self.assertNotEqual(hashlib.sha256((self.ROOT / self.MANIFESTS[3]).read_bytes()).hexdigest(),
                            TRANCHE_3N_RS_SHAS[3])
        # Neither class 3n MEASURED was classified by 3n itself; tranche 3o took
        # a method range of the winner, and left the runner-up alone entirely.
        classified = {(e["file"], e["class"]) for e in total}
        for name, cls, *_rest in TRANCHE_3N_CANDIDATES:
            with self.subTest(cls=cls): self.assertNotIn((name, cls), classified)
        third = json.loads((self.ROOT / "document_test_classification_003.json").read_text(encoding="utf-8"))
        self.assertEqual([(e["file"], e["classes"]) for e in third["scope"]],
                         [(TRANCHE_3N_CANDIDATES[0][0], [TRANCHE_3N_CANDIDATES[0][1]])])
        self.assertNotIn(TRANCHE_3N_CANDIDATES[1][1], {e["class"] for e in third["assertions"]})

    def test_the_recorded_candidate_measurement_reproduces_from_live_source(self):
        """Every candidate figure in the record is re-derived here from the
        real source with the real tool, so the record cannot drift from it."""
        import ast
        import document_test_inventory as dti

        for name, cls, methods, assertions, start, end, window, count, nxt, nxt_n, nxt_total in TRANCHE_3N_CANDIDATES:
            with self.subTest(cls=cls):
                source = (self.ROOT / name).read_text(encoding="utf-8")
                node = next(n for n in ast.walk(ast.parse(source, filename=name)) if isinstance(n, ast.ClassDef) and n.name == cls)
                order = [m.name for m in dti._class_test_methods_in_source_order(node)]
                records = dti.enumerate_assertions(source, name, [cls])
                per = {m: sum(1 for r in records if r.method == m) for m in order}
                self.assertEqual((len(order), len(records)), (methods, assertions))
                self.assertEqual((order[0], order[window - 1], order[window]), (start, end, nxt))
                # The greedy contiguous prefix is exactly the recorded window, it
                # stops exactly because the next whole method overflows, and no
                # single method is itself unclassifiable under the 150 cap.
                self.assertEqual((sum(per[m] for m in order[:window]), per[nxt], count + per[nxt]), (count, nxt_n, nxt_total))
                self.assertLessEqual((count, 151, max(per.values())), (150, nxt_total, 150))
        # The winner is unique: no tie to break.
        counts = [candidate[7] for candidate in TRANCHE_3N_CANDIDATES]
        self.assertEqual(len(set(counts)), len(counts))
        self.assertEqual(max(counts), 146)


TRANCHE_3O_SHARD_003_SHA = "f3c28245d708cdd1fc20432e4f02cd01d2ecc5eb13da976beb0cc94872674ceb"
TRANCHE_3O_FROZEN_SHAS = ("640585ca03d7836cbdd66edcc8e2b21df7ea1de946b767ae20fa5c12e0c5f15a",
    "0e1893593594daf44fb52e32ea610f2f7deb572148338faf90f2edfa7949b2cd",
    "d86d521627dabfed4b4555b8759a50c9a3538a9d89d55c8f2e5d928845e39f46", )
TRANCHE_3O_RANGE = ("test_document_is_approved_version_14_maintenance_update",
                    "test_bl028_is_recorded_verbatim_as_complete")


class Bl038Tranche3oRecordSyncTest(unittest.TestCase):
    """BL-038 tranche 3o (PR #96 closeout sync + the 146 assertions of the FIRST
    method-range scope in the repository) record-sync. 1-3n accepted, 3o is not,
    BL-038 open. Owns the CURRENT residual bullet and shard 003."""

    ROOT = Bl038Tranche3eRecordSyncTest.ROOT
    _read = Bl038Tranche3eRecordSyncTest._read
    _bl038_section = Bl038Tranche3eRecordSyncTest._bl038_section
    _status_bl038_line = Bl038Tranche3eRecordSyncTest._status_bl038_line

    BRANCH = "test/bl038-tranche3o-security-requirements-method-range"
    ACCEPTED_HEAD_3N = "8c7079a0d5f7db33505a9adddd27492b0a8ac3a6"
    ACCEPTED_MERGE = "61767aea50d3ecdeb50f7a40e3ff45938ef63784"
    SOURCE_FILE = "test_security_requirements.py"
    CLASS = "SecurityRequirementsTest"
    SHARDS = ("document_test_classification.json", "document_test_classification_001.json",
              "document_test_classification_002.json", "document_test_classification_003.json")

    def test_backlog_records_entries_thirtyfour_and_thirtyfive_with_updated_counts(self):
        bl038 = self._bl038_section()
        history_start = bl038.index("ユーザー原文の履歴")
        history = bl038[history_start : bl038.index("着手時ユーザー原文:", history_start)]
        # 「ok」 13->14 (entry 34); 「はい」 5->6 (entry 35). Entries 36/37 then
        # took them to 15 and 7, which is the header this now reads.
        self.assertIn("「ok」19回・「おk」7回・「次へ進めて」1回・「次へ」2回・「はい」12回・" "「進んで」1回・「うん」1回・「うん。進めて」1回", history)
        for stale in ("「ok」14回", "「ok」13回", "「はい」6回", "「はい」5回"):
            with self.subTest(stale=stale): self.assertNotIn(stale, history)
        self.assertIn("長文の作業指示2回", history)  # unchanged by 34/35
        entries = re.findall(r"^\s*(\d+)\.\s+(.*?)(?=^\s*\d+\.\s|\Z)", history, re.MULTILINE | re.DOTALL)
        self.assertEqual([number for number, _ in entries], [str(i) for i in range(1, 48)])
        for number, requirements in (
            ("34", ("tranche 3n final acceptance original", "2026-08-09", "** `ok` —", "PR #96",
                    "Draft解除・Ready化", "通常のmerge commit方式によるmerge",
                    "#1・#3・#5・#7・#9・#17・#19・#21・#23・#25・#27・#29・#32と同一文字列だが",
                    "**tranche 3nはinfrastructure専用でclassification 0件であり、この受入はclassificationの受入ではない。**",
                    "403件／177件のclassification開始の承認でもなく", "tranche 3o implementationの先行受入でもなく",
                    "tranche 3全体またはBL-038全体の完了承認でもなく", "workflow_dispatch")),
            ("35", ("tranche 3o kickoff original", "2026-08-09", "** `はい` —", "tranche 3n closeout",
                    "latest main上での一意候補の再測定", "19 methods／146 assertionsを分類",
                    "#13・#24・#26・#30・#33と同一文字列だが", "別の時点・別のtrancheに対する別の発言であり、混同・上書きしない",
                    "tranche 3o final acceptanceの承認ではなく", "Ready化・merge承認でもなく",
                    "`SourceUsagePolicyTest` 140件への着手承認でもなく", "tailへの着手承認でもなく",
                    "150 assertion capの引き上げ承認でもなく", "assertion内分割の承認でもなく")), ):
            entry = next(text for n, text in entries if n == number)
            for required in requirements:
                with self.subTest(entry=number, required=required): self.assertIn(required, entry)

    def test_backlog_records_the_tranche3n_closeout_merge_and_pages(self):
        lines = self._bl038_section().splitlines()
        for prefix, requirements in (("- **tranche 3n最終受入(2026-08-09 JST):**",
             ("tranche 3n final acceptance原文は raw `ok`(上記34", "PR #96", self.ACCEPTED_HEAD_3N,
              "Accept／Blocker 0", "4889091113", "4889112666", "31264008272", "completed・success",
              "**tranche 3nのclassificationは0件**", "combined 945件", "**A 28／B 337／C 435／D 145**",
              "byte-identical", "`_003`・`_004`は未作成", "5 files／985 changed lines",
              "full unittest 2101 OK", "inventory tests 125 OK", "classification structural tests 118 OK",
              "385 OK", "未解決review thread 0")),
            ("- **tranche 3n merge・Pages(2026-08-09 JST):**", ("通常のmerge commit方式(squash・rebase不使用)",
              self.ACCEPTED_MERGE, "80fe54b3621746cad21868c480f83a4f02b5a439", self.ACCEPTED_HEAD_3N,
              "31265472768", "attempt 1", "event `dynamic`", "completed・success",
              "merge契機の自動runであり、手動Pages・`workflow_dispatch`ではない",
              "**これによりtranche 1〜3nはいずれも受入済みとなった。**", "**日付はJST基準である**",
              "2026-08-08T15:48:56Z`(=2026-08-09 00:48:56 JST)", "2026-08-08T15:50:34Z`(=2026-08-09 00:50:34 JST)",
              "tranche 3n closeout一式はJSTでは2026-08-09である")), ):
            record = next(l for l in lines if l.startswith(prefix))
            for required in requirements:
                with self.subTest(record=prefix[:30], required=required): self.assertIn(required, record)

    def test_backlog_records_the_measurement_selection_classification_and_allocation(self):
        lines = self._bl038_section().splitlines()
        for prefix, requirements in (("- **tranche 3o着手(2026-08-09):**", (self.BRANCH, "diff 0", self.ACCEPTED_MERGE,
              "full unittest 2101 OK", "inventory 125 OK", "classification 118 OK", "record-sync 385 OK",
              "indexed manifests 3 shards・combined 945件", "**A 28／B 337／C 435／D 145**",
              "unclassified／stale／fingerprint mismatchいずれも0", "585 entries・596行", "259 entries・268行",
              "101 entries・112行", "default changed-lines capは1000", "tranche 3mの1200例外は持ち越していない")),
            ("- **候補再測定(tranche 3o):**", ("repository recordの146／140を鵜呑みにせず",
              "39 test methods・403 assertions・既分類method 0", "**19 methods・146 assertions**",
              "164となり150を超えるため停止", "36 test methods・177 assertions", "**32 methods・140 assertions**",
              "**146 > 140でSecurityRequirementsTestが一意のwinner、tieなし。**",
              "単独で150 assertionsを超えるtest methodは0件", "stop findingは発生していない",
              "期待値(39／403／19／146／18／164／32／140)は再測定と完全一致")),
            ("- **選択(tranche 3o):**", ("**これはrepository初のmethod-range scopeであり",
              "19 methods・146 assertionsの全件をinventory ID順で分類",
              "method内部のassertion分割・境界変更・cherry-pickはいずれも行っていない",
              "assertIn 89／assertEqual 21／assertRegex 14／assertNotIn 13／assertLess 7／assertTrue 2",
              "`SourceUsagePolicyTest`の140件には着手しておらず", "tail 20 methods・257 assertionsにも着手していない",
              "source testとtarget documentはいずれも分類のために変更していない")),
            ("- **実装証跡(tranche 3o):**", ("**A 0／B 70／C 54／D 22**(total 146)",
              "事前にcategory countsを固定せず", "**Category A 0は実測根拠つきである**",
              "node数36〜448、skeleton一致group 0", "選択内のfingerprint重複は1組のみ",
              "両methodはarityが3と4", "fingerprint重複だけではAとしない",
              "既存945件とのfingerprint collisionは2件", "既存7 entryすべてD", "既存6 entryすべてB",
              "既存entryは1件も変更していない", "Category B 70件", "Category C 54件", "Category D 22件",
              "**Category C source conversionは行っていない**", "Category A helper conversionも行っていない")),
            ("- **shard allocation(tranche 3o、validator実測):**", ("allocationは決め打ちせずvalidatorで実測",
              "**いずれも既に`test_security_requirements.py`をscopeしており**", "`duplicate-scope-file`",
              "`shard-line-cap-exceeded`", "既存accepted shardのscope書き換えや過去のaccepted classificationの移動は行わない",
              "**新規`document_test_classification_003.json`を作成し、root indexの末尾へ追加した**",
              "146 entries／154行", TRANCHE_3O_SHARD_003_SHA, "600行cap内",
              "`_004`は作成していない", "combined 1091件", "**A 28／B 407／C 489／D 167**", "shards 4")),
            ("- **structural guard(tranche 3o):**", ("118→130 tests", "exact start/end boundary",
              "19 methods／146 assertions", "**最初の未分類method(index 0)から始まる**",
              "164>150となり停止", "winnerが一意(tieなし)", "runner-up fileがどのshardからもscopeされていない",
              "**classified range内部へmethodをinsertすると`unclassified`になること**",
              "prefix invariantを満たしtailが正当な未分類として残ること",
              "source構造に不要なexact prose/bindingは新たにpinしていない")),
            ("- **mutation-style verification(tranche 3o", ("commitしない一時変更、検証後に完全復元",
              "**24 mutation**", "**Category B 9件**", "**Category D 7件**", "**Category C 8件**",
              "**意味を保ったまま失敗**", "**assertionはPASSし続けた**", "protection gapそのものである",
              "**Category A該当は0件のためA mutationは対象外。**",
              "3 fileのSHA-256はいずれもpreと一致し、`git diff`residueは0",
              "wide-span maskingは構造的に発生しない")),
            ("- **検証(tranche 3o):**", ("`test_security_requirements.py` 120 tests OK(source無変更)",
              "`test_document_test_classification.py` 130 OK", "`test_document_test_inventory.py` 125 OK",
              "1091件", "shards 4", "shard003単体成功", "byte identityをSHA-256で再確認",
              "全shard 600行以下(base 596／shard001 268／shard002 112／shard003 154)")), ):
            record = next(l for l in lines if l.startswith(prefix))
            for required in requirements:
                with self.subTest(record=prefix[:34], required=required): self.assertIn(required, record)

    def test_status_line_carries_the_tranche3n_closeout_and_tranche3o_scope(self):
        status = self._status_bl038_line()
        for required in ("**tranche 3n最終受入・merge・Pages(2026-08-09 JST):**", "entry 34", "4889091113",
            "4889112666", "31264008272", self.ACCEPTED_HEAD_3N, self.ACCEPTED_MERGE, "31265472768",
            "**これによりtranche 1〜3nはいずれも受入済みとなった。**",
            "**tranche 3o着手(2026-08-09):**", self.BRANCH, "entry 35",
            # Raw originals, and the JST basis for the corrected closeout date.
            "tranche 3n final acceptance原文は raw `ok`", "tranche 3o kickoff原文は raw `はい`",
            "表示上の`「」`は原文の一部ではない", "**日付はJST基準**",
            "**候補再測定(tranche 3o):**", "**19 methods／146 assertions**", "**32 methods／140**",
            "**146 > 140で前者が一意のwinner、tieなし。単独150超のmethodは0件(最大81)でstop findingなし。**",
            "**選択・分類(tranche 3o):**", "**repository初のmethod-range scope**",
            "**A 0／B 70／C 54／D 22(total 146)**", "**A 0は実測根拠つき**",
            "既存entryは1件も変更していない", "**shard allocation(tranche 3o):**",
            "**いずれも既に`test_security_requirements.py`をscope済み**",
            "**新規`document_test_classification_003.json`を作成しindex末尾へ追加**",
            TRANCHE_3O_SHARD_003_SHA, "combined **1091・A 28／B 407／C 489／D 167**",
            "**guard・mutation(tranche 3o):**", "118→130", "**24件**", "**protection gap**",
            "**残り(post-3o):**", "tail **9 methods／133 assertions**", "**36 methods／177 assertions全件**",
            "BL-038全体は未完了",
            # PR #97 merged, so 3o's own line is now history, not current state.
            "**tranche 3oはPR #97で受入・merge済み**", ):
            with self.subTest(required=required): self.assertIn(required, status)
        for stale in ("**tranche 3oは未受入**", "tranche 3pは受入済み", "BL-038は完了"):
            with self.subTest(stale=stale): self.assertNotIn(stale, status)

    def test_current_residual_work_line_keeps_the_durable_tranche3o_facts(self):
        residual = re.search(r"^- \*\*残作業:\*\* .*$", self._bl038_section(), re.MULTILINE).group(0)
        for required in ("tranche 3oの54件", "shard003 154/600行",
                "**`test_security_requirements.py::SecurityRequirementsTest`のtail 9 methods・133 assertions**",
                "tranche 3oが先頭19 methods・146件を分類済み",
                "tranche 3d・3e・3h・3i・3j・3k・3m・3o・3qはCategory A該当なしと確定済み",
                "BL-038全体の最終受入は上記残作業が完了するまで行わない"):
            with self.subTest(required=required): self.assertIn(required, residual)
        for stale in ("tranche 3nのDraft PR独立レビュー", "tranche 3oのDraft PR独立レビュー",
                      "現行ruleでのeligible candidateは0件", "tranche 3oは実装中"):
            with self.subTest(stale=stale): self.assertNotIn(stale, residual)

    def test_repository_state_matches_the_recorded_method_range_append(self):
        """The numbers the record claims are the numbers on disk: a fourth shard
        holding exactly the window, three frozen shards, and a combined 1091."""
        from collections import Counter

        raw = (self.ROOT / self.SHARDS[3]).read_bytes()
        text = raw.decode("utf-8")
        shard = json.loads(text)
        self.assertEqual((hashlib.sha256(raw).hexdigest(), len(text.splitlines()),
                          len(shard["assertions"])), (TRANCHE_3O_SHARD_003_SHA, 154, 146))
        self.assertLessEqual(len(text.splitlines()), 600)
        self.assertEqual(shard["scope"], [{"file": self.SOURCE_FILE, "classes": [self.CLASS],
                                           "method_range": {"start": TRANCHE_3O_RANGE[0],
                                                            "end": TRANCHE_3O_RANGE[1]}}])
        self.assertEqual(dict(Counter(e["category"] for e in shard["assertions"])),
                         {"B": 70, "C": 54, "D": 22})
        self.assertEqual({e["action"] for e in shard["assertions"] if e["category"] == "C"}, {"refactor_later"})
        self.assertEqual({(e["file"], e["class"]) for e in shard["assertions"]}, {(self.SOURCE_FILE, self.CLASS)})
        self.assertEqual(len({e["method"] for e in shard["assertions"]}), 19)
        # The three accepted shards are byte-identical, and the index gained one entry.
        self.assertEqual(tuple(hashlib.sha256((self.ROOT / n).read_bytes()).hexdigest()
                               for n in self.SHARDS[:3]), TRANCHE_3O_FROZEN_SHAS)
        # Tranche 3o's four shards still lead the index in the same order, and
        # the 1091/A28-B407-C489-D167 they hold is exactly 3o's combined total --
        # now a prefix of the classification rather than all of it, because
        # tranche 3p appended `_004`.
        index = json.loads((self.ROOT / "document_test_classification_index.json").read_text(encoding="utf-8"))
        self.assertEqual(index["shards"][:4], list(self.SHARDS))
        total = [e for n in self.SHARDS for e in json.loads((self.ROOT / n).read_text(encoding="utf-8"))["assertions"]]
        self.assertEqual((len(total), len({e["id"] for e in total})), (1091, 1091))
        self.assertEqual(dict(Counter(e["category"] for e in total)), {"A": 28, "B": 407, "C": 489, "D": 167})
        # THROUGH tranche 3o the runner-up class was untouched; tranche 3p is
        # what classified it, so this is pinned over 3o's snapshot only.
        self.assertNotIn("test_source_usage_policy.py",
                         {e["file"] for n in self.SHARDS
                          for e in json.loads((self.ROOT / n).read_text(encoding="utf-8"))["scope"]})
        # Neither the selected source test nor its target documents moved.
        source = (self.ROOT / self.SOURCE_FILE).read_text(encoding="utf-8")
        self.assertIn(f"class {self.CLASS}(unittest.TestCase):", source)
        for document, marker in (("SECURITY_REQUIREMENTS.md", "## 8. Gap register"), ("BACKLOG.md", "## BL-028")):
            with self.subTest(document=document): self.assertIn(marker, (self.ROOT / document).read_text(encoding="utf-8"))


TRANCHE_3P_SHARD_004_SHA = "26522ff5c37ce8a30d0f2dc61bd1b1cfcbdc60929e059d984890e97e1544f792"
TRANCHE_3P_FROZEN_SHAS = ("640585ca03d7836cbdd66edcc8e2b21df7ea1de946b767ae20fa5c12e0c5f15a",
    "0e1893593594daf44fb52e32ea610f2f7deb572148338faf90f2edfa7949b2cd",
    "d86d521627dabfed4b4555b8759a50c9a3538a9d89d55c8f2e5d928845e39f46",
    "f3c28245d708cdd1fc20432e4f02cd01d2ecc5eb13da976beb0cc94872674ceb", )
TRANCHE_3P_RANGE = ("test_gemini_gate_references_point_to_chapter_5",
                    "test_cisa_has_no_url_in_official_evidence_url_and_is_terms_not_identified")


class Bl038Tranche3pRecordSyncTest(unittest.TestCase):
    """BL-038 tranche 3p (PR #97 closeout sync + the 140 assertions of the second
    method-range scope, on a class no shard had touched) record-sync. 1-3o
    accepted, 3p is not, BL-038 open. Owns the CURRENT residual bullet and
    shard 004."""

    ROOT = Bl038Tranche3eRecordSyncTest.ROOT
    _read = Bl038Tranche3eRecordSyncTest._read
    _bl038_section = Bl038Tranche3eRecordSyncTest._bl038_section
    _status_bl038_line = Bl038Tranche3eRecordSyncTest._status_bl038_line

    BRANCH = "test/bl038-tranche3p-source-usage-policy-method-range"
    ACCEPTED_HEAD_3O = "2785589388d698384907862bb8fbab7191dd2e48"
    ACCEPTED_MERGE = "d5d246990973d4905da8108b23d71ab5c772ef6c"
    SOURCE_FILE = "test_source_usage_policy.py"
    CLASS = "SourceUsagePolicyTest"
    SHARDS = ("document_test_classification.json", "document_test_classification_001.json", "document_test_classification_002.json", "document_test_classification_003.json",
              "document_test_classification_004.json")

    def test_backlog_records_entries_thirtysix_and_thirtyseven_as_raw_originals(self):
        bl038 = self._bl038_section()
        history_start = bl038.index("ユーザー原文の履歴")
        history = bl038[history_start : bl038.index("着手時ユーザー原文:", history_start)]
        # 「ok」 14->15 (entry 36); 「はい」 6->7 (entry 37).
        self.assertIn("「ok」19回・「おk」7回・「次へ進めて」1回・「次へ」2回・「はい」12回・" "「進んで」1回・「うん」1回・「うん。進めて」1回", history)
        for stale in ("「ok」14回", "「はい」6回"):
            with self.subTest(stale=stale): self.assertNotIn(stale, history)
        entries = re.findall(r"^\s*(\d+)\.\s+(.*?)(?=^\s*\d+\.\s|\Z)", history, re.MULTILINE | re.DOTALL)
        self.assertEqual([number for number, _ in entries], [str(i) for i in range(1, 48)])
        for number, requirements in (
            # Raw originals: the corner brackets are display quoting, not the message.
            ("36", ("tranche 3o final acceptance original", "2026-08-09", "** `ok` —", "PR #97", "表示上の`「」`は原文の一部ではない", "Draft解除・Ready化", "通常のmerge commit方式によるmerge",
                    "#1・#3・#5・#7・#9・#17・#19・#21・#23・#25・#27・#29・#32・#34と同一文字列だが", "Category C source conversionの承認ではなく", "Category A helper conversionの承認でもなく",
                    "tranche 3p implementationの先行受入でもなく", "workflow_dispatch")), ("37", ("tranche 3p kickoff original", "2026-08-09", "** `はい` —", "tranche 3o closeout",
                    "表示上の`「」`は原文の一部ではない", "latest main上での候補再測定", "32 methods／140 assertionsを分類", "#13・#24・#26・#30・#33・#35と同一文字列だが", "残り4 methods／37 assertionsへの着手承認でもなく",
                    "`SecurityRequirementsTest` 124件への着手承認でもなく", "150 assertion capの引き上げ承認でもなく", "assertion内分割の承認でもなく")), ):
            entry = next(text for n, text in entries if n == number)
            for required in requirements:
                with self.subTest(entry=number, required=required): self.assertIn(required, entry)

    def test_backlog_records_the_tranche3o_closeout_in_the_real_github_order(self):
        """The order matters: the final acceptance review was recorded AFTER the
        PR came out of Draft, not before it."""
        lines = self._bl038_section().splitlines()
        for prefix, requirements in (("- **tranche 3o最終受入(2026-08-09 JST):**", ("tranche 3o final acceptance原文はraw `ok`(上記36", "PR #97", self.ACCEPTED_HEAD_3O,
              "**GitHub上の実際の順序**", "final acceptance reviewはReady化より前ではない", "4890126614", "Accept／Blocker 0", "2026-08-09T00:00:03Z", "ユーザーがraw `ok`で最終受入",
              "Draft解除・Ready化(`2026-08-09T01:54:45Z`)", "4890302399", "2026-08-09T01:57:53Z", "2026-08-09T01:58:18Z", "2026-08-09T01:58:19Z", "31282229621", "completed・success",
              "**A 0／B 70／C 54／D 22**", "146 entries／154行", "f3c28245d708cdd1fc20432e4f02cd01d2ecc5eb13da976beb0cc94872674ceb",
              "combined 1091件", "**A 28／B 407／C 489／D 167**", "7 files／970 changed lines", "full unittest 2119 OK", "未解決review thread 0")),
            ("- **tranche 3o merge・Pages(2026-08-09 JST):**", ("通常のmerge commit方式(squash・rebase不使用)", self.ACCEPTED_MERGE, "4100192cdc66b33837e975296affee28d96fedce", self.ACCEPTED_HEAD_3O,
              "**commit signatureはverified／valid**", "31289348799", "attempt 1", "event `dynamic`", "completed・success", "**手動Pages・`workflow_dispatch`はいずれも未実施**",
              "**これによりtranche 1〜3oはいずれも受入済みとなった。**")), ):
            record = next(l for l in lines if l.startswith(prefix))
            for required in requirements:
                with self.subTest(record=prefix[:32], required=required): self.assertIn(required, record)

    def test_backlog_records_the_measurement_selection_classification_and_allocation(self):
        lines = self._bl038_section().splitlines()
        for prefix, requirements in (("- **tranche 3p着手(2026-08-09):**", (self.BRANCH, "diff 0", self.ACCEPTED_MERGE, "既存branchの再利用なし", "full unittest 2119 OK",
              "indexed shards 4・combined 1091件", "**A 28／B 407／C 489／D 167**", "default changed-lines capは1000", "tranche 3mの1200例外は流用していない")),
            ("- **候補再測定(tranche 3p):**", ("記録値を優先せず", "**candidate A**", "**candidate B**", "39 methods／403 assertions", "**11 methods／124 assertions**", "205となり150を超えるため停止",
              "36 methods／177 assertions・既分類0件", "**32 methods／140 assertions**", "151となり150超過", "**140 > 124でSourceUsagePolicyTestが一意のwinner、tieなし。**",
              "stop findingは発生していない", "期待値", "再測定と完全一致")), ("- **選択(tranche 3p):**", ("**tranche 3oに続く2件目のmethod-range scopeであり", "どのshardも一度もscopeしていなかったclassへ適用した最初の例である",
              "32 methods・140 assertionsの全件をinventory ID順で分類", "assertIn 89／assertEqual 27／assertNotIn 18／assertTrue 5／assertNotRegex 1",
              "残り4 methods／37 assertions", "`SecurityRequirementsTest`の124件にも着手していない", "分類のために変更していない")), ("- **実装証跡(tranche 3p):**", ("**A 2／B 80／C 50／D 8**(total 140)",
              "**Category A 2件は実測根拠つきである**", "一致groupは2組", "node-type skeletonが`assertIn`と`assertNotIn`を区別しないことによる**偽陽性**", "45-node skeletonが一致し", "**bodyがbyte-identicalになる**",
              "2件のfingerprintは相異なるため、fingerprint重複によるA判定ではない", "既存1091件とのfingerprint collisionは**0件**", "既存entryは1件も変更していない", "Category B 80件", "Category C 50件", "Category D 8件",
              "**Category C source conversionは行っていない**", "**Category A helper conversionも行っていない**")), ("- **shard allocation(tranche 3p、validator実測):**", ("allocationは決め打ちせず",
              "**今回のfileはどのshardもscopeしていない**", "`duplicate-scope-file`はどこでも発生せず",
              "`shard-line-cap-exceeded`", "**shard001へのappend 19件、shard002へのappend 18件、shard003へのappend 13件、新規`_004` 12件**", "**4つの既存accepted shardをすべてbyte-identicalのまま維持できる唯一の選択肢**",
              "既存accepted entriesの移動・再分類は一切行っていない", "「trancheごとに新shard」というルールではない", "140 entries／148行", TRANCHE_3P_SHARD_004_SHA, "600行cap内", "`_005`は作成していない",
              "combined 1231件", "**A 30／B 487／C 539／D 175**", "shards 5")), ("- **structural guard(tranche 3p):**", ("130→142 tests", "exact start/end boundary",
              "32 methods／140 assertions", "**最初の未分類method(index 0)から始まる**", "151>150となり停止", "11 methods／124 assertions", "winnerが一意(tieなし)",
              "**未分類tail 4 methods／37 assertionsを合法なfuture tailとして記録すること**", "禁止contractにはしていない", "**historical testにmutable current shard setを使って「今後もtailを分類してはならない」というcontractは作っていない**",
              "TRANCHE_3M/3O/3P_HISTORICAL_SHARD_ORDER")), ("- **mutation-style verification(tranche 3p", ("commitしない一時変更、検証後に完全復元",
              "**23 mutation**", "**Category B 8件**", "**Category D 4件**", "**Category C 8件**", "**意味を保ったまま失敗**", "**assertionはPASSし続けた**", "protection gapそのものである",
              "**Category A 3件**", "一方のmutationがもう一方のtestを緑のまま残す", "SHA-256はpreと一致し、`git diff`residueは0")),
            ("- **独立レビューround 1(tranche 3p、2026-08-09):**", ("952edd19a6472b575a2ade62be57af972f4160fb", "4890440049", "Blocker 2件", "`下記7章` negative proseのB→C訂正",
              "bare identifierではなく日本語のcross-reference phrase", "`後述7章`・`以下の7章`・`第7章参照`", "negative prose substringのprotection gap", "**A 2／B 80／C 50／D 8**(total 140)",
              "combined **1231(A 30／B 487／C 539／D 175)**", "shard004は変更後に再実測し", "26522ff5c37ce8a30d0f2dc61bd1b1cfcbdc60929e059d984890e97e1544f792", "round 1前は`ffb218f1…`",
              "**PASSし続けた**", "used-binding narrow guardの補完", "**used-binding-onlyでnarrow structural guardを追加する**", "**26 methodに合計90個のload-bearing outer string literal**",
              "**`subTest(...)`のlabel引数は意図的に除外している**", "whole-file hashではなくAST/structuralなpin", "**140 assertionのfingerprintが1件も変化しない**", "**新しいnarrow guardだけがFAIL**", "142→150 tests")),
            ("- **独立レビューround 2(tranche 3p、2026-08-09):**", ("b566e2773597300e31f072806b6cead388892024",
              "4890476282", "Blocker 1件", "**used-binding guardがouter string literalしかcoverしていない**", "`> 2`へ変えても140 fingerprintも90 outer string literalも全件不変", "`_outer_semantics()`",
              "**数値定数・比較演算子・slice/index topology・`split()`のmaxsplit・comprehension条件**", "**comment・cosmetic subTest label・variable renameはfreeのまま**", "narrow expression equalityへ強化",
              "`if part.strip()`のempty-token filterを削除しても通っていた", "**digestはCPython versionに依存しない実装である**", "31294209709", "`_expr()`", "150→152 tests")),
            ("- **独立レビューround 3(tranche 3p、2026-08-09):**", ("7e16dfed1a0363cd530ff72e0df403654bfac900", "4890572647", "Blocker 2件", "32 selected methods全体のouter-AST digestがover-pinだった。",
              "manifestのcontract_summary/rationaleが一切変わらず140 fingerprintも変わらない無害な同値変形までFAIL", "blanket digest", "は削除し", "**multisetとして**比較", "順序が意味を持つ唯一の箇所",
              "row bindingを解決して", "**無害な同値変形3件**", "**guardがPASS**", "**semantic変更4件**", "**guardがFAIL**", "PR body内のstale diff値", "152→153 tests")),
            ("- **独立レビューround 4(tranche 3p、2026-08-09):**", ("3916ccba8907902e18ef86759ae68824a71f69d2",
              "4890615003", "Blocker 2件", "outer-literal multisetではsource_id→row bindingの対応関係が失われていた", "**assertion ordinal → source_id**という意味mappingとしてpinするnarrow guardを追加",
              "**local変数名そのものはcontractにしていない**", "**blanket AST digestは復活させていない。**", "**140 assertion IDs不変・140 fingerprints不変・outer literal multiset不変**", "**新guardがFAIL**",
              "**新guardはPASS**", "153→154 tests")), ("- **独立レビューround 5(tranche 3p、2026-08-09):**", ("6a346baee9a995bacf707c9d65c8a77d9d237479", "4890707358", "Blocker 2件",
              "`self.rows_by_id[...]`という直接syntaxをover-pinしていた", "`rows = self.rows_by_id`", "**無害な同値refactor**", "semantic markerへ解決",
              "harmless local aliasを許容", "**fixpoint反復**", "**local変数名は——rowのものもregistry aliasのものも——contractにしていない。",
              "**A(harmless alias)**", "**B(semantic RHS swap)**", "**C(既存local rename)**", "**新guardがFAIL**",
              "per-round Post-correction stateが1 roundずれていた", "historical factsは変更していない", "round 5ではtest件数は増減しておらず")),
            ("- **検証(tranche 3p):**", ("`test_source_usage_policy.py` 36 tests OK(source無変更)",
              "`test_document_test_classification.py` 154 OK", "1231件", "shards 5", "shard004単体成功", "BL-038 record-sync(`test_fetch.py`全体)397 OK", "full unittest 2149 OK",
              "`f3c28245…`", "全shard 600行以下(base 596／shard001 268／shard002 112／shard003 154／shard004 148)")), ):
            record = next(l for l in lines if l.startswith(prefix))
            for required in requirements:
                with self.subTest(record=prefix[:34], required=required): self.assertIn(required, record)

    def test_status_line_carries_the_tranche3o_closeout_and_tranche3p_scope(self):
        status = self._status_bl038_line()
        for required in ("**tranche 3o最終受入・merge・Pages(2026-08-09 JST):**", "entry 36", "raw `ok`", "表示上の`「」`は原文の一部ではない", "**GitHub上の順序**",
            "**final acceptance reviewはReady化より後**", "4890126614", "4890302399", "31282229621", self.ACCEPTED_HEAD_3O, self.ACCEPTED_MERGE, "**signature verified／valid**", "31289348799",
            "**手動Pages・`workflow_dispatch`はいずれも未実施**", "**これによりtranche 1〜3oはいずれも受入済みとなった。**", "**tranche 3p着手(2026-08-09):**", self.BRANCH, "entry 37", "raw `はい`",
            "**候補再測定(tranche 3p):**", "**11 methods／124 assertions**", "**32 methods／140 assertions**", "**140 > 124で後者が一意のwinner、tieなし。単独150超のmethodは0件でstop findingなし。**",
            "**選択・分類(tranche 3p):**", "**2件目のmethod-range scope、かつどのshardも未scopeだったclassへの初適用**", "**A 2／B 80／C 50／D 8(total 140)**", "**A 2は実測根拠つき**",
            "既存1091件とのfingerprint collisionは**0件**", "既存entryは1件も変更していない", "**shard allocation(tranche 3p):**", "001→19件、002→18件、003→13件、新規`_004`→12件",
            "**4つの既存accepted shardをすべてbyte-identicalに保てる唯一の選択肢**", TRANCHE_3P_SHARD_004_SHA, "combined **1231・A 30／B 487／C 539／D 175**",
            "**guard・mutation(tranche 3p):**", "130→142", "**23件**", "**protection gap**",
            "**独立レビューround 5(2026-08-09):**", "over-pin", "**fixpoint反復**", "**local変数名は非contractのまま、blanket AST digestなし**",
            "**A(alias)は140 IDs／fingerprints／literals不変で新guard PASS、B(semantic RHS swap)は同じく全不変のまま新guard FAIL、C(既存rename)はPASS**",
            "per-round Post-correction stateが1 roundずれていた", "**残り(post-3q):**", "tail **4 methods／37 assertions**", "tail **9 methods／133 assertions**",
            "**次trancheのcandidateは必ずlatest sourceから再測定すること。**", "**tranche 3qは最終受入・merge・自動Pagesまで完了**", "BL-038全体は未完了", ):
            with self.subTest(required=required): self.assertIn(required, status)
        for stale in ("**tranche 3oは未受入**", "tranche 3pは受入済み", "BL-038は完了"):
            with self.subTest(stale=stale): self.assertNotIn(stale, status)

    def test_current_residual_work_line_reflects_tranche3p(self):
        residual = re.search(r"^- \*\*残作業:\*\* .*$", self._bl038_section(), re.MULTILINE).group(0)
        for required in ("tranche 3pの50件", "次trancheの候補再測定・着手", "**`test_source_usage_policy.py::SourceUsagePolicyTest`のtail 4 methods・37 assertions**",
                "tranche 3pはprefix 32 methods・140件のみを分類し、tailには着手していない", "**`test_security_requirements.py::SecurityRequirementsTest`のtail 9 methods・133 assertions**",
                "tranche 3qで11 methods・124 assertionsを分類済み。残り9 methods・133 assertions", "**次trancheのcandidateはtranche 3nのselection ruleでその時点のlatest source上から必ず再測定すること**",
                "記録値を優先しない", "既存accepted shardをbyte-identicalに保てる唯一の選択肢として`_004`を選んだ", "shard004 148/600行", "tranche 3p 2件", "tranche 1〜3qは受入済み",
                "tranche 3qはPR #99で最終受入・merge・自動Pagesまで完了"):
            with self.subTest(required=required): self.assertIn(required, residual)
        for stale in ("tranche 3oのDraft PR独立レビュー", "tranche 3oは実装中"):
            with self.subTest(stale=stale): self.assertNotIn(stale, residual)

    def test_repository_state_matches_the_recorded_second_method_range(self):
        """The numbers the record claims are the numbers on disk: a fifth shard
        holding exactly the window, four frozen shards, and a combined 1231."""
        from collections import Counter

        raw = (self.ROOT / self.SHARDS[4]).read_bytes()
        text = raw.decode("utf-8")
        shard = json.loads(text)
        self.assertEqual((hashlib.sha256(raw).hexdigest(), len(text.splitlines()), len(shard["assertions"])), (TRANCHE_3P_SHARD_004_SHA, 148, 140))
        self.assertLessEqual(len(text.splitlines()), 600)
        self.assertEqual(shard["scope"], [{"file": self.SOURCE_FILE, "classes": [self.CLASS], "method_range": {"start": TRANCHE_3P_RANGE[0], "end": TRANCHE_3P_RANGE[1]}}])
        self.assertEqual(dict(Counter(e["category"] for e in shard["assertions"])), {"A": 2, "B": 80, "C": 50, "D": 8})
        self.assertEqual({e["action"] for e in shard["assertions"] if e["category"] == "C"}, {"refactor_later"})
        self.assertEqual({e["action"] for e in shard["assertions"] if e["category"] == "A"}, {"keep"})
        self.assertEqual({(e["file"], e["class"]) for e in shard["assertions"]}, {(self.SOURCE_FILE, self.CLASS)})
        self.assertEqual(len({e["method"] for e in shard["assertions"]}), 32)
        # The four accepted shards are byte-identical, and the index gained one.
        self.assertEqual(tuple(hashlib.sha256((self.ROOT / n).read_bytes()).hexdigest() for n in self.SHARDS[:4]), TRANCHE_3P_FROZEN_SHAS)
        index = json.loads((self.ROOT / "document_test_classification_index.json").read_text(encoding="utf-8"))
        self.assertEqual(index["shards"][:5], list(self.SHARDS))
        self.assertNotIn("document_test_classification_005.json", self.SHARDS)
        total = [e for n in self.SHARDS for e in json.loads((self.ROOT / n).read_text(encoding="utf-8"))["assertions"]]
        self.assertEqual((len(total), len({e["id"] for e in total})), (1231, 1231))
        self.assertEqual(dict(Counter(e["category"] for e in total)), {"A": 30, "B": 487, "C": 539, "D": 175})
        # Neither the selected source test nor its targets moved.
        source = (self.ROOT / self.SOURCE_FILE).read_text(encoding="utf-8")
        self.assertIn(f"class {self.CLASS}(unittest.TestCase):", source)
        for document, marker in (("SOURCE_USAGE_POLICY.md", "## 4. Source-by-source audit matrix"), ("source_definitions.json", '"sources"')):
            with self.subTest(document=document): self.assertIn(marker, (self.ROOT / document).read_text(encoding="utf-8"))


class Bl038Tranche3qRecordSyncTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.backlog = (Path(__file__).resolve().parent / "BACKLOG.md").read_text(encoding="utf-8")
        cls.status = (Path(__file__).resolve().parent / "STATUS.md").read_text(encoding="utf-8")
        start = cls.backlog.index("## BL-038")
        end = cls.backlog.find("\n## ", start + 8)
        cls.bl038 = cls.backlog[start:] if end < 0 else cls.backlog[start:end]

    def test_current_state_and_user_history_are_synced(self):
        state = next(line for line in self.bl038.splitlines() if line.startswith("- **状態:**"))
        self.assertIn("3p・3q・3r・3s・3t受入済み／document・static-contract assertion classificationは全件分類済み", state)
        history = self.bl038[self.bl038.index("ユーザー原文の履歴"):self.bl038.index("着手時ユーザー原文:")]
        self.assertIn("「ok」19回", history)
        self.assertIn("「はい」12回", history)
        entries = re.findall(r"^\s*(\d+)\.\s+(.*?)(?=^\s*\d+\.\s|\Z)", history, re.MULTILINE | re.DOTALL)
        self.assertEqual([n for n, _ in entries], [str(i) for i in range(1, 48)])
        e38 = next(text for n, text in entries if n == "38")
        e39 = next(text for n, text in entries if n == "39")
        e40 = next(text for n, text in entries if n == "40")
        e41 = next(text for n, text in entries if n == "41")
        e42 = next(text for n, text in entries if n == "42")
        for token in ("tranche 3p final acceptance original", "`ok`", "PR #98", "cf1cb2ab", "4890795812", "4890815821", "31300179831"):
            self.assertIn(token, e38)
        for token in ("tranche 3q kickoff original", "`はい`", "latest main", "一意winner", "最終受入／Ready化／merge"):
            self.assertIn(token, e39)
        for token in ("tranche 3q continuation original", "`はい`", "bootstrap", "technical verification", "最終受入／Ready化／merge"):
            self.assertIn(token, e40)
        for token in ("tranche 3q final acceptance original", "`ok`", "PR #99", "275591e7", "4894000902", "4894940035", "31359746299", "806 changed lines"):
            self.assertIn(token, e41)
        for token in ("tranche 3r kickoff original", "`はい`", "latest main", "一意winner", "Draft PR", "最終受入／Ready化／merge"):
            self.assertIn(token, e42)

    def test_current_backlog_and_status_record_3q_evidence(self):
        for token in (
            "**124>37でAが一意winner、tieなし**", "**A 0／B 49／C 42／D 33**",
            "4eae57a35e144fd3480fba94a0f5e6ec9b32e3d757abb820238f75926809aac6",
            "combined **1355(A30/B536/C581/D208)**", "wide-span masking", "124 fingerprints不変のままguard FAIL",
            "B 3件", "Cはmeaning-preserving reword 2件", "D 3件", "full unittest 2163 OK",
            "独立レビューround 1(tranche 3q", "4893945240", "Blocker 3件", "entry 40", "unittest.main()", "31358989984",
            "独立レビューround 2(tranche 3q", "4893982010", "matching group 0件", "fingerprint collision 2組", "tranche 3q最終受入(2026-08-10 JST)", "4894940035", "tranche 3q closeout(2026-08-10 JST)", "0c0300b3b5208175adb8ef4ea987804b0374aa24", "31371275732",
            "tail **9 methods／133 assertions**", "tail **4 methods／37 assertions**",
        ):
            with self.subTest(token=token):
                self.assertIn(token, self.bl038)
        for token in ("entry 38 raw `ok`", "entry 39 raw `はい`", "**1355・A30/B536/C581/D208**", "full unittest **2163 OK**", "**独立レビューround 1(2026-08-10):**", "4893945240", "31359415777", "**独立レビューround 2(2026-08-10):**", "4893982010", "matching group **0件**", "**tranche 3q最終受入(2026-08-10):**", "4894940035", "**残り(post-3q):**", "**tranche 3qは最終受入・merge・自動Pagesまで完了**", "**tranche 3r着手(2026-08-10):**", "**tranche 3rは最終受入済み。PR #100のReady化・通常merge承認済み／受入記録CI後にmergeする。**"):
            with self.subTest(token=token):
                self.assertIn(token, self.status)

    def test_repository_state_matches_current_record(self):
        index = json.loads((Path(__file__).resolve().parent / "document_test_classification_index.json").read_text(encoding="utf-8"))
        self.assertEqual(index["shards"][-1], "document_test_classification_007.json")
        self.assertEqual(len(index["shards"]), 8)
        entries = []
        for name in index["shards"]:
            entries.extend(json.loads((Path(__file__).resolve().parent / name).read_text(encoding="utf-8"))["assertions"])
        self.assertEqual((len(entries), len({e["id"] for e in entries})), (1525, 1525))
        self.assertEqual({cat: sum(1 for e in entries if e["category"] == cat) for cat in ("A", "B", "C", "D")}, {"A": 30, "B": 612, "C": 638, "D": 245})
        shard = json.loads((Path(__file__).resolve().parent / "document_test_classification_005.json").read_text(encoding="utf-8"))
        self.assertEqual(len(shard["assertions"]), 124)
        self.assertEqual({cat: sum(1 for e in shard["assertions"] if e["category"] == cat) for cat in ("A", "B", "C", "D")}, {"A": 0, "B": 49, "C": 42, "D": 33})


class Bl038Tranche3rRecordSyncTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        root = Path(__file__).resolve().parent
        cls.backlog = (root / "BACKLOG.md").read_text(encoding="utf-8")
        cls.status = (root / "STATUS.md").read_text(encoding="utf-8")
        start = cls.backlog.index("## BL-038")
        end = cls.backlog.find("\n## ", start + 8)
        cls.bl038 = cls.backlog[start:] if end < 0 else cls.backlog[start:end]
        cls.root = root

    def test_3q_closeout_and_3r_kickoff_are_recorded_without_over_authorization(self):
        for token in ("tranche 3q closeout(2026-08-10 JST)", "4b970c75", "0c0300b3", "signature verified／valid", "31371275732", "10 files／814 changed lines",
                      "tranche 3r kickoff original(2026-08-10)", "entry 42 raw `はい`", "tranche 3r着手・候補再測定", "133 > 37、tieなし"):
            with self.subTest(token=token): self.assertIn(token, self.bl038)
        self.assertIn("3p・3q・3r・3s・3t受入済み／document・static-contract assertion classificationは全件分類済み", self.bl038)
        self.assertNotIn("／tranche 3r実装中", self.bl038)
        for token in ("tranche 3r final acceptance original(2026-08-10)", "entry 43", "raw `ok`", "014c0b48d6b19cd5339a60f369bf7bd1fd92cf50", "4895868311", "31379567027", "10 files／481 changed lines"):
            with self.subTest(token=token): self.assertIn(token, self.bl038)

    def test_3r_classification_binding_and_remaining_work_are_recorded(self):
        for token in ("**A 0／B 60／C 37／D 36**", "fingerprint collisionは22件", "category conflictは0件", "document_test_classification_006.json",
                      "**1488(A30/B596/C618/D244)**", "SecurityRequirementsTest`は3rにより全39 methods", "wide-span masking", "2171 tests OK"):
            with self.subTest(token=token): self.assertIn(token, self.bl038)
        for token in ("独立レビューround 1(tranche 3r", "4895738881", "Blocker 2件", "matching group 0件", "alias-tolerant semantic section boundary guard", "full unittest 2175 OK"):
            with self.subTest(token=token): self.assertIn(token, self.bl038)
        for token in ("**tranche 3r着手(2026-08-10):**", "**1488・A30/B596/C618/D244**", "**独立レビューround 1(2026-08-10):**", "4895738881", "full unittest **2175 OK**", "**残り(post-3r):**", "**tranche 3rは最終受入済み。PR #100のReady化・通常merge承認済み／受入記録CI後にmergeする。**"):
            with self.subTest(token=token): self.assertIn(token, self.status)

    def test_live_index_matches_the_recorded_post_3r_totals(self):
        index = json.loads((self.root / "document_test_classification_index.json").read_text(encoding="utf-8"))
        self.assertEqual(len(index["shards"]), 8)
        self.assertEqual(index["shards"][-1], "document_test_classification_007.json")
        shard = json.loads((self.root / "document_test_classification_006.json").read_text(encoding="utf-8"))
        self.assertEqual(len(shard["assertions"]), 133)
        self.assertEqual({c: sum(e["category"] == c for e in shard["assertions"]) for c in ("A","B","C","D")}, {"A":0,"B":60,"C":37,"D":36})
        all_entries = [e for name in index["shards"] for e in json.loads((self.root / name).read_text(encoding="utf-8"))["assertions"]]
        self.assertEqual((len(all_entries), len({e["id"] for e in all_entries})), (1525,1525))
        self.assertEqual({c: sum(e["category"] == c for e in all_entries) for c in ("A","B","C","D")}, {"A":30,"B":612,"C":638,"D":245})


class Bl038Tranche3sAcceptanceRecordTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = Path(__file__).resolve().parent
        cls.backlog = (cls.root / "BACKLOG.md").read_text(encoding="utf-8")
        cls.status = (cls.root / "STATUS.md").read_text(encoding="utf-8")
        start = cls.backlog.index("## BL-038")
        end = cls.backlog.find("\n## ", start + 8)
        cls.bl038 = cls.backlog[start:] if end < 0 else cls.backlog[start:end]

    def test_user_history_keeps_kickoff_conditional_ok_and_continuation_distinct(self):
        history = self.bl038[self.bl038.index("ユーザー原文の履歴"):self.bl038.index("着手時ユーザー原文:")]
        self.assertIn("「ok」19回", history)
        self.assertIn("「はい」12回", history)
        self.assertIn("「うん。進めて」1回", history)
        entries = re.findall(r"^\s*(\d+)\.\s+(.*?)(?=^\s*\d+\.\s+|\Z)", history, re.MULTILINE | re.DOTALL)
        self.assertEqual([n for n, _ in entries], [str(i) for i in range(1, 48)])
        e44 = next(body for n, body in entries if n == "44")
        e45 = next(body for n, body in entries if n == "45")
        e46 = next(body for n, body in entries if n == "46")
        self.assertIn("tranche 3s kickoff original", e44)
        self.assertIn("`うん。進めて`", e44)
        self.assertIn("tranche 3s final acceptance authorization original", e45)
        self.assertIn("`ok`", e45)
        self.assertIn("すべてgreenにできた場合に限り", e45)
        self.assertIn("tranche 3s continuation original", e46)
        self.assertIn("`はい`", e46)
        self.assertIn("`ok`へ読み替えず", e46)

    def test_final_acceptance_evidence_and_scope_are_recorded(self):
        for token in (
            "tranche 3r closeout(2026-08-10 JST)",
            "cf9a6d74a7a453ee0c28d7fd27385dbfb8b9e7b9",
            "31392417301",
            "tranche 3s着手・候補再測定(2026-08-10)",
            "**4 methods／37 assertions**",
            "**A 0／B 16／C 20／D 1**",
            "24674dbc4707baa94782428a4600cd1addd920dcddf0960aa137b0080e33d441",
            "**1525(A30/B612/C638/D245)**",
            "8d66082861f274454300cd0941e5a0ab050a9e69",
            "31450770842",
            "4902388560",
            "未解決review thread 0",
            "tranche 3s最終受入(2026-08-11 JST)",
            "classification tailは0",
        ):
            with self.subTest(token=token):
                self.assertIn(token, self.bl038)
        self.assertIn("Category C source conversion", self.bl038)
        self.assertIn("Category A helper consolidation", self.bl038)
        self.assertNotIn("BL-038全体最終受入済み", self.bl038)

    def test_status_matches_the_acceptance_record_without_over_authorization(self):
        for token in (
            "tranche 3s final acceptance (2026-08-11 JST)",
            "entry 45 raw `ok`",
            "8d660828",
            "31450770842",
            "4902388560",
            "classification tailは0",
            "entry 46 raw `はい`",
            "Category C source conversion",
            "BL-038全体完了",
        ):
            with self.subTest(token=token):
                self.assertIn(token, self.status)

    def test_live_index_is_fully_classified_at_accepted_3s_totals(self):
        index = json.loads((self.root / "document_test_classification_index.json").read_text(encoding="utf-8"))
        self.assertEqual(len(index["shards"]), 8)
        self.assertEqual(index["shards"][-1], "document_test_classification_007.json")
        entries = [
            entry
            for name in index["shards"]
            for entry in json.loads((self.root / name).read_text(encoding="utf-8"))["assertions"]
        ]
        self.assertEqual((len(entries), len({entry["id"] for entry in entries})), (1525, 1525))
        self.assertEqual(
            {c: sum(entry["category"] == c for entry in entries) for c in ("A", "B", "C", "D")},
            {"A": 30, "B": 612, "C": 638, "D": 245},
        )
        failures, summary = dti.validate_indexed_manifests(root=self.root)
        self.assertEqual([failure.format() for failure in failures], [])
        self.assertEqual((summary["unclassified"], summary["stale"], summary["fingerprint_mismatch"]), (0, 0, 0))


class Bl038Tranche3tHistoryFoundationRecordSyncTest(unittest.TestCase):
    """BL-038 tranche 3t: the Category A closeout, the accepted-history foundation and
    the explicit scope boundary (Category C still blocked) are recorded in the
    repository's canonical documents, and the offline ledger agrees with them."""

    @classmethod
    def setUpClass(cls):
        cls.root = Path(__file__).resolve().parent
        cls.backlog = (cls.root / "BACKLOG.md").read_text(encoding="utf-8")
        cls.status = (cls.root / "STATUS.md").read_text(encoding="utf-8")
        start = cls.backlog.index("## BL-038")
        end = cls.backlog.find("\n## ", start + 8)
        cls.bl038 = cls.backlog[start:] if end < 0 else cls.backlog[start:end]
        cls.ledger = json.loads(
            (cls.root / "document_test_classification_history.json").read_text(encoding="utf-8"))

    def test_category_a_closeout_is_recorded_as_decided_without_consolidation(self):
        for token in (
            "tranche 3t着手・Category A再監査(2026-08-11 JST)",
            "83b7ab1ae59ca0a246142ee2e8b1d2c7eb6cf7e8",
            "**7 helper family**",
            "**Category A helper consolidationは追加実装なしで判断完了**",
            "CNAME survival 6", "no-wildcard-DNS 2", "SD-030 vs SD-002 4",
            "workflow action pinning 6", "SourceUsagePolicy (mode,column) 2",
            "historical independence", "InventoryError",
            "**Category C 638件はsource conversion未着手**",
        ):
            with self.subTest(token=token):
                self.assertIn(token, self.bl038)
        self.assertNotIn("BL-038全体最終受入済み", self.bl038)

    def test_the_history_foundation_and_the_split_decision_are_recorded(self):
        for token in (
            "tranche 3t(classification history foundation、2026-08-11)",
            "document_test_classification_history.json",
            "document_test_history.py",
            "LEDGER_DIGEST",
            "**historical evidence値は1つも書き換えていない。**",
            "12 record",
            "Round 1",
            "assertion-level freeze",
            "index-slice coupling",
            "cap例外は採用せず分割",
            "tranche 3t初版の追記方法が持ち込んだもの",
            "5557行中5556行目",
            "tranche 3u",
            "Category C source conversionはtranche 3t後も引き続きblocked",
        ):
            with self.subTest(token=token):
                self.assertIn(token, self.bl038)
        for token in (
            "BL-038 tranche 3t (classification history foundation, 2026-08-11 JST)",
            "Category A helper consolidationは判断完了・追加実装なし",
            "Category C source conversionは未着手・未unblock",
            "tranche 3u",
        ):
            with self.subTest(status_token=token):
                self.assertIn(token, self.status)
        # Never claimed: the things tranche 3t does NOT deliver. Checked as affirmative
        # phrases -- "BL-038完了" alone appears legitimately inside a NEGATING sentence
        # elsewhere in STATUS.md ("これはBL-038完了を意味せず"), so a bare substring test
        # would be measuring the wrong thing.
        for over_claim in ("Category C conversion fully unblocked", "migration lifecycle完成",
                           "BL-038全体最終受入済み", "Category C 638件をunblock済み",
                           "Category C source conversion開始"):
            with self.subTest(not_claimed=over_claim):
                self.assertNotIn(over_claim, self.bl038)
                self.assertNotIn(over_claim, self.status)
        self.assertIn("「Category C 638件をunblockした」とは記録しない", self.bl038)

    def test_the_planned_tranche_3u_scope_is_recorded(self):
        for token in ("tranche 3uのplanned scope", "23", "migration ledger",
                      "1対1 conversion", "identity-changing conversion",
                      "nested accepted window", "silent deletion",
                      "wip/bl038-tranche3t-round1-full"):
            with self.subTest(token=token):
                self.assertIn(token, self.bl038)

    def test_every_ledger_record_is_anchored_in_the_backlog_acceptance_record(self):
        self.assertEqual(len(self.ledger["accepted"]), 12)
        for record in self.ledger["accepted"]:
            with self.subTest(tranche=record["tranche"]):
                self.assertIn(record["historical"]["sha256"], self.backlog)
                self.assertIn(record["merge_commit"], self.bl038)

    def test_the_ledger_is_offline_and_pinned_and_the_migration_ledger_is_empty(self):
        module = (self.root / "document_test_history.py").read_text(encoding="utf-8")
        for token in ("subprocess", "urllib", "requests", "socket", "os.system"):
            with self.subTest(token=token):
                self.assertNotIn(token, module)
        digest = hashlib.sha256(json.dumps(self.ledger, ensure_ascii=False, sort_keys=True,
                                           separators=(",", ":")).encode("utf-8")).hexdigest()
        self.assertIn(f'LEDGER_DIGEST = "{digest}"', module)
        self.assertIn(digest, (self.root / "test_document_test_classification.py")
                      .read_text(encoding="utf-8"))
        # Tranche 3t shipped no migration ledger; tranche 3u introduces it, empty,
        # because 3u fixes the engine contract without converting anything.
        self.assertEqual(json.loads((self.root / "document_test_classification_migrations.json")
                                    .read_text(encoding="utf-8")),
                         {"schema_version": 1, "migrations": []})

    def test_the_current_residual_paragraph_states_the_post_3s_merge_state(self):
        """Final-review Blocker 1: the CURRENT `残作業` paragraph still said PR #101's
        Ready/merge was yet to happen, contradicting the tranche 3s record in the same
        ticket. Scoped deliberately to the slice BEFORE the
        `historical post-3r residual snapshot` marker: the snapshot below it keeps its
        older values on purpose and must NOT be dragged forward."""
        start = self.bl038.index("- **残作業:** assertion classification自体は完了し、")
        marker = "**historical post-3r residual snapshot"
        end = self.bl038.index(marker, start)
        current = self.bl038[start:end]
        for stale in ("PR #101のReady化・mergeはこれから",
                      "Ready化・mergeはこれから行う",
                      "PR #101のReady化・mergeは未了"):
            with self.subTest(stale=stale):
                self.assertNotIn(stale, current)
        for fact in ("tranche 1〜3sはいずれも最終受入済み",
                     "83b7ab1ae59ca0a246142ee2e8b1d2c7eb6cf7e8",
                     "merge済みである",
                     "Category C 638件はsource conversion未着手",
                     # BL-038 tranche 3v: the 4-PR split moved the boundary from 3v to 3y.
                     "**Category Cのunblockはtranche 3y acceptance後**",
                     "Category A 30件はtranche 3tで判断完了",
                     "BL-038全体は未完了"):
            with self.subTest(fact=fact):
                self.assertIn(fact, current)
        # The marker itself must stay, since it is what bounds the current slice -- but
        # this guard deliberately asserts NOTHING about the wording or the values below
        # it. That snapshot is history and a later tranche may restate it.
        self.assertIn(marker + "（現在の未分類残件を意味しない）", self.bl038)
        self.assertLess(start, end)

    def test_the_technical_acceptance_record_never_claims_a_github_approve(self):
        """The tranche 3t technical acceptance record states Accept/Blocker 0 AND that no
        GitHub APPROVE review exists, because the reviewer connector authenticates as the
        PR author and GitHub refuses self-approval. Guards the two prohibitions: no
        fabricated review ID, and no claim that an independent GitHub APPROVE exists."""
        for record in (self.bl038, self.status):
            for fact in ("5226bbc56e46bdaa433d0717954db1d395a92930",
                         "Accept／Blocker 0", "31472464106", "757 changed lines",
                         "Review Can not approve your own pull request"):
                with self.subTest(fact=fact):
                    self.assertIn(fact, record)
        self.assertIn("**GitHub上のAPPROVE reviewは存在しない**", self.bl038)
        self.assertIn("架空のreview IDを記録しない", self.bl038)
        # No review id may be attributed to tranche 3t. GitHub review ids are 10-digit
        # numbers; the only long digit runs allowed near this record are the CI run id
        # and the accepted head, so check the 3t acceptance sentence itself.
        start = self.bl038.index("- **tranche 3t technical acceptance(2026-08-11 JST")
        end = self.bl038.index("\n- **", start + 10)
        sentence = self.bl038[start:end]
        allowed = {"31472464106"}
        # Pin the accepted facts inside the SENTENCE, not merely somewhere in the
        # section: a wrong run id here would otherwise be masked by the correct one in
        # STATUS.md.
        for fact in ("5226bbc56e46bdaa433d0717954db1d395a92930", "31472464106",
                     "757 changed lines", "2205 OK", "12 record"):
            with self.subTest(in_sentence=fact):
                self.assertIn(fact, sentence)
        found = set(re.findall(r"\b\d{9,10}\b", sentence)) - allowed
        self.assertEqual(found, set(), f"unexplained review-id-like number(s): {found}")
        # Only unambiguous markers of a real review OBJECT are forbidden. A substring
        # like "independent APPROVE" appears inside this record's own DENIAL
        # ("GitHub上のindependent APPROVEが存在するとは記録しない"), so blacklisting it
        # would measure the wrong thing -- the same mistake the current-residual guard
        # avoids for the historical snapshot.
        for object_marker in ("pullrequestreview", "#pullrequestreview-"):
            with self.subTest(no_review_object=object_marker):
                self.assertNotIn(object_marker, sentence)
        self.assertIn("GitHub上のindependent APPROVEが存在するとは記録しない", sentence)
        # And the record must not pretend this is merge authorization.
        self.assertIn("Ready化・mergeは未実施", sentence)
        self.assertIn("merge承認ではない", sentence)

    def test_the_post_merge_state_of_tranche_3t_is_recorded(self):
        """Post-merge record sync. Pins the merge facts inside the closeout BULLET (not
        merely somewhere in the section -- several of these SHAs and ids legitimately
        appear more than once, so a section-wide check would let a wrong value hide
        behind a correct one) and asserts the pre-merge wording cannot return to the
        CURRENT slice. Scoped before the `historical post-3r residual snapshot` marker:
        historical wording legitimately describes a Draft/unmerged past."""
        marker = "**historical post-3r residual snapshot"
        current = self.bl038[:self.bl038.index(marker)]
        head = "- **tranche 3t最終受入・merge・Pages(2026-08-11 JST):**"
        self.assertIn(head, current)
        bullet = current[current.index(head):]
        bullet = bullet[:bullet.index("\n- **")]
        # Exact phrasings, each of which encodes one fact uniquely.
        for fact in (
            "merge commit **`dfa5df2c859ee353b531d0d9f8ed080d28a62377`**",
            "final technical accepted head `5226bbc56e46bdaa433d0717954db1d395a92930`",
            "acceptance-record head `a0ccf723e496dc8c1a6a056606ebe5fd854aa0fc`",
            "parent 1 = merge直前main `83b7ab1ae59ca0a246142ee2e8b1d2c7eb6cf7e8`",
            "parent 2 = `a0ccf723e496dc8c1a6a056606ebe5fd854aa0fc`",
            "parent 2個の真のmerge commit",
            "**通常のmerge commit方式**", "squash・rebase mergeは使用していない",
            "signature **verified=true／reason valid**", "PR state **MERGED**",
            "**803 changed lines**",
            "[run 31473501774](https://github.com/matkei31/security-digest/actions/runs/31473501774)",
            "full unittest **2206 OK**",
            "**1525件・A30/B612/C638/D245・unclassified/stale/fingerprint mismatch 0/0/0**",
            "accepted-history ledger **12 record**",
            "[run 31474158474](https://github.com/matkei31/security-digest/actions/runs/31474158474)",
            "`pages build and deployment`", "event **`dynamic`**",
            "**手動Pages実行ではなく`workflow_dispatch`でもない**",
            "`workflow_dispatch` runは0件",
            "**production fetchは実行していない**",
            "**Category C 638件はsource conversion未着手で引き続きblocked**",
            "unblockはtranche 3v acceptance後", "migration lifecycleは未完成",
            "**BL-038全体は未完了**",
            "**supersededとしてclose**", "entry 47(`tranche 3t kickoff original`)",
        ):
            with self.subTest(fact=fact):
                self.assertIn(fact, bullet)
        # No OTHER 40-hex commit may be presented as this merge commit.
        for wrong in re.findall(r"merge commit \*\*`([0-9a-f]{40})`\*\*", bullet):
            with self.subTest(merge_commit=wrong):
                self.assertEqual(wrong, "dfa5df2c859ee353b531d0d9f8ed080d28a62377")
        # tranche 3t must read as merged, not as an open Draft, anywhere in current.
        for stale in ("はDraftのままで、Ready化・mergeは未了", "現在実装中のtranche 3t",
                      "tranche 3tのReady化・mergeはこれから"):
            with self.subTest(stale=stale):
                self.assertNotIn(stale, current)
        self.assertIn("tranche 3t([PR #103](https://github.com/matkei31/security-digest/pull/103)"
                      "、classification history foundation)も最終受入済み", current)
        for token in ("`dfa5df2c859ee353b531d0d9f8ed080d28a62377`", "`31474158474`",
                      "workflow_dispatch 0件", "**BL-038全体未完了。**"):
            with self.subTest(status_token=token):
                self.assertIn(token, self.status)

    def test_entry_47_preserves_the_real_utterance_under_canonical_naming(self):
        """Blocker 1. The raw `はい` recorded only in the closed PR #102 is a real user
        utterance and must survive; the `tranche 4a` label it carried was branch/work
        naming, not the user's words, so it must not become a canonical role name."""
        history = self.bl038[self.bl038.index("ユーザー原文の履歴"):
                             self.bl038.index("着手時ユーザー原文:")]
        entries = re.findall(r"^\s*(\d+)\.\s+(.*?)(?=^\s*\d+\.\s+|\Z)",
                             history, re.MULTILINE | re.DOTALL)
        self.assertEqual([n for n, _ in entries], [str(i) for i in range(1, 48)])
        e47 = next(body for n, body in entries if n == "47")
        self.assertIn("**tranche 3t kickoff original(2026-08-11):**", e47)
        self.assertIn("`はい`", e47)
        self.assertNotIn("`ok`", e47.split("原文`はい`を`ok`へ読み替えず")[0])
        self.assertIn("canonical **tranche 3t**", e47)
        # The old label may be explained, but only as a rejected non-canonical naming.
        self.assertIn("`tranche 4a`", e47)
        self.assertIn("canonical role名としては採用しない", e47)
        # ...and never as an entry's own role.
        self.assertNotIn("**tranche 4a kickoff original", history)
        # Entry 47 grants nothing.
        for not_approved in ("最終受入・Ready化・merge承認ではなく",
                             "Category C source conversion", "tranche 3u implementation",
                             "BL-038全体完了", "`workflow_dispatch`", "手動Pages"):
            with self.subTest(not_approved=not_approved):
                self.assertIn(not_approved, e47)
        # Tally: only 「はい」 moved, and it moved to 12.
        self.assertIn("「ok」19回・「おk」7回・「次へ進めて」1回・「次へ」2回・「はい」12回・"
                      "「進んで」1回・「うん」1回・「うん。進めて」1回", history)
        self.assertNotIn("「はい」11回", history)
        # Every other raw-utterance tally is untouched by this change.
        for unchanged in ("「ok」19回", "「おk」7回", "「次へ進めて」1回", "「次へ」2回",
                          "「進んで」1回", "「うん」1回", "「うん。進めて」1回"):
            with self.subTest(unchanged=unchanged):
                self.assertIn(unchanged, history)

    def test_the_top_level_state_line_reflects_the_category_a_decision(self):
        """Blocker 2. Category A's consolidation question is decided, so the summary must
        not still list it as outstanding work alongside Category C."""
        line = next(l for l in self.bl038.splitlines() if l.startswith("- **状態:**"))
        for fact in ("3s・3t受入済み",
                     "document・static-contract assertion classificationは全件分類済み",
                     "**Category A helper consolidation要否判断はtranche 3tで完了し、"
                     "追加helper consolidationは実施しない**",
                     "Category C source conversionとBL-038全体最終受入は未完了"):
            with self.subTest(fact=fact):
                self.assertIn(fact, line)
        # The old phrasing listed Category A as an incomplete task; it must not return.
        for stale in ("Category C source conversion・Category A helper consolidation・BL-038全体最終受入は未完了",
                      "Category A helper consolidation・BL-038全体最終受入は未完了"):
            with self.subTest(stale=stale):
                self.assertNotIn(stale, line)

    def test_current_totals_are_unchanged_by_the_foundation_tranche(self):
        """3t converts nothing and consolidates nothing, so the live classification is
        bit-for-bit the accepted tranche 3s result."""
        failures, summary = dti.validate_indexed_manifests(root=self.root)
        self.assertEqual([failure.format() for failure in failures], [])
        self.assertEqual(summary["inventoried_assertions"], 1525)
        self.assertEqual(summary["category_counts"], {"A": 30, "B": 612, "C": 638, "D": 245})
        self.assertEqual((summary["unclassified"], summary["stale"],
                          summary["fingerprint_mismatch"]), (0, 0, 0))
        self.assertIn("**1525件・A30/B612/C638/D245・unclassified/stale/fingerprint mismatch 0/0/0**",
                      self.bl038)



class Bl038Tranche3uMigrationEngineRecordSyncTest(unittest.TestCase):
    """BL-038 tranche 3u: the engine scope, the corrected coupling measurement, and the
    standing boundary (Category C stays blocked until 3v) are recorded as facts."""

    @classmethod
    def setUpClass(cls):
        cls.root = Path(__file__).resolve().parent
        cls.backlog = (cls.root / "BACKLOG.md").read_text(encoding="utf-8")
        cls.status = (cls.root / "STATUS.md").read_text(encoding="utf-8")
        start = cls.backlog.index("## BL-038")
        end = cls.backlog.find("\n## ", start + 8)
        cls.bl038 = cls.backlog[start:] if end < 0 else cls.backlog[start:end]

    def test_the_engine_scope_and_corrected_measurement_are_recorded(self):
        for token in ("tranche 3u(migration engine foundation、2026-08-11)",
                      "fbb49e547b2bfadf88d040ae1b9253a83b300e53",
                      "**約67件**",
                      "**25はSHA/digest/known positional familyの実測件数であり、coupling universeではない。**",
                      "responsibility migrationはtranche 3vのscope",
                      "live - successors + retired == accepted",
                      "`(file, class, method, targets)`",
                      "pure ordinal driftはmigration metadata不要",
                      "ACCEPTED_RANGE_METHODS", "3p/3sのように同一classを異なるrangeで分割",
                      "current indexed manifests全体",
                      "exactly 1件実在し、file/class/method/targetsが一致すること",
                      "historical locatorに留め",
                      "**real Category C conversionは0件**"):
            with self.subTest(token=token):
                self.assertIn(token, self.bl038)

    def test_the_engine_verification_and_the_3v_boundary_are_recorded(self):
        for token in ("tranche 3u検証(2026-08-11)",
                      "nonexistent successor id(`assert-99`、contract一致)",
                      "true nested whole-class windows", "disjoint same-class method ranges",
                      "boundary method消失のfail closed", "re-shard",
                      "**3uがgreenでもCategory C 638件はunblockedとして扱わない**",
                      "tranche 3vのacceptance条件"):
            with self.subTest(token=token):
                self.assertIn(token, self.bl038)
        for token in ("BL-038 tranche 3u (migration engine foundation, 2026-08-11 JST)",
                      "**約67件**", "Blocker 1修正", "Blocker 2修正",
                      "**3uがgreenでもCategory Cはunblockedとしない**", "tranche 3v"):
            with self.subTest(status_token=token):
                self.assertIn(token, self.status)
        for over_claim in ("migration-aware current lifecycle complete",
                           "all coupled guards retargeted", "Category C unblocked",
                           "positional coupling eliminated"):
            with self.subTest(not_claimed=over_claim):
                self.assertNotIn(over_claim, self.bl038)
                self.assertNotIn(over_claim, self.status)

    def test_the_current_slice_never_says_3u_unblocks_category_c(self):
        """Round 2 Blocker 3. The current `残作業` paragraph said the unblock was in
        tranche 3u's scope, contradicting the same paragraph's 3v statement. Scoped to
        the text BEFORE the `historical post-3r residual snapshot` marker, so wording
        that legitimately described tranche 3u at the time is not policed there."""
        marker = "**historical post-3r residual snapshot"
        current = self.bl038[:self.bl038.index(marker)]
        for stale in ("unblockはtranche 3uの範囲",
                      "unblockはtranche 3uのscope",
                      "Category Cのunblockはtranche 3u",
                      # BL-038 tranche 3v: the 4-PR split superseded the 3v promise too.
                      "Category Cのunblockはtranche 3v acceptance後",
                      "3v acceptanceまでunblocked扱いにしない"):
            with self.subTest(stale=stale):
                self.assertNotIn(stale, current)
        self.assertIn("**Category Cのunblockはtranche 3y acceptance後**", current)
        self.assertIn("tranche 3uはmigration engine foundationのみを確定", current)

    def test_category_c_is_still_unconverted_and_the_ledgers_agree(self):
        """3u fixes the engine without converting anything: the tree is still the
        accepted 3s classification, with an empty migration ledger."""
        failures, summary = dti.validate_indexed_manifests(root=self.root)
        self.assertEqual([f.format() for f in failures], [])
        self.assertEqual(summary["inventoried_assertions"], 1525)
        self.assertEqual(summary["category_counts"], {"A": 30, "B": 612, "C": 638, "D": 245})
        self.assertEqual((summary["unclassified"], summary["stale"],
                          summary["fingerprint_mismatch"]), (0, 0, 0))
        self.assertEqual(dth.load_migrations(self.root),
                         {"schema_version": 1, "migrations": []})
        self.assertEqual(dth.migration_shape_failures(self.root), [])
        self.assertEqual(dth.successor_reference_failures(self.root), [])
        self.assertEqual(hashlib.sha256(
            (self.root / "document_test_classification_history.json").read_bytes()).hexdigest(),
            "763637f1d88e6690363f8d30cc66a5cb76d95d654cd789c8863e6e26d604028a")

class Bl038Tranche3vCouplingRetargetRecordSyncTest(unittest.TestCase):
    """BL-038 tranche 3v: the frozen 106-candidate measurement, the 23-row scope actually
    handled, the residual split and the moved Category C unblock boundary are recorded as
    facts -- including the one measurement false negative, recorded rather than absorbed."""

    @classmethod
    def setUpClass(cls):
        cls.root = Path(__file__).resolve().parent
        cls.backlog = (cls.root / "BACKLOG.md").read_text(encoding="utf-8")
        cls.status = (cls.root / "STATUS.md").read_text(encoding="utf-8")
        start = cls.backlog.index("## BL-038")
        end = cls.backlog.find("\n## ", start + 8)
        cls.bl038 = cls.backlog[start:] if end < 0 else cls.backlog[start:end]

    def test_the_frozen_measurement_and_tranche_split_are_recorded(self):
        for token in ("tranche 3v(coupling retarget、first groups、2026-08-12)",
                      "22af028435f759077b6b4d6352dda35afc5d88de",
                      "106 distinct test methods",
                      "document_test_coupling_inventory_3v.json",
                      "**3v 23件・3w 38件・3x 27件・3y 18件**",
                      "**rewrite 21件・remove_obsolete 2件**"):
            with self.subTest(token=token):
                self.assertIn(token, self.bl038)

    def test_the_residual_split_is_recorded_without_claiming_repo_wide_success(self):
        """Round 1 Blocker 1: the frozen-inventory residual and the KNOWN residual are
        different numbers, because one out-of-inventory false negative is already known.
        The docs must state both and must not present 106 as a complete coupling
        universe in the present tense."""
        # The tranche 3v paragraph keeps ITS OWN accounting (83 + 1 = 84); the current
        # 残作業 paragraph moves on as later tranches land, and is checked separately by
        # the tranche 3w guard.
        for token in ("**frozen-inventory residual 83＋known false-negative correction 1＝"
                      "known residual at least 84**",
                      "**final repo-wide residual scanは未実施**",
                      "**repo-wide coupling eliminatedではない**"):
            with self.subTest(token=token):
                self.assertIn(token, self.bl038)
        self.assertIn("frozen-inventory residual 83＋known false-negative 1＝known residual "
                      "at least 84", self.status)
        self.assertIn("**final repo-wide scanは未実施**", self.status)
        self.assertIn("repo-wide coupling eliminatedではない", self.status)
        # The snapshot must not be described as a live tracker.
        self.assertIn("**CURRENT state trackerではない**", self.status)
        # Round 2: the CURRENT 残作業 paragraph must not leave a bare residual figure
        # standing as the total. "frozen-inventory residual 83" is correct and stays
        # allowed; an unqualified "residual 83" as the whole story does not.
        current = self.bl038[self.bl038.rindex("- **残作業:**"):]
        self.assertNotIn("future residual 83", current)
        self.assertNotIn("実施済み、residual 83", current)
        for bare in ("residual 83)", "residual 83。", "residual 83、"):
            with self.subTest(bare=bare):
                self.assertNotIn(bare, current)
        self.assertIn("**frozen 18＋known correction 1でknown work at least 19**", current)
        self.assertIn("**final repo-wide residual scanは未実施**", current)
        # The qualified planning-context phrasing is legitimate and must remain.
        self.assertIn("frozen-inventory residual 83", self.bl038)
        for text in (self.bl038, self.status):
            with self.subTest():
                self.assertNotIn("**3v residual 0／future residual 83**", text)

    def test_the_c021_classification_error_is_recorded_as_correction_3v_2(self):
        """Round 1 Blocker 2: C021 was planned H5/H6 mixed/rewrite but is actually H7-A
        remove_obsolete. Recorded as a correction; the frozen row is not rewritten, and
        planned 21/2 stays distinguishable from the actual 20/3."""
        for token in ("correction `3v-2`",
                      "**H7-A／whole method remove_obsolete**",
                      "**actual結果はrewrite 20件・remove_obsolete 3件**",
                      "planning時点で**rewrite 21件・remove_obsolete 2件**",
                      "population／group／trancheの変更は0"):
            with self.subTest(token=token):
                self.assertIn(token, self.bl038)
        self.assertIn("**actual rewrite 20／remove 3**", self.status)
        snapshot = json.loads((self.root / "document_test_coupling_inventory_3v.json")
                              .read_text(encoding="utf-8"))
        correction = {c["id"]: c for c in snapshot["corrections"]}["3v-2"]
        self.assertEqual(correction["population_change"], 0)
        c021 = {c["candidate_id"]: c for c in snapshot["candidates"]}["C021"]
        self.assertEqual(c021["keep_or_remove"], "rewrite")  # planning record intact
        self.assertEqual(snapshot["candidate_count"], 106)

    def test_the_planned_h7_a_plus_b_rows_are_named_precisely(self):
        """Round 1: the earlier "H7-A+B 2件(3h/3i)" wording was wrong. The planned pair is
        C012 (3h, tranche 3v) and C077 (3q, tranche 3x); only C012 is implemented here."""
        self.assertIn("**C012(3h、tranche 3v)とC077(3q、tranche 3x)**", self.bl038)
        self.assertIn("今回3vで実装したのは**C012のみ**", self.bl038)
        self.assertIn("**C012(3h/3v)とC077(3q/3x)**", self.status)
        for text in (self.bl038, self.status):
            with self.subTest():
                self.assertNotIn("H7-A+B 2件(3h/3i", text)

    def test_the_category_c_unblock_boundary_now_names_tranche_3y(self):
        self.assertIn("unblockはtranche 3y acceptance後", self.status)
        self.assertIn("Category Cのunblockはtranche 3y acceptance後", self.bl038)
        self.assertIn("real Category C conversion 0件", self.bl038)
        # The current-state text must not still promise an unblock at 3v.
        # The LAST 残作業 bullet is the current-state one; earlier ones are history.
        current = self.bl038[self.bl038.rindex("- **残作業:**"):]
        self.assertNotIn("tranche 3v acceptance後", current)
        self.assertNotIn("3v acceptanceまでunblocked扱いにしない", current)

    def test_the_measurement_false_negative_is_recorded_not_absorbed(self):
        for token in ("measurement definitionのfalse negative 1件を発見",
                      "test_tranche3h_shard_subset_survives_the_tranche3i_append",
                      "frozen 106 populationは指示どおり変更せず",
                      "correction `3v-1`"):
            with self.subTest(token=token):
                self.assertIn(token, self.bl038)
        snapshot = json.loads((self.root / "document_test_coupling_inventory_3v.json")
                              .read_text(encoding="utf-8"))
        self.assertEqual(snapshot["candidate_count"], 106)
        self.assertEqual(len(snapshot["known_false_negatives"]), 1)

    def test_the_representative_conversion_proof_is_recorded_and_restored(self):
        for token in ("tranche 3v representative conversion proof(2026-08-12)",
                      "**migration metadata 0**", "**tranche 3v candidate failure 0**",
                      "mutationは完全復元済み"):
            with self.subTest(token=token):
                self.assertIn(token, self.bl038)
        # Restored means restored: the ledgers are untouched and empty as before.
        migrations = json.loads((self.root / "document_test_classification_migrations.json")
                                .read_text(encoding="utf-8"))
        self.assertEqual(migrations["migrations"], [])


class Bl038Tranche3wCouplingRetargetRecordSyncTest(unittest.TestCase):
    """BL-038 tranche 3w: the 38-row shard002 scope, the actual disposition, the residual
    accounting after 3v+3w and the unchanged Category C boundary are recorded as facts."""

    @classmethod
    def setUpClass(cls):
        cls.root = Path(__file__).resolve().parent
        cls.backlog = (cls.root / "BACKLOG.md").read_text(encoding="utf-8")
        cls.status = (cls.root / "STATUS.md").read_text(encoding="utf-8")
        start = cls.backlog.index("## BL-038")
        end = cls.backlog.find("\n## ", start + 8)
        cls.bl038 = cls.backlog[start:] if end < 0 else cls.backlog[start:end]

    def test_the_scope_and_actual_disposition_are_recorded(self):
        for token in ("tranche 3w(shard002 coupling retarget、2026-08-12)",
                      "121f0a1ab1597723f5cf8c9d7c0fa9c8facab002",
                      "**C024〜C061の38 rowsのみ**",
                      "**rewrite 33件・remove_obsolete 5件**",
                      "**3w known G1 residual 0**"):
            with self.subTest(token=token):
                self.assertIn(token, self.bl038)
        self.assertIn("frozen **rewrite 33／remove 5**", self.status)

    def test_no_new_framework_was_added_and_the_ledgers_are_untouched(self):
        for token in ("新しいledger／snapshot／migration mechanism／分類体系は追加していない",
                      "**retroactive ledger追加は0件**", "**validatorは弱めていない**",
                      "**real Category C conversion 0件**"):
            with self.subTest(token=token):
                self.assertIn(token, self.bl038)
        snapshot = json.loads((self.root / "document_test_coupling_inventory_3v.json").read_text(encoding="utf-8"))
        self.assertEqual(snapshot["candidate_count"], 106)  # population untouched
        self.assertEqual([c["id"] for c in snapshot["corrections"]],
                         ["R0.1-1", "R0.1-2", "R0.1-3", "R0.2-1", "3v-1", "3v-2", "3w-1", "3w-2"])
        migrations = json.loads((self.root / "document_test_classification_migrations.json").read_text(encoding="utf-8"))
        self.assertEqual(migrations["migrations"], [])
        # Residual accounting after 3v+3w, stated in the CURRENT paragraph.
        current = self.bl038[self.bl038.rindex("- **残作業:**"):]
        self.assertIn("3v＋3wでfrozen 61件を実施済み", current)
        self.assertIn("**frozen-inventory residual 45にknown false-negative correction 1があり、"
                      "known residualはat least 46**", current)
        self.assertIn("**final repo-wide residual scanは未実施**", current)
        for bare in ("residual 45)", "residual 45。", "residual 45、"):
            with self.subTest(bare=bare):
                self.assertNotIn(bare, current)  # no bare figure as the total
        self.assertIn("known residual at least 46", self.status)

    def test_the_two_out_of_population_false_negatives_are_recorded_and_handled(self):
        """Round 1: two genuine H7-A couplings outside the frozen 106 were found and
        removed here, so the plan (33/5) and the implementation total (40 methods, 33/7)
        are distinct, and 3v-1 stays the only unresolved correction."""
        for token in ("**frozen 106 population外のgenuine H7-A false negativeを2件**",
                      "test_no_two_of_the_34_share_a_fingerprint",
                      "test_no_two_of_the_seventeen_share_a_fingerprint",
                      "**frozen C001〜C106 populationは変更せず**",
                      "**3w implementation total = 40 coupling methods handled"
                      "／rewrite 33・remove_obsolete 7**",
                      "unresolved known out-of-inventory correctionは**`3v-1`のみ**",
                      "8 prohibited shapeのcandidate-scope residual auditは**0 hits**"):
            with self.subTest(token=token):
                self.assertIn(token, self.bl038)
        self.assertIn("**3w implementation total 40 methods／rewrite 33・remove 7**", self.status)
        self.assertNotIn("新しいgenuine couplingの発見は0件", self.bl038)
        self.assertNotIn("新規coupling発見0", self.status)

    def test_the_conversion_proof_and_its_failure_buckets_are_recorded(self):
        for token in ("tranche 3w representative conversion proof(2026-08-12)",
                      "**migration metadata 0**",
                      "**3v handled rows failure 0・3w handled rows failure 0**",
                      "**other unexpected noncandidate failure 0**",
                      "couplingが解消したわけではなく、3yで対応する"):
            with self.subTest(token=token):
                self.assertIn(token, self.bl038)

    def test_category_c_is_still_blocked_until_tranche_3y(self):
        self.assertIn("**Category C 638件は引き続きblockedで、unblockはtranche 3y acceptance後。**", self.bl038)
        self.assertIn("unblockはtranche 3y acceptance後", self.status)


if __name__ == "__main__":
    unittest.main()
