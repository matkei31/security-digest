#!/usr/bin/env python3
"""Ticket 14a: Atom記事リンク選択(_select_atom_article_url / _parse_feed_items のAtom分岐)の
回帰テスト。外部HTTP通信は行わず、XML文字列とfixtureファイルだけを使う。

不具合: Atomの<link>は子要素を持たないため、現在のElement真偽値評価では
`find(...) or find(...)` の左辺がFalseとなり、意図したrel=alternateではなく先頭の
rel=repliesコメントフィードURLが記事URLとして選択されていた。"""

import unittest
import xml.etree.ElementTree as ET
from pathlib import Path
from unittest.mock import patch

import fetch

ATOM = "http://www.w3.org/2005/Atom"


def _entry(links_xml, title="T", published="2026-07-10T09:00:00Z"):
    feed = (f'<feed xmlns="{ATOM}"><entry>'
            f'<title type="text">{title}</title>'
            f'<published>{published}</published>'
            f'<updated>{published}</updated>'
            f'{links_xml}</entry></feed>')
    root = ET.fromstring(feed)
    return root.find("{%s}entry" % ATOM)


def _parse(links_xml):
    feed = (f'<feed xmlns="{ATOM}"><entry>'
            f'<title type="text">T</title><updated>2026-07-10T09:00:00Z</updated>'
            f'{links_xml}</entry></feed>')
    return fetch._parse_feed_items(ET.fromstring(feed), "Google TAG", "en")


class SelectAtomArticleUrlTest(unittest.TestCase):

    def test_6_1_comment_link_before_article(self):
        links = (
            '<link rel="replies" type="application/atom+xml" '
            'href="https://security.googleblog.com/feeds/123/comments/default"/>'
            '<link rel="alternate" type="text/html" '
            'href="https://security.googleblog.com/2026/07/example.html"/>'
        )
        self.assertEqual(
            fetch._select_atom_article_url(_entry(links)),
            "https://security.googleblog.com/2026/07/example.html",
        )

    def test_6_2_order_reversed_alternate_first(self):
        links = (
            '<link rel="alternate" type="text/html" href="https://x/article.html"/>'
            '<link rel="replies" type="application/atom+xml" href="https://x/feeds/1/comments/default"/>'
        )
        self.assertEqual(fetch._select_atom_article_url(_entry(links)), "https://x/article.html")

    def test_6_3_rel_unset_is_alternate(self):
        links = ('<link type="text/html" href="https://x/plain-article.html"/>'
                 '<link rel="replies" href="https://x/feeds/1/comments/default"/>')
        self.assertEqual(fetch._select_atom_article_url(_entry(links)),
                         "https://x/plain-article.html")

    def test_6_4_prefer_text_html_type(self):
        links = (
            '<link rel="self" type="application/atom+xml" href="https://x/self"/>'
            '<link rel="alternate" type="application/atom+xml" href="https://x/atomform"/>'
            '<link rel="alternate" type="text/html" href="https://x/real-article.html"/>'
        )
        self.assertEqual(fetch._select_atom_article_url(_entry(links)),
                         "https://x/real-article.html")

    def test_6_5_only_comment_link_returns_empty_and_skips(self):
        links = ('<link rel="replies" type="application/atom+xml" '
                 'href="https://security.googleblog.com/feeds/1/comments/default"/>')
        self.assertEqual(fetch._select_atom_article_url(_entry(links)), "")
        # _parse_feed_items はこのentryをスキップする(記事として残さない)。
        self.assertEqual(_parse(links), [])

    def test_6_6_self_hub_enclosure_not_selected(self):
        for rel in ("self", "hub", "enclosure", "license", "edit"):
            with self.subTest(rel=rel):
                links = f'<link rel="{rel}" type="text/html" href="https://x/{rel}-page"/>'
                self.assertEqual(fetch._select_atom_article_url(_entry(links)), "")

    def test_6_7_non_http_schemes_rejected(self):
        for bad in ("javascript:alert(1)", "file:///etc/passwd", "data:text/html,x"):
            with self.subTest(scheme=bad):
                links = f'<link rel="alternate" type="text/html" href="{bad}"/>'
                self.assertEqual(fetch._select_atom_article_url(_entry(links)), "")

    def test_6_7b_comment_feed_url_pattern_rejected(self):
        # rel=alternate を偽装していても /comments/default URLは選ばない。
        links = ('<link rel="alternate" type="text/html" '
                 'href="https://x/feeds/9/comments/default"/>')
        self.assertEqual(fetch._select_atom_article_url(_entry(links)), "")

    def test_6_8_rss_link_handling_unchanged(self):
        rss = ('<rss version="2.0"><channel><title>C</title>'
               '<item><title>A</title><link>https://example.com/article-1</link>'
               '<description>d</description>'
               '<pubDate>Fri, 10 Jul 2026 12:00:00 +0000</pubDate></item>'
               '</channel></rss>')
        items = fetch._parse_feed_items(ET.fromstring(rss), "Some RSS", "en")
        self.assertEqual(items[0]["link"], "https://example.com/article-1")

    def test_6_9_fixture_no_comment_default_in_selected_urls(self):
        fixture = Path(fetch.__file__).resolve().parent / "test_fixtures_google_tag_atom.xml"
        root = ET.fromstring(fixture.read_text(encoding="utf-8"))
        items = fetch._parse_feed_items(root, "Google TAG", "en")
        self.assertEqual(len(items), 3)
        for it in items:
            self.assertNotIn("/comments/default", it["link"])
            self.assertTrue(it["link"].startswith("https://security.googleblog.com/2026/07/"))
        # 各entryの記事URLが正しく選ばれていること。
        selected = {it["link"] for it in items}
        self.assertIn("https://security.googleblog.com/2026/07/ai-threats.html", selected)
        self.assertIn("https://security.googleblog.com/2026/07/rust-pixel-baseband.html", selected)


class InvalidEntrySkipTest(unittest.TestCase):
    """先頭にスキップ対象(コメントフィード等)があっても、後続の正常entryを
    確認して収集する(Ticket 14a)。BL-044でparse段階の件数上限(旧MAX_PER_FEED)は
    撤廃されたため、有効entryは打ち切られずすべて返る。"""

    def _feed(self):
        def art(slug):
            return (f'<entry><title>{slug}</title><updated>2026-07-10T09:00:00Z</updated>'
                    f'<link rel="alternate" type="text/html" href="https://x/{slug}.html"/>'
                    f'</entry>')
        comment_only = ('<entry><title>skip</title><updated>2026-07-10T09:00:00Z</updated>'
                        '<link rel="replies" type="application/atom+xml" '
                        'href="https://x/feeds/1/comments/default"/></entry>')
        return (f'<feed xmlns="{ATOM}">{comment_only}{art("A")}{art("B")}{art("C")}</feed>')

    def test_invalid_entries_are_skipped_without_truncating_valid_ones(self):
        # Ticket 14aの本来の意図(先頭の無効entryが後続の正常entryを潰さない)を
        # 維持しつつ、BL-044で parse段階の件数打ち切りが撤廃されたことを固定する。
        # 旧実装はMAX_PER_FEEDでparse段階を切っていたため、この検証は「上限まで
        # 集める」形だった。現在はparse段階に上限が無く、有効entryは全件返る。
        items = fetch._parse_feed_items(ET.fromstring(self._feed()), "Google TAG", "en")
        links = [it["link"] for it in items]
        # 先頭のコメントentryはスキップし、A・B・Cの3件すべてを集める。
        self.assertEqual(len(items), 3)
        self.assertEqual(
            links, ["https://x/A.html", "https://x/B.html", "https://x/C.html"]
        )
        self.assertFalse(
            any("comments" in link for link in links),
            "コメントフィードURLを記事URLとして採用してはいけない",
        )


class CommentFeedUrlHelperTest(unittest.TestCase):
    def test_comment_default_detected(self):
        self.assertTrue(fetch._is_comment_feed_url(
            "http://security.googleblog.com/feeds/820776653483778595/comments/default"))

    def test_feeds_and_comments_detected(self):
        self.assertTrue(fetch._is_comment_feed_url("https://host/feeds/1/comments/anything"))

    def test_normal_article_not_flagged(self):
        self.assertFalse(fetch._is_comment_feed_url(
            "https://security.googleblog.com/2026/07/ai-threats.html"))


if __name__ == "__main__":
    unittest.main()
