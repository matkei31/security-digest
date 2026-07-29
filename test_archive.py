#!/usr/bin/env python3
"""
日次バックナンバーとアーカイブ導線の回帰テスト (Ticket 9)。
標準ライブラリ unittest のみを使用する。
"""

import copy
import datetime
import json
import re
import tempfile
import unittest
from html.parser import HTMLParser
from pathlib import Path
from unittest import mock

import daily_json as dj
import fetch


JST = datetime.timezone(datetime.timedelta(hours=9))


class AnchorParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.anchors = []
        self.comments = []
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

    def handle_comment(self, data):
        self.comments.append(data)


def parse_anchors(html):
    parser = AnchorParser()
    parser.feed(html)
    return parser


class ArticleMetaParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.meta_by_url = {}
        self.article_urls = []
        self._in_card = False
        self._article_url = None
        self._article_meta = None
        self._meta_parts = None

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        classes = set((attrs.get("class") or "").split())
        if tag == "article" and "card" in classes:
            self._in_card = True
            self._article_url = None
            self._article_meta = None
            self._meta_parts = None
        elif self._in_card and tag == "a" and "article-title-link" in classes:
            self._article_url = attrs.get("href")
            if self._article_url:
                self.article_urls.append(self._article_url)
        elif self._in_card and tag == "p" and "article-meta" in classes:
            self._meta_parts = []

    def handle_data(self, data):
        if self._meta_parts is not None:
            self._meta_parts.append(data)

    def handle_endtag(self, tag):
        if tag == "p" and self._meta_parts is not None:
            self._article_meta = "".join(self._meta_parts).strip()
            self._meta_parts = None
        elif tag == "article" and self._in_card:
            if self._article_url and self._article_meta:
                self.meta_by_url[self._article_url] = self._article_meta
            self._in_card = False
            self._article_url = None
            self._article_meta = None
            self._meta_parts = None


def article_meta_for_url(html, url):
    parser = ArticleMetaParser()
    parser.feed(html)
    return parser.meta_by_url.get(url)


def source_footer_segment(html):
    start = html.index('<div class="sources">')
    end = html.index("</details>", start) + len("</details>")
    return html[start:end]


def make_digest(digest_date="2026-07-11", *, title="記事A", total_items=1, high_count=1):
    items = []
    for index in range(total_items):
        importance = "高" if index < high_count else "中"
        items.append({
            "id": f"id-{digest_date}-{index}",
            "source_id": "test_source",
            "source_name": "Test Source",
            "source_type": "報道・メディア",
            "source_tier": "Tier 2",
            "collection_method": "rss",
            "language": "ja",
            "url": f"https://example.com/{digest_date}/{index}",
            "canonical_url": f"https://example.com/{digest_date}/{index}",
            "published_at": f"{digest_date}T07:00:00+09:00",
            "fetched_at": f"{digest_date}T07:10:00+09:00",
            "title": f"{title}{index + 1}",
            "raw_title": f"Raw {title}{index + 1}",
            "raw_excerpt": "raw excerpt should not be rendered",
            "content_hash": f"hash-{index}",
            "rule_flags": [],
            "analysis": {
                "status": "success",
                "model": "gemini-2.5-flash",
                "prompt_version": "article-analysis-v2",
                "generated_at": f"{digest_date}T07:20:00+09:00",
                "category": "脆弱性・パッチ",
                "category_reason": "表示しないカテゴリ理由",
                "importance": importance,
                "urgency": "本日確認" if importance == "高" else "今週確認",
                "summary": f"{title}{index + 1}の要約",
                "financial_impact": f"{title}{index + 1}の金融影響",
                "recommended_actions": [f"{title}{index + 1}の確認事項"],
                "reason": f"{title}{index + 1}の重要情報理由",
                "tags": ["パッチ"],
                "error_type": None,
                "http_status": None,
            },
        })
    return {
        "schema_version": 1,
        "digest_date": digest_date,
        "generated_at": f"{digest_date}T07:30:00+09:00",
        "generator": {
            "application": "security-digest",
            "model": "gemini-2.5-flash",
            "article_prompt_version": "article-analysis-v2",
            "brief_prompt_version": "today-brief-v2",
        },
        "run": {
            "status": "success",
            "overwrite_policy": "replace",
            "total_items": total_items,
            "ai_attempted_count": total_items,
            "ai_success_count": total_items,
            "ai_fallback_count": 0,
            "ai_failed_count": 0,
            "ai_not_attempted_count": 0,
        },
        "counts": {
            "importance": {"高": high_count, "中": total_items - high_count, "低": 0, "未判定": 0},
            "urgency": {"本日確認": high_count, "今週確認": total_items - high_count, "参考": 0, "未判定": 0},
            "category": {k: 0 for k in dj.CATEGORY_VALUES} | {"脆弱性・パッチ": total_items, "未判定": 0},
        },
        "brief": {
            "status": "success",
            "model": "gemini-2.5-flash",
            "prompt_version": "today-brief-v2",
            "overview": f"{digest_date}の概況",
            "important_highlights": [f"{digest_date}のハイライト"],
            "discussion_points": [f"{digest_date}の論点"],
            "check_items": [f"{digest_date}の確認"],
            "error_type": None,
        },
        "items": items,
    }


def write_digest(data_dir, digest):
    path = Path(data_dir) / f"{digest['digest_date']}.json"
    path.write_text(json.dumps(digest, ensure_ascii=False, indent=2), encoding="utf-8")
    return path


class ArticleTimeNormalizationTest(unittest.TestCase):
    def test_aware_datetime_and_iso_offsets_normalize_to_same_jst_instant(self):
        expected = datetime.datetime(2026, 7, 18, 6, 20, 10, tzinfo=JST)
        cases = {
            "UTC aware datetime": datetime.datetime(
                2026, 7, 17, 21, 20, 10, tzinfo=datetime.timezone.utc
            ),
            "JST aware datetime": expected,
            "ISO Z": "2026-07-17T21:20:10Z",
            "ISO +00:00": "2026-07-17T21:20:10+00:00",
            "ISO +09:00": "2026-07-18T06:20:10+09:00",
        }

        for label, value in cases.items():
            with self.subTest(label=label):
                normalized = fetch.normalize_datetime_for_display(value)
                self.assertEqual(normalized, expected)
                self.assertEqual(normalized.isoformat(), "2026-07-18T06:20:10+09:00")
                self.assertEqual(fetch.format_article_meta_time({"date": value}), "07/18 06:20")

    def test_naive_datetime_keeps_wall_clock_without_timezone_inference(self):
        legacy = datetime.datetime(2026, 7, 18, 6, 20, 10)

        normalized = fetch.normalize_datetime_for_display(legacy)

        self.assertEqual(normalized, legacy)
        self.assertIsNone(normalized.tzinfo)
        self.assertEqual(
            fetch.format_article_meta_time({"date": "2026-07-18T06:20:10"}),
            "07/18 06:20",
        )

    def test_invalid_datetime_keeps_existing_empty_fallback(self):
        self.assertIsNone(fetch.parse_archive_datetime("not-a-date"))
        self.assertIsNone(fetch.normalize_datetime_for_display("not-a-date"))
        self.assertEqual(
            fetch.format_article_meta_time(
                {"published_at_jst": "not-a-date", "date": None}
            ),
            "",
        )

    def test_display_normalization_does_not_change_collection_cutoff_value(self):
        raw = "2026-07-17T21:20:10Z"
        collection_date = fetch.parse_date(raw)
        cutoff = datetime.datetime(2026, 7, 17, 22, 0, 0)
        accepted_before = collection_date >= cutoff
        item = {
            "date": collection_date,
            "published_at_jst": dj.parse_date_to_jst(raw),
        }

        self.assertEqual(fetch.format_article_meta_time(item), "07/18 06:20")
        self.assertEqual(collection_date, datetime.datetime(2026, 7, 17, 21, 20, 10))
        self.assertIsNone(collection_date.tzinfo)
        self.assertEqual(collection_date >= cutoff, accepted_before)
        self.assertFalse(accepted_before)

    def test_existing_daily_json_values_order_and_digest_date_are_unchanged(self):
        digest_path = Path(fetch.__file__).resolve().parent / "data" / "2026-07-18.json"
        original_bytes = digest_path.read_bytes()
        digest = fetch.load_daily_digest(digest_path)
        published_values = [item.get("published_at") for item in digest["items"]]
        digest_date = digest["digest_date"]
        items = fetch.digest_items_for_html(digest)
        expected_urls = [
            item["link"] for item in fetch.sort_items_for_display(items)
        ]

        html = fetch.build_html(items, fetch.brief_for_html_from_digest(digest))
        parser = ArticleMetaParser()
        parser.feed(html)

        self.assertEqual(parser.article_urls, expected_urls)
        self.assertEqual(
            [item.get("published_at") for item in digest["items"]],
            published_values,
        )
        self.assertEqual(digest["digest_date"], digest_date)
        self.assertEqual(digest_path.read_bytes(), original_bytes)


class ArchiveGenerationTest(unittest.TestCase):
    def test_existing_daily_json_article_time_matches_normal_generation_path(self):
        digest_path = Path(fetch.__file__).resolve().parent / "data" / "2026-07-18.json"
        digest = fetch.load_daily_digest(digest_path)
        article_url = (
            "https://thehackernews.com/2026/07/"
            "new-wp2shell-wordpress-core-flaw-lets.html"
        )
        entry = next(item for item in digest["items"] if item.get("url") == article_url)
        saved_published_at = entry["published_at"]
        published_at = fetch.parse_archive_datetime(saved_published_at)

        restored_item = next(
            item for item in fetch.digest_items_for_html(digest)
            if item.get("link") == article_url
        )
        normal_item = copy.deepcopy(restored_item)
        normal_item["date"] = (
            published_at.astimezone(datetime.timezone.utc).replace(tzinfo=None)
        )
        normal_item["published_at_jst"] = published_at.astimezone(JST)

        normal_meta = article_meta_for_url(fetch.build_html([normal_item]), article_url)
        restored_meta = article_meta_for_url(fetch.build_html([restored_item]), article_url)

        self.assertEqual(
            entry["title"],
            "New wp2shell WordPress Core Flaw Lets Unauthenticated Attackers Run Code",
        )
        self.assertEqual(saved_published_at, "2026-07-18T06:20:10+09:00")
        self.assertEqual(normal_item["date"], datetime.datetime(2026, 7, 17, 21, 20, 10))
        self.assertIsNone(normal_item["date"].tzinfo)
        self.assertEqual(
            normal_item["published_at_jst"],
            datetime.datetime(2026, 7, 18, 6, 20, 10, tzinfo=JST),
        )
        self.assertEqual(
            restored_item["date"],
            datetime.datetime(2026, 7, 18, 6, 20, 10, tzinfo=JST),
        )
        self.assertEqual(normal_item["date"].strftime("%m/%d %H:%M"), "07/17 21:20")
        self.assertEqual(restored_item["date"].strftime("%m/%d %H:%M"), "07/18 06:20")
        self.assertEqual(
            restored_item["date"].replace(tzinfo=None) - normal_item["date"],
            datetime.timedelta(hours=9),
        )
        self.assertEqual(
            normal_meta,
            restored_meta,
            "normal path date is UTC-naive while the JSON path retains +09:00; "
            f"normal={normal_item['date']!r}, published_at_jst="
            f"{normal_item['published_at_jst']!r}, restored={restored_item['date']!r}",
        )
        self.assertEqual(normal_meta, "The Hacker News ・ 07/18 06:20")

    def test_daily_archive_from_json_contains_expected_sections_and_omits_internal_fields(self):
        digest = make_digest(total_items=2, high_count=1)
        html = fetch.build_daily_archive_html(digest)

        self.assertIn("Monomi Digest", html)
        self.assertIn("日次ダイジェスト：2026年07月11日", html)
        self.assertIn("最終更新: 2026年07月11日 07:30", html)
        self.assertIn("本日の要点", html)
        self.assertNotIn("Today's Brief", html)
        self.assertNotIn("Today’s Brief", html)
        self.assertIn("本日のダッシュボード", html)
        self.assertIn("優先確認", html)
        self.assertNotIn("本日の重要情報", html)
        self.assertEqual(html.count('class="card"'), 2)
        self.assertLess(html.index("記事A1"), html.index("記事A2"))
        self.assertIn("記事A1の要約", html)
        self.assertIn("記事A1の金融影響", html)
        self.assertIn("記事A1の確認事項", html)
        self.assertIn("元記事を読む", html)
        cards = html[html.index('<div class="cards">'):]
        self.assertNotIn("表示しないカテゴリ理由", html)
        self.assertNotIn("raw excerpt should not be rendered", html)
        self.assertNotIn("content_hash", html)
        self.assertNotIn("error_type", html)
        self.assertNotIn("None", html)
        self.assertNotIn(">null<", html)
        self.assertNotIn("記事A1の重要情報理由", cards)

    def test_old_brief_and_missing_fields_are_compatible(self):
        digest = make_digest(total_items=2, high_count=1)
        digest["brief"] = {
            "status": "success",
            "model": "gemini-2.5-flash",
            "prompt_version": "executive-summary-v1",
            "overview": None,
            "important_highlights": ["旧形式ハイライト"],
            "discussion_points": [],
            "check_items": [],
            "error_type": None,
        }
        digest["items"][0]["analysis"]["category"] = "未判定"
        digest["items"][0]["analysis"]["urgency"] = "未判定"
        digest["items"][0]["analysis"]["tags"] = []
        digest["items"][1]["analysis"] = {"status": "failed"}
        del digest["items"][1]["raw_title"]

        html = fetch.build_daily_archive_html(digest)

        self.assertNotIn("旧形式ハイライト", html)
        self.assertIn("記事A2", html)
        self.assertEqual(html.count('class="card"'), 2)
        self.assertNotIn("None", html)
        self.assertNotIn(">null<", html)

    def test_v3_archive_with_evaluable_analysis_reconstructs_new_priority_heading(self):
        # BL-029: HTML描画はitems[].ai_analysisから常に重要・優先事項を再構成し、
        # 保存済みprompt_version(旧today-brief-v3)には依存しない。make_digest()の
        # 記事は有効なanalysisを持つため、旧v3タグのままでも新見出しへ移行する。
        digest = make_digest(total_items=2, high_count=1)
        digest["brief"]["prompt_version"] = "today-brief-v3"
        before = json.dumps(digest, ensure_ascii=False, sort_keys=True)

        html = fetch.build_daily_archive_html(digest)
        brief_html = html[html.index('<div class="todays-brief">'):html.index('<section class="important-items">')]

        self.assertIn('<h3 class="brief-section-title">重要・優先事項</h3>', brief_html)
        self.assertNotIn("本日の注目論点", brief_html)
        self.assertNotIn("金融機関との関連", brief_html)
        self.assertEqual(
            json.dumps(digest, ensure_ascii=False, sort_keys=True),
            before,
        )

    def test_extractive_archive_reconstructs_new_priority_heading(self):
        # BL-029: prompt_versionがtoday-brief-extractive-v1でも、items[].ai_analysis
        # から重要・優先事項を再構成する(バージョン非依存の再構成)。
        digest = make_digest(total_items=2, high_count=1)
        digest["brief"]["prompt_version"] = "today-brief-extractive-v1"

        html = fetch.build_daily_archive_html(digest)
        brief_html = html[html.index('<div class="todays-brief">'):html.index('<section class="important-items">')]

        self.assertIn('<h3 class="brief-section-title">重要・優先事項</h3>', brief_html)
        self.assertNotIn("本日の注目論点", brief_html)
        self.assertNotIn("金融機関との関連", brief_html)
        # article card自体の見出しとしては引き続き表示される
        self.assertIn("金融機関との関連", html)

    def test_internal_and_external_links_are_safe(self):
        digest = make_digest(total_items=1)
        digest["items"][0]["url"] = "javascript:alert(1)"
        digest["items"][0]["title"] = "<script>alert(1)</script>"
        digest["brief"]["overview"] = "<b>概要</b>"
        html = fetch.build_daily_archive_html(digest)
        parser = parse_anchors(html)

        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", html)
        self.assertIn("&lt;b&gt;概要&lt;/b&gt;", html)
        self.assertNotIn("javascript:alert(1)", html)
        article_links = [a for a in parser.anchors if a.get("class") in ("article-title-link", "article-source-link")]
        self.assertEqual(article_links, [])
        internal = [a for a in parser.anchors if a.get("class") == "archive-link"]
        # BL-028: the daily-archive global-nav link order is 過去→最新.
        self.assertEqual(
            [a.get("href") for a in internal],
            ["index.html", "../index.html", "index.html", "../index.html"],
        )
        self.assertTrue(all("target" not in a and "rel" not in a for a in internal))
        self.assertFalse(parser.nested_anchor)
        self.assertEqual(parser.comments, [])

    def test_daily_archive_all_items_uses_same_display_order_and_numbers_as_top(self):
        digest = make_digest(total_items=3, high_count=0)
        digest["items"][0]["title"] = "reference-high"
        digest["items"][0]["analysis"]["importance"] = "高"
        digest["items"][0]["analysis"]["urgency"] = "参考"
        digest["items"][1]["title"] = "today-low"
        digest["items"][1]["analysis"]["importance"] = "低"
        digest["items"][1]["analysis"]["urgency"] = "本日確認"
        digest["items"][2]["title"] = "week-high"
        digest["items"][2]["analysis"]["importance"] = "高"
        digest["items"][2]["analysis"]["urgency"] = "今週確認"

        archive_html = fetch.build_daily_archive_html(digest)
        top_html = fetch.build_html(fetch.digest_items_for_html(digest), fetch.brief_for_html_from_digest(digest))
        archive_cards = archive_html[archive_html.index('<div class="cards">'):archive_html.index('<div class="sources">')]
        top_cards = top_html[top_html.index('<div class="cards">'):top_html.index('<div class="sources">')]

        self.assertIn("確認目安、重要度、元の収集順で表示しています。", archive_html)
        self.assertLess(archive_cards.index("today-low"), archive_cards.index("week-high"))
        self.assertLess(archive_cards.index("week-high"), archive_cards.index("reference-high"))
        self.assertIn('<span class="article-index">1.</span>', archive_cards)
        self.assertIn('<span class="article-index">2.</span>', archive_cards)
        self.assertIn('<span class="article-index">3.</span>', archive_cards)
        self.assertNotIn("No. 1", archive_cards)
        self.assertEqual(archive_cards, top_cards)

    def test_priority_reason_label_rewrite_matches_top_and_archive(self):
        digest = make_digest(total_items=1, high_count=1)
        digest["items"][0]["analysis"]["reason"] = (
            "重要度は高い一方、脆弱性の重要度と重要度の高い脆弱性は一般表現です。"
        )

        archive_html = fetch.build_daily_archive_html(digest)
        top_html = fetch.build_html(fetch.digest_items_for_html(digest), fetch.brief_for_html_from_digest(digest))
        archive_important = archive_html[
            archive_html.index('<section class="important-items">'):archive_html.index('<section class="dashboard">')
        ]
        top_important = top_html[
            top_html.index('<section class="important-items">'):top_html.index('<section class="dashboard">')
        ]

        self.assertIn("重要度は高い", archive_important)
        self.assertNotIn("確認優先度", archive_important)
        self.assertIn("脆弱性の重要度", archive_important)
        self.assertIn("重要度の高い脆弱性", archive_important)
        self.assertEqual(archive_important, top_important)

    def test_brief_status_line_and_heading_match_between_top_and_archive(self):
        digest = make_digest(total_items=1, high_count=1)
        ctx = {
            "published_total": 5, "importance_high": 2,
            "urgency_today": 1, "urgency_week": 1, "unclassified": 0,
        }
        status_line = fetch.format_brief_status_line(ctx)
        digest["brief"]["overview"] = status_line + "\nGeminiによる本文です。"

        archive_html = fetch.build_daily_archive_html(digest)
        top_html = fetch.build_html(
            fetch.digest_items_for_html(digest), fetch.brief_for_html_from_digest(digest)
        )

        for html in (archive_html, top_html):
            self.assertIn("本日の要点", html)
            self.assertNotIn("Today's Brief", html)
            self.assertNotIn("Today’s Brief", html)
            self.assertIn(f'<p class="brief-status-line">{status_line}</p>', html)
            self.assertIn('<p class="brief-overview">Geminiによる本文です。</p>', html)
            # 改行自体は表示要素の外へ出ない(status lineとoverview本文の
            # HTMLエスケープ後テキストに"\n"が残らない)
            self.assertNotIn(f"{status_line}\n", html)

    def test_legacy_free_text_overview_is_filled_with_synthesized_status_line_in_archive(self):
        # BL-016 Blocker1: 決定論的状態行を持たない旧BRIEF(Ticket 15b以前、
        # 自由文のみのoverview)は、archive表示時に限り、保存済みitemsから
        # 記事単位判定で算出した状態行が補完される。overview文字列自体は
        # 変更しない。
        digest = make_digest(digest_date="2026-07-05", total_items=1, high_count=1)
        digest["brief"]["overview"] = "2026-07-05の概況"
        original_overview = digest["brief"]["overview"]

        html = fetch.build_daily_archive_html(digest)

        self.assertIn('<p class="brief-overview">2026-07-05の概況</p>', html)
        self.assertIn(
            '<p class="brief-status-line">掲載1件｜重要度「高」1件｜本日確認1件｜今週確認0件</p>',
            html,
        )
        # digest自体(overview文字列)は補完前後で変更されない
        self.assertEqual(digest["brief"]["overview"], original_overview)

    def test_unrecognized_overview_without_items_is_shown_in_full_without_status_line(self):
        # BL-016: digest.itemsがlist以外(不正)の場合はfail-openし、旧来どおり
        # 全文表示する。合成は記事単位の判定(digest.items由来)を前提とするため、
        # countsフィールドの有無ではなくitems自体の妥当性で判断する。
        digest = make_digest(digest_date="2026-07-05")
        digest["brief"]["overview"] = "2026-07-05の概況"
        digest["items"] = None

        html = fetch.build_daily_archive_html(digest)

        self.assertIn('<p class="brief-overview">2026-07-05の概況</p>', html)
        self.assertNotIn('<p class="brief-status-line">', html)

    def test_legacy_status_line_overview_converts_identically_in_top_and_archive(self):
        # BL-016: Ticket 15b/15c形式のoverviewを保持した過去archive再生成の
        # 回帰テスト。data/JSON側の文字列(件数・記事内容)は変更せず、表示側
        # だけが現行のラベルなし｜区切り形式へ変換され、トップページと
        # archiveで一致することを確認する。
        digest = make_digest(digest_date="2026-07-14", total_items=1, high_count=1)
        legacy_overview = (
            "本日の状態（掲載5件）：重要度「高」2件、確認目安「本日確認」1件、"
            "確認目安「今週確認」1件。Geminiによる本文です。"
        )
        digest["brief"]["overview"] = legacy_overview

        archive_html = fetch.build_daily_archive_html(digest)
        top_html = fetch.build_html(
            fetch.digest_items_for_html(digest), fetch.brief_for_html_from_digest(digest)
        )

        expected_status_line = "掲載5件｜重要度「高」2件｜本日確認1件｜今週確認1件"
        for html in (archive_html, top_html):
            self.assertNotIn("本日の状態", html)
            self.assertIn(f'<p class="brief-status-line">{expected_status_line}</p>', html)
            self.assertIn('<p class="brief-overview">Geminiによる本文です。</p>', html)
        self.assertEqual(archive_html.count(expected_status_line), top_html.count(expected_status_line))
        # digest自体(記事内容・件数・overview文字列)は変換前後で変更されない
        self.assertEqual(digest["brief"]["overview"], legacy_overview)


class LegacyStatusLineSynthesisTest(unittest.TestCase):
    """BL-016: synthesize_legacy_brief_status_line_from_digest()の記事単位判定
    テスト。is_article_evaluated()/compute_brief_trusted_context()と全く同じ
    「analysis.statusがsuccess/fallback、かつimportance・urgencyの両方が
    有効値の場合のみ判定済み。いずれか一方でも欠落・不正なら記事全体を
    未判定として扱う」という定義から外れないことを確認する。
    """

    def test_valid_importance_with_invalid_urgency_is_unclassified_not_high(self):
        digest = make_digest(total_items=1, high_count=1)
        digest["items"][0]["analysis"]["urgency"] = "不正な値"
        status_line = fetch.synthesize_legacy_brief_status_line_from_digest(digest)
        self.assertIn("重要度「高」0件", status_line)
        self.assertIn("未判定1件", status_line)

    def test_valid_urgency_with_invalid_importance_is_unclassified_not_today(self):
        digest = make_digest(total_items=1, high_count=0)
        digest["items"][0]["analysis"]["importance"] = "不正な値"
        digest["items"][0]["analysis"]["urgency"] = "本日確認"
        status_line = fetch.synthesize_legacy_brief_status_line_from_digest(digest)
        self.assertIn("本日確認0件", status_line)
        self.assertIn("未判定1件", status_line)

    def test_two_articles_each_invalid_on_different_axis_both_count_as_unclassified(self):
        digest = make_digest(total_items=2, high_count=0)
        digest["items"][0]["analysis"]["importance"] = "高"
        digest["items"][0]["analysis"]["urgency"] = "不正な値"
        digest["items"][1]["analysis"]["importance"] = "不正な値"
        digest["items"][1]["analysis"]["urgency"] = "本日確認"
        status_line = fetch.synthesize_legacy_brief_status_line_from_digest(digest)
        self.assertIn("未判定2件", status_line)
        self.assertIn("重要度「高」0件", status_line)
        self.assertIn("本日確認0件", status_line)

    def test_only_success_or_fallback_with_both_axes_valid_are_aggregated(self):
        digest = make_digest(total_items=3, high_count=1)
        # items[0]: success/高/本日確認(既定) → 集計対象
        digest["items"][1]["analysis"]["status"] = "fallback"  # 両軸有効のまま → 集計対象
        digest["items"][2]["analysis"]["status"] = "success"
        digest["items"][2]["analysis"]["importance"] = "不正な値"  # 無効 → 未判定
        status_line = fetch.synthesize_legacy_brief_status_line_from_digest(digest)
        self.assertIn("掲載3件", status_line)
        self.assertIn("未判定1件", status_line)

    def test_failed_and_not_attempted_status_are_unclassified(self):
        digest = make_digest(total_items=2, high_count=2)
        digest["items"][0]["analysis"]["status"] = "failed"
        digest["items"][1]["analysis"]["status"] = "not_attempted"
        status_line = fetch.synthesize_legacy_brief_status_line_from_digest(digest)
        self.assertIn("未判定2件", status_line)
        self.assertIn("重要度「高」0件", status_line)

    def test_existing_2026_07_archive_results_are_unchanged(self):
        # 記事単位判定への変更後も、実データ(2026-07-11/07-12/07-14)の
        # 合成結果が変わらないことを固定値で回帰確認する。
        for digest_date, expected in (
            ("2026-07-11", "掲載6件｜重要度「高」1件｜本日確認1件｜今週確認2件"),
            ("2026-07-12", "掲載3件｜重要度「高」1件｜本日確認1件｜今週確認1件"),
            ("2026-07-14", "掲載11件｜重要度「高」0件｜本日確認0件｜今週確認7件"),
        ):
            with self.subTest(digest_date=digest_date):
                digest = fetch.load_daily_digest(
                    Path(__file__).resolve().parent / "data" / f"{digest_date}.json"
                )
                self.assertEqual(
                    fetch.synthesize_legacy_brief_status_line_from_digest(digest),
                    expected,
                )


class ArchiveIndexAndPathTest(unittest.TestCase):
    def test_generate_archive_outputs_writes_daily_list_and_archive_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            data_dir = root / "data"
            docs_dir = root / "docs"
            data_dir.mkdir()
            write_digest(data_dir, make_digest("2026-07-10", title="past", total_items=0, high_count=0))
            write_digest(data_dir, make_digest("2026-07-11", title="today", total_items=2, high_count=1))
            dj.save_index(data_dir, datetime.datetime(2026, 7, 11, 8, 0, tzinfo=JST))

            summaries = fetch.generate_archive_outputs(data_dir, docs_dir, datetime.datetime(2026, 7, 11, 8, 0, tzinfo=JST))

            self.assertEqual([s["digest_date"] for s in summaries], ["2026-07-11", "2026-07-10"])
            self.assertTrue((docs_dir / "archive" / "2026-07-11.html").exists())
            self.assertTrue((docs_dir / "archive" / "2026-07-10.html").exists())
            index_html = (docs_dir / "archive" / "index.html").read_text(encoding="utf-8")
            self.assertLess(index_html.index("2026年07月11日"), index_html.index("2026年07月10日"))
            self.assertIn('href="2026-07-11.html"', index_html)
            self.assertIn("記事2件", index_html)
            self.assertIn("重要度 高1件", index_html)
            self.assertNotIn("本日の要点あり", index_html)
            self.assertNotIn("本日の要点なし", index_html)
            self.assertNotIn("Today's Brief", index_html)
            self.assertNotIn("Today’s Brief", index_html)
            self.assertNotIn("missing.html", index_html)
            self.assertEqual(index_html.count('<div class="archive-meta">'), 4)

            index_json = json.loads((data_dir / "index.json").read_text(encoding="utf-8"))
            dates = [d["digest_date"] for d in index_json["digests"]]
            self.assertEqual(dates, ["2026-07-11", "2026-07-10"])
            self.assertEqual(dates.count("2026-07-11"), 1)
            self.assertEqual(index_json["digests"][0]["total_items"], 2)
            self.assertEqual(index_json["digests"][0]["high_count"], 1)
            self.assertEqual(index_json["digests"][0]["archive_path"], "docs/archive/2026-07-11.html")

    def test_daily_navigation_uses_existing_dates_at_top_and_bottom(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            data_dir = root / "data"
            docs_dir = root / "docs"
            data_dir.mkdir()
            for digest_date in ("2026-07-10", "2026-07-12", "2026-07-15"):
                write_digest(data_dir, make_digest(digest_date))
            dj.save_index(data_dir, datetime.datetime(2026, 7, 15, 8, 0, tzinfo=JST))
            daily_before = {
                path.name: path.read_bytes()
                for path in data_dir.glob("????-??-??.json")
            }

            fetch.generate_archive_outputs(
                data_dir,
                docs_dir,
                datetime.datetime(2026, 7, 15, 8, 0, tzinfo=JST),
            )

            daily_after = {
                path.name: path.read_bytes()
                for path in data_dir.glob("????-??-??.json")
            }
            self.assertEqual(daily_after, daily_before)

            oldest_html = (docs_dir / "archive" / "2026-07-10.html").read_text(encoding="utf-8")
            middle_html = (docs_dir / "archive" / "2026-07-12.html").read_text(encoding="utf-8")
            latest_html = (docs_dir / "archive" / "2026-07-15.html").read_text(encoding="utf-8")

            for html in (oldest_html, middle_html, latest_html):
                self.assertEqual(html.count(">最新のダイジェスト</a>"), 2)
                self.assertEqual(html.count(">過去のダイジェスト</a>"), 2)
                self.assertEqual(
                    html.count('<div class="archive-nav-group archive-direction-nav">'),
                    2,
                )
                self.assertEqual(
                    html.count('<div class="archive-nav-group archive-global-nav">'),
                    2,
                )
                self.assertLess(
                    html.index('<div class="archive-nav-group archive-direction-nav">'),
                    html.index('<div class="archive-nav-group archive-global-nav">'),
                )
                parser = parse_anchors(html)
                internal_links = [
                    anchor for anchor in parser.anchors
                    if anchor.get("class") and "archive-link" in anchor["class"].split()
                ]
                self.assertTrue(
                    all("target" not in anchor and "rel" not in anchor for anchor in internal_links)
                )

            self.assertNotIn("archive-prev-link", oldest_html)
            self.assertEqual(oldest_html.count("archive-next-link"), 2)
            self.assertEqual(oldest_html.count(fetch.NEXT_DIGEST_LABEL), 2)
            self.assertIn('href="2026-07-12.html"', oldest_html)

            self.assertEqual(middle_html.count("archive-prev-link"), 2)
            self.assertEqual(middle_html.count("archive-next-link"), 2)
            self.assertEqual(middle_html.count(fetch.PREVIOUS_DIGEST_LABEL), 2)
            self.assertEqual(middle_html.count(fetch.NEXT_DIGEST_LABEL), 2)
            header_html = middle_html[:middle_html.index("</header>")]
            bottom_html = middle_html[middle_html.index('<nav class="archive-nav archive-bottom-nav"'):]
            for nav_html in (header_html, bottom_html):
                self.assertIn('href="2026-07-10.html"', nav_html)
                self.assertIn('href="2026-07-15.html"', nav_html)
            self.assertNotIn('href="2026-07-11.html"', middle_html)
            self.assertNotIn('href="2026-07-13.html"', middle_html)
            self.assertGreater(
                middle_html.index('<nav class="archive-nav archive-bottom-nav"'),
                middle_html.index('<div class="sources">'),
            )

            self.assertEqual(latest_html.count("archive-prev-link"), 2)
            self.assertNotIn("archive-next-link", latest_html)
            self.assertEqual(latest_html.count(fetch.PREVIOUS_DIGEST_LABEL), 2)
            self.assertIn('href="2026-07-12.html"', latest_html)

    def test_regenerating_archive_from_legacy_json_does_not_modify_source_json(self):
        # BL-016: 既存archive再生成の回帰テスト。旧形式のoverviewを含む
        # daily JSONファイルを再生成しても、ファイル自体のバイト列は
        # 一切変更されない(表示側だけが現行形式へ変換される)ことを確認する。
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            data_dir = root / "data"
            docs_dir = root / "docs"
            data_dir.mkdir()
            digest = make_digest("2026-07-14", title="legacy", total_items=1, high_count=1)
            legacy_overview = (
                "本日の状態（掲載9件）：重要度「高」1件、確認目安「本日確認」1件、"
                "確認目安「今週確認」2件。Geminiによる本文。"
            )
            digest["brief"]["overview"] = legacy_overview
            digest_path = write_digest(data_dir, digest)
            dj.save_index(data_dir, datetime.datetime(2026, 7, 14, 8, 0, tzinfo=JST))
            generated_at = datetime.datetime(2026, 7, 14, 8, 0, tzinfo=JST)
            # 実リポジトリの状態(archive_pathが既に生成済みhtmlを指している)を
            # 再現するため、まず一度生成してからbefore/afterを比較する。
            fetch.generate_archive_outputs(data_dir, docs_dir, generated_at)
            before_bytes = digest_path.read_bytes()
            before_index_bytes = (data_dir / "index.json").read_bytes()

            fetch.generate_archive_outputs(data_dir, docs_dir, generated_at)

            self.assertEqual(digest_path.read_bytes(), before_bytes)
            self.assertEqual((data_dir / "index.json").read_bytes(), before_index_bytes)

            archive_html = (docs_dir / "archive" / "2026-07-14.html").read_text(encoding="utf-8")
            self.assertNotIn("本日の状態", archive_html)
            self.assertIn(
                '<p class="brief-status-line">掲載9件｜重要度「高」1件｜本日確認1件｜今週確認2件</p>',
                archive_html,
            )

    def test_archive_summary_does_not_generate_brief_status(self):
        digest = make_digest("2026-07-12", title="none", total_items=1, high_count=0)
        digest["brief"] = {
            "status": "not_attempted",
            "model": None,
            "prompt_version": None,
            "overview": None,
            "important_highlights": [],
            "discussion_points": [],
            "check_items": [],
            "error_type": None,
        }
        summary = fetch.archive_summary_from_digest(digest)
        self.assertNotIn("brief_status", summary)

    def test_data_index_json_is_not_treated_as_daily_digest(self):
        with tempfile.TemporaryDirectory() as tmp:
            data_dir = Path(tmp) / "data"
            data_dir.mkdir()
            write_digest(data_dir, make_digest("2026-07-11"))
            (data_dir / "index.json").write_text(
                json.dumps({"digests": [{"digest_date": "2099-01-01"}]}),
                encoding="utf-8",
            )

            paths = [p.name for p in fetch.daily_digest_paths(data_dir)]

            self.assertEqual(paths, ["2026-07-11.json"])
            self.assertNotIn("index.json", paths)

    def test_same_day_rerun_overwrites_today_without_mixing_past(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            data_dir = root / "data"
            docs_dir = root / "docs"
            data_dir.mkdir()
            write_digest(data_dir, make_digest("2026-07-10", title="past", total_items=1, high_count=0))
            write_digest(data_dir, make_digest("2026-07-11", title="first", total_items=1, high_count=1))
            fetch.generate_archive_outputs(data_dir, docs_dir, datetime.datetime(2026, 7, 11, 8, 0, tzinfo=JST))

            write_digest(data_dir, make_digest("2026-07-11", title="second", total_items=1, high_count=1))
            fetch.generate_archive_outputs(data_dir, docs_dir, datetime.datetime(2026, 7, 11, 9, 0, tzinfo=JST))

            today_html = (docs_dir / "archive" / "2026-07-11.html").read_text(encoding="utf-8")
            past_html = (docs_dir / "archive" / "2026-07-10.html").read_text(encoding="utf-8")
            self.assertIn("second1", today_html)
            self.assertNotIn("first1", today_html)
            self.assertIn("past1", past_html)
            self.assertNotIn("second1", past_html)

    def test_invalid_past_json_is_skipped_without_breaking_valid_archives(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            data_dir = root / "data"
            docs_dir = root / "docs"
            data_dir.mkdir()
            write_digest(data_dir, make_digest("2026-07-10", title="valid"))
            dj.save_index(data_dir, datetime.datetime(2026, 7, 11, 8, 0, tzinfo=JST))
            existing = docs_dir / "archive" / "2026-07-11.html"
            existing.parent.mkdir(parents=True)
            existing.write_text("existing archive", encoding="utf-8")
            (data_dir / "2026-07-11.json").write_text("{ not valid json", encoding="utf-8")

            with mock.patch("builtins.print") as mocked_print:
                fetch.generate_archive_outputs(data_dir, docs_dir)

            warning_text = " ".join(str(call) for call in mocked_print.call_args_list)
            self.assertIn("2026-07-11.json", warning_text)
            self.assertTrue((docs_dir / "archive" / "2026-07-10.html").exists())
            self.assertEqual(existing.read_text(encoding="utf-8"), "existing archive")
            index_json = json.loads((data_dir / "index.json").read_text(encoding="utf-8"))
            by_date = {d["digest_date"]: d for d in index_json["digests"]}
            self.assertEqual(by_date["2026-07-10"]["archive_path"], "docs/archive/2026-07-10.html")
            self.assertNotIn("2026-07-11", by_date)

    def test_missing_digest_date_and_mismatched_filename_are_skipped(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            data_dir = root / "data"
            docs_dir = root / "docs"
            data_dir.mkdir()
            write_digest(data_dir, make_digest("2026-07-09", title="valid"))
            missing = make_digest("2026-07-10")
            del missing["digest_date"]
            (data_dir / "2026-07-10.json").write_text(
                json.dumps(missing, ensure_ascii=False), encoding="utf-8"
            )
            mismatched = make_digest("2026-07-12")
            (data_dir / "2026-07-11.json").write_text(
                json.dumps(mismatched, ensure_ascii=False), encoding="utf-8"
            )

            with mock.patch("builtins.print") as mocked_print:
                summaries = fetch.generate_archive_outputs(data_dir, docs_dir)

            warning_text = " ".join(str(call) for call in mocked_print.call_args_list)
            self.assertIn("2026-07-10.json", warning_text)
            self.assertIn("2026-07-11.json", warning_text)
            self.assertEqual([s["digest_date"] for s in summaries], ["2026-07-09"])
            self.assertTrue((docs_dir / "archive" / "2026-07-09.html").exists())
            self.assertFalse((docs_dir / "archive" / "2026-07-10.html").exists())
            self.assertFalse((docs_dir / "archive" / "2026-07-12.html").exists())

    def test_failed_archive_is_not_marked_as_successful_archive_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            data_dir = root / "data"
            docs_dir = root / "docs"
            data_dir.mkdir()
            write_digest(data_dir, make_digest("2026-07-11"))
            dj.save_index(data_dir, datetime.datetime(2026, 7, 11, 8, 0, tzinfo=JST))

            with mock.patch("fetch.atomic_write_text", side_effect=OSError("disk full")):
                with self.assertRaises(OSError):
                    fetch.generate_archive_outputs(data_dir, docs_dir)

            index_json = json.loads((data_dir / "index.json").read_text(encoding="utf-8"))
            self.assertIsNone(index_json["digests"][0]["archive_path"])


class ArchiveAtomicWriteTest(unittest.TestCase):
    def test_atomic_write_text_writes_readable_html_and_cleans_temp_on_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "page.html"
            fetch.atomic_write_text(path, "<!DOCTYPE html><html></html>", validator=fetch.validate_html_document)
            self.assertEqual(path.read_text(encoding="utf-8"), "<!DOCTYPE html><html></html>")

            original = path.read_text(encoding="utf-8")
            with mock.patch("fetch.os.replace", side_effect=OSError("replace failed")):
                with self.assertRaises(OSError):
                    fetch.atomic_write_text(path, "<!DOCTYPE html><html><body>broken</body></html>")

            self.assertEqual(path.read_text(encoding="utf-8"), original)
            self.assertEqual(list(Path(tmp).glob("*.tmp")), [])


class TopPageArchiveLinkTest(unittest.TestCase):
    def test_top_page_has_archive_index_link_without_external_attrs(self):
        html = fetch.build_html([], None)
        parser = parse_anchors(html)
        archive_links = [a for a in parser.anchors if a.get("href") == "archive/index.html"]

        self.assertEqual(len(archive_links), 1)
        self.assertIn(">過去のダイジェスト</a>", html)
        self.assertNotIn("過去のダイジェストを見る", html)
        self.assertTrue(all("target" not in a and "rel" not in a for a in archive_links))

    def test_previous_calendar_day_uses_unified_label_and_archive_url(self):
        html = fetch.render_top_archive_nav_html(
            "2026-07-23",
            ["2026-07-22", "2026-07-21"],
        )

        self.assertIn('href="archive/2026-07-22.html"', html)
        self.assertIn(fetch.PREVIOUS_DIGEST_LABEL, html)
        self.assertNotIn("前日のダイジェスト", html)
        self.assertNotIn("前回のダイジェスト", html)

    def test_missing_calendar_day_uses_latest_existing_date_and_unified_label(self):
        html = fetch.render_top_archive_nav_html(
            "2026-07-23",
            ["2026-07-19", "2026-07-21"],
        )

        self.assertIn('href="archive/2026-07-21.html"', html)
        self.assertIn(fetch.PREVIOUS_DIGEST_LABEL, html)
        self.assertNotIn("7/21", html)
        self.assertNotIn("前回のダイジェスト", html)

    def test_no_past_date_hides_direct_link_but_keeps_archive_index(self):
        html = fetch.render_top_archive_nav_html(
            "2026-07-23",
            ["2026-07-23", "2026-07-24"],
        )

        self.assertNotIn("← 前", html)
        self.assertIn('href="archive/index.html"', html)
        self.assertIn(">過去のダイジェスト</a>", html)
        # BL-028: with no direction link to show, the direction-nav group is
        # omitted entirely rather than rendered empty; the global-nav group
        # is promoted to the top.
        self.assertNotIn("archive-direction-nav", html)
        self.assertIn("archive-global-nav", html)

    def test_irregular_index_order_is_compared_by_date(self):
        self.assertEqual(
            fetch.select_previous_digest_date(
                "2026-07-23",
                ["2026-07-18", "2026-07-22", "2026-07-19", "2026-07-21"],
            ),
            "2026-07-22",
        )

    def test_current_future_and_invalid_dates_are_never_selected_or_injected(self):
        html = fetch.render_top_archive_nav_html(
            "2026-07-23",
            [
                "2026-07-23",
                "2026-07-24",
                '2026-07-22"><script>alert(1)</script>',
            ],
        )

        self.assertNotIn("<script>", html)
        self.assertNotIn("2026-07-24", html)
        self.assertEqual(html.count("<a "), 1)

    def test_navigation_wraps_and_does_not_enable_horizontal_scrolling(self):
        html = fetch.build_html(
            [],
            None,
            archive_nav_html=fetch.render_top_archive_nav_html(
                "2026-07-23",
                ["2026-07-22"],
            ),
        )

        # BL-028: PC and 390px share the same left-aligned two-row layout;
        # there is no longer a right-aligned single-row PC variant or a
        # mobile-only override that stretches groups to full width.
        self.assertIn(
            ".archive-nav{display:flex;flex-direction:column;"
            "align-items:flex-start;row-gap:8px;",
            html,
        )
        self.assertIn(".archive-nav-group{display:flex;", html)
        self.assertNotIn(
            ".archive-nav{display:flex;align-items:center;justify-content:space-between",
            html,
        )
        self.assertNotIn(".archive-global-nav{margin-left:auto}", html)
        self.assertNotIn(".archive-nav-group{width:100%}", html)
        self.assertNotIn(".archive-global-nav{margin-left:0}", html)
        self.assertIn("min-height:32px", html)
        self.assertNotIn(".archive-nav{white-space:nowrap", html)
        self.assertNotIn("overflow-x:scroll", html)
        self.assertNotIn("overflow-x:auto", html)
        self.assertNotIn("outline:none", html)
        self.assertNotIn("outline:0", html)

    def test_only_fully_validated_published_dates_are_loaded(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            data_dir = root / "data"
            docs_dir = root / "docs"
            archive_dir = docs_dir / "archive"
            data_dir.mkdir()
            archive_dir.mkdir(parents=True)

            valid_digest = make_digest("2026-07-22")
            for item in valid_digest["items"]:
                item["facts"] = {"cves": []}
            write_digest(data_dir, valid_digest)
            (archive_dir / "2026-07-22.html").write_text(
                "<!DOCTYPE html><html><body>valid</body></html>",
                encoding="utf-8",
            )
            missing_archive_digest = make_digest("2026-07-21")
            for item in missing_archive_digest["items"]:
                item["facts"] = {"cves": []}
            write_digest(data_dir, missing_archive_digest)
            wrong_path_digest = make_digest("2026-07-20")
            for item in wrong_path_digest["items"]:
                item["facts"] = {"cves": []}
            write_digest(data_dir, wrong_path_digest)
            (archive_dir / "2026-07-20.html").write_text(
                "<!DOCTYPE html><html><body>wrong path</body></html>",
                encoding="utf-8",
            )
            (data_dir / "index.json").write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "digests": [
                            {
                                "digest_date": "2026-07-21",
                                "archive_path": "docs/archive/2026-07-21.html",
                            },
                            {
                                "digest_date": "2026-07-20",
                                "archive_path": "docs/archive/not-the-date.html",
                            },
                            {
                                "digest_date": "2026-07-22",
                                "archive_path": "docs/archive/2026-07-22.html",
                            },
                        ],
                    }
                ),
                encoding="utf-8",
            )

            self.assertEqual(
                fetch.load_validated_published_digest_dates(data_dir, docs_dir),
                ["2026-07-22"],
            )

    def test_validated_digest_with_internal_date_mismatch_is_excluded(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            data_dir = root / "data"
            docs_dir = root / "docs"
            archive_dir = docs_dir / "archive"
            data_dir.mkdir()
            archive_dir.mkdir(parents=True)

            mismatched_digest = make_digest("2026-07-21")
            for item in mismatched_digest["items"]:
                item["facts"] = {"cves": []}
            (data_dir / "2026-07-22.json").write_text(
                json.dumps(mismatched_digest),
                encoding="utf-8",
            )
            (data_dir / "index.json").write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "digests": [
                            {
                                "digest_date": "2026-07-22",
                                "archive_path": "docs/archive/2026-07-22.html",
                            },
                        ],
                    }
                ),
                encoding="utf-8",
            )
            (archive_dir / "2026-07-22.html").write_text(
                "<!DOCTYPE html><html><body>published</body></html>",
                encoding="utf-8",
            )

            def load_without_filename_check(path):
                return json.loads(Path(path).read_text(encoding="utf-8"))

            with mock.patch(
                "fetch.load_daily_digest",
                side_effect=load_without_filename_check,
            ):
                self.assertEqual(
                    fetch.load_validated_published_digest_dates(data_dir, docs_dir),
                    [],
                )

    def test_main_uses_generated_date_for_top_daily_and_archive_across_midnight(self):
        fetched_at = datetime.datetime(2026, 7, 23, 23, 59, 59, tzinfo=JST)
        generated_at = datetime.datetime(2026, 7, 24, 0, 0, 1, tzinfo=JST)

        class CrossingMidnightDateTime(datetime.datetime):
            values = [fetched_at, generated_at]
            call_count = 0

            @classmethod
            def now(cls, tz=None):
                value = cls.values[cls.call_count]
                cls.call_count += 1
                return value

        def render_navigation(current_digest_date, published_dates):
            self.assertEqual(CrossingMidnightDateTime.call_count, 2)
            self.assertEqual(current_digest_date, "2026-07-24")
            self.assertEqual(published_dates, ["2026-07-23"])
            return '<nav class="archive-nav"></nav>'

        with tempfile.TemporaryDirectory() as tmp:
            docs_dir = Path(tmp) / "docs"
            with (
                mock.patch("fetch.DOCS_DIR", docs_dir),
                mock.patch("fetch.datetime.datetime", CrossingMidnightDateTime),
                mock.patch("fetch.collect_recent", return_value=[]),
                mock.patch("fetch.get_source_definition", return_value=None),
                mock.patch(
                    "fetch.vulnerability_facts.default_cache_path",
                    return_value=Path(tmp) / "facts-cache.json",
                ),
                mock.patch(
                    "fetch.vulnerability_facts.build_facts_for_items",
                    return_value={},
                ),
                mock.patch(
                    "fetch.vulnerability_facts.format_facts_log_summary",
                    return_value="facts",
                ),
                mock.patch("fetch.enrich_with_ai", return_value=[]),
                mock.patch(
                    "fetch.build_todays_brief",
                    return_value={"status": "not_attempted"},
                ),
                mock.patch(
                    "fetch.load_validated_published_digest_dates",
                    return_value=["2026-07-23"],
                ),
                mock.patch(
                    "fetch.render_top_archive_nav_html",
                    side_effect=render_navigation,
                ) as render_mock,
                mock.patch(
                    "fetch.build_html",
                    return_value="<!DOCTYPE html><html><body></body></html>",
                ),
                mock.patch("fetch.atomic_write_text"),
                mock.patch(
                    "fetch.daily_json.generate_and_save_daily_digest",
                    return_value={
                        "digest_date": "2026-07-24",
                        "run": {"status": "success"},
                    },
                ) as generate_digest_mock,
                mock.patch(
                    "fetch.generate_archive_outputs",
                    return_value=[],
                ) as generate_archive_mock,
            ):
                fetch.main()

        self.assertEqual(CrossingMidnightDateTime.call_count, 2)
        render_mock.assert_called_once_with("2026-07-24", ["2026-07-23"])
        self.assertEqual(
            generate_digest_mock.call_args.kwargs["generated_at"],
            generated_at,
        )
        self.assertEqual(
            generate_digest_mock.call_args.kwargs["fetched_at"],
            fetched_at,
        )
        self.assertEqual(
            generate_archive_mock.call_args.kwargs["generated_at"],
            generated_at,
        )

    def test_daily_archive_navigation_uses_unified_labels_and_global_links(self):
        html = fetch.build_daily_archive_html(
            make_digest("2026-07-22"),
            previous_date="2026-07-20",
            next_date="2026-07-23",
        )

        self.assertEqual(html.count(fetch.PREVIOUS_DIGEST_LABEL), 2)
        self.assertEqual(html.count(fetch.NEXT_DIGEST_LABEL), 2)
        self.assertEqual(html.count(">最新のダイジェスト</a>"), 2)
        self.assertEqual(html.count(">過去のダイジェスト</a>"), 2)
        self.assertIn('href="2026-07-20.html"', html)
        self.assertIn('href="2026-07-23.html"', html)

        for obsolete in (
            "前日のダイジェスト",
            "前回のダイジェスト",
            "前のダイジェスト（",
            "次のダイジェスト（",
            "過去のダイジェストを見る",
            "過去のダイジェスト一覧へ戻る",
            "最新のダイジェストへ戻る",
        ):
            self.assertNotIn(obsolete, html)

    def test_daily_archive_without_adjacent_dates_keeps_global_links_at_both_positions(self):
        html = fetch.build_daily_archive_html(make_digest("2026-07-22"))

        self.assertNotIn("archive-prev-link", html)
        self.assertNotIn("archive-next-link", html)
        self.assertEqual(html.count(">最新のダイジェスト</a>"), 2)
        self.assertEqual(html.count(">過去のダイジェスト</a>"), 2)
        # BL-028: no direction links means the direction-nav group itself is
        # omitted (not rendered empty), so the global-nav group is promoted
        # to the top of the (now single-row) nav.
        self.assertEqual(
            html.count('<div class="archive-nav-group archive-direction-nav">'),
            0,
        )
        self.assertEqual(
            html.count('<div class="archive-nav-group archive-global-nav">'),
            2,
        )

    def test_top_daily_and_archive_index_use_the_same_navigation_terms(self):
        top_html = fetch.render_top_archive_nav_html(
            "2026-07-23",
            ["2026-07-21"],
        )
        daily_html = fetch.build_daily_archive_html(
            make_digest("2026-07-22"),
            previous_date="2026-07-20",
            next_date="2026-07-23",
        )
        archive_index_html = fetch.build_archive_index_html(
            [fetch.archive_summary_from_digest(make_digest("2026-07-22"))]
        )

        self.assertIn(fetch.PREVIOUS_DIGEST_LABEL, top_html)
        self.assertIn(fetch.PREVIOUS_DIGEST_LABEL, daily_html)
        self.assertIn(fetch.NEXT_DIGEST_LABEL, daily_html)
        self.assertIn(fetch.LATEST_DIGEST_LABEL, daily_html)
        self.assertIn(fetch.LATEST_DIGEST_LABEL, archive_index_html)
        self.assertIn(fetch.ARCHIVE_INDEX_LABEL, top_html)
        self.assertIn(fetch.ARCHIVE_INDEX_LABEL, daily_html)


class SourceFooterConsistencyTest(unittest.TestCase):
    def test_enabled_sources_drive_top_and_restored_archive_footer(self):
        sources = [
            {
                "id": "nist_news", "name": "NIST News", "collection_method": "rss",
                "enabled": True, "color": "#111111",
            },
            {
                "id": "cisa", "name": "CISA Advisory", "collection_method": "rss",
                "enabled": False, "color": "#222222",
            },
            {
                "id": "cisa_kev", "name": "CISA KEV", "collection_method": "cisa_kev_json",
                "enabled": True, "color": "#333333",
            },
            {
                "id": "nist_nvd", "name": "NIST NVD", "collection_method": "nist_nvd_json",
                "enabled": False, "color": "#444444",
            },
        ]
        digest = make_digest()

        self.assertEqual(
            [source["id"] for source in fetch.build_footer_sources(sources)],
            ["nist_news", "cisa_kev"],
        )

        with mock.patch.object(fetch, "SOURCE_DEFINITIONS", sources):
            top_html = fetch.build_html(
                fetch.digest_items_for_html(digest),
                fetch.brief_for_html_from_digest(digest),
            )
            archive_html = fetch.build_daily_archive_html(digest)

        top_footer = source_footer_segment(top_html)
        archive_footer = source_footer_segment(archive_html)
        self.assertEqual(top_footer, archive_footer)
        self.assertIn("収集元 (2ソース)", top_footer)
        self.assertEqual(top_footer.count("<li>"), 2)
        self.assertLess(top_footer.index("NIST News"), top_footer.index("CISA KEV"))
        self.assertNotIn("CISA Advisory", top_footer)
        self.assertNotIn("NIST NVD", top_footer)
        self.assertNotIn("<li style=", top_footer)
        self.assertNotIn("<li class=", top_footer)
        self.assertNotIn("background:", top_footer)
        self.assertIn(
            ".sources ul{margin:10px 0 0;padding-left:18px;display:grid;"
            "grid-template-columns:repeat(3,minmax(0,1fr));",
            top_html,
        )
        self.assertIn(
            ".sources li{font-size:11px;line-height:1.5;color:#8b949e;"
            "overflow-wrap:anywhere}",
            top_html,
        )
        self.assertIn(
            "@media (max-width:600px){.sources ul{grid-template-columns:1fr}}",
            top_html,
        )
        self.assertNotIn(".sources li{font-size:11px;padding:", top_html)
        self.assertNotIn(".sources li{font-size:11px;border-radius:", top_html)

    def test_real_footer_keeps_enabled_set_count_order_and_plain_contract(self):
        expected = fetch.build_footer_sources(fetch.SOURCE_DEFINITIONS)
        html = fetch.build_html([])
        footer = source_footer_segment(html)

        self.assertEqual(len(expected), 13)
        self.assertIn("収集元 (13ソース)", footer)
        self.assertEqual(footer.count("<li>"), len(expected))
        positions = []
        for source in expected:
            escaped_name = fetch.esc(source["name"])
            self.assertIn(f"<li>{escaped_name}</li>", footer)
            positions.append(footer.index(escaped_name))
        self.assertEqual(positions, sorted(positions))
        self.assertIn("nist", [source["id"] for source in expected])
        self.assertIn("<li>CISA KEV</li>", footer)
        self.assertIn("<li>NIST</li>", footer)
        self.assertNotIn("CISA Advisory", footer)
        self.assertNotIn(">NIST NVD<", footer)
        self.assertNotIn("NVD vulnerability facts", footer)
        # BL-030: CrowdStrike・Cloudflareは規約確認までの暫定停止でfooterから除外される。
        self.assertNotIn(">CrowdStrike<", footer)
        self.assertNotIn(">Cloudflare<", footer)


class Bl028NavigationLayoutTest(unittest.TestCase):
    """BL-028: 左寄せ二段・ラベルなしナビゲーション配置契約。"""

    def _text_order(self, html, needles):
        positions = [html.index(n) for n in needles]
        return positions == sorted(positions)

    def test_daily_archive_top_nav_reads_prev_next_then_past_latest_in_order(self):
        html = fetch.build_daily_archive_html(
            make_digest("2026-07-22"), previous_date="2026-07-21", next_date="2026-07-23"
        )
        top_nav = html[html.index("<nav"):html.index("</nav>") + len("</nav>")]
        self.assertTrue(
            self._text_order(
                top_nav,
                [
                    fetch.PREVIOUS_DIGEST_LABEL,
                    fetch.NEXT_DIGEST_LABEL,
                    fetch.ARCHIVE_INDEX_LABEL,
                    fetch.LATEST_DIGEST_LABEL,
                ],
            )
        )

    def test_daily_archive_bottom_nav_reads_prev_next_then_past_latest_in_order(self):
        html = fetch.build_daily_archive_html(
            make_digest("2026-07-22"), previous_date="2026-07-21", next_date="2026-07-23"
        )
        bottom_nav = html[html.index('<nav class="archive-nav archive-bottom-nav"'):]
        bottom_nav = bottom_nav[:bottom_nav.index("</nav>") + len("</nav>")]
        self.assertTrue(
            self._text_order(
                bottom_nav,
                [
                    fetch.PREVIOUS_DIGEST_LABEL,
                    fetch.NEXT_DIGEST_LABEL,
                    fetch.ARCHIVE_INDEX_LABEL,
                    fetch.LATEST_DIGEST_LABEL,
                ],
            )
        )

    def test_daily_archive_global_nav_group_lists_past_before_latest(self):
        html = fetch.build_daily_archive_html(
            make_digest("2026-07-22"), previous_date="2026-07-21", next_date="2026-07-23"
        )
        global_groups = re.findall(
            r'<div class="archive-nav-group archive-global-nav">(.*?)</div>', html
        )
        self.assertEqual(len(global_groups), 2)
        for group in global_groups:
            self.assertLess(group.index(fetch.ARCHIVE_INDEX_LABEL), group.index(fetch.LATEST_DIGEST_LABEL))

    def test_top_page_nav_row_order_is_prev_then_archive_index_only(self):
        html = fetch.render_top_archive_nav_html("2026-07-23", ["2026-07-22"])
        self.assertTrue(
            self._text_order(html, [fetch.PREVIOUS_DIGEST_LABEL, fetch.ARCHIVE_INDEX_LABEL])
        )
        self.assertNotIn(fetch.LATEST_DIGEST_LABEL, html)
        self.assertNotIn(fetch.NEXT_DIGEST_LABEL, html)

    def test_archive_index_single_link_has_no_right_alignment_css(self):
        html = fetch.build_archive_index_html([])
        nav_css = html[html.index(".archive-nav{"):html.index(".archive-nav{") + 120]
        self.assertNotIn("justify-content", nav_css)
        self.assertNotIn("margin-left:auto", html)
        self.assertIn(f'<a class="archive-link" href="../index.html">{fetch.LATEST_DIGEST_LABEL}</a>', html)

    def test_shared_css_is_two_row_left_aligned_with_no_pc_only_split_variant(self):
        html = fetch.build_html([])
        self.assertIn(
            ".archive-nav{display:flex;flex-direction:column;align-items:flex-start;row-gap:8px;",
            html,
        )
        # No PC-only right-split rule and no 390px-only override remain.
        self.assertNotIn(
            ".archive-nav{display:flex;align-items:center;justify-content:space-between", html
        )
        self.assertNotIn(".archive-nav-group{width:100%}", html)
        self.assertNotIn(".archive-global-nav{margin-left:0}", html)
        self.assertNotIn(".archive-global-nav{margin-left:auto}", html)
        # The single .archive-nav rule applies identically regardless of viewport
        # width; there is exactly one such rule (no @media (max-width:600px)
        # variant redefining its layout).
        self.assertEqual(html.count(".archive-nav{display:flex;flex-direction:column"), 1)

    def test_both_directions_absent_omits_direction_group_but_keeps_global_group(self):
        html = fetch.build_daily_archive_html(make_digest("2026-07-22"))
        self.assertNotIn('<div class="archive-nav-group archive-direction-nav">', html)
        self.assertEqual(html.count('<div class="archive-nav-group archive-global-nav">'), 2)

    def test_single_direction_link_sits_alone_with_no_reserved_space_for_missing_one(self):
        html = fetch.build_daily_archive_html(make_digest("2026-07-22"), next_date="2026-07-23")
        direction_groups = re.findall(
            r'<div class="archive-nav-group archive-direction-nav">(.*?)</div>', html
        )
        self.assertEqual(len(direction_groups), 2)
        for group in direction_groups:
            self.assertIn(fetch.NEXT_DIGEST_LABEL, group)
            self.assertNotIn(fetch.PREVIOUS_DIGEST_LABEL, group)
        self.assertNotIn("archive-prev-link", html)


if __name__ == "__main__":
    unittest.main()
