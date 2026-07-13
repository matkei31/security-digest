#!/usr/bin/env python3
"""Ticket 14a-3: Atom日時(小数秒付きISO 8601)parseと日付不明記事の扱いの回帰テスト。
外部HTTP通信は行わない(XML文字列とmockのみ)。

不具合: Atomのpublished/updatedが小数秒付き(例 2026-04-23T17:38:00.001-04:00)で、
共通parserが小数秒を扱えずNoneになり、collect_recentがdate=Noneを無条件採用して
古い記事(2026年4月)が2026年7月のダイジェストへ毎日再掲されていた。"""

import datetime
import io
import unittest
import xml.etree.ElementTree as ET
from contextlib import redirect_stdout, redirect_stderr
from unittest.mock import patch

import daily_json
import fetch

ATOM = "http://www.w3.org/2005/Atom"
JST = daily_json.JST


def _atom(entries_xml):
    return f'<feed xmlns="{ATOM}"><title>T</title><updated>2026-07-01T00:00:00Z</updated>{entries_xml}</feed>'


def _entry(links, published=None, updated=None, title="A"):
    p = f"<published>{published}</published>" if published is not None else ""
    u = f"<updated>{updated}</updated>" if updated is not None else ""
    return f"<entry><title>{title}</title>{p}{u}{links}</entry>"


ALT = ('<link rel="alternate" type="text/html" '
       'href="https://security.googleblog.com/2026/04/x.html"/>')


class CommonParserTest(unittest.TestCase):
    def test_iso_fractional_offset(self):
        dt = daily_json.parse_datetime("2026-04-23T17:38:00.001-04:00")
        self.assertIsNotNone(dt); self.assertIsNotNone(dt.tzinfo)
        self.assertEqual(dt.utcoffset(), datetime.timedelta(hours=-4))

    def test_iso_no_fractional_offset(self):
        dt = daily_json.parse_datetime("2026-04-23T17:38:00-04:00")
        self.assertIsNotNone(dt.tzinfo)

    def test_iso_fractional_z(self):
        dt = daily_json.parse_datetime("2026-04-23T17:38:00.001Z")
        self.assertEqual(dt.utcoffset(), datetime.timedelta(0))

    def test_iso_no_fractional_z(self):
        dt = daily_json.parse_datetime("2026-04-23T17:38:00Z")
        self.assertEqual(dt.utcoffset(), datetime.timedelta(0))

    def test_iso_plus0000(self):
        dt = daily_json.parse_datetime("2026-04-23T17:38:00+00:00")
        self.assertEqual(dt.utcoffset(), datetime.timedelta(0))

    def test_rfc822_numeric(self):
        dt = daily_json.parse_datetime("Fri, 10 Jul 2026 12:00:00 +0000")
        self.assertEqual(dt.utcoffset(), datetime.timedelta(0))

    def test_rfc822_gmt(self):
        dt = daily_json.parse_datetime("Fri, 10 Jul 2026 12:00:00 GMT")
        self.assertEqual(dt.utcoffset(), datetime.timedelta(0))

    def test_invalid_is_none(self):
        self.assertIsNone(daily_json.parse_datetime("not a date"))

    def test_empty_and_nonstr_is_none(self):
        self.assertIsNone(daily_json.parse_datetime(""))
        self.assertIsNone(daily_json.parse_datetime("   "))
        self.assertIsNone(daily_json.parse_datetime(None))

    def test_date_only_is_naive(self):
        dt = daily_json.parse_datetime("2026-07-10")
        self.assertIsNotNone(dt)
        self.assertIsNone(dt.tzinfo)  # 日付のみ(YYYY-MM-DD)はnaive

    def test_timezoneless_datetime_is_none(self):
        # タイムゾーンなしの時刻付きISO日時は、正確な瞬間を特定できないためNone。
        for s in ("2026-07-13T09:00:00", "2026-07-13T09:00", "2026-07-13T09:00:00.123"):
            with self.subTest(s=s):
                self.assertIsNone(daily_json.parse_datetime(s))
                self.assertIsNone(fetch.parse_date(s))


class JstConversionTest(unittest.TestCase):
    def test_fractional_offset_to_jst(self):
        dt = daily_json.parse_date_to_jst("2026-04-23T17:38:00.001-04:00")
        # -04:00 17:38 = 21:38 UTC = 翌日06:38 JST
        self.assertEqual(dt.year, 2026); self.assertEqual(dt.month, 4); self.assertEqual(dt.day, 24)
        self.assertEqual(dt.hour, 6); self.assertEqual(dt.minute, 38)
        self.assertEqual(dt.utcoffset(), datetime.timedelta(hours=9))

    def test_fractional_seconds_not_in_output(self):
        dt = daily_json.parse_date_to_jst("2026-04-23T17:38:00.001-04:00")
        self.assertEqual(dt.microsecond, 0)
        self.assertNotIn(".", dt.isoformat().split("+")[0].split("T")[1])

    def test_date_only_to_jst_is_none(self):
        # オフセットが無い形式は正確な瞬間を特定できないためNone(従来契約を維持)。
        self.assertIsNone(daily_json.parse_date_to_jst("2026-07-10"))

    def test_parse_date_and_to_jst_consistent_success_for_tz_inputs(self):
        for s in ("2026-04-23T17:38:00.001-04:00", "2026-04-23T17:38:00Z",
                  "Fri, 10 Jul 2026 12:00:00 +0000"):
            self.assertIsNotNone(fetch.parse_date(s))
            self.assertIsNotNone(daily_json.parse_date_to_jst(s))


class ParseDateUtcNormalizationTest(unittest.TestCase):
    """parse_dateはtimezone-aware入力をUTCへ正規化したnaive datetimeを返す。"""

    def test_equivalent_instants_same_result(self):
        # 同一の実時刻を表す3つのタイムゾーン表記が同じparse_date結果になる。
        results = [fetch.parse_date(s) for s in (
            "2026-07-12T08:00:00Z",
            "2026-07-12T04:00:00-04:00",
            "2026-07-12T17:00:00+09:00",
        )]
        for r in results:
            self.assertEqual(r, datetime.datetime(2026, 7, 12, 8, 0, 0))
            self.assertIsNone(r.tzinfo)

    def test_timezone_naive_input_unchanged(self):
        # 日付のみ(YYYY-MM-DD)は従来どおりnaiveのまま(KEV dateAddedを壊さない)。
        self.assertEqual(fetch.parse_date("2026-07-10"), datetime.datetime(2026, 7, 10, 0, 0))

    def test_timezoneless_time_returns_none(self):
        # タイムゾーンなしの時刻付き日時は parse_date でも None(recentへ広げない)。
        self.assertIsNone(fetch.parse_date("2026-07-13T09:00:00"))


class AtomDateSelectionTest(unittest.TestCase):
    def _parse_one(self, published=None, updated=None):
        feed = _atom(_entry(ALT, published=published, updated=updated))
        items = fetch._parse_feed_items(ET.fromstring(feed), "Google TAG", "en")
        return items[0] if items else None

    def test_prefers_published_over_updated(self):
        it = self._parse_one(published="2026-04-09T13:07:00.001-04:00",
                             updated="2026-06-27T18:01:27.620-04:00")
        # publishedを採用し、UTCへ正規化した日時を使う。
        # 2026-04-09T13:07-04:00 = 2026-04-09 17:07 UTC(日付は4/9のまま)。
        self.assertEqual(it["date"].month, 4); self.assertEqual(it["date"].day, 9)
        self.assertEqual(it["date"].hour, 17)  # -04:00 13:07 = 17:07 UTC

    def test_falls_back_to_updated_when_published_missing(self):
        it = self._parse_one(published=None, updated="2026-06-27T18:01:27.620-04:00")
        self.assertEqual(it["date"].month, 6); self.assertEqual(it["date"].day, 27)

    def test_falls_back_to_updated_when_published_empty(self):
        it = self._parse_one(published="   ", updated="2026-06-27T18:01:27.620-04:00")
        self.assertEqual(it["date"].month, 6)

    def test_no_fallback_when_published_unparseable(self):
        # publishedが存在するがparse不能 → updatedへfallbackせず日付不明(date=None)。
        it = self._parse_one(published="garbage-date", updated="2026-06-27T18:01:27.620-04:00")
        self.assertIsNone(it["date"])
        self.assertIsNone(it["published_at_jst"])

    def test_blogger_fractional_parsed(self):
        it = self._parse_one(published="2026-04-23T17:38:00.001-04:00")
        self.assertIsNotNone(it["date"])
        self.assertIsNotNone(it["published_at_jst"])

    def test_crowdstrike_like_fractional_parsed(self):
        # 小数秒3桁+Z形式(CrowdStrike相当)も解釈できる。
        it = self._parse_one(published="2026-04-10T11:12:00.123Z")
        self.assertIsNotNone(it["date"])
        self.assertIsNotNone(it["published_at_jst"])

    def test_date_and_published_at_from_same_raw(self):
        it = self._parse_one(published="2026-04-23T17:38:00.001-04:00",
                             updated="2026-06-27T18:01:27.620-04:00")
        # dateはpublished(4/23)由来。published_at_jstも同じraw由来(4/24 JST)。
        self.assertEqual(it["date"].day, 23)
        self.assertEqual(it["published_at_jst"].day, 24)


class _FixedDateTime(datetime.datetime):
    """utcnow()を固定するテスト用datetime。now=2026-07-13 07:00:00 UTC、
    DAYS_BACK=1のcutoff=2026-07-12 07:00:00 UTC。"""
    @classmethod
    def utcnow(cls):
        return cls(2026, 7, 13, 7, 0, 0)


class DaysBackFilterTest(unittest.TestCase):
    """collect_recentが date=None・parse失敗・cutoffより古い記事を除外することを、
    固定now(2026-07-13 07:00:00 UTC)基準で決定論的に検証する。"""

    def _run(self, entries_xml):
        feed = _atom(entries_xml).encode("utf-8")

        class Resp:
            status = 200
            def read(s): return feed
            def geturl(s): return "https://x/feed"
            def getcode(s): return 200
            def __enter__(s): return s
            def __exit__(s, *a): return False

        # fetch.datetime.datetime を固定utcnowクラスへ差し替え、終了後に必ず戻す。
        with patch("fetch.datetime.datetime", _FixedDateTime), \
                patch("fetch.RSS_FEEDS", [("Google TAG", "https://x/feed", "en")]), \
                patch("fetch.collect_non_rss_items", return_value=[]), \
                patch("fetch.urllib.request.urlopen", return_value=Resp()), \
                patch("fetch.time.sleep"), \
                redirect_stderr(io.StringIO()), redirect_stdout(io.StringIO()) as out:
            items = fetch.collect_recent()
        return items, out.getvalue()

    def test_newer_old_and_none_excluded(self):
        # now=07-13 07:00Z, cutoff=07-12 07:00Z。
        entries = (
            _entry(ALT, published="2026-07-13T00:00:00Z", title="newer") +       # 採用
            _entry(ALT, published="2026-04-23T17:38:00.001-04:00", title="april") +  # 古く除外
            _entry(ALT, published="garbage", title="undated")                    # date=None除外
        )
        items, out = self._run(entries)
        titles = [it["title"] for it in items]
        self.assertIn("newer", titles)
        self.assertNotIn("april", titles)
        self.assertNotIn("undated", titles)
        self.assertEqual(len(items), 1)
        self.assertIn("undated_skipped=1", out)
        self.assertIn("older_skipped=1", out)

    def test_april_article_does_not_pass_july_days_back(self):
        entries = _entry(ALT, published="2026-04-23T17:38:00.001-04:00", title="april")
        items, out = self._run(entries)
        self.assertEqual(items, [])
        self.assertNotIn("undated_skipped=1", out)  # parse成功なので undated ではない
        self.assertIn("older_skipped=1", out)

    def test_negative_offset_boundary_included(self):
        # 記事 2026-07-12T04:00:00-04:00 = 08:00 UTC >= cutoff(07:00 UTC) → 採用。
        # 旧実装(wall time 04:00 UTC比較)なら誤って除外される回帰検出。
        entries = _entry(ALT, published="2026-07-12T04:00:00-04:00", title="neg")
        items, out = self._run(entries)
        self.assertEqual([it["title"] for it in items], ["neg"])
        self.assertIn("older_skipped=0", out)

    def test_positive_offset_boundary_excluded(self):
        # 記事 2026-07-12T15:30:00+09:00 = 06:30 UTC < cutoff(07:00 UTC) → 除外。
        # wall time 15:30 で誤採用しないこと。
        entries = _entry(ALT, published="2026-07-12T15:30:00+09:00", title="pos")
        items, out = self._run(entries)
        self.assertEqual(items, [])
        self.assertIn("older_skipped=1", out)

    def test_exact_cutoff_included(self):
        # 記事 2026-07-12T07:00:00Z == cutoff(2026-07-12 07:00 UTC) → 完全一致で採用。
        entries = _entry(ALT, published="2026-07-12T07:00:00Z", title="exact")
        items, out = self._run(entries)
        self.assertEqual([it["title"] for it in items], ["exact"])
        self.assertIn("older_skipped=0", out)
        self.assertIn("undated_skipped=0", out)

    def test_timezoneless_time_excluded_as_undated(self):
        # タイムゾーンなしの時刻付き日時はparse不能→date=None→recentから除外され、
        # undated_skippedへ計上される(older_skippedではない)。
        entries = _entry(ALT, published="2026-07-13T09:00:00", title="tzless")
        items, out = self._run(entries)
        self.assertEqual(items, [])
        self.assertIn("undated_skipped=1", out)
        self.assertIn("older_skipped=0", out)


class RegressionTest(unittest.TestCase):
    def test_rss_rfc822_still_parses(self):
        rss = ('<rss version="2.0"><channel><title>C</title>'
               '<item><title>A</title><link>https://x/a</link><description>d</description>'
               '<pubDate>Fri, 10 Jul 2026 12:00:00 +0000</pubDate></item></channel></rss>')
        items = fetch._parse_feed_items(ET.fromstring(rss), "Some RSS", "en")
        self.assertIsNotNone(items[0]["date"])
        self.assertIsNotNone(items[0]["published_at_jst"])

    def test_atom_comment_url_still_excluded(self):
        links = ('<link rel="replies" type="application/atom+xml" '
                 'href="https://x/feeds/1/comments/default"/>' + ALT)
        feed = _atom(_entry(links, published="2031-01-01T00:00:00Z"))
        items = fetch._parse_feed_items(ET.fromstring(feed), "Google TAG", "en")
        self.assertEqual(items[0]["link"], "https://security.googleblog.com/2026/04/x.html")

    def test_kev_date_only_still_parses_for_parse_date(self):
        # KEV dateAdded(YYYY-MM-DD)は parse_date で従来どおり値を返す(naive)。
        self.assertIsNotNone(fetch.parse_date("2026-07-10"))

    def test_max_per_feed_maintained_for_atom(self):
        entries = "".join(
            _entry(ALT, published="2031-01-0%dT00:00:00Z" % i, title=f"a{i}")
            for i in range(1, 6))
        items = fetch._parse_feed_items(ET.fromstring(_atom(entries)), "Google TAG", "en")
        self.assertEqual(len(items), fetch.MAX_PER_FEED)


if __name__ == "__main__":
    unittest.main()
