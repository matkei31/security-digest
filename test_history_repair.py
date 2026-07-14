#!/usr/bin/env python3
"""Ticket 14a-4: 2026-07-11..13 履歴修復のデータ整合性回帰テスト。

Atom日時parse不具合(Ticket 14a-3で fix-forward 済み)で 2026-07-11..13 へ誤混入した
Google TAG / CrowdStrike の古い記事(6記事×3日=18レコード)を除去した結果を検証する。
外部通信は行わない(修復済みのdata/docsファイルとcompute関数のみを使う)。
"""
import json
import unittest
from pathlib import Path

import daily_json
import fetch

REPAIR_DATES = ("2026-07-11", "2026-07-12", "2026-07-13")
STALE_SOURCES = {"Google TAG", "CrowdStrike"}
DATA_DIR = daily_json.DATA_DIR
DOCS_DIR = fetch.DOCS_DIR


def _load(date):
    return json.loads((DATA_DIR / f"{date}.json").read_text(encoding="utf-8"))


class RepairedDailyJsonTest(unittest.TestCase):
    def test_no_stale_sources_remain(self):
        for date in REPAIR_DATES:
            d = _load(date)
            srcs = [it.get("source_name") for it in d["items"]]
            for s in STALE_SOURCES:
                self.assertNotIn(s, srcs, f"{date}: {s} still present")

    def test_no_comment_feed_urls(self):
        for date in REPAIR_DATES:
            blob = json.dumps(_load(date), ensure_ascii=False)
            self.assertNotIn("/comments/default", blob, f"{date}")

    def test_item_counts(self):
        # 修復後の記事数(stale 6件除去後)。
        expected = {"2026-07-11": 6, "2026-07-12": 3, "2026-07-13": 0}
        for date, n in expected.items():
            d = _load(date)
            self.assertEqual(len(d["items"]), n, date)
            self.assertEqual(d["run"]["total_items"], n, date)

    def test_counts_and_run_match_items(self):
        for date in REPAIR_DATES:
            d = _load(date)
            self.assertEqual(d["counts"], daily_json.compute_counts(d["items"]), f"{date} counts")
            self.assertEqual(d["run"], daily_json.compute_run_meta(d["items"]), f"{date} run")

    def test_0711_legacy_schema_preserved_no_facts_added(self):
        # 07-11 はTicket 12a以前の旧スキーマ(facts無し)。factsを後付けしていないこと。
        d = _load("2026-07-11")
        self.assertEqual(len(d["items"]), 6)
        for it in d["items"]:
            self.assertNotIn("facts", it, "facts must not be added to legacy 07-11")

    def test_0713_zero_articles_brief_not_attempted(self):
        # 07-13 は記事0件 → 既存build_todays_briefのnot_attemptedをそのまま採用。
        d = _load("2026-07-13")
        self.assertEqual(len(d["items"]), 0)
        self.assertEqual(d["brief"]["status"], "not_attempted")
        self.assertIsNone(d["brief"]["overview"])
        self.assertEqual(d["brief"]["important_highlights"], [])
        self.assertEqual(d["brief"]["discussion_points"], [])
        self.assertEqual(d["brief"]["check_items"], [])

    def test_historical_brief_prompt_version_preserved(self):
        # 履歴修復(Ticket 14a-4)はこれらの日付のbrief.prompt_versionを書き換えて
        # いないことを確認する。生成時点のリテラル("today-brief-v2")と比較する
        # (daily_json.BRIEF_PROMPT_VERSIONは以後のTicketで更新されうる現行定数であり、
        # 過去に生成済みのJSONの値は現行定数へ追随しない)。
        for date in ("2026-07-11", "2026-07-12"):
            d = _load(date)
            self.assertEqual(d["brief"]["prompt_version"], "today-brief-v2")
            self.assertEqual(d["brief"]["status"], "success")

    def test_loadable_and_archive_renderable(self):
        for date in REPAIR_DATES:
            digest = fetch.load_daily_digest(DATA_DIR / f"{date}.json")
            html = fetch.build_daily_archive_html(digest)
            fetch.validate_html_document(html)  # 例外なし


class RepairedIndexAndArchiveTest(unittest.TestCase):
    def test_index_consistent_with_day_files(self):
        idx = json.loads((DATA_DIR / "index.json").read_text(encoding="utf-8"))
        by_date = {e["digest_date"]: e for e in idx["digests"]}
        for date in REPAIR_DATES:
            e = by_date[date]
            d = _load(date)
            self.assertEqual(e["total_items"], d["run"]["total_items"], date)
            self.assertEqual(e["high_count"], d["counts"]["importance"]["高"], date)
            self.assertEqual(e["ai_run_status"], d["run"]["status"], date)

    def test_archive_html_clean(self):
        stale_titles = ("ガードレールのない", "Pixel ベースバンド", "Rust を導入")
        files = [DOCS_DIR / "archive" / f"{d}.html" for d in REPAIR_DATES]
        files += [DOCS_DIR / "archive" / "index.html", DOCS_DIR / "index.html"]
        for f in files:
            t = f.read_text(encoding="utf-8")
            self.assertNotIn("/comments/default", t, str(f))
            for title in stale_titles:
                self.assertNotIn(title, t, f"{f}: stale '{title}'")


if __name__ == "__main__":
    unittest.main()
