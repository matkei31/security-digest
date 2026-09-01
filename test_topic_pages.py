#!/usr/bin/env python3
"""BL-051 topic-page v0.1 regression tests."""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import topic_pages as tp


class TopicDefinitionContractTest(unittest.TestCase):
    def test_registry_has_unique_nonempty_slugs_and_no_other_topic(self):
        slugs = [definition.slug for definition in tp.TOPIC_DEFINITIONS]
        labels = [definition.label for definition in tp.TOPIC_DEFINITIONS]
        self.assertEqual(len(slugs), len(set(slugs)))
        self.assertTrue(all(slug and slug.isascii() for slug in slugs))
        self.assertNotIn("その他", labels)
        self.assertEqual(
            slugs,
            [
                "vulnerabilities",
                "threats",
                "incidents",
                "regulation-governance",
                "identity-access",
                "cloud-supply-chain",
                "ai",
                "ransomware",
            ],
        )

    def test_v01_uses_existing_category_and_tags_as_or_signals(self):
        identity = next(d for d in tp.TOPIC_DEFINITIONS if d.slug == "identity-access")
        vulnerabilities = next(d for d in tp.TOPIC_DEFINITIONS if d.slug == "vulnerabilities")
        self.assertTrue(tp._topic_matches(identity, "その他", ["IAM"]))
        self.assertTrue(tp._topic_matches(vulnerabilities, "脆弱性・パッチ", []))
        self.assertTrue(tp._topic_matches(vulnerabilities, "インシデント", ["KEV"]))
        self.assertFalse(tp._topic_matches(identity, "その他", []))


class TopicPublicationThresholdTest(unittest.TestCase):
    def _article(self, date, index=1):
        return tp.TopicArticle(
            digest_date=date,
            article_index=index,
            title=f"article-{date}-{index}",
            source="Source",
            summary="summary",
            importance="中",
            urgency="今週確認",
            category="脆弱性・パッチ",
            tags=("CVE",),
        )

    def test_requires_five_articles_and_two_distinct_dates(self):
        slug = tp.TOPIC_DEFINITIONS[0].slug
        four = [self._article("2026-08-01", i) for i in range(1, 5)]
        five_one_day = [self._article("2026-08-01", i) for i in range(1, 6)]
        five_two_days = five_one_day[:4] + [self._article("2026-08-02", 1)]

        self.assertEqual(tp.select_published_topics({slug: four}), ())
        self.assertEqual(tp.select_published_topics({slug: five_one_day}), ())
        published = tp.select_published_topics({slug: five_two_days})
        self.assertEqual(len(published), 1)
        self.assertEqual(published[0].article_count, 5)
        self.assertEqual(published[0].date_count, 2)


class TopicCollectionTest(unittest.TestCase):
    def test_collection_uses_archive_display_order_for_article_anchor(self):
        digest = {"digest_date": "2026-08-29"}
        display_items = [
            {
                "title": "Incident first",
                "source": "A",
                "ai_analysis": {
                    "category": "インシデント",
                    "tags": ["情報漏えい"],
                    "summary": "one",
                    "importance": "高",
                    "urgency": "本日確認",
                },
            },
            {
                "title": "Vulnerability second",
                "source": "B",
                "ai_analysis": {
                    "category": "脆弱性・パッチ",
                    "tags": ["CVE"],
                    "summary": "two",
                    "importance": "中",
                    "urgency": "今週確認",
                },
            },
        ]
        with (
            patch.object(tp.fetch, "load_validated_published_digest_dates", return_value=["2026-08-29"]),
            patch.object(tp.fetch, "load_daily_digest", return_value=digest),
            patch.object(tp.fetch, "digest_items_for_html", return_value=list(reversed(display_items))),
            patch.object(tp.fetch, "sort_items_for_display", return_value=display_items),
        ):
            collected = tp.collect_topic_articles(Path("data"), Path("docs"))

        incidents = collected["incidents"]
        vulnerabilities = collected["vulnerabilities"]
        self.assertEqual(incidents[0].article_index, 1)
        self.assertEqual(incidents[0].archive_href, "/archive/2026-08-29.html#article-1")
        self.assertEqual(vulnerabilities[0].article_index, 2)
        self.assertEqual(vulnerabilities[0].archive_href, "/archive/2026-08-29.html#article-2")

    def test_missing_or_unclassified_analysis_is_not_forced_into_a_topic(self):
        self.assertIsNone(tp._article_from_display_item("2026-08-01", 1, {"title": "x"}))
        self.assertIsNone(
            tp._article_from_display_item(
                "2026-08-01", 1,
                {"title": "x", "ai_analysis": {"category": None, "tags": []}},
            )
        )


class TopicHtmlTest(unittest.TestCase):
    def _published_topic(self):
        d = tp.TOPIC_DEFINITIONS[0]
        articles = tuple(
            tp.TopicArticle(
                digest_date="2026-08-29" if i < 4 else "2026-08-28",
                article_index=i + 1,
                title="<script>title</script>" if i == 0 else f"Article {i + 1}",
                source="Source & Co",
                summary="summary <b>unsafe</b>",
                importance="高" if i == 0 else "中",
                urgency="本日確認" if i == 0 else "今週確認",
                category="脆弱性・パッチ",
                tags=("CVE",),
            )
            for i in range(5)
        )
        return tp.PublishedTopic(d, articles)

    def test_index_and_topic_pages_have_unique_title_description_and_canonical(self):
        topic = self._published_topic()
        with (
            patch.object(tp.fetch, "public_url", side_effect=lambda path: f"https://monomidigest.com/{path}"),
            patch.object(tp.fetch, "render_analytics_footer_html", return_value='<footer class="site-footer">analytics</footer>'),
            patch.object(tp.fetch, "render_cloudflare_web_analytics_html", return_value='<script src="https://static.cloudflareinsights.com/beacon.min.js"></script>'),
        ):
            index = tp.build_topic_index_html([topic])
            page = tp.build_topic_html(topic)

        self.assertIn("<title>テーマから探す | Monomi Digest</title>", index)
        self.assertIn('<link rel="canonical" href="https://monomidigest.com/topics/">', index)
        self.assertIn("<meta name=\"description\"", index)
        self.assertIn("<title>脆弱性・パッチ | Monomi Digest</title>", page)
        self.assertIn(
            '<link rel="canonical" href="https://monomidigest.com/topics/vulnerabilities/">',
            page,
        )
        self.assertIn("site-footer", page)
        self.assertIn("static.cloudflareinsights.com", page)

    def test_topic_page_escapes_article_text_and_links_to_daily_archive(self):
        topic = self._published_topic()
        with (
            patch.object(tp.fetch, "public_url", side_effect=lambda path: f"https://monomidigest.com/{path}"),
            patch.object(tp.fetch, "render_analytics_footer_html", return_value=""),
            patch.object(tp.fetch, "render_cloudflare_web_analytics_html", return_value=""),
        ):
            page = tp.build_topic_html(topic)
        self.assertNotIn("<script>title</script>", page)
        self.assertIn("&lt;script&gt;title&lt;/script&gt;", page)
        self.assertIn("Source &amp; Co", page)
        self.assertIn("summary &lt;b&gt;unsafe&lt;/b&gt;", page)
        self.assertIn('/archive/2026-08-29.html#article-1', page)


class TopicOutputIntegrationTest(unittest.TestCase):
    def test_top_navigation_injection_is_idempotent_and_scoped(self):
        base = (
            '<nav><div class="archive-nav-group archive-global-nav">'
            '<a class="archive-link" href="archive/index.html">過去のダイジェスト</a>'
            '</div></nav>\n'
        )
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "index.html"
            path.write_text(base, encoding="utf-8")
            with patch.object(
                tp.fetch,
                "atomic_write_text",
                side_effect=lambda p, text: Path(p).write_text(text, encoding="utf-8"),
            ):
                tp.inject_top_navigation_link(path)
                first = path.read_text(encoding="utf-8")
                tp.inject_top_navigation_link(path)
                second = path.read_text(encoding="utf-8")
        self.assertEqual(first, second)
        self.assertEqual(first.count(tp.TOP_NAV_LINK_HTML), 1)
        self.assertIn("過去のダイジェスト", first)

    def test_top_navigation_missing_marker_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "index.html"
            path.write_text("<html></html>", encoding="utf-8")
            with self.assertRaises(RuntimeError):
                tp.inject_top_navigation_link(path)

    def test_generate_topic_outputs_does_not_modify_existing_sitemap_contract(self):
        topic = TopicHtmlTest()._published_topic()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            docs = root / "docs"
            data = root / "data"
            docs.mkdir()
            data.mkdir()
            (docs / "index.html").write_text(
                '<div class="archive-nav-group archive-global-nav">'
                '<a class="archive-link" href="archive/index.html">過去のダイジェスト</a>'
                '</div>',
                encoding="utf-8",
            )
            sitemap = "<?xml version=\"1.0\"?><urlset><url><loc>https://monomidigest.com/</loc></url></urlset>\n"
            (docs / "sitemap.xml").write_text(sitemap, encoding="utf-8")

            def write_text(path, text):
                path = Path(path)
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(text, encoding="utf-8")

            with (
                patch.object(tp, "collect_topic_articles", return_value={topic.definition.slug: list(topic.articles)}),
                patch.object(tp, "select_published_topics", return_value=(topic,)),
                patch.object(tp.fetch, "public_url", side_effect=lambda p: f"https://monomidigest.com/{p}"),
                patch.object(tp.fetch, "render_analytics_footer_html", return_value=""),
                patch.object(tp.fetch, "render_cloudflare_web_analytics_html", return_value=""),
                patch.object(tp.fetch, "atomic_write_text", side_effect=write_text),
            ):
                tp.generate_topic_outputs(data_dir=data, docs_dir=docs)
        self.assertEqual((docs / "sitemap.xml").read_text(encoding="utf-8"), sitemap)

    def test_write_topic_pages_removes_only_stale_registered_topic_directory(self):
        topic = TopicHtmlTest()._published_topic()
        with tempfile.TemporaryDirectory() as tmp:
            docs = Path(tmp)
            stale = docs / "topics" / "threats"
            unknown = docs / "topics" / "manual-note"
            stale.mkdir(parents=True)
            unknown.mkdir(parents=True)
            (stale / "index.html").write_text("stale", encoding="utf-8")
            (unknown / "keep.txt").write_text("keep", encoding="utf-8")

            def write_text(path, text):
                path = Path(path)
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(text, encoding="utf-8")

            with (
                patch.object(tp.fetch, "public_url", side_effect=lambda p: f"https://monomidigest.com/{p}"),
                patch.object(tp.fetch, "render_analytics_footer_html", return_value=""),
                patch.object(tp.fetch, "render_cloudflare_web_analytics_html", return_value=""),
                patch.object(tp.fetch, "atomic_write_text", side_effect=write_text),
            ):
                tp.write_topic_pages(docs, [topic])
            self.assertFalse(stale.exists())
            self.assertTrue((docs / "topics" / "vulnerabilities" / "index.html").is_file())
            self.assertTrue((unknown / "keep.txt").is_file())


class TopicWorkflowContractTest(unittest.TestCase):
    def test_production_workflow_runs_topic_generator_after_fetch_and_before_commit(self):
        workflow = (
            Path(__file__).resolve().parent / ".github" / "workflows" / "fetch.yml"
        ).read_text(encoding="utf-8")
        fetch_pos = workflow.index("python3 fetch.py")
        topic_pos = workflow.index("python3 topic_pages.py")
        commit_pos = workflow.index("- name: Commit and push")
        self.assertLess(fetch_pos, topic_pos)
        self.assertLess(topic_pos, commit_pos)
        self.assertEqual(workflow.count("python3 topic_pages.py"), 1)


if __name__ == "__main__":
    unittest.main()
