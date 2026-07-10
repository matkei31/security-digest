#!/usr/bin/env python3
"""
source_definitions.json の読み込み・検証・互換レイヤーの回帰テスト (Ticket 2)
標準ライブラリの unittest のみを使用する。
"""

import json
import tempfile
import unittest
from pathlib import Path

import fetch


# Ticket 2 着手前 (source_definitions.json 導入前) の fetch.py にハードコードされて
# いた値そのもの。互換レイヤーがこれと一致し続けることを保証するための基準値。
BASELINE_RSS_FEEDS = [
    ("金融庁",             "https://www.fsa.go.jp/fsaNewsListAll_rss2.xml",              "ja"),
    ("JPCERT/CC",          "https://www.jpcert.or.jp/rss/jpcert.rdf",                   "ja"),
    ("IPA",                "https://www.ipa.go.jp/security/rss/alert.rdf",              "ja"),
    ("CISA",               "https://www.cisa.gov/cybersecurity-advisories/all.xml",     "en"),
    ("NIST",               "https://www.nist.gov/news-events/news/rss.xml",             "en"),
    ("Microsoft Security", "https://www.microsoft.com/en-us/security/blog/feed/",       "en"),
    ("Mandiant",           "https://cloudblog.withgoogle.com/topics/threat-intelligence/rss/", "en"),
    ("CrowdStrike",        "https://www.crowdstrike.com/blog/feed/",                    "en"),
    ("Google TAG",         "https://security.googleblog.com/feeds/posts/default",       "en"),
    ("NCSC",               "https://www.ncsc.gov.uk/api/1/services/v1/all-rss-feed.xml","en"),
    ("Krebs on Security",  "https://krebsonsecurity.com/feed/",                         "en"),
    ("Dark Reading",       "https://www.darkreading.com/rss.xml",                       "en"),
    ("The Hacker News",    "https://feeds.feedburner.com/TheHackersNews",               "en"),
    ("Cisco Talos",        "https://blog.talosintelligence.com/rss/",                    "en"),
    ("Cloudflare",         "https://blog.cloudflare.com/rss/",                            "en"),
]

BASELINE_SOURCE_COLORS = {
    "金融庁":             "#c0392b",
    "JPCERT/CC":          "#2471a3",
    "CISA":               "#1e8449",
    "CISA KEV":           "#e74c3c",
    "Microsoft Security": "#0078d4",
    "NIST NVD":           "#7d3c98",
    "Mandiant":           "#e67e22",
    "CrowdStrike":        "#cc0000",
    "Google TAG":         "#4285f4",
    "NCSC":               "#005eb8",
    "Cisco Talos":        "#6f42c1",
    "Cloudflare":         "#f38020",
}

BASELINE_TRUSTED_CYBER_SOURCES = {
    "JPCERT/CC", "CISA", "Microsoft Security", "Mandiant",
    "CrowdStrike", "Google TAG", "NCSC", "Cisco Talos",
    "The Hacker News", "Krebs on Security", "Dark Reading",
}


def _valid_entry(**overrides):
    """バリデーションを通る最小構成のsourceエントリを1件返す。"""
    entry = {
        "id": "test_source",
        "name": "Test Source",
        "url": "https://example.com/feed.xml",
        "collection_method": "rss",
        "language": "en",
        "source_type": "その他",
        "source_tier": "Tier 3",
        "enabled": True,
        "planned_phase": "Phase 1",
        "activation_condition": "",
        "collection_frequency": "daily",
        "color": "#555",
        "trusted_cyber_source": False,
        "notes": "",
    }
    entry.update(overrides)
    return entry


def _write_temp_definitions(entries):
    tmp = tempfile.NamedTemporaryFile(
        mode="w", suffix=".json", delete=False, encoding="utf-8"
    )
    json.dump({"sources": entries}, tmp, ensure_ascii=False)
    tmp.close()
    return Path(tmp.name)


class LoadSourceDefinitionsTest(unittest.TestCase):
    def test_real_file_loads_successfully(self):
        sources = fetch.load_source_definitions()
        self.assertIsInstance(sources, list)
        self.assertEqual(len(sources), 17)
        self.assertEqual(sources[0]["id"], "fsa")

    def test_missing_file_raises_clear_error(self):
        missing_path = Path(tempfile.gettempdir()) / "does_not_exist_source_definitions.json"
        with self.assertRaises(fetch.SourceDefinitionError) as ctx:
            fetch.load_source_definitions(path=missing_path)
        self.assertIn(str(missing_path), str(ctx.exception))

    def test_invalid_json_raises_clear_error(self):
        tmp = tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        )
        tmp.write("{ not valid json ")
        tmp.close()
        try:
            with self.assertRaises(fetch.SourceDefinitionError) as ctx:
                fetch.load_source_definitions(path=Path(tmp.name))
            self.assertIn("JSON解析", str(ctx.exception))
        finally:
            Path(tmp.name).unlink()

    def test_missing_sources_key_raises_clear_error(self):
        tmp = tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        )
        json.dump({"not_sources": []}, tmp)
        tmp.close()
        try:
            with self.assertRaises(fetch.SourceDefinitionError) as ctx:
                fetch.load_source_definitions(path=Path(tmp.name))
            self.assertIn("sources", str(ctx.exception))
        finally:
            Path(tmp.name).unlink()

    def test_duplicate_id_is_detected(self):
        path = _write_temp_definitions([
            _valid_entry(id="dup", name="A"),
            _valid_entry(id="dup", name="B"),
        ])
        try:
            with self.assertRaises(fetch.SourceDefinitionError) as ctx:
                fetch.load_source_definitions(path=path)
            self.assertIn("id", str(ctx.exception))
            self.assertIn("dup", str(ctx.exception))
        finally:
            path.unlink()

    def test_duplicate_name_is_detected(self):
        path = _write_temp_definitions([
            _valid_entry(id="a", name="Same Name"),
            _valid_entry(id="b", name="Same Name"),
        ])
        try:
            with self.assertRaises(fetch.SourceDefinitionError) as ctx:
                fetch.load_source_definitions(path=path)
            self.assertIn("name", str(ctx.exception))
        finally:
            path.unlink()

    def test_missing_required_field_is_detected(self):
        entry = _valid_entry()
        del entry["source_tier"]
        path = _write_temp_definitions([entry])
        try:
            with self.assertRaises(fetch.SourceDefinitionError) as ctx:
                fetch.load_source_definitions(path=path)
            self.assertIn("source_tier", str(ctx.exception))
        finally:
            path.unlink()

    def test_invalid_source_type_is_detected(self):
        path = _write_temp_definitions([_valid_entry(source_type="架空の分類")])
        try:
            with self.assertRaises(fetch.SourceDefinitionError) as ctx:
                fetch.load_source_definitions(path=path)
            self.assertIn("source_type", str(ctx.exception))
        finally:
            path.unlink()

    def test_invalid_source_tier_is_detected(self):
        path = _write_temp_definitions([_valid_entry(source_tier="Tier 9")])
        try:
            with self.assertRaises(fetch.SourceDefinitionError) as ctx:
                fetch.load_source_definitions(path=path)
            self.assertIn("source_tier", str(ctx.exception))
        finally:
            path.unlink()

    def test_invalid_planned_phase_is_detected(self):
        path = _write_temp_definitions([_valid_entry(planned_phase="Phase 99")])
        try:
            with self.assertRaises(fetch.SourceDefinitionError) as ctx:
                fetch.load_source_definitions(path=path)
            self.assertIn("planned_phase", str(ctx.exception))
        finally:
            path.unlink()

    def test_invalid_collection_frequency_is_detected(self):
        path = _write_temp_definitions([_valid_entry(collection_frequency="hourly")])
        try:
            with self.assertRaises(fetch.SourceDefinitionError) as ctx:
                fetch.load_source_definitions(path=path)
            self.assertIn("collection_frequency", str(ctx.exception))
        finally:
            path.unlink()

    def test_invalid_collection_method_is_detected(self):
        path = _write_temp_definitions([_valid_entry(collection_method="ftp")])
        try:
            with self.assertRaises(fetch.SourceDefinitionError) as ctx:
                fetch.load_source_definitions(path=path)
            self.assertIn("collection_method", str(ctx.exception))
        finally:
            path.unlink()

    def test_missing_url_for_url_required_method_is_detected(self):
        path = _write_temp_definitions([_valid_entry(url="")])
        try:
            with self.assertRaises(fetch.SourceDefinitionError) as ctx:
                fetch.load_source_definitions(path=path)
            self.assertIn("URL", str(ctx.exception))
        finally:
            path.unlink()

    def test_non_bool_enabled_is_detected(self):
        path = _write_temp_definitions([_valid_entry(enabled="true")])
        try:
            with self.assertRaises(fetch.SourceDefinitionError) as ctx:
                fetch.load_source_definitions(path=path)
            self.assertIn("enabled", str(ctx.exception))
        finally:
            path.unlink()


class CompatLayerTest(unittest.TestCase):
    def test_disabled_source_excluded_from_rss_feeds(self):
        sources = [
            _valid_entry(id="a", name="A", enabled=True),
            _valid_entry(id="b", name="B", enabled=False),
        ]
        result = fetch.build_rss_feeds(sources)
        names = [name for name, _, _ in result]
        self.assertIn("A", names)
        self.assertNotIn("B", names)

    def test_non_rss_method_excluded_from_rss_feeds(self):
        sources = [
            _valid_entry(id="a", name="A", collection_method="rss"),
            _valid_entry(id="b", name="B", collection_method="cisa_kev_json"),
        ]
        result = fetch.build_rss_feeds(sources)
        names = [name for name, _, _ in result]
        self.assertIn("A", names)
        self.assertNotIn("B", names)

    def test_rss_feeds_names_and_order_match_baseline(self):
        baseline_names = [name for name, _, _ in BASELINE_RSS_FEEDS]
        current_names = [name for name, _, _ in fetch.RSS_FEEDS]
        self.assertEqual(current_names, baseline_names)

    def test_rss_feeds_fully_match_baseline(self):
        self.assertEqual(fetch.RSS_FEEDS, BASELINE_RSS_FEEDS)

    def test_trusted_cyber_sources_match_baseline(self):
        self.assertEqual(fetch.TRUSTED_CYBER_SOURCES, BASELINE_TRUSTED_CYBER_SOURCES)

    def test_source_colors_match_baseline(self):
        all_names = (
            set(BASELINE_SOURCE_COLORS)
            | set(fetch.SOURCE_COLORS)
            | {name for name, _, _ in BASELINE_RSS_FEEDS}
        )
        for name in all_names:
            with self.subTest(name=name):
                self.assertEqual(
                    BASELINE_SOURCE_COLORS.get(name, "#555"),
                    fetch.SOURCE_COLORS.get(name, "#555"),
                )


if __name__ == "__main__":
    unittest.main()
