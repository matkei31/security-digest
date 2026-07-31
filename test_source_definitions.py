#!/usr/bin/env python3
"""
source_definitions.json の読み込み・検証・互換レイヤーの回帰テスト (Ticket 2)
標準ライブラリの unittest のみを使用する。
"""

import json
import os
import re
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import fetch


# Ticket 2 着手前 (source_definitions.json 導入前) の fetch.py にハードコードされて
# いた値そのもの。Ticket 2当時の履歴的baselineであり、以後のチケットによる
# 意図的な取得対象変更のためにこの値自体は改変しない(fetch.RSS_FEEDSとの直接比較
# には使わず、EXPECTED_ACTIVE_RSS_FEEDSとの差分検証にのみ用いる)。
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

# 「CISA取得経路の整理」チケットにより、CISA(id="cisa")は意図的に無効化
# (enabled=false)され、現在のactive RSS一覧から除外されている。これは
# BASELINE_RSS_FEEDS(Ticket 2当時の履歴的baseline、上記)からの意図的な差分で
# あり、単なるテストのバイパスではない(CisaDeliberatelyExcludedFromActiveRssTest
# 参照)。CISA自体のsource定義はsource_definitions.json上に削除されず残り、
# trusted_cyber_source・色等の履歴的メタデータも維持される。
#
# BL-030(取得元・翻訳経路の緊急リスク低減)により、CrowdStrike(id="crowdstrike")・
# Cloudflare(id="cloudflare")も、公式規約の適用範囲・許諾が確認できるまでの
# 暫定停止として意図的に無効化(enabled=false)され、active RSS一覧から除外
# されている(Bl030SourceRiskContainmentTest参照)。両source自体の定義は
# source_definitions.json上に削除されず残り、trusted_cyber_source・色等の
# 履歴的メタデータも維持される。
#
# BL-031(全取得元の公式規約監査とセキュリティ文書整合化)により、Dark Reading
# (id="dark_reading")も、Informa TechTarget Termsの確認結果に基づく暫定停止
# として意図的に無効化(enabled=false)され、active RSS一覧から除外されている
# (Bl031SourceTermsAuditTest参照)。source自体の定義はsource_definitions.json
# 上に削除されず残り、trusted_cyber_source・色等の履歴的メタデータも維持される。
EXPECTED_ACTIVE_RSS_FEEDS = [
    entry for entry in BASELINE_RSS_FEEDS
    if entry[0] not in ("CISA", "CrowdStrike", "Cloudflare", "Dark Reading")
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


# BL-032: バリデーションを通る最小構成のpolicyオブジェクト(structured_open相当)。
_VALID_POLICY = {
    "content_usage_mode": "structured_open",
    "allow_network_fetch": True,
    "allow_description": True,
    "allow_rich_content": False,
    "allow_ai_processing": True,
    "allow_excerpt_storage": True,
    "allow_public_summary": True,
    "attribution_requirement": "test fixture attribution",
    "attribution_url": None,
    "checked_at": "2026-07-29",
    "confidence": "high",
    "unresolved_issue": "",
    "recheck_trigger": "test fixture",
    "official_evidence_url": "https://example.com/terms",
    "evidence_type": "terms",
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
        "policy": dict(_VALID_POLICY),
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


class CollectionUrlValidationTest(unittest.TestCase):
    """外部取得用urlだけにabsolute HTTP(S)境界を適用するBL-025契約。"""

    def _load_one(self, **overrides):
        path = _write_temp_definitions([_valid_entry(**overrides)])
        try:
            return fetch.load_source_definitions(path=path)
        finally:
            path.unlink()

    def test_http_and_https_absolute_urls_are_accepted(self):
        valid_urls = (
            "http://example.com/feed.xml",
            "https://example.com/feed.xml",
            "https://example.com:8443/feed.xml",
            "https://example.com/feed.xml?format=rss",
            "HTTPS://EXAMPLE.com/feed.xml",
        )
        for url in valid_urls:
            with self.subTest(url=url):
                sources = self._load_one(url=url)
                self.assertEqual(sources[0]["url"], url)

    def test_every_url_required_collection_method_accepts_https(self):
        self.assertEqual(fetch.ALLOWED_COLLECTION_URL_SCHEMES, {"http", "https"})
        self.assertEqual(
            fetch.URL_REQUIRED_COLLECTION_METHODS,
            fetch.VALID_COLLECTION_METHODS,
        )
        for method in fetch.URL_REQUIRED_COLLECTION_METHODS:
            with self.subTest(method=method):
                sources = self._load_one(
                    collection_method=method,
                    url=f"https://example.com/{method}",
                    enabled=False,
                )
                self.assertEqual(sources[0]["collection_method"], method)

    def test_disabled_source_still_validates_and_accepts_a_valid_url(self):
        sources = self._load_one(
            id="disabled_source",
            enabled=False,
            url="http://example.com:8080/feed?disabled=true",
        )
        self.assertFalse(sources[0]["enabled"])

    def test_invalid_collection_urls_are_rejected_with_stable_context(self):
        invalid_urls = (
            "file:///etc/passwd",
            "ftp://example.com/feed",
            "data:text/plain,hello",
            "javascript:alert(1)",
            "mailto:security@example.com",
            "//example.com/feed",
            "feed.xml",
            "/feed.xml",
            "https:/feed.xml",
            "https://",
            "",
            "   ",
            " https://example.com/feed ",
            None,
            123,
            ["https://example.com/feed"],
            {"url": "https://example.com/feed"},
        )
        for url in invalid_urls:
            with self.subTest(url=url):
                path = _write_temp_definitions([
                    _valid_entry(id="invalid_url_source", url=url)
                ])
                try:
                    with self.assertRaises(fetch.SourceDefinitionError) as ctx:
                        fetch.load_source_definitions(path=path)
                    message = str(ctx.exception)
                    self.assertIn("sources[0]", message)
                    self.assertIn("invalid_url_source", message)
                    self.assertIn("url", message)
                    self.assertIn("http", message)
                    self.assertIn("https", message)
                finally:
                    path.unlink()

    def test_non_http_scheme_is_rejected_for_every_url_required_method(self):
        for method in fetch.URL_REQUIRED_COLLECTION_METHODS:
            with self.subTest(method=method):
                path = _write_temp_definitions([
                    _valid_entry(
                        id=f"invalid_{method}",
                        collection_method=method,
                        url="ftp://example.com/source",
                        enabled=False,
                    )
                ])
                try:
                    with self.assertRaises(fetch.SourceDefinitionError):
                        fetch.load_source_definitions(path=path)
                finally:
                    path.unlink()

    @patch("fetch.urllib.request.urlopen")
    def test_invalid_url_fails_before_any_external_request(self, mock_urlopen):
        path = _write_temp_definitions([
            _valid_entry(id="pre_request_failure", url="file:///etc/passwd")
        ])
        try:
            with self.assertRaises(fetch.SourceDefinitionError):
                fetch.load_source_definitions(path=path)
            mock_urlopen.assert_not_called()
        finally:
            path.unlink()

    def test_display_url_is_not_treated_as_a_collection_endpoint(self):
        # disabledの表示用値は取得にも公開にも使われない。collection urlだけを
        # BL-025 validatorへ渡し、display_urlの既存presence契約は変更しない。
        sources = self._load_one(
            id="cisa_kev",
            name="CISA KEV",
            collection_method="cisa_kev_json",
            enabled=False,
            url="https://example.com/kev.json",
            display_url="relative-display-reference",
        )
        self.assertEqual(sources[0]["display_url"], "relative-display-reference")

    def test_structured_source_urls_remain_unchanged(self):
        cisa_kev = fetch.get_source_definition(fetch.SOURCE_DEFINITIONS, "cisa_kev")
        nist_nvd = fetch.get_source_definition(fetch.SOURCE_DEFINITIONS, "nist_nvd")
        self.assertEqual(
            cisa_kev["url"],
            "https://raw.githubusercontent.com/cisagov/kev-data/develop/"
            "known_exploited_vulnerabilities.json",
        )
        self.assertEqual(
            nist_nvd["url"],
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
        )


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

    def test_rss_feeds_names_and_order_match_expected_active(self):
        # 「CISA取得経路の整理」チケット以降、有効なactive RSS一覧は
        # BASELINE_RSS_FEEDS(Ticket 2当時の履歴的baseline)そのものではなく、
        # CISAを意図的に除いたEXPECTED_ACTIVE_RSS_FEEDSと一致する。
        expected_names = [name for name, _, _ in EXPECTED_ACTIVE_RSS_FEEDS]
        current_names = [name for name, _, _ in fetch.RSS_FEEDS]
        self.assertEqual(current_names, expected_names)

    def test_rss_feeds_fully_match_expected_active(self):
        self.assertEqual(fetch.RSS_FEEDS, EXPECTED_ACTIVE_RSS_FEEDS)

    def test_trusted_cyber_sources_match_baseline(self):
        self.assertEqual(fetch.TRUSTED_CYBER_SOURCES, BASELINE_TRUSTED_CYBER_SOURCES)

    def test_source_definition_colors_match_baseline(self):
        current_colors = {
            source["name"]: source["color"]
            for source in fetch.SOURCE_DEFINITIONS
        }
        all_names = (
            set(BASELINE_SOURCE_COLORS)
            | set(current_colors)
            | {name for name, _, _ in BASELINE_RSS_FEEDS}
        )
        for name in all_names:
            with self.subTest(name=name):
                self.assertEqual(
                    BASELINE_SOURCE_COLORS.get(name, "#555"),
                    current_colors.get(name, "#555"),
                )


class CisaDeliberatelyExcludedFromActiveRssTest(unittest.TestCase):
    """「CISA取得経路の整理」チケット: CISA RSS(id="cisa")はTicket 13c以降の
    本番runで継続してHTTP 403となっており、有効な取得元として扱い続けることを
    やめるため、意図的にenabled=falseへ変更した。BASELINE_RSS_FEEDSの単なる
    ドリフトではなく、CISAだけが意図的にactive RSS一覧から除外されたことを
    ここで明示的に検証する。CISA自体のsource定義・trusted_cyber_source・色等の
    履歴的メタデータは削除せず維持する。
    """

    def _cisa_def(self):
        return fetch.get_source_definition(fetch.SOURCE_DEFINITIONS, "cisa")

    def test_1_cisa_is_disabled(self):
        self.assertFalse(self._cisa_def()["enabled"])

    def test_2_cisa_planned_phase_is_hold(self):
        self.assertEqual(self._cisa_def()["planned_phase"], "保留")

    def test_3_cisa_activation_condition_is_documented(self):
        condition = self._cisa_def()["activation_condition"]
        self.assertTrue(condition.strip())
        # 再有効化条件に必須の4要素が明記されていること。
        for required_phrase in (
            "機械可読な広範アドバイザリー取得経路",
            "GitHub Actions",
            "第三者プロキシ",
            "2025年5月",
        ):
            self.assertIn(required_phrase, condition)

    def test_4_disabled_cisa_is_not_in_active_rss_feeds(self):
        names = [name for name, _, _ in fetch.RSS_FEEDS]
        self.assertNotIn("CISA", names)
        # 現在のactive RSS一覧は、CISAを意図的に除いたEXPECTED_ACTIVE_RSS_FEEDS
        # と一致する(他ソースの順序・内容は不変)。
        expected_names = [name for name, _, _ in EXPECTED_ACTIVE_RSS_FEEDS]
        self.assertEqual(names, expected_names)

    def test_diff_between_ticket2_baseline_and_current_active_rss_is_cisa_and_bl030_and_bl031_only(self):
        # Ticket 2当時の履歴的baseline(BASELINE_RSS_FEEDS)と、現在のfetch.RSS_FEEDS
        # との差分が、CISAの除外(「CISA取得経路の整理」チケット)、BL-030による
        # CrowdStrike・Cloudflareの暫定停止、BL-031によるDark Readingの暫定停止
        # だけであることを明示的に検証する(他ソースが意図せず増減・変更されて
        # いないことの保証)。
        baseline_names = [name for name, _, _ in BASELINE_RSS_FEEDS]
        current_names = [name for name, _, _ in fetch.RSS_FEEDS]
        removed = set(baseline_names) - set(current_names)
        added = set(current_names) - set(baseline_names)
        self.assertEqual(removed, {"CISA", "CrowdStrike", "Cloudflare", "Dark Reading"})
        self.assertEqual(added, set())
        # CISA・CrowdStrike・Cloudflare・Dark Readingを除けば、残りのソースの
        # 順序・内容も完全一致する。
        self.assertEqual(
            [name for name in baseline_names
             if name not in ("CISA", "CrowdStrike", "Cloudflare", "Dark Reading")],
            current_names,
        )

    def test_5_cisa_definition_remains_in_source_definitions(self):
        # source定義自体は削除されず、SOURCE_DEFINITIONSに残り続ける。
        self.assertIsNotNone(self._cisa_def())
        ids = [s["id"] for s in fetch.SOURCE_DEFINITIONS]
        self.assertIn("cisa", ids)

    def test_cisa_historical_metadata_is_preserved(self):
        cisa_def = self._cisa_def()
        self.assertEqual(cisa_def["source_tier"], "Tier 1")
        self.assertTrue(cisa_def["trusted_cyber_source"])
        self.assertEqual(cisa_def["color"], "#1e8449")
        self.assertEqual(cisa_def["url"], "https://www.cisa.gov/cybersecurity-advisories/all.xml")

    def test_cisa_notes_record_the_403_history(self):
        notes = self._cisa_def()["notes"]
        for required_phrase in (
            "403",
            "2026-07-11",
            "User-Agent",
            "cisa_kev",
        ):
            self.assertIn(required_phrase, notes)

    def test_cisa_still_counted_as_trusted_cyber_source_despite_being_disabled(self):
        # trusted_cyber_sourceは維持されるため、enabled有無に関わらずCISAは
        # TRUSTED_CYBER_SOURCESへ残り続ける(build_trusted_cyber_sourcesは
        # enabled状態を見ない設計のため)。
        self.assertIn("CISA", fetch.TRUSTED_CYBER_SOURCES)


class CisaKevGitHubMirrorTest(unittest.TestCase):
    """「CISA取得経路の整理」チケット: CISA KEVの取得元をCISA公式GitHub
    Organization(cisagov/kev-data)のミラーJSONへ変更したことの回帰テスト。"""

    NEW_KEV_URL = (
        "https://raw.githubusercontent.com/cisagov/kev-data/develop/"
        "known_exploited_vulnerabilities.json"
    )

    def _cisa_kev_def(self):
        return fetch.get_source_definition(fetch.SOURCE_DEFINITIONS, "cisa_kev")

    def test_6_cisa_kev_remains_enabled(self):
        self.assertTrue(self._cisa_kev_def()["enabled"])

    def test_7_cisa_kev_url_is_the_official_github_json(self):
        self.assertEqual(self._cisa_kev_def()["url"], self.NEW_KEV_URL)

    def test_8_display_url_is_unchanged(self):
        self.assertEqual(
            self._cisa_kev_def()["display_url"],
            "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        )

    def test_cisa_kev_collection_method_and_tier_unchanged(self):
        cisa_kev_def = self._cisa_kev_def()
        self.assertEqual(cisa_kev_def["collection_method"], "cisa_kev_json")
        self.assertEqual(cisa_kev_def["source_tier"], "Tier 1")
        self.assertEqual(cisa_kev_def["color"], "#e74c3c")


class NonRssSourceDispatchTest(unittest.TestCase):
    """CISA KEV・NIST NVD等、非RSSソースのURL/enabledがsource_definitions.json
    由来であることを、外部APIを実際に呼ばずに検証する(fetch_cisa_kev/fetch_nist_nvd
    をモックに差し替える)。"""

    def _sources(self, cisa_kev_enabled, nist_nvd_enabled):
        return [
            {
                "id": "cisa_kev",
                "name": "CISA KEV",
                "url": "https://example.com/kev.json",
                "display_url": "https://example.com/kev-catalog",
                "collection_method": "cisa_kev_json",
                "enabled": cisa_kev_enabled,
                "policy": dict(_VALID_POLICY),
            },
            {
                "id": "nist_nvd",
                "name": "NIST NVD",
                "url": "https://example.com/nvd-base",
                "collection_method": "nist_nvd_json",
                "enabled": nist_nvd_enabled,
                "policy": dict(_VALID_POLICY),
            },
        ]

    @patch("fetch.fetch_nist_nvd")
    @patch("fetch.fetch_cisa_kev")
    def test_cisa_kev_enabled_is_fetched_with_json_url(self, mock_kev, mock_nvd):
        mock_kev.return_value = [{"source": "CISA KEV"}]
        sources = self._sources(cisa_kev_enabled=True, nist_nvd_enabled=False)

        result = fetch.collect_non_rss_items(fetch.datetime.datetime.utcnow(), sources)

        mock_kev.assert_called_once()
        self.assertEqual(mock_kev.call_args.kwargs["url"], "https://example.com/kev.json")
        self.assertEqual(mock_kev.call_args.kwargs["display_url"], "https://example.com/kev-catalog")
        self.assertEqual(mock_kev.call_args.kwargs["source_name"], "CISA KEV")
        mock_nvd.assert_not_called()
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["source"], "CISA KEV")
        self.assertEqual(result[0]["source_id"], "cisa_kev")
        self.assertTrue(result[0]["content_policy"]["ai_eligible"])

    @patch("fetch.fetch_nist_nvd")
    @patch("fetch.fetch_cisa_kev")
    def test_cisa_kev_disabled_is_not_fetched(self, mock_kev, mock_nvd):
        sources = self._sources(cisa_kev_enabled=False, nist_nvd_enabled=False)

        result = fetch.collect_non_rss_items(fetch.datetime.datetime.utcnow(), sources)

        mock_kev.assert_not_called()
        self.assertEqual(result, [])

    @patch("fetch.fetch_nist_nvd")
    @patch("fetch.fetch_cisa_kev")
    def test_nist_nvd_disabled_is_not_fetched(self, mock_kev, mock_nvd):
        sources = self._sources(cisa_kev_enabled=False, nist_nvd_enabled=False)

        fetch.collect_non_rss_items(fetch.datetime.datetime.utcnow(), sources)

        mock_nvd.assert_not_called()

    @patch("fetch.fetch_nist_nvd")
    @patch("fetch.fetch_cisa_kev")
    def test_nist_nvd_enabled_is_fetched_with_json_url(self, mock_kev, mock_nvd):
        mock_nvd.return_value = [{"source": "NIST NVD"}]
        sources = self._sources(cisa_kev_enabled=False, nist_nvd_enabled=True)

        result = fetch.collect_non_rss_items(fetch.datetime.datetime.utcnow(), sources)

        mock_nvd.assert_called_once()
        self.assertEqual(mock_nvd.call_args.kwargs["base_url"], "https://example.com/nvd-base")
        self.assertEqual(mock_nvd.call_args.kwargs["source_name"], "NIST NVD")
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["source"], "NIST NVD")
        self.assertEqual(result[0]["source_id"], "nist_nvd")
        self.assertTrue(result[0]["content_policy"]["ai_eligible"])

    def test_real_definitions_cisa_kev_enabled_and_nist_nvd_disabled(self):
        # 実際のsource_definitions.jsonにおける現状のenabled値を確認する
        # (「今回の修正で実際の取得対象は変えない」の裏付け)
        cisa_kev_def = fetch.get_source_definition(fetch.SOURCE_DEFINITIONS, "cisa_kev")
        nist_nvd_def = fetch.get_source_definition(fetch.SOURCE_DEFINITIONS, "nist_nvd")
        self.assertTrue(cisa_kev_def["enabled"])
        self.assertFalse(nist_nvd_def["enabled"])


class NoDuplicateUrlInSourceCodeTest(unittest.TestCase):
    """CISA KEV・NIST NVDの取得元URLが、fetch.pyのソースコード中に
    ハードコードされたまま残っていない(source_definitions.jsonのみに存在する)
    ことを確認する。"""

    NEW_CISA_KEV_URL = (
        "https://raw.githubusercontent.com/cisagov/kev-data/develop/"
        "known_exploited_vulnerabilities.json"
    )
    OLD_CISA_KEV_URL = (
        "https://www.cisa.gov/sites/default/files/feeds/"
        "known_exploited_vulnerabilities.json"
    )

    def setUp(self):
        self.fetch_source_text = Path(fetch.__file__).read_text(encoding="utf-8")

    def test_cisa_kev_json_url_not_hardcoded_in_fetch_py(self):
        # 「CISA取得経路の整理」チケットで採用したCISA公式GitHubミラーURL。
        self.assertNotIn(self.NEW_CISA_KEV_URL, self.fetch_source_text)

    def test_old_cisa_kev_json_url_not_hardcoded_in_fetch_py(self):
        # 旧urlも(元々hardcodeされていなかったが)引き続き含まれないことを確認する。
        self.assertNotIn(self.OLD_CISA_KEV_URL, self.fetch_source_text)

    def test_cisa_kev_display_url_not_hardcoded_in_fetch_py(self):
        display_url = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
        self.assertNotIn(display_url, self.fetch_source_text)

    def test_nist_nvd_base_url_not_hardcoded_in_fetch_py(self):
        nvd_base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.assertNotIn(nvd_base_url, self.fetch_source_text)

    def test_9_new_cisa_kev_url_is_defined_exactly_once_in_source_definitions_json(self):
        definitions_text = (Path(fetch.__file__).parent / "source_definitions.json").read_text(
            encoding="utf-8"
        )
        self.assertEqual(definitions_text.count(self.NEW_CISA_KEV_URL), 1)

    def test_old_cisa_kev_url_no_longer_present_in_source_definitions_json(self):
        definitions_text = (Path(fetch.__file__).parent / "source_definitions.json").read_text(
            encoding="utf-8"
        )
        self.assertEqual(definitions_text.count(self.OLD_CISA_KEV_URL), 0)

    def test_nvd_base_url_is_defined_exactly_once_in_source_definitions_json(self):
        definitions_text = (Path(fetch.__file__).parent / "source_definitions.json").read_text(
            encoding="utf-8"
        )
        nvd_base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.assertEqual(definitions_text.count(nvd_base_url), 1)


class SourceDefinitionsPathTest(unittest.TestCase):
    """source_definitions.json の読み込みパスが、実行時のカレントディレクトリに
    依存せずfetch.py配置ディレクトリを基準にしていることを確認する。"""

    def test_path_is_absolute(self):
        self.assertTrue(fetch.SOURCE_DEFINITIONS_PATH.is_absolute())

    def test_path_points_next_to_fetch_py(self):
        expected_dir = Path(fetch.__file__).resolve().parent
        self.assertEqual(fetch.SOURCE_DEFINITIONS_PATH.parent, expected_dir)

    def test_default_load_succeeds_regardless_of_cwd(self):
        original_cwd = os.getcwd()
        try:
            os.chdir(tempfile.gettempdir())
            sources = fetch.load_source_definitions()
            self.assertEqual(len(sources), 17)
        finally:
            os.chdir(original_cwd)


class NonRssSourceSpecificValidationTest(unittest.TestCase):
    """CISA KEV固有のdisplay_url必須チェック、およびcollect_non_rss_itemsが
    参照するsource IDが定義に存在しない場合の明確なエラーを確認する。"""

    def test_cisa_kev_enabled_without_display_url_is_rejected(self):
        entry = _valid_entry(
            id="cisa_kev", name="CISA KEV",
            collection_method="cisa_kev_json", enabled=True,
        )
        entry.pop("display_url", None)  # display_url未設定
        path = _write_temp_definitions([entry])
        try:
            with self.assertRaises(fetch.SourceDefinitionError) as ctx:
                fetch.load_source_definitions(path=path)
            self.assertIn("display_url", str(ctx.exception))
            self.assertIn("cisa_kev", str(ctx.exception))
        finally:
            path.unlink()

    def test_cisa_kev_enabled_with_empty_display_url_is_rejected(self):
        entry = _valid_entry(
            id="cisa_kev", name="CISA KEV",
            collection_method="cisa_kev_json", enabled=True,
            display_url="",
        )
        path = _write_temp_definitions([entry])
        try:
            with self.assertRaises(fetch.SourceDefinitionError) as ctx:
                fetch.load_source_definitions(path=path)
            self.assertIn("display_url", str(ctx.exception))
        finally:
            path.unlink()

    def test_cisa_kev_disabled_without_display_url_is_accepted(self):
        # enabled=falseならdisplay_url未設定でもロードエラーにならない
        entry = _valid_entry(
            id="cisa_kev", name="CISA KEV",
            collection_method="cisa_kev_json", enabled=False,
        )
        entry.pop("display_url", None)
        path = _write_temp_definitions([entry])
        try:
            sources = fetch.load_source_definitions(path=path)
            self.assertEqual(len(sources), 1)
        finally:
            path.unlink()

    def test_cisa_kev_enabled_with_display_url_is_accepted(self):
        entry = _valid_entry(
            id="cisa_kev", name="CISA KEV",
            collection_method="cisa_kev_json", enabled=True,
            display_url="https://example.com/catalog",
        )
        path = _write_temp_definitions([entry])
        try:
            sources = fetch.load_source_definitions(path=path)
            self.assertEqual(len(sources), 1)
        finally:
            path.unlink()

    def test_real_cisa_kev_definition_has_display_url(self):
        cisa_kev_def = fetch.get_source_definition(fetch.SOURCE_DEFINITIONS, "cisa_kev")
        self.assertTrue(cisa_kev_def.get("display_url"))

    def test_missing_cisa_kev_id_raises_clear_error(self):
        sources = [
            {
                "id": "nist_nvd", "name": "NIST NVD",
                "url": "https://example.com/nvd-base",
                "collection_method": "nist_nvd_json", "enabled": False,
            },
        ]
        with self.assertRaises(fetch.SourceDefinitionError) as ctx:
            fetch.collect_non_rss_items(fetch.datetime.datetime.utcnow(), sources)
        self.assertIn("cisa_kev", str(ctx.exception))

    def test_missing_nist_nvd_id_raises_clear_error(self):
        sources = [
            {
                "id": "cisa_kev", "name": "CISA KEV",
                "url": "https://example.com/kev.json",
                "display_url": "https://example.com/kev-catalog",
                "collection_method": "cisa_kev_json", "enabled": False,
            },
        ]
        with self.assertRaises(fetch.SourceDefinitionError) as ctx:
            fetch.collect_non_rss_items(fetch.datetime.datetime.utcnow(), sources)
        self.assertIn("nist_nvd", str(ctx.exception))


class Bl030SourceRiskContainmentTest(unittest.TestCase):
    """BL-030: 取得元・翻訳経路の緊急リスク低減。CrowdStrike・Cloudflareの暫定停止と
    source総数・enabled/disabled件数の契約を検証する。最終的な法的判断ではなく、
    公式規約確認までの暫定的なリスク低減であることを前提とする。
    """

    def _def(self, source_id):
        return fetch.get_source_definition(fetch.SOURCE_DEFINITIONS, source_id)

    def test_source_total_count_is_17(self):
        self.assertEqual(len(fetch.SOURCE_DEFINITIONS), 17)

    def test_enabled_12_disabled_5(self):
        # BL-031がDark Readingを追加で暫定停止したため、BL-030完了直後の
        # 13 enabled/4 disabledから12 enabled/5 disabledに変わっている。
        # このクラスはBL-030固有の契約(CrowdStrike・Cloudflareの暫定停止)を
        # 検証するものだが、総数はfetch.SOURCE_DEFINITIONSの現在値に追従する。
        enabled = [s for s in fetch.SOURCE_DEFINITIONS if s["enabled"]]
        disabled = [s for s in fetch.SOURCE_DEFINITIONS if not s["enabled"]]
        self.assertEqual(len(enabled), 12)
        self.assertEqual(len(disabled), 5)
        self.assertEqual(
            {s["id"] for s in disabled},
            {"cisa", "crowdstrike", "cloudflare", "nist_nvd", "dark_reading"},
        )

    def test_crowdstrike_is_disabled_with_documented_activation_condition(self):
        crowdstrike = self._def("crowdstrike")
        self.assertFalse(crowdstrike["enabled"])
        self.assertEqual(crowdstrike["planned_phase"], "保留")
        condition = crowdstrike["activation_condition"]
        self.assertTrue(condition.strip())
        self.assertIn("許諾", condition)
        self.assertIn("再有効化しない", condition)

    def test_cloudflare_is_disabled_with_documented_activation_condition(self):
        cloudflare = self._def("cloudflare")
        self.assertFalse(cloudflare["enabled"])
        self.assertEqual(cloudflare["planned_phase"], "保留")
        condition = cloudflare["activation_condition"]
        self.assertTrue(condition.strip())
        self.assertIn("robots.txt", condition)
        self.assertIn("再有効化しない", condition)

    def test_cloudflare_activation_condition_requires_both_robots_allow_and_ai_only_user_agent(self):
        # BL-030修正: 書面許諾がない限り、(1) robots.txtでの明示的allowと
        # (2) AI用途bot専用(多目的でない)User-Agentの両方を要求する。
        condition = self._def("cloudflare")["activation_condition"]
        self.assertIn("robots.txtで明示的にallowed", condition)
        self.assertIn("AI用途botの識別だけに使用", condition)
        self.assertIn("多目的User-Agentではなく", condition)
        self.assertIn("書面による明示的な許諾", condition)

    def test_crowdstrike_and_cloudflare_notes_state_it_is_not_a_final_legal_determination(self):
        for source_id in ("crowdstrike", "cloudflare"):
            with self.subTest(source_id=source_id):
                notes = self._def(source_id)["notes"]
                self.assertIn("法的違反を確定したものではなく", notes)
                self.assertIn("BL-030", notes)

    def test_crowdstrike_and_cloudflare_unrelated_fields_are_unchanged(self):
        # trusted_cyber_source・color・source_tier・source_type・language・urlは、
        # 無効化に不要なためBL-030では変更していない。
        crowdstrike = self._def("crowdstrike")
        self.assertTrue(crowdstrike["trusted_cyber_source"])
        self.assertEqual(crowdstrike["color"], "#cc0000")
        self.assertEqual(crowdstrike["source_tier"], "Tier 2")
        self.assertEqual(crowdstrike["url"], "https://www.crowdstrike.com/blog/feed/")

        cloudflare = self._def("cloudflare")
        self.assertFalse(cloudflare["trusted_cyber_source"])
        self.assertEqual(cloudflare["color"], "#f38020")
        self.assertEqual(cloudflare["source_tier"], "Tier 2")
        self.assertEqual(cloudflare["url"], "https://blog.cloudflare.com/rss/")

    def test_crowdstrike_and_cloudflare_excluded_from_rss_feeds(self):
        names = [name for name, _, _ in fetch.RSS_FEEDS]
        self.assertNotIn("CrowdStrike", names)
        self.assertNotIn("Cloudflare", names)

    def test_crowdstrike_and_cloudflare_excluded_from_footer_sources(self):
        footer_ids = [s["id"] for s in fetch.build_footer_sources(fetch.SOURCE_DEFINITIONS)]
        self.assertNotIn("crowdstrike", footer_ids)
        self.assertNotIn("cloudflare", footer_ids)

    def test_cisa_kev_still_enabled(self):
        self.assertTrue(self._def("cisa_kev")["enabled"])

    def test_cisa_and_nist_nvd_unchanged_by_bl030(self):
        self.assertFalse(self._def("cisa")["enabled"])
        self.assertFalse(self._def("nist_nvd")["enabled"])

    def test_no_unofficial_translation_endpoint_string_remains_in_fetch_py(self):
        text = Path(fetch.__file__).read_text(encoding="utf-8")
        self.assertNotIn("translate.googleapis.com/translate_a/single", text)
        self.assertNotIn("client=gtx", text)

    def test_translate_cache_json_does_not_exist_in_docs(self):
        repo_root = Path(fetch.__file__).resolve().parent
        self.assertFalse((repo_root / "docs" / "translate_cache.json").exists())

    def test_translate_and_cache_functions_are_removed(self):
        self.assertFalse(hasattr(fetch, "translate"))
        self.assertFalse(hasattr(fetch, "load_cache"))
        self.assertFalse(hasattr(fetch, "save_cache"))
        self.assertFalse(hasattr(fetch, "CACHE_PATH"))


class Bl031SourceTermsAuditTest(unittest.TestCase):
    """BL-031: 全取得元の公式規約監査によるDark Reading暫定停止と、
    source総数・enabled/disabled件数・他sourceの不変性を検証する。監査・文書
    整合化のみが本Ticketのscopeであり、`content_usage_mode`等のfield追加や
    fetch.py側のenforcement実装は行わない(BL-032へ委譲)ことを前提とする。
    """

    def _def(self, source_id):
        return fetch.get_source_definition(fetch.SOURCE_DEFINITIONS, source_id)

    def test_source_total_count_is_17(self):
        self.assertEqual(len(fetch.SOURCE_DEFINITIONS), 17)

    def test_enabled_12_disabled_5(self):
        enabled = [s for s in fetch.SOURCE_DEFINITIONS if s["enabled"]]
        disabled = [s for s in fetch.SOURCE_DEFINITIONS if not s["enabled"]]
        self.assertEqual(len(enabled), 12)
        self.assertEqual(len(disabled), 5)
        self.assertEqual(
            {s["id"] for s in disabled},
            {"cisa", "crowdstrike", "cloudflare", "nist_nvd", "dark_reading"},
        )

    def test_dark_reading_is_disabled_with_documented_activation_condition(self):
        dark_reading = self._def("dark_reading")
        self.assertFalse(dark_reading["enabled"])
        self.assertEqual(dark_reading["planned_phase"], "保留")
        condition = dark_reading["activation_condition"]
        self.assertTrue(condition.strip())
        self.assertIn("Informa TechTarget", condition)
        self.assertIn("再有効化しない", condition)

    def test_dark_reading_notes_cite_bl031_terms_url_and_not_a_legal_determination(self):
        notes = self._def("dark_reading")["notes"]
        self.assertIn("BL-031", notes)
        self.assertIn("2026-07-29確認", notes)
        self.assertIn("informatechtarget.com/terms-of-use", notes)
        self.assertIn("法的違反を確定したものではなく", notes)

    def test_dark_reading_excluded_from_rss_feeds_and_footer(self):
        names = [name for name, _, _ in fetch.RSS_FEEDS]
        self.assertNotIn("Dark Reading", names)
        footer_ids = [s["id"] for s in fetch.build_footer_sources(fetch.SOURCE_DEFINITIONS)]
        self.assertNotIn("dark_reading", footer_ids)

    def test_dark_reading_unrelated_fields_are_unchanged(self):
        # BL-031はenabled／planned_phase／activation_condition／notesの追加のみを
        # 変更する。trusted_cyber_source・color・source_tier・urlは無効化に不要
        # なため変更していない。
        dark_reading = self._def("dark_reading")
        self.assertTrue(dark_reading["trusted_cyber_source"])
        self.assertEqual(dark_reading["color"], "#555")
        self.assertEqual(dark_reading["source_tier"], "Tier 2")
        self.assertEqual(dark_reading["url"], "https://www.darkreading.com/rss.xml")

    def test_other_16_sources_enabled_field_is_unchanged_by_bl031(self):
        # Dark Reading以外の16 sourceについて、BL-031前後でenabled状態が
        # 変わっていないことを確認する(CrowdStrike・Cloudflareの暫定停止は
        # BL-030由来であり、BL-031で新たに変更したものではない)。
        expected_enabled_by_id = {
            "fsa": True,
            "jpcert_cc": True,
            "ipa": True,
            "cisa": False,
            "nist": True,
            "microsoft_security": True,
            "mandiant": True,
            "crowdstrike": False,
            "google_tag": True,
            "ncsc": True,
            "krebs_on_security": True,
            "the_hacker_news": True,
            "cisco_talos": True,
            "cloudflare": False,
            "cisa_kev": True,
            "nist_nvd": False,
        }
        for source_id, expected in expected_enabled_by_id.items():
            with self.subTest(source_id=source_id):
                self.assertEqual(self._def(source_id)["enabled"], expected)

    def test_cisa_kev_still_enabled_and_nist_nvd_still_disabled(self):
        self.assertTrue(self._def("cisa_kev")["enabled"])
        self.assertFalse(self._def("nist_nvd")["enabled"])


class Bl030AcceptanceRecordTest(unittest.TestCase):
    """BL-030: ユーザー受入・完了記録(BACKLOG／STATUS／DECISIONS SD-029)の検証。"""

    REPO_ROOT = Path(__file__).resolve().parent

    @classmethod
    def setUpClass(cls):
        cls.backlog = (cls.REPO_ROOT / "BACKLOG.md").read_text(encoding="utf-8")
        cls.status = (cls.REPO_ROOT / "STATUS.md").read_text(encoding="utf-8")
        cls.decisions = (cls.REPO_ROOT / "DECISIONS.md").read_text(encoding="utf-8")

    def _section(self, text, marker, next_marker="\n## "):
        start = text.index(marker)
        rest = text[start + len(marker):]
        end = rest.find(next_marker)
        return rest if end == -1 else rest[:end]

    def test_bl030_is_recorded_as_complete(self):
        bl030 = self._section(self.backlog, "## BL-030")
        self.assertIn("- **状態:** 完了", bl030)

    def test_bl030_user_acceptance_evidence_records_pr_head_and_ci(self):
        bl030 = self._section(self.backlog, "## BL-030")
        self.assertIn("PR #66", bl030)
        self.assertIn("9757ae98c2f5ef9f13da667be5677d870a6e2cd1", bl030)
        self.assertIn("30428514818", bl030)

    def test_status_active_work_is_clear_of_bl030_bl031_bl032(self):
        # BL-032のPR #69 merge後、Active workからBL-032も外れた。BL-030・
        # BL-031・BL-032はいずれもActive workへ戻っておらず、すべて
        # Recently completed workに残っていることだけを検証する。
        active = self._section(self.status, "## Active work", "\n## 5. Recently completed work")
        self.assertNotIn("BL-030", active)
        self.assertNotIn("BL-031", active)
        self.assertNotIn("BL-032", active)
        recently_completed = self._section(
            self.status, "## 5. Recently completed work", "\n## 6. Known issues and limitations"
        )
        self.assertIn("BL-030", recently_completed)
        self.assertIn("BL-031", recently_completed)
        self.assertIn("BL-032", recently_completed)

    def test_status_never_describes_bl032_as_currently_pending(self):
        # Scoped to the specific current-state locations that once described
        # BL-032 as Draft/pending merge, not a blanket ban on these phrases
        # across all of STATUS.md -- "current Active work item",
        # "要件定義済み／未着手", and "Ready化・merge待ち" are ordinary status
        # vocabulary that a future, unrelated ticket may legitimately use
        # while it is genuinely active and pending.
        active = self._section(self.status, "## Active work", "\n## 5. Recently completed work")
        self.assertNotIn("BL-032", active)

        recently_completed = self._section(
            self.status, "## 5. Recently completed work", "\n## 6. Known issues and limitations"
        )
        self.assertIn("BL-032", recently_completed)
        bl032 = next(
            line for line in recently_completed.splitlines() if line.startswith("- BL-032 ")
        )
        self.assertTrue(
            "PR #69" in bl032 or "cd5e6ec" in bl032,
            "BL-032's Recently completed entry must record PR #69 or the merge commit",
        )

        next_candidates = self._section(self.status, "## 7. Next candidates", "\n## 8. ")
        self.assertIn("BL-032", next_candidates)
        self.assertNotIn("current Active work item", next_candidates)

        bl030 = next(
            line for line in recently_completed.splitlines() if line.startswith("- BL-030 ")
        )
        self.assertNotIn(
            "is registered and is the current Active work item, 要件定義済み／未着手",
            bl030,
        )
        self.assertIn("BL-031", bl030)
        self.assertIn("BL-032", bl030)
        self.assertIn("are both completed, approved, and merged", bl030)

    def test_sd029_is_unique(self):
        headings = re.findall(r"^## (SD-\d{3})\b", self.decisions, flags=re.MULTILINE)
        self.assertEqual(headings.count("SD-029"), 1)

    def test_sd029_records_date_status_decision_consequences_evidence(self):
        sd029 = self._section(self.decisions, "## SD-029")
        self.assertIn("- **Date:** 2026-07-29", sd029)
        self.assertIn("- **Status:** Accepted", sd029)
        self.assertIn("- **Decision:**", sd029)
        self.assertIn("- **Consequences:**", sd029)
        self.assertIn("- **Evidence:**", sd029)
        self.assertIn("PR #66", sd029)
        self.assertIn("9757ae98c2f5ef9f13da667be5677d870a6e2cd1", sd029)

    def test_sd029_does_not_assert_terms_violation(self):
        sd029 = self._section(self.decisions, "## SD-029")
        self.assertIn(
            "does not determine that CrowdStrike or Cloudflare's terms were in fact violated",
            sd029,
        )

    def test_bl030_residual_work_excludes_followup_tickets(self):
        bl030 = self._section(self.backlog, "## BL-030")
        self.assertIn("BL-030の実装上の残作業はなし", bl030)
        self.assertIn("BL-031", bl030)
        self.assertIn("後続Ticketであり、BL-030自体の残作業ではない", bl030)

    def test_bl031_scope_includes_security_doc_reconciliation(self):
        bl030 = self._section(self.backlog, "## BL-030")
        self.assertIn("SECURITY_REQUIREMENTS.md", bl030)
        self.assertIn("SECURITY_OPERATIONS.md", bl030)
        self.assertIn("BL-031", bl030)


if __name__ == "__main__":
    unittest.main()
