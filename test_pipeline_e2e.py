#!/usr/bin/env python3
"""BL-037 (Fable 5 whole-repository review R-13): pipeline integration E2E。
標準ライブラリの unittest のみを使用する。

役割の区別(既存testとの関係):
- test_archive.TopPageArchiveLinkTest.
  test_main_uses_generated_date_for_top_daily_and_archive_across_midnight:
  主要pipeline function(collect_recent・enrich_with_ai・build_todays_brief・
  build_html・daily_json.generate_and_save_daily_digest・
  generate_archive_outputs等)をすべてmockし、fetch.main()の呼出順・引数を
  検証するorchestration test(配線契約の検証)。本testはこれを置き換えない。
- 本file(Bl037PipelineE2ETest): external I/O境界(urllib.request経由の実際の
  network呼び出し)だけをdeterministicにmockし、fetch.main()を実際に呼び出して、
  収集・content usage policy適用・AI分析・vulnerability facts・Today's Brief・
  日次JSON・index.html・Archive生成までを実function間の結合として検証する
  pipeline integration E2E。
- test_repository_data.Bl037RepositoryDataValidationTest: 別fileにある、
  repositoryに保存済みの全daily JSONに対するread-only schema regression test。

今回保証しないもの: 実publisher endpointの可用性、実Gemini APIの可用性・品質、
GitHub Actions production環境そのもの、GitHub Pagesの実deploy、ブラウザ描画、
public siteの目視、記事内容の事実正確性。
"""

import datetime
import json
import os
import tempfile
import unittest
import urllib.request
from pathlib import Path
from unittest import mock

import daily_json
import fetch


JST = fetch.JST

# main()内のdatetime.datetime.now()/.utcnow()呼び出しをすべて固定値へ差し替える
# (timezone/実行日に依存しないため)。
FROZEN_UTC_NOW = datetime.datetime(2026, 8, 4, 3, 0, 0)
FROZEN_JST_NOW = datetime.datetime(2026, 8, 4, 12, 0, 0, tzinfo=JST)
EXPECTED_DIGEST_DATE = "2026-08-04"

# AI eligible(structured_open)なfixture記事: NIST。
NIST_TITLE = "E2E-MARKER-NIST-STRUCTURED-OPEN-ARTICLE"
NIST_LINK = "https://www.nist.gov/news-events/news/2026/08/e2e-marker-article"
NIST_SUMMARY = (
    "E2E pipeline integration test marker summary about a cyber security "
    "vulnerability, for a NIST structured_open article."
)
NIST_PUBDATE = "Mon, 03 Aug 2026 20:00:00 GMT"

# AI非対象(metadata_only)なfixture記事: Microsoft Security。AI非対象経路と
# source attribution表示の双方を同一run内で確認する。
MS_TITLE = "E2E-MARKER-MICROSOFT-METADATA-ONLY-ARTICLE"
MS_LINK = "https://www.microsoft.com/en-us/security/blog/2026/08/e2e-marker-metadata-only/"
MS_SUMMARY = "E2E pipeline integration test marker summary for a Microsoft metadata_only article."
MS_PUBDATE = "Mon, 03 Aug 2026 21:00:00 GMT"

GEMINI_SUMMARY_MARKER = "E2E-MARKER-GEMINI-SUMMARY-TEXT"
GEMINI_IMPACT_MARKER = "E2E-MARKER-GEMINI-FINANCIAL-IMPACT-TEXT"
GEMINI_TITLE_JA_MARKER = "E2Eパイプライン統合テストマーカー記事"
FAKE_GEMINI_API_KEY = "test-key-not-real"

GEMINI_ANALYSIS_FIXTURE = {
    "title_ja": GEMINI_TITLE_JA_MARKER,
    "category": "脆弱性・パッチ",
    "category_reason": "E2Eマーカー記事のcategory判定理由。",
    "importance": "中",
    "urgency": "参考",
    "summary": GEMINI_SUMMARY_MARKER,
    "financial_impact": GEMINI_IMPACT_MARKER,
    "recommended_actions": [],
    "reason": (
        "重要度は、E2Eパイプライン結合テストの検証目的のため「中」です。"
        "確認目安は、E2Eパイプライン結合テストの検証目的のため「参考」です。"
    ),
    "tags": [],
}

# CISA KEVカタログ: 有効なcveIDを持つ要素が0件だとカタログ自体が
# 信頼できないものとして扱われる(load_kev_catalog参照)ため、DAYS_BACKの
# cutoffより十分古いdateAddedを持つ1件だけを含め、カタログ取得は成功させつつ
# 新着記事としては採用されないようにする。
KEV_HISTORICAL_CVE_ID = "CVE-2020-00000"

ENABLED_RSS_SOURCE_IDS = (
    "fsa", "jpcert_cc", "ipa", "nist", "microsoft_security", "mandiant",
    "google_tag", "ncsc", "krebs_on_security", "the_hacker_news", "cisco_talos",
)

GEMINI_URL = (
    f"https://generativelanguage.googleapis.com/v1beta/models/"
    f"{fetch.GEMINI_MODEL}:generateContent"
)


def _empty_rss(title="Empty Feed"):
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        f"<rss version=\"2.0\"><channel><title>{title}</title>"
        "<link>https://example.invalid/</link><description>empty</description>"
        "</channel></rss>"
    ).encode("utf-8")


def _rss_with_item(title, link, summary, pub_date, feed_title="Feed"):
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        f"<rss version=\"2.0\"><channel><title>{feed_title}</title>"
        f"<item><title>{title}</title><link>{link}</link>"
        f"<description>{summary}</description><pubDate>{pub_date}</pubDate></item>"
        "</channel></rss>"
    ).encode("utf-8")


def _empty_atom(title="Empty Atom Feed"):
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        f'<feed xmlns="http://www.w3.org/2005/Atom"><title>{title}</title></feed>'
    ).encode("utf-8")


def _kev_catalog_json():
    return json.dumps({
        "vulnerabilities": [{
            "cveID": KEV_HISTORICAL_CVE_ID,
            "vulnerabilityName": "E2E-MARKER-HISTORICAL-KEV-ENTRY",
            "dateAdded": "2020-01-01",
            "shortDescription": "Historical marker entry outside the DAYS_BACK cutoff window.",
        }]
    }).encode("utf-8")


def _gemini_response_json():
    return json.dumps({
        "candidates": [{
            "content": {
                "parts": [{"text": json.dumps(GEMINI_ANALYSIS_FIXTURE, ensure_ascii=False)}]
            }
        }]
    }).encode("utf-8")


class _FrozenDateTime(datetime.datetime):
    """fetch.py内のdatetime.datetime.now()/.utcnow()呼び出しをすべて固定値へ
    差し替える。now(tz)は常にFROZEN_JST_NOWをtzへ変換した値、utcnow()は
    常にFROZEN_UTC_NOW(naive)を返す(呼び出し回数・順序に依存しない)。"""

    @classmethod
    def now(cls, tz=None):
        if tz is None:
            return FROZEN_UTC_NOW
        return FROZEN_JST_NOW.astimezone(tz)

    @classmethod
    def utcnow(cls):
        return FROZEN_UTC_NOW


class _FakeHTTPResponse:
    def __init__(self, body, url, status=200):
        self._body = body
        self._url = url
        self.status = status

    def read(self):
        return self._body

    def geturl(self):
        return self._url

    def getcode(self):
        return self.status

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        return False


def _request_url(fullurl):
    if isinstance(fullurl, urllib.request.Request):
        return fullurl.full_url
    return fullurl


class _FakeUrlRouter:
    """urllib.request.OpenerDirector.openを差し替え、登録済みURLだけへ
    deterministicな応答を返すfake router。

    urlopen()の直接呼び出し(fetch.py側)と、urlopen_fn=urllib.request.urlopenが
    def実行時にcaptureされているvulnerability_facts.py側の呼び出し(default引数
    捕捉により、urllib.request.urlopen自体を後からpatchしても遮断できない)の
    両方を、実urlopen()が内部で必ず経由する`_opener.open()`という共通境界を
    差し替えることで、一箇所で確実に遮断する(fetch.urllib.request.urlopenだけを
    patchする方式では、vulnerability_facts.load_kev_catalog/fetch_nvd_batchの
    default引数捕捉分が素通りし、実networkへ到達してしまう)。

    登録されていないURLへのアクセスはAssertionErrorとして即座に失敗させ、
    空responseへのfallbackや実networkへのfallbackは行わない。
    """

    def __init__(self):
        self.routes = {}
        self.calls = []

    def register(self, url, body):
        self.routes[url] = body

    def __call__(self, fullurl, data=None, timeout=None):
        # 注意: これは urllib.request.OpenerDirector.open の代わりに、
        # `mock.patch("urllib.request.OpenerDirector.open", self.router)` で
        # インスタンスそのものをclass属性へ差し替えている。OpenerDirectorの
        # インスタンス(opener)側は `opener.open(url, data, timeout)` を呼ぶが、
        # 差し替え先が(記述子プロトコルを実装しない)plain instanceのため、
        # 属性アクセス経由の自動self束縛は起きず、`opener.open` は
        # このrouterインスタンス自体を返す。結果として実際の呼び出しは
        # `router_instance(url, data, timeout)` となり、Pythonの`__call__`
        # dispatch(型経由)によってselfはこのrouterインスタンスへ正しく
        # 束縛される(第1引数にopener自身は渡ってこない)。
        url = _request_url(fullurl)
        self.calls.append(url)
        if url not in self.routes:
            raise AssertionError(
                "pipeline E2E fake router: unregistered URL requested "
                f"(fail-closed, no real-network fallback): {url!r}"
            )
        return _FakeHTTPResponse(self.routes[url], url)


def _source_url(source_id):
    for source in fetch.SOURCE_DEFINITIONS:
        if source["id"] == source_id:
            return source["url"]
    raise AssertionError(f"source definition not found for id={source_id!r}")


def _build_router():
    router = _FakeUrlRouter()
    for source_id in ENABLED_RSS_SOURCE_IDS:
        url = _source_url(source_id)
        if source_id == "nist":
            router.register(
                url, _rss_with_item(NIST_TITLE, NIST_LINK, NIST_SUMMARY, NIST_PUBDATE, "NIST News")
            )
        elif source_id == "microsoft_security":
            router.register(
                url, _rss_with_item(MS_TITLE, MS_LINK, MS_SUMMARY, MS_PUBDATE, "MSRC Blog")
            )
        elif source_id == "google_tag":
            # Atom形式のfeedも1件は経路として確認する(RSS 2.0だけでなくAtomの
            # parse経路も実際に通す)。
            router.register(url, _empty_atom("Google TAG (Atom, empty)"))
        else:
            router.register(url, _empty_rss())
    router.register(_source_url("cisa_kev"), _kev_catalog_json())
    router.register(GEMINI_URL, _gemini_response_json())
    return router


class Bl037PipelineE2ETest(unittest.TestCase):
    """fetch.main()を実際に呼び出し、urllib.request経由のnetwork I/O境界だけを
    deterministicにmockして、実function間の結合(収集→policy適用→AI分析→
    facts→Today's Brief→日次JSON→index.html→Archive生成)を検証する。

    mockしない(実際に通す)主要関数: collect_recent, RSS/Atom parser,
    source definition読込み・validation, content usage policy適用,
    enrich_with_ai, build_facts_for_items(vulnerability_facts経由),
    build_todays_brief, build_html, daily_json.build_daily_digest,
    daily_json.validate_daily_digest, daily_json.save_daily_digest,
    Archive生成処理, data index生成処理。

    mockする境界: urllib.request.OpenerDirector.open(実質的な
    urllib.request.urlopen()の共通境界)、fetch.time.sleep(Gemini呼び出し間の
    rate-limit pacerで、networkの一部ではなくprocess内待機のため)、
    fetch.datetime.datetime(現在時刻)、fetch.DOCS_DIR・daily_json.DATA_DIR
    (書込み先をtemporary directoryへ隔離)、GEMINI_API_KEY環境変数
    (AI経路を有効化するテスト専用のダミー値)。
    """

    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp_dir.cleanup)
        tmp_path = Path(self.tmp_dir.name)
        self.docs_dir = tmp_path / "docs"
        self.data_dir = tmp_path / "data"
        self.data_dir.mkdir(parents=True)
        self.router = _build_router()

    def _run_main(self):
        with (
            mock.patch.dict(os.environ, {"GEMINI_API_KEY": FAKE_GEMINI_API_KEY}, clear=False),
            mock.patch("urllib.request.OpenerDirector.open", self.router),
            mock.patch("fetch.DOCS_DIR", self.docs_dir),
            mock.patch("daily_json.DATA_DIR", self.data_dir),
            mock.patch("fetch.datetime.datetime", _FrozenDateTime),
            mock.patch("fetch.time.sleep"),
        ):
            fetch.main()

    def _daily_json_paths(self):
        return sorted(self.data_dir.glob("*.json"))

    def _load_digest(self):
        path = self.data_dir / f"{EXPECTED_DIGEST_DATE}.json"
        self.assertTrue(path.exists(), f"expected daily digest file missing: {path}")
        with path.open(encoding="utf-8") as f:
            return json.load(f)

    def _find_item(self, digest, source_id):
        for entry in digest["items"]:
            if entry["source_id"] == source_id:
                return entry
        raise AssertionError(f"no digest item found for source_id={source_id!r}")

    def test_main_runs_real_pipeline_with_only_network_boundary_mocked(self):
        self._run_main()

        # --- urlopen router: 実際に呼ばれた境界の確認 -------------------------
        self.assertIn(
            _source_url("nist"), self.router.calls,
            "NIST(AI eligible)RSS feed URLが実際に取得されていない",
        )
        self.assertIn(
            _source_url("microsoft_security"), self.router.calls,
            "Microsoft(metadata_only)RSS feed URLが実際に取得されていない",
        )
        self.assertIn(
            _source_url("cisa_kev"), self.router.calls,
            "CISA KEV JSON URLが実際に取得されていない",
        )
        self.assertIn(GEMINI_URL, self.router.calls, "Gemini endpointが実際に呼ばれていない")

        # --- 生成物: temporary filesystemへの出力確認 --------------------------
        index_html_path = self.docs_dir / "index.html"
        self.assertTrue(index_html_path.exists(), "docs/index.htmlが生成されていない")

        daily_paths = self._daily_json_paths()
        self.assertIn(
            self.data_dir / f"{EXPECTED_DIGEST_DATE}.json", daily_paths,
            "data/<digest_date>.jsonが生成されていない",
        )

        index_json_path = self.data_dir / "index.json"
        self.assertTrue(index_json_path.exists(), "data/index.jsonが生成されていない")

        archive_dir = self.docs_dir / "archive"
        archive_today_path = archive_dir / f"{EXPECTED_DIGEST_DATE}.html"
        self.assertTrue(archive_today_path.exists(), "docs/archive/<digest_date>.htmlが生成されていない")
        archive_index_path = archive_dir / "index.html"
        self.assertTrue(archive_index_path.exists(), "docs/archive/index.htmlが生成されていない")

        # --- 生成された日次JSON: パース可能性とvalidate_daily_digest() ----------
        digest = self._load_digest()
        daily_json.validate_daily_digest(digest)  # 例外が出なければ成功
        self.assertEqual(digest["digest_date"], EXPECTED_DIGEST_DATE)

        run = digest["run"]
        self.assertNotEqual(run["total_items"], 0, "run.total_itemsが0のまま(記事が1件も収集されていない)")

        # --- 実収集pipelineを通過した記事の確認 ---------------------------------
        nist_entry = self._find_item(digest, "nist")
        self.assertEqual(nist_entry["raw_title"], NIST_TITLE)
        self.assertEqual(nist_entry["url"], NIST_LINK)

        ms_entry = self._find_item(digest, "microsoft_security")
        self.assertEqual(ms_entry["raw_title"], MS_TITLE)

        # --- AI eligible記事のanalysisが期待どおり保存されている ----------------
        self.assertEqual(nist_entry["analysis"]["status"], "success")
        self.assertEqual(nist_entry["analysis"]["summary"], GEMINI_SUMMARY_MARKER)
        self.assertEqual(nist_entry["analysis"]["financial_impact"], GEMINI_IMPACT_MARKER)
        # 表示title(main()内のresolve_display_title適用後)はAIのtitle_jaへ差し替わる。
        self.assertEqual(nist_entry["title"], GEMINI_TITLE_JA_MARKER)

        # --- AI非対象(metadata_only)記事はanalysisを試行していない --------------
        self.assertEqual(ms_entry["analysis"]["status"], "not_attempted")
        self.assertEqual(ms_entry["title"], MS_TITLE)

        # --- policy情報が保存されている -----------------------------------------
        self.assertEqual(nist_entry["policy"]["configured_mode"], "structured_open")
        self.assertEqual(nist_entry["policy"]["effective_mode"], "structured_open")
        self.assertTrue(nist_entry["policy"]["ai_eligible"])
        self.assertEqual(ms_entry["policy"]["configured_mode"], "metadata_only")
        self.assertFalse(ms_entry["policy"]["ai_eligible"])

        # --- facts構造が保存されている(CVE言及の無いfixtureなのでcvesは空) -------
        self.assertIn("cves", nist_entry["facts"])
        self.assertEqual(nist_entry["facts"]["cves"], [])
        self.assertIn("cves", ms_entry["facts"])

        # --- Today's Brief構造が保存されている -----------------------------------
        self.assertIn("brief", digest)
        self.assertIn(digest["brief"]["status"], ("success", "not_attempted", "failed"))

        # --- index.htmlへ記事が表示されている -------------------------------------
        index_html = index_html_path.read_text(encoding="utf-8")
        self.assertIn(GEMINI_TITLE_JA_MARKER, index_html, "AI分析後のtitle_jaがindex.htmlへ表示されていない")
        self.assertIn(MS_TITLE, index_html, "metadata_only記事の原題がindex.htmlへ表示されていない")
        # metadata_onlyのsource attribution(AIによる要約・評価を行っていない旨)が表示されている。
        self.assertIn(
            "AIによる要約・評価は行っていません", index_html,
            "metadata_only記事のsource attributionがindex.htmlへ表示されていない",
        )

        # --- Archiveへ同日記事が表示されている --------------------------------
        archive_html = archive_today_path.read_text(encoding="utf-8")
        self.assertIn(GEMINI_TITLE_JA_MARKER, archive_html, "AI分析後のtitle_jaがArchiveへ表示されていない")
        self.assertIn(MS_TITLE, archive_html, "metadata_only記事の原題がArchiveへ表示されていない")

        # --- fixtureの秘密値がoutputへ漏れていない ---------------------------------
        self.assertNotIn(FAKE_GEMINI_API_KEY, index_html)
        self.assertNotIn(FAKE_GEMINI_API_KEY, archive_html)
        self.assertNotIn(FAKE_GEMINI_API_KEY, json.dumps(digest, ensure_ascii=False))

        # --- unknown URLへの通信が一切無い(router登録分だけが呼ばれている) --------
        for called_url in self.router.calls:
            self.assertIn(called_url, self.router.routes)

    def test_run_is_deterministic_across_repeated_invocations(self):
        # 5.7: 実行順・timezone・実行日に依存しないことを、同一processで2回
        # 独立に実行し、両方成功しdigest_dateが一致することで確認する
        # (rerunでflakyにならないこと自体を1 test内で検証する)。
        self._run_main()
        first_digest = self._load_digest()

        # 2回目はfilesystemを別の隔離tempdirへ切り替えて再実行する。
        with tempfile.TemporaryDirectory() as second_tmp:
            second_docs_dir = Path(second_tmp) / "docs"
            second_data_dir = Path(second_tmp) / "data"
            second_data_dir.mkdir(parents=True)
            second_router = _build_router()
            with (
                mock.patch.dict(os.environ, {"GEMINI_API_KEY": FAKE_GEMINI_API_KEY}, clear=False),
                mock.patch("urllib.request.OpenerDirector.open", second_router),
                mock.patch("fetch.DOCS_DIR", second_docs_dir),
                mock.patch("daily_json.DATA_DIR", second_data_dir),
                mock.patch("fetch.datetime.datetime", _FrozenDateTime),
                mock.patch("fetch.time.sleep"),
            ):
                fetch.main()
            second_digest_path = second_data_dir / f"{EXPECTED_DIGEST_DATE}.json"
            with second_digest_path.open(encoding="utf-8") as f:
                second_digest = json.load(f)

        self.assertEqual(first_digest["digest_date"], second_digest["digest_date"])
        self.assertEqual(first_digest["run"]["total_items"], second_digest["run"]["total_items"])


if __name__ == "__main__":
    unittest.main()
