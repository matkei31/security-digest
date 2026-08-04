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
  収集・content usage policy適用・AI分析・vulnerability facts(NVD/KEV含む)・
  Today's Brief・日次JSON・index.html・Archive生成までを実function間の結合として
  検証するpipeline integration E2E。
- test_repository_data.Bl037RepositoryDataValidationTest: 別fileにある、
  repositoryに保存済みの全daily JSONに対するread-only schema regression test。

今回保証しないもの: 実publisher endpointの可用性、実Gemini/NVD APIの可用性・品質、
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
import vulnerability_facts


JST = fetch.JST

# main()内のdatetime.datetime.now()/.utcnow()呼び出しをすべて固定値へ差し替える
# (timezone/実行日に依存しないため)。fetch.datetime.datetimeとは別module
# namespaceのvulnerability_facts.datetime.datetimeも、facts解決内部の
# fetched_at(datetime.datetime.now(datetime.timezone.utc))が参照するため
# 同じ固定値へ差し替える(daily_json.pyはfetched_at/generated_atを引数として
# 受け取るだけでdatetime.now()を自ら呼ばないため、patch不要と確認済み)。
FROZEN_UTC_NOW = datetime.datetime(2026, 8, 4, 3, 0, 0)
FROZEN_JST_NOW = datetime.datetime(2026, 8, 4, 12, 0, 0, tzinfo=JST)
EXPECTED_DIGEST_DATE = "2026-08-04"
FROZEN_UTC_NOW_Z = "2026-08-04T03:00:00Z"

# AI eligible(structured_open)なfixture記事: NIST。TEST_CVE_IDを自然な形で
# summaryへ含め、CVE抽出→NVD/KEV facts解決経路を実際に通す。
TEST_CVE_ID = "CVE-2020-12345"
NIST_TITLE = "E2E-MARKER-NIST-STRUCTURED-OPEN-ARTICLE"
NIST_LINK = "https://www.nist.gov/news-events/news/2026/08/e2e-marker-article"
NIST_SUMMARY = (
    "E2E pipeline integration test marker summary about a cyber security "
    f"vulnerability {TEST_CVE_ID}, for a NIST structured_open article."
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
FAKE_GEMINI_API_KEY = "test-key-not-real-gemini"
FAKE_NVD_API_KEY = "test-key-not-real-nvd"

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

# NVD CVSSフィクスチャ(deterministic)。
NVD_BASE_SCORE = 9.8
NVD_BASE_SEVERITY = "CRITICAL"
NVD_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
NVD_VULN_STATUS = "Analyzed"

# CISA KEVカタログ: 有効なcveIDを持つ要素が0件だとカタログ自体が
# 信頼できないものとして扱われる(load_kev_catalog参照)ため、DAYS_BACKの
# cutoffより十分古いdateAddedを持つTEST_CVE_IDの1件だけを含め、カタログ取得は
# 成功させつつ新着記事としては採用されないようにする。NIST fixtureが言及する
# TEST_CVE_IDと同じCVEにすることで、collect_recent()側のCISA KEV収集で
# 作られるkev_catalog_memoが、facts解決側のresolve_kev_facts()で
# そのまま再利用され(優先度1のmemoパス)、CISA KEV endpointが二重取得されない
# ことを確認する。
KEV_DATE_ADDED = "2020-01-01"

ENABLED_RSS_SOURCE_IDS = (
    "fsa", "jpcert_cc", "ipa", "nist", "microsoft_security", "mandiant",
    "google_tag", "ncsc", "krebs_on_security", "the_hacker_news", "cisco_talos",
)

GEMINI_URL = (
    f"https://generativelanguage.googleapis.com/v1beta/models/"
    f"{fetch.GEMINI_MODEL}:generateContent"
)
NVD_URL = f"{vulnerability_facts.NVD_API_URL}?cveIds={TEST_CVE_ID}"


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
            "cveID": TEST_CVE_ID,
            "vulnerabilityName": "E2E-MARKER-HISTORICAL-KEV-ENTRY",
            "dateAdded": KEV_DATE_ADDED,
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


def _nvd_response_json():
    # vulnerability_facts.normalize_nvd_record/select_cvssが要求する構造:
    # vulnerabilities[].cve.{id,vulnStatus,published,lastModified,metrics}。
    # published/lastModifiedはdatetime.fromisoformat()で解釈できる形式にする
    # (小数秒なし)。metricsはsource="nvd@nist.gov"・type="Primary"のCVSS 3.1を
    # 1件だけ含める(select_cvssの優先group 1・version 3.1)。
    return json.dumps({
        "vulnerabilities": [{
            "cve": {
                "id": TEST_CVE_ID,
                "vulnStatus": NVD_VULN_STATUS,
                "published": "2020-01-01T00:00:00",
                "lastModified": "2020-01-02T00:00:00",
                "metrics": {
                    "cvssMetricV31": [{
                        "source": "nvd@nist.gov",
                        "type": "Primary",
                        "cvssData": {
                            "baseScore": NVD_BASE_SCORE,
                            "baseSeverity": NVD_BASE_SEVERITY,
                            "vectorString": NVD_VECTOR,
                        },
                    }],
                },
            },
        }],
    }).encode("utf-8")


class _FrozenDateTime(datetime.datetime):
    """fetch.py・vulnerability_facts.py双方のdatetime.datetime.now()/
    .utcnow()呼び出しをすべて固定値へ差し替える。now(tz)は常に
    FROZEN_JST_NOWをtzへ変換した値、utcnow()は常にFROZEN_UTC_NOW(naive)を
    返す(呼び出し回数・順序に依存しない)。"""

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
    router.register(NVD_URL, _nvd_response_json())
    return router


class Bl037PipelineE2ETest(unittest.TestCase):
    """fetch.main()を実際に呼び出し、urllib.request経由のnetwork I/O境界だけを
    deterministicにmockして、実function間の結合(収集→policy適用→AI分析→
    NVD/KEV facts→Today's Brief→日次JSON→index.html→Archive生成)を検証する。

    mockしない(実際に通す)主要関数: collect_recent, RSS/Atom parser,
    source definition読込み・validation, content usage policy適用,
    enrich_with_ai, vulnerability_facts.build_facts_for_items(CVE抽出・
    NVD API・CISA KEV memo再利用・CVSS選択・facts cache永続化を含む),
    build_todays_brief, build_html, daily_json.build_daily_digest,
    daily_json.validate_daily_digest, daily_json.save_daily_digest,
    Archive生成処理, data index生成処理。

    mockする境界: urllib.request.OpenerDirector.open(実質的な
    urllib.request.urlopen()の共通境界)、fetch.time.sleep(Gemini呼び出し間の
    rate-limit pacerで、networkの一部ではなくprocess内待機のため)、
    fetch.datetime.datetime・vulnerability_facts.datetime.datetime(現在時刻。
    daily_json.pyはdatetime.now()を自ら呼ばずfetched_at/generated_atを引数
    として受け取るだけのためpatch不要)、fetch.DOCS_DIR・daily_json.DATA_DIR
    (書込み先をtemporary directoryへ隔離。vulnerability facts cacheの
    path(vulnerability_facts.default_cache_path)はdaily_json.DATA_DIRから
    実行時に導出されるため、この2つのpatchだけで一緒に隔離される)、
    GEMINI_API_KEY・NVD_API_KEY環境変数(ホスト環境の実キーに依存しない、
    test専用のダミー値)。
    """

    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp_dir.cleanup)
        tmp_path = Path(self.tmp_dir.name)
        self.docs_dir = tmp_path / "docs"
        self.data_dir = tmp_path / "data"
        self.data_dir.mkdir(parents=True)
        self.router = _build_router()

    def _run_main(self, router=None, docs_dir=None, data_dir=None):
        router = router or self.router
        docs_dir = docs_dir or self.docs_dir
        data_dir = data_dir or self.data_dir
        env = {"GEMINI_API_KEY": FAKE_GEMINI_API_KEY, "NVD_API_KEY": FAKE_NVD_API_KEY}
        with (
            mock.patch.dict(os.environ, env, clear=False),
            mock.patch("urllib.request.OpenerDirector.open", router),
            mock.patch("fetch.DOCS_DIR", docs_dir),
            mock.patch("daily_json.DATA_DIR", data_dir),
            mock.patch("fetch.datetime.datetime", _FrozenDateTime),
            mock.patch("vulnerability_facts.datetime.datetime", _FrozenDateTime),
            mock.patch("fetch.time.sleep"),
        ):
            fetch.main()

    def _daily_json_paths(self, data_dir=None):
        return sorted((data_dir or self.data_dir).glob("*.json"))

    def _load_digest(self, data_dir=None):
        data_dir = data_dir or self.data_dir
        path = data_dir / f"{EXPECTED_DIGEST_DATE}.json"
        self.assertTrue(path.exists(), f"expected daily digest file missing: {path}")
        with path.open(encoding="utf-8") as f:
            return json.load(f)

    def _load_facts_cache(self, data_dir=None):
        data_dir = data_dir or self.data_dir
        path = data_dir / "vulnerability_facts_cache.json"
        self.assertTrue(path.exists(), f"vulnerability_facts_cache.jsonが生成されていない: {path}")
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
        self.assertIn(GEMINI_URL, self.router.calls, "Gemini endpointが実際に呼ばれていない")
        self.assertIn(NVD_URL, self.router.calls, "NVD endpointが実際に呼ばれていない")
        self.assertEqual(
            self.router.calls.count(NVD_URL), 1,
            f"NVD URLが1回だけ呼ばれることを期待したが{self.router.calls.count(NVD_URL)}回だった",
        )
        kev_url = _source_url("cisa_kev")
        self.assertIn(kev_url, self.router.calls, "CISA KEV JSON URLが実際に取得されていない")
        self.assertEqual(
            self.router.calls.count(kev_url), 1,
            "CISA KEV URLはcollect_recent()での収集とfacts解決の双方から参照されるが、"
            f"kev_catalog_memoにより1回だけ取得される想定が{self.router.calls.count(kev_url)}回だった",
        )

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

        # --- facts/CVSS構造が実NVD/KEV応答fixtureどおりに保存されている ---------
        self.assertEqual(len(nist_entry["facts"]["cves"]), 1, "NIST記事のfacts.cvesが1件ではない")
        cve_fact = nist_entry["facts"]["cves"][0]
        self.assertEqual(cve_fact["cve_id"], TEST_CVE_ID)

        nvd_fact = cve_fact["nvd"]
        self.assertEqual(nvd_fact["status"], "found")
        self.assertEqual(nvd_fact["retrieval"], "live")
        self.assertEqual(nvd_fact["vuln_status"], NVD_VULN_STATUS)
        self.assertEqual(nvd_fact["cvss"]["version"], "3.1")
        self.assertEqual(nvd_fact["cvss"]["base_score"], NVD_BASE_SCORE)
        self.assertEqual(nvd_fact["cvss"]["base_severity"], NVD_BASE_SEVERITY)
        self.assertEqual(nvd_fact["cvss"]["vector"], NVD_VECTOR)
        self.assertEqual(nvd_fact["cvss"]["source"], "nvd@nist.gov")
        self.assertEqual(nvd_fact["cvss"]["type"], "Primary")

        kev_fact = cve_fact["kev"]
        self.assertEqual(kev_fact["status"], "listed")
        self.assertEqual(kev_fact["retrieval"], "live")
        self.assertEqual(kev_fact["date_added"], KEV_DATE_ADDED)

        # metadata_only記事はfacts構造を持つが、CVE言及がないのでcvesは空。
        self.assertIn("cves", ms_entry["facts"])
        self.assertEqual(ms_entry["facts"]["cves"], [])

        # --- vulnerability facts cacheがtemporary directoryへ生成されている -----
        cache = self._load_facts_cache()
        self.assertIn(TEST_CVE_ID, cache.get("nvd", {}), "NVD cacheにTEST_CVE_IDが保存されていない")
        self.assertEqual(cache["nvd"][TEST_CVE_ID]["status"], "found")
        self.assertIn(
            TEST_CVE_ID, cache.get("kev", {}).get("entries", {}),
            "KEV cacheにTEST_CVE_IDが保存されていない",
        )

        # --- Today's Brief構造が保存されている(AI分析成功のためsuccessを期待) ----
        brief = digest["brief"]
        self.assertEqual(brief["status"], "success")
        self.assertEqual(brief["model"], daily_json.BRIEF_MODEL)
        self.assertEqual(brief["prompt_version"], daily_json.BRIEF_PROMPT_VERSION)
        self.assertIsInstance(brief["overview"], str)
        self.assertTrue(brief["overview"].strip(), "brief.overviewが空")
        for key in ("important_highlights", "discussion_points", "check_items"):
            self.assertIsInstance(brief[key], list)
        # metadata_only記事(MS)のpublisher textがBriefへ混入していない。
        brief_text = json.dumps(brief, ensure_ascii=False)
        self.assertNotIn(MS_SUMMARY, brief_text)
        self.assertNotIn(MS_TITLE, brief_text)

        # --- index.htmlへ記事・facts・CVEが表示されている ------------------------
        index_html = index_html_path.read_text(encoding="utf-8")
        self.assertIn(GEMINI_TITLE_JA_MARKER, index_html, "AI分析後のtitle_jaがindex.htmlへ表示されていない")
        self.assertIn(MS_TITLE, index_html, "metadata_only記事の原題がindex.htmlへ表示されていない")
        # metadata_onlyのsource attribution(AIによる要約・評価を行っていない旨)が表示されている。
        self.assertIn(
            "AIによる要約・評価は行っていません", index_html,
            "metadata_only記事のsource attributionがindex.htmlへ表示されていない",
        )
        self.assertIn(TEST_CVE_ID, index_html, "TEST_CVE_IDがindex.htmlへ表示されていない")
        self.assertIn(str(NVD_BASE_SCORE), index_html, "NVD base scoreがindex.htmlへ表示されていない")

        # --- Archiveへ同日記事とCVEが表示されている --------------------------------
        archive_html = archive_today_path.read_text(encoding="utf-8")
        self.assertIn(GEMINI_TITLE_JA_MARKER, archive_html, "AI分析後のtitle_jaがArchiveへ表示されていない")
        self.assertIn(MS_TITLE, archive_html, "metadata_only記事の原題がArchiveへ表示されていない")
        self.assertIn(TEST_CVE_ID, archive_html, "TEST_CVE_IDがArchiveへ表示されていない")

        # --- fixtureの秘密値がoutputへ漏れていない ---------------------------------
        combined_output = index_html + archive_html + json.dumps(digest, ensure_ascii=False) + json.dumps(cache)
        self.assertNotIn(FAKE_GEMINI_API_KEY, combined_output)
        self.assertNotIn(FAKE_NVD_API_KEY, combined_output)

        # --- unknown URLへの通信が一切無い(router登録分だけが呼ばれている) --------
        for called_url in self.router.calls:
            self.assertIn(called_url, self.router.routes)

    def test_run_is_deterministic_across_repeated_invocations(self):
        # 5.7: 実行順・timezone・実行日に依存しないことを、同一processで2回
        # 独立に実行し、両方成功しdigest_date・総件数に加えてNVD/KEV facts・
        # brief metadataという主要deterministic fieldsも一致することで確認する
        # (rerunでflakyにならないこと自体を1 test内で検証する。HTML/JSON全体の
        # 完全一致までは求めない)。
        self._run_main()
        first_digest = self._load_digest()
        first_cache = self._load_facts_cache()

        # 2回目はfilesystemを別の隔離tempdirへ切り替えて再実行する。
        with tempfile.TemporaryDirectory() as second_tmp:
            second_docs_dir = Path(second_tmp) / "docs"
            second_data_dir = Path(second_tmp) / "data"
            second_data_dir.mkdir(parents=True)
            second_router = _build_router()
            self._run_main(router=second_router, docs_dir=second_docs_dir, data_dir=second_data_dir)
            second_digest = self._load_digest(data_dir=second_data_dir)
            second_cache = self._load_facts_cache(data_dir=second_data_dir)

        self.assertEqual(first_digest["digest_date"], second_digest["digest_date"])
        self.assertEqual(first_digest["run"]["total_items"], second_digest["run"]["total_items"])

        first_nist = self._find_item(first_digest, "nist")
        second_nist = self._find_item(second_digest, "nist")
        first_cve_fact = first_nist["facts"]["cves"][0]
        second_cve_fact = second_nist["facts"]["cves"][0]
        self.assertEqual(first_cve_fact["nvd"], second_cve_fact["nvd"])
        self.assertEqual(first_cve_fact["kev"], second_cve_fact["kev"])
        self.assertEqual(first_cve_fact["nvd"]["fetched_at"], FROZEN_UTC_NOW_Z)
        self.assertEqual(first_cve_fact["kev"]["fetched_at"], FROZEN_UTC_NOW_Z)

        self.assertEqual(first_cache["nvd"][TEST_CVE_ID], second_cache["nvd"][TEST_CVE_ID])
        self.assertEqual(
            first_cache["kev"]["entries"][TEST_CVE_ID], second_cache["kev"]["entries"][TEST_CVE_ID]
        )

        self.assertEqual(first_digest["brief"], second_digest["brief"])


if __name__ == "__main__":
    unittest.main()
