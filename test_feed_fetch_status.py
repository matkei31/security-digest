#!/usr/bin/env python3
"""Ticket 13c: RSS取得結果の構造化(正常0件とHTTP/parse失敗の分離)・最小retry・
CISA KEVの「成功・新着0件」表示の回帰テスト。外部HTTP通信は一切行わない
(urllib.request.urlopen と time.sleep をモックする)。"""

import io
import unittest
import urllib.error
from contextlib import redirect_stdout, redirect_stderr
from unittest.mock import patch

import fetch


# ── テスト用ヘルパー ─────────────────────────────────────────────────────

RSS_TEMPLATE = """<?xml version="1.0"?>
<rss version="2.0"><channel><title>T</title>
{items}
</channel></rss>"""

ITEM_TEMPLATE = """<item><title>{title}</title><link>{link}</link>
<description>d</description><pubDate>{pub}</pubDate></item>"""


def _rss_bytes(items):
    body = "\n".join(
        ITEM_TEMPLATE.format(title=t, link=l, pub=p) for (t, l, p) in items
    )
    return RSS_TEMPLATE.format(items=body).encode("utf-8")


class _FakeResp:
    def __init__(self, body, url="https://www.cisa.gov/cybersecurity-advisories/all.xml",
                 status=200):
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

    def __exit__(self, *a):
        return False


class _FakeRespNoStatus:
    """status属性もgetcode()も持たない特殊mock(互換性の安全確認用)。"""

    def __init__(self, body):
        self._body = body

    def read(self):
        return self._body

    def geturl(self):
        return "https://x/all.xml"

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _http_error(code, reason="ERR"):
    return urllib.error.HTTPError(
        "https://www.cisa.gov/x", code, reason, hdrs=None, fp=None
    )


def _run(urlopen_side_effect, url="https://www.cisa.gov/cybersecurity-advisories/all.xml"):
    """_fetch_feed_result を、モックしたurlopenで1回実行し結果を返す。"""
    with patch("fetch.urllib.request.urlopen", side_effect=urlopen_side_effect) as mock_open, \
            patch("fetch.time.sleep") as mock_sleep, \
            redirect_stderr(io.StringIO()) as err:
        result = fetch._fetch_feed_result("CISA", url, "en")
    return result, mock_open, mock_sleep, err.getvalue()


# 未来日付(必ずcutoff以降=直近)と過去日付(必ずcutoff未満=対象外)。
FUTURE_PUB = "Wed, 01 Jan 2031 12:00:00 +0000"
PAST_PUB = "Thu, 01 Jan 2015 12:00:00 +0000"


class RssFetchResultTest(unittest.TestCase):
    def test_1_http200_with_items(self):
        body = _rss_bytes([("A", "https://x/a", FUTURE_PUB)])
        result, mock_open, _, _ = _run([_FakeResp(body)])
        self.assertTrue(result.fetch_success)
        self.assertTrue(result.parse_success)
        self.assertGreater(len(result.items), 0)
        self.assertEqual(result.http_status, 200)
        self.assertEqual(result.retry_count, 0)
        self.assertEqual(mock_open.call_count, 1)

    def test_2_http200_valid_xml_zero_target_items(self):
        # 正常取得・正常parseだが、対象itemが古く直近0件になるケース。
        # _fetch_feed_result自体はitems(パース済み)を返し、fetch/parseは成功。
        body = _rss_bytes([("Old", "https://x/old", PAST_PUB)])
        result, _, _, _ = _run([_FakeResp(body)])
        self.assertTrue(result.fetch_success)
        self.assertTrue(result.parse_success)
        self.assertIsNone(result.error_type)
        # itemはパースされるが、直近判定(cutoff)はcollect_recent側。
        # ここではfetch/parse成功=失敗ではないことを検証する。

    def test_3_http403_no_retry(self):
        result, mock_open, mock_sleep, _ = _run([_http_error(403, "Forbidden")])
        self.assertFalse(result.fetch_success)
        self.assertFalse(result.parse_success)
        self.assertEqual(result.http_status, 403)
        self.assertEqual(result.error_type, "http_error")
        self.assertEqual(result.retry_count, 0)
        self.assertEqual(mock_open.call_count, 1)  # retryしない
        mock_sleep.assert_not_called()

    def test_4_http429_then_200(self):
        body = _rss_bytes([("A", "https://x/a", FUTURE_PUB)])
        result, mock_open, mock_sleep, _ = _run([_http_error(429, "Too Many"), _FakeResp(body)])
        self.assertTrue(result.fetch_success)
        self.assertTrue(result.parse_success)
        self.assertEqual(result.retry_count, 1)
        self.assertEqual(mock_open.call_count, 2)
        mock_sleep.assert_called_once()

    def test_5_http503_twice_retry_once_only(self):
        result, mock_open, mock_sleep, _ = _run([_http_error(503, "Unavailable"),
                                                 _http_error(503, "Unavailable")])
        self.assertFalse(result.fetch_success)
        self.assertEqual(result.http_status, 503)
        self.assertEqual(result.retry_count, 1)
        self.assertEqual(mock_open.call_count, 2)  # 3回以上呼ばない
        mock_sleep.assert_called_once()

    def test_6_xml_parse_error_no_retry(self):
        result, mock_open, mock_sleep, _ = _run([_FakeResp(b"<not valid xml")])
        self.assertTrue(result.fetch_success)      # HTTP自体は成功
        self.assertFalse(result.parse_success)
        self.assertEqual(result.error_type, "parse_error")
        self.assertEqual(mock_open.call_count, 1)  # parse失敗はretryしない
        mock_sleep.assert_not_called()

    def test_7_fetch_feed_backward_compatible_returns_list(self):
        body = _rss_bytes([("A", "https://x/a", FUTURE_PUB)])
        with patch("fetch.urllib.request.urlopen", side_effect=[_FakeResp(body)]), \
                patch("fetch.time.sleep"):
            items = fetch.fetch_feed("CISA", "https://x/all.xml", "en")
        self.assertIsInstance(items, list)
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["source"], "CISA")

    def test_8_response_body_and_cookie_not_in_logs(self):
        secret_body = b"SECRETCOOKIEVALUE=abc123; TOPSECRETBODY"
        # 403本文にcookie/body相当を入れても、error_message/logへ出さない。
        err_with_body = urllib.error.HTTPError(
            "https://www.cisa.gov/x", 403, "Forbidden", hdrs=None,
            fp=io.BytesIO(secret_body),
        )
        result, _, _, stderr = _run([err_with_body])
        self.assertNotIn("SECRETCOOKIEVALUE", result.error_message or "")
        self.assertNotIn("TOPSECRETBODY", result.error_message or "")
        self.assertNotIn("SECRETCOOKIEVALUE", stderr)
        self.assertNotIn("TOPSECRETBODY", stderr)

    def test_4_1_oserror_reason_preserved(self):
        # reason属性が無い素のOSError/TimeoutErrorでも具体的理由を保持し、retryしない。
        for exc, needle in ((OSError("connection reset"), "connection reset"),
                            (TimeoutError("timed out"), "timed out")):
            with self.subTest(exc=type(exc).__name__):
                result, mock_open, mock_sleep, stderr = _run([exc])
                self.assertFalse(result.fetch_success)
                self.assertEqual(result.error_type, "url_error")
                self.assertIn(needle, result.error_message)
                # 単なる型名だけにならない(具体的理由が残る)。
                self.assertNotEqual(result.error_message, type(exc).__name__)
                self.assertIn(needle, stderr)
                self.assertEqual(mock_open.call_count, 1)  # retryしない
                mock_sleep.assert_not_called()

    def test_4_2_newline_in_reason_is_sanitized(self):
        # 例外メッセージの改行が error_message / stderr のログ行へ注入されないこと。
        exc = OSError("line1\nINJECTED-LINE\r\nline3")
        result, _, _, stderr = _run([exc])
        self.assertNotIn("\n", result.error_message)
        self.assertNotIn("\r", result.error_message)
        self.assertIn("line1", result.error_message)
        self.assertIn("INJECTED-LINE", result.error_message)  # 内容は残るが同一行
        # stderrの該当WARN行が1行に収まる(改行注入で別行化していない)。
        warn_lines = [ln for ln in stderr.splitlines() if "INJECTED-LINE" in ln]
        self.assertEqual(len(warn_lines), 1)
        self.assertIn("line1", warn_lines[0])
        self.assertIn("line3", warn_lines[0])

    def test_4_2b_reason_capped_at_200_chars(self):
        exc = OSError("x" * 500)
        result, _, _, _ = _run([exc])
        self.assertLessEqual(len(result.error_message), 200)

    def test_4_3_real_http_status_recorded_on_success(self):
        body = _rss_bytes([("A", "https://x/a", FUTURE_PUB)])
        result, _, _, _ = _run([_FakeResp(body, status=203)])  # 200以外の成功status
        self.assertTrue(result.fetch_success)
        self.assertTrue(result.parse_success)
        self.assertEqual(result.http_status, 203)

    def test_4_3b_real_http_status_kept_on_parse_error(self):
        result, _, _, _ = _run([_FakeResp(b"<broken", status=203)])
        self.assertTrue(result.fetch_success)
        self.assertFalse(result.parse_success)
        self.assertEqual(result.http_status, 203)

    def test_4_3c_getcode_fallback_and_no_status(self):
        # status属性が無くても getcode() があれば拾う: 通常の_FakeRespはstatus属性あり。
        # status も getcode() も無いmockでは None のまま(互換を壊さずクラッシュしない)。
        body = _rss_bytes([("A", "https://x/a", FUTURE_PUB)])
        result, _, _, _ = _run([_FakeRespNoStatus(body)])
        self.assertTrue(result.fetch_success)
        self.assertTrue(result.parse_success)
        self.assertIsNone(result.http_status)

    # ── v3: 内部ファイルパス非露出 ────────────────────────────────────────
    def test_v3_1_oserror_filename_not_exposed(self):
        secret_path = "/Users/example/private/secret.txt"
        exc = OSError(2, "No such file or directory", secret_path)
        result, mock_open, mock_sleep, stderr = _run([exc])
        self.assertFalse(result.fetch_success)
        self.assertEqual(result.error_type, "url_error")
        # 人間可読な理由(strerror)は残る。
        self.assertIn("No such file or directory", result.error_message)
        # 内部ファイルパスは error_message にも stderr にも出さない。
        self.assertNotIn(secret_path, result.error_message)
        self.assertNotIn(secret_path, stderr)
        self.assertNotIn("secret.txt", result.error_message)
        self.assertNotIn("secret.txt", stderr)
        self.assertEqual(mock_open.call_count, 1)  # retryしない
        mock_sleep.assert_not_called()

    def test_v3_1b_oserror_filename2_not_exposed(self):
        # filename2を持つOSError(rename等)。5引数形式(errno, strerror, filename,
        # winerror, filename2)で filename2 を実際に設定する。
        exc = OSError(18, "Invalid cross-device link", "/private/src", None, "/private/dst")
        self.assertEqual(exc.filename, "/private/src")
        self.assertEqual(exc.filename2, "/private/dst")  # 実際にfilename2が設定される
        result, _, _, stderr = _run([exc])
        self.assertIn("Invalid cross-device link", result.error_message)
        for leak in ("/private/src", "/private/dst"):
            self.assertNotIn(leak, result.error_message)
            self.assertNotIn(leak, stderr)

    def test_v3_2_urlerror_wrapping_oserror_with_path(self):
        secret_path = "/private/internal/path"
        exc = urllib.error.URLError(OSError(2, "No such file or directory", secret_path))
        result, _, _, stderr = _run([exc])
        self.assertFalse(result.fetch_success)
        self.assertEqual(result.error_type, "url_error")
        self.assertIn("No such file or directory", result.error_message)
        self.assertNotIn(secret_path, result.error_message)
        self.assertNotIn(secret_path, stderr)

    def test_v3_2b_common_network_reasons_preserved(self):
        for reason in ("connection reset", "timed out",
                       "Name or service not known", "certificate verify failed"):
            with self.subTest(reason=reason):
                exc = urllib.error.URLError(reason)
                result, _, _, _ = _run([exc])
                self.assertIn(reason, result.error_message)

    def test_v3_3_httperror_reason_sanitized(self):
        long_reason = "Forbidden\nINJECTED " + ("z" * 500)
        err = urllib.error.HTTPError("https://x", 403, long_reason, hdrs=None, fp=None)
        result, _, _, stderr = _run([err])
        self.assertEqual(result.http_status, 403)  # status維持
        self.assertEqual(result.error_type, "http_error")
        # 1行・200文字以内(reason部分)・改行なし。
        self.assertNotIn("\n", result.error_message)
        self.assertNotIn("\r", result.error_message)
        warn_lines = [ln for ln in stderr.splitlines() if "INJECTED" in ln]
        self.assertEqual(len(warn_lines), 1)
        # error_message = "HTTP 403 <safe_reason(<=200)>" の形。
        self.assertTrue(result.error_message.startswith("HTTP 403 "))
        safe_reason_part = result.error_message[len("HTTP 403 "):]
        self.assertLessEqual(len(safe_reason_part), 200)


class CollectRecentSummaryTest(unittest.TestCase):
    """collect_recentの[OK]/[NG]表示・サマリが、成功0件を失敗にしないことを検証。"""

    def _run_collect(self, feeds, urlopen_side_effect):
        with patch("fetch.RSS_FEEDS", feeds), \
                patch("fetch.collect_non_rss_items", return_value=[]), \
                patch("fetch.urllib.request.urlopen", side_effect=urlopen_side_effect), \
                patch("fetch.time.sleep"), \
                redirect_stderr(io.StringIO()), \
                redirect_stdout(io.StringIO()) as out:
            fetch.collect_recent()
        return out.getvalue()

    def test_9_zero_recent_is_ok_not_ng(self):
        feeds = [("CISA", "https://www.cisa.gov/cybersecurity-advisories/all.xml", "en")]
        body = _rss_bytes([("Old", "https://x/old", PAST_PUB)])  # 直近0件
        output = self._run_collect(feeds, [_FakeResp(body)])
        self.assertIn("[OK] CISA: 取得 1 件 / 直近 0 件", output)
        self.assertNotIn("[NG] CISA", output)
        self.assertIn("RSS sources: success=0 zero=1 failed=0", output)

    def test_9b_http_failure_is_ng_and_counted_failed(self):
        feeds = [("CISA", "https://www.cisa.gov/cybersecurity-advisories/all.xml", "en")]
        output = self._run_collect(feeds, [_http_error(403, "Forbidden")])
        self.assertIn("[NG] CISA: HTTP 403 Forbidden", output)
        self.assertIn("RSS sources: success=0 zero=0 failed=1", output)


class CisaKevZeroVsFailureTest(unittest.TestCase):
    """CISA KEV: カタログ取得成功・新着0件を[OK]に、取得失敗のみ[NG]にする。"""

    def _sources(self):
        policy = {
            "content_usage_mode": "structured_open", "allow_network_fetch": True,
            "allow_description": True, "allow_rich_content": False,
            "allow_ai_processing": True, "allow_excerpt_storage": True,
            "allow_public_summary": True, "attribution_requirement": "test fixture",
            "attribution_url": None, "checked_at": "2026-07-29", "confidence": "high",
            "unresolved_issue": "", "recheck_trigger": "test fixture",
            "official_evidence_url": "https://example.com/terms", "evidence_type": "terms",
        }
        return [
            {"id": "cisa_kev", "name": "CISA KEV",
             "url": "https://example.com/kev.json",
             "display_url": "https://example.com/kev-catalog",
             "collection_method": "cisa_kev_json", "enabled": True,
             "policy": dict(policy)},
            {"id": "nist_nvd", "name": "NIST NVD", "url": "https://example.com/nvd",
             "collection_method": "nist_nvd_json", "enabled": False,
             "policy": dict(policy)},
        ]

    def _kev_entry(self, cve, date_added):
        return {"cveID": cve, "vulnerabilityName": "V", "shortDescription": "d",
                "dateAdded": date_added}

    def test_10_catalog_success_with_recent_items_ok(self):
        cutoff = fetch.datetime.datetime.utcnow()
        recent = (cutoff + fetch.datetime.timedelta(days=1)).strftime("%Y-%m-%d")
        vulns = [self._kev_entry("CVE-2026-0001", recent)]
        out = io.StringIO()
        with patch("fetch.vulnerability_facts.load_kev_catalog", return_value=(vulns, True)), \
                redirect_stderr(io.StringIO()), redirect_stdout(out):
            result = fetch.collect_non_rss_items(cutoff - fetch.datetime.timedelta(days=1),
                                                 self._sources())
        self.assertIn("[OK] CISA KEV: 取得 1 件", out.getvalue())
        self.assertEqual(len(result), 1)

    def test_11_catalog_success_zero_recent_is_ok(self):
        cutoff = fetch.datetime.datetime.utcnow()
        old = "2015-01-01"
        vulns = [self._kev_entry("CVE-2015-0001", old)]  # cutoffより古い=新着0件
        out = io.StringIO()
        with patch("fetch.vulnerability_facts.load_kev_catalog", return_value=(vulns, True)), \
                redirect_stderr(io.StringIO()), redirect_stdout(out):
            result = fetch.collect_non_rss_items(cutoff, self._sources())
        self.assertIn("[OK] CISA KEV: 取得 0 件", out.getvalue())
        self.assertNotIn("[NG] CISA KEV", out.getvalue())
        self.assertEqual(result, [])

    def test_12_catalog_failure_is_ng_distinct_from_zero(self):
        cutoff = fetch.datetime.datetime.utcnow()
        out = io.StringIO()
        with patch("fetch.vulnerability_facts.load_kev_catalog", return_value=(None, False)), \
                redirect_stderr(io.StringIO()), redirect_stdout(out):
            result = fetch.collect_non_rss_items(cutoff, self._sources())
        text = out.getvalue()
        self.assertIn("[NG] CISA KEV", text)
        self.assertNotIn("[OK] CISA KEV", text)
        self.assertEqual(result, [])

    def test_12b_fetch_cisa_kev_status_out_reports_ok_and_failure(self):
        # status_outでカタログ成功/失敗を呼び出し側が区別できる。
        cutoff = fetch.datetime.datetime.utcnow()
        vulns = [self._kev_entry("CVE-2015-0001", "2015-01-01")]
        for load_ret, expect_ok in (((vulns, True), True), ((None, False), False)):
            with self.subTest(ok=expect_ok):
                st = {}
                with patch("fetch.vulnerability_facts.load_kev_catalog", return_value=load_ret), \
                        redirect_stderr(io.StringIO()):
                    fetch.fetch_cisa_kev(cutoff, url="https://example.com/kev.json",
                                         display_url="https://example.com/c", source_name="CISA KEV",
                                         status_out=st)
                self.assertEqual(st["catalog_ok"], expect_ok)


if __name__ == "__main__":
    unittest.main()
