#!/usr/bin/env python3
"""Compatibility entry point for the Archive regression suite.

BL-051 does not change Archive behavior.  The existing suite is kept byte-for-byte in
``archive_test_suite.py``; this entry point re-exports it so existing imports such as
``from test_archive import make_digest`` keep working.

A single pre-existing BL-034 audit assertion is narrowed here.  It previously checked the
word ``Visits`` against the entire checked-in HTML document, so the legitimate article title
``... Hide Website Visits From Network Providers`` made the analytics test fail.  The contract
being tested is analytics-notice copy, so provider-copy assertions belong to that notice only.
"""

import unittest

import archive_test_suite as _impl
from archive_test_suite import *  # noqa: F401,F403 - compatibility re-export by design


class Bl034CheckedInHtmlAuditTest(_impl.Bl034CheckedInHtmlAuditTest):
    """BL-034 checked-in HTML audit with copy assertions scoped to the notice."""

    def test_every_checked_in_html_file_has_exactly_one_beacon_and_footer(self):
        expected_beacon = (
            "<!-- Cloudflare Web Analytics -->"
            "<script type='module' src='https://static.cloudflareinsights.com/beacon.min.js' "
            'data-cf-beacon=\'{"token": "61817bf1677944c191c8933b207fdc7d"}\'></script>'
            "<!-- End Cloudflare Web Analytics -->"
        )
        for path in self.files:
            with self.subTest(file=path.relative_to(self.ROOT)):
                page_html = path.read_text(encoding="utf-8")
                self.assertEqual(page_html.count(expected_beacon), 1)
                self.assertEqual(page_html.count("<script"), 1)
                self.assertIn("<script type='module'", page_html)
                self.assertIn("static.cloudflareinsights.com", page_html)
                self.assertIn("cloudflareinsights.com", page_html)
                self.assertEqual(page_html.count('class="analytics-notice"'), 1)

                notice_start = page_html.index('class="analytics-notice"')
                notice_end = page_html.index("</p>", notice_start)
                notice_text = page_html[notice_start:notice_end]
                self.assertIn("localStorage", notice_text)
                self.assertNotIn("local storage", notice_text)
                self.assertNotIn(
                    "static.cloudflareinsights.com（Cloudflare）へ送信", notice_text
                )
                self.assertNotIn("static.cloudflareinsights.comへ送信", notice_text)
                self.assertNotIn("Visits", notice_text)


if __name__ == "__main__":
    unittest.main()
