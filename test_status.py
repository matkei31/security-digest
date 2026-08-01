#!/usr/bin/env python3
"""
BL-033: STATUS.mdの最新公開実績が data/index.json とその参照先 daily JSON への
正本委譲になっていることを検証する回帰テスト。標準ライブラリunittestのみを使用する。

これらのtestは、意図的に特定の最新公開日・記事数・production commitを
アサーションしない。それらを固定値でチェックすると、通常のscheduled
production runが発生するたびにこのtest自体が古くなるという、BL-033が
解消しようとしている問題そのものを再導入してしまうため。
"""

import re
import unittest
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parent


class StatusSourceOfTruthTest(unittest.TestCase):
    """STATUS.mdの「Current versions」節が、日次で変化する公開実績を
    固定値として複製せず、data/index.json・参照先daily JSON・Git履歴への
    正本委譲として記述していることを検証する(BL-033)。
    """

    @classmethod
    def setUpClass(cls):
        cls.status = (REPOSITORY_ROOT / "STATUS.md").read_text(encoding="utf-8")

    def _section(self, text, marker, next_marker="\n## "):
        start = text.index(marker)
        rest = text[start + len(marker):]
        end = rest.find(next_marker)
        return rest if end == -1 else rest[:end]

    def _current_versions_section(self):
        return self._section(self.status, "## 2. Current versions", "\n## 3.")

    def _source_of_truth_rows(self):
        return [
            line
            for line in self._current_versions_section().splitlines()
            if line.startswith("| Latest publication source of truth |")
        ]

    def _source_of_truth_row(self):
        # Returns exactly one full table row by matching the row's own
        # leading cell text and taking the rest of that line -- this does
        # NOT assume the row is the table's last line, so a later addition
        # of another stable-contract row after it cannot leak into what
        # this row is checked against.
        rows = self._source_of_truth_rows()
        return next(iter(rows))

    def test_current_versions_has_latest_publication_source_of_truth_row(self):
        section = self._current_versions_section()
        self.assertIn("| Latest publication source of truth |", section)

    def test_source_of_truth_row_is_unique(self):
        self.assertEqual(len(self._source_of_truth_rows()), 1)

    def test_source_of_truth_row_references_index_json(self):
        row = self._source_of_truth_row()
        self.assertIn("data/index.json", row)

    def test_source_of_truth_row_defers_to_referenced_daily_json(self):
        row = self._source_of_truth_row()
        self.assertIn("data/YYYY-MM-DD.json", row)
        self.assertIn("正本とする", row)

    def test_source_of_truth_row_points_production_commit_to_git_history(self):
        row = self._source_of_truth_row()
        self.assertIn("Git履歴", row)

    def test_current_versions_no_longer_has_volatile_latest_published_daily_json_rows(self):
        section = self._current_versions_section()
        self.assertNotIn("| Latest published daily JSON |", section)
        self.assertNotIn("| Latest published daily JSON schema |", section)

    def test_source_of_truth_row_does_not_pin_a_specific_latest_publication_date(self):
        # Guards against reintroducing a fixed generated_at/digest_date into
        # this specific row (a stable-contract row like the generator-schema
        # row below may legitimately mention a merge commit's date/hash for
        # historical context; only this row's volatility is under test).
        row = self._source_of_truth_row()
        self.assertNotRegex(row, r"\b20\d{2}-\d{2}-\d{2}\b")
        self.assertNotRegex(row, r"\b\d{2}:\d{2}\s*JST\b")

    def test_source_of_truth_row_does_not_pin_a_specific_article_count(self):
        row = self._source_of_truth_row()
        self.assertNotRegex(row, r"\d+記事")

    def test_source_of_truth_row_does_not_pin_a_specific_production_commit(self):
        # Detects any 7-40 hex-char token that looks like a commit SHA,
        # regardless of how it is introduced (a "commit `abc1234`" phrase, a
        # bare backtick-quoted SHA, or a markdown link) -- not just the
        # literal "commit `<sha>`" wording used by the row previously
        # deleted from this table.
        row = self._source_of_truth_row()
        self.assertNotRegex(row, r"\b[0-9a-f]{7,40}\b")

    def test_source_of_truth_row_does_not_pin_a_specific_published_schema_value(self):
        # "schemaはこの文書へ複製しない" (a description of the delegation) is
        # fine; a specific value -- "schema_version 2", "published schema
        # 4", "最新公開schemaは5", "schema v3" -- is not, for ANY digit, not
        # just today's "2" (a future schema bump reintroducing this row's
        # staleness with a different number must still fail this test).
        # Current generator schema on `main` is a separate, deliberately-
        # pinned stable-contract row and is untouched by this check since it
        # is scoped to the source-of-truth row only.
        row = self._source_of_truth_row()
        self.assertNotRegex(row, r"(?i)\bschema[_ ]version\b\s*[:=はが]?\s*[`「]?\s*\d+\b")
        self.assertNotRegex(
            row, r"(?i)\bpublished schema(?: version)?\b\s*[:=はが]?\s*[`「]?\s*v?\d+\b"
        )
        self.assertNotRegex(row, r"最新公開schema(?:_version| version)?\s*[はが:=]?\s*[`「]?\s*v?\d+\b")
        self.assertNotRegex(row, r"(?i)\bschema\s+v\d+\b")

    def test_current_generator_schema_on_main_is_still_2(self):
        section = self._current_versions_section()
        row = self._section(section, "| Current generator schema on `main` |", "\n|")
        self.assertIn("`2`", row)

    def test_as_of_is_document_update_date_not_production_run_date(self):
        as_of_section = self._section(self.status, "## 1. As of", "\n## 2.")
        self.assertIn("最終更新日", as_of_section)
        self.assertIn("production run日ではない", as_of_section)

    def _source_of_truth_paragraph(self):
        # The explanatory prose paragraph right after the Current-versions
        # table (not the table itself, and not the unrelated PR #35/BL-021/
        # BL-022 sentences that precede it in the same paragraph).
        section = self._current_versions_section()
        return section[section.index("**正本の分担"):]

    def test_current_versions_paragraph_states_generator_contract_source_of_truth(self):
        paragraph = self._source_of_truth_paragraph()
        self.assertIn("generator契約", paragraph)
        self.assertIn("正本は`main`上のコード", paragraph)

    def test_current_versions_paragraph_states_latest_publication_source_of_truth(self):
        paragraph = self._source_of_truth_paragraph()
        self.assertIn("data/index.json", paragraph)

    def test_current_versions_paragraph_states_referenced_daily_json_source_of_truth(self):
        paragraph = self._source_of_truth_paragraph()
        self.assertIn("data/YYYY-MM-DD.json", paragraph)
        self.assertIn("generated_at・run結果・記事数・AI各件数・schema_versionの正本", paragraph)

    def test_current_versions_paragraph_states_production_commit_source_of_truth(self):
        paragraph = self._source_of_truth_paragraph()
        self.assertIn("production commit", paragraph)
        self.assertIn("Git履歴を正本とする", paragraph)

    def test_current_versions_paragraph_states_no_daily_value_duplication(self):
        paragraph = self._source_of_truth_paragraph()
        self.assertIn("この文書へ固定値として複製しない", paragraph)

    def test_current_versions_paragraph_treats_past_runs_as_historical_not_latest(self):
        paragraph = self._source_of_truth_paragraph()
        self.assertIn("歴史的観測事実", paragraph)
        self.assertIn("現在の最新公開状態を主張するものではない", paragraph)

    def test_current_versions_paragraph_does_not_reintroduce_the_deleted_row_as_current(self):
        # Guards against the exact PR #70 round-2 regression: the table
        # updated, but this paragraph kept narrating a specific run via the
        # now-deleted "Latest published daily JSON" row as if it were still
        # current.
        section = self._current_versions_section()
        self.assertNotIn("上記「Latest published daily JSON」は", section)


class Sd031DecisionTest(unittest.TestCase):
    """SD-031(STATUS.mdの動的公開実績を正本へ委譲する設計判断)がDECISIONS.mdへ
    一意に記録され、Context/Decision/Consequences/Evidenceが必要な内容を
    含んでいることを検証する(BL-033)。
    """

    @classmethod
    def setUpClass(cls):
        cls.decisions = (REPOSITORY_ROOT / "DECISIONS.md").read_text(encoding="utf-8")

    def _section(self, text, marker, next_marker="\n## "):
        start = text.index(marker)
        rest = text[start + len(marker):]
        end = rest.find(next_marker)
        return rest if end == -1 else rest[:end]

    def _sd031(self):
        return self._section(self.decisions, "## SD-031")

    def test_sd031_is_unique(self):
        headings = re.findall(r"^## (SD-031)\b", self.decisions, flags=re.MULTILINE)
        self.assertEqual(len(headings), 1)

    def test_sd031_records_date_and_status(self):
        sd031 = self._sd031()
        self.assertIn("- **Date:** 2026-08-01", sd031)
        self.assertIn("- **Status:** Accepted", sd031)

    def test_sd031_decision_records_source_of_truth_delegation(self):
        sd031 = self._sd031()
        decision = self._section(sd031, "- **Decision:**", "\n- **")
        self.assertIn("data/index.json", decision)
        self.assertIn("data/YYYY-MM-DD.json", decision)
        self.assertIn("source of truth", decision)
        self.assertIn("does not duplicate daily-volatile publication values", decision)
        self.assertIn("Git history", decision)

    def test_sd031_evidence_includes_bl033_commit_and_prs(self):
        sd031 = self._sd031()
        evidence = self._section(sd031, "- **Evidence:**", "\n- **")
        self.assertIn(
            "[BL-033](BACKLOG.md#bl-033--statusmdの動的公開実績を正本へ委譲する)",
            evidence,
        )
        self.assertIn("982a261b15afd695486fffe50fadf9209cc0faa5", evidence)
        self.assertIn("[PR #69](https://github.com/matkei31/security-digest/pull/69)", evidence)
        self.assertIn("[PR #70](https://github.com/matkei31/security-digest/pull/70)", evidence)


if __name__ == "__main__":
    unittest.main()
