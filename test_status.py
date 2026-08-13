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

import document_test_utils as dtu

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


class Bl035ActiveWorkTest(unittest.TestCase):
    """BL-035 (Fable 5 review R-02/R-03): STATUS.md's Active work section held
    the runbook/agent-guidance synchronization work while it was in progress,
    replacing the "None." state left by BL-034's closeout. BL-035 has since
    received final user acceptance via PR #75 and moved to Recently completed
    work, returning Active work to "None." -- the same oscillation pattern
    BL-030 through BL-034 went through before it.
    """

    @classmethod
    def setUpClass(cls):
        cls.status = (REPOSITORY_ROOT / "STATUS.md").read_text(encoding="utf-8")

    def _active_work_section(self):
        return self.status.split("## Active work", 1)[1].split(
            "\n## 5. Recently completed work", 1
        )[0]

    def _recently_completed_section(self):
        return self.status.split("## 5. Recently completed work", 1)[1].split(
            "\n## 6. Known issues and limitations", 1
        )[0]

    def test_active_work_is_none_and_does_not_list_bl035(self):
        # BL-036 (Fable 5 review R-01) held Active work between BL-035's and
        # BL-036's own closeouts; both have since completed and Active work is
        # "None." again (see test_ui_spec.Bl036ArticleAttributionUiSpecTest for
        # BL-036's own Active-work/Recently-completed check). This test only
        # checks that BL-035 itself did not reappear as its own item.
        active = self._active_work_section()
        self.assertFalse(
            any(line.startswith("- BL-035 ") for line in active.splitlines()),
            "BL-035 must not reappear as its own Active work item after final acceptance",
        )

    def test_recently_completed_bl035_entry_records_required_content(self):
        recently_completed = self._recently_completed_section()
        bl035 = next(
            line for line in recently_completed.splitlines() if line.startswith("- BL-035 ")
        )
        for required in (
            "Fable 5",
            "R-02",
            "R-03",
            "SECURITY_OPERATIONS",
            "Version 1.2",
            "BL-032",
            "AGENTS",
            "STATUS",
            "PR CI",
            "[PR #75](https://github.com/matkei31/security-digest/pull/75)",
            "43bc14c584c05ed6539e20b9cba000e784d70bd3",
            "round 1・2",
            "1622 tests OK",
            "[Pull Request CI run 30801691143]"
            "(https://github.com/matkei31/security-digest/actions/runs/30801691143)",
            "unresolved review threadsは0",
            "Approved化",
            "Ready化",
            "通常のmerge commit方式によるmerge",
            "9件",
            "BL-035に残作業はない",
        ):
            with self.subTest(required=required):
                self.assertIn(required, bl035)
        self.assertIn("は変更していない", bl035)


class StatusSecurityOperationsSourceOfTruthTest(unittest.TestCase):
    """STATUS.md's section 8 "Sources of truth" table previously hardcoded
    `SECURITY_OPERATIONS.md Version 1.0`, which had already gone stale (the
    document had moved to Version 1.1) before BL-035 advanced it again, first
    to Version 1.2 Draft and then, on final acceptance via PR #75, to Version
    1.2 Approved. The row delegates the current Version/Status to
    SECURITY_OPERATIONS.md's own header instead of duplicating a number or a
    fixed `Approved` label, so this staleness cannot recur on the next Version
    or Status change (including the Draft-to-Approved change BL-035 itself
    just made).
    """

    @classmethod
    def setUpClass(cls):
        root = Path(__file__).resolve().parent
        cls.status = (root / "STATUS.md").read_text(encoding="utf-8")
        cls.operations = (root / "SECURITY_OPERATIONS.md").read_text(encoding="utf-8")

    def _sources_of_truth_row(self, label):
        section = self.status.split("## 8. Sources of truth", 1)[1].split("\n## 9.", 1)[0]
        return next(
            line for line in section.splitlines() if line.startswith(f"| {label} |")
        )

    def test_row_delegates_to_security_operations_header_not_a_fixed_version_or_status(self):
        row = self._sources_of_truth_row(
            "Incident, secret-rotation, correction, withdrawal, regeneration, "
            "and external-artifact policy"
        )
        self.assertIn("[SECURITY_OPERATIONS.md](SECURITY_OPERATIONS.md)", row)
        self.assertNotIn("Version 1.0", row)
        self.assertNotIn("Version 1.1", row)
        self.assertNotRegex(row, r"Version\s+\d+\.\d+")
        # Must not hardcode "Approved" either: even now that
        # SECURITY_OPERATIONS.md's header is in fact Approved (BL-035 final
        # acceptance), a fixed "Approved" label here would go stale again the
        # next time the document enters a Draft state for a future Version.
        self.assertNotIn("Approved", row)
        self.assertIn("同ファイル冒頭のheaderを正本とする", row)
        self.assertIn("特定のVersion番号を複製しない", row)

    def test_security_operations_itself_reflects_bl035_final_acceptance(self):
        # This documentation-only fix must not touch SECURITY_OPERATIONS.md's own
        # substantive content beyond what BL-035 already changed -- it now stands
        # at Version 1.2, Approved (final user acceptance via PR #75).
        self.assertIn("**Version:** 1.2", self.operations)
        self.assertIn("**Status:** Approved", self.operations)


class Bl036PostMergeRecordFixTest(unittest.TestCase):
    """BL-036 post-merge independent review found four documentation-only
    staleness issues in the final acceptance records: STATUS.md's "As of"
    had not been bumped to match its own last content update, and BACKLOG.md's
    BL-036 entry still described the SD-016 exception as an unconfirmed
    proposal and SD-033 as not-yet-created, contradicting the fact that both
    were confirmed in the same PR. These tests check the fix without locking
    the full surrounding prose verbatim.
    """

    @classmethod
    def setUpClass(cls):
        cls.status = (REPOSITORY_ROOT / "STATUS.md").read_text(encoding="utf-8")
        cls.backlog = (REPOSITORY_ROOT / "BACKLOG.md").read_text(encoding="utf-8")

    def _bl036_section(self):
        marker = "## BL-036 "
        start = self.backlog.index(marker)
        end = self.backlog.find("\n## ", start + len(marker))
        return self.backlog[start:] if end == -1 else self.backlog[start:end]

    def test_status_as_of_is_20260804(self):
        # BL-038: was a literal "## 1. As of\n\n2026-08-04" substring check,
        # which is brittle to any reformatting of the blank line between the
        # heading and its value (e.g. a single newline instead of two) even
        # though the actual contract is the exact date value. The section's
        # body has explanatory prose after the date (see
        # StatusSourceOfTruthTest.test_as_of_is_document_update_date_not_
        # production_run_date below), so this extracts just the first
        # non-empty line and requires it to equal "2026-08-04" exactly --
        # not merely start with it -- so a near-miss value like
        # "2026-08-04-old" or "2026-08-04 (stale)" still fails.
        as_of_section = dtu.extract_markdown_section(self.status, "## 1. As of")
        as_of_value = next(line.strip() for line in as_of_section.splitlines() if line.strip())
        # BL-038 closure (2026-08-14): this PR materially updates STATUS.md, and
        # "As of" is defined by STATUS itself as the document's own last-update
        # date, so the asserted value moves with it. The 2026-08-04 mentions above
        # are historical context (BL-036's post-merge fix) and stay as written; the
        # method name keeps its original date for identity continuity.
        self.assertEqual(
            as_of_value,
            "2026-08-14",
            f"STATUS.md's As of section's value must be exactly 2026-08-14: {as_of_value!r}",
        )

    def test_status_bl036_entry_distinguishes_implementation_and_final_evidence(self):
        recently_completed = self.status.split("## 5. Recently completed work", 1)[1]
        bl036_line = next(
            line for line in recently_completed.splitlines() if line.startswith("- BL-036 ")
        )
        self.assertIn("12a6f502973c78e21dbe0b209073f824731a3e5d", bl036_line)
        self.assertIn("30813905763", bl036_line)
        self.assertIn("1641 tests OK", bl036_line)
        self.assertIn("9件", bl036_line)
        self.assertIn("c1c09855bcafce2c5fab3a1071801aaae06e3f0d", bl036_line)
        self.assertIn("30833853521", bl036_line)
        self.assertIn("1644 tests OK", bl036_line)
        self.assertIn("final changed files 10件", bl036_line)
        self.assertIn("38095fff8eaafd938a33603f4332bbf8c100fba2", bl036_line)
        self.assertIn("30833953993", bl036_line)

    def test_backlog_bl036_no_longer_contains_stale_pending_current_state_wording(self):
        bl036 = self._bl036_section()
        for stale_phrase in (
            "本Ticketではsupersedeしない",
            "今回はSD-033自体を作成せず、DECISIONS.mdも変更しない",
            "仕様・Decision上まだ確定していない提案である",
            "維持する予定である",
        ):
            with self.subTest(stale_phrase=stale_phrase):
                self.assertNotIn(stale_phrase, bl036)

    def test_backlog_bl036_records_sd033_partial_supersession_as_confirmed(self):
        bl036 = self._bl036_section()
        self.assertIn("正式に確定した", bl036)
        self.assertIn("SD-033", bl036)
        self.assertIn("2026-08-04", bl036)
        self.assertIn("維持されている", bl036)

    def test_backlog_bl036_distinguishes_accepted_implementation_and_final_files(self):
        bl036 = self._bl036_section()
        self.assertIn("accepted implementation", bl036)
        self.assertIn("changed files 9件", bl036)
        self.assertIn("final acceptance", bl036)
        self.assertIn("final changed files 10件", bl036)
        self.assertIn("30833853521", bl036)
        self.assertIn("1644 tests OK", bl036)
        self.assertIn("38095fff8eaafd938a33603f4332bbf8c100fba2", bl036)
        self.assertIn("30833953993", bl036)
        self.assertIn("次回の通常scheduled production run", bl036)

    def test_backlog_bl036_note_does_not_claim_decisions_untouched(self):
        bl036 = self._bl036_section()
        self.assertNotIn("`DECISIONS.md`・`.github/workflows/`", bl036)
        self.assertIn("SD-033追加とSD-016のPartially superseded by note追加だけを変更", bl036)


class Bl036ProductionEvidenceSyncTest(unittest.TestCase):
    """BL-036 merged as PR #76 without touching docs/, so STATUS.md/BACKLOG.md's
    final-acceptance record correctly described the new CSS as pending the next
    scheduled production run. That production run then happened independently
    (production commit 5b7f40c..., synced into PR #77 before PR #77 itself
    merged), so the "次回scheduled production待ち" framing described a state
    that was no longer current. These tests check that the current-state record
    now reflects the CSS as already deployed via that production commit and PR
    #77's own merge, without locking the full surrounding prose verbatim.
    """

    @classmethod
    def setUpClass(cls):
        cls.status = (REPOSITORY_ROOT / "STATUS.md").read_text(encoding="utf-8")
        cls.backlog = (REPOSITORY_ROOT / "BACKLOG.md").read_text(encoding="utf-8")

    def _bl036_section(self):
        marker = "## BL-036 "
        start = self.backlog.index(marker)
        end = self.backlog.find("\n## ", start + len(marker))
        return self.backlog[start:] if end == -1 else self.backlog[start:end]

    def _status_bl036_line(self):
        recently_completed = self.status.split("## 5. Recently completed work", 1)[1]
        return next(
            line for line in recently_completed.splitlines() if line.startswith("- BL-036 ")
        )

    def test_status_bl036_line_records_production_commit_and_pages_run(self):
        line = self._status_bl036_line()
        self.assertIn("5b7f40c30b9309cbf35469fb3c3ae2acb0f4a544", line)
        self.assertIn("30864611190", line)

    def test_backlog_bl036_records_production_commit_and_pages_run(self):
        bl036 = self._bl036_section()
        self.assertIn("5b7f40c30b9309cbf35469fb3c3ae2acb0f4a544", bl036)
        self.assertIn("30864611190", bl036)

    def test_status_no_longer_claims_current_state_is_pending_next_production(self):
        self.assertNotIn(
            "新CSSの公開HTML反映は次回の通常scheduled production run待ちである",
            self.status,
        )

    def test_backlog_no_longer_claims_current_state_is_pending_next_production(self):
        bl036 = self._bl036_section()
        self.assertNotIn(
            "新CSSの公開HTML反映は次回の通常scheduled production run待ちである",
            bl036,
        )

    def test_status_distinguishes_independent_scheduled_production_from_bl036_manual_work(self):
        line = self._status_bl036_line()
        self.assertIn("独立した通常scheduled production", line)
        self.assertIn("手動production", line)

    def test_backlog_distinguishes_independent_scheduled_production_from_bl036_manual_work(self):
        bl036 = self._bl036_section()
        self.assertIn("独立した通常scheduled production", bl036)
        self.assertIn("手動production", bl036)

    def test_backlog_bl036_still_complete_with_no_remaining_work(self):
        bl036 = self._bl036_section()
        self.assertIn("- **状態:** 完了", bl036)
        self.assertIn("- **残作業:** なし。", bl036)

    def test_status_no_longer_contains_unqualified_no_production_claim(self):
        # Round 1 of independent review found this sentence still present,
        # unqualified, elsewhere in the same BL-036 entry -- contradicting the
        # entry's own record that production commit 5b7f40c... (an independent,
        # later scheduled production run) actually happened. It must not read
        # as "BL-036 work involved no production of any kind, ever."
        line = self._status_bl036_line()
        self.assertNotIn(
            "production・`workflow_dispatch`・実Gemini API呼び出し・"
            "通常の外部収集は行っていない。",
            line,
        )

    def test_backlog_bl036_no_longer_contains_unqualified_no_production_claim(self):
        bl036 = self._bl036_section()
        self.assertNotIn(
            "production・`workflow_dispatch`・実Gemini API呼び出し・"
            "通常の外部収集は行っていない。",
            bl036,
        )

    def test_status_bl036_scopes_the_no_manual_production_claim_to_bl036_work(self):
        line = self._status_bl036_line()
        self.assertIn("BL-036の実装・受入作業", line)

    def test_backlog_bl036_scopes_the_no_manual_production_claim_to_bl036_work(self):
        bl036 = self._bl036_section()
        self.assertIn("BL-036の実装・受入作業", bl036)
        self.assertIn("本Ticketの実装・受入作業", bl036)


if __name__ == "__main__":
    unittest.main()
