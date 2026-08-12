#!/usr/bin/env python3
"""BL-038 tranche 3r: final SecurityRequirementsTest tail classification guards."""
import ast
import hashlib
import json
import unittest
from collections import Counter, defaultdict
from pathlib import Path
import document_test_inventory as dti
import document_test_history as dth
from test_document_test_classification_3q_bindings import _narrow_section_facts
ROOT = Path(__file__).resolve().parent
SOURCE_FILE = 'test_security_requirements.py'
CLASS_NAME = 'SecurityRequirementsTest'
SHARD_FILENAME = 'document_test_classification_006.json'
SHARD_PATH = ROOT / SHARD_FILENAME
RANGE_START = 'test_sd024_sd025_and_follow_up_tickets_are_recorded'
RANGE_END = 'test_security_requirements_internal_markdown_links_resolve'
METHOD_RANGE = {"start": RANGE_START, "end": RANGE_END}
PRE_SHARDS = ('document_test_classification.json', 'document_test_classification_001.json', 'document_test_classification_002.json', 'document_test_classification_003.json', 'document_test_classification_004.json', 'document_test_classification_005.json')
EXPECTED_INDEX = PRE_SHARDS + (SHARD_FILENAME,)
CURRENT_INDEX = EXPECTED_INDEX + ('document_test_classification_007.json',)
EXPECTED_ASSERTIONS = 133
EXPECTED_METHODS = 9
EXPECTED_METHOD_COUNTS = (('test_sd024_sd025_and_follow_up_tickets_are_recorded', 81), ('test_owner_checklist_mandatory_items_are_resolved_without_sensitive_data', 5), ('test_agents_references_security_docs_without_blanket_authorization', 12), ('test_agents_ui_spec_reference_delegates_version_too', 3), ('test_agents_describes_pr_ci_and_fetch_yml_triggers_accurately', 14), ('test_agents_pr_ci_checkout_target_is_the_merge_candidate_not_the_head', 5), ('test_agents_distinguishes_unittest_target_diff_check_range_and_head_association', 6), ('test_agents_pr_ci_secret_and_token_wording_is_precise', 4), ('test_security_requirements_internal_markdown_links_resolve', 3))
EXPECTED_API_COUNTS = {'assertIn': 113, 'assertNotIn': 10, 'assertRegex': 2, 'assertGreaterEqual': 1, 'assertTrue': 3, 'assertEqual': 1, 'assertNotRegex': 3}
EXPECTED_CATEGORY_COUNTS = {"A": 0, "B": 60, "C": 37, "D": 36}
EXPECTED_B_IDS = ('test_security_requirements.py::SecurityRequirementsTest::test_sd024_sd025_and_follow_up_tickets_are_recorded::assert-01', 'test_security_requirements.py::SecurityRequirementsTest::test_sd024_sd025_and_follow_up_tickets_are_recorded::assert-04', 'test_security_requirements.py::SecurityRequirementsTest::test_sd024_sd025_and_follow_up_tickets_are_recorded::assert-08', 'test_security_requirements.py::SecurityRequirementsTest::test_sd024_sd025_and_follow_up_tickets_are_recorded::assert-09', 'test_security_requirements.py::SecurityRequirementsTest::test_sd024_sd025_and_follow_up_tickets_are_recorded::assert-11', 'test_security_requirements.py::SecurityRequirementsTest::test_sd024_sd025_and_follow_up_tickets_are_recorded::assert-12', 'test_security_requirements.py::SecurityRequirementsTest::test_sd024_sd025_and_follow_up_tickets_are_recorded::assert-15', 'test_security_requirements.py::SecurityRequirementsTest::test_sd024_sd025_and_follow_up_tickets_are_recorded::assert-21', 'test_security_requirements.py::SecurityRequirementsTest::test_sd024_sd025_and_follow_up_tickets_are_recorded::assert-22', 'test_security_requirements.py::SecurityRequirementsTest::test_sd024_sd025_and_follow_up_tickets_are_recorded::assert-24', 'test_security_requirements.py::SecurityRequirementsTest::test_sd024_sd025_and_follow_up_tickets_are_recorded::assert-30', 'test_security_requirements.py::SecurityRequirementsTest::test_sd024_sd025_and_follow_up_tickets_are_recorded::assert-31', 'test_security_requirements.py::SecurityRequirementsTest::test_sd024_sd025_and_follow_up_tickets_are_recorded::assert-32', 'test_security_requirements.py::SecurityRequirementsTest::test_sd024_sd025_and_follow_up_tickets_are_recorded::assert-33', 'test_security_requirements.py::SecurityRequirementsTest::test_sd024_sd025_and_follow_up_tickets_are_recorded::assert-34', 'test_security_requirements.py::SecurityRequirementsTest::test_sd024_sd025_and_follow_up_tickets_are_recorded::assert-35', 'test_security_requirements.py::SecurityRequirementsTest::test_sd024_sd025_and_follow_up_tickets_are_recorded::assert-36', 'test_security_requirements.py::SecurityRequirementsTest::test_sd024_sd025_and_follow_up_tickets_are_recorded::assert-44', 'test_security_requirements.py::SecurityRequirementsTest::test_sd024_sd025_and_follow_up_tickets_are_recorded::assert-50', 'test_security_requirements.py::SecurityRequirementsTest::test_sd024_sd025_and_follow_up_tickets_are_recorded::assert-59', 'test_security_requirements.py::SecurityRequirementsTest::test_sd024_sd025_and_follow_up_tickets_are_recorded::assert-61', 'test_security_requirements.py::SecurityRequirementsTest::test_sd024_sd025_and_follow_up_tickets_are_recorded::assert-63', 'test_security_requirements.py::SecurityRequirementsTest::test_sd024_sd025_and_follow_up_tickets_are_recorded::assert-64', 'test_security_requirements.py::SecurityRequirementsTest::test_sd024_sd025_and_follow_up_tickets_are_recorded::assert-65', 'test_security_requirements.py::SecurityRequirementsTest::test_sd024_sd025_and_follow_up_tickets_are_recorded::assert-67', 'test_security_requirements.py::SecurityRequirementsTest::test_sd024_sd025_and_follow_up_tickets_are_recorded::assert-68', 'test_security_requirements.py::SecurityRequirementsTest::test_sd024_sd025_and_follow_up_tickets_are_recorded::assert-71', 'test_security_requirements.py::SecurityRequirementsTest::test_sd024_sd025_and_follow_up_tickets_are_recorded::assert-72', 'test_security_requirements.py::SecurityRequirementsTest::test_sd024_sd025_and_follow_up_tickets_are_recorded::assert-77', 'test_security_requirements.py::SecurityRequirementsTest::test_sd024_sd025_and_follow_up_tickets_are_recorded::assert-78', 'test_security_requirements.py::SecurityRequirementsTest::test_sd024_sd025_and_follow_up_tickets_are_recorded::assert-79', 'test_security_requirements.py::SecurityRequirementsTest::test_sd024_sd025_and_follow_up_tickets_are_recorded::assert-80', 'test_security_requirements.py::SecurityRequirementsTest::test_sd024_sd025_and_follow_up_tickets_are_recorded::assert-81', 'test_security_requirements.py::SecurityRequirementsTest::test_owner_checklist_mandatory_items_are_resolved_without_sensitive_data::assert-01', 'test_security_requirements.py::SecurityRequirementsTest::test_owner_checklist_mandatory_items_are_resolved_without_sensitive_data::assert-02', 'test_security_requirements.py::SecurityRequirementsTest::test_owner_checklist_mandatory_items_are_resolved_without_sensitive_data::assert-03', 'test_security_requirements.py::SecurityRequirementsTest::test_owner_checklist_mandatory_items_are_resolved_without_sensitive_data::assert-04', 'test_security_requirements.py::SecurityRequirementsTest::test_agents_references_security_docs_without_blanket_authorization::assert-01', 'test_security_requirements.py::SecurityRequirementsTest::test_agents_references_security_docs_without_blanket_authorization::assert-02', 'test_security_requirements.py::SecurityRequirementsTest::test_agents_references_security_docs_without_blanket_authorization::assert-03', 'test_security_requirements.py::SecurityRequirementsTest::test_agents_references_security_docs_without_blanket_authorization::assert-04', 'test_security_requirements.py::SecurityRequirementsTest::test_agents_references_security_docs_without_blanket_authorization::assert-05', 'test_security_requirements.py::SecurityRequirementsTest::test_agents_references_security_docs_without_blanket_authorization::assert-06', 'test_security_requirements.py::SecurityRequirementsTest::test_agents_ui_spec_reference_delegates_version_too::assert-01', 'test_security_requirements.py::SecurityRequirementsTest::test_agents_ui_spec_reference_delegates_version_too::assert-03', 'test_security_requirements.py::SecurityRequirementsTest::test_agents_describes_pr_ci_and_fetch_yml_triggers_accurately::assert-01', 'test_security_requirements.py::SecurityRequirementsTest::test_agents_describes_pr_ci_and_fetch_yml_triggers_accurately::assert-02', 'test_security_requirements.py::SecurityRequirementsTest::test_agents_describes_pr_ci_and_fetch_yml_triggers_accurately::assert-03', 'test_security_requirements.py::SecurityRequirementsTest::test_agents_describes_pr_ci_and_fetch_yml_triggers_accurately::assert-04', 'test_security_requirements.py::SecurityRequirementsTest::test_agents_describes_pr_ci_and_fetch_yml_triggers_accurately::assert-08', 'test_security_requirements.py::SecurityRequirementsTest::test_agents_describes_pr_ci_and_fetch_yml_triggers_accurately::assert-11', 'test_security_requirements.py::SecurityRequirementsTest::test_agents_pr_ci_checkout_target_is_the_merge_candidate_not_the_head::assert-04', 'test_security_requirements.py::SecurityRequirementsTest::test_agents_pr_ci_checkout_target_is_the_merge_candidate_not_the_head::assert-05', 'test_security_requirements.py::SecurityRequirementsTest::test_agents_distinguishes_unittest_target_diff_check_range_and_head_association::assert-03', 'test_security_requirements.py::SecurityRequirementsTest::test_agents_distinguishes_unittest_target_diff_check_range_and_head_association::assert-06', 'test_security_requirements.py::SecurityRequirementsTest::test_agents_pr_ci_secret_and_token_wording_is_precise::assert-02', 'test_security_requirements.py::SecurityRequirementsTest::test_agents_pr_ci_secret_and_token_wording_is_precise::assert-03', 'test_security_requirements.py::SecurityRequirementsTest::test_security_requirements_internal_markdown_links_resolve::assert-01', 'test_security_requirements.py::SecurityRequirementsTest::test_security_requirements_internal_markdown_links_resolve::assert-02', 'test_security_requirements.py::SecurityRequirementsTest::test_security_requirements_internal_markdown_links_resolve::assert-03')
EXPECTED_C_IDS = ('test_security_requirements.py::SecurityRequirementsTest::test_sd024_sd025_and_follow_up_tickets_are_recorded::assert-20', 'test_security_requirements.py::SecurityRequirementsTest::test_sd024_sd025_and_follow_up_tickets_are_recorded::assert-25', 'test_security_requirements.py::SecurityRequirementsTest::test_sd024_sd025_and_follow_up_tickets_are_recorded::assert-26', 'test_security_requirements.py::SecurityRequirementsTest::test_sd024_sd025_and_follow_up_tickets_are_recorded::assert-37', 'test_security_requirements.py::SecurityRequirementsTest::test_sd024_sd025_and_follow_up_tickets_are_recorded::assert-43', 'test_security_requirements.py::SecurityRequirementsTest::test_sd024_sd025_and_follow_up_tickets_are_recorded::assert-49', 'test_security_requirements.py::SecurityRequirementsTest::test_sd024_sd025_and_follow_up_tickets_are_recorded::assert-57', 'test_security_requirements.py::SecurityRequirementsTest::test_sd024_sd025_and_follow_up_tickets_are_recorded::assert-58', 'test_security_requirements.py::SecurityRequirementsTest::test_sd024_sd025_and_follow_up_tickets_are_recorded::assert-60', 'test_security_requirements.py::SecurityRequirementsTest::test_sd024_sd025_and_follow_up_tickets_are_recorded::assert-62', 'test_security_requirements.py::SecurityRequirementsTest::test_sd024_sd025_and_follow_up_tickets_are_recorded::assert-66', 'test_security_requirements.py::SecurityRequirementsTest::test_sd024_sd025_and_follow_up_tickets_are_recorded::assert-73', 'test_security_requirements.py::SecurityRequirementsTest::test_owner_checklist_mandatory_items_are_resolved_without_sensitive_data::assert-05', 'test_security_requirements.py::SecurityRequirementsTest::test_agents_references_security_docs_without_blanket_authorization::assert-07', 'test_security_requirements.py::SecurityRequirementsTest::test_agents_references_security_docs_without_blanket_authorization::assert-08', 'test_security_requirements.py::SecurityRequirementsTest::test_agents_references_security_docs_without_blanket_authorization::assert-09', 'test_security_requirements.py::SecurityRequirementsTest::test_agents_references_security_docs_without_blanket_authorization::assert-10', 'test_security_requirements.py::SecurityRequirementsTest::test_agents_references_security_docs_without_blanket_authorization::assert-11', 'test_security_requirements.py::SecurityRequirementsTest::test_agents_references_security_docs_without_blanket_authorization::assert-12', 'test_security_requirements.py::SecurityRequirementsTest::test_agents_ui_spec_reference_delegates_version_too::assert-02', 'test_security_requirements.py::SecurityRequirementsTest::test_agents_describes_pr_ci_and_fetch_yml_triggers_accurately::assert-05', 'test_security_requirements.py::SecurityRequirementsTest::test_agents_describes_pr_ci_and_fetch_yml_triggers_accurately::assert-06', 'test_security_requirements.py::SecurityRequirementsTest::test_agents_describes_pr_ci_and_fetch_yml_triggers_accurately::assert-07', 'test_security_requirements.py::SecurityRequirementsTest::test_agents_describes_pr_ci_and_fetch_yml_triggers_accurately::assert-09', 'test_security_requirements.py::SecurityRequirementsTest::test_agents_describes_pr_ci_and_fetch_yml_triggers_accurately::assert-10', 'test_security_requirements.py::SecurityRequirementsTest::test_agents_describes_pr_ci_and_fetch_yml_triggers_accurately::assert-12', 'test_security_requirements.py::SecurityRequirementsTest::test_agents_describes_pr_ci_and_fetch_yml_triggers_accurately::assert-13', 'test_security_requirements.py::SecurityRequirementsTest::test_agents_describes_pr_ci_and_fetch_yml_triggers_accurately::assert-14', 'test_security_requirements.py::SecurityRequirementsTest::test_agents_pr_ci_checkout_target_is_the_merge_candidate_not_the_head::assert-01', 'test_security_requirements.py::SecurityRequirementsTest::test_agents_pr_ci_checkout_target_is_the_merge_candidate_not_the_head::assert-02', 'test_security_requirements.py::SecurityRequirementsTest::test_agents_pr_ci_checkout_target_is_the_merge_candidate_not_the_head::assert-03', 'test_security_requirements.py::SecurityRequirementsTest::test_agents_distinguishes_unittest_target_diff_check_range_and_head_association::assert-01', 'test_security_requirements.py::SecurityRequirementsTest::test_agents_distinguishes_unittest_target_diff_check_range_and_head_association::assert-02', 'test_security_requirements.py::SecurityRequirementsTest::test_agents_distinguishes_unittest_target_diff_check_range_and_head_association::assert-04', 'test_security_requirements.py::SecurityRequirementsTest::test_agents_distinguishes_unittest_target_diff_check_range_and_head_association::assert-05', 'test_security_requirements.py::SecurityRequirementsTest::test_agents_pr_ci_secret_and_token_wording_is_precise::assert-01', 'test_security_requirements.py::SecurityRequirementsTest::test_agents_pr_ci_secret_and_token_wording_is_precise::assert-04')
EXPECTED_D_IDS = ('test_security_requirements.py::SecurityRequirementsTest::test_sd024_sd025_and_follow_up_tickets_are_recorded::assert-02', 'test_security_requirements.py::SecurityRequirementsTest::test_sd024_sd025_and_follow_up_tickets_are_recorded::assert-03', 'test_security_requirements.py::SecurityRequirementsTest::test_sd024_sd025_and_follow_up_tickets_are_recorded::assert-05', 'test_security_requirements.py::SecurityRequirementsTest::test_sd024_sd025_and_follow_up_tickets_are_recorded::assert-06', 'test_security_requirements.py::SecurityRequirementsTest::test_sd024_sd025_and_follow_up_tickets_are_recorded::assert-07', 'test_security_requirements.py::SecurityRequirementsTest::test_sd024_sd025_and_follow_up_tickets_are_recorded::assert-10', 'test_security_requirements.py::SecurityRequirementsTest::test_sd024_sd025_and_follow_up_tickets_are_recorded::assert-13', 'test_security_requirements.py::SecurityRequirementsTest::test_sd024_sd025_and_follow_up_tickets_are_recorded::assert-14', 'test_security_requirements.py::SecurityRequirementsTest::test_sd024_sd025_and_follow_up_tickets_are_recorded::assert-16', 'test_security_requirements.py::SecurityRequirementsTest::test_sd024_sd025_and_follow_up_tickets_are_recorded::assert-17', 'test_security_requirements.py::SecurityRequirementsTest::test_sd024_sd025_and_follow_up_tickets_are_recorded::assert-18', 'test_security_requirements.py::SecurityRequirementsTest::test_sd024_sd025_and_follow_up_tickets_are_recorded::assert-19', 'test_security_requirements.py::SecurityRequirementsTest::test_sd024_sd025_and_follow_up_tickets_are_recorded::assert-23', 'test_security_requirements.py::SecurityRequirementsTest::test_sd024_sd025_and_follow_up_tickets_are_recorded::assert-27', 'test_security_requirements.py::SecurityRequirementsTest::test_sd024_sd025_and_follow_up_tickets_are_recorded::assert-28', 'test_security_requirements.py::SecurityRequirementsTest::test_sd024_sd025_and_follow_up_tickets_are_recorded::assert-29', 'test_security_requirements.py::SecurityRequirementsTest::test_sd024_sd025_and_follow_up_tickets_are_recorded::assert-38', 'test_security_requirements.py::SecurityRequirementsTest::test_sd024_sd025_and_follow_up_tickets_are_recorded::assert-39', 'test_security_requirements.py::SecurityRequirementsTest::test_sd024_sd025_and_follow_up_tickets_are_recorded::assert-40', 'test_security_requirements.py::SecurityRequirementsTest::test_sd024_sd025_and_follow_up_tickets_are_recorded::assert-41', 'test_security_requirements.py::SecurityRequirementsTest::test_sd024_sd025_and_follow_up_tickets_are_recorded::assert-42', 'test_security_requirements.py::SecurityRequirementsTest::test_sd024_sd025_and_follow_up_tickets_are_recorded::assert-45', 'test_security_requirements.py::SecurityRequirementsTest::test_sd024_sd025_and_follow_up_tickets_are_recorded::assert-46', 'test_security_requirements.py::SecurityRequirementsTest::test_sd024_sd025_and_follow_up_tickets_are_recorded::assert-47', 'test_security_requirements.py::SecurityRequirementsTest::test_sd024_sd025_and_follow_up_tickets_are_recorded::assert-48', 'test_security_requirements.py::SecurityRequirementsTest::test_sd024_sd025_and_follow_up_tickets_are_recorded::assert-51', 'test_security_requirements.py::SecurityRequirementsTest::test_sd024_sd025_and_follow_up_tickets_are_recorded::assert-52', 'test_security_requirements.py::SecurityRequirementsTest::test_sd024_sd025_and_follow_up_tickets_are_recorded::assert-53', 'test_security_requirements.py::SecurityRequirementsTest::test_sd024_sd025_and_follow_up_tickets_are_recorded::assert-54', 'test_security_requirements.py::SecurityRequirementsTest::test_sd024_sd025_and_follow_up_tickets_are_recorded::assert-55', 'test_security_requirements.py::SecurityRequirementsTest::test_sd024_sd025_and_follow_up_tickets_are_recorded::assert-56', 'test_security_requirements.py::SecurityRequirementsTest::test_sd024_sd025_and_follow_up_tickets_are_recorded::assert-69', 'test_security_requirements.py::SecurityRequirementsTest::test_sd024_sd025_and_follow_up_tickets_are_recorded::assert-70', 'test_security_requirements.py::SecurityRequirementsTest::test_sd024_sd025_and_follow_up_tickets_are_recorded::assert-74', 'test_security_requirements.py::SecurityRequirementsTest::test_sd024_sd025_and_follow_up_tickets_are_recorded::assert-75', 'test_security_requirements.py::SecurityRequirementsTest::test_sd024_sd025_and_follow_up_tickets_are_recorded::assert-76')
EXPECTED_SHA256 = 'f8abbc6e80d9762115540ee340050df7d9dc7e196752aa8876bdaed048c604f9'
EXPECTED_LINE_COUNT = 141
HISTORICAL_COMBINED_ASSERTIONS = 1488
HISTORICAL_COMBINED_CATEGORIES = {"A": 30, "B": 596, "C": 618, "D": 244}
# BL-038 tranche 3y-b: the CURRENT_COMBINED_* constants were removed -- see the
# HISTORICAL_COMBINED_* pair above, which is what this tranche actually recorded. The
# removed pair froze the live tree onto the post-3s tally.
RIVAL_FILE = 'test_source_usage_policy.py'
RIVAL_CLASS = 'SourceUsagePolicyTest'
RIVAL_START = 'test_mandiant_distinguishes_rss_evidence_from_terms_evidence'
PRE_SHARD_HASHES = {'document_test_classification.json': '640585ca03d7836cbdd66edcc8e2b21df7ea1de946b767ae20fa5c12e0c5f15a', 'document_test_classification_001.json': '0e1893593594daf44fb52e32ea610f2f7deb572148338faf90f2edfa7949b2cd', 'document_test_classification_002.json': 'd86d521627dabfed4b4555b8759a50c9a3538a9d89d55c8f2e5d928845e39f46', 'document_test_classification_003.json': 'f3c28245d708cdd1fc20432e4f02cd01d2ecc5eb13da976beb0cc94872674ceb', 'document_test_classification_004.json': '26522ff5c37ce8a30d0f2dc61bd1b1cfcbdc60929e059d984890e97e1544f792', 'document_test_classification_005.json': '4eae57a35e144fd3480fba94a0f5e6ec9b32e3d757abb820238f75926809aac6'}

class Tranche3rClassificationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Round 1 (Blocker 1B): logical accepted window, no physical shard resolution.
        cls.entries = dth.accepted_window(ROOT, "3r")[1]
        cls.source = (ROOT / SOURCE_FILE).read_text(encoding="utf-8")
        cls.node = next(n for n in ast.parse(cls.source).body if isinstance(n, ast.ClassDef) and n.name == CLASS_NAME)
        cls.order = [m.name for m in dti._class_test_methods_in_source_order(cls.node)]
        cls.all_records = dti.enumerate_assertions(cls.source, SOURCE_FILE, [CLASS_NAME])
        cls.per = Counter(r.method for r in cls.all_records)
        cls.window = dti.enumerate_assertions(cls.source, SOURCE_FILE, [CLASS_NAME], method_ranges={CLASS_NAME: METHOD_RANGE})

    def test_scope_hash_line_budget_and_index_are_exact(self):
        """Round 1 (C085): accepted descriptor from the pinned map, accepted bytes and line
        count from the ledger, no physical shard read; current validity is the validator's."""
        accepted_scope, _window = dth.accepted_window(ROOT, "3r")
        self.assertEqual(accepted_scope, dth.ACCEPTED_SCOPES["3r"])
        self.assertEqual(tuple(accepted_scope[0]), ("file", "classes", "method_range"))
        dth.assert_accepted(self, ROOT, "3r", sha256=EXPECTED_SHA256, line_count=EXPECTED_LINE_COUNT)
        self.assertEqual([f.format() for f in dti.validate_indexed_manifests(root=ROOT)[0]], [])

    def test_every_entry_matches_live_source_and_hardcoded_categories(self):
        """BL-038 tranche 3x (C083): the accepted id list, the hardcoded B/C/D membership and
        the accepted counts are past facts from the ledger; source-to-manifest agreement is
        the validator's. Category/action consistency and continuity remain."""
        dth.assert_accepted(self, ROOT, "3r", category_counts={"A": 0, "B": 60, "C": 37, "D": 36})
        for e in self.entries:
            with self.subTest(id=e["id"]):
                self.assertEqual(e["action"], dti.CATEGORY_TO_ACTION[e["category"]])
        dth.assert_accepted_contracts_accounted_for(self, ROOT, "3r")

    def test_selection_is_latest_source_greedy_tail_and_wins_133_to_37(self):
        owned = {e["method"] for name in PRE_SHARDS for e in json.loads((ROOT/name).read_text(encoding="utf-8"))["assertions"]
                 if (e["file"], e["class"]) == (SOURCE_FILE, CLASS_NAME)}
        start = next(i for i,m in enumerate(self.order) if m not in owned)
        run=0; end=start
        while end < len(self.order) and run + self.per[self.order[end]] <= 150:
            run += self.per[self.order[end]]; end += 1
        self.assertEqual((self.order[start], end-start, run, end), (RANGE_START, 9, 133, len(self.order)))
        self.assertEqual(tuple((m,self.per[m]) for m in self.order[start:]), EXPECTED_METHOD_COUNTS)
        rival_text=(ROOT/RIVAL_FILE).read_text(encoding="utf-8")
        rival_node=next(n for n in ast.parse(rival_text).body if isinstance(n,ast.ClassDef) and n.name==RIVAL_CLASS)
        rival_order=[m.name for m in dti._class_test_methods_in_source_order(rival_node)]
        rival_per=Counter(r.method for r in dti.enumerate_assertions(rival_text,RIVAL_FILE,[RIVAL_CLASS]))
        rival_owned={e["method"] for name in PRE_SHARDS for e in json.loads((ROOT/name).read_text(encoding="utf-8"))["assertions"]
                     if (e["file"],e["class"])==(RIVAL_FILE,RIVAL_CLASS)}
        rs=next(i for i,m in enumerate(rival_order) if m not in rival_owned); rr=0; re=rs
        while re<len(rival_order) and rr+rival_per[rival_order[re]]<=150:
            rr+=rival_per[rival_order[re]]; re+=1
        self.assertEqual((rival_order[rs], re-rs, rr), (RIVAL_START,4,37))
        self.assertGreater(133,37)

    def test_a_zero_uses_whole_method_structural_measurement(self):
        methods={m.name:m for m in dti._class_test_methods_in_source_order(self.node)}
        by=defaultdict(list)
        for name,_ in EXPECTED_METHOD_COUNTS: by[tuple(type(x).__name__ for x in ast.walk(methods[name]))].append(name)
        self.assertEqual(sorted(tuple(v) for v in by.values() if len(v)>1), [])

    def test_combined_index_is_clean_and_security_class_is_fully_owned(self):
        failures,summary=dti.validate_indexed_manifests(root=ROOT)
        self.assertEqual([f.format() for f in failures],[])
        self.assertEqual((HISTORICAL_COMBINED_ASSERTIONS, HISTORICAL_COMBINED_CATEGORIES), (1488, {"A":30,"B":596,"C":618,"D":244}))
        self.assertEqual(summary["manifest_assertions"],summary["inventoried_assertions"])
        self.assertEqual(sum(summary["category_counts"][c] for c in ("A","B","C","D")),
                         summary["inventoried_assertions"])
        self.assertEqual((summary["unclassified"],summary["stale"],summary["fingerprint_mismatch"]),(0,0,0))
        owned={e["method"] for name in EXPECTED_INDEX for e in json.loads((ROOT/name).read_text(encoding="utf-8"))["assertions"]
               if (e["file"],e["class"])==(SOURCE_FILE,CLASS_NAME)}
        self.assertEqual(owned,set(self.order))

    def test_prior_accepted_shards_are_byte_identical(self):
        """BL-038 tranche 3x (C084): requiring the prior shards to stay byte-identical blocks
        Category C conversion. Their accepted bytes live in each tranche's ledger record."""
        for tranche in ("3f", "3h", "3i", "3j", "3k", "3l", "3m", "3o", "3p", "3q"):
            with self.subTest(tranche=tranche):
                dth.assert_accepted_contracts_accounted_for(self, ROOT, tranche)

    def test_category_a_zero_has_no_whole_method_structural_candidates(self):
        groups=defaultdict(list)
        methods={m.name:m for m in dti._class_test_methods_in_source_order(self.node)}
        for method_name,_ in EXPECTED_METHOD_COUNTS:
            method=methods[method_name]
            # Deliberately coarse first-pass candidate finder: literal values,
            # names and attribute spellings are ignored; node topology remains.
            groups[tuple(type(part).__name__ for part in ast.walk(method))].append(method_name)
        structural_groups=sorted(tuple(names) for names in groups.values() if len(names)>1)
        self.assertEqual(structural_groups,[])

    def test_sd024_and_sd025_bindings_are_bounded_to_their_own_sections(self):
        method=next(m for m in dti._class_test_methods_in_source_order(self.node) if m.name==RANGE_START)
        facts=_narrow_section_facts(method)
        self.assertIn(("decisions","## SD-024","## SD-025"),facts)
        self.assertIn(("decisions","## SD-025","## SD-026"),facts)

if __name__ == "__main__": unittest.main()
