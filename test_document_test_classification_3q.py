#!/usr/bin/env python3
"""BL-038 tranche 3q: selection and classification guards for the second
SecurityRequirementsTest method-range window.

This module deliberately keeps tranche-3q-specific current-state assertions out
of the long historical classification guard.  It pins the selection rule, the
new shard's live inventory, and the narrow source bindings that ordinary
assertion fingerprints cannot see.
"""

import ast
import hashlib
import json
import unittest
from collections import Counter, defaultdict
from pathlib import Path

import document_test_inventory as dti
import document_test_history as dth

ROOT = Path(__file__).resolve().parent
INDEX_PATH = ROOT / dti.INDEX_FILENAME
SOURCE_FILE = "test_security_requirements.py"
CLASS_NAME = "SecurityRequirementsTest"
SHARD_FILENAME = "document_test_classification_005.json"
SHARD_PATH = ROOT / SHARD_FILENAME
RANGE_START = "test_bl029_is_recorded_verbatim_as_complete"
RANGE_END = "test_bl015_is_complete_and_removed_from_active_work"
METHOD_RANGE = {"start": RANGE_START, "end": RANGE_END}
SELECTION_CAP = 150
EXPECTED_ASSERTION_COUNT = 124
EXPECTED_METHOD_COUNT = 11
EXPECTED_LINE_COUNT = 130
EXPECTED_SHA256 = "4eae57a35e144fd3480fba94a0f5e6ec9b32e3d757abb820238f75926809aac6"
EXPECTED_COMBINED_ASSERTIONS = 1355
EXPECTED_COMBINED_CATEGORIES = {"A": 30, "B": 536, "C": 581, "D": 208}
EXPECTED_CATEGORY_COUNTS = {"A": 0, "B": 49, "C": 42, "D": 33}
EXPECTED_API_COUNTS = {"assertIn": 103, "assertNotIn": 15, "assertRegex": 3, "assertNotRegex": 3}
EXPECTED_METHOD_ORDER = (
    ("test_bl029_is_recorded_verbatim_as_complete", 18),
    ("test_bl028_bl029_registration_does_not_reopen_or_merge_other_tickets", 9),
    ("test_sd027_partially_supersedes_sd021_and_preserves_its_other_contracts", 10),
    ("test_bl028_kickoff_does_not_reopen_bl017_or_bl022", 3),
    ("test_bl027_acceptance_head_is_distinct_from_pr54_final_head", 3),
    ("test_bl027_backlog_entry_records_completed_workflow_dispatch_validation", 30),
    ("test_bl026_closure_records_pending_run_limitation_and_leaves_other_gaps_unchanged", 5),
    ("test_current_gaps_non_required_and_triggers_are_distinct", 6),
    ("test_future_components_are_not_misstated_as_current", 6),
    ("test_no_secret_value_or_local_absolute_path_is_present", 6),
    ("test_bl015_is_complete_and_removed_from_active_work", 28),
)
NEXT_METHOD = "test_sd024_sd025_and_follow_up_tickets_are_recorded"
NEXT_METHOD_ASSERTIONS = 81
NEXT_RUNNING_TOTAL = 205
RIVAL_FILE = "test_source_usage_policy.py"
RIVAL_CLASS = "SourceUsagePolicyTest"
RIVAL_TAIL_METHODS = 4
RIVAL_TAIL_ASSERTIONS = 37
POST_3Q_SECURITY_TAIL_METHODS = 9
POST_3Q_SECURITY_TAIL_ASSERTIONS = 133
PRE_3Q_SHARDS = (
    "document_test_classification.json",
    "document_test_classification_001.json",
    "document_test_classification_002.json",
    "document_test_classification_003.json",
    "document_test_classification_004.json",
)
EXPECTED_INDEX = PRE_3Q_SHARDS + (SHARD_FILENAME,)
CURRENT_INDEX = EXPECTED_INDEX + ("document_test_classification_006.json", "document_test_classification_007.json")
CURRENT_COMBINED_ASSERTIONS = 1525
CURRENT_COMBINED_CATEGORIES = {"A": 30, "B": 612, "C": 638, "D": 245}
EXPECTED_DUPLICATE_GROUPS = (
    (
        SOURCE_FILE + "::" + CLASS_NAME + "::test_bl028_bl029_registration_does_not_reopen_or_merge_other_tickets::assert-04",
        SOURCE_FILE + "::" + CLASS_NAME + "::test_bl027_backlog_entry_records_completed_workflow_dispatch_validation::assert-24",
    ),
    (
        SOURCE_FILE + "::" + CLASS_NAME + "::test_bl028_bl029_registration_does_not_reopen_or_merge_other_tickets::assert-06",
        SOURCE_FILE + "::" + CLASS_NAME + "::test_bl027_backlog_entry_records_completed_workflow_dispatch_validation::assert-27",
    ),
)
# The class-level document bindings are load-bearing for every target claim in
# this shard.  Local variable names inside the test methods are intentionally
# not part of the contract.
EXPECTED_SETUP_BINDINGS = {
    "backlog": "BACKLOG.md",
    "status": "STATUS.md",
    "decisions": "DECISIONS.md",
    "agents": "AGENTS.md",
}


class Tranche3qSecurityRequirementsRangeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # BL-038 tranche 3x round 1 (Blocker 1B): candidate entries are the LOGICAL accepted
        # window. No physical owning shard is resolved, so co-resident unrelated scopes can
        # never leak in and a legal re-shard cannot break the fixture.
        cls.entries = dth.accepted_window(ROOT, "3q")[1]
        cls.source = (ROOT / SOURCE_FILE).read_text(encoding="utf-8")
        cls.tree = ast.parse(cls.source, filename=SOURCE_FILE)
        cls.node = next(n for n in cls.tree.body if isinstance(n, ast.ClassDef) and n.name == CLASS_NAME)
        cls.methods = {m.name: m for m in dti._class_test_methods_in_source_order(cls.node)}
        cls.order = list(cls.methods)
        cls.whole = dti.enumerate_assertions(cls.source, SOURCE_FILE, [CLASS_NAME])
        cls.per = Counter(r.method for r in cls.whole)
        cls.window = dti.enumerate_assertions(
            cls.source, SOURCE_FILE, [CLASS_NAME], method_ranges={CLASS_NAME: METHOD_RANGE}
        )

    def test_index_and_scope_are_exactly_the_new_disjoint_range(self):
        """BL-038 tranche 3x round 1 (C080): the accepted scope descriptor comes from the
        pinned map and the accepted bytes and line count from the ledger. No physical shard is
        read and the exact CURRENT index is not pinned -- index validity, shard format, the
        line cap and scope legality are all the existing validator's contract."""
        accepted_scope, _window = dth.accepted_window(ROOT, "3q")
        self.assertEqual(accepted_scope, dth.ACCEPTED_SCOPES["3q"])
        self.assertEqual(tuple(accepted_scope[0]), ("file", "classes", "method_range"))
        dth.assert_accepted(self, ROOT, "3q", sha256=EXPECTED_SHA256, line_count=EXPECTED_LINE_COUNT)
        self.assertEqual([f.format() for f in dti.validate_indexed_manifests(root=ROOT)[0]], [])


    def test_combined_index_is_clean_at_the_post_3q_totals(self):
        failures, summary = dti.validate_indexed_manifests(root=ROOT)
        self.assertEqual([f.format() for f in failures], [])
        # EXPECTED_COMBINED_* above remains the exact post-3q historical
        # snapshot. The live repository has since legally appended tranches 3r and 3s.
        self.assertEqual((EXPECTED_COMBINED_ASSERTIONS, EXPECTED_COMBINED_CATEGORIES),
                         (1355, {"A": 30, "B": 536, "C": 581, "D": 208}))
        self.assertEqual(summary["shard_count"], len(CURRENT_INDEX))
        self.assertEqual(summary["shard_files"], list(CURRENT_INDEX))
        self.assertEqual(summary["inventoried_assertions"], CURRENT_COMBINED_ASSERTIONS)
        self.assertEqual(summary["manifest_assertions"], CURRENT_COMBINED_ASSERTIONS)
        self.assertEqual(summary["category_counts"], CURRENT_COMBINED_CATEGORIES)
        self.assertEqual(
            (summary["unclassified"], summary["stale"], summary["fingerprint_mismatch"]),
            (0, 0, 0),
        )

    def test_entries_are_exactly_the_live_inventory_window_in_source_order(self):
        """BL-038 tranche 3x (C079): the accepted id list and count are past facts, and
        source-to-manifest agreement is the existing validator's contract. Category/action
        consistency stays, plus accepted-contract continuity."""
        for entry in self.entries:
            with self.subTest(id=entry["id"]):
                self.assertEqual(entry["action"], dti.CATEGORY_TO_ACTION[entry["category"]])
        dth.assert_accepted_contracts_accounted_for(self, ROOT, "3q")

    def test_method_order_counts_and_window_boundaries_are_hardcoded(self):
        self.assertEqual(len(EXPECTED_METHOD_ORDER), EXPECTED_METHOD_COUNT)
        self.assertEqual(sum(n for _, n in EXPECTED_METHOD_ORDER), EXPECTED_ASSERTION_COUNT)
        self.assertEqual([m for m, _ in EXPECTED_METHOD_ORDER], self.order[19:30])
        for method, count in EXPECTED_METHOD_ORDER:
            with self.subTest(method=method):
                self.assertEqual(self.per[method], count)
        self.assertEqual(self.order[19], RANGE_START)
        self.assertEqual(self.order[29], RANGE_END)
        self.assertEqual({r.method for r in self.window}, {m for m, _ in EXPECTED_METHOD_ORDER})

    def test_selection_is_rederived_from_the_pre_3q_index_and_wins_124_to_37(self):
        owned = {
            e["method"]
            for name in PRE_3Q_SHARDS
            for e in json.loads((ROOT / name).read_text(encoding="utf-8"))["assertions"]
            if (e["file"], e["class"]) == (SOURCE_FILE, CLASS_NAME)
        }
        start = next(i for i, m in enumerate(self.order) if m not in owned)
        self.assertEqual((start, self.order[start]), (19, RANGE_START))
        run = 0
        end = start
        while end < len(self.order) and run + self.per[self.order[end]] <= SELECTION_CAP:
            run += self.per[self.order[end]]
            end += 1
        self.assertEqual((end - start, run), (EXPECTED_METHOD_COUNT, EXPECTED_ASSERTION_COUNT))
        self.assertEqual((self.order[end], self.per[self.order[end]]), (NEXT_METHOD, NEXT_METHOD_ASSERTIONS))
        self.assertEqual(run + self.per[self.order[end]], NEXT_RUNNING_TOTAL)
        self.assertGreater(NEXT_RUNNING_TOTAL, SELECTION_CAP)

        rival_source = (ROOT / RIVAL_FILE).read_text(encoding="utf-8")
        rival_node = next(n for n in ast.parse(rival_source, filename=RIVAL_FILE).body
                          if isinstance(n, ast.ClassDef) and n.name == RIVAL_CLASS)
        rival_order = [m.name for m in dti._class_test_methods_in_source_order(rival_node)]
        rival_per = Counter(r.method for r in dti.enumerate_assertions(rival_source, RIVAL_FILE, [RIVAL_CLASS]))
        rival_owned = {
            e["method"]
            for name in PRE_3Q_SHARDS
            for e in json.loads((ROOT / name).read_text(encoding="utf-8"))["assertions"]
            if (e["file"], e["class"]) == (RIVAL_FILE, RIVAL_CLASS)
        }
        rival_start = next(i for i, m in enumerate(rival_order) if m not in rival_owned)
        rival_run = 0
        rival_end = rival_start
        while rival_end < len(rival_order) and rival_run + rival_per[rival_order[rival_end]] <= SELECTION_CAP:
            rival_run += rival_per[rival_order[rival_end]]
            rival_end += 1
        self.assertEqual((rival_end - rival_start, rival_run),
                         (RIVAL_TAIL_METHODS, RIVAL_TAIL_ASSERTIONS))
        self.assertGreater(EXPECTED_ASSERTION_COUNT, rival_run)

    def test_category_and_api_breakdowns_are_the_recorded_ones(self):
        # BL-038 tranche 3x (C078): accepted category and API breakdowns from the ledger.
        dth.assert_accepted(self, ROOT, "3q", entry_count=EXPECTED_ASSERTION_COUNT,
                            category_counts=EXPECTED_CATEGORY_COUNTS)
        self.assertEqual(sum(EXPECTED_API_COUNTS.values()), EXPECTED_ASSERTION_COUNT)

    def test_category_a_is_zero_on_whole_method_structural_evidence(self):
        """BL-038 tranche 3x (C077, H7-A+B). The accepted-time measurement is gone: the
        exact duplicate groups, the two colliding method names, their [9, 30] assertion
        counts and the collision categories were a snapshot of the corpus, and a legal
        Category C conversion changes fingerprints. `structural_groups == []` over the LIVE
        3q window is not re-frozen either. Accepted A=0 is a ledger fact. What remains is
        the H7-B mechanics of the node-type skeleton grouper, proven on a small synthetic
        AST fixture: topology alone decides the grouping, so different names and literals
        with the same topology group together, and a different topology does not."""
        record = dth.assert_accepted(self, ROOT, "3q", category_counts=EXPECTED_CATEGORY_COUNTS)
        self.assertEqual(record["historical"]["category_counts"]["A"], 0)
        fixture = ast.parse(
            "class F:\n"
            "    def test_one(self):\n"
            "        self.assertIn('alpha', 'alphabet')\n"
            "    def test_two(self):\n"
            "        self.assertIn('beta', 'betamax')\n"
            "    def test_three(self):\n"
            "        for item in ('x',):\n"
            "            self.assertIn(item, 'xyz')\n"
        )
        methods = {m.name: m for m in ast.walk(fixture) if isinstance(m, ast.FunctionDef)}
        self.assertEqual(sorted(methods), ["test_one", "test_three", "test_two"])
        by_skeleton = defaultdict(list)
        for name, node in sorted(methods.items()):
            by_skeleton[tuple(type(part).__name__ for part in ast.walk(node))].append(name)
        groups = sorted(tuple(names) for names in by_skeleton.values() if len(names) > 1)
        # Same topology, different names and literals -> one group.
        self.assertEqual(groups, [("test_one", "test_two")])
        # Different topology -> never grouped with them.
        self.assertEqual([g for g in by_skeleton.values() if g == ["test_three"]], [["test_three"]])
        self.assertEqual(len(by_skeleton), 2)

    def test_post_3q_remaining_tails_are_measured_not_forbidden(self):
        """BL-038 tranche 3x (C081): the accepted tail counts are past facts, and rebuilding
        "what earlier shards already owned" by reading the historical shard FILES pinned
        physical placement. Ownership is logical now: the point that survives is that the
        tail is measured rather than forbidden -- methods this tranche does not own are
        simply not owned by it, which a later tranche may legally claim."""
        owned_by_3q = {m for m in self.order
                       if dth.owns("3q", SOURCE_FILE, CLASS_NAME, m)}
        self.assertTrue(owned_by_3q)
        self.assertTrue(set(self.order) - owned_by_3q)  # a tail exists, and is not forbidden
        dth.assert_accepted_contracts_accounted_for(self, ROOT, "3q")
        # This records future work; it deliberately does not assert that a
        # later disjoint method range may never own these methods.

    def test_setupclass_document_bindings_match_the_manifest_targets(self):
        setup = next(m for m in self.node.body if isinstance(m, ast.FunctionDef) and m.name == "setUpClass")
        bindings = {}
        for assign in ast.walk(setup):
            if not (isinstance(assign, ast.Assign) and len(assign.targets) == 1
                    and isinstance(assign.targets[0], ast.Attribute)):
                continue
            target = assign.targets[0]
            if not (isinstance(target.value, ast.Name) and target.value.id == "cls"):
                continue
            md = [n.value for n in ast.walk(assign.value)
                  if isinstance(n, ast.Constant) and isinstance(n.value, str) and n.value.endswith(".md")]
            if md:
                bindings[target.attr] = md[0]
        self.assertEqual(bindings, EXPECTED_SETUP_BINDINGS)

    def test_anchored_manifest_targets_have_matching_outer_section_markers(self):
        """Narrow used-binding guard.  For a target carrying `#BL-NNN` or
        `#SD-NNN`, the selected method must bind/read that exact section marker
        outside the assertion call.  This catches retargeting a local `bl029`,
        `bl027`, `sd021` or `sd027` binding while every assertion fingerprint
        remains unchanged, without pinning incidental local variable names."""
        targets_by_method = defaultdict(set)
        for entry in self.entries:
            targets_by_method[entry["method"]].update(entry["targets"])
        for method_name, targets in targets_by_method.items():
            node = self.methods[method_name]
            outer_strings = {
                n.value for n in ast.walk(node)
                if isinstance(n, ast.Constant) and isinstance(n.value, str)
            }
            for target in targets:
                if "#BL-" in target:
                    marker = "## " + target.split("#", 1)[1]
                elif "#SD-" in target:
                    marker = "## " + target.split("#", 1)[1]
                else:
                    continue
                with self.subTest(method=method_name, marker=marker):
                    self.assertIn(marker, outer_strings)


if __name__ == "__main__":
    unittest.main()
