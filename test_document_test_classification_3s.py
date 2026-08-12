#!/usr/bin/env python3
"""BL-038 tranche 3s: remaining SourceUsagePolicyTest tail classification guards."""
import ast
import hashlib
import json
import unittest
from collections import Counter, defaultdict
from pathlib import Path

import document_test_inventory as dti
import document_test_history as dth

ROOT = Path(__file__).resolve().parent
SOURCE_FILE = "test_source_usage_policy.py"
CLASS_NAME = "SourceUsagePolicyTest"
SHARD_FILENAME = "document_test_classification_007.json"
PRE_SHARDS = (
    "document_test_classification.json",
    "document_test_classification_001.json",
    "document_test_classification_002.json",
    "document_test_classification_003.json",
    "document_test_classification_004.json",
    "document_test_classification_005.json",
    "document_test_classification_006.json",
)
EXPECTED_INDEX = PRE_SHARDS + (SHARD_FILENAME,)
RANGE_START = "test_mandiant_distinguishes_rss_evidence_from_terms_evidence"
RANGE_END = "test_relationship_section_defers_enforcement_to_bl032"
EXPECTED_METHOD_COUNTS = (
    (RANGE_START, 11),
    ("test_output_similarity_controls_are_recorded_as_bl032_merged", 3),
    ("test_output_similarity_controls_distinguish_mechanical_from_residual_risk", 20),
    (RANGE_END, 3),
)
EXPECTED_ASSERTIONS = 37
EXPECTED_API_COUNTS = {"assertEqual": 2, "assertIn": 31, "assertTrue": 3, "assertNotIn": 1}
EXPECTED_CATEGORY_COUNTS = {"A": 0, "B": 16, "C": 20, "D": 1}
EXPECTED_COMBINED_ASSERTIONS = 1525
EXPECTED_COMBINED_CATEGORIES = {"A": 30, "B": 612, "C": 638, "D": 245}
EXPECTED_LINE_COUNT = 45
EXPECTED_SHA256 = "24674dbc4707baa94782428a4600cd1addd920dcddf0960aa137b0080e33d441"
EXPECTED_C_IDS = frozenset({
    "test_source_usage_policy.py::SourceUsagePolicyTest::test_mandiant_distinguishes_rss_evidence_from_terms_evidence::assert-10",
    "test_source_usage_policy.py::SourceUsagePolicyTest::test_mandiant_distinguishes_rss_evidence_from_terms_evidence::assert-11",
    "test_source_usage_policy.py::SourceUsagePolicyTest::test_output_similarity_controls_are_recorded_as_bl032_merged::assert-02",
    "test_source_usage_policy.py::SourceUsagePolicyTest::test_output_similarity_controls_are_recorded_as_bl032_merged::assert-03",
    "test_source_usage_policy.py::SourceUsagePolicyTest::test_output_similarity_controls_distinguish_mechanical_from_residual_risk::assert-04",
    "test_source_usage_policy.py::SourceUsagePolicyTest::test_output_similarity_controls_distinguish_mechanical_from_residual_risk::assert-06",
    "test_source_usage_policy.py::SourceUsagePolicyTest::test_output_similarity_controls_distinguish_mechanical_from_residual_risk::assert-07",
    "test_source_usage_policy.py::SourceUsagePolicyTest::test_output_similarity_controls_distinguish_mechanical_from_residual_risk::assert-09",
    "test_source_usage_policy.py::SourceUsagePolicyTest::test_output_similarity_controls_distinguish_mechanical_from_residual_risk::assert-10",
    "test_source_usage_policy.py::SourceUsagePolicyTest::test_output_similarity_controls_distinguish_mechanical_from_residual_risk::assert-11",
    "test_source_usage_policy.py::SourceUsagePolicyTest::test_output_similarity_controls_distinguish_mechanical_from_residual_risk::assert-12",
    "test_source_usage_policy.py::SourceUsagePolicyTest::test_output_similarity_controls_distinguish_mechanical_from_residual_risk::assert-13",
    "test_source_usage_policy.py::SourceUsagePolicyTest::test_output_similarity_controls_distinguish_mechanical_from_residual_risk::assert-14",
    "test_source_usage_policy.py::SourceUsagePolicyTest::test_output_similarity_controls_distinguish_mechanical_from_residual_risk::assert-15",
    "test_source_usage_policy.py::SourceUsagePolicyTest::test_output_similarity_controls_distinguish_mechanical_from_residual_risk::assert-16",
    "test_source_usage_policy.py::SourceUsagePolicyTest::test_output_similarity_controls_distinguish_mechanical_from_residual_risk::assert-17",
    "test_source_usage_policy.py::SourceUsagePolicyTest::test_output_similarity_controls_distinguish_mechanical_from_residual_risk::assert-18",
    "test_source_usage_policy.py::SourceUsagePolicyTest::test_output_similarity_controls_distinguish_mechanical_from_residual_risk::assert-19",
    "test_source_usage_policy.py::SourceUsagePolicyTest::test_output_similarity_controls_distinguish_mechanical_from_residual_risk::assert-20",
    "test_source_usage_policy.py::SourceUsagePolicyTest::test_relationship_section_defers_enforcement_to_bl032::assert-03",
})
EXPECTED_D_IDS = frozenset({
    "test_source_usage_policy.py::SourceUsagePolicyTest::test_output_similarity_controls_are_recorded_as_bl032_merged::assert-01",
})

def _owning_shard(tranche):
    """BL-038 tranche 3x: resolve the shard that CURRENTLY holds this tranche's accepted
    scope by scanning the live index, instead of hardcoding a physical filename. A legal
    re-shard may move the range to another shard, and the accepted facts live in the
    ledger either way."""
    index = json.loads((ROOT / dti.INDEX_FILENAME).read_text(encoding="utf-8"))
    accepted = dth.ACCEPTED_SCOPES[tranche]
    for name in index["shards"]:
        manifest = json.loads((ROOT / name).read_text(encoding="utf-8"))
        if any(entry in accepted for entry in manifest["scope"]):
            return ROOT / name
    raise AssertionError(f"no indexed shard currently holds tranche {tranche}'s accepted scope")


def _method_node(source, method_name):
    tree = ast.parse(source, filename=SOURCE_FILE)
    cls = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == CLASS_NAME)
    return next(m for m in dti._class_test_methods_in_source_order(cls) if m.name == method_name)


def _constant(node):
    return node.value if isinstance(node, ast.Constant) else None


def _row_binding_facts(method):
    """Resolve rows_by_id aliases to semantic source-id/column facts."""
    assigns = [
        n for n in ast.walk(method)
        if isinstance(n, ast.Assign)
        and len(n.targets) == 1
        and isinstance(n.targets[0], ast.Name)
    ]
    table_aliases = set()
    row_aliases = {}
    cell_aliases = {}
    for _ in range(len(assigns) + 2):
        changed = False
        for assign in assigns:
            name, value = assign.targets[0].id, assign.value
            if (
                isinstance(value, ast.Attribute)
                and isinstance(value.value, ast.Name)
                and value.value.id == "self"
                and value.attr == "rows_by_id"
            ):
                if name not in table_aliases:
                    table_aliases.add(name)
                    changed = True
            elif isinstance(value, ast.Name) and value.id in table_aliases:
                if name not in table_aliases:
                    table_aliases.add(name)
                    changed = True

            if isinstance(value, ast.Subscript):
                base = value.value
                is_table = (
                    isinstance(base, ast.Attribute)
                    and isinstance(base.value, ast.Name)
                    and base.value.id == "self"
                    and base.attr == "rows_by_id"
                ) or (isinstance(base, ast.Name) and base.id in table_aliases)
                key = _constant(value.slice)
                if is_table and isinstance(key, str) and row_aliases.get(name) != key:
                    row_aliases[name] = key
                    changed = True
            elif isinstance(value, ast.Name) and value.id in row_aliases:
                if row_aliases.get(name) != row_aliases[value.id]:
                    row_aliases[name] = row_aliases[value.id]
                    changed = True

            if (
                isinstance(value, ast.Call)
                and isinstance(value.func, ast.Attribute)
                and value.func.attr == "_split_cell"
                and len(value.args) == 1
                and isinstance(value.args[0], ast.Subscript)
                and isinstance(value.args[0].value, ast.Name)
                and value.args[0].value.id in row_aliases
            ):
                column = _constant(value.args[0].slice)
                if isinstance(column, str):
                    fact = (row_aliases[value.args[0].value.id], column)
                    if cell_aliases.get(name) != fact:
                        cell_aliases[name] = fact
                        changed = True
            elif isinstance(value, ast.Name) and value.id in cell_aliases:
                if cell_aliases.get(name) != cell_aliases[value.id]:
                    cell_aliases[name] = cell_aliases[value.id]
                    changed = True
        if not changed:
            break
    return set(row_aliases.values()), set(cell_aliases.values())


def _section_binding_facts(method):
    """Resolve self.policy split aliases to semantic section-boundary facts."""
    assigns = [
        n for n in ast.walk(method)
        if isinstance(n, ast.Assign)
        and len(n.targets) == 1
        and isinstance(n.targets[0], ast.Name)
    ]
    aliases = {}

    def int_value(node):
        value = _constant(node)
        return value if isinstance(value, int) else None

    def resolve(node):
        if (
            isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Name)
            and node.value.id == "self"
            and node.attr == "policy"
        ):
            return ("policy",)
        if isinstance(node, ast.Name):
            return aliases.get(node.id)
        if not isinstance(node, ast.Subscript) or int_value(node.slice) not in (0, 1):
            return None
        call = node.value
        if not (
            isinstance(call, ast.Call)
            and isinstance(call.func, ast.Attribute)
            and call.func.attr == "split"
            and len(call.args) >= 2
            and isinstance(call.args[0], ast.Constant)
            and int_value(call.args[1]) == 1
        ):
            return None
        source = resolve(call.func.value)
        if source is None:
            return None
        marker = call.args[0].value
        index = int_value(node.slice)
        if index == 1:
            return ("tail", source, marker)
        if index == 0 and source[0] == "tail":
            return ("section", source[1], source[2], marker)
        return None

    for _ in range(len(assigns) + 2):
        changed = False
        for assign in assigns:
            value = resolve(assign.value)
            name = assign.targets[0].id
            if value is not None and aliases.get(name) != value:
                aliases[name] = value
                changed = True
        if not changed:
            break
    return set(aliases.values())


def _mutate_method(source, method_name, old, new):
    method = _method_node(source, method_name)
    lines = source.splitlines(keepends=True)
    segment = "".join(lines[method.lineno - 1:method.end_lineno])
    if segment.count(old) != 1:
        raise AssertionError(
            f"{method_name}: expected one mutation target for {old!r}, got {segment.count(old)}"
        )
    segment = segment.replace(old, new, 1)
    mutated = "".join(lines[:method.lineno - 1]) + segment + "".join(lines[method.end_lineno:])
    return _method_node(mutated, method_name)


class Tranche3sClassificationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = (ROOT / SOURCE_FILE).read_text(encoding="utf-8")
        cls.node = next(n for n in ast.parse(cls.source).body if isinstance(n, ast.ClassDef) and n.name == CLASS_NAME)
        cls.order = [m.name for m in dti._class_test_methods_in_source_order(cls.node)]
        cls.all_records = dti.enumerate_assertions(cls.source, SOURCE_FILE, [CLASS_NAME])
        cls.per = Counter(r.method for r in cls.all_records)
        selected = {name for name, _ in EXPECTED_METHOD_COUNTS}
        cls.window = [r for r in cls.all_records if r.method in selected]
        cls.text = _owning_shard("3s").read_text(encoding="utf-8")
        cls.manifest = json.loads(cls.text)
        cls.entries = cls.manifest["assertions"]

    def test_latest_main_tail_selection_is_exactly_four_methods_37_assertions(self):
        owned = {
            e["method"]
            for name in PRE_SHARDS
            for e in json.loads((ROOT / name).read_text(encoding="utf-8"))["assertions"]
            if (e["file"], e["class"]) == (SOURCE_FILE, CLASS_NAME)
        }
        start = next(i for i, name in enumerate(self.order) if name not in owned)
        run = 0
        end = start
        while end < len(self.order) and run + self.per[self.order[end]] <= 150:
            run += self.per[self.order[end]]
            end += 1
        self.assertEqual((self.order[start], end - start, run, end), (RANGE_START, 4, 37, len(self.order)))
        self.assertEqual(tuple((name, self.per[name]) for name in self.order[start:]), EXPECTED_METHOD_COUNTS)

    def test_shard_scope_bytes_and_index_are_pinned(self):
        # BL-038 tranche 3x (C088): accepted scope descriptor from the pinned map, accepted
        # bytes/lines/entry count from the ledger; the exact CURRENT index is not pinned and
        # index validity is the validator's.
        accepted_scope, _window = dth.accepted_window(ROOT, "3s")
        self.assertEqual(accepted_scope, dth.ACCEPTED_SCOPES["3s"])
        dth.assert_accepted(self, ROOT, "3s", sha256=EXPECTED_SHA256,
                            line_count=EXPECTED_LINE_COUNT, entry_count=EXPECTED_ASSERTIONS)
        self.assertEqual(tuple(self.manifest["scope"][0]), ("file", "classes", "method_range"))
        self.assertLessEqual(len(self.text.splitlines()), dti.SHARD_LINE_CAP)
        self.assertEqual([f.format() for f in dti.validate_indexed_manifests(root=ROOT)[0]], [])

    def test_live_assertions_and_reviewed_categories_match_exactly(self):
        """BL-038 tranche 3x (C087): the accepted id list, the reviewed C/D membership and the
        accepted counts are past facts from the ledger; source-to-manifest agreement is the
        validator's. Category/action consistency and continuity remain."""
        dth.assert_accepted(self, ROOT, "3s", category_counts={"A": 0, "B": 16, "C": 20, "D": 1})
        for entry in self.entries:
            with self.subTest(id=entry["id"]):
                self.assertEqual(entry["action"], dti.CATEGORY_TO_ACTION[entry["category"]])
        dth.assert_accepted_contracts_accounted_for(self, ROOT, "3s")

    def test_category_a_zero_has_no_coarse_whole_method_topology_candidates(self):
        methods = {m.name: m for m in dti._class_test_methods_in_source_order(self.node)}
        groups = defaultdict(list)
        for method_name, _ in EXPECTED_METHOD_COUNTS:
            groups[tuple(type(part).__name__ for part in ast.walk(methods[method_name]))].append(method_name)
        self.assertEqual(sorted(tuple(names) for names in groups.values() if len(names) > 1), [])

    def test_assertion_external_bindings_are_semantically_pinned(self):
        method = _method_node(self.source, RANGE_START)
        rows, cells = _row_binding_facts(method)
        self.assertIn("mandiant", rows)
        self.assertEqual(
            cells,
            {("mandiant", "official_evidence_url"), ("mandiant", "evidence_type")},
        )

        controls = (
            "section",
            ("policy",),
            "## 7. Output-similarity and quotation controls",
            "## 8. Recheck triggers",
        )
        for method_name in (
            "test_output_similarity_controls_are_recorded_as_bl032_merged",
            "test_output_similarity_controls_distinguish_mechanical_from_residual_risk",
        ):
            with self.subTest(method=method_name):
                self.assertIn(controls, _section_binding_facts(_method_node(self.source, method_name)))

        detailed = _section_binding_facts(
            _method_node(
                self.source,
                "test_output_similarity_controls_distinguish_mechanical_from_residual_risk",
            )
        )
        self.assertIn(
            (
                "section",
                controls,
                "### A. 機械的に強制可能なBL-032要件",
                "### B. 自動的な完全検出を約束しない残余リスク",
            ),
            detailed,
        )
        self.assertIn(
            ("tail", controls, "### B. 自動的な完全検出を約束しない残余リスク"),
            detailed,
        )
        self.assertIn(
            ("tail", ("policy",), "## 10. Relationship to BL-032 and BL-009"),
            _section_binding_facts(_method_node(self.source, RANGE_END)),
        )

    def test_binding_mutations_allow_aliases_and_reject_semantic_retargeting(self):
        alias_row = _mutate_method(
            self.source,
            RANGE_START,
            'mandiant = self.rows_by_id["mandiant"]',
            'rows_alias = self.rows_by_id\n        mandiant = rows_alias["mandiant"]',
        )
        rows, cells = _row_binding_facts(alias_row)
        self.assertIn("mandiant", rows)
        self.assertEqual(
            cells,
            {("mandiant", "official_evidence_url"), ("mandiant", "evidence_type")},
        )

        wrong_row = _mutate_method(
            self.source,
            RANGE_START,
            'self.rows_by_id["mandiant"]',
            'self.rows_by_id["google_tag"]',
        )
        wrong_rows, wrong_cells = _row_binding_facts(wrong_row)
        self.assertNotIn("mandiant", wrong_rows)
        self.assertNotEqual(
            wrong_cells,
            {("mandiant", "official_evidence_url"), ("mandiant", "evidence_type")},
        )

        method_name = "test_output_similarity_controls_are_recorded_as_bl032_merged"
        alias_policy = _mutate_method(
            self.source,
            method_name,
            "controls = self.policy.split(",
            "policy_alias = self.policy\n        controls = policy_alias.split(",
        )
        expected = (
            "section",
            ("policy",),
            "## 7. Output-similarity and quotation controls",
            "## 8. Recheck triggers",
        )
        self.assertIn(expected, _section_binding_facts(alias_policy))

        widened = _mutate_method(
            self.source,
            method_name,
            '"## 8. Recheck triggers"',
            '"## 9. Unknowns and owner verification"',
        )
        self.assertNotIn(expected, _section_binding_facts(widened))

    def test_combined_index_is_clean_and_source_usage_class_is_fully_owned(self):
        failures, summary = dti.validate_indexed_manifests(root=ROOT)
        self.assertEqual([f.format() for f in failures], [])
        self.assertEqual(summary["inventoried_assertions"], EXPECTED_COMBINED_ASSERTIONS)
        self.assertEqual(summary["manifest_assertions"], EXPECTED_COMBINED_ASSERTIONS)
        self.assertEqual(summary["category_counts"], EXPECTED_COMBINED_CATEGORIES)
        self.assertEqual((summary["unclassified"], summary["stale"], summary["fingerprint_mismatch"]), (0, 0, 0))
        owned = {
            e["method"]
            for name in EXPECTED_INDEX
            for e in json.loads((ROOT / name).read_text(encoding="utf-8"))["assertions"]
            if (e["file"], e["class"]) == (SOURCE_FILE, CLASS_NAME)
        }
        self.assertEqual(owned, set(self.order))


if __name__ == "__main__":
    unittest.main()
