#!/usr/bin/env python3
"""BL-038 tranche 3b: declared-scope/count structural guard for
document_test_classification.json's test_custom_domain.py entries.

document_test_inventory.py's validator can only check a manifest against
whatever scope it *declares* -- it cannot detect a class/file being
silently removed from that declared scope (both `scope` and the matching
`assertions` shrinking together, staying internally consistent). This
suite pins the expected scope/class-set/count as *hardcoded literals*,
independent of whatever the manifest file currently says, so a silent
scope shrinkage is caught here even though the validator alone would not
catch it.
"""

import json
import unittest
from pathlib import Path

import document_test_inventory as dti

ROOT = Path(__file__).resolve().parent
MANIFEST_PATH = ROOT / "document_test_classification.json"
SOURCE_FILE = "test_custom_domain.py"

# Hardcoded literal contract -- NOT derived from the manifest or from a
# live AST scan. This is what makes scope shrinkage detectable.
EXPECTED_CLASSES = (
    "DocsCnameFileTest",
    "CnameSurvivesGenerationTest",
    "ArticleBriefContractUnchangedTest",
    "Bl007DocumentationTest",
    "ReadmePublicUrlTest",
    "Bl007ClosureRecordTest",
    "TicketIdTypoTest",
)
EXPECTED_ASSERTION_COUNT = 97
EXPECTED_CATEGORY_COUNTS = {"A": 12, "B": 74, "C": 0, "D": 11}


class DocumentTestClassificationScopeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest_text = MANIFEST_PATH.read_text(encoding="utf-8")
        cls.manifest = json.loads(cls.manifest_text)
        cls.source = (ROOT / SOURCE_FILE).read_text(encoding="utf-8")
        cls.live_records = dti.enumerate_assertions(
            cls.source, SOURCE_FILE, list(EXPECTED_CLASSES)
        )

    # 1-2: manifest exists, valid JSON object
    def test_manifest_exists_and_is_a_valid_json_object(self):
        self.assertTrue(MANIFEST_PATH.is_file())
        self.assertIsInstance(self.manifest, dict)

    # 3: schema_version == 1
    def test_schema_version_is_exactly_1(self):
        self.assertEqual(self.manifest["schema_version"], 1)
        self.assertIs(type(self.manifest["schema_version"]), int)

    # 4-8: scope is exactly test_custom_domain.py with the expected classes
    def test_scope_is_exactly_test_custom_domain_with_expected_classes(self):
        scope = self.manifest["scope"]
        self.assertEqual(len(scope), 1, "scope must list exactly 1 file")
        entry = scope[0]
        self.assertEqual(entry["file"], SOURCE_FILE)
        actual_classes = tuple(entry["classes"])
        self.assertEqual(
            actual_classes,
            EXPECTED_CLASSES,
            "declared scope classes must exactly equal the hardcoded literal "
            "expected-class tuple (order and membership)",
        )
        self.assertEqual(len(actual_classes), 7)

    # 9-10: assertion count and live inventory count both == 97 (literal)
    def test_assertion_and_live_inventory_counts_are_exactly_97(self):
        self.assertEqual(len(self.manifest["assertions"]), EXPECTED_ASSERTION_COUNT)
        self.assertEqual(len(self.live_records), EXPECTED_ASSERTION_COUNT)

    # 11: manifest IDs == live inventory IDs, exact equality
    def test_manifest_ids_match_live_inventory_ids_exactly(self):
        manifest_ids = {a["id"] for a in self.manifest["assertions"]}
        live_ids = {r.id for r in self.live_records}
        self.assertEqual(manifest_ids, live_ids)

    # 12: file/class/method/ordinal/assertion_api/fingerprint match live inventory
    def test_manifest_entries_match_live_inventory_fields(self):
        live_by_id = {r.id: r for r in self.live_records}
        for entry in self.manifest["assertions"]:
            with self.subTest(id=entry["id"]):
                record = live_by_id[entry["id"]]
                self.assertEqual(entry["file"], record.file)
                self.assertEqual(entry["class"], record.cls)
                self.assertEqual(entry["method"], record.method)
                self.assertEqual(int(entry["id"].rsplit("assert-", 1)[1]), record.ordinal)
                self.assertEqual(entry["assertion_api"], record.assertion_api)
                self.assertEqual(entry["fingerprint"], record.fingerprint)

    # 13: validate_manifest() failures are empty
    def test_validate_manifest_reports_no_failures(self):
        failures, summary = dti.validate_manifest(self.manifest, root=ROOT)
        self.assertEqual([f.format() for f in failures], [])
        self.assertEqual(summary["unclassified"], 0)
        self.assertEqual(summary["stale"], 0)
        self.assertEqual(summary["fingerprint_mismatch"], 0)

    # 14-15: category counts == corrected final tally, total == 97
    def test_category_counts_match_corrected_final_tally(self):
        counts = {"A": 0, "B": 0, "C": 0, "D": 0}
        for entry in self.manifest["assertions"]:
            counts[entry["category"]] += 1
        self.assertEqual(counts, EXPECTED_CATEGORY_COUNTS)
        self.assertEqual(sum(counts.values()), EXPECTED_ASSERTION_COUNT)

    # 16: action / category-action mapping is exact for every entry
    def test_action_matches_category_mapping_for_every_entry(self):
        for entry in self.manifest["assertions"]:
            with self.subTest(id=entry["id"]):
                self.assertEqual(
                    entry["action"], dti.CATEGORY_TO_ACTION[entry["category"]]
                )

    # 17: target style is uniform (single-target style) across the manifest
    def test_target_style_is_uniform_single_target_across_manifest(self):
        for entry in self.manifest["assertions"]:
            with self.subTest(id=entry["id"]):
                self.assertIn("target", entry)
                self.assertNotIn("targets", entry)
                self.assertIsInstance(entry["target"], str)
                self.assertTrue(entry["target"].strip())

    # 18-19: summary/rationale nonblank, and not filled with duplicate generic prose
    def test_summaries_and_rationales_are_nonblank_and_not_generic_filler(self):
        rationales = []
        for entry in self.manifest["assertions"]:
            with self.subTest(id=entry["id"]):
                self.assertTrue(entry["contract_summary"].strip())
                self.assertTrue(entry["rationale"].strip())
                self.assertGreater(len(entry["rationale"]), 40)
            rationales.append(entry["rationale"])
        # every rationale is individually written; none of the 97 entries
        # share identical rationale text (contract_summary may legitimately
        # repeat for the small set of genuine cross-method duplicate
        # assertions flagged as Category A -- rationale never does, since
        # each entry also explains its own call site).
        self.assertEqual(
            len(set(rationales)),
            EXPECTED_ASSERTION_COUNT,
            "no two entries may share identical rationale text",
        )

    # 20: scope shrinkage mutation -- removing a class from scope must be
    # caught by comparison against the hardcoded EXPECTED_CLASSES literal.
    def test_scope_shrinkage_mutation_is_caught_by_expected_classes_literal(self):
        mutated = tuple(
            c for c in self.manifest["scope"][0]["classes"] if c != "TicketIdTypoTest"
        )
        self.assertNotEqual(mutated, EXPECTED_CLASSES)
        with self.assertRaises(AssertionError):
            self.assertEqual(mutated, EXPECTED_CLASSES)

    # 21: deleting an assertion entry -> unclassified
    def test_assertion_deletion_mutation_is_detected_as_unclassified(self):
        mutated = json.loads(self.manifest_text)
        del mutated["assertions"][0]
        failures, _ = dti.validate_manifest(mutated, root=ROOT)
        types = {f.mismatch_type for f in failures}
        self.assertIn("unclassified", types)

    # 22: an extra, ordinal-out-of-range assertion entry -> stale-entry
    def test_extra_assertion_mutation_is_detected_as_stale_entry(self):
        mutated = json.loads(self.manifest_text)
        extra = dict(mutated["assertions"][0])
        extra["id"] = extra["id"].rsplit("assert-", 1)[0] + "assert-99"
        extra["ordinal"] = 99
        mutated["assertions"].append(extra)
        failures, _ = dti.validate_manifest(mutated, root=ROOT)
        types = {f.mismatch_type for f in failures}
        self.assertIn("stale-entry", types)

    # 23: a changed fingerprint -> fingerprint-mismatch
    def test_fingerprint_mutation_is_detected_as_fingerprint_mismatch(self):
        mutated = json.loads(self.manifest_text)
        mutated["assertions"][0]["fingerprint"] = "0" * 64
        failures, _ = dti.validate_manifest(mutated, root=ROOT)
        types = {f.mismatch_type for f in failures}
        self.assertIn("fingerprint-mismatch", types)

    # 24: category/action inconsistency -> category-action-mismatch
    def test_category_action_inconsistency_mutation_is_detected(self):
        mutated = json.loads(self.manifest_text)
        entry = mutated["assertions"][0]
        entry["category"] = "B" if entry["category"] != "B" else "D"
        # leave action unchanged, now inconsistent with the new category
        failures, _ = dti.validate_manifest(mutated, root=ROOT)
        types = {f.mismatch_type for f in failures}
        self.assertIn("category-action-mismatch", types)


if __name__ == "__main__":
    unittest.main()
