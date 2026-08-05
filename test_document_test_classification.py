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
catch it (round 1 review, Blocker 4: `_assert_expected_scope()` is
exercised both directly and against a deliberately-shrunk mutated copy,
so this claim is demonstrated, not just asserted).
"""

import json
import re
import unittest
from collections import OrderedDict
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
# Round 1 review corrected this tally after finding 30 entries were
# misclassified B (raw document-prose substring checks vulnerable to a
# meaning-preserving line-wrap) instead of C, and 4 of the original 12 A
# entries were prose duplicates that needed C, not A, as their primary
# classification.
EXPECTED_CATEGORY_COUNTS = {"A": 8, "B": 48, "C": 30, "D": 11}

EXPECTED_ENTRY_KEY_ORDER = (
    "id",
    "file",
    "class",
    "method",
    "ordinal",
    "assertion_api",
    "fingerprint",
    "targets",
    "category",
    "action",
    "contract_summary",
    "rationale",
)

# Entries whose single AST call site genuinely spans more than one target
# file/path (a `for` loop over distinct targets), keyed by manifest id.
EXPECTED_MULTI_TARGETS = {
    "test_custom_domain.py::TicketIdTypoTest::"
    "test_no_bl007_underscore_typo_anywhere_in_tracked_markdown_or_python::assert-01": (
        "README.md",
        "BACKLOG.md",
        "STATUS.md",
        "DECISIONS.md",
        "UI_SPEC.md",
        "fetch.py",
        "daily_json.py",
    ),
    "test_custom_domain.py::CnameSurvivesGenerationTest::"
    "test_cname_survives_repeated_full_archive_regeneration::assert-03": (
        "docs/archive/2026-07-10.html",
        "docs/archive/2026-07-11.html",
        "docs/archive/2026-07-12.html",
    ),
}

_PLACEHOLDER_WORDS = ("todo", "fixme", "placeholder", "tbd", "xxx", "n/a")
_CATEGORY_MARKERS = {
    "A": ("duplicat", "helper", "consolidat", "shared", "call site", "identical fingerprint", "repeated"),
    "B": (
        "structural", "atomic", "convention", "no internal wrap", "no wrap point",
        "no realistic", "token", "marker", "single word", "ordering", "position-based",
        "existence", "minimal", "not subject to", "editorial reflow", "config",
        "meaning-preserving edit", "short", "one line", "sanity", "postcondition",
        "cname",
    ),
    "C": ("brittle", "reflow", "wrap", "normalize", "prose", "clause", "sentence"),
    "D": ("exact", "identifier", "sha", "literal", "evidence"),
}


class DocumentTestClassificationScopeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest_text = MANIFEST_PATH.read_text(encoding="utf-8")
        cls.manifest = json.loads(cls.manifest_text)
        cls.source = (ROOT / SOURCE_FILE).read_text(encoding="utf-8")
        cls.live_records = dti.enumerate_assertions(
            cls.source, SOURCE_FILE, list(EXPECTED_CLASSES)
        )

    # -- shared helper, used both directly and against a mutated copy in
    # test_scope_shrinkage_mutation_is_actually_caught_by_the_guard below --
    def _assert_expected_scope(self, manifest):
        scope = manifest["scope"]
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

    def test_manifest_exists_and_is_a_valid_json_object(self):
        self.assertTrue(MANIFEST_PATH.is_file())
        self.assertIsInstance(self.manifest, dict)

    def test_schema_version_is_exactly_1(self):
        self.assertEqual(self.manifest["schema_version"], 1)
        self.assertIs(type(self.manifest["schema_version"]), int)

    def test_scope_is_exactly_test_custom_domain_with_expected_classes(self):
        self._assert_expected_scope(self.manifest)

    def test_assertion_and_live_inventory_counts_are_exactly_97(self):
        self.assertEqual(len(self.manifest["assertions"]), EXPECTED_ASSERTION_COUNT)
        self.assertEqual(len(self.live_records), EXPECTED_ASSERTION_COUNT)

    def test_manifest_ids_match_live_inventory_ids_in_source_order(self):
        # List (not set) equality: the manifest must list assertions in the
        # same source order document_test_inventory.py enumerates them in,
        # not merely contain the same set of IDs in arbitrary order.
        manifest_ids = [a["id"] for a in self.manifest["assertions"]]
        live_ids = [r.id for r in self.live_records]
        self.assertEqual(manifest_ids, live_ids)

    def test_manifest_entries_match_live_inventory_fields(self):
        live_by_id = {r.id: r for r in self.live_records}
        for entry in self.manifest["assertions"]:
            with self.subTest(id=entry["id"]):
                record = live_by_id[entry["id"]]
                self.assertEqual(entry["file"], record.file)
                self.assertEqual(entry["class"], record.cls)
                self.assertEqual(entry["method"], record.method)
                # Direct field check -- independent of re-deriving the
                # ordinal from the id string, so a manifest whose "id" and
                # "ordinal" fields were edited out of sync is still caught.
                self.assertEqual(entry["ordinal"], record.ordinal)
                self.assertEqual(
                    int(entry["id"].rsplit("assert-", 1)[1]), record.ordinal
                )
                self.assertEqual(entry["assertion_api"], record.assertion_api)
                self.assertEqual(entry["fingerprint"], record.fingerprint)

    def test_validate_manifest_reports_no_failures(self):
        failures, summary = dti.validate_manifest(self.manifest, root=ROOT)
        self.assertEqual([f.format() for f in failures], [])
        self.assertEqual(summary["unclassified"], 0)
        self.assertEqual(summary["stale"], 0)
        self.assertEqual(summary["fingerprint_mismatch"], 0)

    def test_category_counts_match_corrected_final_tally(self):
        counts = {"A": 0, "B": 0, "C": 0, "D": 0}
        for entry in self.manifest["assertions"]:
            counts[entry["category"]] += 1
        self.assertEqual(counts, EXPECTED_CATEGORY_COUNTS)
        self.assertEqual(sum(counts.values()), EXPECTED_ASSERTION_COUNT)

    def test_action_matches_category_mapping_for_every_entry(self):
        for entry in self.manifest["assertions"]:
            with self.subTest(id=entry["id"]):
                self.assertEqual(
                    entry["action"], dti.CATEGORY_TO_ACTION[entry["category"]]
                )

    # Round 1 fix (Blocker 2): every entry uses `targets` (a list), never
    # the old single-string `target`; genuinely multi-file call sites list
    # every real target path, not a slash-joined/brace-style combined label.
    def test_all_entries_use_targets_list_style_not_target(self):
        for entry in self.manifest["assertions"]:
            with self.subTest(id=entry["id"]):
                self.assertNotIn("target", entry)
                self.assertIn("targets", entry)
                targets = entry["targets"]
                self.assertIsInstance(targets, list)
                self.assertTrue(targets, "targets must be nonempty")
                self.assertEqual(len(targets), len(set(targets)), "targets must be unique")
                for t in targets:
                    self.assertIsInstance(t, str)
                    self.assertTrue(t.strip())

    def test_known_multi_target_entries_list_every_real_target_path(self):
        by_id = {a["id"]: a for a in self.manifest["assertions"]}
        for entry_id, expected_targets in EXPECTED_MULTI_TARGETS.items():
            with self.subTest(id=entry_id):
                self.assertIn(entry_id, by_id)
                self.assertEqual(tuple(by_id[entry_id]["targets"]), expected_targets)

    def test_non_multi_target_entries_have_exactly_one_target(self):
        multi_target_ids = set(EXPECTED_MULTI_TARGETS)
        for entry in self.manifest["assertions"]:
            if entry["id"] in multi_target_ids:
                continue
            with self.subTest(id=entry["id"]):
                self.assertEqual(len(entry["targets"]), 1)

    # Round 1 fix (Blocker 5): exact-uniqueness across all 97 rationale
    # strings was itself brittle (it forbids two genuine duplicate-fingerprint
    # entries from sharing a rationale, and rewards inventing 97 distinct
    # wordings over clear ones). Replaced with a structural quality check:
    # nonblank, no placeholder filler, and category-appropriate content.
    def test_summaries_and_rationales_are_nonblank_and_category_appropriate(self):
        for entry in self.manifest["assertions"]:
            with self.subTest(id=entry["id"]):
                summary = entry["contract_summary"]
                rationale = entry["rationale"]
                self.assertTrue(summary.strip())
                self.assertTrue(rationale.strip())
                self.assertGreater(len(rationale), 40)
                lowered = rationale.lower()
                for placeholder in _PLACEHOLDER_WORDS:
                    self.assertNotIn(placeholder, lowered)
                markers = _CATEGORY_MARKERS[entry["category"]]
                self.assertTrue(
                    any(marker in lowered for marker in markers),
                    f"rationale for category {entry['category']} should mention "
                    f"one of {markers}: {rationale!r}",
                )

    # Round 1 fix (Blocker 4): the mutation test now demonstrates the actual
    # gap it claims to close, using the SAME helper the real scope check
    # uses -- rather than just proving unequal tuples fail assertEqual.
    def test_scope_shrinkage_mutation_is_actually_caught_by_the_guard(self):
        mutated = json.loads(self.manifest_text)
        mutated["scope"][0]["classes"] = [
            c for c in mutated["scope"][0]["classes"] if c != "TicketIdTypoTest"
        ]
        mutated["assertions"] = [
            a for a in mutated["assertions"] if a["class"] != "TicketIdTypoTest"
        ]
        # Step 1: prove the gap this guard exists to close -- a manifest
        # that shrank its own declared scope, self-consistently, passes
        # validate_manifest() with zero failures.
        failures, _ = dti.validate_manifest(mutated, root=ROOT)
        self.assertEqual(failures, [])
        # Step 2: prove the structural guard (the same helper the real
        # test above uses) actually catches what the validator missed.
        with self.assertRaises(AssertionError):
            self._assert_expected_scope(mutated)

    def test_assertion_deletion_mutation_is_detected_as_unclassified(self):
        mutated = json.loads(self.manifest_text)
        del mutated["assertions"][0]
        failures, _ = dti.validate_manifest(mutated, root=ROOT)
        types = {f.mismatch_type for f in failures}
        self.assertIn("unclassified", types)

    def test_extra_assertion_mutation_is_detected_as_stale_entry(self):
        mutated = json.loads(self.manifest_text)
        extra = dict(mutated["assertions"][0])
        extra["id"] = extra["id"].rsplit("assert-", 1)[0] + "assert-99"
        extra["ordinal"] = 99
        mutated["assertions"].append(extra)
        failures, _ = dti.validate_manifest(mutated, root=ROOT)
        types = {f.mismatch_type for f in failures}
        self.assertIn("stale-entry", types)

    def test_fingerprint_mutation_is_detected_as_fingerprint_mismatch(self):
        mutated = json.loads(self.manifest_text)
        mutated["assertions"][0]["fingerprint"] = "0" * 64
        failures, _ = dti.validate_manifest(mutated, root=ROOT)
        types = {f.mismatch_type for f in failures}
        self.assertIn("fingerprint-mismatch", types)

    def test_category_action_inconsistency_mutation_is_detected(self):
        mutated = json.loads(self.manifest_text)
        entry = mutated["assertions"][0]
        entry["category"] = "B" if entry["category"] != "B" else "D"
        failures, _ = dti.validate_manifest(mutated, root=ROOT)
        types = {f.mismatch_type for f in failures}
        self.assertIn("category-action-mismatch", types)

    # Round 1 fix (Blocker 3): deterministic manifest format -- fixed key
    # order per entry, one compact-JSON line per assertion, final newline.
    def test_manifest_entry_key_order_is_deterministic(self):
        raw = json.loads(self.manifest_text, object_pairs_hook=OrderedDict)
        for entry in raw["assertions"]:
            with self.subTest(id=entry.get("id")):
                self.assertEqual(tuple(entry.keys()), EXPECTED_ENTRY_KEY_ORDER)

    def test_manifest_assertions_block_is_one_entry_per_line(self):
        lines = self.manifest_text.splitlines()
        start = next(i for i, l in enumerate(lines) if l.strip() == '"assertions": [')
        end = next(i for i, l in enumerate(lines) if i > start and l.strip() == "]")
        entry_lines = lines[start + 1 : end]
        self.assertEqual(len(entry_lines), EXPECTED_ASSERTION_COUNT)
        for line in entry_lines:
            stripped = line.strip().rstrip(",")
            parsed = json.loads(stripped)
            self.assertIsInstance(parsed, dict)

    def test_manifest_has_trailing_newline_and_deterministic_reread(self):
        self.assertTrue(self.manifest_text.endswith("\n"))
        reread = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
        self.assertEqual(reread, self.manifest)


if __name__ == "__main__":
    unittest.main()
