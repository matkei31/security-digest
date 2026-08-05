#!/usr/bin/env python3
"""BL-038 (Fable 5 whole-repository review R-04, tranche 3): unit tests for
document_test_inventory.py. Uses short synthetic Python source fixtures and
synthetic manifests only -- no production test file is copied into a
fixture. Standard library unittest only.
"""

import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

import document_test_inventory as dti


def _records_to_manifest_entries(records, *, category="A", action="keep"):
    entries = []
    for record in records:
        entries.append(
            {
                "id": record.id,
                "file": record.file,
                "class": record.cls,
                "method": record.method,
                "ordinal": record.ordinal,
                "assertion_api": record.assertion_api,
                "fingerprint": record.fingerprint,
                "target": "dummy-target",
                "category": category,
                "action": action,
                "contract_summary": f"synthetic summary for {record.id}",
                "rationale": f"synthetic rationale for {record.id}",
            }
        )
    return entries


def _manifest_for(file_name, classes, entries):
    return {
        "schema_version": 1,
        "scope": [{"file": file_name, "classes": classes}],
        "assertions": entries,
    }


def _failure_types(failures):
    return {f.mismatch_type for f in failures}


class EnumerationOrderTest(unittest.TestCase):
    def test_unittest_assertions_are_listed_in_source_order(self):
        src = (
            "import unittest\n"
            "class FooTest(unittest.TestCase):\n"
            "    def test_basic(self):\n"
            "        self.assertEqual(1, 1)\n"
            "        self.assertIn('a', 'abc')\n"
            "        self.assertTrue(True)\n"
        )
        records = dti.enumerate_assertions(src, "foo.py", ["FooTest"])
        self.assertEqual(
            [(r.ordinal, r.assertion_api) for r in records],
            [(1, "assertEqual"), (2, "assertIn"), (3, "assertTrue")],
        )
        self.assertEqual(
            [r.id for r in records],
            [
                "foo.py::FooTest::test_basic::assert-01",
                "foo.py::FooTest::test_basic::assert-02",
                "foo.py::FooTest::test_basic::assert-03",
            ],
        )

    def test_bare_assert_statements_are_enumerated(self):
        src = (
            "import unittest\n"
            "class FooTest(unittest.TestCase):\n"
            "    def test_basic(self):\n"
            "        assert 1 == 1\n"
            "        assert 'a' in 'abc', 'must contain a'\n"
        )
        records = dti.enumerate_assertions(src, "foo.py", ["FooTest"])
        self.assertEqual([r.assertion_api for r in records], ["assert", "assert"])
        self.assertEqual(len(records), 2)

    def test_assert_raises_context_manager_is_enumerated_exactly_once(self):
        src = (
            "import unittest\n"
            "class FooTest(unittest.TestCase):\n"
            "    def test_basic(self):\n"
            "        with self.assertRaises(ValueError):\n"
            "            raise ValueError('boom')\n"
            "        self.assertTrue(True)\n"
        )
        records = dti.enumerate_assertions(src, "foo.py", ["FooTest"])
        # Must appear exactly once (the withitem's context_expr call node is
        # reachable both via the With-node check and via generic descendant
        # traversal; the second visit must be skipped, not double-counted).
        self.assertEqual(
            [(r.ordinal, r.assertion_api) for r in records],
            [(1, "assertRaises"), (2, "assertTrue")],
        )

    def test_assert_raises_regex_context_manager_is_enumerated(self):
        src = (
            "import unittest\n"
            "class FooTest(unittest.TestCase):\n"
            "    def test_basic(self):\n"
            "        with self.assertRaisesRegex(ValueError, 'boom'):\n"
            "            raise ValueError('boom')\n"
        )
        records = dti.enumerate_assertions(src, "foo.py", ["FooTest"])
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].assertion_api, "assertRaisesRegex")

    def test_custom_assertion_helper_call_is_enumerated(self):
        src = (
            "import unittest\n"
            "class FooTest(unittest.TestCase):\n"
            "    def _assert_row_state(self, row, state):\n"
            "        self.assertIn(state, row)\n"
            "    def test_basic(self):\n"
            "        self._assert_row_state('abc', 'a')\n"
        )
        records = dti.enumerate_assertions(src, "foo.py", ["FooTest"])
        # Only the test_* method's own call site is enumerated as an entry
        # for this class scope -- the helper's internal assertIn is not a
        # separate entry (the helper method itself is not a test_* method,
        # so its body is not walked as a separate method's assertions).
        # Its definition is NOT ignored, though: the call site's
        # fingerprint incorporates the resolved helper's own body (see
        # FingerprintStabilityTest's composite-fingerprint tests), so a
        # semantic change to the helper is still detected even though the
        # call site itself stays untouched.
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].assertion_api, "_assert_row_state")

    def test_plain_setup_helper_is_not_treated_as_an_assertion_helper(self):
        src = (
            "import unittest\n"
            "class FooTest(unittest.TestCase):\n"
            "    def _build_fixture(self):\n"
            "        return {'a': 1}\n"
            "    def test_basic(self):\n"
            "        fixture = self._build_fixture()\n"
            "        self.assertEqual(fixture['a'], 1)\n"
        )
        records = dti.enumerate_assertions(src, "foo.py", ["FooTest"])
        self.assertEqual([r.assertion_api for r in records], ["assertEqual"])


class FingerprintStabilityTest(unittest.TestCase):
    def _fingerprint(self, src):
        return dti.enumerate_assertions(src, "foo.py", ["FooTest"])[0].fingerprint

    def test_source_formatting_does_not_change_fingerprint(self):
        src_a = (
            "import unittest\n"
            "class FooTest(unittest.TestCase):\n"
            "    def test_basic(self):\n"
            "        self.assertEqual(\n"
            "            'hello',\n"
            "            'hello',\n"
            "        )\n"
        )
        src_b = (
            "import unittest\n"
            "class FooTest(unittest.TestCase):\n"
            "    def test_basic(self):\n"
            "        self.assertEqual('hello', 'hello')\n"
        )
        self.assertEqual(self._fingerprint(src_a), self._fingerprint(src_b))

    def test_blank_lines_and_indentation_do_not_change_fingerprint(self):
        src_a = (
            "import unittest\n"
            "class FooTest(unittest.TestCase):\n"
            "    def test_basic(self):\n"
            "        self.assertEqual('hello', 'hello')\n"
        )
        src_b = (
            "import unittest\n\n\n"
            "class FooTest(unittest.TestCase):\n\n"
            "    def test_basic(self):\n\n\n"
            "        self.assertEqual('hello', 'hello')\n"
        )
        self.assertEqual(self._fingerprint(src_a), self._fingerprint(src_b))

    def test_literal_value_change_changes_fingerprint(self):
        src_a = (
            "import unittest\n"
            "class FooTest(unittest.TestCase):\n"
            "    def test_basic(self):\n"
            "        self.assertEqual('hello', 'hello')\n"
        )
        src_b = (
            "import unittest\n"
            "class FooTest(unittest.TestCase):\n"
            "    def test_basic(self):\n"
            "        self.assertEqual('hello', 'world')\n"
        )
        self.assertNotEqual(self._fingerprint(src_a), self._fingerprint(src_b))

    def test_assertion_api_change_changes_fingerprint(self):
        src_a = (
            "import unittest\n"
            "class FooTest(unittest.TestCase):\n"
            "    def test_basic(self):\n"
            "        self.assertEqual('hello', 'hello')\n"
        )
        src_b = (
            "import unittest\n"
            "class FooTest(unittest.TestCase):\n"
            "    def test_basic(self):\n"
            "        self.assertIn('hello', 'hello')\n"
        )
        self.assertNotEqual(self._fingerprint(src_a), self._fingerprint(src_b))

    def test_line_number_shift_alone_does_not_change_fingerprint(self):
        # Same assertion, pushed down several lines by unrelated leading
        # statements/comments -- lineno changes, the assertion's own code
        # does not.
        src_a = (
            "import unittest\n"
            "class FooTest(unittest.TestCase):\n"
            "    def test_basic(self):\n"
            "        self.assertEqual(1, 1)\n"
        )
        src_b = (
            "import unittest\n"
            "class FooTest(unittest.TestCase):\n"
            "    def test_basic(self):\n"
            "        # a comment\n"
            "        x = 1\n"
            "        y = 1\n"
            "        self.assertEqual(1, 1)\n"
        )
        # ordinal shifts too (there is only one assertion in each, so
        # ordinal is still 1 in both -- what matters here is only that the
        # assertion's OWN fingerprint, not its position, stays identical).
        self.assertEqual(self._fingerprint(src_a), self._fingerprint(src_b))


class CustomHelperCompositeFingerprintTest(unittest.TestCase):
    """BL-038 tranche 3a round 1 review Blocker 1: a custom assertion
    helper's call site fingerprint must incorporate the resolved helper
    DEFINITION's own body, not just the call node -- otherwise a semantic
    change to the helper (its assertion API, comparison structure, or
    literal values) could go undetected while the call site itself stays
    untouched, silently drifting the manifest out of sync with what the
    helper actually checks.
    """

    HELPER_DEF = (
        "    def _assert_row_state(self, row, state):\n"
        "        self.assertIn(state, row)\n"
    )

    def _fingerprint(self, helper_def):
        src = (
            "import unittest\n"
            "class FooTest(unittest.TestCase):\n"
            f"{helper_def}"
            "    def test_basic(self):\n"
            "        self._assert_row_state('abc', 'a')\n"
        )
        records = dti.enumerate_assertions(src, "foo.py", ["FooTest"])
        self.assertEqual(len(records), 1)
        return records[0].fingerprint

    def test_helper_body_formatting_change_does_not_change_fingerprint(self):
        reformatted = (
            "    def _assert_row_state(self, row, state):\n\n"
            "        self.assertIn(\n"
            "            state,\n"
            "            row,\n"
            "        )\n"
        )
        self.assertEqual(self._fingerprint(self.HELPER_DEF), self._fingerprint(reformatted))

    def test_helper_body_api_change_changes_fingerprint(self):
        changed = (
            "    def _assert_row_state(self, row, state):\n"
            "        self.assertNotIn(state, row)\n"
        )
        self.assertNotEqual(self._fingerprint(self.HELPER_DEF), self._fingerprint(changed))

    def test_helper_body_literal_change_changes_fingerprint(self):
        changed = (
            "    def _assert_row_state(self, row, state):\n"
            "        self.assertIn(state, row.upper())\n"
        )
        self.assertNotEqual(self._fingerprint(self.HELPER_DEF), self._fingerprint(changed))

    def test_helper_body_semantic_change_after_manifest_creation_is_fingerprint_mismatch(self):
        tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(tmpdir.cleanup)
        root = Path(tmpdir.name)
        src = (
            "import unittest\n"
            "class FooTest(unittest.TestCase):\n"
            f"{self.HELPER_DEF}"
            "    def test_basic(self):\n"
            "        self._assert_row_state('abc', 'a')\n"
        )
        (root / "foo.py").write_text(src, encoding="utf-8")
        records = dti.enumerate_assertions(src, "foo.py", ["FooTest"])
        manifest = _manifest_for("foo.py", ["FooTest"], _records_to_manifest_entries(records))

        # Change ONLY the helper body -- the call site is untouched.
        changed_src = (
            "import unittest\n"
            "class FooTest(unittest.TestCase):\n"
            "    def _assert_row_state(self, row, state):\n"
            "        self.assertNotIn(state, row)\n"
            "    def test_basic(self):\n"
            "        self._assert_row_state('abc', 'a')\n"
        )
        (root / "foo.py").write_text(changed_src, encoding="utf-8")

        failures, _ = dti.validate_manifest(manifest, root=root)
        self.assertIn("fingerprint-mismatch", _failure_types(failures))
        failure = next(f for f in failures if f.mismatch_type == "fingerprint-mismatch")
        self.assertEqual(failure.id, records[0].id)
        self.assertEqual(failure.cls, "FooTest")
        self.assertEqual(failure.method, "test_basic")
        # Failure output must stay short (identify the target), not dump
        # the whole document/source.
        self.assertLess(len(failure.format()), 300)


class PublicHelperPrecedenceAndUnresolvedHelperTest(unittest.TestCase):
    """BL-038 tranche 3a round 2 review Blocker 1: a PUBLIC-style helper
    name (`assert_section_contains`) also starts with "assert" and was
    previously matched by the generic unittest-builtin check BEFORE the
    custom-helper check ever ran, giving it a call-only fingerprint that
    couldn't see semantic drift in the helper's own body. Custom helper
    resolution must be checked first, for both naming styles. Separately,
    a call whose name matches the custom-helper pattern but has no
    same-class definition must raise an explicit error, never silently
    fall back to a call-only fingerprint or be silently skipped.
    """

    PUBLIC_HELPER_DEF = (
        "    def assert_section_contains(self, section, marker):\n"
        "        self.assertIn(marker, section)\n"
    )

    def _fingerprint(self, helper_def):
        src = (
            "import unittest\n"
            "class FooTest(unittest.TestCase):\n"
            f"{helper_def}"
            "    def test_basic(self):\n"
            "        self.assert_section_contains('abc', 'a')\n"
        )
        records = dti.enumerate_assertions(src, "foo.py", ["FooTest"])
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].assertion_api, "assert_section_contains")
        return records[0].fingerprint

    def test_public_helper_call_is_a_single_entry(self):
        # Assertion already made inside _fingerprint (len(records) == 1);
        # this test exists so that contract is checked independent of any
        # other assertion in this class about fingerprint values.
        self._fingerprint(self.PUBLIC_HELPER_DEF)

    def test_public_helper_body_formatting_change_does_not_change_fingerprint(self):
        reformatted = (
            "    def assert_section_contains(self, section, marker):\n\n"
            "        self.assertIn(\n            marker,\n            section,\n        )\n"
        )
        self.assertEqual(
            self._fingerprint(self.PUBLIC_HELPER_DEF), self._fingerprint(reformatted)
        )

    def test_public_helper_body_api_change_changes_fingerprint(self):
        changed = (
            "    def assert_section_contains(self, section, marker):\n"
            "        self.assertNotIn(marker, section)\n"
        )
        self.assertNotEqual(
            self._fingerprint(self.PUBLIC_HELPER_DEF), self._fingerprint(changed)
        )

    def test_public_helper_body_literal_change_changes_fingerprint(self):
        changed = (
            "    def assert_section_contains(self, section, marker):\n"
            "        self.assertIn(marker, section.upper())\n"
        )
        self.assertNotEqual(
            self._fingerprint(self.PUBLIC_HELPER_DEF), self._fingerprint(changed)
        )

    def test_public_helper_semantic_change_after_manifest_creation_is_fingerprint_mismatch(self):
        tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(tmpdir.cleanup)
        root = Path(tmpdir.name)
        src = (
            "import unittest\n"
            "class FooTest(unittest.TestCase):\n"
            f"{self.PUBLIC_HELPER_DEF}"
            "    def test_basic(self):\n"
            "        self.assert_section_contains('abc', 'a')\n"
        )
        (root / "foo.py").write_text(src, encoding="utf-8")
        records = dti.enumerate_assertions(src, "foo.py", ["FooTest"])
        manifest = _manifest_for("foo.py", ["FooTest"], _records_to_manifest_entries(records))

        changed_src = src.replace(
            "self.assertIn(marker, section)", "self.assertNotIn(marker, section)"
        )
        (root / "foo.py").write_text(changed_src, encoding="utf-8")
        failures, _ = dti.validate_manifest(manifest, root=root)
        self.assertIn("fingerprint-mismatch", _failure_types(failures))

    def test_unresolved_underscore_style_helper_call_is_an_explicit_failure(self):
        src = (
            "import unittest\n"
            "class FooTest(unittest.TestCase):\n"
            "    def test_basic(self):\n"
            "        self._assert_inherited_contract('x')\n"
        )
        with self.assertRaises(dti.InventoryError):
            dti.enumerate_assertions(src, "foo.py", ["FooTest"])

    def test_unresolved_public_style_helper_call_is_an_explicit_failure(self):
        src = (
            "import unittest\n"
            "class FooTest(unittest.TestCase):\n"
            "    def test_basic(self):\n"
            "        self.assert_custom_contract('x')\n"
        )
        with self.assertRaises(dti.InventoryError):
            dti.enumerate_assertions(src, "foo.py", ["FooTest"])

    def test_builtin_unittest_assertions_are_not_treated_as_unsupported_helpers(self):
        src = (
            "import unittest\n"
            "class FooTest(unittest.TestCase):\n"
            "    def test_basic(self):\n"
            "        self.assertEqual(1, 1)\n"
            "        self.assertIn('a', 'abc')\n"
            "        self.assertTrue(True)\n"
        )
        records = dti.enumerate_assertions(src, "foo.py", ["FooTest"])
        self.assertEqual(
            [r.assertion_api for r in records], ["assertEqual", "assertIn", "assertTrue"]
        )


class TransitiveHelperDependencyClosureTest(unittest.TestCase):
    """BL-038 tranche 3a round 2 review Blocker 2: a custom helper's
    fingerprint must fold in every same-class helper it calls, directly or
    transitively (not just the one it calls directly) -- otherwise a
    semantic change buried in a nested helper is invisible to both the
    call site's AST and the direct helper's AST, and the manifest would
    silently drift.
    """

    OUTER_INNER_SRC = (
        "import unittest\n"
        "class FooTest(unittest.TestCase):\n"
        "    def _assert_inner(self, value):\n"
        "        self.assertTrue(value)\n"
        "    def _assert_outer(self, value):\n"
        "        self._assert_inner(value)\n"
        "    def test_basic(self):\n"
        "        self._assert_outer(1)\n"
    )

    def _fingerprint(self, src):
        records = dti.enumerate_assertions(src, "foo.py", ["FooTest"])
        self.assertEqual(len(records), 1)
        return records[0].fingerprint

    def test_nested_helper_semantic_change_changes_outer_call_fingerprint(self):
        changed = self.OUTER_INNER_SRC.replace(
            "self.assertTrue(value)", "self.assertFalse(value)"
        )
        self.assertNotEqual(self._fingerprint(self.OUTER_INNER_SRC), self._fingerprint(changed))

    def test_nested_helper_formatting_change_does_not_change_fingerprint(self):
        reformatted = self.OUTER_INNER_SRC.replace(
            "        self.assertTrue(value)\n",
            "        self.assertTrue(\n            value\n        )\n",
        )
        self.assertEqual(self._fingerprint(self.OUTER_INNER_SRC), self._fingerprint(reformatted))

    def test_nested_helper_change_after_manifest_creation_is_fingerprint_mismatch(self):
        tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(tmpdir.cleanup)
        root = Path(tmpdir.name)
        (root / "foo.py").write_text(self.OUTER_INNER_SRC, encoding="utf-8")
        records = dti.enumerate_assertions(self.OUTER_INNER_SRC, "foo.py", ["FooTest"])
        manifest = _manifest_for("foo.py", ["FooTest"], _records_to_manifest_entries(records))

        changed = self.OUTER_INNER_SRC.replace(
            "self.assertTrue(value)", "self.assertFalse(value)"
        )
        (root / "foo.py").write_text(changed, encoding="utf-8")
        failures, _ = dti.validate_manifest(manifest, root=root)
        self.assertIn("fingerprint-mismatch", _failure_types(failures))

    def test_three_level_chain_detects_deepest_change(self):
        src = (
            "import unittest\n"
            "class FooTest(unittest.TestCase):\n"
            "    def _assert_deepest(self, value):\n"
            "        self.assertTrue(value)\n"
            "    def _assert_middle(self, value):\n"
            "        self._assert_deepest(value)\n"
            "    def _assert_top(self, value):\n"
            "        self._assert_middle(value)\n"
            "    def test_basic(self):\n"
            "        self._assert_top(1)\n"
        )
        changed = src.replace("self.assertTrue(value)", "self.assertFalse(value)")
        self.assertNotEqual(self._fingerprint(src), self._fingerprint(changed))

    def test_helper_cycle_does_not_infinite_recurse(self):
        src = (
            "import unittest\n"
            "class FooTest(unittest.TestCase):\n"
            "    def _assert_a(self, value):\n"
            "        self.assertTrue(value)\n"
            "        self._assert_b(value)\n"
            "    def _assert_b(self, value):\n"
            "        self._assert_a(value)\n"
            "    def test_basic(self):\n"
            "        self._assert_a(1)\n"
        )
        # Must complete (not hang/stack-overflow) and still enumerate the
        # one call-site assertion with a real fingerprint.
        records = dti.enumerate_assertions(src, "foo.py", ["FooTest"])
        self.assertEqual(len(records), 1)
        self.assertTrue(records[0].fingerprint)

    def test_unresolved_nested_helper_is_an_explicit_failure(self):
        src = (
            "import unittest\n"
            "class FooTest(unittest.TestCase):\n"
            "    def _assert_outer(self, value):\n"
            "        self._assert_missing(value)\n"
            "    def test_basic(self):\n"
            "        self._assert_outer(1)\n"
        )
        with self.assertRaises(dti.InventoryError) as ctx:
            dti.enumerate_assertions(src, "foo.py", ["FooTest"])
        # Failure must identify the class/helper, not dump the document.
        message = str(ctx.exception)
        self.assertIn("FooTest", message)
        self.assertIn("_assert_outer", message)
        self.assertLess(len(message), 400)


class ManifestValidationFailureTest(unittest.TestCase):
    """Each test builds a minimal synthetic (file, manifest) pair in a
    temp directory and checks validate_manifest() reports the specific
    failure type under test."""

    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmpdir.cleanup)
        self.root = Path(self._tmpdir.name)

    def _write_source(self, name, src):
        (self.root / name).write_text(src, encoding="utf-8")

    SRC = (
        "import unittest\n"
        "class FooTest(unittest.TestCase):\n"
        "    def test_basic(self):\n"
        "        self.assertEqual(1, 1)\n"
        "        self.assertIn('a', 'abc')\n"
    )

    def _valid_manifest(self):
        self._write_source("foo.py", self.SRC)
        records = dti.enumerate_assertions(self.SRC, "foo.py", ["FooTest"])
        entries = _records_to_manifest_entries(records)
        return _manifest_for("foo.py", ["FooTest"], entries)

    def test_valid_manifest_has_no_failures(self):
        manifest = self._valid_manifest()
        failures, summary = dti.validate_manifest(manifest, root=self.root)
        self.assertEqual(failures, [])
        self.assertEqual(summary["inventoried_assertions"], 2)
        self.assertEqual(summary["category_counts"]["A"], 2)

    def test_missing_manifest_entry_is_unclassified(self):
        manifest = self._valid_manifest()
        manifest["assertions"].pop()
        failures, _ = dti.validate_manifest(manifest, root=self.root)
        self.assertIn("unclassified", _failure_types(failures))

    def test_stale_manifest_entry_is_detected(self):
        manifest = self._valid_manifest()
        stale = dict(manifest["assertions"][0])
        stale["id"] = "foo.py::FooTest::test_basic::assert-09"
        stale["ordinal"] = 9
        manifest["assertions"].append(stale)
        failures, _ = dti.validate_manifest(manifest, root=self.root)
        self.assertIn("stale-entry", _failure_types(failures))

    def test_duplicate_id_is_detected(self):
        manifest = self._valid_manifest()
        manifest["assertions"].append(dict(manifest["assertions"][0]))
        failures, _ = dti.validate_manifest(manifest, root=self.root)
        self.assertIn("duplicate-id", _failure_types(failures))

    def test_duplicate_ordinal_key_is_detected(self):
        manifest = self._valid_manifest()
        dup = dict(manifest["assertions"][1])
        dup["ordinal"] = manifest["assertions"][0]["ordinal"]
        dup["id"] = manifest["assertions"][0]["id"]
        manifest["assertions"][1] = dup
        failures, _ = dti.validate_manifest(manifest, root=self.root)
        self.assertIn("duplicate-key", _failure_types(failures))

    def test_ordinal_gap_is_detected(self):
        manifest = self._valid_manifest()
        manifest["assertions"][1]["ordinal"] = 3
        manifest["assertions"][1]["id"] = "foo.py::FooTest::test_basic::assert-03"
        failures, _ = dti.validate_manifest(manifest, root=self.root)
        self.assertIn("ordinal-gap", _failure_types(failures))

    def test_invalid_category_is_detected(self):
        manifest = self._valid_manifest()
        manifest["assertions"][0]["category"] = "Z"
        failures, _ = dti.validate_manifest(manifest, root=self.root)
        self.assertIn("invalid-category", _failure_types(failures))

    def test_invalid_action_is_detected(self):
        manifest = self._valid_manifest()
        manifest["assertions"][0]["action"] = "rewrite_now"
        failures, _ = dti.validate_manifest(manifest, root=self.root)
        self.assertIn("invalid-action", _failure_types(failures))

    def test_category_action_mismatch_is_detected(self):
        manifest = self._valid_manifest()
        manifest["assertions"][0]["category"] = "C"
        # action left as "keep", which is only valid for category A.
        failures, _ = dti.validate_manifest(manifest, root=self.root)
        self.assertIn("category-action-mismatch", _failure_types(failures))

    def test_fingerprint_mismatch_is_detected(self):
        manifest = self._valid_manifest()
        manifest["assertions"][0]["fingerprint"] = "0" * 64
        failures, _ = dti.validate_manifest(manifest, root=self.root)
        self.assertIn("fingerprint-mismatch", _failure_types(failures))

    def test_blank_contract_summary_is_detected(self):
        manifest = self._valid_manifest()
        manifest["assertions"][0]["contract_summary"] = ""
        failures, _ = dti.validate_manifest(manifest, root=self.root)
        self.assertIn("missing-field", _failure_types(failures))

    def test_blank_rationale_is_detected(self):
        manifest = self._valid_manifest()
        manifest["assertions"][0]["rationale"] = ""
        failures, _ = dti.validate_manifest(manifest, root=self.root)
        self.assertIn("missing-field", _failure_types(failures))

    def test_unknown_class_in_scope_is_detected(self):
        manifest = self._valid_manifest()
        manifest["scope"][0]["classes"].append("NoSuchTest")
        failures, _ = dti.validate_manifest(manifest, root=self.root)
        self.assertIn("inventory-error", _failure_types(failures))

    def test_entry_referencing_file_outside_declared_scope_is_detected(self):
        manifest = self._valid_manifest()
        manifest["assertions"][0]["file"] = "bar.py"
        manifest["assertions"][0]["id"] = manifest["assertions"][0]["id"].replace(
            "foo.py", "bar.py"
        )
        failures, _ = dti.validate_manifest(manifest, root=self.root)
        self.assertIn("out-of-scope-file", _failure_types(failures))

    def test_entry_referencing_class_outside_declared_scope_is_detected(self):
        manifest = self._valid_manifest()
        manifest["assertions"][0]["class"] = "OtherTest"
        manifest["assertions"][0]["id"] = manifest["assertions"][0]["id"].replace(
            "FooTest", "OtherTest"
        )
        failures, _ = dti.validate_manifest(manifest, root=self.root)
        self.assertIn("out-of-scope-class", _failure_types(failures))

    def test_source_assertion_added_is_detected_as_unclassified(self):
        manifest = self._valid_manifest()
        grown_src = self.SRC + "        self.assertTrue(True)\n"
        self._write_source("foo.py", grown_src)
        failures, _ = dti.validate_manifest(manifest, root=self.root)
        self.assertIn("unclassified", _failure_types(failures))

    def test_source_assertion_removed_is_detected_as_stale(self):
        manifest = self._valid_manifest()
        shrunk_src = (
            "import unittest\n"
            "class FooTest(unittest.TestCase):\n"
            "    def test_basic(self):\n"
            "        self.assertEqual(1, 1)\n"
        )
        self._write_source("foo.py", shrunk_src)
        failures, _ = dti.validate_manifest(manifest, root=self.root)
        self.assertIn("stale-entry", _failure_types(failures))


class ManifestSchemaValidationTest(unittest.TestCase):
    """BL-038 tranche 3a round 1 review Blocker 2: the validator must
    itself enforce document_test_classification.json's schema shape --
    schema_version, top-level manifest/scope/assertions shape, the
    exactly-one target/targets contract (and manifest-wide style
    consistency), and non-bool ordinals -- not just per-field business
    rules on an assumed-well-formed manifest.
    """

    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmpdir.cleanup)
        self.root = Path(self._tmpdir.name)
        self.src = (
            "import unittest\n"
            "class FooTest(unittest.TestCase):\n"
            "    def test_basic(self):\n"
            "        self.assertEqual(1, 1)\n"
            "        self.assertIn('a', 'abc')\n"
        )
        (self.root / "foo.py").write_text(self.src, encoding="utf-8")
        self.records = dti.enumerate_assertions(self.src, "foo.py", ["FooTest"])

    def _valid_entries(self, *, use_targets=False):
        entries = _records_to_manifest_entries(self.records)
        if use_targets:
            for entry in entries:
                target = entry.pop("target")
                entry["targets"] = [target]
        return entries

    def _check(self, manifest):
        return dti.validate_manifest(manifest, root=self.root)

    def test_missing_schema_version_is_detected(self):
        manifest = {"scope": [{"file": "foo.py", "classes": ["FooTest"]}], "assertions": self._valid_entries()}
        failures, _ = self._check(manifest)
        self.assertIn("invalid-schema-version", _failure_types(failures))

    def test_wrong_schema_version_is_detected(self):
        manifest = _manifest_for("foo.py", ["FooTest"], self._valid_entries())
        manifest["schema_version"] = 999
        failures, _ = self._check(manifest)
        self.assertIn("invalid-schema-version", _failure_types(failures))

    def test_bool_schema_version_is_detected(self):
        manifest = _manifest_for("foo.py", ["FooTest"], self._valid_entries())
        manifest["schema_version"] = True
        failures, _ = self._check(manifest)
        self.assertIn("invalid-schema-version", _failure_types(failures))

    def test_scope_not_a_list_is_detected(self):
        manifest = _manifest_for("foo.py", ["FooTest"], self._valid_entries())
        manifest["scope"] = {"file": "foo.py", "classes": ["FooTest"]}
        failures, _ = self._check(manifest)
        self.assertIn("invalid-manifest-shape", _failure_types(failures))

    def test_assertions_not_a_list_is_detected(self):
        manifest = _manifest_for("foo.py", ["FooTest"], self._valid_entries())
        manifest["assertions"] = {"not": "a list"}
        failures, _ = self._check(manifest)
        self.assertIn("invalid-manifest-shape", _failure_types(failures))

    def test_scope_entry_not_an_object_is_detected(self):
        manifest = _manifest_for("foo.py", ["FooTest"], self._valid_entries())
        manifest["scope"] = ["foo.py"]
        failures, _ = self._check(manifest)
        self.assertIn("invalid-scope-shape", _failure_types(failures))

    def test_assertion_entry_not_an_object_is_detected(self):
        manifest = _manifest_for("foo.py", ["FooTest"], ["not an object"])
        failures, _ = self._check(manifest)
        self.assertIn("invalid-manifest-shape", _failure_types(failures))

    def test_both_target_and_targets_is_detected(self):
        entries = self._valid_entries()
        entries[0]["targets"] = [entries[0]["target"]]
        manifest = _manifest_for("foo.py", ["FooTest"], entries)
        failures, _ = self._check(manifest)
        self.assertIn("invalid-target", _failure_types(failures))

    def test_neither_target_nor_targets_is_detected(self):
        entries = self._valid_entries()
        del entries[0]["target"]
        manifest = _manifest_for("foo.py", ["FooTest"], entries)
        failures, _ = self._check(manifest)
        self.assertIn("invalid-target", _failure_types(failures))

    def test_blank_target_is_detected(self):
        entries = self._valid_entries()
        entries[0]["target"] = "   "
        manifest = _manifest_for("foo.py", ["FooTest"], entries)
        failures, _ = self._check(manifest)
        self.assertIn("invalid-target", _failure_types(failures))

    def test_empty_targets_list_is_detected(self):
        entries = self._valid_entries(use_targets=True)
        entries[0]["targets"] = []
        manifest = _manifest_for("foo.py", ["FooTest"], entries)
        failures, _ = self._check(manifest)
        self.assertIn("invalid-target", _failure_types(failures))

    def test_targets_with_blank_or_non_string_is_detected(self):
        entries = self._valid_entries(use_targets=True)
        entries[0]["targets"] = ["ok", "", 123]
        manifest = _manifest_for("foo.py", ["FooTest"], entries)
        failures, _ = self._check(manifest)
        self.assertIn("invalid-target", _failure_types(failures))

    def test_duplicate_targets_is_detected(self):
        entries = self._valid_entries(use_targets=True)
        entries[0]["targets"] = ["a", "a"]
        manifest = _manifest_for("foo.py", ["FooTest"], entries)
        failures, _ = self._check(manifest)
        self.assertIn("invalid-target", _failure_types(failures))

    def test_mixed_target_style_across_manifest_is_detected(self):
        entries = self._valid_entries()
        entries[1]["targets"] = [entries[1].pop("target")]
        manifest = _manifest_for("foo.py", ["FooTest"], entries)
        failures, _ = self._check(manifest)
        self.assertIn("mixed-target-style", _failure_types(failures))

    def test_bool_ordinal_is_detected(self):
        entries = self._valid_entries()
        entries[0]["ordinal"] = True
        entries[0]["id"] = "foo.py::FooTest::test_basic::assert-01"
        manifest = _manifest_for("foo.py", ["FooTest"], entries)
        failures, _ = self._check(manifest)
        self.assertIn("invalid-ordinal", _failure_types(failures))

    def test_valid_single_target_style_manifest_has_no_failures(self):
        manifest = _manifest_for("foo.py", ["FooTest"], self._valid_entries(use_targets=False))
        failures, _ = self._check(manifest)
        self.assertEqual(failures, [])

    def test_valid_multi_target_style_manifest_has_no_failures(self):
        manifest = _manifest_for("foo.py", ["FooTest"], self._valid_entries(use_targets=True))
        failures, _ = self._check(manifest)
        self.assertEqual(failures, [])

    # --- round 2 review: schema_version exactness, required scope/
    # assertions keys, and per-entry field TYPE safety (must not crash the
    # validator with an unhashable-type TypeError). ---

    def test_float_schema_version_is_rejected(self):
        # 1.0 == 1 in Python, so a naive `!= 1` check alone would accept
        # this; schema_version must be exactly the int 1, not a float.
        manifest = _manifest_for("foo.py", ["FooTest"], self._valid_entries())
        manifest["schema_version"] = 1.0
        failures, _ = self._check(manifest)
        self.assertIn("invalid-schema-version", _failure_types(failures))

    def test_missing_scope_key_is_detected(self):
        manifest = {"schema_version": 1, "assertions": self._valid_entries()}
        failures, _ = self._check(manifest)
        self.assertIn("invalid-manifest-shape", _failure_types(failures))

    def test_missing_assertions_key_is_detected(self):
        manifest = {"schema_version": 1, "scope": [{"file": "foo.py", "classes": ["FooTest"]}]}
        failures, _ = self._check(manifest)
        self.assertIn("invalid-manifest-shape", _failure_types(failures))

    def test_empty_scope_list_is_detected(self):
        manifest = {"schema_version": 1, "scope": [], "assertions": self._valid_entries()}
        failures, _ = self._check(manifest)
        self.assertIn("invalid-manifest-shape", _failure_types(failures))

    def test_scope_entry_with_empty_classes_is_detected(self):
        manifest = _manifest_for("foo.py", [], self._valid_entries())
        failures, _ = self._check(manifest)
        self.assertIn("invalid-scope-shape", _failure_types(failures))

    def test_entry_field_type_errors_are_caught_without_crashing(self):
        # Table-driven: each case sets ONE required string-ish field on
        # entries[0] to an unhashable/wrong-type value and confirms the
        # validator reports a clean failure (not a TypeError) rather than
        # crashing when that value is later used as a dict/set key. Values
        # are deliberately TRUTHY (nonempty list/dict, nonzero number) --
        # a falsy value ([], {}, None) is already caught earlier by the
        # existing missing-field check and never reaches this path, so it
        # wouldn't exercise the crash-safety fix this test targets.
        cases = [
            ("id", [1, 2, 3]),
            ("file", {"a": 1}),
            ("class", [1, 2, 3]),
            ("method", {"a": 1}),
            ("assertion_api", 123),
            ("contract_summary", ["x"]),
            ("rationale", ["x"]),
        ]
        for field, bad_value in cases:
            with self.subTest(field=field):
                entries = self._valid_entries()
                entries[0][field] = bad_value
                manifest = _manifest_for("foo.py", ["FooTest"], entries)
                # Must not raise -- this is the crash-safety assertion.
                failures, _ = self._check(manifest)
                self.assertIn("invalid-entry-shape", _failure_types(failures))

    def test_malformed_fingerprint_is_detected(self):
        entries = self._valid_entries()
        entries[0]["fingerprint"] = "not-64-hex-chars"
        manifest = _manifest_for("foo.py", ["FooTest"], entries)
        failures, _ = self._check(manifest)
        self.assertIn("invalid-fingerprint", _failure_types(failures))

    def test_uppercase_fingerprint_is_detected(self):
        entries = self._valid_entries()
        entries[0]["fingerprint"] = entries[0]["fingerprint"].upper()
        manifest = _manifest_for("foo.py", ["FooTest"], entries)
        failures, _ = self._check(manifest)
        self.assertIn("invalid-fingerprint", _failure_types(failures))

    def test_malformed_entry_does_not_crash_validator_and_other_entries_still_checked(self):
        entries = self._valid_entries()
        entries[0]["id"] = [1, 2, 3]  # unhashable -- would crash a naive validator
        manifest = _manifest_for("foo.py", ["FooTest"], entries)
        # Must complete and still report the second (valid) entry as fine
        # while flagging the first as invalid-entry-shape.
        failures, _ = self._check(manifest)
        self.assertIn("invalid-entry-shape", _failure_types(failures))
        self.assertNotIn(
            entries[1]["id"],
            {f.id for f in failures if f.mismatch_type not in ("unclassified",)},
        )


class AsyncTestMethodAndUnknownMethodTest(unittest.TestCase):
    """BL-038 tranche 3a round 1 review Blocker 3: `async def test_*`
    methods must be enumerated like any other test method (not silently
    skipped), and a manifest entry naming a method that does not exist at
    all must be distinguished from one naming a real method whose specific
    ordinal doesn't exist (`unknown-method` vs `stale-entry`).
    """

    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmpdir.cleanup)
        self.root = Path(self._tmpdir.name)

    def _write(self, src):
        (self.root / "foo.py").write_text(src, encoding="utf-8")

    def test_async_test_method_assertions_are_enumerated_in_source_order(self):
        src = (
            "import unittest\n"
            "class FooTest(unittest.TestCase):\n"
            "    async def test_basic(self):\n"
            "        self.assertEqual(1, 1)\n"
            "        assert 'a' in 'abc'\n"
        )
        records = dti.enumerate_assertions(src, "foo.py", ["FooTest"])
        self.assertEqual(
            [(r.ordinal, r.assertion_api) for r in records],
            [(1, "assertEqual"), (2, "assert")],
        )

    def test_async_custom_helper_semantic_change_is_detected(self):
        src = (
            "import unittest\n"
            "class FooTest(unittest.TestCase):\n"
            "    async def _assert_row_state(self, row, state):\n"
            "        self.assertIn(state, row)\n"
            "    async def test_basic(self):\n"
            "        await self._assert_row_state('abc', 'a')\n"
        )
        # Note: `await self._assert_row_state(...)` is an Await node
        # wrapping the Call -- the call itself is still reached by plain
        # descendant traversal, so this is enumerated exactly like the
        # synchronous case.
        records = dti.enumerate_assertions(src, "foo.py", ["FooTest"])
        self.assertEqual(len(records), 1)
        self._write(src)
        manifest = _manifest_for("foo.py", ["FooTest"], _records_to_manifest_entries(records))

        changed_src = src.replace("self.assertIn(state, row)", "self.assertNotIn(state, row)")
        self._write(changed_src)
        failures, _ = dti.validate_manifest(manifest, root=self.root)
        self.assertIn("fingerprint-mismatch", _failure_types(failures))

    def test_unknown_method_entry_is_distinguished_from_stale_entry(self):
        src = (
            "import unittest\n"
            "class FooTest(unittest.TestCase):\n"
            "    def test_basic(self):\n"
            "        self.assertEqual(1, 1)\n"
            "        self.assertIn('a', 'abc')\n"
        )
        self._write(src)
        records = dti.enumerate_assertions(src, "foo.py", ["FooTest"])
        entries = _records_to_manifest_entries(records)
        # entries[1] names a method that does not exist at all.
        entries[1]["method"] = "test_no_such_method"
        entries[1]["id"] = "foo.py::FooTest::test_no_such_method::assert-02"
        manifest = _manifest_for("foo.py", ["FooTest"], entries)

        failures, _ = dti.validate_manifest(manifest, root=self.root)
        types_by_id = {f.id: f.mismatch_type for f in failures}
        self.assertEqual(types_by_id[entries[1]["id"]], "unknown-method")
        # The real method's own real assertion (assert-02, now unclassified
        # since entries[1] was repointed away from it) must be reported as
        # unclassified, not conflated with the unknown-method failure.
        self.assertIn(
            "unclassified",
            {f.mismatch_type for f in failures if f.method == "test_basic"},
        )
        # unknown-method must not ALSO be reported as stale-entry for the
        # same id.
        self.assertNotIn("stale-entry", {t for i, t in types_by_id.items() if i == entries[1]["id"]})

    def test_existing_method_removed_assertion_is_still_stale_entry(self):
        src = (
            "import unittest\n"
            "class FooTest(unittest.TestCase):\n"
            "    def test_basic(self):\n"
            "        self.assertEqual(1, 1)\n"
            "        self.assertIn('a', 'abc')\n"
        )
        self._write(src)
        records = dti.enumerate_assertions(src, "foo.py", ["FooTest"])
        manifest = _manifest_for("foo.py", ["FooTest"], _records_to_manifest_entries(records))

        shrunk_src = (
            "import unittest\n"
            "class FooTest(unittest.TestCase):\n"
            "    def test_basic(self):\n"
            "        self.assertEqual(1, 1)\n"
        )
        self._write(shrunk_src)
        failures, _ = dti.validate_manifest(manifest, root=self.root)
        self.assertIn("stale-entry", _failure_types(failures))
        self.assertNotIn("unknown-method", _failure_types(failures))


class CliOutputTest(unittest.TestCase):
    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmpdir.cleanup)
        self.root = Path(self._tmpdir.name)
        # main() resolves a relative --manifest path against the module's
        # REPOSITORY_ROOT; point that at this test's temp dir for the
        # duration of the test so synthetic fixtures are found there
        # instead of the real repository root.
        original_root = dti.REPOSITORY_ROOT
        dti.REPOSITORY_ROOT = self.root
        self.addCleanup(setattr, dti, "REPOSITORY_ROOT", original_root)

    def _write(self, name, content):
        path = self.root / name
        path.write_text(content, encoding="utf-8")
        return path

    def _run_cli(self, manifest_path):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            exit_code = dti.main(["--manifest", str(manifest_path), "--check"])
        return exit_code, buf.getvalue()

    def test_cli_success_reports_counts_and_zero_check(self):
        src = (
            "import unittest\n"
            "class FooTest(unittest.TestCase):\n"
            "    def test_basic(self):\n"
            "        self.assertEqual(1, 1)\n"
        )
        self._write("foo.py", src)
        records = dti.enumerate_assertions(src, "foo.py", ["FooTest"])
        manifest = _manifest_for(
            "foo.py", ["FooTest"], _records_to_manifest_entries(records)
        )
        manifest_path = self._write("manifest.json", json.dumps(manifest))
        exit_code, output = self._run_cli(manifest_path)
        self.assertEqual(exit_code, 0)
        self.assertIn("manifest check OK", output)
        self.assertIn("unclassified: 0", output)
        self.assertIn("stale: 0", output)
        self.assertIn("fingerprint mismatch: 0", output)

    def test_cli_failure_output_is_short_and_identifies_target(self):
        src = (
            "import unittest\n"
            "class FooTest(unittest.TestCase):\n"
            "    def test_basic(self):\n"
            "        self.assertEqual(1, 1)\n"
        )
        self._write("foo.py", src)
        records = dti.enumerate_assertions(src, "foo.py", ["FooTest"])
        entries = _records_to_manifest_entries(records)
        entries[0]["fingerprint"] = "0" * 64
        manifest = _manifest_for("foo.py", ["FooTest"], entries)
        manifest_path = self._write("manifest.json", json.dumps(manifest))
        exit_code, output = self._run_cli(manifest_path)
        self.assertEqual(exit_code, 1)
        self.assertIn("fingerprint-mismatch", output)
        self.assertIn(records[0].id, output)
        # Output must stay short (an identifying line per failure), not a
        # dump of the whole document/source under test.
        self.assertLess(len(output), 2000)

    def test_cli_missing_manifest_file_is_a_short_clean_failure(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            exit_code = dti.main(["--manifest", "does-not-exist.json", "--check"])
        output = buf.getvalue()
        self.assertEqual(exit_code, 1)
        self.assertIn("manifest-load-error", output)
        # No Python traceback markers.
        self.assertNotIn("Traceback", output)
        self.assertLess(len(output), 500)

    def test_cli_invalid_json_is_a_short_clean_failure(self):
        manifest_path = self._write("manifest.json", "{not valid json")
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            exit_code = dti.main(["--manifest", str(manifest_path), "--check"])
        output = buf.getvalue()
        self.assertEqual(exit_code, 1)
        self.assertIn("manifest-load-error", output)
        self.assertNotIn("Traceback", output)
        self.assertLess(len(output), 500)


if __name__ == "__main__":
    unittest.main()
