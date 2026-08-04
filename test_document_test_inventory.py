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
        # Only the test_* method's own call site is enumerated for this
        # class scope -- not the helper's internal assertIn (the helper
        # method itself is not a test_* method, so its body is not walked
        # as a separate method's assertions).
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


if __name__ == "__main__":
    unittest.main()
