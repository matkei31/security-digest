"""Test-only AST inventory and classification-manifest validator for BL-038
tranche 3 (Fable 5 whole-repository review R-04: per-assertion A/B/C/D
classification of document/static-contract test assertions).

This module has two jobs:

1. Enumerate the document/static-contract-candidate assertions that
   actually exist, in source order, inside a scoped set of
   `unittest.TestCase` classes in a given Python test file (see
   `enumerate_assertions`/`scan_classes`). "Assertion" here means: a
   `self.assert*`/`cls.assert*` call, a bare `assert` statement, a
   `with self.assertRaises*(...)`/`assertRaisesRegex(...)` context
   manager, or a call to a custom assertion-style helper method defined on
   the same class (a non-`test_` method whose name starts with `assert_`,
   or starts with `_` and contains "assert") -- both plain `def` and
   `async def` methods are supported throughout, test methods and helper
   definitions alike. Each is given a stable ID
   `<file>::<class>::<method>::assert-<NN>` (ordinal is source order
   within the method, 2-digit, 1-based) and a canonical AST fingerprint
   that changes if and only if the assertion's actual code (API, argument
   structure, literal values) changes -- not if the surrounding source is
   merely reformatted. For a custom helper call, the fingerprint also
   incorporates the resolved helper DEFINITION's own body (see
   `composite_fingerprint`), so a semantic change to the helper is
   detected even when the call site itself is untouched.

2. Check a `document_test_classification.json`-shaped manifest for shape,
   schema, and internal consistency against that enumeration (see
   `validate_manifest`): the manifest's top-level shape and
   `schema_version`, every entry's `target`/`targets` contract (exactly
   one, correctly typed, and consistent in style across the whole
   manifest), every enumerated assertion having exactly one manifest entry
   naming a method that actually exists (a nonexistent method is
   `unknown-method`, distinct from a real method whose specific ordinal
   doesn't exist, `stale-entry`), every manifest entry corresponding to a
   real enumerated assertion with a matching fingerprint, IDs/ordinals
   being contiguous, unique, and non-boolean, and every entry's fields
   being well-formed.

This is a project-management/test-maintenance tool, not a general Python
analyzer. It is deliberately narrow: it does not resolve control flow, does
not evaluate expressions, and does not attempt to guess an assertion's
`category`/`action`/`contract_summary`/`rationale` -- those are recorded by
a human reviewer in the manifest. The tool's job is only to make it
IMPOSSIBLE for that manifest to silently drift out of sync with the source
it describes (an assertion added/removed/changed without the manifest
being updated to match).

Test-only: this module must never be imported by runtime/production code
(fetch.py/daily_json.py/vulnerability_facts.py) and has no dependency on
them. The `test_` prefix is deliberately omitted from this filename so
unittest's test discovery does not try to collect it as a test module
itself (matching the convention already used by document_test_utils.py).
"""

import argparse
import ast
import hashlib
import json
import sys
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parent

REQUIRED_ASSERTION_FIELDS = (
    "id",
    "file",
    "class",
    "method",
    "ordinal",
    "assertion_api",
    "fingerprint",
    "category",
    "action",
    "contract_summary",
    "rationale",
)
# Either "target" (single string) or "targets" (list of strings) must also
# be present; which one a manifest uses is checked separately, since the
# instructions allow either as long as it is used consistently.

VALID_CATEGORIES = ("A", "B", "C", "D")
VALID_ACTIONS = ("keep", "refactor_later", "already_structural", "historical_keep")

# The standard category -> action mapping (BL-038 tranche 3 kickoff
# instructions, section 4.3). This tool does not implement an exception
# mechanism for this mapping -- every pilot-scope entry follows it exactly,
# so any mismatch is treated as a manifest error rather than something a
# human might have deliberately overridden. If a genuine exception is ever
# needed, this mapping (and the validator that enforces it) is the place
# to extend, not something to work around by hand-editing the manifest.
CATEGORY_TO_ACTION = {
    "A": "keep",
    "B": "already_structural",
    "C": "refactor_later",
    "D": "historical_keep",
}


class InventoryError(Exception):
    """Raised for malformed input (unparseable source, unknown scope)."""


class AssertionRecord:
    """One enumerated document/static-contract-candidate assertion."""

    __slots__ = ("file", "cls", "method", "ordinal", "assertion_api", "fingerprint", "node")

    def __init__(self, file, cls, method, ordinal, assertion_api, fingerprint, node):
        self.file = file
        self.cls = cls
        self.method = method
        self.ordinal = ordinal
        self.assertion_api = assertion_api
        self.fingerprint = fingerprint
        self.node = node

    @property
    def id(self):
        return f"{self.file}::{self.cls}::{self.method}::assert-{self.ordinal:02d}"

    def key(self):
        return (self.file, self.cls, self.method, self.ordinal)


def _hash_dumps(nodes):
    """SHA-256 over the canonical (line/column/formatting-free) AST dumps
    of `nodes`, joined with a NUL separator so dumps from different nodes
    can never be concatenated ambiguously (a node whose own dump happens to
    look like "A" + "B" cannot collide with two nodes "A" and "B").
    """
    parts = [ast.dump(n, annotate_fields=True, include_attributes=False) for n in nodes]
    return hashlib.sha256("\x00".join(parts).encode("utf-8")).hexdigest()


def canonical_fingerprint(node):
    """A SHA-256 hex digest of `node`'s structure, deliberately excluding
    line/column/formatting information (`include_attributes=False`), so it
    is stable across pure reformatting (parenthesization, line-wrapping,
    string-literal concatenation-vs-single-literal choices that produce the
    same AST) but changes whenever the assertion's own API, argument
    structure, or literal values change.
    """
    return _hash_dumps([node])


def composite_fingerprint(nodes):
    """Like `canonical_fingerprint`, but over several nodes at once (in the
    given order). Used for a custom assertion helper call: the call site
    alone does not carry the helper's own logic, so a semantic change to
    the helper's BODY (its assertion API, comparison structure, or literal
    values) must also change the fingerprint recorded against the call
    site -- otherwise the manifest could silently drift from what the
    helper actually checks. Purely cosmetic changes to the helper body
    (formatting, comments, blank lines) still leave this unchanged, for the
    same reason a single node's formatting doesn't change its own
    fingerprint.
    """
    return _hash_dumps(nodes)


def _is_unittest_assert_call(call_node):
    return (
        isinstance(call_node, ast.Call)
        and isinstance(call_node.func, ast.Attribute)
        and call_node.func.attr.startswith("assert")
        and isinstance(call_node.func.value, ast.Name)
        and call_node.func.value.id in ("self", "cls")
    )


def _is_custom_helper_call(call_node, helper_defs):
    return (
        isinstance(call_node, ast.Call)
        and isinstance(call_node.func, ast.Attribute)
        and call_node.func.attr in helper_defs
        and isinstance(call_node.func.value, ast.Name)
        and call_node.func.value.id in ("self", "cls")
    )


def _assert_raises_call_in_with(with_node):
    """If `with_node` has a `self.assertRaises*(...)` context manager,
    return that call node; otherwise None. Only the context-manager call
    itself is treated as the assertion (its exception-type/regex
    arguments); the with-block's body is the code under test, not itself
    part of this assertion's contract.
    """
    for item in with_node.items:
        ctx = item.context_expr
        if (
            isinstance(ctx, ast.Call)
            and isinstance(ctx.func, ast.Attribute)
            and ctx.func.attr.startswith("assertRaises")
            and isinstance(ctx.func.value, ast.Name)
            and ctx.func.value.id in ("self", "cls")
        ):
            return ctx
    return None


_METHOD_DEF_TYPES = (ast.FunctionDef, ast.AsyncFunctionDef)


def _helper_defs_for_class(class_node):
    """Non-test helper methods (`def` or `async def`) on `class_node` whose
    name marks them as an assertion-style helper: starts with `assert_`, or
    starts with `_` and contains "assert" (case-insensitive) -- e.g.
    `_assert_row_state`, `assert_section_contains`. Plain fixture/setup
    helpers are excluded. Returns {name: def_node}, not just names, so a
    call site's fingerprint can incorporate the resolved helper's own body
    (see composite_fingerprint) -- a call site's fingerprint must change if
    the helper it calls changes semantically, not just if the call itself
    changes.
    """
    defs = {}
    for item in class_node.body:
        if isinstance(item, _METHOD_DEF_TYPES) and not item.name.startswith("test_"):
            lname = item.name.lower()
            if lname.startswith("assert_") or (lname.startswith("_") and "assert" in lname):
                defs[item.name] = item
    return defs


def _iter_source_order(node, stop_types):
    """Pre-order DFS over `node`'s descendants, in AST field order (which
    for statement sequences, If/For/While/With/Try bodies, etc. matches
    left-to-right, top-to-bottom source order). Does not descend into
    nested function/class/lambda definitions -- an assertion helper's own
    body is enumerated separately, when that class/method is itself in
    scope, not inlined into every call site.
    """
    for child in ast.iter_child_nodes(node):
        if isinstance(child, stop_types):
            continue
        yield child
        yield from _iter_source_order(child, stop_types)


_STOP_DESCENDING = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)


def _enumerate_method_assertions(file_name, class_name, method_node, helper_defs):
    records = []
    ordinal = 0
    # The Call node inside a `with self.assertRaises(...):` item is reached
    # twice by plain source-order traversal: once when the With statement
    # itself is visited (handled explicitly below, to treat the whole
    # context-manager form as ONE assertion), and again when traversal
    # descends into that With node's own children (which include the
    # withitem's context_expr, the same Call object). Track consumed node
    # identities so the second visit is skipped rather than double-counted.
    consumed_ids = set()
    for node in _iter_source_order(method_node, _STOP_DESCENDING):
        assertion_api = None
        fingerprint = None
        assertion_node = None
        if isinstance(node, ast.Assert):
            assertion_api = "assert"
            fingerprint = canonical_fingerprint(node)
            assertion_node = node
        elif isinstance(node, ast.With):
            raises_call = _assert_raises_call_in_with(node)
            if raises_call is not None:
                assertion_api = raises_call.func.attr
                fingerprint = canonical_fingerprint(raises_call)
                assertion_node = raises_call
                consumed_ids.add(id(raises_call))
        elif id(node) in consumed_ids:
            continue
        elif _is_unittest_assert_call(node):
            assertion_api = node.func.attr
            fingerprint = canonical_fingerprint(node)
            assertion_node = node
        elif _is_custom_helper_call(node, helper_defs):
            assertion_api = node.func.attr
            # The call site alone doesn't carry the helper's own logic --
            # fold the resolved helper definition's body into the
            # fingerprint too, so a semantic change to the helper (its
            # assertion API, comparison structure, or literal values) is
            # detected even though the call site itself is untouched.
            fingerprint = composite_fingerprint([node, helper_defs[node.func.attr]])
            assertion_node = node
        if assertion_api is None:
            continue
        ordinal += 1
        records.append(
            AssertionRecord(
                file=file_name,
                cls=class_name,
                method=method_node.name,
                ordinal=ordinal,
                assertion_api=assertion_api,
                fingerprint=fingerprint,
                node=assertion_node,
            )
        )
    return records


def scan_classes(source_text, file_name, scoped_classes):
    """Parse `source_text` (the contents of `file_name`) and return
    `(records, known_methods)`:

    - `records`: a list of AssertionRecord for every document/static-
      contract-candidate assertion in every `test_*`/`async def test_*`
      method of every class named in `scoped_classes`, in (class, method,
      ordinal) source order.
    - `known_methods`: {(file_name, class_name): {test method names}} --
      the real test methods that exist in each scoped class, regardless of
      whether they contain any enumerable assertions. A manifest entry
      naming a method not in this set is referencing a method that does
      not exist at all (see validate_manifest's `unknown-method` check),
      which is a different problem from an entry whose ordinal doesn't
      match any assertion in a method that DOES exist (`stale-entry`).

    Raises InventoryError if `source_text` does not parse, or if a name in
    `scoped_classes` is not a class defined in this file.
    """
    try:
        tree = ast.parse(source_text, filename=file_name)
    except SyntaxError as exc:
        raise InventoryError(f"{file_name}: could not parse source: {exc}") from exc

    classes_by_name = {
        node.name: node for node in ast.walk(tree) if isinstance(node, ast.ClassDef)
    }
    missing = [name for name in scoped_classes if name not in classes_by_name]
    if missing:
        raise InventoryError(f"{file_name}: unknown class(es) in scope: {missing}")

    records = []
    known_methods = {}
    for class_name in scoped_classes:
        class_node = classes_by_name[class_name]
        helper_defs = _helper_defs_for_class(class_node)
        methods = set()
        for item in class_node.body:
            if isinstance(item, _METHOD_DEF_TYPES) and item.name.startswith("test_"):
                methods.add(item.name)
                records.extend(
                    _enumerate_method_assertions(file_name, class_name, item, helper_defs)
                )
        known_methods[(file_name, class_name)] = methods
    return records, known_methods


def enumerate_assertions(source_text, file_name, scoped_classes):
    """Convenience wrapper around scan_classes() for callers that only need
    the assertion records, not each class's known test-method names."""
    records, _ = scan_classes(source_text, file_name, scoped_classes)
    return records


def load_manifest(manifest_path):
    with open(manifest_path, encoding="utf-8") as fh:
        return json.load(fh)


def _validate_target(entry):
    """Check entry's target/targets contract. Returns None if valid, or a
    short detail string describing the violation. Exactly one of `target`
    (a nonblank string) or `targets` (a nonempty list of unique nonblank
    strings) must be present -- not both, not neither, and not the wrong
    type/shape for whichever one is used.
    """
    has_target = "target" in entry
    has_targets = "targets" in entry
    if has_target and has_targets:
        return "entry must not have both 'target' and 'targets'"
    if not has_target and not has_targets:
        return "entry must have exactly one of 'target' or 'targets'"
    if has_target:
        target = entry["target"]
        if not isinstance(target, str) or not target.strip():
            return f"'target' must be a nonblank string, got {target!r}"
        return None
    targets = entry["targets"]
    if not isinstance(targets, list) or not targets:
        return f"'targets' must be a nonempty list, got {targets!r}"
    for t in targets:
        if not isinstance(t, str) or not t.strip():
            return f"'targets' entries must all be nonblank strings, got {t!r}"
    if len(set(targets)) != len(targets):
        return "'targets' must not contain duplicates"
    return None


def _empty_summary():
    return {
        "scoped_files": [],
        "scoped_classes": 0,
        "inventoried_assertions": 0,
        "manifest_assertions": 0,
        "category_counts": {"A": 0, "B": 0, "C": 0, "D": 0},
        "file_counts": {},
        "unclassified": 0,
        "stale": 0,
        "fingerprint_mismatch": 0,
    }


class ValidationFailure:
    __slots__ = ("id", "file", "cls", "method", "mismatch_type", "detail")

    def __init__(self, mismatch_type, detail, id_=None, file=None, cls=None, method=None):
        self.mismatch_type = mismatch_type
        self.detail = detail
        self.id = id_
        self.file = file
        self.cls = cls
        self.method = method

    def format(self):
        parts = [self.mismatch_type]
        if self.id:
            parts.append(f"id={self.id}")
        else:
            if self.file:
                parts.append(f"file={self.file}")
            if self.cls:
                parts.append(f"class={self.cls}")
            if self.method:
                parts.append(f"method={self.method}")
        parts.append(self.detail)
        return " ".join(parts)


def validate_manifest(manifest, root=None):
    """Check `manifest` (a parsed document_test_classification.json dict)
    for completeness and consistency against the actual source files named
    in its `scope`. Returns (failures, summary) where `failures` is a list
    of ValidationFailure (empty means the manifest is valid) and `summary`
    is a dict of counts, always returned even when there are failures (so
    a caller can report partial progress). `root` defaults to this
    module's REPOSITORY_ROOT, read at call time (not at import time), so
    that tests can point it at a temporary directory of synthetic fixture
    files without needing to pass `root` through every call site.
    """
    if root is None:
        root = REPOSITORY_ROOT

    if not isinstance(manifest, dict):
        return (
            [ValidationFailure("invalid-manifest-shape", "manifest must be a JSON object")],
            _empty_summary(),
        )

    failures = []

    schema_version = manifest.get("schema_version")
    if isinstance(schema_version, bool) or schema_version != 1:
        failures.append(
            ValidationFailure(
                "invalid-schema-version",
                f"schema_version must be exactly the integer 1, got {schema_version!r}",
            )
        )

    scope_raw = manifest.get("scope", [])
    if not isinstance(scope_raw, list):
        failures.append(ValidationFailure("invalid-manifest-shape", "scope must be a list"))
        scope_raw = []

    assertions_raw = manifest.get("assertions", [])
    if not isinstance(assertions_raw, list):
        failures.append(ValidationFailure("invalid-manifest-shape", "assertions must be a list"))
        assertions_raw = []

    scope_files = set()
    scoped_classes_by_file = {}
    for scope_entry in scope_raw:
        if not isinstance(scope_entry, dict):
            failures.append(
                ValidationFailure(
                    "invalid-scope-shape",
                    f"scope entry must be an object, got {type(scope_entry).__name__}",
                )
            )
            continue
        file_name = scope_entry.get("file")
        classes = scope_entry.get("classes")
        if not isinstance(file_name, str) or not file_name.strip():
            failures.append(
                ValidationFailure(
                    "invalid-scope-shape", "scope entry 'file' must be a nonblank string"
                )
            )
            continue
        if not isinstance(classes, list) or not all(
            isinstance(c, str) and c.strip() for c in classes
        ):
            failures.append(
                ValidationFailure(
                    "invalid-scope-shape",
                    "scope entry 'classes' must be a list of nonblank strings",
                    file=file_name,
                )
            )
            continue
        if file_name in scope_files:
            failures.append(
                ValidationFailure("duplicate-scope-file", f"file {file_name!r} listed twice")
            )
        scope_files.add(file_name)
        seen_classes = set()
        for cls in classes:
            if cls in seen_classes:
                failures.append(
                    ValidationFailure(
                        "duplicate-scope-class",
                        f"class {cls!r} listed twice",
                        file=file_name,
                        cls=cls,
                    )
                )
            seen_classes.add(cls)
        scoped_classes_by_file[file_name] = classes

    inventory_by_key = {}
    known_methods_by_class = {}
    for file_name, classes in scoped_classes_by_file.items():
        source_path = root / file_name
        try:
            source_text = source_path.read_text(encoding="utf-8")
        except OSError as exc:
            failures.append(
                ValidationFailure("unreadable-scope-file", str(exc), file=file_name)
            )
            continue
        try:
            records, known_methods = scan_classes(source_text, file_name, classes)
        except InventoryError as exc:
            failures.append(ValidationFailure("inventory-error", str(exc), file=file_name))
            continue
        for record in records:
            inventory_by_key[record.key()] = record
        known_methods_by_class.update(known_methods)

    entries = assertions_raw
    manifest_by_key = {}
    manifest_ids = set()
    manifest_ordinals_by_method = {}
    counts = {"A": 0, "B": 0, "C": 0, "D": 0}
    target_style = None  # "target" or "targets", once the first valid entry sets it

    for entry in entries:
        if not isinstance(entry, dict):
            failures.append(
                ValidationFailure(
                    "invalid-manifest-shape",
                    f"assertion entry must be an object, got {type(entry).__name__}",
                )
            )
            continue

        entry_id = entry.get("id")
        file_name = entry.get("file")
        cls = entry.get("class")
        method = entry.get("method")
        ordinal = entry.get("ordinal")

        missing_fields = [f for f in REQUIRED_ASSERTION_FIELDS if not entry.get(f) and entry.get(f) != 0]
        # ordinal=0 would be invalid separately; don't let falsy-but-present
        # numeric 0 slip past required-field detection for other fields.
        missing_fields = [
            f for f in missing_fields if not (f == "ordinal" and isinstance(entry.get(f), int))
        ]
        if missing_fields:
            failures.append(
                ValidationFailure(
                    "missing-field",
                    f"missing/blank fields: {missing_fields}",
                    id_=entry_id,
                    file=file_name,
                    cls=cls,
                    method=method,
                )
            )
            continue

        target_error = _validate_target(entry)
        if target_error:
            failures.append(
                ValidationFailure(
                    "invalid-target", target_error, id_=entry_id, file=file_name, cls=cls, method=method
                )
            )
        else:
            entry_style = "targets" if "targets" in entry else "target"
            if target_style is None:
                target_style = entry_style
            elif entry_style != target_style:
                failures.append(
                    ValidationFailure(
                        "mixed-target-style",
                        f"manifest already uses {target_style!r}-style entries; "
                        f"this entry uses {entry_style!r}",
                        id_=entry_id, file=file_name, cls=cls, method=method,
                    )
                )

        if file_name not in scope_files:
            failures.append(
                ValidationFailure(
                    "out-of-scope-file",
                    f"file {file_name!r} not declared in scope",
                    id_=entry_id,
                    file=file_name,
                )
            )
            continue
        if cls not in scoped_classes_by_file.get(file_name, []):
            failures.append(
                ValidationFailure(
                    "out-of-scope-class",
                    f"class {cls!r} not declared in scope for {file_name!r}",
                    id_=entry_id,
                    file=file_name,
                    cls=cls,
                )
            )
            continue
        if method not in known_methods_by_class.get((file_name, cls), set()):
            failures.append(
                ValidationFailure(
                    "unknown-method",
                    f"method {method!r} does not exist in class {cls!r}",
                    id_=entry_id, file=file_name, cls=cls, method=method,
                )
            )
            continue

        if isinstance(ordinal, bool) or not isinstance(ordinal, int) or ordinal < 1:
            failures.append(
                ValidationFailure(
                    "invalid-ordinal", f"ordinal must be a positive int, got {ordinal!r}",
                    id_=entry_id, file=file_name, cls=cls, method=method,
                )
            )
            continue

        manifest_ordinals_by_method.setdefault((file_name, cls, method), set()).add(ordinal)

        expected_id = f"{file_name}::{cls}::{method}::assert-{ordinal:02d}"
        if entry_id != expected_id:
            failures.append(
                ValidationFailure(
                    "id-mismatch", f"expected id {expected_id!r}, got {entry_id!r}",
                    id_=entry_id, file=file_name, cls=cls, method=method,
                )
            )

        if entry_id in manifest_ids:
            failures.append(
                ValidationFailure("duplicate-id", "duplicate id", id_=entry_id, file=file_name, cls=cls, method=method)
            )
        manifest_ids.add(entry_id)

        key = (file_name, cls, method, ordinal)
        if key in manifest_by_key:
            failures.append(
                ValidationFailure(
                    "duplicate-key", f"duplicate (file, class, method, ordinal) {key}",
                    id_=entry_id, file=file_name, cls=cls, method=method,
                )
            )
        manifest_by_key[key] = entry

        category = entry.get("category")
        action = entry.get("action")
        if category not in VALID_CATEGORIES:
            failures.append(
                ValidationFailure(
                    "invalid-category", f"category {category!r} not in {VALID_CATEGORIES}",
                    id_=entry_id, file=file_name, cls=cls, method=method,
                )
            )
        if action not in VALID_ACTIONS:
            failures.append(
                ValidationFailure(
                    "invalid-action", f"action {action!r} not in {VALID_ACTIONS}",
                    id_=entry_id, file=file_name, cls=cls, method=method,
                )
            )
        if category in VALID_CATEGORIES and action in VALID_ACTIONS:
            expected_action = CATEGORY_TO_ACTION[category]
            if action != expected_action:
                failures.append(
                    ValidationFailure(
                        "category-action-mismatch",
                        f"category {category!r} requires action {expected_action!r}, got {action!r}",
                        id_=entry_id, file=file_name, cls=cls, method=method,
                    )
                )
            else:
                counts[category] += 1

        inventory_record = inventory_by_key.get(key)
        if inventory_record is None:
            failures.append(
                ValidationFailure(
                    "stale-entry",
                    "manifest entry has no matching source assertion (removed or renamed?)",
                    id_=entry_id, file=file_name, cls=cls, method=method,
                )
            )
            continue

        if entry.get("assertion_api") != inventory_record.assertion_api:
            failures.append(
                ValidationFailure(
                    "assertion-api-mismatch",
                    f"manifest says {entry.get('assertion_api')!r}, source is "
                    f"{inventory_record.assertion_api!r}",
                    id_=entry_id, file=file_name, cls=cls, method=method,
                )
            )
        if entry.get("fingerprint") != inventory_record.fingerprint:
            failures.append(
                ValidationFailure(
                    "fingerprint-mismatch",
                    "manifest fingerprint does not match current source "
                    "(assertion API, arguments, or literal values changed)",
                    id_=entry_id, file=file_name, cls=cls, method=method,
                )
            )

    for key, record in inventory_by_key.items():
        if key not in manifest_by_key:
            failures.append(
                ValidationFailure(
                    "unclassified",
                    "source assertion has no manifest entry",
                    id_=record.id, file=record.file, cls=record.cls, method=record.method,
                )
            )

    # Ordinal-gap is checked against the MANIFEST's own ordinal numbering
    # per method (e.g. entries for assert-01 and assert-03 but no
    # assert-02), independent of whether those ordinals also match a real
    # source assertion -- that sync question is already covered separately
    # by unclassified/stale-entry above. (Inventory-side ordinals can never
    # gap on their own: enumerate_assertions always assigns them
    # sequentially with no skips.)
    for (file_name, cls, method), ordinals in manifest_ordinals_by_method.items():
        expected = set(range(1, max(ordinals) + 1))
        gap = expected - ordinals
        if gap:
            failures.append(
                ValidationFailure(
                    "ordinal-gap",
                    f"missing ordinal(s) {sorted(gap)} out of {sorted(ordinals)}",
                    file=file_name, cls=cls, method=method,
                )
            )

    summary = {
        "scoped_files": sorted(scope_files),
        "scoped_classes": sum(len(v) for v in scoped_classes_by_file.values()),
        "inventoried_assertions": len(inventory_by_key),
        "manifest_assertions": len(entries),
        "category_counts": counts,
        "file_counts": {
            file_name: sum(1 for k in inventory_by_key if k[0] == file_name)
            for file_name in scope_files
        },
        "unclassified": sum(1 for f in failures if f.mismatch_type == "unclassified"),
        "stale": sum(1 for f in failures if f.mismatch_type == "stale-entry"),
        "fingerprint_mismatch": sum(1 for f in failures if f.mismatch_type == "fingerprint-mismatch"),
    }
    return failures, summary


def _print_report(failures, summary, stream=None):
    if stream is None:
        stream = sys.stdout
    if not failures:
        print("document_test_inventory: manifest check OK", file=stream)
        print(f"  scoped files: {summary['scoped_files']}", file=stream)
        print(f"  scoped classes: {summary['scoped_classes']}", file=stream)
        print(f"  inventoried assertions: {summary['inventoried_assertions']}", file=stream)
        counts = summary["category_counts"]
        print(
            f"  A={counts['A']} B={counts['B']} C={counts['C']} D={counts['D']} "
            f"(total {sum(counts.values())})",
            file=stream,
        )
        for file_name, count in summary["file_counts"].items():
            print(f"  {file_name}: {count}", file=stream)
        print(f"  unclassified: {summary['unclassified']}", file=stream)
        print(f"  stale: {summary['stale']}", file=stream)
        print(f"  fingerprint mismatch: {summary['fingerprint_mismatch']}", file=stream)
        return
    print(f"document_test_inventory: manifest check FAILED ({len(failures)} issue(s))", file=stream)
    for failure in failures:
        print(f"  {failure.format()}", file=stream)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--manifest", required=True, help="path to document_test_classification.json")
    parser.add_argument("--check", action="store_true", help="validate the manifest and print a report")
    args = parser.parse_args(argv)

    manifest_path = Path(args.manifest)
    if not manifest_path.is_absolute():
        manifest_path = REPOSITORY_ROOT / manifest_path
    manifest = load_manifest(manifest_path)

    failures, summary = validate_manifest(manifest)
    _print_report(failures, summary)
    if not args.check:
        return 0
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
