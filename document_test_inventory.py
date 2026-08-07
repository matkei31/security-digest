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

3. Validate the shard INDEX (`document_test_classification_index.json`),
   the combined set of shards it lists in index order, and each listed
   shard's PHYSICAL file format (`validate_indexed_manifests`). A manifest is
   one entry per line under a 600-line cap and the base one is already at
   596, so further classification goes into ADDITIONAL shards, declared by
   the index -- never by glob, never followed through a symlink.

This is a project-management/test-maintenance tool, not a general Python
analyzer. It is deliberately narrow: it does not resolve control flow, does
not evaluate expressions, and does not attempt to guess an assertion's
`category`/`action`/`contract_summary`/`rationale` -- those are recorded by
a human reviewer in the manifest. The tool's job is only to make it
IMPOSSIBLE for that manifest to silently drift out of sync with the source
it describes (an assertion added/removed/changed without the manifest
being updated to match) -- WITHIN the manifest's own human-declared
`scope`. It cannot notice a class/file quietly REMOVED from `scope`
itself; guarding against that silent shrinkage is the job of the
structural record tests that pin a pilot's expected scope (BL-038
tranche 3b/3c), not of this tool alone.

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
import re
import stat
import sys
from pathlib import Path, PurePosixPath, PureWindowsPath

REPOSITORY_ROOT = Path(__file__).resolve().parent

# The index is the sole source of truth for which shards exist and in what
# order; only the base manifest and `..._NNN.json` (3 digits) are accepted.
INDEX_FILENAME = "document_test_classification_index.json"
BASE_SHARD_FILENAME = "document_test_classification.json"
INDEX_TOP_LEVEL_KEYS = ("schema_version", "shards")
_ADDITIONAL_SHARD_RE = re.compile(r"document_test_classification_[0-9]{3}\.json")

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

# Physical-file contract for every shard read through the index.
SHARD_LINE_CAP = 600
ENTRY_KEY_ORDERS = tuple(
    REQUIRED_ASSERTION_FIELDS[:7] + (style,) + REQUIRED_ASSERTION_FIELDS[7:]
    for style in ("target", "targets")
)

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


def _is_self_or_cls_call(call_node):
    return (
        isinstance(call_node, ast.Call)
        and isinstance(call_node.func, ast.Attribute)
        and isinstance(call_node.func.value, ast.Name)
        and call_node.func.value.id in ("self", "cls")
    )


def _is_unittest_assert_call(call_node):
    # Excludes custom-helper-named calls even though they also start with
    # "assert" -- real unittest methods are camelCase, never an underscore
    # right after "assert", so this never misclassifies a real built-in.
    # Second, independent line of defense on top of call-order in
    # _enumerate_method_assertions (custom-helper checks run first there).
    return (
        _is_self_or_cls_call(call_node)
        and call_node.func.attr.startswith("assert")
        and not _looks_like_custom_helper_name(call_node.func.attr)
    )


def _is_custom_helper_call(call_node, helper_defs):
    return (
        _is_self_or_cls_call(call_node)
        and call_node.func.attr in helper_defs
    )


def _is_unresolved_helper_call(call_node, helper_defs):
    """A `self.<name>(...)`/`cls.<name>(...)` call whose name matches the
    custom-helper naming pattern but has no same-class definition -- must
    never be silently treated as a builtin (call-only fingerprint) or
    silently omitted. Cross-file/inherited/dynamic helpers are explicitly
    unsupported; callers should raise InventoryError when this matches.
    """
    return (
        _is_self_or_cls_call(call_node)
        and _looks_like_custom_helper_name(call_node.func.attr)
        and call_node.func.attr not in helper_defs
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


def _looks_like_custom_helper_name(name):
    """True for `assert_*` or `_*assert*` (case-insensitive) -- this
    repository's assertion-style helper naming convention, e.g.
    `_assert_row_state`, `assert_section_contains`. No real
    unittest.TestCase method matches this (they're camelCase, never an
    underscore right after "assert"), so it safely selects both helper
    DEFINITIONS and CALL sites without misclassifying a genuine built-in.
    """
    lname = name.lower()
    return lname.startswith("assert_") or (lname.startswith("_") and "assert" in lname)


def _helper_defs_for_class(class_node):
    """Non-test helper methods (`def`/`async def`) on `class_node` whose
    name matches _looks_like_custom_helper_name. Returns {name: def_node},
    not just names, so a call site's fingerprint can incorporate the
    resolved helper's own body (composite_fingerprint).
    """
    defs = {}
    for item in class_node.body:
        if (
            isinstance(item, _METHOD_DEF_TYPES)
            and not item.name.startswith("test_")
            and _looks_like_custom_helper_name(item.name)
        ):
            defs[item.name] = item
    return defs


def _resolve_helper_dependency_closure(start_name, helper_defs, file_name, class_name):
    """DFS over helper_defs from `start_name`. Returns an ordered list of
    definition nodes: the starting helper, then every same-class helper it
    calls -- directly or transitively -- each exactly once, deterministic
    (first-encountered, depth-first) order. A cycle is truncated safely
    (finite, no re-append). Raises InventoryError on an unresolved
    dependency -- never silently dropped from the fingerprint.
    """
    ordered = []
    visited = set()
    visiting = set()

    def visit(name):
        if name in visited or name in visiting:
            return
        visiting.add(name)
        def_node = helper_defs[name]
        ordered.append(def_node)
        for node in _iter_source_order(def_node, _STOP_DESCENDING):
            if _is_custom_helper_call(node, helper_defs):
                visit(node.func.attr)
            elif _is_unresolved_helper_call(node, helper_defs):
                raise InventoryError(
                    f"{file_name}::{class_name}: helper {name!r} calls unresolved "
                    f"custom assertion helper {node.func.attr!r} (name matches the "
                    f"custom-helper pattern but no same-class definition was found; "
                    f"cross-file/inherited/dynamic helpers are not supported)"
                )
        visiting.discard(name)
        visited.add(name)

    visit(start_name)
    return ordered


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
        elif _is_custom_helper_call(node, helper_defs):
            # Checked BEFORE _is_unittest_assert_call: a public-style
            # helper name (`assert_section_contains`) also starts with
            # "assert" and would otherwise be swept up as a "built-in"
            # unittest call with a call-only fingerprint, hiding semantic
            # drift in the helper's own body. Resolving custom helpers
            # first (regardless of naming style) ensures composite
            # fingerprinting always applies to them.
            assertion_api = node.func.attr
            # The call site alone doesn't carry the helper's own logic --
            # fold the resolved helper definition's body (and, transitively,
            # any same-class helper IT calls) into the fingerprint too, so a
            # semantic change anywhere in that dependency chain is detected
            # even though the call site itself is untouched.
            closure_defs = _resolve_helper_dependency_closure(
                node.func.attr, helper_defs, file_name, class_name
            )
            fingerprint = composite_fingerprint([node] + closure_defs)
            assertion_node = node
        elif _is_unresolved_helper_call(node, helper_defs):
            raise InventoryError(
                f"{file_name}::{class_name}::{method_node.name}: unresolved custom "
                f"assertion helper call {node.func.attr!r} (name matches the "
                f"custom-helper pattern but no same-class definition was found; "
                f"cross-file/inherited/dynamic helpers are not supported)"
            )
        elif _is_unittest_assert_call(node):
            assertion_api = node.func.attr
            fingerprint = canonical_fingerprint(node)
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


_FINGERPRINT_RE = re.compile(r"[0-9a-f]{64}")
_ENTRY_STRING_FIELDS = (
    "id", "file", "class", "method", "assertion_api", "contract_summary", "rationale",
)


def _validate_entry_shape(entry):
    """Type checks that MUST pass before `id`/`file`/`class`/`method` are
    used as dict/set keys anywhere downstream (a list or dict value there
    would raise TypeError: unhashable type, crashing the validator instead
    of reporting a clean failure). Returns (failure_type, detail) if the
    entry is unsafe to process further, or (None, None) if these fields are
    all well-typed (value-level checks -- category/action membership,
    target contract, ordinal range -- are handled separately once shape is
    confirmed safe).
    """
    for field in _ENTRY_STRING_FIELDS:
        value = entry.get(field)
        if not isinstance(value, str) or not value.strip():
            return "invalid-entry-shape", f"{field!r} must be a nonblank string, got {value!r}"
    fingerprint = entry.get("fingerprint")
    if not isinstance(fingerprint, str) or not _FINGERPRINT_RE.fullmatch(fingerprint):
        return "invalid-fingerprint", "'fingerprint' must be a 64-character lowercase hex string"
    return None, None


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
    # type(...) is int (not isinstance) deliberately rejects both bool
    # (type is bool, a distinct type) and float (1.0 == 1 is True in
    # Python, so a naive `!= 1` check alone would accept the float 1.0).
    if type(schema_version) is not int or schema_version != 1:
        failures.append(
            ValidationFailure(
                "invalid-schema-version",
                f"schema_version must be exactly the integer 1, got {schema_version!r}",
            )
        )

    if "scope" not in manifest:
        failures.append(ValidationFailure("invalid-manifest-shape", "manifest must have a 'scope' key"))
        scope_raw = []
    else:
        scope_raw = manifest["scope"]
        if not isinstance(scope_raw, list) or not scope_raw:
            failures.append(
                ValidationFailure("invalid-manifest-shape", "scope must be a nonempty list")
            )
            scope_raw = scope_raw if isinstance(scope_raw, list) else []

    if "assertions" not in manifest:
        failures.append(
            ValidationFailure("invalid-manifest-shape", "manifest must have an 'assertions' key")
        )
        assertions_raw = []
    else:
        assertions_raw = manifest["assertions"]
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
        if not isinstance(classes, list) or not classes or not all(
            isinstance(c, str) and c.strip() for c in classes
        ):
            failures.append(
                ValidationFailure(
                    "invalid-scope-shape",
                    "scope entry 'classes' must be a nonempty list of nonblank strings",
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

        # Must run before ANY of entry_id/file_name/cls/method is used as a
        # dict/set key below (out-of-scope lookups, manifest_ids.add(),
        # manifest_by_key[key] = ...) -- an unhashable value (e.g. a list
        # passed where a string was expected) would otherwise crash the
        # validator with TypeError instead of reporting a clean failure.
        shape_failure_type, shape_detail = _validate_entry_shape(entry)
        if shape_failure_type:
            failures.append(
                ValidationFailure(
                    shape_failure_type,
                    shape_detail,
                    id_=entry_id if isinstance(entry_id, str) else None,
                    file=file_name if isinstance(file_name, str) else None,
                    cls=cls if isinstance(cls, str) else None,
                    method=method if isinstance(method, str) else None,
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


def is_allowed_shard_filename(name):
    """True only for the base manifest and `..._NNN.json` (NNN = 3 digits)."""
    if not isinstance(name, str):
        return False
    return name == BASE_SHARD_FILENAME or _ADDITIONAL_SHARD_RE.fullmatch(name) is not None


def discover_shard_filenames(root):
    """Sorted names in `root` that LOOK like a shard, file or not. Used ONLY
    to detect shards missing from the index -- never to add one. An unreadable
    root propagates OSError: "cannot enumerate" is not "nothing is there"."""
    return sorted(e.name for e in root.iterdir() if is_allowed_shard_filename(e.name))


def _is_absolute_shard_path(shard):
    # Both flavours plus a bare Windows drive prefix (is_absolute() alone
    # reports that False), so absolute paths are rejected on any platform.
    return (PurePosixPath(shard).is_absolute() or PureWindowsPath(shard).is_absolute()
            or PureWindowsPath(shard).drive != "")


def _shard_path_failure(shard):
    """(mismatch_type, detail) for an unacceptable `shards` element, else None."""
    if not isinstance(shard, str) or not shard.strip() or shard != shard.strip():
        return ("invalid-shard-path", f"shard entry must be a nonblank, unpadded string, got {shard!r}")
    if _is_absolute_shard_path(shard):
        return ("absolute-shard-path", f"shard path must be root-relative, got {shard!r}")
    if "/" in shard or "\\" in shard or ".." in shard:
        return ("invalid-shard-path", f"shard path must be a bare filename without '..', got {shard!r}")
    if shard == INDEX_FILENAME:
        return ("index-registered-as-shard", "the index must not list itself as a shard")
    if not is_allowed_shard_filename(shard):
        return ("invalid-shard-filename", f"shard filename is not an allowed form, got {shard!r}")
    return None


def validate_index(index, root=None):
    """Check a parsed shard index. Returns `(failures, shard_filenames)`, the
    latter being the ordered, syntactically acceptable shards it declares.
    Fail closed: a caller seeing failures must NOT fall back to the base
    manifest -- an index this tool cannot understand means unknown coverage."""
    if root is None:
        root = REPOSITORY_ROOT
    if not isinstance(index, dict):
        return ([ValidationFailure("invalid-index-shape", "index must be a JSON object")], [])

    failures = []

    def fail(mismatch_type, detail, **kwargs):
        failures.append(ValidationFailure(mismatch_type, detail, **kwargs))

    keys = list(index.keys())
    if set(keys) != set(INDEX_TOP_LEVEL_KEYS):
        fail("invalid-index-keys", f"top-level keys must be exactly {list(INDEX_TOP_LEVEL_KEYS)}, got {keys}")
    elif tuple(keys) != INDEX_TOP_LEVEL_KEYS:
        fail("invalid-index-key-order", f"top-level keys must be ordered {list(INDEX_TOP_LEVEL_KEYS)}, got {keys}")

    schema_version = index.get("schema_version")
    # Same int-identity check validate_manifest uses: rejects bool and 1.0.
    if type(schema_version) is not int or schema_version != 1:
        fail("invalid-index-schema-version", f"schema_version must be exactly the integer 1, got {schema_version!r}")

    shards_raw = index.get("shards")
    if not isinstance(shards_raw, list) or not shards_raw:
        fail("invalid-index-shape", f"'shards' must be a nonempty list, got {shards_raw!r}")
        shards_raw = shards_raw if isinstance(shards_raw, list) else []

    shard_filenames = []
    declared = set()
    for shard in shards_raw:
        path_failure = _shard_path_failure(shard)
        if path_failure:
            fail(*path_failure)
        elif shard in declared:
            fail("duplicate-shard-path", f"shard {shard!r} is listed twice", file=shard)
        else:
            declared.add(shard)
            shard_filenames.append(shard)

    for shard in shard_filenames:
        # lstat(), not exists()/is_file(): those follow symlinks, so a
        # shard-named symlink would otherwise pass and then be READ through.
        try:
            mode = (root / shard).lstat().st_mode
        except OSError:
            fail("missing-shard", f"shard {shard!r} is listed in the index but does not exist", file=shard)
            continue
        if stat.S_ISLNK(mode):
            fail("shard-is-a-symlink", f"shard {shard!r} is a symlink, not a regular file", file=shard)
        elif not stat.S_ISREG(mode):
            fail("shard-not-a-file", f"shard {shard!r} is not a regular file", file=shard)

    try:
        discovered = discover_shard_filenames(root)
    except OSError as exc:
        discovered = []
        fail("shard-discovery-error", f"{root}: cannot enumerate the repository root: {exc}")
    for name in discovered:
        if name not in declared:
            fail("unlisted-shard", f"{name!r} looks like a shard but is not listed in the index", file=name)

    return failures, shard_filenames


def validate_index_path(index_path):
    """The index decides which shards exist, so its own directory entry is
    lstat()ed before anything opens it: a symlinked index could redirect
    coverage outside the repository entirely."""
    try:
        mode = Path(index_path).lstat().st_mode
    except OSError as exc:
        return [ValidationFailure("index-load-error", str(exc))]
    if stat.S_ISLNK(mode):
        return [ValidationFailure("index-is-a-symlink", f"{index_path}: index is a symlink")]
    if not stat.S_ISREG(mode):
        return [ValidationFailure("index-not-a-file", f"{index_path}: index is not a regular file")]
    return []


def load_index(index_path):
    with open(index_path, encoding="utf-8") as fh:
        return json.load(fh)


def load_shard_manifests(shard_filenames, root=None):
    """Every listed shard, in index order, as `(filename, manifest)` pairs.
    Unreadable/undecodable/unparseable yields `shard-load-error`, never a
    silent skip."""
    if root is None:
        root = REPOSITORY_ROOT
    failures = []
    shard_manifests = []
    for shard in shard_filenames:
        try:
            shard_manifests.append((shard, load_manifest(root / shard)))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            failures.append(ValidationFailure("shard-load-error", f"{shard}: {exc}", file=shard))
    return failures, shard_manifests


def validate_shard_file_format(path, manifest, shard=None):
    """The PHYSICAL-file contract for one shard, invisible to the parsed-
    object `validate_manifest`: at most SHARD_LINE_CAP lines, one compact
    JSON line per entry, fixed key order, a trailing newline, and raw text
    that re-parses to the loaded manifest. Failures name the shard."""
    path = Path(path)
    name = shard or path.name
    failures = []

    def fail(mismatch_type, detail):
        failures.append(ValidationFailure(mismatch_type, detail, file=name))

    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        return [ValidationFailure("shard-load-error", f"{name}: {exc}", file=name)]

    lines = text.splitlines()
    if len(lines) > SHARD_LINE_CAP:
        fail("shard-line-cap-exceeded", f"{len(lines)} lines exceeds the {SHARD_LINE_CAP}-line cap")
    if not text.endswith("\n"):
        fail("shard-missing-trailing-newline", "shard must end with a newline")
    try:
        if json.loads(text) != manifest:
            fail("shard-reparse-mismatch", "re-reading the raw text did not reproduce the loaded manifest")
    except json.JSONDecodeError as exc:
        return failures + [ValidationFailure("shard-load-error", f"invalid JSON: {exc}", file=name)]

    starts = [i for i, line in enumerate(lines) if line.strip() == '"assertions": [']
    ends = [i for i, line in enumerate(lines) if line.strip() == "]"]
    if len(starts) != 1 or not any(i > starts[0] for i in ends):
        fail("shard-assertions-block-shape", 'shard needs one `"assertions": [` line and a closing `]`')
        return failures
    start = starts[0]
    entry_lines = lines[start + 1 : min(i for i in ends if i > start)]
    entries = manifest.get("assertions") if isinstance(manifest, dict) else None
    if not isinstance(entries, list) or len(entry_lines) != len(entries):
        parsed_count = len(entries) if isinstance(entries, list) else "?"
        fail("shard-entry-line-count-mismatch", f"{len(entry_lines)} line(s), {parsed_count} entries")
        return failures

    for offset, line in enumerate(entry_lines):
        where = f"assertion line {start + 2 + offset}"
        try:
            parsed = json.loads(line.strip().rstrip(","))
        except json.JSONDecodeError:
            parsed = None
        if not isinstance(parsed, dict):
            fail("shard-entry-not-one-line", f"{where} is not one compact JSON object")
        elif tuple(parsed.keys()) not in ENTRY_KEY_ORDERS:
            fail("shard-entry-key-order", f"{where}: keys {list(parsed.keys())} are not a fixed order")
    return failures


def combined_assertion_ids(shard_manifests):
    """Combined assertion order: index order, then each shard's own order."""
    return [entry.get("id") for _s, m in shard_manifests if isinstance(m, dict)
            for entry in (m.get("assertions") or []) if isinstance(entry, dict)]


def _combined_summary(shard_filenames):
    summary = _empty_summary()
    summary.update(shard_count=len(shard_filenames), shard_files=list(shard_filenames))
    return summary


def _scope_pairs(manifest):
    """(file, class) pairs a manifest declares, skipping malformed ones."""
    scope = manifest.get("scope") if isinstance(manifest, dict) else None
    for entry in scope if isinstance(scope, list) else ():
        if not isinstance(entry, dict) or not isinstance(entry.get("file"), str):
            continue
        for cls in entry["classes"] if isinstance(entry.get("classes"), list) else ():
            if isinstance(cls, str):
                yield entry["file"], cls


def validate_shard_manifests(shard_manifests, root=None):
    """Validate every `(shard_filename, manifest)` pair with
    `validate_manifest`, then the cross-shard invariants, and return
    `(failures, summary)` for the COMBINED classification. The summary keeps
    every single-manifest key -- so a one-shard index reports exactly what
    the single-manifest path reports -- and adds `shard_count`/`shard_files`.
    Cross-shard invariants: no assertion ID in two shards, no `file`+`class`
    pair in two shards. Splitting ONE file BY CLASS is the growth path."""
    if root is None:
        root = REPOSITORY_ROOT

    failures = []
    summary = _combined_summary([name for name, _ in shard_manifests])
    scope_files = set()
    owner_by_class = {}
    owner_by_id = {}

    for shard, manifest in shard_manifests:
        shard_failures, shard_summary = validate_manifest(manifest, root=root)
        failures.extend(shard_failures)

        scope_files.update(shard_summary["scoped_files"])
        for key in ("scoped_classes", "inventoried_assertions", "manifest_assertions"):
            summary[key] += shard_summary[key]
        for category, count in shard_summary["category_counts"].items():
            summary["category_counts"][category] += count
        for file_name, count in shard_summary["file_counts"].items():
            summary["file_counts"][file_name] = summary["file_counts"].get(file_name, 0) + count

        for file_name, cls in _scope_pairs(manifest):
            owner = owner_by_class.setdefault((file_name, cls), shard)
            if owner != shard:
                failures.append(ValidationFailure(
                    "cross-shard-duplicate-ownership",
                    f"{file_name}::{cls} is claimed by both {owner!r} and {shard!r}",
                    file=file_name, cls=cls))
        for entry_id in combined_assertion_ids([(shard, manifest)]):
            owner = owner_by_id.setdefault(entry_id, shard) if isinstance(entry_id, str) else shard
            if owner != shard:
                failures.append(ValidationFailure(
                    "cross-shard-duplicate-id",
                    f"assertion id is listed by both {owner!r} and {shard!r}", id_=entry_id))

    summary["scoped_files"] = sorted(scope_files)
    summary["unclassified"] = sum(1 for f in failures if f.mismatch_type == "unclassified")
    summary["stale"] = sum(1 for f in failures if f.mismatch_type == "stale-entry")
    summary["fingerprint_mismatch"] = sum(1 for f in failures if f.mismatch_type == "fingerprint-mismatch")
    return failures, summary


def validate_indexed_manifests(root=None, index_path=None):
    """Index-driven combined validation: check the index entry, load and
    validate the index, load every listed shard, check each shard's raw file
    format, validate the combined classification. Every stage fails closed."""
    if root is None:
        root = REPOSITORY_ROOT
    if index_path is None:
        index_path = root / INDEX_FILENAME

    entry_failures = validate_index_path(index_path)
    if entry_failures:
        return entry_failures, _combined_summary([])
    try:
        index = load_index(index_path)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        return [ValidationFailure("index-load-error", f"{index_path}: {exc}")], _combined_summary([])

    failures, shard_filenames = validate_index(index, root=root)
    if failures:
        return failures, _combined_summary(shard_filenames)

    load_failures, shard_manifests = load_shard_manifests(shard_filenames, root=root)
    if load_failures:
        return load_failures, _combined_summary(shard_filenames)

    format_failures = []
    for shard, manifest in shard_manifests:
        format_failures.extend(validate_shard_file_format(root / shard, manifest, shard=shard))
    failures, summary = validate_shard_manifests(shard_manifests, root=root)
    return format_failures + failures, summary


def _print_report(failures, summary, stream=None):
    if stream is None:
        stream = sys.stdout
    if not failures:
        print("document_test_inventory: manifest check OK", file=stream)
        if "shard_files" in summary:
            print(f"  shards: {summary['shard_count']} {summary['shard_files']}", file=stream)
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
    # Neither is required: with no source argument the tool validates the
    # COMBINED classification through the index. `--manifest` keeps the
    # original single-manifest behaviour and never reads the index.
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--manifest", help="path to a single classification manifest to validate on its own")
    source.add_argument("--index", help=f"path to the shard index (default: {INDEX_FILENAME})")
    parser.add_argument("--check", action="store_true", help="validate and print a report")
    args = parser.parse_args(argv)

    def report(failures, summary):
        _print_report(failures, summary)
        return (1 if failures else 0) if args.check else 0

    if args.manifest is None:
        index_path = Path(args.index) if args.index else Path(INDEX_FILENAME)
        if not index_path.is_absolute():
            index_path = REPOSITORY_ROOT / index_path
        return report(*validate_indexed_manifests(index_path=index_path))

    manifest_path = Path(args.manifest)
    if not manifest_path.is_absolute():
        manifest_path = REPOSITORY_ROOT / manifest_path

    # A missing file or invalid JSON must produce a short, actionable
    # message and exit code 1 -- not an uncaught traceback. (A valid JSON
    # document whose top level isn't an object is instead handled by
    # validate_manifest's own "invalid-manifest-shape" check below, since
    # that's a manifest-content problem, not a load problem.)
    try:
        manifest = load_manifest(manifest_path)
    except (OSError, UnicodeError) as exc:
        print(f"document_test_inventory: manifest-load-error {exc}", file=sys.stdout)
        return 1
    except json.JSONDecodeError as exc:
        print(f"document_test_inventory: manifest-load-error invalid JSON: {exc}", file=sys.stdout)
        return 1

    return report(*validate_manifest(manifest))


if __name__ == "__main__":
    sys.exit(main())
