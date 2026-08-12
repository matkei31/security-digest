#!/usr/bin/env python3
"""BL-038 tranche 3q: narrow section-binding guard for anchored manifest targets.

Ordinary assertion fingerprints do not include the assignment that selects a
Markdown section.  This guard therefore records only the load-bearing semantic
fact: an assertion classified against BACKLOG.md#BL-NNN or DECISIONS.md#SD-NNN
must read that section with a bounded end, not from its heading through EOF.
Local variable names and two equivalent extraction forms remain free.
"""

import ast
import unittest
from collections import defaultdict
from pathlib import Path

import document_test_history as dth
import document_test_inventory as dti

ROOT = Path(__file__).resolve().parent
SOURCE_FILE = "test_security_requirements.py"
CLASS_NAME = "SecurityRequirementsTest"
TRANCHE = "3q"
FILE_TO_ATTR = {"BACKLOG.md": "backlog", "DECISIONS.md": "decisions"}


def _constant_int(node):
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, int) else None


def _narrow_section_facts(method):
    """Return (document binding, start marker, end boundary) semantic facts."""
    assigns = [
        node for node in ast.walk(method)
        if isinstance(node, ast.Assign)
        and len(node.targets) == 1
        and isinstance(node.targets[0], ast.Name)
    ]

    # Resolve harmless local aliases of self.backlog/self.decisions to fixpoint.
    aliases = {}
    changed = True
    while changed:
        changed = False
        for assign in assigns:
            name = assign.targets[0].id
            value = assign.value
            resolved = None
            if (
                isinstance(value, ast.Attribute)
                and isinstance(value.value, ast.Name)
                and value.value.id == "self"
                and value.attr in FILE_TO_ATTR.values()
            ):
                resolved = value.attr
            elif isinstance(value, ast.Name) and value.id in aliases:
                resolved = aliases[value.id]
            if resolved is not None and aliases.get(name) != resolved:
                aliases[name] = resolved
                changed = True

    def source_attr(node):
        if (
            isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Name)
            and node.value.id == "self"
            and node.attr in FILE_TO_ATTR.values()
        ):
            return node.attr
        if isinstance(node, ast.Name):
            return aliases.get(node.id)
        return None

    def split_call(call):
        if not (
            isinstance(call, ast.Call)
            and isinstance(call.func, ast.Attribute)
            and call.func.attr == "split"
            and len(call.args) >= 2
            and isinstance(call.args[0], ast.Constant)
            and _constant_int(call.args[1]) == 1
        ):
            return None
        return call.func.value, call.args[0].value

    facts = set()
    for assign in assigns:
        expr = assign.value

        # text.split(start, 1)[1].split(end, 1)[0]
        if isinstance(expr, ast.Subscript) and _constant_int(expr.slice) == 0:
            outer = split_call(expr.value)
            if outer is not None:
                inner_subscript, end = outer
                if isinstance(inner_subscript, ast.Subscript) and _constant_int(inner_subscript.slice) == 1:
                    inner = split_call(inner_subscript.value)
                    if inner is not None:
                        source, start = inner
                        attr = source_attr(source)
                        if attr is not None:
                            boundary = "<next-heading>" if isinstance(end, str) and end.strip() == "##" else end
                            facts.add((attr, start, boundary))

        # text[text.index(start):text.index(end)]
        if isinstance(expr, ast.Subscript) and isinstance(expr.slice, ast.Slice):
            attr = source_attr(expr.value)
            low, high = expr.slice.lower, expr.slice.upper
            if attr is None or not isinstance(low, ast.Call) or not isinstance(high, ast.Call):
                continue

            def index_marker(call):
                if not (
                    isinstance(call.func, ast.Attribute)
                    and call.func.attr == "index"
                    and source_attr(call.func.value) == attr
                    and len(call.args) == 1
                    and isinstance(call.args[0], ast.Constant)
                ):
                    return None
                return call.args[0].value

            start, end = index_marker(low), index_marker(high)
            if start is not None and end is not None:
                facts.add((attr, start, end))

    return facts


class Tranche3qAnchoredSectionBindingTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        source = (ROOT / SOURCE_FILE).read_text(encoding="utf-8")
        tree = ast.parse(source, filename=SOURCE_FILE)
        node = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == CLASS_NAME)
        cls.methods = {m.name: m for m in dti._class_test_methods_in_source_order(node)}
        # BL-038 tranche 3y-a (N4): the audited population is tranche 3q's accepted
        # LOGICAL window, not whatever a physical shard file happens to hold. Reading
        # document_test_classification_005.json directly assumed that file contained
        # nothing but this class, so a legal re-shard that made another accepted scope
        # co-resident broke setUpClass. The binding guard itself is unchanged.
        cls.entries = dth.accepted_window(ROOT, TRANCHE)[1]

    def test_every_anchored_target_is_bounded_to_its_own_markdown_section(self):
        targets_by_method = defaultdict(set)
        for entry in self.entries:
            targets_by_method[entry["method"]].update(entry["targets"])

        for method_name, targets in targets_by_method.items():
            facts = _narrow_section_facts(self.methods[method_name])
            for target in targets:
                if "#BL-" not in target and "#SD-" not in target:
                    continue
                filename, anchor = target.split("#", 1)
                prefix, number = anchor.split("-", 1)
                start = "## " + anchor
                next_heading = f"## {prefix}-{int(number) + 1:03d}"
                attr = FILE_TO_ATTR[filename]
                acceptable = {
                    (attr, start, next_heading),
                    (attr, start, "<next-heading>"),
                }
                with self.subTest(method=method_name, target=target):
                    self.assertTrue(
                        facts & acceptable,
                        f"{target} is not bounded to its own section; facts={sorted(facts)!r}",
                    )


if __name__ == "__main__":
    unittest.main()
