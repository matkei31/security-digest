#!/usr/bin/env python3
"""BL-038 (Fable 5 whole-repository review R-04): unit tests for
document_test_utils.py. Uses short synthetic Markdown fixtures only --
does not copy any production document into a fixture. Standard library
unittest only.
"""

import unittest

import document_test_utils as dtu


class MarkdownHeadingsTest(unittest.TestCase):
    def test_finds_headings_at_every_level_in_document_order(self):
        text = (
            "# Title\n"
            "intro text\n"
            "## Section A\n"
            "body a\n"
            "### Subsection A.1\n"
            "body a.1\n"
            "## Section B\n"
            "body b\n"
        )
        headings = dtu.markdown_headings(text)
        self.assertEqual(
            [(level, name) for level, name, _ in headings],
            [
                (1, "Title"),
                (2, "Section A"),
                (3, "Subsection A.1"),
                (2, "Section B"),
            ],
        )

    def test_does_not_match_a_bare_hash_inside_a_prose_line(self):
        text = "This line mentions a #hashtag but is not a heading.\n## Real Heading\nbody\n"
        headings = dtu.markdown_headings(text)
        self.assertEqual([(level, name) for level, name, _ in headings], [(2, "Real Heading")])

    def test_strips_surrounding_whitespace_from_heading_text(self):
        text = "##   Padded Heading   \nbody\n"
        headings = dtu.markdown_headings(text)
        self.assertEqual(headings[0][1], "Padded Heading")


class FencedCodeBlockHeadingTest(unittest.TestCase):
    """A heading-shaped line inside a fenced code block is code, not a
    document heading (BL-038 round 1 review: the original implementation
    scanned the whole document with one regex and had no fence awareness
    at all, so it misdetected these)."""

    def test_ignores_heading_shaped_line_inside_a_backtick_fence(self):
        text = "## Real Section\n\n```text\n## Fake heading\n```\n\nbody\n"
        headings = dtu.markdown_headings(text)
        self.assertEqual([(level, name) for level, name, _ in headings], [(2, "Real Section")])

    def test_ignores_heading_shaped_line_inside_a_tilde_fence(self):
        text = "## Real Section\n\n~~~text\n### Fake heading\n~~~\n\nbody\n"
        headings = dtu.markdown_headings(text)
        self.assertEqual([(level, name) for level, name, _ in headings], [(2, "Real Section")])

    def test_opening_fence_with_an_info_string_is_still_recognized_as_a_fence(self):
        # The info string ("python" here) must not prevent fence detection.
        text = "```python\n## Fake heading\n```\n## Real Heading\n"
        headings = dtu.markdown_headings(text)
        self.assertEqual([(level, name) for level, name, _ in headings], [(2, "Real Heading")])

    def test_unclosed_fence_suppresses_headings_to_the_end_of_the_document(self):
        text = "## Before\n```\n## Inside unclosed fence\n## Still inside\n"
        headings = dtu.markdown_headings(text)
        self.assertEqual([(level, name) for level, name, _ in headings], [(2, "Before")])

    def test_heading_after_a_properly_closed_fence_is_still_detected(self):
        text = "```\ncode\n```\n## Real Heading After Fence\nbody\n"
        headings = dtu.markdown_headings(text)
        self.assertEqual(
            [(level, name) for level, name, _ in headings], [(2, "Real Heading After Fence")]
        )

    def test_extract_markdown_section_does_not_end_early_at_a_fake_heading_in_its_body(self):
        text = (
            "## Section A\n"
            "before fence\n"
            "```text\n"
            "## Section A\n"  # same level+text as the section itself, but it's code
            "```\n"
            "after fence\n"
            "## Section B\n"
            "b body\n"
        )
        section = dtu.extract_markdown_section(text, "## Section A")
        self.assertIn("before fence", section)
        self.assertIn("after fence", section)
        self.assertNotIn("b body", section)

    def test_heading_shaped_line_in_a_fence_does_not_count_as_a_duplicate_heading(self):
        # Without fence-awareness, this document would look like "## Same
        # Heading" appears twice and extract_markdown_section would refuse
        # it as ambiguous; with fence-awareness there is exactly one real
        # heading, so extraction must succeed.
        text = "## Same Heading\nreal body\n```\n## Same Heading\n```\nmore body\n"
        section = dtu.extract_markdown_section(text, "## Same Heading")
        self.assertIn("real body", section)
        self.assertIn("more body", section)

    def test_ordinary_inline_code_and_prose_hash_handling_is_unaffected(self):
        text = (
            "This paragraph has `inline code` and a #hashtag, neither is a heading.\n"
            "## Real Heading\n"
            "body with `a #hash in code span` too\n"
        )
        headings = dtu.markdown_headings(text)
        self.assertEqual([(level, name) for level, name, _ in headings], [(2, "Real Heading")])


class ExtractMarkdownSectionTest(unittest.TestCase):
    DOC = (
        "# Doc Title\n"
        "preamble\n"
        "## Section A\n"
        "a-line-1\n"
        "a-line-2\n"
        "### Subsection A.1\n"
        "a1-line-1\n"
        "## Section B\n"
        "b-line-1\n"
        "# Second Top Level\n"
        "top-line-1\n"
    )

    def test_extracts_body_up_to_next_same_level_heading(self):
        section = dtu.extract_markdown_section(self.DOC, "## Section A")
        self.assertIn("a-line-1", section)
        self.assertIn("a-line-2", section)
        # A deeper heading (### Subsection A.1) and its body stay inside
        # the "## Section A" body (extracting a subsection is done by
        # calling extract_markdown_section again on this returned text).
        self.assertIn("### Subsection A.1", section)
        self.assertIn("a1-line-1", section)
        # But content belonging to the next "##"-level section must not
        # leak in.
        self.assertNotIn("b-line-1", section)
        self.assertNotIn("Section B", section)

    def test_subsection_is_not_taken_from_outside_its_parent_section(self):
        section_b = dtu.extract_markdown_section(self.DOC, "## Section B")
        with self.assertRaises(dtu.MarkdownSectionError):
            # "### Subsection A.1" exists in the document, but not inside
            # Section B's own body -- extracting it FROM section_b's text
            # must fail rather than silently reaching back into Section A.
            dtu.extract_markdown_section(section_b, "### Subsection A.1")

    def test_extracts_nested_subsection_via_two_calls(self):
        section_a = dtu.extract_markdown_section(self.DOC, "## Section A")
        subsection = dtu.extract_markdown_section(section_a, "### Subsection A.1")
        self.assertIn("a1-line-1", subsection)

    def test_body_text_matching_heading_text_is_not_mistaken_for_a_heading(self):
        doc = (
            "## Real Section\n"
            "This paragraph literally says Real Section as prose, not a heading.\n"
            "## Next Section\n"
            "next body\n"
        )
        section = dtu.extract_markdown_section(doc, "## Real Section")
        self.assertIn("literally says Real Section as prose", section)
        self.assertNotIn("next body", section)

    def test_last_section_in_document_runs_to_end_of_text(self):
        section = dtu.extract_markdown_section(self.DOC, "# Second Top Level")
        self.assertIn("top-line-1", section)

    def test_missing_heading_raises_with_the_heading_text_in_the_message(self):
        with self.assertRaises(dtu.MarkdownSectionError) as ctx:
            dtu.extract_markdown_section(self.DOC, "## Does Not Exist")
        self.assertIn("Does Not Exist", str(ctx.exception))

    def test_malformed_heading_argument_raises(self):
        with self.assertRaises(dtu.MarkdownSectionError):
            dtu.extract_markdown_section(self.DOC, "Section A")  # missing '#'

    def test_duplicate_heading_raises_by_default(self):
        doc = "## Repeated\nfirst body\n## Repeated\nsecond body\n"
        with self.assertRaises(dtu.MarkdownSectionError):
            dtu.extract_markdown_section(doc, "## Repeated")

    def test_duplicate_heading_returns_first_occurrence_when_allowed(self):
        doc = "## Repeated\nfirst body\n## Repeated\nsecond body\n"
        section = dtu.extract_markdown_section(doc, "## Repeated", allow_duplicate=True)
        self.assertIn("first body", section)
        self.assertNotIn("second body", section)

    def test_heading_level_is_part_of_the_match_not_just_the_text(self):
        # A level-3 "### Same Text" nested inside "## Same Text" is part of
        # the level-2 section's own body (a deeper heading never ends a
        # shallower section) -- extract_markdown_section("## Same Text")
        # legitimately includes it. What must NOT happen is the two
        # differently-leveled headings being treated as one ambiguous
        # duplicate: each is independently addressable by its own level.
        doc = "## Same Text\nh2 body\n### Same Text\nh3 body\n"
        h2 = dtu.extract_markdown_section(doc, "## Same Text")
        h3 = dtu.extract_markdown_section(doc, "### Same Text")
        self.assertIn("h2 body", h2)
        self.assertIn("h3 body", h2)  # nested subsection stays inside the parent body
        self.assertIn("h3 body", h3)
        self.assertNotIn("h2 body", h3)  # but extracting the child alone excludes the parent's own text


class NormalizeMarkdownProseTest(unittest.TestCase):
    def test_collapses_newlines_and_repeated_whitespace_to_a_single_space(self):
        text = "some   text\nwrapped\n\nacross    lines"
        self.assertEqual(dtu.normalize_markdown_prose(text), "some text wrapped across lines")

    def test_strips_leading_and_trailing_whitespace(self):
        self.assertEqual(dtu.normalize_markdown_prose("  \n padded \n "), "padded")

    def test_harmless_rewrap_of_the_same_sentence_still_matches_after_normalizing_both_sides(self):
        original = "Fable 5 could not retrieve `STATUS.md` or\n`test_security_requirements.py`"
        rewrapped = "Fable 5 could not\nretrieve `STATUS.md`\nor `test_security_requirements.py`"
        self.assertEqual(
            dtu.normalize_markdown_prose(original), dtu.normalize_markdown_prose(rewrapped)
        )

    def test_does_not_delete_or_substitute_any_non_whitespace_character(self):
        text = "CVE-2020-12345, SR-045, 「ok」, 9.8/CRITICAL"
        self.assertEqual(dtu.normalize_markdown_prose(text), text)

    def test_a_genuine_wording_change_is_not_hidden_by_normalization(self):
        original = normalized_a = dtu.normalize_markdown_prose(
            "the request was accepted by the user"
        )
        mutated = dtu.normalize_markdown_prose("the request was rejected by the user")
        self.assertNotEqual(normalized_a, mutated)

    def test_a_missing_id_is_not_hidden_by_normalization(self):
        # Normalization alone cannot make a test pass against a document
        # that dropped a required ID: the full original text (with both
        # IDs) is not a substring of a document that only has one of them.
        original = dtu.normalize_markdown_prose("approved by SD-033 and SR-045")
        missing_one_id = dtu.normalize_markdown_prose("approved by SD-033")
        self.assertNotIn(original, missing_one_id)


if __name__ == "__main__":
    unittest.main()
