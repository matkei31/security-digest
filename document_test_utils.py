"""Test-only helpers for parsing this repository's Markdown documents
(BACKLOG.md, STATUS.md, DECISIONS.md, UI_SPEC.md, SECURITY_REQUIREMENTS.md,
SECURITY_OPERATIONS.md, SOURCE_USAGE_POLICY.md, AGENTS.md).

BL-038 (Fable 5 whole-repository review R-04): several document tests had
grown ad-hoc, duplicated `text.split(marker)`-style section extraction, and
some assertions locked long prose verbatim -- including the exact line-wrap
position inherited from however the source Markdown happened to be
reformatted, not any semantic content. This module is the shared,
unit-tested replacement for that ad-hoc parsing; it exists to make document
tests express what they actually require (a section exists and contains a
value, not "this exact 40-word sentence wraps at this exact column").

This is not a general Markdown parser: it implements exactly the section/
heading extraction pattern this repository's document tests need (ATX `#`
headings, ATX-only -- Setext `===`/`---` underline headings are not used
anywhere in this repository's documents and are not supported). Heading
recognition is fenced-code-block-aware: a line that looks like an ATX
heading but sits inside a ` ``` `/`~~~` fenced code block is a line of
CODE, not a document heading, and is not returned as one (see
markdown_headings). No new dependency was added; this module uses only
the standard library.

Import this from test_*.py files only. It has no dependency on runtime
code (fetch.py/daily_json.py/vulnerability_facts.py) and must never be
imported by them -- it exists purely to keep document tests maintainable,
not to influence what those documents mean at runtime. The `test_` prefix
is deliberately omitted from this filename so unittest's test discovery
does not try to collect it as a test module itself.
"""

import re


class MarkdownSectionError(Exception):
    """Raised when a requested Markdown section/heading cannot be located
    or extracted unambiguously."""


# Matches a single line (no trailing newline) that is an ATX heading: `#`
# through `######` at the start of the line, followed by at least one
# space/tab and the heading text. A bare `#` inside prose (not at the very
# start of the line) never matches this. Applied only to lines the fenced-
# code-block scanner in markdown_headings has determined are NOT inside a
# code fence -- a line that merely looks like this pattern but sits inside
# a ```/~~~ fenced code block is code, not a heading (see below).
_HEADING_LINE_RE = re.compile(r"^(#{1,6})[ \t]+(.*?)[ \t]*$")

# Matches a fenced-code-block delimiter line: 0-3 leading spaces (matching
# CommonMark's fence-indentation allowance), then a run of 3+ backticks or
# 3+ tildes, then the rest of the line (an opening fence's info string, or
# -- when this same pattern is reused to test for the CLOSING fence -- text
# that must turn out to be empty/whitespace-only for the line to actually
# close the fence).
_FENCE_RE = re.compile(r"^ {0,3}(`{3,}|~{3,})(.*)$")

_WHITESPACE_RUN_RE = re.compile(r"\s+")


def markdown_headings(text):
    """Return every ATX heading in `text`, in document order, as a list of
    (level, heading_text, line_start_offset) tuples. `level` is 1-6 (the
    number of leading `#` characters). `heading_text` is the heading line's
    content after the `#` markers, with surrounding whitespace stripped.
    `line_start_offset` is the character offset where the heading LINE
    begins (not the offset of the heading text itself), for use by
    extract_markdown_section.

    A line that looks like an ATX heading is skipped -- not returned as a
    heading -- while a fenced code block (delimited by a line of 3+
    backticks or 3+ tildes, optionally indented up to 3 spaces, optionally
    followed by an info string on the OPENING fence) is open. The closing
    fence must use the same character as the opening fence, be at least as
    long, and (per CommonMark) contain nothing but that fence character
    and optional trailing whitespace -- a line that merely starts with
    enough of the fence character but has other trailing text does not
    close the fence. An unclosed fence runs to the end of the document,
    so nothing after it is scanned for headings either. This is not a
    general Markdown parser -- indented (non-fenced) code blocks and
    Setext headings are intentionally out of scope, since this
    repository's documents don't use either.
    """
    headings = []
    in_fence = False
    fence_char = None
    fence_len = 0
    offset = 0
    for line in text.splitlines(keepends=True):
        content = line.rstrip("\r\n")
        fence_match = _FENCE_RE.match(content)
        if in_fence:
            if (
                fence_match
                and fence_match.group(1)[0] == fence_char
                and len(fence_match.group(1)) >= fence_len
                and fence_match.group(2).strip() == ""
            ):
                in_fence = False
        elif fence_match:
            in_fence = True
            fence_char = fence_match.group(1)[0]
            fence_len = len(fence_match.group(1))
        else:
            heading_match = _HEADING_LINE_RE.match(content)
            if heading_match:
                headings.append(
                    (len(heading_match.group(1)), heading_match.group(2).strip(), offset)
                )
        offset += len(line)
    return headings


def _parse_heading_spec(heading):
    match = re.match(r"^(#{1,6})[ \t]+(.*?)[ \t]*$", heading)
    if not match:
        raise MarkdownSectionError(
            "heading argument must look like an ATX heading, e.g. "
            f"'## 1. As of': {heading!r}"
        )
    return len(match.group(1)), match.group(2).strip()


def extract_markdown_section(text, heading, *, allow_duplicate=False):
    """Return the body of the section introduced by the ATX heading given
    by `heading`, which must include its leading `#` markers exactly as
    they appear in the document (for example "## 1. As of" or
    "## BL-037 --- pipeline E2Eとrepository実データ全件検証を追加する").
    Both the heading level (number of `#`) and its text must match.

    The returned body starts immediately after the heading's own line and
    ends immediately before the next heading at the SAME level or
    shallower (a deeper heading -- e.g. an "###" subsection inside a "##"
    section -- is included in the body, which is what makes this function
    also usable to grab a subsection: call it again on the returned text
    with the "###" heading). If no shallower-or-equal heading follows, the
    body runs to the end of `text`.

    Only real heading lines (see markdown_headings) are matched, so a
    paragraph or list item that happens to contain the same text as a
    heading is never mistaken for the heading itself.

    Raises MarkdownSectionError if `heading` is not a well-formed ATX
    heading string, or if no such (level, text) heading appears anywhere
    in `text`. If it appears more than once, raises MarkdownSectionError
    (ambiguous which occurrence the caller wants) unless
    allow_duplicate=True, in which case the FIRST occurrence is used --
    callers that intentionally expect a repeated heading label (e.g. the
    same subsection title recurring under different parent sections) must
    opt in explicitly rather than silently getting whichever occurrence
    happens to be first.
    """
    wanted_level, wanted_text = _parse_heading_spec(heading)
    headings = markdown_headings(text)
    matches = [h for h in headings if h[0] == wanted_level and h[1] == wanted_text]
    if not matches:
        raise MarkdownSectionError(f"heading not found: {heading!r}")
    if len(matches) > 1 and not allow_duplicate:
        raise MarkdownSectionError(
            f"heading {heading!r} appears {len(matches)} times; "
            "pass allow_duplicate=True if more than one occurrence is expected"
        )

    level, _, start = matches[0]
    match_index = headings.index(matches[0])

    line_break = text.find("\n", start)
    body_start = len(text) if line_break == -1 else line_break + 1

    body_end = len(text)
    for other_level, _, other_start in headings[match_index + 1:]:
        if other_level <= level:
            body_end = other_start
            break

    return text[body_start:body_end]


def normalize_markdown_prose(text):
    """Collapse every run of whitespace in `text` (including newlines) to
    a single space, and strip leading/trailing whitespace. No character
    other than whitespace is added, removed, or reordered -- words, IDs,
    punctuation, and values are all preserved verbatim.

    Use this to compare a known prose fragment against document text when
    only the fragment's line-wrap position (not its actual wording) is
    expected to vary -- for example `self.assertIn(normalize_markdown_prose(fragment),
    normalize_markdown_prose(section))`. Do not use it for headings, tables,
    or code blocks, where whitespace (indentation, cell alignment, newlines)
    can be semantically significant. It also must not be used as a
    substitute for checking that specific words/values are present: it only
    absorbs whitespace differences, so a genuine wording or value change
    still changes the normalized string and is still caught by assertIn.
    """
    return _WHITESPACE_RUN_RE.sub(" ", text).strip()
