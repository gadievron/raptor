r"""Post-processing for LLM-returned strings before they reach reports / UI.

Pairs with prompt_envelope at the input side: where the envelope quarantines
input from being treated as instructions by the model, this module
quarantines model output from rendering surprises (terminal-injection,
markdown auto-render) when the operator views findings.

Pipeline:
  1. strip autofetch markup (envelope regex + the report-side
     supplement below — a genuine second layer, not an alias)
  2. entity-escape raw-HTML construct openers (`<` before a tag
     letter / `/` / `!` / `?` → `&lt;`) — non-fetching structural
     HTML (`<h1>`, `<table>`, `<details>`, `<!--`) is the HTML
     spelling of block-structure forgery, and the comment/collapse
     forms hide the REST of the rendered report
  3. blank block-structure forgery lines (setext underlines, ---
     rules, table delimiter rows)
  4. defang line-leading markdown control chars (`*_#|> at line
     start) on real newline boundaries — keeps prose readable
     mid-string while disabling block-level rendering
  5. escape ANSI / BIDI / control bytes (preserves `\n`, `\t` so
     multi-line prose still renders as paragraphs in reports)
  6. length-cap at max_chars with a single Unicode ellipsis (…)

Note: the /tmp/llm.md spec listed escape→strip→cap. We deviate to strip→
escape→cap because `core.security.log_sanitisation.escape_nonprintable`
treats `\n` as non-printable and would convert it to `\x0a`, which both
breaks the multi-line strip and prevents reports from showing line breaks.
The spec's *intent* (multi-line markdown defanged, ANSI/BIDI killed,
natural prose preserved) is preserved; only the literal order changed.
"""

from __future__ import annotations

import re

from core.security.log_sanitisation import escape_nonprintable
from core.security.prompt_envelope import _strip_autofetch_markup


# Line-leading markdown control chars. `|` (table rows) and `>`
# (blockquotes) joined the class for the injection-evasion battery's
# a leading-pipe row plus a forged delimiter row rendered as a
# fake metrics table in operator-facing reports; blockquote leads
# reformatted attacker prose as authoritative quotation.
# REPEATED runs (separated by spaces/tabs) are consumed together:
# stripping only the first run left `# # X` as ` # X`, which markdown
# (up to 3 leading spaces) still renders as an h1.
# `~` joined for tilde fences: a line-leading `~~~` opens a fenced
# code block exactly like ``` (CommonMark), and a hostile value that
# opens one swallows the REST of the rendered report — the writer's
# own fences, headings, and every later finding render as literal
# code until a closing tilde run. The backtick was in the class from
# day one; the tilde spelling of the same construct was not.
_LINE_LEAD_MD_RE = re.compile(
    r'(?m)^([ \t]*)([`*_#|>~]+(?:[ \t]+[`*_#|>~]+)*)'
)

# Line-leading list markers (`- item`, `+ item`, `1. item`, `1) item`)
# — CommonMark only forms a list item when the char AFTER the marker
# is a space/tab, so a ZWSP inserted between them defangs the
# construct while the visible text (numbering included) survives;
# stripping, as the class above does, would delete meaningful "1." /
# "-" prefixes from prose. `*` bullets are already stripped by the
# class above. `--flag` / `1.5` stay untouched (no space after the
# marker shape).
_LIST_MARKER_RE = re.compile(r'(?m)^([ \t]*)([-+]|\d{1,9}[.)])([ \t])')

# Block-structure forgery lines: a line consisting solely of
# space / tab / `|` / `:` / `-` / `=` with at least one `-` or `=` is
# markdown STRUCTURE, never prose — setext heading underlines
# (`TEXT\n====` / `TEXT\n----`), horizontal rules / frontmatter
# fences (`---`), and GFM table delimiter rows (`|---|:---:|`, which
# is what turns pipe-bearing lines into a rendered table at all).
# Blanked outright: the escape-in-place style used for inline chars
# can't help here because ANY run of the marker chars re-forms the
# construct.
_MD_STRUCTURE_LINE_RE = re.compile(
    r'(?m)^(?=[ \t|:=-]+$)(?=.*[-=])[ \t|:=-]+$'
)

# Report-side autofetch supplement: forms verified to slip the
# envelope's _AUTOFETCH_MARKUP_RE and land in rendered reports. Kept
# as a SEPARATE second layer in the output sanitiser — the envelope
# regex is the input-side defence and is versioned independently; the
# report side must hold even when the input side misses.
#   * <image> — HTML parsers alias it to <img> (auto-fetch).
#   * <input type=image src=...> fetches; any stray <input> in report
#     prose is safe to strip wholesale.
#   * <frame>/<track>/<bgsound>/<portal>/<applet>/<mglyph> — fetching
#     tags absent from the envelope alternation.
#   * <a/href=...> — `/` also delimits attributes in HTML; the
#     envelope's `<a\s` arm requires whitespace.
#   * style ATTRIBUTE url() fetch (`<div style="background:url(//e)">`)
#     — the envelope only covers the <style> element and @import.
_REPORT_AUTOFETCH_SUPPLEMENT_RE = re.compile(
    r'<(?:image|input|frame|track|bgsound|portal|applet|mglyph)\b[^>]{0,8192}>'
    r'|<a/[^>]{0,8192}>'
    r'|<[a-zA-Z][^>]{0,8192}?style\s*=[^>]{0,8192}?url\s*\([^>]{0,8192}>',
    re.IGNORECASE,
)

# Raw-HTML construct openers. CommonMark passes raw HTML through
# verbatim, and its HTML-block rules (types 1-7) plus inline raw HTML
# make a bare `<` the entry point for every structural forgery the
# line-leading class above blocks in its markdown spelling: `<h1>ALL
# CLEAR</h1>` forges a heading, `<table>` forges a metrics table,
# `<blockquote>` reformats attacker prose as authoritative quotation —
# and the suppression direction is worse: a line-leading `<!--`
# comments out EVERY subsequent finding, heading and fence until a
# `-->`, and `<details>` collapses the remainder of the report. The
# autofetch layers above only strip FETCHING tags; non-fetching
# structural HTML sailed through both. Entity-escape the opener
# instead of stripping: `&lt;` renders as a literal `<` so prose that
# legitimately quotes markup stays readable, while no renderer can
# form a tag, comment (`<!--`), declaration (`<!DOCTYPE`), CDATA
# section (`<![CDATA[`), or processing instruction (`<?`) from it.
# The lookahead keeps comparison prose (`a < b`, `x <- y`) untouched:
# only `<` immediately followed by a tag-name letter, `/` (close
# tag), `!` (comment/declaration/CDATA) or `?` (PI) can open an HTML
# construct. Already-escaped text (`&lt;h1&gt;`) has no raw `<` and
# passes unchanged — CommonMark renders entities as literal text,
# never as markup, so there is no decode-then-parse reintroduction.
_HTML_CONSTRUCT_OPEN_RE = re.compile(r'<(?=[A-Za-z/!?])')

_ELLIPSIS = '…'


def sanitise_string(s: str, *, max_chars: int = 500) -> str:
    """Defang an LLM-returned string for safe rendering in reports / UI.

    `max_chars` is the post-escape length cap; the suffix ellipsis counts
    toward the cap (returned string is at most `max_chars` characters).

    Also strips autofetch markup. Pre-fix `sanitise_string` defanged
    line-leading markdown control chars but DIDN'T strip the
    autofetch markup family (`![](url)` images, `[text](javascript:)`
    links, `<img>`/`<iframe>`/`<script>` HTML tags, scheme-relative
    `//host` links). The input-side envelope already strips these
    from untrusted slot values BEFORE the model sees them, but
    the OUTPUT side leaked them through — the LLM could be
    coaxed into reproducing autofetch markup in its response,
    and that response landed in markdown reports / web UI without
    further sanitization. A finding renderer that opens the report
    in a browser then fired the autofetch (image src, iframe load,
    redirect link), exfiltrating context to the attacker-controlled
    URL.
    """
    s = _strip_autofetch_markup(s)
    s = _REPORT_AUTOFETCH_SUPPLEMENT_RE.sub(
        '[REDACTED-AUTOFETCH-MARKUP]', s,
    )
    # After both autofetch layers (they match raw tags), before the
    # markdown-structure passes: raw HTML is the HTML spelling of the
    # same block-structure forgery those passes defang.
    s = _HTML_CONSTRUCT_OPEN_RE.sub('&lt;', s)
    s = _MD_STRUCTURE_LINE_RE.sub('', s)
    s = _LINE_LEAD_MD_RE.sub(lambda m: m.group(1), s)
    s = escape_nonprintable(s, preserve_newlines=True)
    # ZWSP insertion AFTER escape_nonprintable (same ordering as
    # sanitise_code's fence-break ZWSP) — the escape pass would turn
    # an earlier-inserted ZWSP into a visible literal backslash-u200b.
    s = _LIST_MARKER_RE.sub(
        lambda m: m.group(1) + m.group(2) + '​' + m.group(3), s,
    )
    if len(s) > max_chars:
        s = s[: max_chars - 1] + _ELLIPSIS
    return s


def sanitise_inline(s: str, *, max_chars: int = 300) -> str:
    """Defang for SINGLE-LINE slots — headings, labels, table cells —
    where the rendered value never begins a markdown line of its own.

    Newlines/line separators are flattened to spaces (so the value
    cannot START a line), autofetch markup is stripped (both layers —
    ``<img>`` in a table cell still fetches), control/bidi bytes are
    escaped, and the result is length-capped. The line-leading
    markdown stripping of :func:`sanitise_string` is deliberately
    omitted: the slot's own prefix (``# ``, ``| ``, ``**``) makes
    mid-string ``#``/``*``/``-`` inert, and stripping them would eat
    legitimate label text (a literal ``#`` column header, a ``-``
    placeholder cell).

    In-slot STRUCTURE characters are entity-escaped (the ``_md_cell``
    idiom, cf. cve-diff's table renderer): an in-cell ``|`` splits the
    table row and shifts attacker text under different column
    headers, and a backtick closes a wrapping `` ` `` code span so
    the tail renders as live inline markdown. ``&#124;`` / ``&#96;``
    render as the literal character in plain markdown slots; inside a
    code span they display as the entity text — the safe direction,
    since no raw delimiter survives to terminate the span.
    """
    s = (str(s)
         .replace("\r", " ").replace("\n", " ")
         .replace("\u2028", " ").replace("\u2029", " "))
    s = _strip_autofetch_markup(s)
    s = _REPORT_AUTOFETCH_SUPPLEMENT_RE.sub(
        '[REDACTED-AUTOFETCH-MARKUP]', s,
    )
    # Inline raw HTML forms anywhere in a slot (`t<h1>x</h1>` in a
    # heading, `<details>` in a table cell collapses the row's tail) —
    # same construct-opener escape as the prose lane.
    s = _HTML_CONSTRUCT_OPEN_RE.sub('&lt;', s)
    s = escape_nonprintable(s)
    s = s.replace("|", "&#124;").replace("`", "&#96;")
    if len(s) > max_chars:
        s = s[: max_chars - 1] + _ELLIPSIS
    return s


def sanitise_code(s: str, *, max_chars: int = 10_000) -> str:
    """Escape control chars in LLM-returned code for fenced-block rendering.

    Unlike sanitise_string, does NOT strip markdown control chars — code
    contains ``#include``, ``*ptr``, ``__attribute__`` legitimately.
    Fenced code blocks (` ``` `) already isolate markdown rendering; the
    remaining threat is ANSI/BIDI/control-byte injection via terminal
    emulators (``cat report.md``) — handled by `escape_nonprintable`.

    Fence-break protection: LLM-returned code can legitimately contain
    triple-backtick runs (nested fenced blocks in a docstring, code
    that quotes another fenced block, an LLM that hallucinated a
    fence inside its response). Pre-fix the function returned that
    code as-is; the wrapping renderer's outer ``` fence was then
    prematurely closed by the embedded ```, and everything AFTER
    that point spilled out of the code block — rendering as
    interpreted markdown (links autofetch, headings break layout,
    `<script>` tags execute on some preview surfaces).

    Insert a zero-width-space (U+200B) between the second and third
    backtick of any 3+ backtick run. Visually invisible to the
    operator reading the rendered markdown, but the markdown parser
    no longer sees a fence terminator. The reader's eye still sees
    ``` if they care, just not as a parse-relevant fence.
    """
    s = escape_nonprintable(s, preserve_newlines=True)
    # Defang fence-break: any run of 3+ backticks gets a ZWSP
    # inserted after the second char so the markdown parser sees
    # `` then `` ``` `` becomes `` `` U+200B ` `` etc. Use a regex
    # with a callback to handle 3, 4, 5+ backtick runs uniformly.
    import re as _re
    s = _re.sub(r"`{3,}", lambda m: "``​" + "`" * (len(m.group(0)) - 2), s)
    if len(s) > max_chars:
        s = s[: max_chars - 1] + _ELLIPSIS
    return s
