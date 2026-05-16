"""English-aliased pre-canonicalisation for SMT encoder parsers.

LLM output frequently uses english operator phrases — "is greater than",
"equals", "is at least" — instead of the canonical symbolic forms.
This module applies a small ordered set of regex rewrites *before* the
parser sees the input, mapping common english forms to ``>``, ``<``,
``>=``, ``<=``, ``==``, ``!=`` (with NULL / 0 specialisations for the
``is null`` / ``is zero`` / ``is non-null`` / ``is non-zero`` family).

Coverage at a glance:
- Relational: ``is greater than``, ``is less than``, ``is at least``,
  ``is at most``, ``is greater than or equal to``, ``is less than or
  equal to``, ``exceeds``, ``below``, ``does not exceed``, ``up to``.
- Equality: ``equals``, ``is equal to``, ``is not equal to``,
  ``does not equal``.
- Null/zero: ``is null``, ``is zero``, ``is non-null``, ``is non-zero``
  (``-`` and a single space accepted between ``non`` and the noun).

Design intent:
- Rewrites are *additive*: phrases the per-parser grammar already
  recognises (notably one-gadget's native ``is writable`` suffix form
  and bracketed memory references like ``[rsp+0x8]``) are NOT touched
  here, so existing parse paths keep their dedicated rejection
  messages.  The exception is ``is null``: both encoders see the
  rewritten ``== NULL`` form first, but they encode it identically to
  the dedicated grammar would have done.
- Order matters — longer, more-specific phrases are tried before
  shorter ones (``is greater than or equal to`` before ``is greater
  than``; ``does not exceed`` before ``exceeds``).
- Word boundaries (``\\b``) keep rewrites from firing inside
  identifiers (``equalsValue`` must NOT become ``==Value``).
- ``up to N`` is read as inclusive (``<= N``).  Some writers treat it
  as exclusive; the inclusive reading is the convention in maths/CS
  and is documented at the rewrite site.

Used by:
  packages/codeql/smt_path_validator.py :: _parse_condition
  packages/exploit_feasibility/smt_onegadget.py :: _parse_atom
"""

from __future__ import annotations

import re
from typing import Tuple

# (pattern, replacement) pairs.  Replacements include surrounding spaces
# because the english phrases don't always sit next to whitespace; the
# trailing collapse-whitespace pass tidies up.
#
# Order matters — rewrites are applied sequentially.  Longer, more-
# specific phrases must precede their shorter prefixes; otherwise the
# shorter pattern eats part of the longer one and leaves a malformed
# tail like ``is == to``.  In particular:
#   - ``is greater than or equal to`` before ``is greater than``
#   - ``does not exceed`` before ``exceeds``
#   - ``is non-null`` before ``is null``
_REWRITES: Tuple[Tuple[re.Pattern[str], str], ...] = (
    # Longer phrases first.
    (re.compile(r'\bis\s+greater\s+than\s+or\s+equal\s+to\b', re.IGNORECASE), ' >= '),
    (re.compile(r'\bis\s+less\s+than\s+or\s+equal\s+to\b',    re.IGNORECASE), ' <= '),
    (re.compile(r'\bis\s+not\s+equal\s+to\b',                 re.IGNORECASE), ' != '),
    (re.compile(r'\bdoes\s+not\s+equal\b',                    re.IGNORECASE), ' != '),
    (re.compile(r'\bdoes\s+not\s+exceed\b',                   re.IGNORECASE), ' <= '),
    (re.compile(r'\bis\s+at\s+least\b',                       re.IGNORECASE), ' >= '),
    (re.compile(r'\bis\s+at\s+most\b',                        re.IGNORECASE), ' <= '),
    (re.compile(r'\bis\s+greater\s+than\b',                   re.IGNORECASE), ' > '),
    (re.compile(r'\bis\s+less\s+than\b',                      re.IGNORECASE), ' < '),
    (re.compile(r'\bis\s+equal\s+to\b',                       re.IGNORECASE), ' == '),
    # Negative null/zero forms before the positive ones.
    (re.compile(r'\bis\s+non[-\s]?zero\b',                    re.IGNORECASE), ' != 0 '),
    (re.compile(r'\bis\s+non[-\s]?null\b',                    re.IGNORECASE), ' != NULL '),
    # Positive forms — close the asymmetry with the negated counterparts
    # above.  Without these, a writer using ``ptr is null`` got an
    # ``UNRECOGNIZED_FORM`` rejection from the path validator (one_gadget
    # has its own native ``is NULL`` suffix grammar, but the rewrite is
    # semantically identical for it: both reach ``lhs == 0``).
    # Lookbehind requires a non-whitespace LHS before `is null` /
    # `is zero`. Pre-fix `is null` at the start of a line (or
    # surrounded by whitespace only — empty constraint cell, fragment
    # extracted from a longer prose) rewrote to ` == NULL `, an
    # operator-less expression that the downstream parser then
    # rejected with `UNRECOGNIZED_FORM` — but the operator's actual
    # input was visibly malformed and they got a misleading
    # "rewrite-then-parse failed" diagnostic instead of the more
    # helpful "missing left-hand side". With the lookbehind the
    # rewrite simply doesn't fire on lhs-less input; the original
    # `is null` reaches the parser unchanged and the unrecognised-
    # form rejection is keyed to the original token (operator can
    # find it in their source).
    (re.compile(r'(?<=\S)\s+is\s+null\b',                     re.IGNORECASE), ' == NULL '),
    (re.compile(r'(?<=\S)\s+is\s+zero\b',                     re.IGNORECASE), ' == 0 '),
    # Single-word synonyms. Tightened to require WHITESPACE
    # (or string boundary) on both sides — `\b` alone matches
    # at any word/non-word transition, including code-form
    # identifiers like `a.equals(b)` (`.` and `(` are
    # non-word, so `\bequals\b` matches the method name and
    # rewrites to `==`, breaking the parse downstream). Real-
    # world hit: any constraint expression that quotes
    # source-form text with `.equals(`, `.exceeds(`,
    # `.below(` — common in Java/Kotlin/C# audits.
    (re.compile(r'(?:^|\s)equals(?:\s|$)',                    re.IGNORECASE), ' == '),
    (re.compile(r'(?:^|\s)exceeds(?:\s|$)',                   re.IGNORECASE), ' > '),
    (re.compile(r'(?:^|\s)below(?:\s|$)',                     re.IGNORECASE), ' < '),
    # ``up to N`` is read as inclusive (``<= N``) — the most common
    # convention in maths/CS, though some writers treat it as exclusive.
    # Document the choice rather than guess case-by-case.
    #
    # Pre-fix the rewrite was `\bup\s+to\b` (no follow-on constraint).
    # That fired on ANY `up to` in the input — including:
    #   * `pointer scaled up to 8 bytes`  → `pointer scaled <= 8 bytes`
    #     — the `up to` was DESCRIPTIVE, not relational.
    #   * `it goes up to a function called X` → `it goes <= a
    #     function called X`
    #   * `the buffer is sized up to allow growth` → `the buffer is
    #     sized <= allow growth`
    # The relational rewrite ate narrative text and corrupted the
    # downstream parser's view of the condition.
    #
    # Require a numeric literal (decimal or hex) AFTER `up to` so the
    # rewrite only fires when the canonical form is unambiguous.
    # Lookahead (`(?=...)`) keeps the literal AS the next token for
    # the parser. Loses some legitimate non-numeric cases (`up to N`
    # with `N` as a variable) — those callers should write `<= N`
    # directly.
    (re.compile(r'\bup\s+to(?=\s+(?:0x[0-9a-f]+|\d))',        re.IGNORECASE), ' <= '),
)

_WHITESPACE_RUN = re.compile(r'[ \t]+')


def canonicalise(text: str) -> str:
    """Rewrite common english operator aliases to canonical syntax.

    Idempotent: input that's already symbolic passes through unchanged
    (modulo whitespace collapse).

    Pre-fix the trailing whitespace collapse used `r'\\s+'` which
    matches NEWLINES + tabs + spaces. Multi-line condition
    inputs — `_substitute_calls(_canonicalise(text), ...)` is
    called with whatever the caller hands it, including
    LLM-emitted JSON arrays where the parser has joined
    multiple distinct conditions with newlines — got their
    structural newlines collapsed into single spaces, merging
    independent conditions into one parser-confused glob:

        cond1: ``a > 0\\nb > 0`` (two conditions)
        post-canonicalise: ``a > 0 b > 0`` (parser sees one
        malformed condition with two operands).

    Restrict the collapse to `[ \\t]+` (spaces + tabs only) so
    newlines survive as logical separators. The downstream
    parsers tokenise per-line, so preserving the newline keeps
    the multi-condition structure intact. Internal multi-space
    runs from rewrite expansion still collapse fine.
    """
    # Cap input length before the per-pattern loop. Pre-fix the
    # `for pat, repl in _REWRITES: out = pat.sub(repl, out)` loop
    # ran ~20 patterns sequentially over the WHOLE input string —
    # O(20*N) work for an N-byte input. Real condition strings
    # passed to canonicalise() are short (a single boolean
    # expression, low-KB at most), but a hostile / corrupt
    # caller passing a multi-MB blob would burn proportional
    # wallclock per call. 256 KB cap is two orders of magnitude
    # beyond any realistic condition; oversized input is
    # almost certainly an upstream bug rather than legitimate
    # data, so truncating is the safer mode than chewing through
    # it. Truncate from the END (keep the head) — the leading
    # part of a condition is the part the rewrites actually
    # care about.
    _CANONICALISE_INPUT_CAP = 256 * 1024
    out = text if len(text) <= _CANONICALISE_INPUT_CAP else text[:_CANONICALISE_INPUT_CAP]
    for pat, repl in _REWRITES:
        out = pat.sub(repl, out)
    return _WHITESPACE_RUN.sub(' ', out).strip()
