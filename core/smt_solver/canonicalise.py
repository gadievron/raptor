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
    (re.compile(r'\bis\s+null\b',                             re.IGNORECASE), ' == NULL '),
    (re.compile(r'\bis\s+zero\b',                             re.IGNORECASE), ' == 0 '),
    # Single-word synonyms.
    (re.compile(r'\bequals\b',                                re.IGNORECASE), ' == '),
    (re.compile(r'\bexceeds\b',                               re.IGNORECASE), ' > '),
    (re.compile(r'\bbelow\b',                                 re.IGNORECASE), ' < '),
    # ``up to N`` is read as inclusive (``<= N``) — the most common
    # convention in maths/CS, though some writers treat it as exclusive.
    # Document the choice rather than guess case-by-case.
    (re.compile(r'\bup\s+to\b',                               re.IGNORECASE), ' <= '),
)

_WHITESPACE_RUN = re.compile(r'\s+')


def canonicalise(text: str) -> str:
    """Rewrite common english operator aliases to canonical syntax.

    Idempotent: input that's already symbolic passes through unchanged
    (modulo whitespace collapse).
    """
    out = text
    for pat, repl in _REWRITES:
        out = pat.sub(repl, out)
    return _WHITESPACE_RUN.sub(' ', out).strip()
