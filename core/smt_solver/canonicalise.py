"""English-aliased pre-canonicalisation for SMT encoder parsers.

LLM output frequently uses english operator phrases — "is greater than",
"equals", "is at least" — instead of the canonical symbolic forms.
This module applies a small ordered set of regex rewrites *before* the
parser sees the input, mapping common english forms to ``>``, ``<``,
``>=``, ``<=``, ``==``, ``!=`` (with NULL / 0 specialisations for
non-zero / non-null phrasings).

Design intent:
- Rewrites are *additive*: phrases the per-parser grammar already
  recognises (``is NULL``, ``is writable`` in one-gadget) are NOT
  touched here, so existing parse paths keep their dedicated
  rejection messages.
- Order matters — longer, more-specific phrases are tried before
  shorter ones (``is greater than or equal to`` before ``is greater
  than``).
- Word boundaries (``\\b``) keep rewrites from firing inside
  identifiers (``equalsValue`` must NOT become ``==Value``).

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
_REWRITES: Tuple[Tuple[re.Pattern[str], str], ...] = (
    (re.compile(r'\bis\s+greater\s+than\s+or\s+equal\s+to\b', re.IGNORECASE), ' >= '),
    (re.compile(r'\bis\s+less\s+than\s+or\s+equal\s+to\b',    re.IGNORECASE), ' <= '),
    (re.compile(r'\bis\s+at\s+least\b',                       re.IGNORECASE), ' >= '),
    (re.compile(r'\bis\s+at\s+most\b',                        re.IGNORECASE), ' <= '),
    (re.compile(r'\bis\s+greater\s+than\b',                   re.IGNORECASE), ' > '),
    (re.compile(r'\bis\s+less\s+than\b',                      re.IGNORECASE), ' < '),
    (re.compile(r'\bis\s+not\s+equal\s+to\b',                 re.IGNORECASE), ' != '),
    (re.compile(r'\bdoes\s+not\s+equal\b',                    re.IGNORECASE), ' != '),
    (re.compile(r'\bis\s+equal\s+to\b',                       re.IGNORECASE), ' == '),
    (re.compile(r'\bequals\b',                                re.IGNORECASE), ' == '),
    (re.compile(r'\bis\s+non[-\s]?zero\b',                    re.IGNORECASE), ' != 0 '),
    (re.compile(r'\bis\s+non[-\s]?null\b',                    re.IGNORECASE), ' != NULL '),
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
