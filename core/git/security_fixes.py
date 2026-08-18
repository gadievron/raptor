"""Shared security-fix commit-message classification.

Extracted from ``core.audit.git_oracle`` (which consumed it for
corroboration-only git-history context) so every consumer that needs to
recognise "this commit message describes a security fix" shares ONE
vocabulary: the audit oracle today; churn prioritization and SCA
patch-presence probes tomorrow.

The pattern set is DATA — a tuple of ``(regex, category)`` pairs — so a
new consumer extends it (or filters it) without forking the matching
logic.  Matching is case-insensitive ``re.search`` over whatever text
the caller supplies (subject line, subject+body, PR title, ...).

SCOPE NOTE: this is heuristic commit-MESSAGE classification, suitable
for corroboration / prioritisation signals only.  It is NOT how the
dataflow harvesters select fix commits — ``core.dataflow.ghsa_harvester``
and ``cvefix_walk`` are advisory-driven (explicit fix-commit references
from GHSA / CVEfixes metadata), which is deliberately stronger than any
message heuristic and must stay that way.
"""

from __future__ import annotations

import re

# Security-fix vocabulary.  Each entry is ``(python_regex, category)``;
# categories surface to consumers (e.g. the audit oracle's
# ``matched_patterns`` journal field), and the regex union feeds
# ``git log --grep -i -E`` prefilters.  Category names are part of the
# journal/report surface — treat renames as breaking.
SECURITY_FIX_PATTERNS: tuple[tuple[str, str], ...] = (
    (r"CVE-[0-9]{4}-[0-9]+", "cve"),
    (r"overflow", "overflow"),
    (r"underflow", "underflow"),
    (r"use[- ]after[- ]free", "use_after_free"),
    (r"double[- ]free", "double_free"),
    (r"out[- ]of[- ]bounds", "out_of_bounds"),
    (r"null (pointer )?deref", "null_deref"),
    (r"uninitial[a-z]*", "uninitialized"),
    (r"security", "security"),
    (r"saniti[sz]", "sanitize"),
    (r"injection", "injection"),
    (r"vulnerab", "vulnerability"),
    (r"exploit", "exploit"),
    (r"race condition|toctou", "race_condition"),
    (r"memory (corruption|safety)", "memory_corruption"),
    (r"bounds check", "bounds_check"),
)

# Union regex for ``git log --grep=<union> -i -E`` prefilters — one
# subprocess-side pass instead of N python-side scans.
GREP_UNION: str = "|".join(p for p, _category in SECURITY_FIX_PATTERNS)

_COMPILED: tuple[tuple[re.Pattern, str], ...] = tuple(
    (re.compile(pattern, re.IGNORECASE), category)
    for pattern, category in SECURITY_FIX_PATTERNS
)


def match_categories(message: str) -> tuple[str, ...]:
    """Every category whose pattern matches ``message``, in declaration
    order.  Empty tuple when nothing matches (or message is falsy)."""
    if not message:
        return ()
    return tuple(cat for rx, cat in _COMPILED if rx.search(message))


def classify(message: str) -> str | None:
    """First matching category (declaration order — most-specific
    patterns like ``cve`` are declared first), or ``None``."""
    if not message:
        return None
    for rx, cat in _COMPILED:
        if rx.search(message):
            return cat
    return None


def is_security_fix(subject_or_message: str) -> bool:
    """True when the text matches any security-fix pattern."""
    return classify(subject_or_message) is not None


__all__ = [
    "GREP_UNION",
    "SECURITY_FIX_PATTERNS",
    "classify",
    "is_security_fix",
    "match_categories",
]
