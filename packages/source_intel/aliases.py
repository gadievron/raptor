"""Curated alias tables for known compiler-attribute macro spellings.

Projects rarely write the literal ``__attribute__((warn_unused_result))`` —
they hide it behind a macro: kernel ``__must_check``, glibc ``__wur``,
C23 ``[[nodiscard]]``, BSD ``__result_use_check``, etc.

This module ships a curated table of known spellings per attribute
family. The cocci rules in ``engine/coccinelle/source_intel/attrs/``
match the literal attribute form; the Python aggregator (``analyze.py``)
augments that by scanning the target for known alias macros and
treating them as the underlying attribute.

A second tier — project-specific alias discovery via header pre-pass —
is planned for the axis-1-expansion PR. The curated table is the v1
baseline.

Public API:
  * ``WUR_ALIASES`` — known warn_unused_result spellings
  * ``alias_match(text)`` — does any known alias appear in `text`?
"""

from __future__ import annotations

import re
from typing import Tuple


#: Known macro / syntax spellings for warn_unused_result. Grouped by
#: origin for documentation; the order is informational only — matching
#: is via the union ``ALL_WUR_ALIASES`` regex below.
WUR_ALIASES_BY_ORIGIN: dict = {
    "literal_gcc": (
        "__attribute__((warn_unused_result))",
        "__attribute__((__warn_unused_result__))",
    ),
    "kernel": (
        "__must_check",
    ),
    "glibc": (
        "__wur",
        "__attribute_warn_unused_result__",
    ),
    "cpp_attribute": (
        "[[nodiscard]]",
        "[[gnu::warn_unused_result]]",
        "[[clang::warn_unused_result]]",
    ),
    "bsd": (
        "__result_use_check",
    ),
}

#: Flat tuple of all WUR alias spellings, used for fast substring checks.
ALL_WUR_ALIASES: Tuple[str, ...] = tuple(
    spelling
    for spellings in WUR_ALIASES_BY_ORIGIN.values()
    for spelling in spellings
)


# Regex compiled once at module load — the alias spellings include
# punctuation that must be escaped before union into a pattern.
_WUR_PATTERN = re.compile(
    "|".join(re.escape(s) for s in ALL_WUR_ALIASES)
)


def wur_alias_in(text: str) -> bool:
    """Return True iff any known WUR alias spelling appears in ``text``.

    This is a fast substring/regex check — it does NOT verify that
    the alias was applied to a specific identifier or position. For
    that, source_intel's cocci rules give precise file/line positions;
    this helper is for header-discovery (does THIS header define a
    project alias) and rule-emission filtering.
    """
    return bool(_WUR_PATTERN.search(text))


def wur_alias_origin(spelling: str) -> str:
    """Classify a WUR alias by origin family. Returns one of:

      * ``"literal_gcc"`` — direct GCC attribute syntax
      * ``"kernel"`` — Linux kernel convention
      * ``"glibc"`` — GNU libc convention
      * ``"cpp_attribute"`` — C++11/C23 attribute syntax
      * ``"bsd"`` — BSD lineage
      * ``"unknown"`` — not in the curated table

    Used by ``analyze.py`` to record provenance: literal observations
    have higher confidence than alias-matched observations.
    """
    for origin, spellings in WUR_ALIASES_BY_ORIGIN.items():
        if spelling in spellings:
            return origin
    return "unknown"
