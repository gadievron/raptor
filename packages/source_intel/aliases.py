"""Curated alias tables for known compiler-attribute macro spellings.

Projects rarely write the literal ``__attribute__((warn_unused_result))`` —
they hide it behind a macro: kernel ``__must_check``, glibc ``__wur``,
C23 ``[[nodiscard]]``, BSD ``__result_use_check``, etc.

This module ships a curated table of known spellings per attribute
family. The cocci rules in ``engine/coccinelle/source_intel/attrs/``
match the literal attribute form; the Python aggregator (``analyze.py``)
augments that by scanning the target for known alias macros and
treating them as the underlying attribute.

Project-specific alias discovery in ``discovery.py`` supplements this
curated table with a bounded header pre-pass.

Public API:
  * ``WUR_ALIASES_BY_ORIGIN`` — spellings grouped by origin
  * ``ALL_WUR_ALIASES`` — the flattened spellings
  * ``wur_alias_in(text)`` — does any known spelling appear in ``text``?
  * ``wur_alias_origin(spelling)`` — look up a spelling's origin
"""

from __future__ import annotations

import re


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
ALL_WUR_ALIASES: tuple[str, ...] = tuple(
    spelling
    for spellings in WUR_ALIASES_BY_ORIGIN.values()
    for spelling in spellings
)


# Regex compiled once at module load — the alias spellings include
# punctuation that must be escaped before union into a pattern.
_WUR_PATTERN = re.compile(
    "|".join(
        r"(?<![A-Za-z0-9_])" + re.escape(s) + r"(?![A-Za-z0-9_])"
        if s.isidentifier() else re.escape(s)
        for s in ALL_WUR_ALIASES
    )
)


def wur_alias_in(text: str) -> bool:
    """Return True iff any known WUR alias spelling appears in ``text``.

    Identifier aliases require ASCII identifier boundaries; literal
    attribute syntax is matched as a substring. This raw-text helper
    does not check comments, strings, declaration binding or positions.
    A match alone does not establish an annotated declaration.
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
