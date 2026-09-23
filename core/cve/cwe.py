"""Shared CWE identifier normalisation.

CWE identifiers arrive in the wild in half a dozen spellings:
``CWE-121``, ``cwe121``, ``CWE 121`` (SARIF taxa URI form), ``cwe_121``
(some SCA producers). Consumers that filter or route findings by CWE
need a canonical spelling before comparison.

  * :func:`canonicalize_cwe`: loose input → ``"CWE-N"`` (uppercase).
    Returns ``None`` on invalid input.
  * :func:`cwe_dir_slug`: loose input → ``"cwe-N"`` (lowercase),
    suitable for filenames / directory names.
  * :func:`format_cwe`: pure numeric CWE ID → ``"CWE-N"``. For
    producers that already extracted a bare number from SARIF taxa
    URIs, tag substrings, or JSON integers.
"""

from __future__ import annotations

import re


# Matches CWE-N shapes we accept: ``CWE-121``, ``cwe-121``, ``cwe121``,
# ``CWE121``, ``CWE 121`` (SARIF sometimes emits a space separator),
# ``cwe_121`` (underscore variant), with tolerated leading/trailing
# whitespace. Rejects empty / non-numeric / malformed. ``re.ASCII``
# pins ``\d``/``\s`` to ASCII (keep in sync with the epss /
# vulnrichment id regexes): non-ASCII decimal digits pass an un-pinned
# ``\d``, so two spellings of one CWE would fail to join for routing /
# filtering and the slug helper would mint non-ASCII directory names.
_CWE_RE = re.compile(r"^\s*cwe[-_\s]?(\d+)\s*$", re.IGNORECASE | re.ASCII)

# ASCII-digits-only gate for :func:`format_cwe`'s string lane —
# ``int()`` itself accepts Unicode digits, which would mint the
# canonical spelling from inputs :func:`canonicalize_cwe` refuses.
_ASCII_NUM_RE = re.compile(r"^\s*-?\d+\s*$", re.ASCII)


def canonicalize_cwe(raw: str | None) -> str | None:
    """Return ``"CWE-N"`` (uppercase) for a CWE identifier.

    ``None`` / empty / non-CWE input → ``None``. Callers that need a
    fallback placeholder should check for ``None`` at the call site
    rather than relying on this helper to invent one.
    """
    if not raw:
        return None
    m = _CWE_RE.match(str(raw))
    if not m:
        return None
    return f"CWE-{m.group(1)}"


def cwe_dir_slug(raw: str | None) -> str | None:
    """Return ``"cwe-N"`` (lowercase) suitable for filenames / dirs.

    Same accept-set as :func:`canonicalize_cwe`; returns ``None`` on
    invalid input.
    """
    canon = canonicalize_cwe(raw)
    if canon is None:
        return None
    return canon.lower()


def format_cwe(number) -> str | None:
    """Format a pure CWE number as the canonical ``"CWE-N"`` string.

    Companion to :func:`canonicalize_cwe` for producers that already
    extracted a numeric CWE ID from surrounding context (SARIF taxa
    URIs, tag substrings, JSON integers) and just need the canonical
    spelling. Consolidating the ``f"CWE-{n}"`` hand-rolls means a
    future spelling change (zero-padding, prefix variant) touches
    one place.

    Accepts ``int`` (positive), ``str`` (ASCII digits only — Unicode
    digits are refused for parity with :func:`canonicalize_cwe`, even
    though ``int()`` would coerce them), or an object that ``int()``
    accepts. Returns ``None`` on non-integers, negatives, or zero.
    """
    if number is None:
        return None
    if isinstance(number, str) and _ASCII_NUM_RE.match(number) is None:
        return None
    try:
        n = int(str(number).strip())
    except (TypeError, ValueError):
        return None
    if n <= 0:
        return None
    return f"CWE-{n}"


__all__ = ["canonicalize_cwe", "cwe_dir_slug", "format_cwe"]
