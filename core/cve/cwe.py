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
from typing import Optional


# Matches CWE-N shapes we accept: ``CWE-121``, ``cwe-121``, ``cwe121``,
# ``CWE121``, ``CWE 121`` (SARIF sometimes emits a space separator),
# ``cwe_121`` (underscore variant), with tolerated leading/trailing
# whitespace. Rejects empty / non-numeric / malformed.
_CWE_RE = re.compile(r"^\s*cwe[-_\s]?(\d+)\s*$", re.IGNORECASE)


def canonicalize_cwe(raw: Optional[str]) -> Optional[str]:
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


def cwe_dir_slug(raw: Optional[str]) -> Optional[str]:
    """Return ``"cwe-N"`` (lowercase) suitable for filenames / dirs.

    Same accept-set as :func:`canonicalize_cwe`; returns ``None`` on
    invalid input.
    """
    canon = canonicalize_cwe(raw)
    if canon is None:
        return None
    return canon.lower()


def format_cwe(number) -> Optional[str]:
    """Format a pure CWE number as the canonical ``"CWE-N"`` string.

    Companion to :func:`canonicalize_cwe` for producers that already
    extracted a numeric CWE ID from surrounding context (SARIF taxa
    URIs, tag substrings, JSON integers) and just need the canonical
    spelling. Consolidating the ``f"CWE-{n}"`` hand-rolls means a
    future spelling change (zero-padding, prefix variant) touches
    one place.

    Accepts ``int`` (positive), ``str`` (digits only), or an object
    that ``int()`` accepts. Returns ``None`` on non-integers,
    negatives, or zero.
    """
    if number is None:
        return None
    try:
        n = int(str(number).strip())
    except (TypeError, ValueError):
        return None
    if n <= 0:
        return None
    return f"CWE-{n}"


__all__ = ["canonicalize_cwe", "cwe_dir_slug", "format_cwe"]
