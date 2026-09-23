"""One normalisation grammar for CWE-derived decision-class strings.

The ``audit:<CWE>`` decision classes have multiple writers (the
/validate Reflexion feedback importer, the offline corpus harness) and
one calibrated reader (``core.audit.calibrated_merge``). The reader
regex-extracts ``CWE-\\d+`` precisely because journal / LLM-derived CWE
text routinely carries suffixes (``"CWE-89: SQL Injection"``,
``"CWE-79 (XSS)"``) and mixed case — a writer that mints from the raw
string creates cells the reliability-weight query can never join, so
the merge silently stays prior-dominated at 0.5.

This module is the single grammar both sides share. It lives under
``core/llm/scorecard`` (not ``core/audit``) because the layering runs
consumers → core.llm: the audit-side reader may import from here; a
core/llm producer must not import ``core.audit``.
"""

from __future__ import annotations

import re

# Case-insensitive: journal rows and LLM output spell "cwe-89" too;
# the canonical rendering is upper case.
CWE_RE = re.compile(r"CWE-\d+", re.IGNORECASE)

# Keep in sync with core.audit.calibrated_merge.DEFAULT_DECISION_CLASS
# (that module imports from here; the literal is duplicated only in
# its own constant definition).
_DEFAULT_AUDIT_DECISION_CLASS = "audit:review"


def extract_cwe(text: object) -> str | None:
    """First ``CWE-<n>`` tag in *text*, canonicalised to upper case.

    ``None`` when *text* is empty or carries no CWE tag. Accepts any
    value (str-coerced) — callers feed journal / report fields whose
    types are not guaranteed.
    """
    if text is None:
        return None
    m = CWE_RE.search(str(text))
    return m.group(0).upper() if m else None


def audit_decision_class(cwe: object) -> str:
    """The ``audit:<CWE>`` decision class for a CWE-ish string,
    normalised to the exact key the calibrated-merge reader derives
    (``audit:CWE-89`` — suffix text and case stripped). Falls back to
    the catch-all audit review class when no CWE tag is present:
    that is the same key the reader falls back to, so garbage CWE
    text still lands in a joinable cell instead of minting an
    orphan."""
    tag = extract_cwe(cwe)
    if tag:
        return f"audit:{tag}"
    return _DEFAULT_AUDIT_DECISION_CLASS


__all__ = ["CWE_RE", "audit_decision_class", "extract_cwe"]
