"""CWE family mapper for cross-CWE rule replay.

Groups CWEs that plausibly share syntactic patterns — a Semgrep rule
for ``cursor.execute(f"...")`` catches both CWE-89 and CWE-564, so
the library should replay it for either.

Only maps families where a single Semgrep/Coccinelle rule could
realistically match across the group.  Two CWEs being related in the
CWE hierarchy (e.g. CWE-120 and CWE-416 are both memory bugs) does
NOT mean they share syntactic patterns.
"""

from __future__ import annotations

_FAMILIES: dict[str, list[str]] = {
    "sql_injection": ["CWE-89", "CWE-564", "CWE-943"],
    "xss": ["CWE-79", "CWE-80", "CWE-83", "CWE-87"],
    "command_injection": ["CWE-77", "CWE-78", "CWE-88"],
    "path_traversal": ["CWE-22", "CWE-23", "CWE-36"],
    "buffer_overflow": ["CWE-120", "CWE-121", "CWE-122", "CWE-787"],
    "integer_overflow": ["CWE-190", "CWE-191", "CWE-680"],
    "use_after_free": ["CWE-415", "CWE-416"],
    "null_deref": ["CWE-476"],
    "format_string": ["CWE-134"],
    "deserialization": ["CWE-502"],
    "ssrf": ["CWE-918"],
    "xxe": ["CWE-611"],
    "open_redirect": ["CWE-601"],
    "info_disclosure": ["CWE-200", "CWE-209"],
}

_CWE_TO_FAMILY: dict[str, str] = {}
for _fam, _cwes in _FAMILIES.items():
    for _cwe in _cwes:
        _CWE_TO_FAMILY[_cwe] = _fam


def cwe_family(cwe: str) -> str:
    """Return the family name for a CWE, or the CWE itself if unmapped."""
    return _CWE_TO_FAMILY.get(cwe, cwe)


def cwe_siblings(cwe: str) -> list[str]:
    """Return all CWEs in the same family (including the input).

    Unmapped CWEs return a single-element list of themselves.
    """
    family = _CWE_TO_FAMILY.get(cwe)
    if family is None:
        return [cwe]
    return list(_FAMILIES[family])
