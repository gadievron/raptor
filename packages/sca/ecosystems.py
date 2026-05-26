"""Canonical ecosystem names accepted by ``raptor-sca`` (and by OSV).

OSV is case-sensitive: ``PyPI`` works, ``pypi`` returns HTTP 400 — silently
treated as "no advisories" upstream. Always canonicalise user-supplied
ecosystem strings before any registry / OSV call.
"""

from __future__ import annotations

from typing import Optional

KNOWN_ECOSYSTEMS = (
    "PyPI", "npm", "Maven", "Cargo", "Go",
    "RubyGems", "NuGet", "Packagist",
    # C/C++ ecosystems (C14):
    "vcpkg", "ConanCenter",
    # ``OSS-Fuzz`` is a fallback ecosystem for C/C++ deps where the
    # primary (vcpkg / ConanCenter / GitHub) returns no advisories.
    # OSV indexes ~700 widely-used C/C++ projects under this
    # ecosystem; ``packages.sca.osv`` retries empty C/C++ queries
    # against it transparently.
    "OSS-Fuzz",
    # CI / build pipelines:
    "GitHub Actions",
)

_LOOKUP = {e.lower(): e for e in KNOWN_ECOSYSTEMS}


def canonicalise(ecosystem: str) -> Optional[str]:
    """Return the canonical ecosystem name, or ``None`` if not recognised.

    Case-insensitive lookup against the known list. Callers SHOULD reject
    unknown ecosystems rather than passing them through to OSV.
    """
    return _LOOKUP.get(ecosystem.lower())


def known_list() -> str:
    """Comma-separated list of known ecosystems for error messages."""
    return ", ".join(sorted(KNOWN_ECOSYSTEMS))
