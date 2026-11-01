"""Canonical ecosystem names accepted by ``raptor-sca`` (and by OSV).

OSV is case-sensitive: ``PyPI`` works, ``pypi`` returns HTTP 400 — silently
treated as "no advisories" upstream. Always canonicalise user-supplied
ecosystem strings before any registry / OSV call.
"""

from __future__ import annotations


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

# Distro package ecosystems for image-derived rows (base-image layer
# package DBs via ``core.oci.sbom``; never parsed from operator
# manifests, so deliberately NOT in KNOWN_ECOSYSTEMS). OSV indexes
# distro packages by source name. Debian, Ubuntu and Alpine queries
# require release context; the family label alone is not query coverage.
DISTRO_ECOSYSTEM_BASES = ("Alpine", "Debian", "Red Hat", "Ubuntu")


def distro_base(ecosystem: str) -> str | None:
    """Return the distro base name for image-derived ecosystem
    strings (``"Alpine:v3.16"`` → ``"Alpine"``), or ``None`` when
    the ecosystem is not a distro one."""
    base = ecosystem.split(":", 1)[0]
    return base if base in DISTRO_ECOSYSTEM_BASES else None


_LOOKUP = {e.lower(): e for e in KNOWN_ECOSYSTEMS}


def canonicalise(ecosystem: str) -> str | None:
    """Return the canonical ecosystem name, or ``None`` if not recognised.

    Case-insensitive lookup against the known list. Callers SHOULD reject
    unknown ecosystems rather than passing them through to OSV.
    """
    return _LOOKUP.get(ecosystem.lower())


def known_list() -> str:
    """Comma-separated list of known ecosystems for error messages."""
    return ", ".join(sorted(KNOWN_ECOSYSTEMS))
