"""Release identities used by distro advisory feeds.

An OS family is not sufficient evidence that a release-specific fix applies.
Keep Ubuntu's standard and Pro/FIPS streams distinct; do not infer a parent
release from ID_LIKE on a derivative distribution.
"""
from __future__ import annotations

import re

_DEBIAN_SUITES = {
    "sid": "sid", "wheezy": "7", "jessie": "8", "stretch": "9", "buster": "10",
    "bullseye": "11", "bookworm": "12", "trixie": "13", "forky": "14",
}
_UBUNTU_SUITES = {
    "trusty": "14.04", "xenial": "16.04", "bionic": "18.04",
    "focal": "20.04", "jammy": "22.04", "noble": "24.04",
    "plucky": "25.04", "questing": "25.10", "resolute": "26.04",
}
_UBUNTU_LTS = frozenset({"10.04", "12.04", "14.04", "16.04", "18.04",
                         "20.04", "22.04", "24.04", "26.04"})


def release_ecosystem(family: str, release: str) -> str | None:
    """Resolve explicit release metadata, returning None for unknown context."""
    if family == "Debian":
        release = _DEBIAN_SUITES.get(release, release)
        if release == "sid":
            return "Debian:sid"
        match = re.fullmatch(r"([1-9][0-9]?)(?:\.[0-9]+)*", release)
        return f"Debian:{match[1]}" if match else None
    if family == "Ubuntu":
        release = _UBUNTU_SUITES.get(release, release)
        match = re.fullmatch(r"([0-9]{2}\.(?:04|10))(?:\.[0-9]+)*", release)
        if not match:
            return None
        version = match[1]
        # Future even-year .04 releases need an explicit LTS decision rather
        # than silently querying the wrong OSV stream.
        if int(version[:2]) % 2 == 0 and version.endswith(".04"):
            return f"Ubuntu:{version}:LTS" if version in _UBUNTU_LTS else None
        return f"Ubuntu:{version}"
    if family == "Alpine":
        match = re.fullmatch(r"v?([0-9]+\.[0-9]+)(?:\.[0-9]+)*", release)
        return f"Alpine:v{match[1]}" if match else None
    return None


def context_error(ecosystem: str, version: str | None = None) -> str | None:
    """Explain why a package cannot safely enter a release-scoped query."""
    family, _, release = ecosystem.partition(":")
    if family in {"Debian", "Ubuntu", "Alpine"}:
        if not release:
            return f"{family} release is unknown; release-specific advisory coverage is unavailable"
        if family == "Debian" and not re.fullmatch(r"(?:[1-9][0-9]?|sid)", release):
            return "invalid Debian advisory release"
        if family == "Alpine" and not re.fullmatch(r"v[0-9]+\.[0-9]+", release):
            return "invalid Alpine advisory release"
        if family == "Ubuntu":
            # Pro/FIPS streams must be explicitly supplied, never inferred
            # from a standard Ubuntu image's numeric VERSION_ID.
            match = re.fullmatch(r"(?:Pro:(?:FIPS(?:-updates)?:)?)?([0-9]{2}\.(?:04|10))(?::LTS)?", release)
            if not match or (release.endswith(":LTS") != (match[1] in _UBUNTU_LTS)):
                return "invalid or unknown Ubuntu advisory stream"
    if family in {"Debian", "Ubuntu"} and version:
        foreign = re.search(r"nodesource[0-9]+\Z", version, re.IGNORECASE)
        if family == "Debian":
            foreign = foreign or re.search(r"ubuntu[^\s]*\Z", version, re.IGNORECASE)
        if foreign:
            return f"package version identifies a foreign vendor; {family} advisory coverage cannot be assumed"
    return None


def ecosystem_matches(query: str, affected: str) -> bool:
    """Match a package's release to an affected block without merging streams."""
    if query == affected:
        return True
    family, _, release = query.partition(":")
    # Debian permits explicitly release-independent affected blocks. Ubuntu
    # and Alpine feeds require release context; a missing suffix is not proof.
    return family == "Debian" and bool(release) and affected == "Debian"
