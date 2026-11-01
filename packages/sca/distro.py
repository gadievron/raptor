"""Project distro inventory rows onto explicit advisory coordinates.

Inventory names, versions and PURLs remain untouched. Only the query view
uses the PURL upstream qualifier to identify the source package. No source
lookup, registry access or binary-to-source inference is performed here.
"""
from __future__ import annotations

from dataclasses import replace
import re
import urllib.parse
from typing import TYPE_CHECKING

from core.oci.distro import context_error, release_ecosystem

if TYPE_CHECKING:
    from .models import Dependency


def advisory_dependency(dep: Dependency, *, require_context: bool = True) -> Dependency:
    """Return a source/release query view; raise ValueError on ambiguity.

    Display callers may retain legacy unscoped identities; actual lookups
    always require release context.
    """
    family = dep.ecosystem.split(":", 1)[0]
    if family not in {"Debian", "Ubuntu", "Alpine"}:
        return dep
    ecosystem, name, version = dep.ecosystem, dep.name, dep.version
    if dep.purl.startswith(("pkg:deb/", "pkg:apk/")):
        expected = "pkg:apk/" if family == "Alpine" else "pkg:deb/"
        if not dep.purl.startswith(expected):
            raise ValueError("distro PURL type conflicts with advisory ecosystem")
        if re.search(r"%(?![0-9A-Fa-f]{2})", dep.purl):
            raise ValueError("malformed distro PURL encoding")
        path = dep.purl.split("/", 1)[1].split("?", 1)[0].split("#", 1)[0]
        namespace = urllib.parse.unquote(path.split("/", 1)[0], errors="strict").lower() if "/" in path else ""
        allowed = {"Debian": {"", "debian"}, "Ubuntu": {"", "ubuntu"}, "Alpine": {"", "alpine"}}[family]
        if namespace not in allowed:
            raise ValueError("distro PURL namespace conflicts with advisory origin")
        query = dep.purl.partition("#")[0].partition("?")[2]
        qualifiers = urllib.parse.parse_qs(query, keep_blank_values=True,
                                         strict_parsing=True, max_num_fields=64, errors="strict")
        if any(len(v) != 1 for v in qualifiers.values()):
            raise ValueError("ambiguous distro PURL qualifiers")
        distro = qualifiers.get("distro", [""])[0].lower()
        if distro:
            release = distro.removeprefix(family.lower() + "-")
            resolved = release_ecosystem(family, release)
            if resolved is None:
                raise ValueError("unknown distro PURL release")
            if ":" in ecosystem and resolved != ecosystem:
                raise ValueError("conflicting distro release metadata")
            ecosystem = resolved
        # Source qualifiers encode source-name or source-name@source-version.
        # When the source version is absent, the package asserts the same
        # version (Debian's unversioned Source field semantics).
        upstream = qualifiers.get("upstream", [""])[0]
        if "upstream" in qualifiers:
            if not upstream:
                raise ValueError("invalid distro upstream qualifier")
            source, separator, source_version = upstream.partition("@")
            source_pattern = r"[a-z0-9][a-z0-9+_.-]*" if family == "Alpine" else r"[a-z0-9][a-z0-9+.-]*"
            if not re.fullmatch(source_pattern, source):
                raise ValueError("invalid distro source package name")
            version_pattern = r"[0-9][A-Za-z0-9.+:~_\-]*" if family == "Alpine" else r"[0-9][A-Za-z0-9.+:~\-]*"
            if separator and (len(source_version) > 4096 or not re.fullmatch(version_pattern, source_version)):
                raise ValueError("invalid distro source package version")
            name = source
            if separator:
                version = source_version
    if require_context or ":" in ecosystem:
        package_pattern = r"[a-z0-9][a-z0-9+_.-]*" if family == "Alpine" else r"[a-z0-9][a-z0-9+.-]*"
        if not re.fullmatch(package_pattern, name):
            raise ValueError("invalid distro source package name")
    if version is not None and (require_context or ":" in ecosystem):
        pattern = r"[0-9][A-Za-z0-9.+:~_\-]*" if family == "Alpine" else r"[0-9][A-Za-z0-9.+:~\-]*"
        if len(version) > 4096 or not re.fullmatch(pattern, version):
            raise ValueError("invalid distro source version")
        if family in {"Debian", "Ubuntu"}:
            upstream_version = version.partition(":")[2] if ":" in version else version
            if not upstream_version or upstream_version[0] not in "0123456789" or upstream_version.endswith("-"):
                raise ValueError("invalid distro source version")
        from .versions import compare
        compare(ecosystem, version, version)
    error = context_error(ecosystem, dep.version) or context_error(ecosystem, version)
    if error and (require_context or ":" in ecosystem):
        raise ValueError(error)
    return replace(dep, ecosystem=ecosystem, name=name, version=version)


def has_source_coordinates(purl: str) -> bool:
    """Whether the PURL explicitly supplies a source identity (not its licence)."""
    try:
        values = urllib.parse.parse_qs(purl.partition("#")[0].partition("?")[2],
                                      strict_parsing=True, max_num_fields=64, errors="strict")
    except (ValueError, UnicodeError):
        return False
    return bool(values.get("upstream", [""])[0]) or values.get("arch") == ["source"]
