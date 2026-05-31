"""Parse ``Directory.Packages.props`` — NuGet's Central Package
Management (CPM) version manifest.

Background
~~~~~~~~~~

Starting with .NET 6 / NuGet 6.2 (2022), Microsoft introduced CPM
to centralise package versions across an entire .NET solution.
Modern .NET projects (ASP.NET Core, EF Core, the dotnet/runtime
repo itself, most enterprise codebases since 2022) flip the
``<PackageReference>`` shape:

  - Pre-CPM csproj:
      ``<PackageReference Include="X" Version="1.2.3" />``
  - CPM csproj (no version):
      ``<PackageReference Include="X" />``
  - CPM-enabled ``Directory.Packages.props``:
      ``<PackageVersion Include="X" Version="1.2.3" />``

Without CPM support, SCA misses ~80-100% of dep coverage on any
modern .NET solution. This module is the read-side fix; the
sibling rewriter at ``packages/sca/bump/rewriters/directory_packages_props``
handles the write-side for bumper / harden.

File semantics that matter for the parser
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

1. **Three elements we read**:
   * ``<PackageVersion Include="X" Version="1.2.3" />`` — main CPM
     declaration. One per centrally-managed dep.
   * ``<GlobalPackageReference Include="X" Version="1.2.3" />`` —
     forcibly included in every csproj in the solution. Tools like
     ``Microsoft.SourceLink.GitHub`` are typically here.
   * ``<ManagePackageVersionsCentrally>`` property — defaults
     ``true`` when ``Directory.Packages.props`` is present. Setting
     it to ``false`` disables CPM even with the file present
     (operators sometimes do this during migration).

2. **Hierarchical inheritance** is handled at the csproj-resolution
   layer, not here. This module parses ONE file. The csproj parser
   walks up the directory tree calling this module for each
   ``Directory.Packages.props`` found, merging maps with
   innermost-wins precedence.

3. **VersionOverride** lives on csproj's ``<PackageReference>``, not
   here. Same comment as above — this module handles one file.

4. **MSBuild expressions** in the Version attribute
   (``Version="$(MyVersion)"``) are NOT resolved. Property
   expansion would require evaluating ``<PropertyGroup>`` blocks
   and inheriting from ``Directory.Build.props``. We log a debug
   note and skip the entry; the csproj falls through to the "no
   resolvable version" path.

Defusedxml dependency
~~~~~~~~~~~~~~~~~~~~~

Same posture as ``parsers/nuget.py`` and ``parsers/pom.py``:
target-repo XML is attacker-controlled, so XXE / billion-laughs
defense is required. The module refuses to parse without
defusedxml installed, logging a single warning at import time.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional
from xml.etree import ElementTree as _ET

from core.security.log_sanitisation import escape_nonprintable

from . import _safe_read

logger = logging.getLogger(__name__)


try:
    from defusedxml.ElementTree import fromstring as _safe_fromstring
    _AVAILABLE = True
except ImportError:                                 # pragma: no cover
    _safe_fromstring = None                         # type: ignore[assignment]
    _AVAILABLE = False
    logger.warning(
        "sca.parsers.directory_packages_props: 'defusedxml' not "
        "installed — Directory.Packages.props files will be skipped. "
        "`pip install defusedxml` to enable NuGet CPM support.",
    )


# MSBuild expression — covers all three forms ``$(...)`` properties,
# ``@(...)`` item references, and ``%(...)`` well-known-metadata.
# When the Version attribute contains any of these we can't resolve
# the version without evaluating MSBuild's full property/item graph
# (PropertyGroup blocks + Directory.Build.props inheritance + tool-
# conditional properties). Skip those entries rather than emit a
# wrong (or attacker-tainted) version string.
_MSBUILD_PROPERTY_RE = re.compile(r"[\$@%]\([^)]+\)")

# A single ``$(Name)`` property reference. We resolve these against properties
# defined IN THE SAME FILE — the dominant pre-CPM pattern, where a
# Directory.Build.targets sets ``<ExtensionsVersion>3.1.0</>`` in a
# PropertyGroup and uses it as ``Version="$(ExtensionsVersion)"``. Cross-file
# inheritance and ``@(...)`` / ``%(...)`` item/metadata expressions are still
# left unresolved (skipped), as is a floating wildcard like ``3.1.0-*``.
_PROP_REF_RE = re.compile(r"\$\(([A-Za-z_][\w.\-]*)\)")
_MAX_PROP_DEPTH = 8


def _extract_properties(root) -> "Dict[str, str]":
    """Collect ``<PropertyGroup>`` properties (name → text) from one file.
    Conditions are ignored and later definitions win — an approximation of
    MSBuild evaluation that's correct for the unconditional central-version
    files this matters for."""
    props: Dict[str, str] = {}
    for prop_group in _findall_local(root, "PropertyGroup"):
        for el in prop_group:
            text = (el.text or "").strip()
            if text:
                props[_strip_namespace(el.tag).lower()] = text
    return props


def _resolve_property_version(
    version: str, props: "Dict[str, str]", _depth: int = 0,
) -> Optional[str]:
    """Substitute ``$(Prop)`` tokens in ``version`` from same-file ``props``
    (recursive, capped). Returns a concrete version, or ``None`` if anything
    MSBuild-expression-shaped survives (cross-file / item / metadata) or the
    result is a floating wildcard (``*``) — neither is a pinnable version."""
    if _depth > _MAX_PROP_DEPTH:
        return None
    resolved = _PROP_REF_RE.sub(
        lambda m: props.get(m.group(1).lower(), m.group(0)), version,
    )
    if resolved != version and "$(" in resolved:
        deeper = _resolve_property_version(resolved, props, _depth + 1)
        resolved = deeper if deeper is not None else resolved
    if resolved is None or _MSBUILD_PROPERTY_RE.search(resolved) or "*" in resolved:
        return None
    return resolved


@dataclass(frozen=True)
class CentralPackage:
    """One ``<PackageVersion>`` or ``<GlobalPackageReference>`` entry.

    ``is_global`` distinguishes the two shapes — ``GlobalPackageReference``
    entries are auto-included in every csproj in the solution (the
    bumper has to surface this when proposing a version change so
    operators know the change has solution-wide blast radius).
    """

    name: str
    version: str
    is_global: bool = False
    declared_in: Optional[Path] = None


@dataclass(frozen=True)
class CPMFile:
    """Parsed view of one ``Directory.Packages.props`` file."""

    path: Path
    # True iff ``<ManagePackageVersionsCentrally>`` is unset OR
    # set to ``true``. False explicitly disables CPM even when
    # the file exists — operators sometimes do this during
    # mid-migration. The csproj resolver must honour this.
    cpm_enabled: bool
    # All ``<PackageVersion>`` + ``<GlobalPackageReference>``
    # entries. Order preserved — useful for diff-friendly
    # bumper rewrites later.
    packages: List[CentralPackage] = field(default_factory=list)

    def version_map(self) -> Dict[str, str]:
        """Flat ``{package_name_lower: version}`` map. NuGet is
        case-insensitive on package names; lowercase keys so the
        csproj resolver doesn't need to repeat the normalisation."""
        return {p.name.lower(): p.version for p in self.packages}

    def global_packages(self) -> List[CentralPackage]:
        """Subset that's ``<GlobalPackageReference>`` — auto-applied
        to every csproj. The csproj resolver should emit these as
        Dependency rows for every csproj, not just those that
        explicitly reference them."""
        return [p for p in self.packages if p.is_global]


# Per-process cache of parsed files. A solution can have 100+
# csproj all walking up to the same ``Directory.Packages.props``.
# Cache keyed by resolved absolute path so identical files
# (rare, but possible in symlinked monorepos) don't get re-parsed.
_PARSE_CACHE: Dict[Path, Optional[CPMFile]] = {}


def parse_directory_packages_props(path: Path) -> Optional[CPMFile]:
    """Parse one ``Directory.Packages.props`` file.

    Returns ``None`` when:
      * ``defusedxml`` isn't installed (logged at module-import).
      * The file can't be read (logged at WARNING).
      * The XML is malformed (logged at WARNING).
      * The file isn't a recognisable Directory.Packages.props
        (no ``<Project>`` root). Logged at DEBUG to avoid noise
        on operators who keep similarly-named files in their
        tree.

    Per-process cached on resolved absolute path so a solution
    walking 100 csproj that all inherit one CPM file pays one
    parse cost.
    """
    if not _AVAILABLE:
        return None
    try:
        resolved = path.resolve()
    except OSError:
        return None
    if resolved in _PARSE_CACHE:
        return _PARSE_CACHE[resolved]
    text = _safe_read.read_bounded(resolved, follow_symlinks=False)
    if text is None:
        # ``read_bounded`` already logged the underlying reason at
        # warning level (oversize / symlink / vanished / …).
        _PARSE_CACHE[resolved] = None
        return None
    try:
        root = _safe_fromstring(text)
    except _ET.ParseError as e:
        logger.warning(
            "sca.parsers.directory_packages_props: invalid XML in %s: %s",
            escape_nonprintable(str(resolved)),
            escape_nonprintable(str(e)),
        )
        _PARSE_CACHE[resolved] = None
        return None

    # Root must be ``<Project>`` (with or without xmlns). MSBuild
    # files namespace-strip in SDK-style format; older formats
    # carry ``xmlns="http://schemas.microsoft.com/developer/msbuild/2003"``.
    tag = _strip_namespace(root.tag)
    if tag != "Project":
        logger.debug(
            "sca.parsers.directory_packages_props: %s root is %r "
            "(expected 'Project'); skipping",
            resolved, tag,
        )
        _PARSE_CACHE[resolved] = None
        return None

    cpm_enabled = _extract_cpm_enabled(root)
    packages = _extract_package_versions(root, declared_in=resolved)
    cpm_file = CPMFile(
        path=resolved, cpm_enabled=cpm_enabled, packages=packages,
    )
    _PARSE_CACHE[resolved] = cpm_file
    return cpm_file


def _extract_cpm_enabled(root) -> bool:
    """Read ``<ManagePackageVersionsCentrally>`` from PropertyGroup
    blocks. Defaults to ``True`` when Directory.Packages.props
    exists (MSBuild's documented default).

    Multiple ``<PropertyGroup>`` blocks are allowed in MSBuild;
    last-wins is the convention. We walk in document order and
    take the LAST occurrence of the property, matching MSBuild
    semantics.

    Value parsing is case-insensitive: ``true`` / ``True`` /
    ``TRUE`` all enable; ``false`` disables. Unrecognised values
    log a debug note and default to enabled (matching MSBuild's
    behaviour of treating malformed booleans as the default).
    """
    enabled = True
    for prop_group in _findall_local(root, "PropertyGroup"):
        for child in prop_group:
            if _strip_namespace(child.tag) != "ManagePackageVersionsCentrally":
                continue
            text = (child.text or "").strip().lower()
            if text in ("true", ""):
                enabled = True
            elif text == "false":
                enabled = False
            else:
                logger.debug(
                    "sca.parsers.directory_packages_props: "
                    "unrecognised <ManagePackageVersionsCentrally> "
                    "value %r; defaulting to enabled",
                    escape_nonprintable(text),
                )
                enabled = True
    return enabled


def _extract_package_versions(
    root, *, declared_in: Path,
) -> List[CentralPackage]:
    """Walk every ``<ItemGroup>`` for ``<PackageVersion>`` /
    ``<GlobalPackageReference>``. MSBuild lets either tag live in
    any ItemGroup; we don't enforce a single ItemGroup convention.

    Skips entries where:
      * ``Include`` attribute is missing / empty
      * ``Version`` attribute is missing AND no child ``<Version>``
        element exists (incomplete entry — operator error)
      * The Version contains an MSBuild property expression
        ``$(X)`` we can't statically resolve. Logged at DEBUG.

    Deduplication: NuGet uses case-insensitive package names. If
    a file declares both ``Newtonsoft.Json`` and ``newtonsoft.json``
    (rare, but operators occasionally do it during migration),
    we keep the LAST declaration — same as MSBuild evaluation
    order.
    """
    out: List[CentralPackage] = []
    # Track which package names we've seen; last-wins on duplicates.
    by_lower_name: Dict[str, int] = {}
    props = _extract_properties(root)

    for item_group in _findall_local(root, "ItemGroup"):
        for el in item_group:
            tag = _strip_namespace(el.tag)
            is_global = tag == "GlobalPackageReference"
            if not is_global and tag != "PackageVersion":
                continue
            name = (el.get("Include") or "").strip()
            if not name:
                continue
            # Version may live in the attribute OR in a child
            # element — same form ``parsers/nuget.py`` already
            # handles for PackageReference.
            version = el.get("Version")
            if version is None:
                child = _find_child(el, "Version")
                if child is not None and child.text:
                    version = child.text.strip()
            if not version:
                logger.debug(
                    "sca.parsers.directory_packages_props: %s in "
                    "%s has no Version; skipping",
                    escape_nonprintable(name), declared_in,
                )
                continue
            if _MSBUILD_PROPERTY_RE.search(version):
                resolved = _resolve_property_version(version, props)
                if resolved is None:
                    logger.debug(
                        "sca.parsers.directory_packages_props: %s in "
                        "%s uses unresolvable MSBuild expression %r "
                        "(cross-file / item / floating); skipping",
                        escape_nonprintable(name), declared_in,
                        escape_nonprintable(version),
                    )
                    continue
                version = resolved
            entry = CentralPackage(
                name=name, version=version,
                is_global=is_global, declared_in=declared_in,
            )
            lower = name.lower()
            if lower in by_lower_name:
                # Last-wins replacement.
                out[by_lower_name[lower]] = entry
            else:
                by_lower_name[lower] = len(out)
                out.append(entry)
    return out


def find_cpm_chain(start_dir: Path) -> List[Path]:
    """Walk UP from ``start_dir`` collecting ``Directory.Packages.props``
    paths. Innermost (closest to ``start_dir``) FIRST in the
    returned list; outermost (closer to filesystem root) LAST.

    Matches MSBuild's resolution order — inner files OVERRIDE outer
    files for the same package. The csproj resolver merges maps in
    REVERSE order (outer first, then innermost overrides) so the
    innermost value wins.

    Walk stops at either:
      * Filesystem root (typically ``/``)
      * Repository root marker (``.git`` directory present) — most
        operators put ``Directory.Packages.props`` at the repo root
        and don't intend MSBuild to walk further. Stopping at the
        repo boundary avoids accidentally picking up an unrelated
        ``Directory.Packages.props`` from a different repo if SCA
        is scanning a nested project.

    Returns an empty list when no CPM file is found in the chain.
    """
    return _find_msbuild_chain(start_dir, "Directory.Packages.props")


def find_build_props_chain(start_dir: Path) -> List[Path]:
    """Walk UP from ``start_dir`` collecting ``Directory.Build.props``
    paths. Same innermost-first / git-boundary semantics as
    :func:`find_cpm_chain`.

    Pre-CPM .NET projects often put shared PackageReference items
    in ``Directory.Build.props`` so every csproj in the solution
    picks them up via MSBuild's auto-import. CPM superseded this
    pattern for VERSION management but ``Directory.Build.props``
    is still common for project-wide PackageReference, build
    properties, analyzer references, etc. We read it as a
    secondary version source — outranked by csproj inline and
    CPM, but used as fallback for the versionless-PackageReference
    case before declaring the dep unresolvable.
    """
    return _find_msbuild_chain(start_dir, "Directory.Build.props")


def find_build_targets_chain(start_dir: Path) -> List[Path]:
    """Walk UP from ``start_dir`` collecting ``Directory.Build.targets``
    paths. Same innermost-first / git-boundary semantics as
    :func:`find_build_props_chain`.

    ``Directory.Build.targets`` is the OTHER MSBuild auto-import (imported
    *after* the project, vs ``Directory.Build.props`` before it). Pre-CPM
    monorepos routinely centralise versions here via
    ``<PackageReference Update="Name" Version="X"/>`` — e.g. IdentityServer4
    puts its whole version table in ``Directory.Build.targets``. Parsed with
    the same :func:`parse_directory_build_props` reader (the ``<Project>`` /
    ``PackageReference`` shape is identical); ``Update`` rows are already
    handled there.
    """
    return _find_msbuild_chain(start_dir, "Directory.Build.targets")


_MAX_WALK_UP_DEPTH = 12


def _find_msbuild_chain(start_dir: Path, filename: str) -> List[Path]:
    """Shared walk-up implementation for both
    ``find_cpm_chain`` (Directory.Packages.props) and
    ``find_build_props_chain`` (Directory.Build.props). Both
    follow the same MSBuild auto-import convention: walk parents,
    stop at the nearest ``.git`` or filesystem root.

    Capped at ``_MAX_WALK_UP_DEPTH`` parents as a defence-in-depth
    bound. The .git-boundary check is the primary stop signal, but
    SCA may be invoked on an extracted-tarball target without any
    .git directory (CI artefact, sandboxed snapshot) — without a
    cap, the walk would proceed all the way to ``/`` and could
    pick up an out-of-tree ``Directory.Packages.props`` from a
    sibling checkout under the same parent. 12 levels matches the
    deepest legitimate solution layouts seen in the wild
    (microservice monorepos with category/subcategory/service
    nesting); anything beyond that is overwhelmingly outside the
    operator's intended scan scope.
    """
    out: List[Path] = []
    try:
        current = start_dir.resolve()
    except OSError:
        return out
    visited: set = set()
    depth = 0
    while True:
        if current in visited:    # symlink loop defence
            break
        visited.add(current)
        candidate = current / filename
        if candidate.is_file():
            out.append(candidate)
        # Stop at repo boundary if present.
        if (current / ".git").exists():
            break
        depth += 1
        if depth >= _MAX_WALK_UP_DEPTH:
            break
        parent = current.parent
        if parent == current:
            break
        current = parent
    return out


def parse_directory_build_props(path: Path) -> Optional[CPMFile]:
    """Parse a ``Directory.Build.props`` for PackageReference rows.

    Pre-CPM era projects routinely placed common ``<PackageReference>``
    entries in ``Directory.Build.props`` so every csproj in the
    solution inherited them. The file's MAIN purpose is MSBuild
    property + import management (logger settings, analyzer
    references, output paths) — but a meaningful subset carries
    PackageReference items too, and the csproj resolver needs to
    see them so the inherited deps get reported.

    Returns a ``CPMFile`` shape so the csproj resolver can treat
    Directory.Build.props and Directory.Packages.props uniformly.
    PackageReference entries with inline Version become
    CentralPackage entries with ``is_global=False`` — they're
    INHERITED into every csproj that doesn't override, which is
    the same effective behaviour as a CPM entry. ``cpm_enabled``
    is always True for Directory.Build.props (it has no
    enable/disable knob); the resolver consumes the file
    regardless of the CPM enable state of any sibling
    Directory.Packages.props.

    Skips ``<PackageReference>`` entries without a Version (same
    as the CPM parser) and entries with MSBuild property
    expressions (``$(MyVersion)``) — same static-resolution
    limitation.
    """
    if not _AVAILABLE:
        return None
    try:
        resolved = path.resolve()
    except OSError:
        return None
    if resolved in _PARSE_CACHE:
        return _PARSE_CACHE[resolved]
    text = _safe_read.read_bounded(resolved, follow_symlinks=False)
    if text is None:
        # ``read_bounded`` already logged the underlying reason at
        # warning level (oversize / symlink / vanished / …).
        _PARSE_CACHE[resolved] = None
        return None
    try:
        root = _safe_fromstring(text)
    except _ET.ParseError as e:
        logger.warning(
            "sca.parsers.directory_packages_props: invalid XML in %s: %s",
            escape_nonprintable(str(resolved)),
            escape_nonprintable(str(e)),
        )
        _PARSE_CACHE[resolved] = None
        return None
    if _strip_namespace(root.tag) != "Project":
        _PARSE_CACHE[resolved] = None
        return None
    packages: List[CentralPackage] = []
    seen: Dict[str, int] = {}
    props = _extract_properties(root)
    for item_group in _findall_local(root, "ItemGroup"):
        for el in item_group:
            if _strip_namespace(el.tag) != "PackageReference":
                continue
            name = (el.get("Include") or el.get("Update") or "").strip()
            if not name:
                continue
            version = el.get("Version")
            if version is None:
                child = _find_child(el, "Version")
                if child is not None and child.text:
                    version = child.text.strip()
            if not version:
                continue
            if _MSBUILD_PROPERTY_RE.search(version):
                resolved_ver = _resolve_property_version(version, props)
                if resolved_ver is None:
                    continue
                version = resolved_ver
            entry = CentralPackage(
                name=name, version=version,
                is_global=False, declared_in=resolved,
            )
            lower = name.lower()
            if lower in seen:
                packages[seen[lower]] = entry
            else:
                seen[lower] = len(packages)
                packages.append(entry)
    cpm_file = CPMFile(
        path=resolved, cpm_enabled=True, packages=packages,
    )
    _PARSE_CACHE[resolved] = cpm_file
    return cpm_file


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------

def _strip_namespace(tag: str) -> str:
    """``{http://...}TagName`` → ``TagName``. MSBuild XML is
    namespaced in legacy format, namespace-less in SDK-style;
    we treat both uniformly by stripping any namespace."""
    if tag.startswith("{"):
        return tag.partition("}")[2]
    return tag


def _findall_local(root, name: str):
    """Walk direct children matching local-name ``name`` (namespace-
    stripped). Avoids using XPath with namespaces — simpler for
    the documented two-element subset we care about."""
    return [el for el in root if _strip_namespace(el.tag) == name]


def _find_child(parent, name: str):
    for child in parent:
        if _strip_namespace(child.tag) == name:
            return child
    return None


def _reset_cache_for_tests() -> None:
    """Test seam — drops the per-process cache so each test runs
    against a fresh parse. Not part of the public API."""
    _PARSE_CACHE.clear()


def reset_cache() -> None:
    """Drop the per-process parse cache. Called from the discovery
    entry point at the start of each scan so a stale parse from a
    previous run on a different target can't leak across scans
    (case-collisions, tmpfs bind-mount re-use, devcontainer dirs).
    Within a single scan the cache is intentionally retained so
    csproj parsers walking up to the same Directory.Packages.props
    don't re-parse the file once per csproj."""
    _PARSE_CACHE.clear()


__all__ = [
    "CPMFile",
    "CentralPackage",
    "find_build_props_chain",
    "find_cpm_chain",
    "parse_directory_build_props",
    "parse_directory_packages_props",
]
