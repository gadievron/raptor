"""NuGet (.NET) parser.

Handles three file shapes:

  - **MSBuild project files** (``*.csproj``, ``*.fsproj``, ``*.vbproj``):
    XML with ``<PackageReference Include="Foo" Version="1.2.3" />`` and
    legacy ``<Reference Include="..." />``. The relevant tag is
    ``<PackageReference>``.

  - **Legacy ``packages.config``**: simple flat XML —
    ``<package id="Foo" version="1.2.3" />``.

  - **``packages.lock.json``**: lockfile JSON emitted by
    ``dotnet restore --use-lock-file``. Per-target dependency tree.

NuGet version specs ("Version") accept a small grammar:
  ``"1.2.3"``      → MINIMUM (≥1.2.3) — NuGet's default semantic
  ``"[1.2.3]"``    → EXACT
  ``"[1.2.3,2.0)"``→ RANGE (mixed bracket forms)
  ``"[1.2,)"``     → RANGE (open-upper)
  ``"(,2.0)"``     → RANGE (open-lower)
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import List, Optional, Tuple
# ``_ET`` kept for its ``ParseError`` exception type — defusedxml
# raises the stdlib's ParseError subclass on malformed XML, so
# catching ``_ET.ParseError`` works for both parsers. The actual
# parse goes through ``_safe_fromstring`` (defusedxml only).
from xml.etree import ElementTree as _ET

from ..models import Confidence, Dependency, PinStyle
from . import register

logger = logging.getLogger(__name__)


# .NET / ASP.NET Core shared-framework packages are referenced WITHOUT a
# version — the SDK's FrameworkReference (Microsoft.AspNetCore.App /
# Microsoft.NETCore.App) supplies it — so a version-less ref to one is expected,
# not a coverage gap. The Microsoft.AspNetCore.* prefix covers the 3.0+ shared
# framework (Authentication.*, Mvc.*, …); a few standalone Microsoft.AspNetCore.*
# packages match too, but they're version-less here for the same reason.
_FRAMEWORK_METAPACKAGES = frozenset({
    "microsoft.aspnetcore.app", "microsoft.aspnetcore.all",
    "microsoft.netcore.app", "microsoft.windowsdesktop.app",
})
_FRAMEWORK_REF_PREFIXES = ("microsoft.aspnetcore.",)


def _is_shared_framework_ref(name: str) -> bool:
    """True if a version-less PackageReference is provided by the shared
    framework (so its missing version is by-design, not a parse gap)."""
    n = name.lower()
    return n in _FRAMEWORK_METAPACKAGES or n.startswith(_FRAMEWORK_REF_PREFIXES)

# ``.csproj`` / ``.fsproj`` / ``.vbproj`` files come from the target
# repo, so an attacker-controlled XXE / billion-laughs payload could
# DoS the parser or exfil filesystem content via external entities
# on the stdlib parser. Require defusedxml; refuse to parse without
# it. Mirrors the ``_AVAILABLE`` pattern in
# ``packages/sca/parsers/pom.py``.
try:
    from defusedxml.ElementTree import fromstring as _safe_fromstring
    _AVAILABLE = True
except ImportError:                         # pragma: no cover — env-dependent
    _safe_fromstring = None                 # type: ignore[assignment]
    _AVAILABLE = False
    logger.warning(
        "sca.parsers.nuget: 'defusedxml' not installed — .csproj / "
        ".fsproj / .vbproj files will be skipped. `pip install "
        "defusedxml` to enable NuGet SCA coverage.",
    )


ECOSYSTEM = "NuGet"
_PURL_TYPE = "nuget"


# ---------------------------------------------------------------------------
# csproj / fsproj / vbproj — MSBuild project file
# ---------------------------------------------------------------------------

@register(suffixes=[".csproj", ".fsproj", ".vbproj"])
def parse_msbuild_project(path: Path) -> List[Dependency]:
    """Parse an MSBuild project file and emit one Dependency per
    ``<PackageReference>``.

    Three version-source paths, in precedence order:

      1. Inline ``Version`` attribute on ``<PackageReference>``
         (or child ``<Version>`` element — same fallback the
         csproj reader has always handled).
      2. ``VersionOverride`` attribute on ``<PackageReference>``
         when CPM is in play — per-csproj override of the
         centrally-declared version.
      3. ``Directory.Packages.props`` walked UP from the csproj
         location (innermost-wins). NuGet's Central Package
         Management (CPM), introduced .NET 6 / NuGet 6.2 (2022).
         Without this resolution path, modern .NET solutions
         lose ~80-100% of dependency coverage because their
         csproj files declare ``<PackageReference Include="X" />``
         with no Version attribute — versions live centrally.

    Plus ``<GlobalPackageReference>`` entries from the CPM chain
    get auto-emitted as Dependency rows on every csproj (matching
    MSBuild's "force include this in every project" semantic).

    When CPM is disabled (``<ManagePackageVersionsCentrally>false</>``
    in the file) the CPM map is ignored — operators sometimes
    disable mid-migration and runtime would also ignore those
    centrally-declared versions.

    When a PackageReference has no resolvable version through any
    of the three paths above, it's skipped with a parser-warning
    log line (surfaces in ``report.md`` via the existing
    ``capture_parse_failures`` mechanism so operators can see the
    coverage gap rather than silently miss the dep).
    """
    if not _AVAILABLE:
        logger.warning(
            "sca.parsers.nuget: skipping %s — 'defusedxml' not "
            "installed; refusing to parse target-repo XML with the "
            "stdlib parser (XXE / billion-laughs exposure)", path,
        )
        return []
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as e:
        logger.warning("sca.parsers.nuget: cannot read %s: %s", path, e)
        return []

    try:
        root = _safe_fromstring(text)
    except _ET.ParseError as e:
        logger.warning("sca.parsers.nuget: invalid XML in %s: %s", path, e)
        return []

    out: List[Dependency] = []
    seen_keys: set = set()
    # Extract the project's target framework(s). Modern SDK-style
    # csproj uses ``<TargetFramework>`` (singular) or
    # ``<TargetFrameworks>`` (plural, semicolon-separated). The
    # TFM list is shared by every PackageReference in the file
    # and feeds the transitive-drop NuGet check (which compares
    # per-TFM dep groups across versions).
    tfms = _extract_target_frameworks(root)

    # Resolve the CPM chain for THIS csproj's location. Empty list
    # when no Directory.Packages.props exists in the walk (the
    # common pre-CPM case) — falls through to inline-only.
    cpm_map, global_packages = _resolve_cpm_chain(path.parent)

    # Build common source_extra carrying TFM information.
    source_extra = {"tfms": tfms} if tfms else None

    # GlobalPackageReference entries from the chain are auto-applied
    # to EVERY csproj in the solution. Emit them BEFORE the inline
    # PackageReference walk so deduplication via seen_keys handles
    # the case where a csproj ALSO explicitly references a global
    # package (uncommon but legal — csproj's reference wins).
    for global_pkg in global_packages:
        dep = _build_msbuild_dep(
            name=global_pkg.name,
            version=global_pkg.version,
            scope="main",
            declared_in=path,
            source_extra=source_extra,
            source_origin="cpm_global",
        )
        if dep.key() in seen_keys:
            continue
        seen_keys.add(dep.key())
        out.append(dep)

    # MSBuild XML is namespaced (xmlns="http://schemas...") in some files
    # but namespace-less in modern SDK-style projects; iter both.
    skipped_no_version = []
    for el in _findall_pkgref(root):
        name = el.get("Include") or el.get("Update")
        if not name:
            continue
        # Version-source resolution chain.
        version = el.get("Version")
        source_origin = "inline_version"
        if version is None:
            child = _find_child(el, "Version")
            if child is not None and child.text:
                version = child.text.strip()
                source_origin = "inline_version_child"
        if not version:
            # No inline version. Check VersionOverride (CPM
            # per-csproj override).
            override = el.get("VersionOverride")
            if override:
                version = override.strip()
                source_origin = "version_override"
        if not version and cpm_map:
            # Fall through to the CPM map walked from the
            # csproj's directory.
            version = cpm_map.get(name.lower())
            if version is not None:
                source_origin = "cpm_central"
        if not version:
            if _is_shared_framework_ref(name):
                # Version-less by design — supplied by the .NET / ASP.NET Core
                # shared framework, not an independently-pinned dep. Skip
                # silently; it's not a coverage gap to surface.
                continue
            # No resolvable version (no inline, VersionOverride, or central
            # entry) for a normal package. Collect + emit ONE warning per file
            # below (a .NET monorepo otherwise produces dozens of per-ref lines).
            skipped_no_version.append(name)
            continue
        pin_style, normalised = _classify_version_spec(version)
        if normalised is not None:
            version = normalised
        scope = _scope_from_msbuild(el)
        dep = _build_msbuild_dep(
            name=name,
            version=version,
            scope=scope,
            declared_in=path,
            source_extra=source_extra,
            source_origin=source_origin,
            pin_style=pin_style,
        )
        if dep.key() in seen_keys:
            continue
        seen_keys.add(dep.key())
        out.append(dep)
    if skipped_no_version:
        # One aggregated parser warning per file instead of one per
        # PackageReference. Keep the canonical "<kind> parse failed for
        # <path>: <reason>" shape so capture_parse_failures still lifts it
        # into report.md (it matches on that format, not the logger name).
        # Sorted names for a stable message.
        logger.warning(
            "sca.parsers.nuget: PackageReference parse failed for %s: "
            "%d reference(s) have no Version, VersionOverride, or CPM "
            "entry (skipped): %s",
            path, len(skipped_no_version),
            ", ".join(sorted(skipped_no_version)),
        )
    return out


def _build_msbuild_dep(
    *, name: str, version: str, scope: str, declared_in: Path,
    source_extra: Optional[dict] = None,
    source_origin: str = "inline_version",
    pin_style: PinStyle = PinStyle.EXACT,
) -> Dependency:
    """Construct a Dependency carrying the MSBuild source-origin
    annotation. ``source_origin`` records where the version came
    from so the bumper can route writes to the right file:

      * ``inline_version`` — csproj ``Version=`` attribute
      * ``inline_version_child`` — csproj ``<Version>`` child
      * ``version_override`` — csproj ``VersionOverride=``
      * ``cpm_central`` — Directory.Packages.props PackageVersion
      * ``cpm_global`` — Directory.Packages.props GlobalPackageReference

    Bumper consumers read this off ``dep.source_extra["origin"]`` to
    pick the rewriter target.
    """
    purl = _build_purl(name, version)
    extra = dict(source_extra) if source_extra else {}
    extra["origin"] = source_origin
    return Dependency(
        ecosystem=ECOSYSTEM,
        name=name,
        version=version,
        declared_in=declared_in,
        scope=scope,
        is_lockfile=False,
        pin_style=pin_style,
        direct=True,
        purl=purl,
        parser_confidence=Confidence(
            "high",
            reason="MSBuild XML — deterministic structure",
        ),
        source_kind="manifest",
        source_extra=extra,
    )


def _resolve_cpm_chain(start_dir: Path):
    """Walk MSBuild auto-import files (``Directory.Packages.props``
    + ``Directory.Build.props``) from ``start_dir`` upward and
    return ``(merged_version_map, global_packages)``.

    Two file types contribute:

      * ``Directory.Packages.props`` — CPM (NuGet 6.2+). Primary
        version source for modern .NET. PackageVersion entries
        feed ``version_map``; GlobalPackageReference entries
        feed ``global_packages``.
      * ``Directory.Build.props`` — older pre-CPM convention.
        PackageReference entries with inline Version go into
        ``version_map`` (treated as non-global central
        declarations). No GlobalPackageReference shape in this
        file type.

    Merge semantics:
      * version_map merges OUTER → INNER (innermost wins).
        Within the same directory, CPM (Directory.Packages.props)
        outranks Directory.Build.props.
      * global_packages from ALL CPM files in the chain are
        concatenated; the rule "GlobalPackageReference applies
        to every csproj" doesn't care about hierarchy.
      * When ANY CPM file in the chain disables CPM
        (``<ManagePackageVersionsCentrally>false</>``), the
        CPM-version-map becomes ineffective and we fall through
        to Directory.Build.props (still active). Matches MSBuild
        — disabling CPM doesn't disable build-props inheritance.

    Returns ``({}, [])`` for the no-MSBuild-auto-import case.
    """
    from .directory_packages_props import (
        find_build_props_chain, find_build_targets_chain, find_cpm_chain,
        parse_directory_build_props, parse_directory_packages_props,
    )

    cpm_paths = find_cpm_chain(start_dir)
    build_paths = find_build_props_chain(start_dir)
    targets_paths = find_build_targets_chain(start_dir)
    if not cpm_paths and not build_paths and not targets_paths:
        return {}, []

    cpm_files = [parse_directory_packages_props(p) for p in cpm_paths]
    cpm_files = [f for f in cpm_files if f is not None]
    build_files = [parse_directory_build_props(p) for p in build_paths]
    build_files = [f for f in build_files if f is not None]
    # Directory.Build.targets uses the same <Project>/PackageReference shape
    # (incl. ``Update=`` rows), so the same reader applies. Pre-CPM monorepos
    # (e.g. IdentityServer4) keep their whole version table here.
    targets_files = [parse_directory_build_props(p) for p in targets_paths]
    targets_files = [f for f in targets_files if f is not None]

    cpm_active = bool(cpm_files) and all(f.cpm_enabled for f in cpm_files)

    merged: dict = {}
    globals_by_name: dict = {}

    # Apply outer-to-inner; within a directory, Directory.Build.props
    # is applied FIRST, then Directory.Packages.props overrides
    # (matching MSBuild's import order — CPM is the more recent
    # and more authoritative system).
    for build_file in reversed(build_files):
        for pkg in build_file.packages:
            merged[pkg.name.lower()] = pkg.version
    # Directory.Build.targets is auto-imported AFTER the project (and after
    # Directory.Build.props), so it wins over .props for the same package.
    for targets_file in reversed(targets_files):
        for pkg in targets_file.packages:
            merged[pkg.name.lower()] = pkg.version

    if cpm_active:
        for cpm_file in reversed(cpm_files):
            for pkg in cpm_file.packages:
                merged[pkg.name.lower()] = pkg.version
                if pkg.is_global:
                    globals_by_name[pkg.name.lower()] = pkg
                elif pkg.name.lower() in globals_by_name:
                    del globals_by_name[pkg.name.lower()]

    return merged, list(globals_by_name.values())


def _extract_target_frameworks(root) -> List[str]:
    """Pull the project's target frameworks from ``<TargetFramework>``
    or ``<TargetFrameworks>``. Returns a list of TFMs (e.g. ``["net6.0",
    "net8.0"]``); empty if neither element is present.

    Per-PackageReference TFM (`Condition="'$(TargetFramework)' == ..."`)
    isn't handled — for v1 we treat all package refs as applying to
    the full TFM set."""
    out: List[str] = []
    for elem in root.iter():
        tag = elem.tag
        if tag.endswith("}TargetFramework") or tag == "TargetFramework":
            if elem.text and elem.text.strip():
                out.append(elem.text.strip())
        elif tag.endswith("}TargetFrameworks") or tag == "TargetFrameworks":
            if elem.text:
                for t in elem.text.split(";"):
                    t = t.strip()
                    if t:
                        out.append(t)
    # Deduplicate preserving order.
    seen: set = set()
    deduped: List[str] = []
    for t in out:
        if t not in seen:
            seen.add(t)
            deduped.append(t)
    return deduped


def _findall_pkgref(root):
    """Find ``<PackageReference>`` elements regardless of namespace."""
    out = []
    for el in root.iter():
        tag = el.tag
        # Strip ``{namespace}`` prefix when present.
        if "}" in tag:
            tag = tag.rsplit("}", 1)[1]
        if tag == "PackageReference":
            out.append(el)
    return out


def _find_child(parent, name: str):
    for el in parent:
        tag = el.tag
        if "}" in tag:
            tag = tag.rsplit("}", 1)[1]
        if tag == name:
            return el
    return None


def _scope_from_msbuild(el) -> str:
    """``PrivateAssets="all"`` (analyser-style refs) → "build"."""
    private = el.get("PrivateAssets") or ""
    if private.strip().lower() == "all":
        return "build"
    return "main"


# ---------------------------------------------------------------------------
# packages.config — legacy NuGet
# ---------------------------------------------------------------------------

@register(filenames=["packages.config"])
def parse_packages_config(path: Path) -> List[Dependency]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as e:
        logger.warning("sca.parsers.nuget: cannot read %s: %s", path, e)
        return []
    try:
        root = _safe_fromstring(text)
    except _ET.ParseError as e:
        logger.warning("sca.parsers.nuget: invalid XML in %s: %s", path, e)
        return []

    out: List[Dependency] = []
    seen_keys: set = set()
    for el in root.iter():
        tag = el.tag.rsplit("}", 1)[-1]
        if tag != "package":
            continue
        name = el.get("id")
        version = el.get("version")
        if not (name and version):
            continue
        pin_style, normalised = _classify_version_spec(version)
        if normalised is not None:
            version = normalised
        purl = _build_purl(name, version)
        dep = Dependency(
            ecosystem=ECOSYSTEM,
            name=name,
            version=version,
            declared_in=path,
            scope="main",
            is_lockfile=False,
            pin_style=pin_style,
            direct=True,
            purl=purl,
            parser_confidence=Confidence(
                "high",
                reason="packages.config XML — deterministic structure",
            ),
            source_kind="manifest",
        )
        if dep.key() in seen_keys:
            continue
        seen_keys.add(dep.key())
        out.append(dep)
    return out


# ---------------------------------------------------------------------------
# packages.lock.json — lockfile
# ---------------------------------------------------------------------------

@register(filenames=["packages.lock.json"])
def parse_lockfile(path: Path) -> List[Dependency]:
    """Parse a NuGet ``packages.lock.json`` and emit one Dependency per
    resolved entry.

    Shape:
        {
          "version": 1,
          "dependencies": {
            "net8.0": {
              "Foo": {"type": "Direct", "requested": "[1.2.3, )",
                      "resolved": "1.2.3", ...},
              "Bar": {"type": "Transitive", "resolved": "2.0.0"}
            }
          }
        }
    """
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        logger.warning("sca.parsers.nuget: cannot read %s: %s", path, e)
        return []

    out: List[Dependency] = []
    seen_keys: set = set()
    deps_block = data.get("dependencies") or {}
    if not isinstance(deps_block, dict):
        return []
    for _target, entries in deps_block.items():
        if not isinstance(entries, dict):
            continue
        for name, spec in entries.items():
            if not isinstance(spec, dict):
                continue
            version = spec.get("resolved")
            if not isinstance(version, str):
                continue
            kind = (spec.get("type") or "").strip().lower()
            direct = kind == "direct"
            purl = _build_purl(name, version)
            dep = Dependency(
                ecosystem=ECOSYSTEM,
                name=name,
                version=version,
                declared_in=path,
                scope="main",
                is_lockfile=True,
                pin_style=PinStyle.EXACT,
                direct=direct,
                purl=purl,
                parser_confidence=Confidence(
                    "high",
                    reason=("packages.lock.json — deterministic JSON; "
                            f"type={kind!r}"),
                ),
                source_kind="lockfile",
            )
            if dep.key() in seen_keys:
                continue
            seen_keys.add(dep.key())
            out.append(dep)
    return out


# ---------------------------------------------------------------------------
# NuGet version-spec grammar
# ---------------------------------------------------------------------------

_BRACKET_RE = re.compile(
    r"^\s*([\[\(])\s*([^,\[\]\(\)]*?)\s*(?:,\s*([^,\[\]\(\)]*?)\s*)?([\]\)])\s*$"
)


def _classify_version_spec(spec: Optional[str]) -> Tuple[PinStyle, Optional[str]]:
    """Return ``(pin_style, bare_version)`` for a NuGet version string.

    Rules:
      ``"1.2.3"``        → CARET-ish (NuGet's "minimum" — we report MINIMUM
                          as RANGE because OSV needs a concrete version
                          to match exactly; the bare version is preserved
                          so harden / OSV use it as a starting point).

      ``"[1.2.3]"``      → EXACT
      ``"[1.0,2.0)"``    → RANGE
      ``"(,1.0]"``       → RANGE (open lower-bound)
      ``"[1.0,)"``       → RANGE (open upper-bound)
    """
    if spec is None:
        return PinStyle.UNKNOWN, None
    s = spec.strip()
    if not s:
        return PinStyle.UNKNOWN, None
    m = _BRACKET_RE.match(s)
    if m:
        lb, lv, uv, ub = m.group(1), m.group(2), m.group(3), m.group(4)
        if uv is None:
            # Single-value form. Only ``[V]`` (both inclusive) is a
            # valid EXACT pin per NuGet spec; ``(V)`` / ``[V)`` /
            # ``(V]`` are pathological (empty interval) — surface
            # UNKNOWN so the planner doesn't treat them as exact
            # matches.
            if lv and lb == "[" and ub == "]":
                return PinStyle.EXACT, lv
            return PinStyle.UNKNOWN, None
        # Range form. Pick the lower bound's bare version when present;
        # else the upper.
        bare = lv if lv else uv if uv else None
        return PinStyle.RANGE, bare
    # Plain ``"1.2.3"`` — NuGet's "minimum" semantic. We report it as
    # RANGE (operator >= is implied) but keep the bare version.
    if re.match(r"^\d[\w.\-+]*$", s):
        return PinStyle.RANGE, s
    return PinStyle.UNKNOWN, None


def _build_purl(name: str, version: Optional[str]) -> str:
    base = f"pkg:{_PURL_TYPE}/{name}"
    if version:
        return f"{base}@{version}"
    return base


__all__ = [
    "parse_msbuild_project",
    "parse_packages_config",
    "parse_lockfile",
]
