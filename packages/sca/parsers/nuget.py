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
from xml.etree import ElementTree as _ET

try:
    from defusedxml.ElementTree import fromstring as _safe_fromstring
except ImportError:                         # pragma: no cover
    _safe_fromstring = _ET.fromstring       # type: ignore[assignment]

from ..models import Confidence, Dependency, PinStyle
from . import register

logger = logging.getLogger(__name__)


ECOSYSTEM = "NuGet"
_PURL_TYPE = "nuget"


# ---------------------------------------------------------------------------
# csproj / fsproj / vbproj — MSBuild project file
# ---------------------------------------------------------------------------

@register(suffixes=[".csproj", ".fsproj", ".vbproj"])
def parse_msbuild_project(path: Path) -> List[Dependency]:
    """Parse an MSBuild project file and emit one Dependency per
    ``<PackageReference>``.

    Some projects use ``<PackageReference Include="X" Version="..."/>``;
    others put the version in a child element
    (``<PackageReference Include="X"><Version>...</Version></PackageReference>``).
    Both forms supported.
    """
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
    # MSBuild XML is namespaced (xmlns="http://schemas...") in some files
    # but namespace-less in modern SDK-style projects; iter both.
    for el in _findall_pkgref(root):
        name = el.get("Include") or el.get("Update")
        if not name:
            continue
        version = el.get("Version")
        if version is None:
            child = _find_child(el, "Version")
            if child is not None and child.text:
                version = child.text.strip()
        pin_style, normalised = _classify_version_spec(version)
        if normalised is not None:
            version = normalised
        purl = _build_purl(name, version)
        scope = _scope_from_msbuild(el)
        source_extra = {"tfms": tfms} if tfms else None
        dep = Dependency(
            ecosystem=ECOSYSTEM,
            name=name,
            version=version,
            declared_in=path,
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
            source_extra=source_extra,
        )
        if dep.key() in seen_keys:
            continue
        seen_keys.add(dep.key())
        out.append(dep)
    return out


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
            # ``[1.2.3]`` form — single value.
            if lv:
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
