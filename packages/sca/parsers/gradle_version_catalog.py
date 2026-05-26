"""Gradle version catalog parser — ``libs.versions.toml``.

Gradle 7.0+ introduced version catalogs as the centralised-version
analogue of NuGet's CPM. Modern Gradle projects (Spring Boot
samples, Kotlin Multiplatform, Android Studio templates since
2022) increasingly use catalogs rather than inline coordinates:

  build.gradle.kts:
      implementation(libs.spring.boot.starter)   // accessor
      testImplementation(libs.junit.jupiter)

  gradle/libs.versions.toml:
      [versions]
      spring-boot = "3.1.0"
      junit = "5.9.0"

      [libraries]
      spring-boot-starter = { module = "org.springframework.boot:spring-boot-starter", version.ref = "spring-boot" }
      junit-jupiter = { module = "org.junit.jupiter:junit-jupiter", version.ref = "junit" }

Without catalog support, ``parsers/gradle_dsl.py`` sees
``libs.spring.boot.starter`` as an unparseable accessor and skips
the dep entirely — losing ~80-100% of dep coverage on any modern
Gradle solution. This module is the read-side fix; the sibling
rewriter in ``bump/rewriters/gradle_version_catalog`` handles the
write-side for bumper / harden.

Conventional location:
  ``<repo_root>/gradle/libs.versions.toml`` is the documented
  default. Multi-catalog projects can declare additional files in
  ``settings.gradle(.kts)`` via ``versionCatalogs { ... }``. We
  honour the default location; multi-catalog support is a
  follow-up.

Format coverage:
  * ``[versions]`` — named version strings.
  * ``[libraries]`` — either ``module + version`` (inline) or
    ``module + version.ref`` (catalog-resolved) or ``group +
    name + version`` (legacy expanded shape).
  * ``[plugins]`` — ``id + version`` / ``id + version.ref``.
    Plugins map to ``pkg:maven/<id>`` for OSV purposes.
  * ``[bundles]`` — alias lists for declaring groups of libs.
    Not emitted as Dependency rows themselves; consumers reading
    a bundle name should expand it via the libraries map.

Skip cases (best-effort, never crash):
  * Malformed TOML — log + return empty.
  * Library entries with no resolvable version (ref pointing at a
    missing key, or no version at all) — log + skip the entry.
  * Plugin IDs without a version — keep them with version=None so
    consumers see the plugin presence.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

try:
    import tomllib                              # Python 3.11+
except ModuleNotFoundError:                     # pragma: no cover
    import tomli as tomllib                     # type: ignore[no-redef]

from core.security.log_sanitisation import escape_nonprintable

from . import _safe_read

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class CatalogLibrary:
    """One ``[libraries]`` entry resolved against the catalog's
    ``[versions]`` table.

    ``alias`` is the catalog key (``spring-boot-starter``). The
    Gradle accessor form (``libs.spring.boot.starter``) is derived
    by replacing ``-`` and ``_`` with ``.``; consumers needing the
    accessor form derive it themselves.
    """

    alias: str
    group: str
    artifact: str
    version: Optional[str]
    # True iff the version came from a ``version.ref`` rather than
    # an inline ``version``. Matters for the bumper: a
    # version.ref-resolved library means the version lives in the
    # ``[versions]`` table; the rewriter targets THAT entry rather
    # than the ``[libraries]`` row.
    version_via_ref: bool = False
    # When ``version_via_ref`` is True, the name of the
    # ``[versions]`` key the library references. Empty otherwise.
    version_ref_name: str = ""


@dataclass(frozen=True)
class CatalogPlugin:
    """One ``[plugins]`` entry. Gradle plugins ship via the
    ``gradlePluginPortal()`` Maven repository; we emit them as
    Maven-coordinate Dependency rows so OSV matching works."""

    alias: str
    plugin_id: str
    version: Optional[str]
    version_via_ref: bool = False
    version_ref_name: str = ""


@dataclass(frozen=True)
class VersionCatalog:
    """Parsed view of a single ``libs.versions.toml`` file."""

    path: Path
    versions: Dict[str, str] = field(default_factory=dict)
    libraries: Dict[str, CatalogLibrary] = field(default_factory=dict)
    plugins: Dict[str, CatalogPlugin] = field(default_factory=dict)
    # ``[bundles]`` map alias → list of library aliases. Kept on
    # the dataclass for completeness; consumers expand a bundle by
    # name into its constituent libraries.
    bundles: Dict[str, List[str]] = field(default_factory=dict)

    def accessor_to_alias(self) -> Dict[str, str]:
        """Map the Gradle accessor form (``libs.spring.boot.starter``)
        to the catalog alias (``spring-boot-starter``).

        Gradle normalises catalog aliases: ``-`` and ``_`` in the
        TOML key become ``.`` in the accessor. Multiple consecutive
        separators collapse to one — but real-world catalogs avoid
        that ambiguity in practice. We do the straightforward
        replacement; ambiguity (unlikely) gets a last-wins
        precedence.
        """
        out: Dict[str, str] = {}
        for alias in self.libraries:
            accessor = alias.replace("-", ".").replace("_", ".")
            out[accessor] = alias
        return out


# Per-process cache. A single repo may have a build.gradle in
# every module of a monorepo; all of them look at the same
# libs.versions.toml. Cache keyed on resolved absolute path.
_PARSE_CACHE: Dict[Path, Optional[VersionCatalog]] = {}


def parse_libs_versions_toml(path: Path) -> Optional[VersionCatalog]:
    """Parse one ``libs.versions.toml`` file.

    Returns ``None`` when:
      * The file can't be read.
      * The TOML is malformed.

    Cached per resolved absolute path so a monorepo's many
    ``build.gradle`` files all sharing one catalog pay one parse
    cost.
    """
    try:
        resolved = path.resolve()
    except OSError:
        return None
    if resolved in _PARSE_CACHE:
        return _PARSE_CACHE[resolved]
    text = _safe_read.read_bounded(resolved, follow_symlinks=False)
    if text is None:
        # ``read_bounded`` already logged the underlying reason.
        _PARSE_CACHE[resolved] = None
        return None
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as e:
        logger.warning(
            "sca.parsers.gradle_version_catalog: TOML parse failed "
            "for %s: %s",
            escape_nonprintable(str(resolved)),
            escape_nonprintable(str(e)),
        )
        _PARSE_CACHE[resolved] = None
        return None
    if not isinstance(data, dict):
        _PARSE_CACHE[resolved] = None
        return None

    versions = _parse_versions(data.get("versions") or {})
    libraries = _parse_libraries(
        data.get("libraries") or {}, versions=versions,
    )
    plugins = _parse_plugins(
        data.get("plugins") or {}, versions=versions,
    )
    bundles = _parse_bundles(data.get("bundles") or {})

    catalog = VersionCatalog(
        path=resolved,
        versions=versions,
        libraries=libraries,
        plugins=plugins,
        bundles=bundles,
    )
    _PARSE_CACHE[resolved] = catalog
    return catalog


def find_default_catalog(repo: Path) -> Optional[Path]:
    """Return the conventional catalog path
    (``<repo>/gradle/libs.versions.toml``) when it exists,
    otherwise ``None``.

    Gradle's documented default. Multi-catalog projects declare
    additional catalogs in ``settings.gradle(.kts)`` via the
    ``versionCatalogs { ... }`` block — supporting those is a
    follow-up; the default is what >95% of real-world projects
    use.
    """
    candidate = repo / "gradle" / "libs.versions.toml"
    return candidate if candidate.is_file() else None


# ---------------------------------------------------------------------------
# Section parsers — each returns a typed view of one TOML table.
# ---------------------------------------------------------------------------

def _parse_versions(raw: dict) -> Dict[str, str]:
    """``[versions]`` table → ``{name: version_string}`` dict.

    Values must be strings; non-string entries (dict / list /
    int) are skipped with a debug log. TOML keys are
    case-sensitive in Gradle catalogs."""
    out: Dict[str, str] = {}
    if not isinstance(raw, dict):
        return out
    for k, v in raw.items():
        if isinstance(v, str) and v:
            out[k] = v
        else:
            logger.debug(
                "sca.parsers.gradle_version_catalog: ignoring "
                "non-string [versions] entry %s=%r",
                escape_nonprintable(str(k)), v,
            )
    return out


def _parse_libraries(
    raw: dict, *, versions: Dict[str, str],
) -> Dict[str, CatalogLibrary]:
    """``[libraries]`` table → ``{alias: CatalogLibrary}``.

    Two value shapes supported (Gradle accepts both):

      1. **String shorthand** — ``"g:a:v"`` or ``"g:a"``.
         Compact form, version optional.
      2. **Inline table** —
         ``{module = "g:a", version = "v"}`` /
         ``{module = "g:a", version.ref = "vname"}`` /
         ``{group = "g", name = "a", version = "v"}``.
         Note ``version.ref`` becomes nested
         ``{"version": {"ref": "vname"}}`` after TOML decode.

    Skips entries with:
      * Missing module / group+name
      * version.ref pointing at a missing [versions] key
        (logs at WARNING since this is likely a typo)
    """
    out: Dict[str, CatalogLibrary] = {}
    if not isinstance(raw, dict):
        return out
    for alias, entry in raw.items():
        if isinstance(entry, str):
            lib = _parse_library_string(alias, entry)
        elif isinstance(entry, dict):
            lib = _parse_library_table(alias, entry, versions=versions)
        else:
            continue
        if lib is not None:
            out[alias] = lib
    return out


def _parse_library_string(
    alias: str, coord: str,
) -> Optional[CatalogLibrary]:
    """String-shorthand library entry: ``"group:artifact:version"``
    (or ``"group:artifact"`` without version)."""
    parts = coord.split(":")
    if len(parts) < 2:
        return None
    group, artifact = parts[0], parts[1]
    version = parts[2] if len(parts) >= 3 else None
    return CatalogLibrary(
        alias=alias, group=group, artifact=artifact,
        version=version, version_via_ref=False, version_ref_name="",
    )


def _parse_library_table(
    alias: str, entry: dict, *, versions: Dict[str, str],
) -> Optional[CatalogLibrary]:
    """Inline-table library entry. Two equivalent shapes:

      ``{module = "g:a", ...}`` — module-style (modern).
      ``{group = "g", name = "a", ...}`` — expanded (legacy).
    """
    group: Optional[str] = None
    artifact: Optional[str] = None
    module = entry.get("module")
    if isinstance(module, str) and ":" in module:
        group, artifact = module.split(":", 1)
    else:
        g = entry.get("group")
        n = entry.get("name")
        if isinstance(g, str) and isinstance(n, str):
            group, artifact = g, n
    if group is None or artifact is None:
        return None

    version: Optional[str] = None
    via_ref = False
    ref_name = ""
    ver_field = entry.get("version")
    if isinstance(ver_field, str):
        version = ver_field
    elif isinstance(ver_field, dict):
        # ``version = { ref = "x" }`` shape after TOML decode.
        ref = ver_field.get("ref")
        if isinstance(ref, str):
            if ref in versions:
                version = versions[ref]
                via_ref = True
                ref_name = ref
            else:
                logger.warning(
                    "sca.parsers.gradle_version_catalog: library "
                    "%r references missing version key %r; "
                    "emitting with no version",
                    escape_nonprintable(str(alias)),
                    escape_nonprintable(str(ref)),
                )
                via_ref = True   # the intent was a ref — keep the flag
                ref_name = ref
                # Leave version=None so consumers know it's unresolved.
        else:
            # ``version = { strictly = "..." }`` / require / prefer.
            # Take the first non-empty string we recognise; same
            # logic Gradle uses for resolved-version selection.
            for k in ("strictly", "require", "prefer"):
                v = ver_field.get(k)
                if isinstance(v, str) and v:
                    version = v
                    break
    return CatalogLibrary(
        alias=alias, group=group, artifact=artifact,
        version=version,
        version_via_ref=via_ref, version_ref_name=ref_name,
    )


def _parse_plugins(
    raw: dict, *, versions: Dict[str, str],
) -> Dict[str, CatalogPlugin]:
    """``[plugins]`` table → ``{alias: CatalogPlugin}``."""
    out: Dict[str, CatalogPlugin] = {}
    if not isinstance(raw, dict):
        return out
    for alias, entry in raw.items():
        if isinstance(entry, str):
            # String shorthand: ``"id:version"``.
            if ":" not in entry:
                continue
            plugin_id, version = entry.split(":", 1)
            out[alias] = CatalogPlugin(
                alias=alias, plugin_id=plugin_id, version=version,
            )
        elif isinstance(entry, dict):
            plugin_id = entry.get("id")
            if not isinstance(plugin_id, str):
                continue
            version: Optional[str] = None
            via_ref = False
            ref_name = ""
            ver_field = entry.get("version")
            if isinstance(ver_field, str):
                version = ver_field
            elif isinstance(ver_field, dict):
                ref = ver_field.get("ref")
                if isinstance(ref, str):
                    if ref in versions:
                        version = versions[ref]
                        via_ref = True
                        ref_name = ref
                    else:
                        logger.warning(
                            "sca.parsers.gradle_version_catalog: "
                            "plugin %r references missing version "
                            "key %r",
                            escape_nonprintable(str(alias)),
                            escape_nonprintable(str(ref)),
                        )
                        via_ref = True
                        ref_name = ref
            out[alias] = CatalogPlugin(
                alias=alias, plugin_id=plugin_id, version=version,
                version_via_ref=via_ref, version_ref_name=ref_name,
            )
    return out


def _parse_bundles(raw: dict) -> Dict[str, List[str]]:
    """``[bundles]`` table → ``{alias: [library_alias, ...]}``."""
    out: Dict[str, List[str]] = {}
    if not isinstance(raw, dict):
        return out
    for alias, entry in raw.items():
        if isinstance(entry, list) and all(isinstance(x, str) for x in entry):
            out[alias] = list(entry)
    return out


def _reset_cache_for_tests() -> None:
    _PARSE_CACHE.clear()


def reset_cache() -> None:
    """Drop the per-process parse cache. See the matching helper in
    ``parsers/directory_packages_props.py`` — same scan-boundary
    reasoning."""
    _PARSE_CACHE.clear()


__all__ = [
    "CatalogLibrary",
    "CatalogPlugin",
    "VersionCatalog",
    "find_default_catalog",
    "parse_libs_versions_toml",
]
