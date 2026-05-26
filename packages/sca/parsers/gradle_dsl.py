"""Gradle build-script DSL parser (``build.gradle`` / ``build.gradle.kts``).

The Gradle DSL is Turing-complete (Groovy or Kotlin), so we deliberately
do not execute it. We regex-match the most common dependency-declaration
shapes:

  Groovy DSL:
      implementation 'group:artifact:version'
      api group: 'g', name: 'a', version: '1.2.3'
      compileOnly "group:artifact:$version"      // string interpolation
      testImplementation 'group:artifact'         // version omitted

  Kotlin DSL:
      implementation("group:artifact:1.2.3")
      api("group:artifact:1.2.3")

Configurations recognised: ``implementation``, ``api``, ``compileOnly``,
``runtimeOnly``, ``testImplementation``, ``testCompileOnly``,
``testRuntimeOnly``, ``annotationProcessor``, ``kapt``, ``ksp``.

Confidence is ``medium`` because:
  - String interpolation values (``$version``) we leave as-is in the
    version field — they're not real versions but we can't resolve
    them without executing the script.
  - Conditional ``if`` / ``when`` branches mean we may emit deps that
    aren't actually included (or miss ones that are).

We do not parse ``settings.gradle`` (workspace declaration), ``init.gradle``
(global), or plugin-block dep declarations. Those are out of scope.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import List, Optional

from ..models import Confidence, Dependency, PinStyle
from . import register

logger = logging.getLogger(__name__)


ECOSYSTEM = "Maven"
_PURL_TYPE = "maven"

# Configurations that introduce a runtime / build-time dep. Each maps
# to a SCA scope value.
_CONFIG_TO_SCOPE = {
    "implementation": "main",
    "api": "main",
    "compileOnly": "main",
    "runtimeOnly": "main",
    "compile": "main",                    # deprecated but still seen
    "runtime": "main",                    # deprecated but still seen
    "kapt": "build",
    "ksp": "build",
    "annotationProcessor": "build",
    "testImplementation": "test",
    "testApi": "test",
    "testCompileOnly": "test",
    "testRuntimeOnly": "test",
    "androidTestImplementation": "test",
}


# Form 1 (single-string): ``implementation 'g:a:v'`` /
#                          ``implementation "g:a:v"`` /
#                          ``implementation("g:a:v")``  (Kotlin).
# We match the config keyword anywhere a word-boundary precedes it (not
# just line-start) so single-line forms like
# ``dependencies { implementation 'g:a:v' }`` parse too.
_SINGLE_STRING_RE = re.compile(
    r"""\b(?P<config>[a-zA-Z]+)
        \s*\(?\s*
        (?P<quote>['"])
        (?P<coord>[A-Za-z0-9_.\-]+:[A-Za-z0-9_.\-]+(?::[^'"]+)?)
        (?P=quote)
    """,
    re.VERBOSE,
)

# Form 2 (named-args, Groovy):
#   implementation group: 'g', name: 'a', version: '1.2.3'
_NAMED_ARGS_RE = re.compile(
    r"""\b(?P<config>[a-zA-Z]+)\s*\(?\s*
        group\s*:\s*(?P<gq>['"])(?P<group>[^'"]+)(?P=gq)\s*,\s*
        name\s*:\s*(?P<nq>['"])(?P<name>[^'"]+)(?P=nq)\s*
        (?:,\s*version\s*:\s*(?P<vq>['"])(?P<version>[^'"]+)(?P=vq)\s*)?
    """,
    re.VERBOSE,
)

# Form 3 (Gradle version catalog accessor):
#   implementation(libs.spring.boot.starter)        // Kotlin DSL
#   implementation libs.spring.boot.starter         // Groovy
#   testImplementation libs.junit.jupiter
# The accessor ``libs.<x>.<y>.<z>`` derives from a TOML alias
# ``x-y-z`` (Gradle replaces ``-`` / ``_`` with ``.`` when
# generating the accessor). Resolution happens at parse time
# via the catalog map. Plugin form ``alias(libs.plugins.X)``
# is handled separately — plugin coords don't go through the
# dependency-config path.
_CATALOG_ACCESSOR_RE = re.compile(
    r"""\b(?P<config>[a-zA-Z]+)\s*\(?\s*
        libs\.(?P<accessor>[A-Za-z0-9_.]+)
    """,
    re.VERBOSE,
)
_PLUGIN_ACCESSOR_RE = re.compile(
    r"""\balias\s*\(?\s*libs\.plugins\.(?P<accessor>[A-Za-z0-9_.]+)
    """,
    re.VERBOSE,
)


@register(filenames=["build.gradle", "build.gradle.kts"])
def parse(path: Path) -> List[Dependency]:
    """Parse a Gradle build script and emit one Dependency per
    recognised dependency declaration."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as e:
        logger.warning("sca.parsers.gradle_dsl: %s: %s", path, e)
        return []

    out: List[Dependency] = []
    seen: set = set()

    for m in _SINGLE_STRING_RE.finditer(text):
        config = m.group("config")
        scope = _CONFIG_TO_SCOPE.get(config)
        if scope is None:
            continue
        coord = m.group("coord")
        parts = coord.split(":")
        if len(parts) < 2:
            continue
        group, name = parts[0], parts[1]
        version = parts[2] if len(parts) >= 3 else None
        dep = _build_dep(group, name, version,
                          scope=scope, declared_in=path)
        if dep is None or dep.key() in seen:
            continue
        seen.add(dep.key())
        out.append(dep)

    for m in _NAMED_ARGS_RE.finditer(text):
        config = m.group("config")
        scope = _CONFIG_TO_SCOPE.get(config)
        if scope is None:
            continue
        group = m.group("group")
        name = m.group("name")
        version = m.group("version")
        dep = _build_dep(group, name, version,
                          scope=scope, declared_in=path)
        if dep is None or dep.key() in seen:
            continue
        seen.add(dep.key())
        out.append(dep)

    # Gradle version-catalog accessors. ``libs.X.Y.Z`` resolves
    # via the catalog map at ``gradle/libs.versions.toml`` (the
    # documented default location). Without this path, ~80-100%
    # of dep coverage on modern Gradle solutions is lost — they
    # increasingly route every PackageReference through the
    # catalog.
    catalog = _resolve_catalog(path)
    if catalog is not None:
        accessor_to_alias = catalog.accessor_to_alias()
        # Library accessors — ``implementation(libs.spring.boot.starter)``.
        for m in _CATALOG_ACCESSOR_RE.finditer(text):
            config = m.group("config")
            scope = _CONFIG_TO_SCOPE.get(config)
            if scope is None:
                continue
            accessor = m.group("accessor")
            alias = accessor_to_alias.get(accessor)
            if alias is None:
                continue
            lib = catalog.libraries.get(alias)
            if lib is None:
                continue
            dep = _build_dep(
                lib.group, lib.artifact, lib.version,
                scope=scope, declared_in=path,
                source_origin=(
                    "gradle_catalog_ref"
                    if lib.version_via_ref else "gradle_catalog_inline"
                ),
                catalog_path=str(catalog.path),
                catalog_alias=alias,
                version_ref_name=lib.version_ref_name,
            )
            if dep is None or dep.key() in seen:
                continue
            seen.add(dep.key())
            out.append(dep)
        # Plugin accessors — ``alias(libs.plugins.kotlin.jvm)``.
        # Plugins are Maven-coordinated under ``com.gradle.plugin``
        # — we record them as Dependency rows so OSV matching can
        # detect plugin-vulns the same way it detects library-vulns.
        plugin_accessor_to_alias = {
            alias.replace("-", ".").replace("_", "."): alias
            for alias in catalog.plugins
        }
        for m in _PLUGIN_ACCESSOR_RE.finditer(text):
            accessor = m.group("accessor")
            alias = plugin_accessor_to_alias.get(accessor)
            if alias is None:
                continue
            plg = catalog.plugins.get(alias)
            if plg is None:
                continue
            # Gradle plugin IDs follow ``group.id`` convention;
            # the Maven coord is ``<plugin_id>:<plugin_id>.gradle.plugin``
            # (Gradle's "marker artifact" pattern).
            dep = _build_dep(
                plg.plugin_id,
                f"{plg.plugin_id}.gradle.plugin",
                plg.version,
                scope="build",
                declared_in=path,
                source_origin=(
                    "gradle_catalog_plugin_ref"
                    if plg.version_via_ref
                    else "gradle_catalog_plugin_inline"
                ),
                catalog_path=str(catalog.path),
                catalog_alias=alias,
                version_ref_name=plg.version_ref_name,
            )
            if dep is None or dep.key() in seen:
                continue
            seen.add(dep.key())
            out.append(dep)

    return out


_MAX_CATALOG_WALK_UP_DEPTH = 12


def _resolve_catalog(build_script_path: Path):
    """Find + parse the Gradle version catalog for a given
    build.gradle(.kts) file.

    Walks UP from the script's directory looking for
    ``gradle/libs.versions.toml`` (the documented default). Stops
    at the .git repo boundary so a nested project doesn't pick up
    a parent repo's catalog. Returns ``None`` when no catalog is
    found in the chain.

    Walk depth is capped at ``_MAX_CATALOG_WALK_UP_DEPTH`` as a
    defence-in-depth bound — same reasoning as
    ``parsers/directory_packages_props._find_msbuild_chain``: a
    target scanned without a ``.git`` directory (CI artefact,
    extracted tarball) would otherwise walk to ``/``.
    """
    from .gradle_version_catalog import (
        find_default_catalog, parse_libs_versions_toml,
    )

    try:
        current = build_script_path.parent.resolve()
    except OSError:
        return None
    visited: set = set()
    depth = 0
    while True:
        if current in visited:
            break
        visited.add(current)
        candidate = find_default_catalog(current)
        if candidate is not None:
            return parse_libs_versions_toml(candidate)
        if (current / ".git").exists():
            break
        depth += 1
        if depth >= _MAX_CATALOG_WALK_UP_DEPTH:
            break
        parent = current.parent
        if parent == current:
            break
        current = parent
    return None


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------

def _build_dep(
    group: str, name: str, version: Optional[str],
    *, scope: str, declared_in: Path,
    source_origin: str = "gradle_inline",
    catalog_path: Optional[str] = None,
    catalog_alias: Optional[str] = None,
    version_ref_name: Optional[str] = None,
) -> Optional[Dependency]:
    """Build a Gradle Dependency carrying source-origin metadata
    for the bumper.

    ``source_origin`` is one of:
      * ``"gradle_inline"`` — version came from the build script
        directly (single-string or named-args form).
      * ``"gradle_catalog_inline"`` — version came from a
        ``[libraries]`` entry with inline ``version="x"``.
      * ``"gradle_catalog_ref"`` — version came from a
        ``[libraries]`` entry's ``version.ref`` resolution against
        the ``[versions]`` table. Bumper targets the
        ``[versions]`` key (``version_ref_name``).
      * ``"gradle_catalog_plugin_inline"`` /
        ``"gradle_catalog_plugin_ref"`` — ditto for ``[plugins]``.

    Catalog confidence is bumped to ``high`` because catalog
    resolution is fully deterministic (TOML → version map);
    only the inline DSL forms keep the ``medium`` confidence
    from the regex-parse heuristic.
    """
    coord = f"{group}/{name}"
    pin_style = _classify_version(version)
    purl = _build_purl(group, name, version)
    is_catalog = source_origin.startswith("gradle_catalog")
    confidence_level = "high" if is_catalog else "medium"
    confidence_reason = (
        "Gradle version catalog — deterministic TOML resolution"
        if is_catalog else
        "Gradle DSL — heuristic regex parse "
        "(Turing-complete script not executed)"
    )
    source_extra = {"origin": source_origin}
    if catalog_path is not None:
        source_extra["catalog_path"] = catalog_path
    if catalog_alias is not None:
        source_extra["catalog_alias"] = catalog_alias
    if version_ref_name:
        source_extra["version_ref_name"] = version_ref_name

    return Dependency(
        ecosystem=ECOSYSTEM,
        name=coord,                          # Maven combined name
        version=version,
        declared_in=declared_in,
        scope=scope,
        is_lockfile=False,
        pin_style=pin_style,
        direct=True,
        purl=purl,
        parser_confidence=Confidence(
            confidence_level, reason=confidence_reason,
        ),
        source_kind="manifest",
        source_extra=source_extra,
    )


def _classify_version(version: Optional[str]) -> PinStyle:
    if version is None:
        return PinStyle.WILDCARD
    if "$" in version:
        # ``$version`` / ``${libs.versions.foo}`` — interpolation;
        # we can't resolve it.
        return PinStyle.UNKNOWN
    if version.startswith("[") or version.startswith("("):
        # Maven-style range: ``[1.0,2.0)``
        return PinStyle.RANGE
    if "+" in version and version.endswith("+"):
        # Gradle "dynamic version" e.g. ``1.+``
        return PinStyle.RANGE
    if version.endswith("-SNAPSHOT") or version == "latest.release":
        return PinStyle.RANGE
    return PinStyle.EXACT


def _build_purl(group: str, name: str, version: Optional[str]) -> str:
    base = f"pkg:{_PURL_TYPE}/{group}/{name}"
    if version:
        return f"{base}@{version}"
    return base


__all__ = ["parse"]
