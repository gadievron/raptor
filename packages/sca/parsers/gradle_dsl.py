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

    return out


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------

def _build_dep(
    group: str, name: str, version: Optional[str],
    *, scope: str, declared_in: Path,
) -> Optional[Dependency]:
    coord = f"{group}/{name}"
    pin_style = _classify_version(version)
    purl = _build_purl(group, name, version)
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
            "medium",
            reason=("Gradle DSL — heuristic regex parse "
                    "(Turing-complete script not executed)"),
        ),
        source_kind="manifest",
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
