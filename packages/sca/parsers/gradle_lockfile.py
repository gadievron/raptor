"""gradle.lockfile parser — Gradle's dependency-locking output.

Format (one resolved coordinate per line):

    # comment
    ch.qos.logback:logback-classic:1.4.11=runtimeClasspath
    com.example:lib:1.0.0=annotationProcessor,compileClasspath,runtimeClasspath
    empty=annotationProcessor,compileClasspath

The trailing ``=`` lists Gradle configurations the dep contributes to.
We map those to a single scope by precedence (main > test > build);
the ``empty=...`` line is metadata, not a dep, and is skipped.

Direct/transitive cannot be derived from this file; ``direct=False``
unconditionally, and the join with ``build.gradle`` flips entries that
also appear in the manifest.
"""

from __future__ import annotations

import logging

from ..models import Confidence, Dependency, PinStyle
from . import _safe_read, register
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

logger = logging.getLogger(__name__)

ECOSYSTEM = "Maven"

# Configurations that count as production runtime / compile.
_MAIN_CONFIGS: set[str] = {
    "compileClasspath",
    "runtimeClasspath",
    "default",
    "apiElements",
    "runtimeElements",
    "implementation",
    "api",
    "compileOnly",
    "runtimeOnly",
    "compile",
    "runtime",
    "providedCompile",
    "providedRuntime",
}

# Test configurations — record as test only when no main config also
# claims the dep.
_TEST_CONFIGS: set[str] = {
    "testCompileClasspath",
    "testRuntimeClasspath",
    "testImplementation",
    "testCompileOnly",
    "testRuntimeOnly",
    "testApi",
    "testCompile",
    "testRuntime",
}

# Build-time only (annotation processors, plugin classpath, etc.).
_BUILD_CONFIGS: set[str] = {
    "annotationProcessor",
    "kapt",
    "ksp",
    "buildscript",
    "classpath",
}


def parse(path: Path) -> list[Dependency]:
    text = _safe_read.read_bounded(path, follow_symlinks=False)
    if text is None:
        # ``read_bounded`` already logged the underlying reason.
        return []

    deps: list[Dependency] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("empty="):
            # Sentinel listing configurations with no resolved deps.
            continue
        d = _parse_line(line, path)
        if d is not None:
            deps.append(d)
    return deps


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------

def _parse_line(line: str, path: Path) -> Dependency | None:
    if "=" not in line:
        return None
    coord, configs_text = line.split("=", 1)
    parts = coord.split(":")
    if len(parts) < 3:
        # Malformed; Gradle entries are always group:artifact:version.
        return None
    group, artifact, version = parts[0], parts[1], ":".join(parts[2:])
    if not group or not artifact or not version:
        return None

    configs = {c.strip() for c in configs_text.split(",") if c.strip()}
    scope = _scope_from_configs(configs)

    return Dependency(
        ecosystem=ECOSYSTEM,
        name=f"{group}:{artifact}",
        version=version,
        declared_in=path,
        scope=scope,
        is_lockfile=True,
        pin_style=PinStyle.EXACT,
        direct=False,
        purl=f"pkg:maven/{group}/{artifact}@{version}",
        parser_confidence=Confidence("high", reason="gradle.lockfile resolved row"),
    )


def _scope_from_configs(configs: set[str]) -> str:
    if configs & _MAIN_CONFIGS:
        return "main"
    if configs & _TEST_CONFIGS:
        return "test"
    if configs & _BUILD_CONFIGS:
        return "build"
    lc = {c.lower() for c in configs}
    if any("test" in c for c in lc):
        return "test"
    if any(kw in c for c in lc
           for kw in ("annotationprocessor", "kapt", "ksp")):
        return "build"
    return "main"


register(filenames=["gradle.lockfile"])(parse)
