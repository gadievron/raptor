"""Module-level reachability for Java / Maven deps.

Walks ``*.java`` files outside test trees, extracts ``import x.y.Z;``
statements (regular + static + wildcard), and matches each Maven
coordinate against the project's import set.

## Why this is heuristic, not authoritative

Unlike Go (where the import path *is* the module identifier) or
PyPI (curated module map + wheel metadata fallback), Maven
coordinates have no deterministic mapping to Java packages.
Examples that defeat the obvious "groupId is the package prefix"
guess:

  * ``com.fasterxml.jackson.core:jackson-databind`` ships
    ``com.fasterxml.jackson.databind.*`` — groupId path doesn't
    match.
  * ``com.google.guava:guava`` ships ``com.google.common.*`` —
    same problem.
  * ``commons-io:commons-io`` ships ``org.apache.commons.io.*`` —
    groupId is opaque.

To handle this without per-artifact registry queries (slow,
network-bound), the resolver tries multiple matching strategies:

  1. The groupId itself as a prefix (catches Spring, Hibernate,
     ASF orgs, the bulk of OSS Java)
  2. ``groupId.artifactId`` without ``-`` separators (catches the
     ``com.example.foo`` → ``com.example.foo`` shape)
  3. A curated override map for famous-mismatch artifacts
     (Jackson, Guava, Commons-IO, etc.) — see ``_PACKAGE_OVERRIDES``

When NONE match, we return ``not_evaluated`` — *not*
``not_reachable``. The risk score's ``not_reachable`` multiplier
is meaningful only when the resolver can confidently say "we
looked, no import matches"; without authoritative mapping data
we can't make that claim, so we preserve the prior verdict.

This means the Maven function-level reachability tier (which
gates on ``imported``) only fires when the heuristic finds a
match. Cases the heuristic misses stay at ``not_evaluated`` —
function-level tier doesn't fire, which matches the pre-this-PR
behaviour.

## Adding to the override map

When operators see a CVE for a dep that they KNOW is imported
but the report shows ``not_evaluated``, add the
groupId:artifactId → package-prefix to ``_PACKAGE_OVERRIDES`` with
a brief comment citing the artifact's actual import statements.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

from ..models import Confidence, Reachability

logger = logging.getLogger(__name__)


_DEFAULT_MAX_DEPTH = 12

# Java imports: ``import x.y.Z;``, ``import static x.y.Z.method;``,
# ``import x.*;``. Capture the dotted path before the optional
# wildcard / method tail.
_IMPORT_RE = re.compile(
    r"^\s*import\s+(?:static\s+)?([A-Za-z_][A-Za-z0-9_.]*)\s*(?:\.\*)?\s*;",
    re.MULTILINE,
)


# Curated artifact -> import-prefix overrides for the common
# groupId-doesn't-match-package cases. Each entry is a single
# package prefix; multi-package artifacts list the most common
# top-level prefix (sub-modules covered by prefix-matching).
#
# Sources are the artifact's actual ``META-INF/MANIFEST.MF`` /
# ``pom.xml`` declared packages. When in doubt verify with
# ``jar tf <artifact>.jar | head``.
_PACKAGE_OVERRIDES: Dict[str, str] = {
    # Jackson family — groupIds are ``com.fasterxml.jackson.<sub>`` but
    # imports use ``com.fasterxml.jackson.<artifact-suffix>``.
    "com.fasterxml.jackson.core:jackson-databind":
        "com.fasterxml.jackson.databind",
    "com.fasterxml.jackson.core:jackson-core":
        "com.fasterxml.jackson.core",
    "com.fasterxml.jackson.core:jackson-annotations":
        "com.fasterxml.jackson.annotation",
    # Guava
    "com.google.guava:guava": "com.google.common",
    # Commons-* — groupId/artifactId both ``commons-X`` but
    # imports go through Apache.
    "commons-io:commons-io": "org.apache.commons.io",
    "commons-codec:commons-codec": "org.apache.commons.codec",
    "commons-cli:commons-cli": "org.apache.commons.cli",
    "commons-logging:commons-logging": "org.apache.commons.logging",
    # SLF4J
    "org.slf4j:slf4j-api": "org.slf4j",
    # Logback
    "ch.qos.logback:logback-classic": "ch.qos.logback.classic",
    "ch.qos.logback:logback-core": "ch.qos.logback.core",
    # Apache HttpClient
    "org.apache.httpcomponents:httpclient": "org.apache.http",
    "org.apache.httpcomponents.client5:httpclient5":
        "org.apache.hc.client5",
    # Spring (groupId IS prefix for most, but a few sub-projects
    # collapse the group differently)
    "org.springframework:spring-jcl": "org.apache.commons.logging",
}


def scan_imports(
    target: Path, *, max_depth: int = _DEFAULT_MAX_DEPTH,
) -> Dict[str, List[Tuple[Path, int, bool]]]:
    """Return ``{import_path: [(file, line, is_test), ...]}``."""
    target = target.resolve()
    out: Dict[str, List[Tuple[Path, int, bool]]] = {}
    for java_file in _walk_java_sources(target, max_depth=max_depth):
        is_test = _is_test_file(java_file)
        try:
            text = java_file.read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            logger.debug(
                "sca.reachability.maven: skip %s (%s)", java_file, e,
            )
            continue
        for path, line in _imports_in(text):
            out.setdefault(path, []).append((java_file, line, is_test))
    return out


def resolve_dep(
    dep_name: str,
    scan: Dict[str, List[Tuple[Path, int, bool]]],
    *,
    target: Optional[Path] = None,
) -> Reachability:
    """Look up Maven ``groupId:artifactId`` in the scan.

    Returns ``imported`` when any of the heuristic prefixes matches
    a non-test import; otherwise ``not_evaluated`` (we don't know,
    rather than ``not_reachable`` — the heuristic isn't authoritative).
    """
    prefixes = list(_candidate_prefixes(dep_name))
    if not prefixes:
        return Reachability(
            verdict="not_evaluated",
            confidence=Confidence(
                "low",
                reason=(
                    f"Maven dep {dep_name!r} produced no candidate "
                    f"package prefixes (malformed coordinate?)"
                ),
            ),
            evidence=[],
        )

    matches: List[Tuple[Path, int, bool]] = []
    for import_path, hits in scan.items():
        for prefix in prefixes:
            if (
                import_path == prefix
                or import_path.startswith(prefix + ".")
            ):
                matches.extend(hits)
                break

    non_test = [h for h in matches if not h[2]]
    if non_test:
        return Reachability(
            verdict="imported",
            confidence=Confidence(
                "medium",
                reason=(
                    f"Java imports under {prefixes[0]!r} from "
                    f"{len({h[0] for h in non_test})} non-test "
                    f"file(s) (heuristic match)"
                ),
            ),
            evidence=[
                f"{p.name}:{ln}" for p, ln, _ in non_test[:3]
            ],
        )
    if matches:
        return Reachability(
            verdict="imported",
            confidence=Confidence(
                "low",
                reason=(
                    f"Java imports under {prefixes[0]!r} only from "
                    f"test files"
                ),
            ),
            evidence=[
                f"{p.name}:{ln}" for p, ln, _ in matches[:3]
            ],
        )
    return Reachability(
        verdict="not_evaluated",
        confidence=Confidence(
            "low",
            reason=(
                f"no Java import matched any candidate prefix "
                f"({', '.join(prefixes)!r}); Maven coord -> package "
                f"mapping is heuristic, dep may still be used"
            ),
        ),
        evidence=[],
    )


def _candidate_prefixes(dep_name: str) -> Iterable[str]:
    """Yield candidate Java package prefixes for a Maven coord.

    Order: explicit override (most precise) first, then heuristics.
    Caller short-circuits on first match.
    """
    if dep_name in _PACKAGE_OVERRIDES:
        yield _PACKAGE_OVERRIDES[dep_name]
        return
    if ":" not in dep_name:
        return
    group_id, artifact_id = dep_name.split(":", 1)
    # Heuristic 1: groupId as prefix (catches the bulk of OSS Java).
    yield group_id
    # Heuristic 2: groupId.artifactId-without-dashes.
    cleaned_artifact = artifact_id.replace("-", "").replace("_", "")
    if cleaned_artifact and cleaned_artifact != group_id.split(".")[-1]:
        yield f"{group_id}.{cleaned_artifact}"


def _imports_in(text: str) -> Iterable[Tuple[str, int]]:
    """Yield ``(import_path, line_number)`` for each ``import`` line."""
    for m in _IMPORT_RE.finditer(text):
        path = m.group(1)
        line = text.count("\n", 0, m.start()) + 1
        yield path, line


def _walk_java_sources(
    root: Path, *, max_depth: int,
) -> Iterable[Path]:
    """Yield ``*.java`` files under root, skipping vendored / build
    output / IDE tree noise. Test files are emitted but tagged
    ``is_test=True`` upstream."""
    # Java-specific extras beyond ``discovery.EXCLUDED_DIR_NAMES``:
    # ``.mvn`` (Maven wrapper config), ``bin``/``obj`` (Eclipse +
    # mixed C/C# output dirs that show up in polyglot trees).
    from ._walker import iter_source_files
    return iter_source_files(
        root, {".java"}, max_depth=max_depth,
        extra_excluded_dir_names=frozenset({".mvn", "bin", "obj"}),
    )


def _is_test_file(path: Path) -> bool:
    """Heuristic test-file detection. Conservative — false positives
    only mark as test (lower confidence), never miss a real source."""
    parts = {p.lower() for p in path.parts}
    if "test" in parts or "tests" in parts:
        return True
    name = path.stem
    return name.endswith("Test") or name.startswith("Test")


__all__ = ["scan_imports", "resolve_dep"]
