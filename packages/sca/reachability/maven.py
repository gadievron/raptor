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
groupId:artifactId → package-prefix to
``packages/sca/data/maven_package_map.json`` (cite the artifact's
actual import statements in the commit message).
"""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Iterable
from pathlib import Path

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
# groupId-doesn't-match-package cases (Jackson, Guava, Commons-*,
# SLF4J, Logback, HttpClient, spring-jcl).
#
# Loaded at import time from ``packages/sca/data/maven_package_map.json``
# — ecosystem metadata lives as a data file, like python_module_map.json,
# so the bundled list can grow without code diffs. A missing or
# malformed file falls back to an empty map; the groupId heuristics in
# ``_candidate_prefixes`` still fire and most coordinates resolve fine
# without the curated tier.
_PACKAGE_MAP_FILE = (
    Path(__file__).resolve().parents[1] / "data" / "maven_package_map.json"
)


def _load_package_overrides() -> dict[str, str]:
    try:
        raw = json.loads(_PACKAGE_MAP_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        logger.warning(
            "sca.reachability.maven: cannot load %s (%s); "
            "falling back to groupId heuristics only",
            _PACKAGE_MAP_FILE, e,
        )
        return {}
    if not isinstance(raw, dict):
        logger.warning(
            "sca.reachability.maven: %s is not a JSON object; ignoring",
            _PACKAGE_MAP_FILE,
        )
        return {}
    return {
        k: v for k, v in raw.items()
        if isinstance(k, str) and isinstance(v, str)
        and not k.startswith("_")
    }


_PACKAGE_OVERRIDES: dict[str, str] = _load_package_overrides()


def scan_imports(
    target: Path, *, max_depth: int = _DEFAULT_MAX_DEPTH,
) -> dict[str, list[tuple[Path, int, bool]]]:
    """Return ``{import_path: [(file, line, is_test), ...]}``."""
    target = target.resolve()
    out: dict[str, list[tuple[Path, int, bool]]] = {}
    for java_file in _walk_java_sources(target, max_depth=max_depth):
        is_test = _is_test_file(java_file, target)
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
    scan: dict[str, list[tuple[Path, int, bool]]],
    *,
    target: Path | None = None,
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

    matches: list[tuple[Path, int, bool]] = []
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


def _imports_in(text: str) -> Iterable[tuple[str, int]]:
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


def _is_test_file(path: Path, scan_root: Path | None = None) -> bool:
    """Heuristic test-file detection. Conservative — false positives
    only mark as test (lower confidence), never miss a real source.

    Relativises the path to ``scan_root`` before checking parts so
    that projects checked out under a directory named ``test`` (e.g.
    ``/home/test/myproject/``) don't misclassify every file.
    """
    if scan_root is not None:
        try:
            rel = path.relative_to(scan_root)
        except ValueError:
            rel = path
    else:
        rel = path
    parts = {p.lower() for p in rel.parts}
    if "test" in parts or "tests" in parts:
        return True
    name = path.stem
    return name.endswith("Test") or name.startswith("Test")


__all__ = ["resolve_dep", "scan_imports"]
