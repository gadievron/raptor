r"""Module-level reachability for Composer (PHP) deps.

Walks ``*.php`` files outside test trees, extracts ``use
<Namespace>\<Class>;`` statements, and matches against the dep's
PSR-4 namespace.

Heuristic: PHP package names are ``vendor/pkg`` (e.g.,
``symfony/console``), and PSR-4 namespaces typically PascalCase the
parts (``Symfony\Component\Console``). Without parsing the
package's own composer.json autoload section, we use two probes:

  1. **Vendor prefix**: a ``use Vendor\Anything`` statement (case-
     insensitive on the vendor) is evidence the package's vendor is
     used somewhere — coarse but useful when we don't know the
     package's exact namespace.
  2. **Pkg-name segment**: ``use Vendor\PkgName\...`` where
     ``PkgName`` matches the dep's pkg part (with kebab→Pascal
     conversion) is stronger evidence.

Confidence is ``medium`` because both probes can false-positive (other
packages from the same vendor) and false-negative (custom autoload
maps).
"""

from __future__ import annotations

import logging
import re

from ..models import Confidence, Reachability
from ._shared import format_evidence as _format_evidence
from ._shared import iter_matches_with_lines as _iter_matches_with_lines
from ..parsers import _safe_read
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterable
    from pathlib import Path

logger = logging.getLogger(__name__)


_DEFAULT_MAX_DEPTH = 12

_TEST_DIR_NAMES = {"tests", "test", "Tests", "Test", "spec"}

# ``use Vendor\Class;`` / ``use function Vendor\fn;`` / ``use const ...``
# Leading indent is HORIZONTAL-only ([^\S\n]): under MULTILINE the
# ``^\s*`` spelling re-scans a run of blank lines from every line
# start inside it — quadratic on attacker-supplied source files.
_PHP_USE_RE = re.compile(
    r"^[^\S\n]*use\s+(?:function\s+|const\s+)?"
    r"([A-Z][A-Za-z0-9_]*(?:\\[A-Za-z_][A-Za-z0-9_]*)*)",
    re.MULTILINE,
)


def scan_imports(
    target: Path, *, max_depth: int = _DEFAULT_MAX_DEPTH,
) -> dict[str, list[tuple[Path, int, bool]]]:
    r"""Return ``{namespace: [(file, line, is_test), ...]}``.

    ``namespace`` is the full ``Vendor\Class\...`` chain from the
    ``use`` statement.
    """
    target = target.resolve()
    out: dict[str, list[tuple[Path, int, bool]]] = {}
    for php_file in _walk_php_sources(target, max_depth=max_depth):
        is_test = _is_test_file(php_file, target)
        text = _safe_read.read_bounded(php_file, follow_symlinks=False)
        if text is None:
            continue
        for ns, line in _imports_in(text):
            out.setdefault(ns, []).append((php_file, line, is_test))
    return out


def resolve_dep(
    dep_name: str,
    scan: dict[str, list[tuple[Path, int, bool]]],
    *,
    target: Path | None = None,
) -> Reachability:
    r"""Match a Composer ``vendor/pkg`` dep against namespaces in the scan.

    Vendor prefix match (``Vendor\...``) yields ``imported`` with
    medium confidence; refining via pkg-name match boosts confidence.
    """
    if "/" not in dep_name:
        return Reachability(
            verdict="not_evaluated",
            confidence=Confidence(
                "low",
                reason="Composer dep without `vendor/pkg` shape",
            ),
            evidence=[],
        )
    vendor, pkg = dep_name.split("/", 1)
    vendor_pascal = _to_pascal(vendor)
    pkg_pascal = _to_pascal(pkg)

    pkg_matches: list[tuple[Path, int, bool]] = []
    vendor_only_matches: list[tuple[Path, int, bool]] = []
    for ns, hits in scan.items():
        head = ns.split("\\", 1)[0]
        if head.lower() != vendor_pascal.lower():
            continue
        # Pkg-name probe: second segment matches.
        parts = ns.split("\\", 2)
        if len(parts) >= 2 and parts[1].lower() == pkg_pascal.lower():
            pkg_matches.extend(hits)
        else:
            vendor_only_matches.extend(hits)

    matches = pkg_matches + vendor_only_matches
    if not matches:
        return Reachability(
            verdict="not_reachable",
            confidence=Confidence(
                "medium",
                reason=(f"no `use {vendor_pascal}\\...` found in "
                        f"non-test PHP source"),
            ),
            evidence=[],
        )

    non_test_pkg = [h for h in pkg_matches if not h[2]]
    non_test_vendor = [h for h in vendor_only_matches if not h[2]]

    if non_test_pkg:
        return Reachability(
            verdict="imported",
            confidence=Confidence(
                "medium",
                reason=(f"`use {vendor_pascal}\\{pkg_pascal}\\...` found "
                        f"in non-test source"),
            ),
            evidence=_format_evidence(non_test_pkg, target=target),
        )
    if non_test_vendor:
        return Reachability(
            verdict="imported",
            confidence=Confidence(
                "low",
                reason=(f"vendor `{vendor_pascal}\\...` referenced; "
                        f"pkg-segment match unconfirmed"),
            ),
            evidence=_format_evidence(non_test_vendor, target=target),
        )
    return Reachability(
        verdict="not_reachable",
        confidence=Confidence(
            "medium",
            reason="vendor referenced only by test code",
        ),
        evidence=_format_evidence(matches, target=target),
    )


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------

def _imports_in(text: str) -> Iterable[tuple[str, int]]:
    # Rolling-cursor line numbers — the naive full-prefix count is
    # quadratic on dense-use files.
    for m, line in _iter_matches_with_lines(
            text, _PHP_USE_RE.finditer(text)):
        yield m.group(1), line


def _to_pascal(name: str) -> str:
    """Convert ``my-pkg-name`` → ``MyPkgName``; preserve already-Pascal."""
    parts = re.split(r"[-_]+", name)
    return "".join(p[:1].upper() + p[1:] for p in parts if p)


def _walk_php_sources(
    target: Path, *, max_depth: int,
) -> Iterable[Path]:
    # PHP-specific extras: ``var/`` (Symfony cache+logs) and the
    # bare ``cache`` dir (some frameworks use it for compiled
    # templates). Both passed to the shared walker so other reach
    # scanners still see those subtrees.
    from ._walker import iter_source_files
    return iter_source_files(
        target, {".php"}, max_depth=max_depth,
        extra_excluded_dir_names=frozenset({"var", "cache"}),
    )


def _is_test_file(path: Path, target: Path) -> bool:
    rel_parts = path.relative_to(target).parts
    if any(p in _TEST_DIR_NAMES for p in rel_parts):
        return True
    return bool(path.stem.endswith(("Test", "Tests")))

