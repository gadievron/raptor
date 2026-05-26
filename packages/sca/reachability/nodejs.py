"""Module-level reachability for npm deps.

Walks JS/TS sources under the target with a regex sweep that catches
the four common import shapes:

    require('foo')
    require("foo")
    import x from 'foo'
    import 'foo'         (side-effect-only)
    import('foo')        (dynamic)
    export ... from 'foo'

We do not parse the language. The implementation accepts the false-negative tail
(template literals in ``require(`${x}/foo`)``, JSX with computed
imports) — every miss only weakens the "imported" verdict, never
strengthens it. The vast majority of real production code is matched.

Specifier → package name:

- ``foo``                 → ``foo``
- ``foo/sub/path``        → ``foo``
- ``@scope/foo``          → ``@scope/foo``
- ``@scope/foo/sub``      → ``@scope/foo``
- ``./foo`` / ``../foo``  → relative; ignored (first-party code)
- ``/abs/foo``            → absolute path; ignored
- ``node:fs``             → built-in; ignored
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple

from ..models import Confidence, Reachability

logger = logging.getLogger(__name__)

# Match imports with single, double, or backtick quoted strings (no
# interpolation handled). A capturing group on the specifier is enough.
_REQUIRE_RE = re.compile(
    r"""
    (?:                                       # match either:
        \brequire\s*\(\s*['"`]([^'"`]+)['"`]\s*\)         # require(...)
      | \bimport\s*\(\s*['"`]([^'"`]+)['"`]\s*\)          # import(...)
      | \bimport\s+(?:[^'";]+?\bfrom\s+)?['"`]([^'"`]+)['"`]
                                                          # static import
      | \bexport\s+(?:.+?\s+from\s+)['"`]([^'"`]+)['"`]   # re-export
    )
    """,
    re.VERBOSE | re.MULTILINE | re.DOTALL,
)

# Directory exclusions live in ``_walker.py`` now — sourced from
# ``discovery.EXCLUDED_DIR_NAMES`` so a new entry there still
# propagates through the shared walk.

_TEST_DIR_NAMES: Set[str] = {"tests", "test", "__tests__", "spec", "e2e"}
_TEST_FILE_RE = re.compile(r".*\.(test|spec)\.[mc]?[jt]sx?$")

_JS_SUFFIXES = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}

_DEFAULT_MAX_DEPTH = 12

# Built-in / runtime modules ``import``-ed but not deps.
_BUILTINS: Set[str] = {
    "fs", "path", "os", "crypto", "http", "https", "stream", "events",
    "util", "url", "querystring", "buffer", "child_process", "cluster",
    "net", "dns", "tls", "vm", "zlib", "assert", "async_hooks",
    "console", "dgram", "domain", "module", "perf_hooks", "process",
    "punycode", "readline", "repl", "string_decoder", "timers",
    "tty", "v8", "worker_threads",
}


def scan_imports(
    target: Path, *, max_depth: int = _DEFAULT_MAX_DEPTH,
) -> Dict[str, List[Tuple[Path, int, bool]]]:
    """Return ``{package_name: [(file, line, is_test_code), ...]}``."""
    target = target.resolve()
    out: Dict[str, List[Tuple[Path, int, bool]]] = {}
    for js_file in _walk_js_sources(target, max_depth=max_depth):
        is_test = _is_test_file(js_file, target)
        try:
            text = js_file.read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            logger.debug("sca.reachability.nodejs: skip %s (%s)", js_file, e)
            continue
        for specifier, line in _imports_in(text):
            pkg = _specifier_to_package(specifier)
            if pkg is None:
                continue
            out.setdefault(pkg, []).append((js_file, line, is_test))
    return out


def resolve_dep(
    dep_name: str,
    scan: Dict[str, List[Tuple[Path, int, bool]]],
    *,
    target: Optional[Path] = None,
) -> Reachability:
    """Build a ``Reachability`` for an npm dep using the scan evidence."""
    hits = scan.get(dep_name, [])
    if not hits:
        return Reachability(
            verdict="not_reachable",
            confidence=Confidence(
                "medium",
                reason=f"no import/require for '{dep_name}' found",
            ),
            evidence=[],
        )

    non_test = [h for h in hits if not h[2]]
    if non_test:
        return Reachability(
            verdict="imported",
            confidence=Confidence(
                "high",
                reason="import/require found in non-test source",
            ),
            evidence=_format_evidence(non_test, target=target),
        )
    return Reachability(
        verdict="not_reachable",
        confidence=Confidence(
            "medium",
            reason="dep referenced only by test code",
        ),
        evidence=_format_evidence(hits, target=target),
    )


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------

def _imports_in(text: str) -> Iterable[Tuple[str, int]]:
    for m in _REQUIRE_RE.finditer(text):
        spec = next((g for g in m.groups() if g is not None), None)
        if not spec:
            continue
        line = text.count("\n", 0, m.start()) + 1
        yield spec, line


def _specifier_to_package(spec: str) -> Optional[str]:
    s = spec.strip()
    if not s:
        return None
    # Relative or absolute path → first-party / OS file. Not a dep.
    if s.startswith(("./", "../", "/")):
        return None
    # Node built-in via ``node:`` prefix.
    if s.startswith("node:"):
        return None
    # Plain built-in (``import 'fs'``).
    if s in _BUILTINS:
        return None
    # Scoped package: ``@scope/name`` or ``@scope/name/sub``.
    if s.startswith("@"):
        parts = s.split("/", 2)
        if len(parts) < 2:
            return None
        return f"{parts[0]}/{parts[1]}"
    # Bare or ``name/sub``.
    return s.split("/", 1)[0]


def _walk_js_sources(target: Path, *, max_depth: int) -> Iterable[Path]:
    # Delegates to the shared walker so the 8 reach scanners
    # collectively pay one ``os.walk`` per ``(target, max_depth)``
    # instead of seven redundant traversals.
    from ._walker import iter_source_files
    return iter_source_files(target, _JS_SUFFIXES, max_depth=max_depth)


def _is_test_file(path: Path, target: Path) -> bool:
    if _TEST_FILE_RE.match(path.name):
        return True
    try:
        rel = path.relative_to(target)
    except ValueError:
        rel = path
    return any(part in _TEST_DIR_NAMES for part in rel.parts)


def _format_evidence(
    hits: List[Tuple[Path, int, bool]],
    *,
    target: Optional[Path] = None,
    max_lines: int = 5,
) -> List[str]:
    out: List[str] = []
    for path, line, is_test in hits[:max_lines]:
        try:
            shown = path.relative_to(target) if target else path
        except ValueError:
            shown = path
        tag = " [test]" if is_test else ""
        out.append(f"{shown}:{line}{tag}")
    if len(hits) > max_lines:
        out.append(f"... and {len(hits) - max_lines} more")
    return out


__all__ = ["scan_imports", "resolve_dep"]
