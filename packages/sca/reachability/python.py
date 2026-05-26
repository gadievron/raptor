"""Module-level reachability for Python deps.

Walks ``*.py`` files under the target, ``ast.parse``-s each one, and
records every top-level module that's imported. The result is a map
from module-name → ``[(file, line), ...]`` evidence.

Dep-name → module-name mapping is heuristic:

1. Look up the dep name in ``_DIST_TO_MODULES`` for the popular cases
   where the distribution name (``pyyaml``) and the import name (``yaml``)
   diverge.
2. Fall back to the PEP 503 / PEP 8 module-name guess: lowercase + dashes
   replaced with underscores.

Module evidence comes from non-test files only — a ``.py`` file under
``tests/``, ``test/``, or matching ``test_*.py`` / ``*_test.py`` is
treated as test code and excluded from the "reachable" verdict (still
recorded as evidence with a ``test`` tag for triage). The exclusion
mirrors the discovery layer's vendored-tree skipping so we never scan
into ``node_modules``, ``.venv``, etc.
"""

from __future__ import annotations

import ast
import json
import logging
import warnings
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from ..models import Confidence, Reachability

logger = logging.getLogger(__name__)

# Directory exclusions are handled by ``_walker.py`` now — sourced
# from ``discovery.EXCLUDED_DIR_NAMES``. The python-specific
# ``site-packages`` exclusion is passed to ``iter_source_files`` at
# the call site below.

# Filename / directory patterns that mark test code. Reachability through
# test files alone shouldn't promote a dep to ``imported`` for production
# triage — it's still recorded but tagged. The detection logic is shared
# with supply-chain detectors via ``packages.sca._test_paths`` so a
# project's test corpus classifies the same way regardless of which
# layer is asking.
from .._test_paths import TEST_DIR_NAMES as _TEST_DIR_NAMES  # noqa: E402,F401
from .._test_paths import is_test_path as _is_test_file       # noqa: E402,F401

_DEFAULT_MAX_DEPTH = 12


# --- Distribution → import-module map --------------------------------------
# Curated list of the common cases where the PyPI distribution name differs
# from the importable module name. Far from exhaustive, but covers the long
# tail of "I installed pyyaml, why isn't `import pyyaml` working".
#
# Loaded at import time from ``packages/sca/data/python_module_map.json``.
# That JSON is what the cron-PR refresh workflow updates — keeping the data
# out of the code keeps source diffs clean when the bundled list grows.
# A missing or malformed JSON file falls back to an empty map; the
# heuristic PEP 503 / PEP 8 guess in ``_candidate_modules`` still fires
# and most projects resolve fine without the curated tier.
_MODULE_MAP_FILE = (
    Path(__file__).resolve().parents[1] / "data" / "python_module_map.json"
)


def _load_dist_to_modules() -> Dict[str, Tuple[str, ...]]:
    try:
        raw = json.loads(_MODULE_MAP_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        logger.warning(
            "sca.reachability.python: cannot load %s (%s); "
            "falling back to PEP 503 heuristic only",
            _MODULE_MAP_FILE, e,
        )
        return {}
    if not isinstance(raw, dict):
        logger.warning(
            "sca.reachability.python: %s is not a JSON object; ignoring",
            _MODULE_MAP_FILE,
        )
        return {}
    out: Dict[str, Tuple[str, ...]] = {}
    for k, v in raw.items():
        if not isinstance(k, str) or not isinstance(v, list):
            continue
        out[k.lower()] = tuple(s for s in v if isinstance(s, str))
    return out


_DIST_TO_MODULES: Dict[str, Tuple[str, ...]] = _load_dist_to_modules()


def scan_imports(
    target: Path, *,
    max_depth: int = _DEFAULT_MAX_DEPTH,
    cache=None,
) -> Dict[str, List[Tuple[Path, int, bool]]]:
    """Return ``{module_name: [(file, line, is_test_code), ...]}``.

    The boolean third tuple element marks whether the import lives in
    test code; downstream callers may treat test-only references as
    weaker evidence than production-source references.

    ``cache`` (a :class:`core.json.JsonCache`) is used to cache the
    per-file extracted ``[(module, line)]`` list keyed by file
    content hash — repeat scans of unchanged files skip the AST
    parse entirely. Pass ``None`` for the legacy uncached behaviour.
    """
    target = target.resolve()
    out: Dict[str, List[Tuple[Path, int, bool]]] = {}
    from .._file_scan_cache import cached_per_file
    for py_file in _walk_python_sources(target, max_depth=max_depth):
        is_test = _is_test_file(py_file, target)
        try:
            text = py_file.read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            logger.debug("sca.reachability.python: skip %s (%s)", py_file, e)
            continue

        def _compute(text=text, py_file=py_file):
            """Parse + extract per-file ``[(module, line)]`` pairs.
            Closed over ``text`` and ``py_file`` so the cache can call
            this lazily on a miss. Test-status is recomputed at
            retrieval time (depends on path + target, not file
            content) — caching it would require a path+target axis on
            the key for no real gain."""
            try:
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore", SyntaxWarning)
                    tree = ast.parse(text, filename=str(py_file))
            except SyntaxError as e:
                logger.debug(
                    "sca.reachability.python: ast parse failed for %s: %s",
                    py_file, e,
                )
                return []
            pairs: List[Tuple[str, int]] = []
            for node in ast.walk(tree):
                for top_module, line in _modules_from_node(node):
                    pairs.append((top_module, line))
            return pairs

        pairs = cached_per_file(
            cache, "reachability:py-imports", text, _compute,
        )
        for top_module, line in pairs:
            out.setdefault(top_module, []).append((py_file, line, is_test))
    return out


def resolve_dep(
    dep_name: str,
    scan: Dict[str, List[Tuple[Path, int, bool]]],
    *,
    target: Optional[Path] = None,
    version: Optional[str] = None,
    http: Optional[Any] = None,
    cache: Optional[Any] = None,
) -> Reachability:
    """Map a dep distribution name through three tiers of resolution
    (curated map → PEP 503 / 8 fallback → on-demand wheel-metadata
    fetch), then build a ``Reachability`` from the scan evidence.

    The third tier — fetching ``<dist>-<ver>.dist-info/top_level.txt``
    over HTTP Range — fires only when ``version``, ``http`` are
    supplied AND the first two tiers found no matches in the scan.
    Callers wire it in for CVE-bearing deps only, since each engaged
    fetch costs ~3 round-trips against the wheel CDN. ``cache``, if
    given, persists the (dist, version) → modules mapping forever
    (PyPI versions are immutable).
    """
    candidates = _candidate_modules(dep_name)
    hits = _hits_for_modules(candidates, scan)

    # Tier 3: if the first two tiers came up empty AND the caller
    # opted in (CVE-bearing dep, http available), consult the wheel.
    if not hits and version is not None and http is not None:
        try:
            from ..python_modules import resolve_modules
            wheel_modules = resolve_modules(
                dep_name, version, http=http, cache=cache,
            )
        except Exception as e:                  # noqa: BLE001
            # Don't let a transient registry hiccup break reachability —
            # the existing tier-1/2 verdict is still what we'd have
            # delivered without the fetch.
            logger.debug("python_modules.resolve_modules raised: %s", e)
            wheel_modules = None
        if wheel_modules:
            candidates = list(wheel_modules)
            hits = _hits_for_modules(candidates, scan)

    if not hits:
        return Reachability(
            verdict="not_reachable",
            confidence=Confidence(
                "medium",
                reason=(
                    "no import found for "
                    f"{dep_name} (modules tried: {', '.join(candidates)})"
                ),
            ),
            evidence=[],
        )

    non_test = [h for h in hits if not h[2]]
    if non_test:
        evidence = _format_evidence(non_test, target=target)
        return Reachability(
            verdict="imported",
            confidence=Confidence(
                "high",
                reason="import found in non-test source",
            ),
            evidence=evidence,
        )
    # Test-only — still meaningful (a dep used only in tests is genuinely
    # not in the production attack surface) but report at lower
    # confidence + a tag in evidence lines.
    evidence = _format_evidence(hits, target=target)
    return Reachability(
        verdict="not_reachable",
        confidence=Confidence(
            "medium",
            reason="dep referenced only by test code",
        ),
        evidence=evidence,
    )


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------

def _hits_for_modules(
    candidates: Iterable[str],
    scan: Dict[str, List[Tuple[Path, int, bool]]],
) -> List[Tuple[Path, int, bool]]:
    """Walk the scan and return every (file, line, is_test) hit whose
    module is one of ``candidates`` or a sub-module thereof.

    A ``from google.protobuf import descriptor`` import shows up in
    the scan keyed by ``google.protobuf`` (the top-level dotted form
    we resolved), so a candidate of ``google`` matches it too via
    the ``startswith(candidate + ".")`` check.
    """
    hits: List[Tuple[Path, int, bool]] = []
    for mod in candidates:
        for known in scan.keys():
            if known == mod or known.startswith(mod + "."):
                hits.extend(scan[known])
    return hits


def _candidate_modules(dep_name: str) -> List[str]:
    """Distribution → module candidates."""
    norm = dep_name.lower()
    explicit = _DIST_TO_MODULES.get(norm)
    if explicit is not None:
        return list(explicit)
    # Heuristic: PyPI canonical names use ``-``; importable modules use
    # ``_``. We try both because some distributions match either form
    # (e.g., ``foo-bar`` import as ``foo_bar`` *and* sometimes ``foo``).
    norm_underscore = norm.replace("-", "_")
    norm_dot = norm.replace("-", ".")
    cands: List[str] = [norm, norm_underscore]
    if norm_dot != norm and norm_dot != norm_underscore:
        cands.append(norm_dot)
    # Strip a leading ``python-`` prefix that's purely cosmetic on PyPI
    # (``python-dateutil``, ``python-magic``).
    if norm.startswith("python-"):
        cands.append(norm[len("python-"):])
        cands.append(norm[len("python-"):].replace("-", "_"))
    # De-dup while preserving order.
    seen: Set[str] = set()
    out: List[str] = []
    for c in cands:
        if c and c not in seen:
            seen.add(c)
            out.append(c)
    return out


def _modules_from_node(node: ast.AST) -> Iterable[Tuple[str, int]]:
    """Yield ``(module_name, line)`` for every dotted prefix of an import.

    For ``from google.protobuf import descriptor`` we yield both
    ``google`` and ``google.protobuf`` so the resolver can match against
    distributions whose canonical module name is the deeper prefix
    (``protobuf`` distribution → ``google.protobuf`` import).
    """
    if isinstance(node, ast.Import):
        for alias in node.names:
            for prefix in _dotted_prefixes(alias.name):
                yield prefix, node.lineno
    elif isinstance(node, ast.ImportFrom):
        if node.level > 0:
            # Relative import — refers to first-party packages, not deps.
            return
        if not node.module:
            return
        for prefix in _dotted_prefixes(node.module):
            yield prefix, node.lineno


def _dotted_prefixes(name: str) -> Iterable[str]:
    parts = name.split(".")
    for i in range(1, len(parts) + 1):
        yield ".".join(parts[:i])


def _walk_python_sources(target: Path, *, max_depth: int) -> Iterable[Path]:
    # Delegates to the shared walker (one ``os.walk`` per target
    # across all reach scanners). ``site-packages`` is the only
    # python-specific extra exclusion beyond
    # ``discovery.EXCLUDED_DIR_NAMES`` — passed as an extra dir name.
    from ._walker import iter_source_files
    return iter_source_files(
        target, {".py"}, max_depth=max_depth,
        extra_excluded_dir_names=frozenset({"site-packages"}),
    )


def _format_evidence(
    hits: List[Tuple[Path, int, bool]],
    *,
    target: Optional[Path] = None,
    max_lines: int = 5,
) -> List[str]:
    """Compact ``file:line`` lines, capped to keep findings.json small."""
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
