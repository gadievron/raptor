"""Module-level reachability for Cargo (Rust) deps.

Walks ``*.rs`` files outside test/example/bench directories, collects
``use <crate>::...`` and ``extern crate <crate>;`` statements, and
matches against the dep's crate name.

Crate-name normalisation: Cargo names are kebab-case (``tokio-util``)
but ``use`` statements are snake_case (``tokio_util``). We normalise
both sides to ``-``-collapsed form for comparison.

A dep is considered reachable (``imported``) when at least one
``use``/``extern crate`` reference appears in non-test source.
Transitive deps are gated on direct-dep reachability — if ``serde``
isn't imported, ``serde_derive`` (a transitive of serde) isn't
reachable either. The join layer / consumer applies that gating.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

from ..models import Confidence, Reachability

logger = logging.getLogger(__name__)


_DEFAULT_MAX_DEPTH = 12

# Test/example/bench directories to skip (Rust convention).
_TEST_DIR_NAMES = {"tests", "examples", "benches", "fuzz"}

# ``use foo::...`` or ``use foo;`` or ``use foo as bar`` — captures the
# top-level crate identifier.
_USE_RE = re.compile(
    r"^\s*(?:pub\s+)?use\s+([A-Za-z_][A-Za-z0-9_]*)",
    re.MULTILINE,
)
# Legacy ``extern crate foo;`` form.
_EXTERN_RE = re.compile(
    r"^\s*extern\s+crate\s+([A-Za-z_][A-Za-z0-9_]*)",
    re.MULTILINE,
)


def scan_imports(
    target: Path, *, max_depth: int = _DEFAULT_MAX_DEPTH,
) -> Dict[str, List[Tuple[Path, int, bool]]]:
    """Return ``{normalised_crate: [(file, line, is_test), ...]}``."""
    target = target.resolve()
    out: Dict[str, List[Tuple[Path, int, bool]]] = {}
    for rs_file in _walk_rust_sources(target, max_depth=max_depth):
        is_test = _is_test_file(rs_file, target)
        try:
            text = rs_file.read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            logger.debug("sca.reachability.cargo: skip %s (%s)", rs_file, e)
            continue
        for crate, line in _imports_in(text):
            key = _normalise(crate)
            out.setdefault(key, []).append((rs_file, line, is_test))
    return out


def resolve_dep(
    dep_name: str,
    scan: Dict[str, List[Tuple[Path, int, bool]]],
    *,
    target: Optional[Path] = None,
) -> Reachability:
    """Look up ``dep_name`` in the scan; return a Reachability verdict."""
    key = _normalise(dep_name)
    hits = scan.get(key, [])
    if not hits:
        return Reachability(
            verdict="not_reachable",
            confidence=Confidence(
                "medium",
                reason=f"no `use {key}` / `extern crate {key}` found",
            ),
            evidence=[],
        )
    non_test = [h for h in hits if not h[2]]
    if non_test:
        return Reachability(
            verdict="imported",
            confidence=Confidence(
                "high",
                reason="`use`/`extern crate` found in non-test source",
            ),
            evidence=_format_evidence(non_test, target=target),
        )
    return Reachability(
        verdict="not_reachable",
        confidence=Confidence(
            "medium",
            reason="crate referenced only by test/example/bench code",
        ),
        evidence=_format_evidence(hits, target=target),
    )


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------

def _normalise(name: str) -> str:
    """Cargo names are case-insensitive PEP-503-style: collapse ``-``/``_``."""
    return re.sub(r"[-_]+", "-", name).lower()


def _imports_in(text: str) -> Iterable[Tuple[str, int]]:
    for m in _USE_RE.finditer(text):
        yield m.group(1), text.count("\n", 0, m.start()) + 1
    for m in _EXTERN_RE.finditer(text):
        yield m.group(1), text.count("\n", 0, m.start()) + 1


def _walk_rust_sources(
    target: Path, *, max_depth: int,
) -> Iterable[Path]:
    from ._walker import iter_source_files
    return iter_source_files(target, {".rs"}, max_depth=max_depth)


def _is_test_file(path: Path, target: Path) -> bool:
    """A Cargo non-library target: a file under a crate-root ``tests/`` /
    ``examples/`` / ``benches/`` / ``fuzz/`` directory, or a ``*_test.rs`` file.

    Cargo only treats those directory names as integration / example / bench
    targets at the CRATE ROOT. A module nested inside the library — e.g.
    ``src/foo/examples/bar.rs`` — is ordinary production code, so matching the
    name at any depth would misclassify it as test-only and wrongly downgrade
    the reachability of a dependency it uses (a false negative). Anchor to the
    first path component relative to the scanned crate root. (In a workspace
    where ``target`` is the workspace root, a nested crate's target dir is
    treated as production — the reachability-conservative direction.)
    """
    rel_parts = path.relative_to(target).parts
    if rel_parts and rel_parts[0] in _TEST_DIR_NAMES:
        return True
    if path.name.endswith("_test.rs"):
        return True
    return False


def _format_evidence(
    hits: List[Tuple[Path, int, bool]],
    *,
    target: Optional[Path],
    cap: int = 5,
) -> List[str]:
    out: List[str] = []
    for f, line, _ in hits[:cap]:
        rel = (f.relative_to(target) if target and target in f.parents
                else f)
        out.append(f"{rel}:{line}")
    if len(hits) > cap:
        out.append(f"... (+{len(hits) - cap} more)")
    return out
