"""Module-level reachability for RubyGems deps.

Walks ``*.rb`` files outside Ruby's test conventions (``spec/``,
``test/``, ``features/``, ``__tests__/``), extracts ``require '...'`` /
``require_relative`` statements, and matches against the gem's name.

Caveats:
  - Some gems' require name differs from the gem name (e.g.
    ``rest-client`` requires as ``rest_client``). We try the exact gem
    name first, then a ``-`` → ``_`` normalised variant.
  - Bundler-generated stubs (``bundle exec``) sometimes omit the
    ``require`` because Bundler injects them; we'd miss those. Hence
    confidence is ``medium`` for not-reachable verdicts.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

from ..models import Confidence, Reachability

logger = logging.getLogger(__name__)


_DEFAULT_MAX_DEPTH = 12

_TEST_DIR_NAMES = {"spec", "test", "tests", "features", "__tests__"}

# ``require 'name'`` / ``require "name"`` — including possible ``::``
# subpaths (``require 'rails/all'``).
_REQUIRE_RE = re.compile(
    r"""^\s*(?:require|require_relative)\s+
        (['"])([^'"]+)\1""",
    re.MULTILINE | re.VERBOSE,
)


def scan_imports(
    target: Path, *, max_depth: int = _DEFAULT_MAX_DEPTH,
) -> Dict[str, List[Tuple[Path, int, bool]]]:
    """Return ``{require_target: [(file, line, is_test), ...]}``.

    Each ``require_target`` is the literal first-segment of the require
    string — ``require 'rails/all'`` keys on ``rails`` so a dep on
    ``rails`` matches.
    """
    target = target.resolve()
    out: Dict[str, List[Tuple[Path, int, bool]]] = {}
    for rb_file in _walk_ruby_sources(target, max_depth=max_depth):
        is_test = _is_test_file(rb_file, target)
        try:
            text = rb_file.read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            logger.debug("sca.reachability.gemfile: skip %s (%s)",
                          rb_file, e)
            continue
        for spec, line in _requires_in(text):
            head = spec.split("/", 1)[0]
            out.setdefault(head, []).append((rb_file, line, is_test))
    return out


def resolve_dep(
    dep_name: str,
    scan: Dict[str, List[Tuple[Path, int, bool]]],
    *,
    target: Optional[Path] = None,
) -> Reachability:
    """Look up ``dep_name`` in the scan, trying both the gem name and a
    ``-`` → ``_`` normalised variant."""
    candidates = {dep_name}
    if "-" in dep_name:
        candidates.add(dep_name.replace("-", "_"))
    elif "_" in dep_name:
        candidates.add(dep_name.replace("_", "-"))
    matches: List[Tuple[Path, int, bool]] = []
    for cand in candidates:
        matches.extend(scan.get(cand, []))

    if not matches:
        return Reachability(
            verdict="not_reachable",
            confidence=Confidence(
                "medium",
                reason=(f"no `require '{dep_name}'` found "
                        f"(also tried {sorted(candidates - {dep_name})})"),
            ),
            evidence=[],
        )
    non_test = [h for h in matches if not h[2]]
    if non_test:
        return Reachability(
            verdict="imported",
            confidence=Confidence(
                "high",
                reason="`require` found in non-test Ruby source",
            ),
            evidence=_format_evidence(non_test, target=target),
        )
    return Reachability(
        verdict="not_reachable",
        confidence=Confidence(
            "medium",
            reason="gem required only by spec/test code",
        ),
        evidence=_format_evidence(matches, target=target),
    )


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------

def _requires_in(text: str) -> Iterable[Tuple[str, int]]:
    for m in _REQUIRE_RE.finditer(text):
        yield m.group(2), text.count("\n", 0, m.start()) + 1


def _walk_ruby_sources(
    target: Path, *, max_depth: int,
) -> Iterable[Path]:
    # Ruby-specific extras: ``tmp/`` and ``log/`` (Rails
    # conventions). Both passed to the shared walker so other reach
    # scanners still see those subtrees.
    from ._walker import iter_source_files
    return iter_source_files(
        target, {".rb"}, max_depth=max_depth,
        extra_excluded_dir_names=frozenset({"tmp", "log"}),
    )


def _is_test_file(path: Path, target: Path) -> bool:
    rel_parts = path.relative_to(target).parts
    if any(p in _TEST_DIR_NAMES for p in rel_parts):
        return True
    if path.name.endswith("_spec.rb") or path.name.endswith("_test.rb"):
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
