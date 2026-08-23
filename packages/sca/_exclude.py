"""Shared ``--exclude <glob>`` matching for the SCA write paths.

``raptor-sca fix`` (all backends) and ``raptor-sca bump`` accept a
repeatable ``--exclude <glob>`` that removes matching surfaces from
the WRITE candidate set (patch hunks / in-place edits). Scanning is
deliberately untouched: findings in excluded trees remain valid and
reported; the operator is only declaring "do not edit these files".

The canonical use case is fixture protection: repos that pin
deliberately-old versions in test fixture manifests (the pins are
test assertions) exclude those trees in their CI bump jobs, e.g.::

    raptor-sca fix . --harden --exclude '**/tests/**' \
        --exclude '**/fixtures/**' --exclude '**/testdata/**'

Semantics — same convention as the bump policy's ``skip: path:``
rules (``packages/sca/bump/policy.py::_path_match``):

* patterns match the target-root-relative POSIX path via
  ``fnmatch.fnmatchcase`` — ``*`` already spans ``/``, so ``*`` and
  ``**`` behave alike;
* additionally, a leading ``**/`` also anchors at the root, so
  ``**/test/**`` matches both ``test/data/x`` (a root-level ``test``
  directory, which raw fnmatch would miss) and ``pkg/test/x``. This
  mirrors the gitignore-style expectation operators bring to ``**/``.
"""

from __future__ import annotations

from fnmatch import fnmatchcase
from pathlib import Path
from typing import Iterable, List, Optional, Sequence, Tuple, Union


def matches_exclude(
    path: Union[Path, str],
    patterns: Optional[Sequence[str]],
    *,
    root: Optional[Path] = None,
) -> bool:
    """True when ``path`` matches any operator ``--exclude`` glob.

    ``root`` (the scan target) anchors relative matching: an absolute
    ``path`` is made root-relative before matching, trying both the
    root as given and its resolved form (walkers hand back resolved
    paths). A path outside ``root`` — or a relative ``path`` — is
    matched as-is.
    """
    if not patterns:
        return False
    p = Path(path)
    if root is not None and p.is_absolute():
        for anchor in (Path(root), Path(root).resolve(strict=False)):
            try:
                p = p.relative_to(anchor)
                break
            except ValueError:
                continue
    rel = p.as_posix()
    for raw in patterns:
        pat = raw.replace("\\", "/")
        if fnmatchcase(rel, pat):
            return True
        if pat.startswith("**/") and fnmatchcase(rel, pat[3:]):
            return True
    return False


def partition_excluded(
    paths: Iterable[Union[Path, str]],
    patterns: Optional[Sequence[str]],
    *,
    root: Optional[Path] = None,
) -> Tuple[List[Path], List[Path]]:
    """Split ``paths`` into ``(kept, excluded)`` by ``--exclude`` globs.

    Order-preserving; with no patterns everything is kept.
    """
    kept: List[Path] = []
    excluded: List[Path] = []
    for p in paths:
        pp = Path(p)
        if matches_exclude(pp, patterns, root=root):
            excluded.append(pp)
        else:
            kept.append(pp)
    return kept, excluded


__all__ = ["matches_exclude", "partition_excluded"]
