"""Shared building blocks for manifest parsers.

Every parser used to hand-roll the same purl assembly; this module is
the single implementation. Per-ecosystem semantics stay at the call
site as explicit arguments (purl type, pre-canonicalised name,
namespace segment) — the shared helper only owns the assembly rule,
so an ecosystem can never be silently unified into another's
behavior.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ..models import Confidence, PinStyle

# Exception classes that escape the narrow per-library catches on
# hostile input, violating the parsers' never-raise contract:
# - RecursionError: recursive-descent parsers (tomllib, PyYAML) blow
#   the interpreter recursion limit — or CPython's C-stack guard —
#   on deeply nested input (e.g. ``"x = " + "[" * 5000``).
# - ValueError: raised outside the library's own error type, e.g.
#   CPython's int digit limit (sys.int_max_str_digits) firing inside
#   packaging's version normalisation on a 100k-digit version.
# MemoryError is deliberately NOT here: catching it invites
# corrupted-state continuation; the dispatcher's catch-all owns that
# terminal case. Catch as ``except (<LibError>, *PARSE_ESCAPE_ERRORS)``
# at every load site so a crafted manifest degrades to the standard
# warning + [] instead of reaching the dispatch catch-all as an
# anomaly with no structured reason.
PARSE_ESCAPE_ERRORS: tuple[type[Exception], ...] = (
    RecursionError,
    ValueError,
)

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path


def build_purl(
    purl_type: str,
    name: str,
    version: str | None,
    *,
    namespace: str | None = None,
) -> str:
    """Assemble ``pkg:<type>/[<namespace>/]<name>[@<version>]``.

    ``name`` is spliced verbatim — per-ecosystem canonicalisation
    (PEP 503 for PyPI, scoped ``@`` preserved for npm) is the
    CALLER's job, exactly as it was when each parser owned its own
    copy. ``namespace`` is the group segment for two-part
    coordinates (Maven ``group/artifact``). A falsy ``version``
    (None or empty) yields a version-less purl.
    """
    base = (
        f"pkg:{purl_type}/{namespace}/{name}"
        if namespace is not None
        else f"pkg:{purl_type}/{name}"
    )
    if version:
        return f"{base}@{version}"
    return base


def lockfile_confidence(
    pin_style: PinStyle,
    version: str | None,
    *,
    git_reason: str,
    path_reason: str,
    unversioned_reason: str,
    resolved_reason: str,
) -> Confidence:
    """The lockfile-family pin-confidence ladder: GIT source ->
    medium, PATH source -> medium, entry without version -> low,
    resolved entry -> high.

    The ladder is shared; the reason strings are the caller's
    per-ecosystem wording (a lockfile row without a version is
    anomalous, hence low — contrast the manifest ladder where
    unpinned is normal and only demotes to medium).
    """
    if pin_style is PinStyle.GIT:
        return Confidence("medium", reason=git_reason)
    if pin_style is PinStyle.PATH:
        return Confidence("medium", reason=path_reason)
    if version is None:
        return Confidence("low", reason=unversioned_reason)
    return Confidence("high", reason=resolved_reason)


def manifest_confidence(
    pin_style: PinStyle,
    version: str | None,
    *,
    unrecognised_reason: str,
    git_path_reason: str,
    unpinned_reason: str,
    pinned_reason: str,
) -> Confidence:
    """The manifest-family pin-confidence ladder: unrecognised spec
    -> low, git/path source -> medium, unpinned / wildcard -> medium,
    structured spec -> high.

    Reason strings are the caller's per-ecosystem wording.
    """
    if pin_style is PinStyle.UNKNOWN:
        return Confidence("low", reason=unrecognised_reason)
    if pin_style in (PinStyle.GIT, PinStyle.PATH):
        return Confidence("medium", reason=git_path_reason)
    if version is None:
        return Confidence("medium", reason=unpinned_reason)
    return Confidence("high", reason=pinned_reason)


# Walk-up bound shared by every ancestor-walking discovery helper
# (pnpm / npm workspace roots, MSBuild Directory.* chains, Gradle
# version catalogs). The scan-root / .git boundary is the primary
# stop signal; the cap is defence-in-depth for targets scanned
# without either (extracted tarball under a deep parent), where the
# walk would otherwise proceed to ``/`` and could adopt an
# out-of-tree file from a sibling checkout or the operator's own
# tree. Trade-off, both directions: raising the cap re-opens the
# out-of-scope adoption window on boundary-less scans; lowering it
# breaks legitimately deep monorepos (12 matches the deepest
# solution layouts seen in the wild — category/subcategory/service
# nesting).
_MAX_WALK_UP_DEPTH = 12


def iter_walk_up(
    start_dir: Path,
    *,
    include_start: bool = True,
    max_levels: int = _MAX_WALK_UP_DEPTH,
) -> Iterator[Path]:
    """Yield ``start_dir`` (resolved; its parent when it's a file)
    and its ancestors for cross-file discovery, bounded by:

    * the active scan root (when declared) — a config file ABOVE the
      scanned target must never steer resolution;
    * the nearest ``.git`` repo boundary;
    * ``max_levels`` yielded levels (defence-in-depth cap);
    * a visited-set symlink-loop guard.

    The bounding level itself IS yielded (a candidate at the repo /
    scan root is legitimate); the walk stops after it.  With
    ``include_start=False`` the start level is bound-checked but not
    yielded — the npm workspace-root shape, where only ancestors are
    eligible.
    """
    from . import _safe_read

    try:
        cur = start_dir.resolve()
    except OSError:
        return
    if cur.is_file():
        cur = cur.parent
    bound = _safe_read.active_scan_root()
    visited: set[Path] = set()
    first = True
    yielded = 0
    while yielded < max_levels:
        if cur in visited:      # symlink loop defence
            return
        visited.add(cur)
        if include_start or not first:
            yield cur
            yielded += 1
        if (bound is not None and cur == bound) or (cur / ".git").exists():
            return
        parent = cur.parent
        if parent == cur:
            return
        cur = parent
        first = False


__all__ = [
    "build_purl",
    "iter_walk_up",
    "lockfile_confidence",
    "manifest_confidence",
]
