"""Shared path-handling primitives — file:// stripping, repo-relative
normalisation, and containment ("confinement") checks.

Before this module existed the tree carried 13+ independent ``file://``
strippers (three of them substring-``replace`` variants that corrupt
paths containing a literal ``file://`` mid-string) and two same-named
``normalise_path`` helpers with OPPOSITE out-of-root semantics:

* ``core/inventory/lookup.normalise_path`` — best-effort, never returns
  ``None``; out-of-root absolute paths come back as ``../..``-style
  relatives (they simply fail to match any inventory key).
* ``core/analysis/reach_chokepoint.normalise_path`` — strict; returns
  ``None`` for out-of-root paths ("outside the analysed tree, do not
  suppress" — fail-open toward analysis).

Both semantics are intentional per-caller, so :func:`to_repo_relative`
carries them as an explicit ``outside_root`` mode instead of hiding the
divergence behind one name. What IS reconciled: relative-path
normalisation. The copies had drifted (lookup ``normpath``-ed, the
chokepoint only stripped a leading ``./``), so ``a/./b`` and ``a/../b``
spellings matched inventory keys through one helper but not the other.
This module normalises both modes identically (``os.path.normpath``),
and in ``"none"`` mode a relative path that still escapes the root
after normalisation (``../x``) returns ``None`` — an escaping path must
never license suppression.

Scope note: this module is purely lexical apart from
:func:`confine`, which resolves symlinks. SARIF-layer normalisation
with percent-decoding stays in ``core/sarif`` (the only layer that
``unquote``\\ s); adoption sweeps for the remaining strippers and
containment checks are follow-up work, site by site.
"""

from __future__ import annotations

import os
from pathlib import Path, PurePosixPath

__all__ = [
    "confine",
    "path_to_module",
    "strip_file_uri",
    "to_repo_relative",
]

_FILE_SCHEME = "file://"


def strip_file_uri(path: str) -> str:
    """Strip a LEADING ``file://`` scheme from *path*.

    ``file:///abs/path`` becomes ``/abs/path`` (the path stays
    absolute — callers decide containment). A ``file://`` appearing
    anywhere else in the string is left untouched: the substring-
    ``replace`` variants this consolidates would corrupt such paths.

    No percent-decoding: ``unquote`` is a SARIF-boundary concern and
    lives in ``core/sarif`` next to its containment checks.
    """
    if path.startswith(_FILE_SCHEME):
        return path[len(_FILE_SCHEME):]
    return path


def to_repo_relative(
    path: str,
    repo_root: str | Path,
    *,
    outside_root: str = "none",
) -> str | None:
    """Normalise *path* (absolute, relative, or ``file://`` URI) to a
    repo-relative form keyed the way inventories key their files.

    ``outside_root`` selects what happens when the path does not live
    under *repo_root*:

    * ``"none"`` — return ``None`` (strict; "outside the analysed
      tree"). Fail-open callers (suppression gates) use this so an
      out-of-root path never matches — and never suppresses. An empty
      *path* and a relative path that still escapes after
      normalisation (``../x``) also return ``None``.
    * ``"relative"`` — best-effort ``os.path.relpath`` (the result may
      contain ``..`` segments, and an un-relativisable path is
      returned unchanged). Never returns ``None``; lookup-style
      callers use this and simply fail to match.

    Relative paths are ``normpath``-normalised in both modes (``./``
    prefixes, ``a/./b``, ``a/../b``, doubled separators all collapse),
    matching the inventory ``files[].path`` convention.

    Purely lexical for the path itself; only *repo_root* is resolved
    (in ``"none"`` mode) so the containment test tolerates a symlinked
    root spelling.
    """
    if outside_root not in ("none", "relative"):
        raise ValueError(
            f"outside_root must be 'none' or 'relative', got {outside_root!r}"
        )
    strict = outside_root == "none"
    if strict and not path:
        return None
    path = strip_file_uri(path)
    if os.path.isabs(path):
        if strict:
            try:
                return str(Path(path).relative_to(Path(repo_root).resolve()))
            except (OSError, ValueError):
                return None
        try:
            path = os.path.relpath(path, str(repo_root))
        except ValueError:
            pass
        return os.path.normpath(path)
    norm = os.path.normpath(path)
    if strict and (norm == ".." or norm.startswith(".." + os.sep)):
        return None
    return norm


def path_to_module(rel_path: str) -> str | None:
    """``packages/foo/bar.py`` → ``packages.foo.bar``.

    For non-Python languages, strip the extension and replace path
    separators with dots — the call_graph extractor produces
    dotted-form keys for every language it covers. Returns ``None``
    for an empty path or one with no extension (can't derive a
    module). Windows separators are normalised first.

    ``foo/__init__.py`` maps to ``foo.__init__`` — the one divergent
    copy that collapsed ``__init__`` (core/analysis/reachability.
    _file_path_to_module) documents its own semantics and stays
    separate.
    """
    if not rel_path:
        return None
    p = PurePosixPath(rel_path.replace("\\", "/"))
    if not p.suffix:
        return None
    parts = list(p.with_suffix("").parts)
    if not parts:
        return None
    return ".".join(parts)


def confine(
    base: str | Path,
    candidate: str | Path,
) -> Path | None:
    """Join *base* / *candidate* and verify the result stays under
    *base* (or is *base* itself). Returns the resolved path, or
    ``None`` when the candidate escapes — traversal segments, an
    absolute path outside *base*, or a symlink pointing out.

    An absolute *candidate* is allowed as long as it resolves under
    *base* (``Path.__truediv__`` semantics: the absolute path wins the
    join, then containment decides) — the same contract as the SARIF
    parser's escape check. Resolution follows symlinks, so this is a
    filesystem-aware check, not a lexical one; the target need not
    exist.
    """
    base_path = Path(base)
    try:
        base_resolved = base_path.resolve()
        resolved = (base_path / candidate).resolve()
    except (OSError, RuntimeError, ValueError):
        return None
    if resolved == base_resolved or resolved.is_relative_to(base_resolved):
        return resolved
    return None
