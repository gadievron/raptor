"""Auto-detect candidate binaries for binary_oracle enrichment.

Operator burden was the gating issue: ``--binary`` is powerful but
invisible — operators won't pass a flag they don't know about, and
even informed operators struggle to remember the build artifact paths
(``build/example``, ``build_o2/libfoo.so``, ``target/release/app``).

This module walks the target tree for plausible debug binaries — ELF
files with a ``.debug_info`` section — and returns them in a stable
order. The CLI exposes it via ``--binary auto``:

  raptor-codeql --target-kind=hybrid --binary auto <target>

For hybrid targets the heuristic includes BOTH library binaries
(``lib*.so*`` / ``lib*.a``) and executables; for library targets only
libraries; for application targets only executables.

Substrate-only — the CLI scripts call ``detect_binaries()`` and feed
the result into ``RaptorConfig.BINARY_ORACLE_PATHS``.
"""

from __future__ import annotations

import logging
import os
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import List, Literal, Optional, Tuple

logger = logging.getLogger(__name__)

# Common build-directory prefixes searched relative to the target root.
# Order matters — the first match in this list wins on collisions. The
# operator-explicit ``build/`` / ``target/release/`` rank above CMake's
# ``build_o2/`` (our own convention from the binary_oracle precision
# harness) so an existing operator build isn't overridden by a leftover
# harness cache.
_BUILD_DIRS: Tuple[str, ...] = (
    # Common single-binary / autotools / CMake
    "build",
    "build_o2",
    "build-release",
    "build-debug",
    "_build",
    # Rust cargo (cross-targeted release/debug omitted — covered by
    # the glob below)
    "target/release",
    "target/debug",
    # CMake conventions
    "cmake-build-release",
    "cmake-build-debug",
    "out/build",
    # Meson
    "builddir",
    # Bazel
    "bazel-bin",
    # Visual Studio / Xcode (Linux ports often produce these too)
    "Debug",
    "Release",
    # Generic dist / output
    "out",
    "dist",
    "bin",
)

# Rust cross-compile target dirs: ``target/<triple>/{release,debug}``
# (e.g. ``target/x86_64-unknown-linux-gnu/release``). Glob-matched at
# runtime so we don't have to enumerate every triple.
_RUST_TARGET_GLOBS: Tuple[str, ...] = (
    "target/*/release",
    "target/*/debug",
)

# How deep to walk inside a build dir before bailing. Bounded to stop
# accidental walks into a target like ``/usr`` if the operator pointed
# us at a system path.
_MAX_WALK_DEPTH = 5

# Default cap on auto-detect results. Exposed as a module constant
# so the CLI helper can warn when the cap is reached (operator likely
# needs to pass --binary explicitly for the binaries beyond the cap).
DEFAULT_MAX_RESULTS = 8

TargetKind = Literal["library", "application", "hybrid", "auto", "unknown"]


@dataclass(frozen=True)
class _Candidate:
    path: Path
    kind: Literal["library", "executable"]


def detect_binaries(
    target_root: Path,
    target_kind: TargetKind = "auto",
    *,
    max_results: int = 8,
) -> List[Path]:
    """Walk ``target_root`` for plausible debug binaries.

    ``target_kind`` shapes what's included:

      ``library``:     ``lib*.{so*,a}`` only
      ``application``: executables only
      ``hybrid`` / ``auto`` / ``unknown``: BOTH (the safe default —
                       picking the wrong filter here would silently drop
                       binaries the operator needed)

    Returns paths in deterministic order (alphabetical within each
    bucket; libraries before executables). Capped at ``max_results``
    so an operator who points at a build tree with thousands of test
    binaries doesn't get a 30-second classification run by accident.

    Filters out:
      * non-ELF files (no ``.debug_info`` checkable on PE/Mach-O here)
      * stripped binaries (no ``.debug_info`` section — classifier
        would return empty anyway, so no point including)
      * dotfiles and `.so.NUMBER` rotated logs that aren't real libs
    """
    target_root = Path(target_root)
    if not target_root.is_dir():
        return []

    candidates: List[_Candidate] = []
    # Expand the literal build-dir list with Rust cross-target globs
    # (``target/x86_64-unknown-linux-gnu/release`` etc.). Glob is
    # cheap — single readdir on ``target/`` — and avoids enumerating
    # every Rust triple in the literal list.
    expanded_dirs: List[str] = list(_BUILD_DIRS)
    for pattern in _RUST_TARGET_GLOBS:
        for hit in target_root.glob(pattern):
            if hit.is_dir():
                rel = hit.relative_to(target_root)
                expanded_dirs.append(str(rel))

    # Search the build dirs AND the target root itself at top-level
    # only — autotools-style builds (zlib, libsodium) emit binaries
    # in the source tree, not in a separate ``build/``. Top-level-
    # only scan keeps the walk cheap and avoids picking up test
    # binaries scattered through the tree.
    for build_dir_rel in (".", *expanded_dirs):
        build_dir = (target_root if build_dir_rel == "."
                     else target_root / build_dir_rel)
        if not build_dir.is_dir():
            continue
        # Top-level of target_root: only direct children (no recursion).
        # Deeper build dirs: walk recursively up to _MAX_WALK_DEPTH.
        walker = (build_dir.iterdir() if build_dir_rel == "."
                  else _walk_capped(build_dir))
        for p in walker:
            if not p.is_file():
                continue
            cand = _classify_candidate(p)
            if cand is None:
                continue
            if not _has_dwarf(cand.path):
                continue
            candidates.append(cand)

    if not candidates:
        return []

    # Dedup by resolved path (one .so symlinked from several names →
    # report once, prefer the SHORTEST path so libz.so beats
    # libz.so.1.3.1 on display).
    seen: dict = {}
    for c in candidates:
        resolved = c.path.resolve()
        existing = seen.get(resolved)
        if existing is None or len(str(c.path)) < len(str(existing.path)):
            seen[resolved] = c
    deduped = list(seen.values())

    # Apply target_kind filter.
    if target_kind == "library":
        deduped = [c for c in deduped if c.kind == "library"]
    elif target_kind == "application":
        deduped = [c for c in deduped if c.kind == "executable"]
    # hybrid / auto / unknown: keep both

    # Stable order: libraries first (often the deployed surface),
    # then executables, alphabetical within each.
    deduped.sort(key=lambda c: (
        0 if c.kind == "library" else 1, str(c.path),
    ))
    return [c.path for c in deduped[:max_results]]


def _walk_capped(root: Path):
    """Generator yielding paths under ``root`` up to ``_MAX_WALK_DEPTH``
    levels deep. Skips dotted directories (``.git``, ``.cache``).

    Symlink safety (adversarial review P0-D-2): use ``os.walk`` with
    ``followlinks=False`` so a symlink loop or a symlinked-in giant
    directory (``node_modules``, ``/usr``) can't drive the walk into
    an explosion. Also resolve each candidate and refuse anything
    that escapes ``root`` — a symlink target outside the project tree
    is not part of the analysed surface.
    """
    root_resolved = root.resolve()
    root_parts = len(root.parts)
    for dirpath, dirnames, filenames in os.walk(
            root, followlinks=False, topdown=True):
        d = Path(dirpath)
        depth = len(d.parts) - root_parts
        if depth > _MAX_WALK_DEPTH:
            dirnames[:] = []
            continue
        # Prune dotted subdirs in-place so os.walk doesn't descend.
        dirnames[:] = [n for n in dirnames if not n.startswith(".")]
        for fn in filenames:
            if fn.startswith("."):
                continue
            p = d / fn
            try:
                p_resolved = p.resolve()
                p_resolved.relative_to(root_resolved)
            except (OSError, ValueError):
                # Symlink target escapes root_resolved (or stat
                # error) — skip; not part of the analysed surface.
                continue
            if not p.is_file():
                continue
            yield p


# Library suffix: ``lib<name>.so`` / ``.so.N`` / ``.so.N.M`` / ``.a``.
# Strict suffix — must end with one of these forms; rejects
# split-debug companions (``.so.debug``, ``.dwo``, ``.dwp``),
# template stubs (``.so.in``, ``.so.tmpl``), backups (``.bak``,
# ``.old``), etc. (adversarial review P0-D-3).
_LIBRARY_NAME_RE = re.compile(
    r"^lib[A-Za-z0-9_.+\-]+\.(?:so(?:\.\d+)*|a)$"
)


# Executable scripts that carry the +x bit but aren't real ELF binaries.
# Skipping by suffix avoids paying a ``readelf -S`` subprocess per text
# file the walk encounters — and avoids relying on ``readelf`` to fail
# gracefully on a hostile-crafted hang/loop input (adversarial review
# Agent D P2: ``_has_dwarf`` fail-open lets a malicious binary that
# hangs readelf slip past the DWARF check).
_NON_BINARY_SUFFIXES = frozenset({
    ".sh", ".bash", ".zsh", ".ksh", ".csh",
    ".py", ".pl", ".rb", ".tcl", ".lua",
    ".cmake", ".in", ".am", ".ac", ".m4",
    ".txt", ".md", ".rst", ".cfg", ".conf",
    ".yaml", ".yml", ".json", ".toml", ".xml",
})
_NON_BINARY_NAMES = frozenset({
    "configure", "Makefile", "GNUmakefile",
    "autogen.sh", "bootstrap",
})


def _classify_candidate(p: Path) -> Optional[_Candidate]:
    """Library vs executable vs neither. Returns None when not a
    plausible debug binary."""
    name = p.name
    if _LIBRARY_NAME_RE.match(name):
        return _Candidate(path=p, kind="library")
    # Cheap-suffix reject before stat() / subprocess — keeps the
    # auto-detect walk fast on large trees.
    if name in _NON_BINARY_NAMES:
        return None
    if p.suffix in _NON_BINARY_SUFFIXES:
        return None
    # Executable: file mode +x.
    try:
        mode = p.stat().st_mode
    except OSError:
        return None
    if mode & 0o111 == 0:
        return None
    return _Candidate(path=p, kind="executable")


def _has_dwarf(path: Path) -> bool:
    """True if ``path`` is an ELF file with a ``.debug_info`` (or
    split-DWARF ``.debug_info.dwo``) section.

    Adversarial review Agent D P2: closed two fail-opens — (1) on
    ``OSError`` / ``TimeoutExpired`` (readelf missing, hung on hostile
    binary, sandbox-killed) the prior code returned ``True``, meaning a
    crafted ELF that hangs readelf would slip through to classification
    via foreign-DWARF; now reject (return False) on failure; (2) added
    ``.debug_info.dwo`` recognition for split-DWARF builds (clang's
    ``-gsplit-dwarf``, gcc's ``-gdwarf-split``) — without it, a perfectly
    valid split-DWARF binary was filtered out as if stripped.
    """
    try:
        out = subprocess.run(
            ["readelf", "-S", str(path)],
            capture_output=True, text=True, check=False, timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired) as e:
        logger.debug("binary_oracle_autodetect: readelf -S failed on %s: %s",
                     path, e)
        return False
    if out.returncode != 0:
        return False
    return ".debug_info" in out.stdout or ".debug_info.dwo" in out.stdout
