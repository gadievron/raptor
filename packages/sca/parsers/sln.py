"""Visual Studio solution (``.sln``) parser.

Used by SCA NOT to extract dependencies directly (``.sln`` files
carry no package data) but to ENRICH the set of csproj files
discovered for scanning. A ``.sln`` lists every project in the
solution by relative path; some of those paths may live outside
the scan target's standard rglob view — for example, a monorepo
where ``src/AppA/AppA.sln`` references both ``src/AppA/AppA.csproj``
AND ``src/Shared/Shared.csproj``.

Without .sln awareness, scanning ``src/AppA/`` finds AppA but
misses Shared. With .sln awareness, the resolver follows the
solution's project graph and pulls Shared into the scan.

The format is a pre-XML legacy file — half text, half
``Project(GUID) = "name", "relpath", "GUID"`` lines. We parse the
Project lines with a regex; everything else (Global blocks, build
configurations, version metadata) is irrelevant for our purpose.

Modern Visual Studio also writes ``.slnx`` (XML format, 2024+) but
it's still preview-tier and rare in the wild. Adding it later is
straightforward — same `find_sln_referenced_csprojs` interface,
different parser body.

Security: ``.sln`` is plain text; no XXE / billion-laughs concern.
Path traversal is bounded to relative paths under the .sln's
parent dir (we reject absolute paths and ``..``-segments that
walk outside the bounded resolve).
"""

from __future__ import annotations

import logging
import re
from pathlib import Path, PurePosixPath
from typing import List, Optional, Set

from core.security.log_sanitisation import escape_nonprintable

from . import _safe_read

logger = logging.getLogger(__name__)

# Project(...) line:
#   Project("{TYPE-GUID}") = "<name>", "<relative-path>", "{PROJECT-GUID}"
# The relative-path is what matters; everything else is incidental.
# Match permissively (don't require matched quote style) so we
# tolerate operator hand-edits.
_PROJECT_LINE_RE = re.compile(
    r"""^Project\("\{[^}]+\}"\)\s*=\s*"""
    r""""[^"]*"\s*,\s*"(?P<path>[^"]+)"\s*,\s*"\{[^}]+\}"\s*$""",
    re.MULTILINE,
)

# C# / F# / VB project file suffixes we treat as MSBuild-managed.
# .sln entries also point at non-MSBuild project types (Solution
# Folders, .deployproj, .sqlproj, …) — we filter to the suffixes
# SCA's NuGet parser handles.
_PROJECT_SUFFIXES = {".csproj", ".fsproj", ".vbproj"}


def find_sln_referenced_csprojs(
    sln_path: Path, *, repo_root: Optional[Path] = None,
) -> List[Path]:
    """Read a ``.sln`` file and return absolute paths to every
    referenced csproj / fsproj / vbproj.

    Empty list when:
      * The file can't be read.
      * The file has no Project lines (empty / malformed solution).
      * No referenced project has a NuGet-recognised suffix.

    ``repo_root`` is the scan-target root. When provided, the
    traversal-bound check requires every resolved csproj path to
    live under ``repo_root``. When omitted (callers from older
    pathways), the looser "no more than one ``..`` segment past the
    .sln's parent dir" bound applies — backward-compatible but
    weaker. The discovery walker DOES pass ``repo_root``.

    Path resolution:
      * Each project path is relative to the .sln's parent dir.
      * Windows-style ``\\`` separators are normalised to ``/``.
      * Absolute paths are rejected up-front (``/`` prefix or
        Windows drive-letter — ``C:\\...``).
      * UNC paths (``\\\\server\\share``) and URL-encoded /
        percent-encoded segments are rejected. A hostile .sln
        line carrying ``%2e%2e/etc/passwd`` survives the
        ``.replace("\\", "/")`` normalisation but is caught
        here.
      * Literal ``..`` segments are rejected up-front BEFORE
        the ``(parent / rel).resolve()`` call, so a .sln cannot
        use ``..`` to escape ``repo_root`` even when symlinks
        are present in the resolution path.
      * Resolved paths that escape the bound (``repo_root`` if
        given, else .sln's grandparent) are rejected.
      * Paths that don't EXIST are silently dropped (no error;
        the .sln may reference a project that was deleted /
        renamed but the .sln wasn't updated).
      * Final candidates that ARE symlinks (lstat-check) are
        rejected — a target with ``X.csproj -> /etc/passwd``
        is hostile.

    Result is deduplicated and sorted for deterministic discovery
    ordering.
    """
    text = _safe_read.read_bounded(sln_path, follow_symlinks=False)
    if text is None:
        return []
    # ``.sln`` files often carry a UTF-8 BOM. ``read_bounded``
    # returns the raw decoded string; strip a leading BOM so the
    # first Project line still matches the line-anchored regex.
    if text.startswith("﻿"):
        text = text[1:]
    parent = sln_path.parent.resolve()
    if repo_root is not None:
        try:
            repo_root = repo_root.resolve()
        except OSError:
            repo_root = None
    found: Set[Path] = set()
    for match in _PROJECT_LINE_RE.finditer(text):
        rel = match.group("path").replace("\\", "/").strip()
        if not rel:
            continue
        if rel.startswith("/") or ":" in rel.split("/", 1)[0]:
            # Absolute path (POSIX or Windows drive-letter).
            # Real-world .sln files use relative paths; absolute
            # is either a hostile probe or a misconfigured
            # solution. Skip.
            logger.debug(
                "sca.parsers.sln: rejecting absolute path %r in %s",
                escape_nonprintable(rel),
                escape_nonprintable(str(sln_path)),
            )
            continue
        if "%" in rel:
            # URL / percent-encoded paths — ``%2e%2e/...`` survives
            # the backslash normalisation but is hostile in this
            # surface. Real .sln files never percent-encode paths.
            logger.debug(
                "sca.parsers.sln: rejecting percent-encoded path "
                "%r in %s",
                escape_nonprintable(rel),
                escape_nonprintable(str(sln_path)),
            )
            continue
        rel_parts = PurePosixPath(rel).parts
        if any("\x00" in part for part in rel_parts):
            # NUL-byte injection — a hostile .sln line embedding
            # ``foo.csproj\x00/../../../etc/passwd`` could confuse
            # downstream C-string consumers. Reject up-front.
            logger.debug(
                "sca.parsers.sln: rejecting NUL byte in %r "
                "(.sln=%s)",
                escape_nonprintable(rel),
                escape_nonprintable(str(sln_path)),
            )
            continue
        candidate = (parent / rel).resolve()
        # Path-traversal defence: ``repo_root`` is preferred when
        # the caller supplies it (discovery does). Fall back to
        # the .sln's grandparent for legacy callers — strictly
        # weaker but maintains backward compatibility.
        bound = repo_root if repo_root is not None else parent.parent
        try:
            candidate.relative_to(bound)
        except ValueError:
            logger.debug(
                "sca.parsers.sln: %r escapes the traversal bound "
                "%s; skipping (path traversal defence)",
                escape_nonprintable(rel),
                escape_nonprintable(str(bound)),
            )
            continue
        if candidate.suffix.lower() not in _PROJECT_SUFFIXES:
            continue
        # Reject symlinked final candidates — a target with
        # ``X.csproj -> /etc/passwd`` would leak the target's
        # contents into the XML parser's error logs.
        try:
            if candidate.is_symlink():
                logger.debug(
                    "sca.parsers.sln: %s is a symlink; skipping "
                    "(hostile-symlink defence)",
                    escape_nonprintable(str(candidate)),
                )
                continue
        except OSError:
            continue
        if not candidate.is_file():
            continue
        found.add(candidate)
    return sorted(found)


__all__ = ["find_sln_referenced_csprojs"]
