"""Resolve CWE-dispatch CodeQL query IDs to on-disk query files.

The CWE dispatch table names standard-pack query IDs
(``cpp/overflow-buffer``) — the ``@id`` metadata of a query inside
CodeQL's published packs — but the sweep needs an on-disk ``.ql``
file, and nothing resolved one from the other: every chain-level
CodeQL step was gated out as unsupported, on every run, even with a
database present.  Same dead-channel class as a dispatch table whose
rule filenames resolve nowhere.

Resolution is mechanical and offline: locate the installed pack
roots (the CLI's ``resolve qlpacks`` answer, the package cache under
``~/.codeql/packages``, and the CLI distribution's bundled
``qlpacks/``), then index each relevant pack's ``.ql`` files by their
``@id`` header in one bounded walk, cached per process.  The CLI has
no direct id→file resolver, so the header scan against the installed
packs IS the mechanical route.  Unresolvable IDs return None and the
chain builder drops the step loudly-once.
"""

from __future__ import annotations

import json
import logging
import os
import re
import subprocess
import threading
from pathlib import Path

logger = logging.getLogger(__name__)

#: Query-ID language prefix → the standard pack that carries it.
_LANG_PREFIX_TO_PACK: dict[str, str] = {
    "cpp": "codeql/cpp-queries",
    "c": "codeql/cpp-queries",
    "py": "codeql/python-queries",
    "js": "codeql/javascript-queries",
    "java": "codeql/java-queries",
    "go": "codeql/go-queries",
    "rb": "codeql/ruby-queries",
    "cs": "codeql/csharp-queries",
    "swift": "codeql/swift-queries",
}

#: Table-controlled today, but validate anyway: a query id is a short
#: language prefix plus a slug.
_QUERY_ID_RE = re.compile(r"^[a-z]{1,8}/[A-Za-z0-9_.-]{1,80}$")

# Horizontal-only indent — the MULTILINE ^\s* idiom is quadratic
# on blank-line runs.
_ID_HEADER_RE = re.compile(r"^[^\S\n]*\*\s*@id\s+(\S+)", re.MULTILINE)

# One pack walk indexes every query, so even the biggest standard
# pack costs a single bounded directory scan per process.
_MAX_PACK_FILES = 20_000
_HEADER_READ_BYTES = 4096

_RESOLVE_QLPACKS_TIMEOUT_S = 30


def _version_key(name: str) -> tuple:
    """Numeric-component sort key for pack version directory names.

    Lexicographic reverse sort indexes a stale revision once any
    component reaches double digits ("0.9.0" > "0.10.0" as strings);
    numeric components compare as integers, non-numeric components
    fall back to string order behind numeric ones.
    """
    parts: list[tuple[int, int, str]] = []
    for comp in name.split("."):
        if comp.isdigit():
            parts.append((1, int(comp), ""))
        else:
            parts.append((0, 0, comp))
    return tuple(parts)

# pack name → {query id → absolute .ql path}; None marks "pack not
# found" so a missing pack is probed once, not per lookup.
_PACK_INDEX_CACHE: dict[str, dict[str, str] | None] = {}
# _CACHE_LOCK guards dict operations only. Pack indexing (a `codeql
# resolve qlpacks` subprocess + an up-to-_MAX_PACK_FILES rglob) runs
# under a PER-PACK lock so it computes once per pack without
# serialising concurrent resolvers of other packs behind it.
_CACHE_LOCK = threading.Lock()
_PACK_LOCKS: dict[str, threading.Lock] = {}


def clear_cache() -> None:
    """Test hook: drop the per-process pack indexes."""
    with _CACHE_LOCK:
        _PACK_INDEX_CACHE.clear()


def _cli_qlpack_roots(pack: str) -> list[Path]:
    """Pack roots from ``codeql resolve qlpacks`` (best-effort; the
    CLI's answer is search-path dependent and may miss the package
    cache — the direct probes below cover that)."""
    try:
        from core.config import RaptorConfig
        proc = subprocess.run(
            ["codeql", "resolve", "qlpacks", "--format=json"],
            capture_output=True, text=True,
            timeout=_RESOLVE_QLPACKS_TIMEOUT_S,
            env=RaptorConfig.get_safe_env(),
            # Neutral cwd: the CLI's pack search path is CWD-
            # influenced, and the answer must never depend on where
            # the audit process happens to run.
            cwd="/",
        )
        data = json.loads(proc.stdout or "{}")
    except Exception:  # noqa: BLE001 — CLI probe is one route of three
        return []
    roots = data.get(pack) if isinstance(data, dict) else None
    if not isinstance(roots, list):
        return []
    return [Path(r) for r in roots if isinstance(r, str)]


def _package_cache_roots(pack: str) -> list[Path]:
    """Versioned pack roots from the CodeQL package cache."""
    base = Path.home() / ".codeql" / "packages"
    scope, _, name = pack.partition("/")
    pack_dir = base / scope / name
    if not pack_dir.is_dir():
        return []
    versions = sorted(
        (d for d in pack_dir.iterdir() if d.is_dir()),
        key=lambda d: _version_key(d.name),
        reverse=True,
    )
    return versions[:1]  # newest version only


def _distribution_roots(pack: str) -> list[Path]:
    """Bundled qlpacks beside the CLI binary (offline distribution)."""
    import shutil

    cli = os.environ.get("CODEQL_CLI") or shutil.which("codeql")
    if not cli:
        return []
    dist = Path(os.path.realpath(cli)).parent / "qlpacks"
    scope, _, name = pack.partition("/")
    pack_dir = dist / scope / name
    if not pack_dir.is_dir():
        return []
    versions = sorted(
        (d for d in pack_dir.iterdir() if d.is_dir()),
        key=lambda d: _version_key(d.name),
        reverse=True,
    )
    return versions[:1] or [pack_dir]


def _pack_roots(pack: str) -> list[Path]:
    roots: list[Path] = []
    for candidate in (
        *_cli_qlpack_roots(pack),
        *_package_cache_roots(pack),
        *_distribution_roots(pack),
    ):
        if candidate.is_dir() and candidate not in roots:
            roots.append(candidate)
    return roots


def _index_pack(pack: str) -> dict[str, str] | None:
    """Build the ``@id`` → path index for *pack* (None: not found)."""
    roots = _pack_roots(pack)
    if not roots:
        return None
    index: dict[str, str] = {}
    seen_files = 0
    for root in roots:
        for ql in root.rglob("*.ql"):
            seen_files += 1
            if seen_files > _MAX_PACK_FILES:
                logger.warning(
                    "codeql query resolver: pack %s exceeds the %d-file "
                    "walk cap — index truncated", pack, _MAX_PACK_FILES,
                )
                return index
            try:
                with open(ql, encoding="utf-8", errors="replace") as fh:
                    header = fh.read(_HEADER_READ_BYTES)
            except OSError:
                continue
            m = _ID_HEADER_RE.search(header)
            if m and m.group(1) not in index:
                index[m.group(1)] = str(ql)
    return index


def resolve_query_id(query_id: str) -> str | None:
    """Map a dispatch-table query ID to an on-disk ``.ql`` file.

    Returns None when the ID is malformed, its pack is not installed,
    or no query in the pack carries that ``@id`` — callers degrade
    loudly-once and drop the chain step (never a phantom dispatch).
    """
    if not query_id or not _QUERY_ID_RE.match(query_id):
        return None
    prefix = query_id.split("/", 1)[0]
    pack = _LANG_PREFIX_TO_PACK.get(prefix)
    if pack is None:
        return None
    with _CACHE_LOCK:
        cached = pack in _PACK_INDEX_CACHE
        index = _PACK_INDEX_CACHE.get(pack)
        pack_lock = _PACK_LOCKS.setdefault(pack, threading.Lock())
    if not cached:
        with pack_lock:
            with _CACHE_LOCK:
                cached = pack in _PACK_INDEX_CACHE
                index = _PACK_INDEX_CACHE.get(pack)
            if not cached:
                index = _index_pack(pack)
                with _CACHE_LOCK:
                    _PACK_INDEX_CACHE[pack] = index
    if not index:
        return None
    path = index.get(query_id)
    if path and Path(path).is_file():
        return path
    return None
