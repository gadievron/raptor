"""Persistent on-disk cache for reachability adjacency indices.

Sibling to :mod:`core.analysis.reachability`. The substrate's
in-process cache (``_INDEX_CACHE``) hits once per inventory
identity inside a single process; this module persists the
built index across processes so a cold start doesn't pay the
~300ms build cost every time.

Threat model: cache files live at ``~/.cache/raptor/reachability/``
mode 0600, dir mode 0700. The on-disk format is DATA-ONLY (a
versioned JSON document behind a magic header) — restored bytes are
decoded into plain dataclass fields, never executed. The historical
pickle format was retired because no amount of open-time gating
(O_NOFOLLOW, fstat, UID/mode, size, magic) can authenticate the
restored bytes themselves: a poisoned cache entry restored from a
backup/archive by the operator or CI passes every gate and
``pickle.loads`` is code execution. Corrupt / unparseable / legacy
cache files are silently treated as misses; the caller rebuilds.

Fingerprinting: the inventory's per-file ``sha256`` is the
authoritative content hash (build_inventory computes it). We
fold every file's sha256 into a single fingerprint plus a
schema-version constant so an index-shape change invalidates
all old cache entries without manual cleanup.

When the inventory lacks ``sha256`` on its files (test
fixtures, hand-built inventories), the fingerprint returns
``None`` and the persistent layer auto-disables — the in-
process cache is still active, just no disk-spill.

API:

  * :func:`compute_fingerprint` — ``inventory -> str | None``
  * :func:`load_index`            — ``fingerprint -> _AdjacencyIndex | None``
  * :func:`save_index`            — ``(fingerprint, index) -> None``
  * :func:`clear_cache`           — drop everything; returns count
  * :func:`cache_dir`             — accessor for tests / status output

Module is intentionally underscore-prefixed in the package
namespace; consumers go through :mod:`core.analysis.reachability`.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
from pathlib import Path
from typing import TYPE_CHECKING, Any

from core.atomic_fs import write_bytes_atomically

if TYPE_CHECKING:
    from .reachability import _AdjacencyIndex

logger = logging.getLogger(__name__)


# Bump when ``_AdjacencyIndex`` field shape changes (rename, type
# change, new mandatory field). Existing cache entries become misses
# automatically. Don't bump for pure additive changes that an old
# cache could still satisfy — the in-process build is fast enough
# that operators don't need version-skew sympathy.
#
# V4 (2026-05-16): per-language alias canonicalisation extended
# ``qualified_to_internal`` with ``<pkg>.<Class>.<method>`` entries
# for Java/C#/PHP/Rust/JS-TS/Ruby method definitions. An old V3
# cache returned ``InternalFunction(verdict=UNCERTAIN)`` for
# class-qualified queries that the new build would have resolved
# to ``CALLED``/``NOT_CALLED`` — a real correctness regression on
# stale caches, so this is a bump-worthy change.
#
# V5 (2026-05-17): index pass-2 fully-qualified-call fast-path
# promotes C++ ``ns::Util::helper()`` chains (and any other
# language's fully-qualified shape) from method_match_overinclusive
# to definitive forward/reverse edges. An old V4 cache would have
# returned these callers in ``method_match_overinclusive`` instead
# of ``definitive`` — same correctness shift, bump for parity.
# V6 (2026-05-23): _AdjacencyIndex grew a `framework_registered`
# field (S2: JS / Go function-as-argument framework registration
# via _FRAMEWORK_REGISTRATION_TAILS + CallSite.argument_identifiers).
# An old V5 cache returns _AdjacencyIndex instances without the
# new attribute — AttributeError on access by is_registered_via_call.
# V7 (2026-05-26): _AdjacencyIndex grew `override_methods` (CHA virtual-
# dispatch candidates). Same hazard: an old pickle lacks the attribute.
# V8 (2026-05-28): override_methods now seeded for Go methods (every
# Go method is a structural-interface virtual-dispatch candidate). Changed
# index contents; a V7 pickle would serve stale verdicts.
# V9 (2026-05-28): Rust now uses tree-sitter item extraction (impl→
# class assoc) + trait impls record the trait as a base → override_methods
# gains Rust trait-impl methods. Changed index contents; bump to rebuild.
# V10: on-disk format switched from pickle to data-only JSON (see the
# module docstring's threat model). Legacy pickle entries are ignored
# — different fingerprint (the version salts it), different suffix,
# different magic — and regenerated.
_CACHE_VERSION = 10

_CACHE_DIR = Path.home() / ".cache" / "raptor" / "reachability"

# A short header sentinel prefixed to each cache entry. Lets us
# version-bump the on-disk format without colliding with a stale
# entry of the same name. Also doubles as a cheap "is this a raptor
# cache file" check before handing bytes to the JSON decoder. The
# numeric suffix tracks ``_CACHE_VERSION``.
_HEADER_MAGIC = b"RAPTOR-REACHABILITY-CACHE-V10\n"

# Suffix of current-format entries. Legacy ``.pickle`` entries are
# never loaded, but eviction / clearing still sweeps them so retired
# files don't squat the cache dir forever.
_CACHE_SUFFIX = ".json"
_LEGACY_SUFFIXES = (".pickle",)

# Hard cap on cache-file size. A genuine reachability index for a
# kernel-scale target weighs in the low MB; anything past this is
# either corruption or an attacker who's planted a pathological file
# in the cache dir. Refuse rather than decode-DoS the process.
# 64 MiB is comfortably above the largest legitimate observed cache
# (linux kernel 6.x reachability index lands at ~12 MiB compressed).
_MAX_INDEX_BYTES = 64 * 1024 * 1024

# Maximum number of cache entries on disk. When exceeded after a save,
# the oldest entries (by mtime) are evicted.
_MAX_CACHE_ENTRIES = 32


def compute_fingerprint(inventory: dict[str, Any]) -> str | None:
    """Return a stable content fingerprint for ``inventory``, or
    ``None`` if the inventory lacks the per-file sha256 we need
    (test fixtures often do).

    The fingerprint folds:
      * ``_CACHE_VERSION``                         — schema-shape salt
      * sorted ``(path, sha256)`` over every file  — content shape

    Excluding ``mtime`` and other volatile fields is deliberate —
    two builds of the same source tree at different times should
    yield the same fingerprint.
    """
    files = inventory.get("files")
    if not isinstance(files, list) or not files:
        return None

    digest = hashlib.sha256()
    digest.update(f"v={_CACHE_VERSION}\n".encode("ascii"))
    # Sort by path so dict-insertion-order variation across builders
    # doesn't change the fingerprint.
    rows = []
    for fr in files:
        if not isinstance(fr, dict):
            continue
        path = fr.get("path")
        sha = fr.get("sha256")
        if not isinstance(path, str) or not isinstance(sha, str):
            # Missing sha256 on any file → can't form a stable
            # fingerprint. Bail out (auto-disable for this inventory).
            return None
        rows.append((path, sha))
    if not rows:
        return None
    rows.sort()
    for path, sha in rows:
        digest.update(path.encode("utf-8"))
        digest.update(b"\0")
        digest.update(sha.encode("ascii"))
        digest.update(b"\n")
    return digest.hexdigest()


_FINGERPRINT_RE = re.compile(r"^[0-9a-f]{64}$")


def _cache_path_for(fingerprint: str) -> Path | None:
    # Defense in depth: ``compute_fingerprint`` always returns a
    # SHA-256 hexdigest, but a future refactor could route an
    # attacker-controlled string here. Reject anything that isn't
    # exactly 64 lowercase hex chars so a fingerprint like
    # ``../../../tmp/poison`` cannot construct a path outside the
    # cache root. Returns ``None`` on rejection; callers treat it
    # as a cache miss / no-op write.
    if not isinstance(fingerprint, str) or not _FINGERPRINT_RE.match(fingerprint):
        logger.warning(
            "reach_cache: invalid fingerprint %r; refusing to construct path",
            fingerprint,
        )
        return None
    return _CACHE_DIR / f"{fingerprint}{_CACHE_SUFFIX}"


# ---------------------------------------------------------------------------
# Data-only codec for _AdjacencyIndex
#
# Node encoding: an InternalFunction becomes the 3-list
# ``[file_path, name, line]``; an ExternalFunction becomes its bare
# ``qualified_name`` string. The JSON type (list vs string)
# disambiguates on decode. Sets round-trip as lists; tuple-keyed
# dicts flatten into row lists. The decoder validates shapes and
# raises ValueError/TypeError on anything unexpected — load_index
# maps that to a cache miss.
# ---------------------------------------------------------------------------


def _index_to_jsonable(index: "_AdjacencyIndex") -> dict[str, Any]:
    from .reachability import InternalFunction

    def enc(node: Any) -> Any:
        if isinstance(node, InternalFunction):
            return [node.file_path, node.name, node.line]
        return node.qualified_name

    return {
        "forward": [
            [enc(src), [enc(d) for d in dsts]]
            for src, dsts in index.forward.items()
        ],
        "reverse": [
            [enc(dst), [enc(s) for s in srcs]]
            for dst, srcs in index.reverse.items()
        ],
        "uncertain_callers_by_tail": [
            [tail, [[enc(fn), ctx] for fn, ctx in pairs]]
            for tail, pairs in index.uncertain_callers_by_tail.items()
        ],
        "method_match": [
            [tail, [[enc(fn), cls] for fn, cls in pairs]]
            for tail, pairs in index.method_match.items()
        ],
        "uncertain_callees": [
            [enc(src), sorted(names)]
            for src, names in index.uncertain_callees.items()
        ],
        "has_method_dispatch": [
            [enc(src), bool(flag)]
            for src, flag in index.has_method_dispatch.items()
        ],
        "definitions": [
            [file_path, name, [enc(fn) for fn in fns]]
            for (file_path, name), fns in index.definitions.items()
        ],
        "class_of_method": [
            [enc(fn), cls] for fn, cls in index.class_of_method.items()
        ],
        "class_bases": [
            [file_path, cls, list(bases)]
            for (file_path, cls), bases in index.class_bases.items()
        ],
        "override_methods": [
            [cls, meth] for cls, meth in index.override_methods
        ],
        "framework_callable": [enc(fn) for fn in index.framework_callable],
        "framework_registered": [
            enc(fn) for fn in index.framework_registered
        ],
        "qualified_to_internal": [
            [qname, enc(fn)]
            for qname, fn in index.qualified_to_internal.items()
        ],
        "call_lines": [
            [enc(src), enc(dst), list(lines)]
            for (src, dst), lines in index.call_lines.items()
        ],
        "test_paths": sorted(index.test_paths),
    }


# Every field _index_to_jsonable writes. A well-formed cache entry
# carries all of them; anything less is foreign/corrupt → miss.
_MANDATORY_INDEX_FIELDS = frozenset({
    "forward", "reverse", "uncertain_callers_by_tail", "method_match",
    "uncertain_callees", "has_method_dispatch", "definitions",
    "class_of_method", "class_bases", "override_methods",
    "framework_callable", "framework_registered",
    "qualified_to_internal", "call_lines", "test_paths",
})


def _index_from_jsonable(data: dict[str, Any]) -> "_AdjacencyIndex":
    from .reachability import (
        ExternalFunction,
        InternalFunction,
        _AdjacencyIndex,
    )

    if not isinstance(data, dict):
        raise ValueError("index document must be a JSON object")
    missing = _MANDATORY_INDEX_FIELDS - data.keys()
    if missing:
        # save_index always writes every field; a document without
        # them (e.g. a bare ``{}`` planted under valid magic) is not a
        # cache entry this module produced → miss, not a valid empty
        # index.
        raise ValueError(
            f"index document missing mandatory fields: {sorted(missing)}"
        )

    def dec_internal(v: Any) -> Any:
        if (
            not isinstance(v, list) or len(v) != 3
            or not isinstance(v[0], str) or not isinstance(v[1], str)
            or not isinstance(v[2], int) or isinstance(v[2], bool)
        ):
            raise ValueError(f"bad internal-function record: {v!r}")
        return InternalFunction(file_path=v[0], name=v[1], line=v[2])

    def dec_node(v: Any) -> Any:
        if isinstance(v, str):
            return ExternalFunction(qualified_name=v)
        return dec_internal(v)

    def str_only(v: Any) -> str:
        if not isinstance(v, str):
            raise ValueError(f"expected string, got {v!r}")
        return v

    def opt_str(v: Any) -> str | None:
        if v is None:
            return None
        return str_only(v)

    def int_only(v: Any) -> int:
        if not isinstance(v, int) or isinstance(v, bool):
            raise ValueError(f"expected int, got {v!r}")
        return v

    def rows(key: str) -> list:
        value = data.get(key, [])
        if not isinstance(value, list):
            raise ValueError(f"field {key} must be a list")
        return value

    return _AdjacencyIndex(
        forward={
            dec_internal(src): {dec_node(d) for d in dsts}
            for src, dsts in rows("forward")
        },
        reverse={
            dec_node(dst): {dec_internal(s) for s in srcs}
            for dst, srcs in rows("reverse")
        },
        uncertain_callers_by_tail={
            str_only(tail): {
                (dec_internal(fn), str_only(ctx)) for fn, ctx in pairs
            }
            for tail, pairs in rows("uncertain_callers_by_tail")
        },
        method_match={
            str_only(tail): {
                (dec_internal(fn), opt_str(cls)) for fn, cls in pairs
            }
            for tail, pairs in rows("method_match")
        },
        uncertain_callees={
            dec_internal(src): {str_only(n) for n in names}
            for src, names in rows("uncertain_callees")
        },
        has_method_dispatch={
            dec_internal(src): bool(flag)
            for src, flag in rows("has_method_dispatch")
        },
        definitions={
            (str_only(file_path), str_only(name)):
                {dec_internal(fn) for fn in fns}
            for file_path, name, fns in rows("definitions")
        },
        class_of_method={
            dec_internal(fn): str_only(cls)
            for fn, cls in rows("class_of_method")
        },
        class_bases={
            (str_only(file_path), str_only(cls)):
                tuple(str_only(b) for b in bases)
            for file_path, cls, bases in rows("class_bases")
        },
        override_methods={
            (str_only(cls), str_only(meth))
            for cls, meth in rows("override_methods")
        },
        framework_callable={
            dec_internal(fn) for fn in rows("framework_callable")
        },
        framework_registered={
            dec_internal(fn) for fn in rows("framework_registered")
        },
        qualified_to_internal={
            str_only(qname): dec_internal(fn)
            for qname, fn in rows("qualified_to_internal")
        },
        call_lines={
            (dec_internal(src), dec_node(dst)): tuple(
                int_only(ln) for ln in lines
            )
            for src, dst, lines in rows("call_lines")
        },
        test_paths=frozenset(str_only(p) for p in rows("test_paths")),
    )


def load_index(fingerprint: str | None) -> _AdjacencyIndex | None:
    """Return the cached index for ``fingerprint``, or ``None`` if
    the cache is cold / corrupt / disabled.

    Disabled signals (return ``None`` without surfacing an error):
      * ``fingerprint is None`` — caller flagged the inventory as
        not fingerprintable.
      * cache dir missing — fresh install / cleared cache.
      * file missing — fingerprint not seen before.
      * magic header mismatch — file present but wrong format
        (manual edit, version skew with an unbumped constant,
        legacy pickle entry).
      * JSON decode / shape-validation failure — corrupted file.
    """
    if fingerprint is None:
        return None
    path = _cache_path_for(fingerprint)
    if path is None:
        return None
    if not path.exists():
        return None
    # UID + mode gate before decoding. The payload is data-only JSON
    # (never executed), so this gate is hygiene rather than the RCE
    # boundary it had to be under the retired pickle format — but a
    # foreign-owned or world-writable cache entry is still not a
    # trustworthy source of reachability verdicts. We refuse
    # to load any cache file not owned by the current user OR with
    # group/other write permission set. Closes:
    #   * Containerised builds where the cache was populated by
    #     one UID and the runtime user differs.
    #   * Symlink plants from a less-privileged process redirecting
    #     to attacker-writable content.
    #   * Multi-user dev hosts where another user could write to
    #     a shared ``~/.cache``.
    # TOCTOU defence: open the file ONCE, then validate via the
    # opened FD's fstat(). Pre-fix the path-based ``lstat()`` then a
    # separate ``read_bytes()`` left a race window where an attacker
    # who could win it could swap the inode between the two calls —
    # e.g. lstat sees a regular file, read_bytes reads a symlink. The
    # ``O_NOFOLLOW`` flag refuses to traverse a symlink at the
    # original path (Linux: opens fail with ELOOP). fstat on the FD
    # is authoritative for the actually-opened inode.
    import stat as _stat
    try:
        fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        return None
    except OSError as exc:
        logger.debug("reach_cache: open failed for %s: %s", path, exc)
        return None
    try:
        try:
            st = os.fstat(fd)
        except OSError as exc:
            logger.debug("reach_cache: fstat failed for %s: %s", path, exc)
            return None
        # ``O_NOFOLLOW`` already refused symlinks at the original
        # path, but a separate check covers the (paranoid) shape of
        # an O_NOFOLLOW-ignoring filesystem.
        if _stat.S_ISLNK(st.st_mode):
            logger.warning(
                "reach_cache: cache entry %s is a symlink — "
                "refusing to load",
                path,
            )
            return None
        if st.st_uid != os.getuid():
            logger.warning(
                "reach_cache: cache entry %s owned by uid=%d, current uid=%d — "
                "refusing to load",
                path, st.st_uid, os.getuid(),
            )
            return None
        if st.st_mode & 0o022:
            logger.warning(
                "reach_cache: cache entry %s has group/world write perms "
                "(mode=%o) — refusing to load",
                path, st.st_mode & 0o777,
            )
            return None
        # Short-circuit size check via ``st.st_size`` BEFORE any
        # read. Pre-fix we walked the read loop up to 64 MiB before
        # bailing on the running ``total > _MAX_INDEX_BYTES`` check
        # — fine for the legitimate case (cache files weigh single
        # MiB) but wasteful on a planted pathological file.
        if st.st_size > _MAX_INDEX_BYTES:
            logger.warning(
                "reach_cache: cache entry %s size %d exceeds %d bytes "
                "— refusing to load",
                path, st.st_size, _MAX_INDEX_BYTES,
            )
            return None
        try:
            # Read via os.read in a loop until EOF — read_bytes can't
            # take an fd directly. The pre-flight size check above
            # bounds total memory; the in-loop check stays as
            # defence-in-depth against TOCTOU file-growth between
            # fstat and the reads.
            chunks: list[bytes] = []
            total = 0
            while True:
                buf = os.read(fd, 1 << 20)
                if not buf:
                    break
                total += len(buf)
                if total > _MAX_INDEX_BYTES:
                    logger.warning(
                        "reach_cache: cache entry %s exceeds %d bytes — "
                        "refusing to load",
                        path, _MAX_INDEX_BYTES,
                    )
                    return None
                chunks.append(buf)
            blob = b"".join(chunks)
        except OSError as exc:
            logger.debug("reach_cache: load failed for %s: %s", path, exc)
            return None
    finally:
        try:
            os.close(fd)
        except OSError:
            pass
    if not blob.startswith(_HEADER_MAGIC):
        logger.debug(
            "reach_cache: cache file %s has wrong magic; ignoring", path,
        )
        return None
    try:
        idx = _index_from_jsonable(json.loads(blob[len(_HEADER_MAGIC):]))
    except (json.JSONDecodeError, UnicodeDecodeError, AttributeError,
            KeyError, IndexError, TypeError, ValueError,
            RecursionError) as exc:
        # Any decode or shape-validation failure — corruption, a
        # hand-edited file, a field renamed without a version bump —
        # is a cache miss; the consumer rebuilds and overwrites.
        # RecursionError: deeply nested JSON (``[[[[…``) blows the
        # interpreter stack inside json.loads — fail-to-miss, never
        # crash the consuming reachability pipeline.
        logger.debug(
            "reach_cache: decode failed for %s: %s "
            "(treating as miss)", path, exc,
        )
        return None
    return idx


def save_index(
    fingerprint: str | None,
    index: _AdjacencyIndex,
) -> None:
    """Persist ``index`` under ``fingerprint``. Atomic write
    (tempfile + rename) so a process crash mid-write can't leave a
    partial cache. mode 0600. ``fingerprint=None`` is a no-op."""
    if fingerprint is None:
        return
    path = _cache_path_for(fingerprint)
    if path is None:
        return
    try:
        _CACHE_DIR.mkdir(parents=True, exist_ok=True)
        os.chmod(_CACHE_DIR, 0o700)
    except OSError as exc:
        logger.debug("reach_cache: dir setup failed: %s", exc)
        return
    # Atomic write: reachability cache, mode=0o600 to preserve the
    # owner-only posture the previous mkstemp+chmod pattern installed.
    # Compact separators keep the adjacency rows dense; the format is
    # Python-version independent by construction (plain JSON).
    payload = _HEADER_MAGIC + json.dumps(
        _index_to_jsonable(index), separators=(",", ":"),
    ).encode("utf-8")
    try:
        write_bytes_atomically(
            path, payload,
            mode=0o600, tmp_prefix=".reach-tmp-",
        )
    except OSError as exc:
        logger.debug("reach_cache: write failed for %s: %s", path, exc)
        return
    _evict_oldest()


def _cache_entries() -> list:
    """Every cache entry on disk — current format plus retired
    legacy suffixes (never loaded, but swept by eviction/clearing
    so they don't squat the cache dir forever)."""
    entries: list = []
    for suffix in (_CACHE_SUFFIX, *_LEGACY_SUFFIXES):
        entries.extend(_CACHE_DIR.glob(f"*{suffix}"))
    return entries


def _evict_oldest() -> None:
    """Remove oldest cache entries (by mtime) when count exceeds cap."""
    try:
        entries = _cache_entries()
    except OSError:
        return
    if len(entries) <= _MAX_CACHE_ENTRIES:
        return

    # Sort by mtime ascending (oldest first). lstat + per-entry
    # fallback: a dangling symlink squatting the cache dir made a
    # plain ``p.stat()`` sort key raise, silently disabling eviction
    # forever (the entry cap was never enforced again). An entry we
    # cannot stat sorts oldest and gets evicted first.
    def _entry_mtime(p: Path) -> float:
        try:
            return p.lstat().st_mtime
        except OSError:
            return 0.0

    entries.sort(key=_entry_mtime)
    to_remove = len(entries) - _MAX_CACHE_ENTRIES
    for p in entries[:to_remove]:
        try:
            p.unlink()
        except OSError:
            pass


def clear_cache() -> int:
    """Delete every cache entry; return the count removed."""
    if not _CACHE_DIR.exists():
        return 0
    n = 0
    for p in _cache_entries():
        try:
            p.unlink()
            n += 1
        except OSError:
            pass
    return n


def cache_dir() -> Path:
    """Public accessor for the cache root."""
    return _CACHE_DIR


__all__ = [
    "cache_dir",
    "clear_cache",
    "compute_fingerprint",
    "load_index",
    "save_index",
]
