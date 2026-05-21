"""Persistent on-disk cache for reachability adjacency indices.

Sibling to :mod:`core.inventory.reachability`. The substrate's
in-process cache (``_INDEX_CACHE``) hits once per inventory
identity inside a single process; this module persists the
built index across processes so a cold start doesn't pay the
~300ms build cost every time.

Threat model: cache files live at ``~/.cache/raptor/reachability/``
mode 0600, dir mode 0700. An attacker with same-UID write access
can already do worse (rewrite ``~/.bashrc``, etc.), so the
trust boundary matches :mod:`core.sandbox.calibrate`. Pickle is
acceptable here under the same model. Corrupt / unparseable
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

  * :func:`compute_fingerprint` — ``inventory -> Optional[str]``
  * :func:`load_index`            — ``fingerprint -> Optional[_AdjacencyIndex]``
  * :func:`save_index`            — ``(fingerprint, index) -> None``
  * :func:`clear_cache`           — drop everything; returns count
  * :func:`cache_dir`             — accessor for tests / status output

Module is intentionally underscore-prefixed in the package
namespace; consumers go through :mod:`core.inventory.reachability`.
"""

from __future__ import annotations

import hashlib
import logging
import os
import pickle
import re
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, Optional

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
_CACHE_VERSION = 5

_CACHE_DIR = Path.home() / ".cache" / "raptor" / "reachability"

# A short header sentinel prefixed to each pickle. Lets us version-
# bump the on-disk format without colliding with a stale pickle of
# the same name. Also doubles as a cheap "is this a raptor cache
# file" check before handing bytes to ``pickle.load``. The numeric
# suffix tracks ``_CACHE_VERSION``.
_HEADER_MAGIC = b"RAPTOR-REACHABILITY-CACHE-V5\n"

# Hard cap on cache-file size. A genuine reachability index for a
# kernel-scale target weighs in the low MB; anything past this is
# either corruption or an attacker who's planted a pathological file
# in the cache dir. Refuse rather than pickle.loads-DoS the process.
# 64 MiB is comfortably above the largest legitimate observed cache
# (linux kernel 6.x reachability index lands at ~12 MiB compressed).
_MAX_INDEX_BYTES = 64 * 1024 * 1024


def compute_fingerprint(inventory: Dict[str, Any]) -> Optional[str]:
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


def _cache_path_for(fingerprint: str) -> Optional[Path]:
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
    return _CACHE_DIR / f"{fingerprint}.pickle"


def load_index(fingerprint: Optional[str]) -> Optional["_AdjacencyIndex"]:
    """Return the cached index for ``fingerprint``, or ``None`` if
    the cache is cold / corrupt / disabled.

    Disabled signals (return ``None`` without surfacing an error):
      * ``fingerprint is None`` — caller flagged the inventory as
        not fingerprintable.
      * cache dir missing — fresh install / cleared cache.
      * file missing — fingerprint not seen before.
      * magic header mismatch — file present but wrong format
        (manual edit, version skew with an unbumped constant).
      * pickle decode failure — corrupted file.
    """
    if fingerprint is None:
        return None
    path = _cache_path_for(fingerprint)
    if path is None:
        return None
    if not path.exists():
        return None
    # UID + mode gate before unpickling. ``pickle.loads`` is RCE-
    # equivalent on attacker-controlled input — the magic-byte
    # prefix check below is necessary but not sufficient. We refuse
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
        # nosemgrep: python.lang.security.deserialization.pickle.avoid-pickle
        # Trust analysis: cache path is ``~/.cache/raptor/
        # reachability/<fingerprint>.bin`` — RAPTOR's own cache dir
        # under the operator's home. Files are created with mode
        # ``0o600`` (owner-only) via O_EXCL atomic write
        # (no symlink-following). A magic-prefix sentinel
        # (``_HEADER_MAGIC``) guards format; mismatched files skip
        # the pickle path entirely. An attacker with write access
        # here has already broken the security boundary far worse
        # than pickle exposure. Accept pickle for fast cache
        # load/save of compiled adjacency indices over a code-
        # execution-class CWE that doesn't apply to this trust
        # profile.
        idx = pickle.loads(blob[len(_HEADER_MAGIC):])
    except (pickle.UnpicklingError, EOFError, AttributeError,
            ImportError, IndexError, TypeError, ValueError) as exc:
        # ``AttributeError`` / ``ImportError`` cover the case where a
        # class referenced inside the pickle was renamed or removed —
        # treat as cache miss; consumer will rebuild and overwrite.
        logger.debug(
            "reach_cache: pickle decode failed for %s: %s "
            "(treating as miss)", path, exc,
        )
        return None
    return idx


def save_index(
    fingerprint: Optional[str],
    index: "_AdjacencyIndex",
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
        # nosemgrep: python.lang.security.audit.insecure-file-permissions
        # 0o700 = owner-only — most restrictive POSIX mode.
        os.chmod(_CACHE_DIR, 0o700)
    except OSError as exc:
        logger.debug("reach_cache: dir setup failed: %s", exc)
        return
    try:
        fd, tmp_path = tempfile.mkstemp(
            prefix=".reach-tmp-", suffix=".pickle",
            dir=str(_CACHE_DIR),
        )
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(_HEADER_MAGIC)
                # ``protocol=4`` is supported on all Python versions
                # raptor targets and gives reasonable size/speed.
                # Avoid the latest protocol so a cache built on a
                # newer Python is still readable on older runtimes
                # in the same dev environment.
                pickle.dump(index, f, protocol=4)
            # nosemgrep: python.lang.security.audit.insecure-file-permissions
            # 0o600 = owner-only file mode (no group/other).
            os.chmod(tmp_path, 0o600)
            os.rename(tmp_path, path)
        except BaseException:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise
    except OSError as exc:
        logger.debug("reach_cache: write failed for %s: %s", path, exc)


def clear_cache() -> int:
    """Delete every cache entry; return the count removed."""
    if not _CACHE_DIR.exists():
        return 0
    n = 0
    for p in _CACHE_DIR.glob("*.pickle"):
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
    "compute_fingerprint",
    "load_index",
    "save_index",
    "clear_cache",
    "cache_dir",
]
