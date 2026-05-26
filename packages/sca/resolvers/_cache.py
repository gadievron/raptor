"""Manifest-keyed cache for resolver dry-run results.

The cascade resolver layer (``packages/sca/resolvers/``) shells out to
language package managers (pip-compile, npm install --dry-run, etc.)
to validate that a proposed manifest resolves cleanly. For deep dep
trees the dry-run dominates wallclock — pip-compile on Python apps
like ``accelerate`` (PyTorch in the dep graph) measures at 110-180s
end-to-end, and SCA paid that cost on every scan even when the
manifest hadn't changed since the previous run.

This cache keys on ``(ecosystem, resolver_class, sha256(manifest_bytes))``
where ``manifest_bytes`` is the deterministic concatenation of the
resolver's declared manifest files. Two scans of the same fixture
hash to the same key; the second one returns the previously-cached
``ResolverResult`` without spawning the resolver subprocess.

Cache is invalidated by:
  * Any byte change to a declared manifest file (different hash).
  * 24h TTL — covers upstream registry drift (newly-published versions
    that match a manifest's range constraint and would extend the
    resolved tree). Short enough that an operator running daily scans
    sees fresh resolution at most a day stale.

Cache is NOT invalidated by:
  * Network state (we don't include reachability in the key).
  * Other files in the project_dir not declared in MANIFEST_FILES.
  * SCA version changes — operators can flush via the underlying
    JsonCache's eviction tooling if a resolver bug needs a re-resolve.

The cache layer is OPT-IN at the call site (``cached_dry_run`` /
``cached_dry_run_batch``) — direct ``resolver.dry_run`` paths in tests
and adversarial-fixture exploration stay subprocess-only.
"""

from __future__ import annotations

import base64
import hashlib
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from . import Resolver, ResolverResult

logger = logging.getLogger(__name__)

# 24h matches the OSV / KEV cache TTL. Manifest content hashes are
# stable; the cache only goes stale when upstream publishes a new
# version that matches a range constraint. Daily scans see fresh
# resolution at most a day late.
_DEFAULT_TTL = 24 * 3600


def _manifest_files(resolver: Resolver) -> Sequence[str]:
    """Return the resolver's declared input filenames.

    Resolvers opt in to caching by declaring a class-level
    ``MANIFEST_FILES`` tuple of relative filenames that constitute
    "the input that determines the resolution". When absent (a
    resolver that doesn't opt in), the cache wrapper falls through
    to a direct subprocess call — caching is strictly opt-in to
    avoid silently caching against the wrong inputs for resolvers
    we haven't audited.
    """
    return getattr(type(resolver), "MANIFEST_FILES", ())


def manifest_hash(
    resolver: Resolver, project_dir: Path,
) -> Optional[str]:
    """Compute a deterministic hash over the resolver's manifest files.

    Returns ``None`` if the resolver doesn't opt in (no
    ``MANIFEST_FILES``) OR if no declared file is present in
    ``project_dir`` (can't key on a non-existent input).

    Hash shape: SHA-256 of ``\\0``-separated ``<rel_path>\\0<bytes>``
    pairs, sorted by rel_path for deterministic order. Missing files
    are skipped silently — they don't contribute to the hash. A
    project that has only ``package.json`` (no lock) hashes the same
    way regardless of declaration order.
    """
    files = _manifest_files(resolver)
    if not files:
        return None
    parts: List[bytes] = []
    for rel in sorted(files):
        path = project_dir / rel
        if not path.is_file():
            continue
        try:
            payload = path.read_bytes()
        except OSError:
            # Read error → treat as absent. Subsequent uncached call
            # will surface the underlying error to the operator.
            continue
        parts.append(rel.encode("utf-8"))
        parts.append(b"\0")
        parts.append(payload)
        parts.append(b"\0")
    if not parts:
        return None
    h = hashlib.sha256()
    for p in parts:
        h.update(p)
    return h.hexdigest()


def _cache_key(resolver: Resolver, hsh: str) -> str:
    """Cache namespace: ``sca/resolvers/<eco>/<class>/<hash>``.

    Includes the resolver class name so a switch from npm → pnpm on
    the same project (different lockfile output shape) doesn't reuse
    a stale entry.
    """
    return (
        f"sca/resolvers/{resolver.ecosystem}"
        f"/{type(resolver).__name__}/{hsh}"
    )


def _serialise(result: ResolverResult) -> Dict[str, Any]:
    """Render a ``ResolverResult`` as a JSON-safe dict.

    ``proposed_lockfile`` is bytes — base64-encode for JSON-safe
    storage. The rest are plain types.
    """
    lockfile_b64 = (
        base64.b64encode(result.proposed_lockfile).decode("ascii")
        if result.proposed_lockfile is not None
        else None
    )
    return {
        "ecosystem": result.ecosystem,
        "success": result.success,
        "available": result.available,
        "proposed_lockfile_b64": lockfile_b64,
        "error": result.error,
        "raw_output": result.raw_output,
    }


def _deserialise(data: Dict[str, Any]) -> Optional[ResolverResult]:
    """Inverse of ``_serialise``. Returns None on shape mismatch so
    the caller falls back to a fresh subprocess call rather than
    handing a malformed result downstream.
    """
    if not isinstance(data, dict):
        return None
    try:
        eco = data["ecosystem"]
        success = data["success"]
        available = data["available"]
    except KeyError:
        return None
    if not isinstance(eco, str) or not isinstance(success, bool):
        return None
    if not isinstance(available, bool):
        return None
    lockfile_b64 = data.get("proposed_lockfile_b64")
    lockfile: Optional[bytes] = None
    if isinstance(lockfile_b64, str):
        try:
            lockfile = base64.b64decode(lockfile_b64.encode("ascii"))
        except (ValueError, TypeError):
            return None
    error = data.get("error")
    raw = data.get("raw_output", "")
    return ResolverResult(
        ecosystem=eco,
        success=success,
        available=available,
        proposed_lockfile=lockfile,
        error=error if isinstance(error, str) else None,
        raw_output=raw if isinstance(raw, str) else "",
    )


def cached_dry_run(
    resolver: Resolver,
    project_dir: Path,
    *,
    cache,
    timeout: int = 120,
    ttl_seconds: int = _DEFAULT_TTL,
) -> ResolverResult:
    """``resolver.dry_run`` with manifest-keyed memoisation.

    On cache hit, returns the cached ``ResolverResult`` without
    spawning the resolver subprocess — the typical 20-180s saving
    on cascade-heavy scans. On miss (or when the resolver doesn't
    declare ``MANIFEST_FILES``), runs the subprocess and caches
    successful results.

    Failed resolves (``success=False``) are cached too — a manifest
    that consistently fails to resolve fails just as fast on rerun.
    The cache persists until TTL or until the manifest content
    changes; an operator who fixes the manifest gets a fresh attempt
    via the new content hash.
    """
    hsh = manifest_hash(resolver, project_dir)
    if hsh is None:
        # Resolver doesn't opt in or no manifest present — fall
        # through. No cache pollution either way.
        return resolver.dry_run(project_dir, timeout=timeout)

    key = _cache_key(resolver, hsh)
    cached = cache.get(key, ttl_seconds=ttl_seconds)
    if isinstance(cached, dict):
        result = _deserialise(cached)
        if result is not None:
            logger.debug(
                "sca.resolvers.cache: hit %s/%s",
                resolver.ecosystem, type(resolver).__name__,
            )
            return result

    result = resolver.dry_run(project_dir, timeout=timeout)
    try:
        cache.put(key, _serialise(result), ttl_seconds=ttl_seconds)
    except Exception:                                   # noqa: BLE001
        # Cache write is best-effort; a write failure must not
        # propagate to the resolver caller. Logged at debug since
        # most cache backends never fail (filesystem JSON write).
        logger.debug(
            "sca.resolvers.cache: write failed for %s/%s",
            resolver.ecosystem, type(resolver).__name__,
            exc_info=True,
        )
    return result


def cached_dry_run_batch(
    resolver: Resolver,
    project_dirs: Sequence[Path],
    *,
    cache,
    common_root: Optional[Path] = None,
    timeout: int = 120,
    ttl_seconds: int = _DEFAULT_TTL,
) -> List[ResolverResult]:
    """Per-project memoised ``dry_run_batch``.

    Splits the input list into hits + misses by manifest hash:
    cached projects skip the subprocess entirely; uncached ones
    flow through the resolver's regular ``dry_run_batch`` (the
    PipResolver shared-venv batch path stays engaged for misses).

    Returns one result per input project_dir, in input order, mixing
    cache hits with fresh resolves.
    """
    from . import dry_run_batch as _dry_run_batch

    # Probe cache per project_dir.
    cached_results: Dict[int, ResolverResult] = {}
    miss_indices: List[int] = []
    miss_dirs: List[Path] = []
    for idx, project_dir in enumerate(project_dirs):
        hsh = manifest_hash(resolver, project_dir)
        if hsh is None:
            miss_indices.append(idx)
            miss_dirs.append(project_dir)
            continue
        key = _cache_key(resolver, hsh)
        raw = cache.get(key, ttl_seconds=ttl_seconds)
        if isinstance(raw, dict):
            result = _deserialise(raw)
            if result is not None:
                cached_results[idx] = result
                continue
        miss_indices.append(idx)
        miss_dirs.append(project_dir)

    if cached_results:
        logger.info(
            "sca.resolvers.cache: %d/%d projects served from cache "
            "(%s)",
            len(cached_results), len(project_dirs),
            type(resolver).__name__,
        )

    fresh: List[ResolverResult] = []
    if miss_dirs:
        fresh = _dry_run_batch(
            resolver, miss_dirs,
            common_root=common_root, timeout=timeout,
        )
        for project_dir, result in zip(miss_dirs, fresh):
            hsh = manifest_hash(resolver, project_dir)
            if hsh is None:
                continue
            key = _cache_key(resolver, hsh)
            try:
                cache.put(key, _serialise(result), ttl_seconds=ttl_seconds)
            except Exception:                           # noqa: BLE001
                logger.debug(
                    "sca.resolvers.cache: write failed", exc_info=True,
                )

    # Stitch results back in input order.
    out: List[ResolverResult] = [None] * len(project_dirs)  # type: ignore[list-item]
    for idx, result in cached_results.items():
        out[idx] = result
    for idx, result in zip(miss_indices, fresh):
        out[idx] = result
    return out


__all__ = [
    "cached_dry_run",
    "cached_dry_run_batch",
    "manifest_hash",
]
