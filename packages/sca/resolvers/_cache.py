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
  * Other files outside the resolver's declared inputs (including dynamic input_files).
Resolver code, RAPTOR version, runtime/platform, effective environment,
tool file identity and resolver policy also invalidate the cache.

The cache layer is OPT-IN at the call site (``cached_dry_run`` /
``cached_dry_run_batch``) — direct ``resolver.dry_run`` paths in tests
and adversarial-fixture exploration stay subprocess-only.
"""

from __future__ import annotations

import base64
import hashlib
import logging
import os
import platform
import shutil
import sys
import stat
from typing import Any, TYPE_CHECKING
from pathlib import Path

from core.json import dumps_canonical

from . import Resolver, ResolverResult
from ._safe_io import read_regular_bytes
from ._proxy_hosts import _OVERRIDE_CONFIG_PATH

if TYPE_CHECKING:
    from collections.abc import Sequence

logger = logging.getLogger(__name__)

# 24h matches the OSV / KEV cache TTL. Manifest content hashes are
# stable; the cache only goes stale when upstream publishes a new
# version that matches a range constraint. Daily scans see fresh
# resolution at most a day late.
_DEFAULT_TTL = 24 * 3600
_MAX_INPUT_BYTES = 50 * 1024 * 1024


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
) -> str | None:
    """Hash the complete declared input set plus runtime/tool/policy identity.

    A resolver may supply input_files(project_dir) for dynamic input names.
    No inputs, refused files, unknown input closure or an aggregate byte-budget
    refusal bypass caching. Native resolution then reports its actual outcome.
    Regular-file records frame path length, path, byte length and content SHA-256
    so embedded separators cannot alias another project's input set.
    """
    input_files = getattr(resolver, "input_files", None)
    files = input_files(project_dir) if input_files is not None else _manifest_files(resolver)
    if not files:
        return None
    h = hashlib.sha256()
    context = _resolution_context(resolver)
    if context is None:
        return None
    h.update(context)
    readable = 0
    remaining = _MAX_INPUT_BYTES
    for rel in sorted(set(files)):
        path = project_dir / rel
        try:
            info = path.lstat()
        except FileNotFoundError:
            continue
        except OSError:
            return None
        if not stat.S_ISREG(info.st_mode) or info.st_size > remaining or remaining <= 0:
            return None
        rel_bytes = rel.encode("utf-8")
        payload = read_regular_bytes(path, max_bytes=remaining)
        if payload is None:
            return None
        h.update(b"F")
        h.update(len(rel_bytes).to_bytes(4, "big"))
        h.update(rel_bytes)
        h.update(len(payload).to_bytes(8, "big"))
        h.update(hashlib.sha256(payload).digest())
        remaining -= len(payload)
        readable += 1
    if readable == 0:
        return None
    return h.hexdigest()


def _resolution_context(resolver: Resolver) -> bytes | None:
    """Versioned cache identity for runtime, resolver code and effective policy.

    Only a digest is persisted. No environment values or credentials are stored.
    Ignore volatile launch/session/CI state; hash declared registry settings and
    the operator override without triggering proxy calibration or tool probes.
    Tool file identity changes invalidate cached results without executing probes.
    """
    from core.config import RaptorConfig
    names = (*getattr(resolver, "CACHE_ENV_KEYS", ()), "PATH", "HOME", "XDG_CONFIG_HOME",
             "JAVA_HOME", "RUSTUP_HOME", "CARGO_HOME", "GOPATH", "GOMODCACHE")
    env = {name: os.environ.get(name) for name in sorted(set(names))}
    override = read_regular_bytes(_OVERRIDE_CONFIG_PATH, max_bytes=1024 * 1024)
    if override is None and (_OVERRIDE_CONFIG_PATH.exists() or _OVERRIDE_CONFIG_PATH.is_symlink()):
        # Refused policy bytes cannot safely share a cache identity with absence.
        return None
    tools = []
    for tool in getattr(resolver, "CACHE_TOOLS", ()):
        path = shutil.which(tool, path=env.get("PATH"))
        try:
            st = os.stat(path) if path else None
            tools.append((path, st.st_size, st.st_mtime_ns, st.st_ino) if st else (None,))
        except OSError:
            tools.append((None,))
    module = sys.modules.get(type(resolver).__module__)
    module_file: str | None = getattr(module, "__file__", None) if module else None
    code = read_regular_bytes(Path(module_file)) if module_file else None
    return dumps_canonical({"schema": 2, "raptor_version": RaptorConfig.VERSION, "runtime": sys.version, "platform": platform.system() + "/" + platform.machine(),
                       "executable": sys.executable, "environment": env, "tools": tools,
                       "resolver": hashlib.sha256(code or b"").hexdigest(),
                       "sdist": getattr(resolver, "allow_sdist_builds", False),
                       "hosts": hashlib.sha256(override).hexdigest() if override is not None else None}).encode("ascii")


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


def _serialise(result: ResolverResult) -> dict[str, Any]:
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


def _deserialise(data: dict[str, Any]) -> ResolverResult | None:
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
    lockfile: bytes | None = None
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

    Failed resolves (``success=False``) are NEVER cached — a failure
    is often environmental (network, missing tool) and a cached one
    would keep reporting stale failures after the environment
    recovered; each rerun retries. Successful results persist until
    TTL or until the manifest content changes (fresh content hash).
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
    if not result.success:
        # Never cache failures: a transient one (registry outage,
        # timeout, throttling) would poison this manifest hash as
        # "failed" for the whole TTL — the next scan must retry.
        logger.debug(
            "sca.resolvers.cache: not caching failed resolve for "
            "%s/%s", resolver.ecosystem, type(resolver).__name__,
        )
        return result
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
    common_root: Path | None = None,
    timeout: int = 120,
    ttl_seconds: int = _DEFAULT_TTL,
) -> list[ResolverResult]:
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
    cached_results: dict[int, ResolverResult] = {}
    miss_indices: list[int] = []
    miss_dirs: list[Path] = []
    probe_hashes: dict[int, str] = {}
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
        probe_hashes[idx] = hsh
        miss_indices.append(idx)
        miss_dirs.append(project_dir)

    if cached_results:
        logger.info(
            "sca.resolvers.cache: %d/%d projects served from cache "
            "(%s)",
            len(cached_results), len(project_dirs),
            type(resolver).__name__,
        )

    fresh: list[ResolverResult] = []
    if miss_dirs:
        fresh = _dry_run_batch(
            resolver, miss_dirs,
            common_root=common_root, timeout=timeout,
        )
        for idx, result in zip(miss_indices, fresh, strict=True):
            hsh = probe_hashes.get(idx)
            if hsh is None:
                continue
            if not result.success:
                # Same rule as the single-project path: one shared
                # batch timeout used to poison EVERY manifest in the
                # batch as "failed" for a full TTL.
                continue
            key = _cache_key(resolver, hsh)
            try:
                cache.put(key, _serialise(result), ttl_seconds=ttl_seconds)
            except Exception:                           # noqa: BLE001
                logger.debug(
                    "sca.resolvers.cache: write failed", exc_info=True,
                )

    # Stitch results back in input order.
    out: list[ResolverResult] = [None] * len(project_dirs)  # type: ignore[list-item]
    for idx, result in cached_results.items():
        out[idx] = result
    for idx, result in zip(miss_indices, fresh, strict=True):
        out[idx] = result
    return out


__all__ = [
    "cached_dry_run",
    "cached_dry_run_batch",
    "manifest_hash",
]
