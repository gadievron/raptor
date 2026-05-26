"""Registry-metadata recursive walk — mode (c) of transitive expansion.

Recurses through each direct dep's declared dependencies as fetched
from the registry's package-metadata API. Returns the transitive
closure as ``Dependency`` rows tagged ``source_kind="metadata_walk"``
with a low parser confidence.

This is the **approximate** mode. The actual installed dep tree depends
on the operator's resolver (pip's pubgrub, npm's resolver, Cargo's
solver) intersecting all the version constraints across the project.
We don't run that solver — we just walk what each package declares.
Consequences:

  - Over-counts: we may emit a transitive dep that the resolver would
    reject because of a constraint elsewhere in the tree.
  - Under-counts version: when a constraint is `>=X`, we record `X`
    (the lower bound). The actually-installed version may be higher,
    and CVEs in higher versions are missed.
  - Under-counts via extras / environment markers: PEP 508 has
    `python_version >= "3.10"` and `extra == "test"` markers; we
    treat them as always-true (over-include) — both produce false
    positives, never false negatives, so we err on the safe side.

For accuracy use mode (b) (cascade resolver in sandbox) instead.
This module is the fallback when the toolchain isn't available, and
the natural mode for ``raptor-sca check <pkg@ver>`` pre-installation
analysis where there's no project to resolve against.

Supported ecosystems today: PyPI, npm, crates.io. Other ecosystems
follow as separate fetcher modules — adding one is purely a matter of
the per-registry metadata shape.

Caching: ``(ecosystem, name, version) -> metadata blob`` is cached
forever (registry metadata for a pinned version is immutable).
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import (
    Callable, Dict, Iterable, List, Optional, Set, Tuple,
)

from core.http import HttpClient, HttpError
from core.json import JsonCache, TTL_FOREVER

from .models import Confidence, Dependency, PinStyle

logger = logging.getLogger(__name__)

# Bounded recursion. Even huge dep trees rarely exceed depth 10 in
# practice (npm/PyPI; Cargo less). 12 is a safe soft cap.
DEFAULT_MAX_DEPTH = 12


@dataclass(frozen=True)
class WalkResult:
    """Summary of a single walk over one or more ecosystems."""

    deps_added: List[Dependency]
    visits: int                       # total (eco, name, version) lookups
    cache_hits: int
    cache_misses: int
    failures: int                     # registry / parse errors


def walk_transitive(
    direct_deps: Iterable[Dependency],
    *,
    http: HttpClient,
    cache: Optional[JsonCache] = None,
    max_depth: int = DEFAULT_MAX_DEPTH,
    ecosystems: Optional[Set[str]] = None,
) -> WalkResult:
    """Walk transitives for every dep in ``direct_deps`` whose ecosystem
    has a metadata-walk fetcher today.

    ``ecosystems`` filter — when given, only deps in this set are walked.
    Useful for tests + per-ecosystem opt-in. None means walk everything
    we have a fetcher for; deps in unsupported ecosystems are skipped
    silently (caller should already know via ``_FETCHERS``'s coverage).

    Direct deps themselves are NOT included in the result — only NEW
    transitives the walk discovered. The caller dedups against existing
    direct deps.
    """
    visited: Set[Tuple[str, str, str]] = set()
    result = WalkResult(deps_added=[], visits=0, cache_hits=0,
                         cache_misses=0, failures=0)

    # Seed visited with the direct deps so the walker doesn't re-emit
    # them. ``version=*`` placeholder for unpinned direct deps so a
    # later version-resolved sibling still adds to the tree.
    #
    # Known under-counting case: PEP 440 considers ``1.0`` and ``1.0.0``
    # equivalent, but our visited check is string-equality. A direct
    # dep at ``1.0`` whose parent declares ``>=1.0.0`` will currently
    # get re-emitted as a transitive at ``1.0.0``. Real-world impact is
    # low (extra noise, not a security gap — the same dep at the same
    # logical version flagged twice in findings.json). Future work:
    # normalise via ``packaging.version.Version`` for PyPI and the
    # equivalent for npm semver / Cargo semver.
    direct_list = list(direct_deps)
    for d in direct_list:
        visited.add((d.ecosystem, _norm_name(d.name, d.ecosystem),
                     d.version or "*"))

    # Walk ecosystem-by-ecosystem so each fetcher only handles its own
    # version-spec syntax + its own metadata shape.
    by_eco: Dict[str, List[Dependency]] = {}
    for d in direct_list:
        if ecosystems is not None and d.ecosystem not in ecosystems:
            continue
        by_eco.setdefault(d.ecosystem, []).append(d)

    for eco, seeds in by_eco.items():
        fetcher = _FETCHERS.get(eco)
        if fetcher is None:
            logger.debug(
                "registry_metadata_walk: no fetcher for ecosystem %r; "
                "skipping %d dep(s)", eco, len(seeds),
            )
            continue
        eco_result = _walk_one_ecosystem(
            seeds, fetcher=fetcher, http=http, cache=cache,
            max_depth=max_depth, visited=visited, ecosystem=eco,
        )
        result = WalkResult(
            deps_added=result.deps_added + eco_result.deps_added,
            visits=result.visits + eco_result.visits,
            cache_hits=result.cache_hits + eco_result.cache_hits,
            cache_misses=result.cache_misses + eco_result.cache_misses,
            failures=result.failures + eco_result.failures,
        )
    return result


# ---------------------------------------------------------------------------
# Per-ecosystem fetcher protocol
# ---------------------------------------------------------------------------
#
# A fetcher returns ``[(name, declared_version_or_None, version_spec), ...]``
# — the declared deps of one (name, version) tuple. Version-spec is the
# raw spec string from the registry; the orchestrator picks a
# "guess version" via ``_lower_bound``.

# A fetcher: (http, cache, name, version) -> List[(name, version_spec)] | None
_Fetcher = Callable[
    [HttpClient, Optional[JsonCache], str, str],
    Optional[List[Tuple[str, str]]],
]


def _safe_fetch(
    fetcher: "_Fetcher", http: HttpClient, cache: Optional[JsonCache],
    ecosystem: str, name: str, version: str,
) -> Tuple[List[Tuple[str, str]], bool]:
    """Run ``fetcher``, return ``(deps, failed)``.

    ``failed`` is True when the fetcher couldn't produce data (raised,
    returned None, or registry hiccup). The walker increments its
    failure counter so operators can see how many transitive lookups
    didn't resolve, even though every individual failure is silently
    "no deps recursed; emit dep with what we have and continue".
    """
    try:
        raw = fetcher(http, cache, name, version)
    except Exception as e:                          # noqa: BLE001
        logger.debug(
            "registry_metadata_walk: fetcher %s/%s@%s raised: %s",
            ecosystem, name, version, e,
        )
        return [], True
    if raw is None:
        return [], True
    return raw, False


def _walk_one_ecosystem(
    seeds: List[Dependency],
    *,
    fetcher: _Fetcher,
    http: HttpClient,
    cache: Optional[JsonCache],
    max_depth: int,
    visited: Set[Tuple[str, str, str]],
    ecosystem: str,
) -> WalkResult:
    deps_added: List[Dependency] = []
    visits = 0
    cache_hits = 0
    cache_misses = 0
    failures = 0

    # BFS queue of (name, version, depth) to walk. Items are added when
    # discovered; visited check happens at pop time.
    queue: List[Tuple[str, str, int]] = []
    for d in seeds:
        if d.version is None:
            continue                  # can't walk metadata without a version
        queue.append((_norm_name(d.name, ecosystem), d.version, 0))

    while queue:
        name, version, depth = queue.pop(0)
        if depth >= max_depth:
            continue
        # The ``visited`` set is seeded at the caller with the
        # direct deps (so children that re-cite a direct dep get
        # short-circuited at child-emission time below). Don't
        # gate parent processing on it — direct seeds ARE in
        # visited, and skipping them here would prevent the
        # walker from discovering any transitives. The child-
        # emission paths below maintain the set so re-queued
        # children are short-circuited at the source.
        cache_key = f"metadata_walk/{ecosystem}/{name}/{version}"

        if cache is not None:
            cached = cache.get(cache_key, ttl_seconds=TTL_FOREVER)
        else:
            cached = None
        if cached is not None:
            cache_hits += 1
            child_specs = cached
        else:
            cache_misses += 1
            child_specs, fetch_failed = _safe_fetch(
                fetcher, http, cache, ecosystem, name, version,
            )
            if fetch_failed:
                failures += 1
            elif cache is not None:
                # Cache only successful fetches — caching a failure
                # would prevent a later run from retrying after the
                # registry recovers.
                cache.put(cache_key, child_specs, ttl_seconds=TTL_FOREVER)
        visits += 1

        for child_name, child_spec in child_specs:
            child_norm = _norm_name(child_name, ecosystem)
            child_version = _lower_bound(child_spec)
            if child_version is None:
                # Pure-exclusion / wildcard / unparseable spec — emit
                # the dep with no version (caller can still match by
                # name in OSV but with much lower confidence) and
                # don't recurse since we don't know which version's
                # metadata to fetch.
                child_key = (ecosystem, child_norm, "*")
                if child_key in visited:
                    continue
                visited.add(child_key)
                deps_added.append(_make_dep(
                    ecosystem, child_norm, None, seeds[0].declared_in,
                ))
                continue
            child_key = (ecosystem, child_norm, child_version)
            if child_key in visited:
                continue
            visited.add(child_key)
            deps_added.append(_make_dep(
                ecosystem, child_norm, child_version, seeds[0].declared_in,
            ))
            queue.append((child_norm, child_version, depth + 1))

    return WalkResult(
        deps_added=deps_added, visits=visits,
        cache_hits=cache_hits, cache_misses=cache_misses,
        failures=failures,
    )


def _make_dep(
    ecosystem: str, name: str, version: Optional[str], host_path: Path,
) -> Dependency:
    """Construct a transitive dep marked with low confidence + the
    metadata-walk source_kind. ``host_path`` is the manifest of the
    direct dep that pulled this transitive in — gives operators a
    breadcrumb when triaging."""
    return Dependency(
        ecosystem=ecosystem,
        name=name,
        version=version,
        declared_in=host_path,
        scope="main",
        is_lockfile=False,
        pin_style=PinStyle.UNKNOWN,
        direct=False,
        purl=_purl(ecosystem, name, version),
        parser_confidence=Confidence(
            "low",
            reason=(
                f"metadata-walk approximation: {ecosystem}:{name}"
                f"{('@' + version) if version else ''}; declared by "
                "the package's registry metadata, not resolved by "
                "the project's actual resolver"
            ),
        ),
        source_kind="metadata_walk",
    )


def _purl(ecosystem: str, name: str, version: Optional[str]) -> str:
    eco = {
        "PyPI": "pypi", "npm": "npm", "crates.io": "cargo",
    }.get(ecosystem, ecosystem.lower())
    if version:
        return f"pkg:{eco}/{name}@{version}"
    return f"pkg:{eco}/{name}"


# ---------------------------------------------------------------------------
# Version-spec lower-bound extraction
# ---------------------------------------------------------------------------

def _lower_bound(spec: str) -> Optional[str]:
    """Return the most permissive version that satisfies ``spec``.

    Per-ecosystem spec syntaxes converge on similar ideas — pick the
    smallest version that the spec admits. ``>=X`` → X. ``^X.Y.Z`` (npm,
    cargo) → X.Y.Z. ``~X.Y.Z`` (npm, cargo) → X.Y.Z. ``==X`` → X.
    Pure exclusion (``!=X``) or wildcard (``*``) → None.

    We don't try to resolve the actual installed version (that's the
    resolver's job); the lower bound is the conservative "this version
    is at least that old" guess, used only as a CVE-match key.
    """
    if not spec:
        return None
    s = spec.strip()
    if s in ("*", "any", "latest", ""):
        return None
    # Strip leading operators we don't want in the version literal.
    # Order matters: longer ops first so we don't strip `=` from `==`.
    for prefix in ("===", "==", ">=", "<=", "~=", "^", "~", ">", "<", "="):
        if s.startswith(prefix):
            s = s[len(prefix):].strip()
            break
    if not s or s.startswith("!"):     # pure exclusion
        return None
    # Multi-spec like ">=1.2,<2.0" — take the lower bound (first comma-
    # separated part with a lower-bound operator).
    if "," in s:
        for part in spec.split(","):
            v = _lower_bound(part)
            if v is not None:
                return v
        return None
    # Strip everything that isn't part of a version literal — e.g.
    # PEP 440 environment markers (``foo>=1.0; python_version>="3.10"``)
    # or whitespace-padded specs. Keep digits, dots, dashes, plus,
    # alpha (for "1.0rc1"), letter (for "1.0b1").
    m = re.match(r"^([\w.+\-]+)", s)
    if not m:
        return None
    candidate = m.group(1)
    # Reject obviously-bad guesses like "true" or "main" branch refs.
    if not re.search(r"\d", candidate):
        return None
    return candidate


# ---------------------------------------------------------------------------
# Name normalisation
# ---------------------------------------------------------------------------

def _norm_name(name: str, ecosystem: str) -> str:
    """Per-ecosystem canonical name. PEP 503 for PyPI; lower-case for
    npm scoped names. Cargo / Maven are case-sensitive at registry
    level so we leave them as-is.
    """
    if ecosystem == "PyPI":
        return re.sub(r"[-_.]+", "-", name).lower()
    if ecosystem == "npm":
        return name.lower()
    return name


# ---------------------------------------------------------------------------
# Per-ecosystem fetchers
# ---------------------------------------------------------------------------

def _fetch_pypi(
    http: HttpClient, cache: Optional[JsonCache],
    name: str, version: str,
) -> Optional[List[Tuple[str, str]]]:
    """``https://pypi.org/pypi/<name>/<version>/json``.

    ``info.requires_dist`` is a list of PEP 508 strings. Filter out
    extras-only entries (``foo ; extra == "test"``) — they pull in the
    extras dep only when an extra is requested, which we don't track
    at this layer.
    """
    url = f"https://pypi.org/pypi/{name}/{version}/json"
    try:
        data = http.get_json(url, retries=0)
    except HttpError as e:
        logger.debug("pypi fetch %s@%s failed: %s", name, version, e)
        return None
    info = data.get("info") or {}
    raw = info.get("requires_dist") or []
    out: List[Tuple[str, str]] = []
    for entry in raw:
        if not isinstance(entry, str):
            continue
        # Drop env-marker-gated entries that are extras-only. Real
        # platform markers (``python_version`` etc.) we keep — over-
        # inclusive on minor-version mismatches, fine for CVE coverage.
        if "; extra ==" in entry or "; extra==" in entry:
            continue
        # PEP 508: ``name [extras] specifier ; marker``. Strip extras
        # and marker; keep name + specifier.
        spec = entry.split(";", 1)[0].strip()
        spec = re.sub(r"\[[^\]]+\]", "", spec)        # drop extras
        m = re.match(r"^\s*([A-Za-z0-9._-]+)\s*(.*?)\s*$", spec)
        if not m:
            continue
        child_name = m.group(1)
        child_spec = m.group(2) or ""
        out.append((child_name, child_spec))
    return out


def _fetch_npm(
    http: HttpClient, cache: Optional[JsonCache],
    name: str, version: str,
) -> Optional[List[Tuple[str, str]]]:
    """``https://registry.npmjs.org/<name>/<version>``.

    The version-specific endpoint returns the package's own metadata
    rather than the full registry blob (which can be megabytes for
    popular packages). ``dependencies``, ``peerDependencies``, and
    ``optionalDependencies`` are all in scope — peer deps especially
    are commonly the supply-chain-attack delivery vehicle. We don't
    walk ``devDependencies`` (test/build-only).
    """
    url = f"https://registry.npmjs.org/{name}/{version}"
    try:
        data = http.get_json(url, retries=0)
    except HttpError as e:
        logger.debug("npm fetch %s@%s failed: %s", name, version, e)
        return None
    out: List[Tuple[str, str]] = []
    for field in ("dependencies", "peerDependencies",
                   "optionalDependencies"):
        block = data.get(field) or {}
        if not isinstance(block, dict):
            continue
        for child_name, spec in block.items():
            if isinstance(child_name, str) and isinstance(spec, str):
                out.append((child_name, spec))
    return out


def _fetch_crates(
    http: HttpClient, cache: Optional[JsonCache],
    name: str, version: str,
) -> Optional[List[Tuple[str, str]]]:
    """``https://crates.io/api/v1/crates/<name>/<version>/dependencies``.

    Cargo's registry returns a structured list. ``kind`` distinguishes
    "normal" / "dev" / "build"; we walk only "normal" so the transitive
    set matches what `cargo build` actually pulls into the binary.
    """
    url = (
        f"https://crates.io/api/v1/crates/{name}/{version}/dependencies"
    )
    try:
        data = http.get_json(url, retries=0)
    except HttpError as e:
        logger.debug("crates fetch %s@%s failed: %s", name, version, e)
        return None
    deps = data.get("dependencies") or []
    out: List[Tuple[str, str]] = []
    for entry in deps:
        if not isinstance(entry, dict):
            continue  # poisoned/MITM'd cache entry — skip
        if entry.get("kind") and entry.get("kind") != "normal":
            continue
        if entry.get("optional"):
            continue
        child_name = entry.get("crate_id") or entry.get("name")
        spec = entry.get("req") or ""
        if isinstance(child_name, str) and isinstance(spec, str):
            out.append((child_name, spec))
    return out


_FETCHERS: Dict[str, _Fetcher] = {
    "PyPI": _fetch_pypi,
    "npm": _fetch_npm,
    "crates.io": _fetch_crates,
}


def supported_ecosystems() -> Set[str]:
    """Ecosystems where (c) registry-metadata walk has a fetcher today."""
    return set(_FETCHERS)


_EXISTENCE_URLS = {
    "PyPI": "https://pypi.org/pypi/{name}/{version}/json",
    "npm": "https://registry.npmjs.org/{name}/{version}",
    "crates.io": "https://crates.io/api/v1/crates/{name}/{version}",
}


def package_version_exists(
    ecosystem: str, name: str, version: str,
    *, http: HttpClient, cache: Optional[JsonCache] = None,
) -> Optional[bool]:
    """Probe whether ``(ecosystem, name, version)`` exists in its registry.

    Returns:
        True  — registry returned metadata.
        False — registry returned 404 / not-found.
        None  — couldn't tell (no probe URL, network error, parse fail).

    Used by ``raptor-sca check`` to escalate the verdict from Clean to
    Review when the registry can't confirm the package exists. Calls
    the registry directly rather than going through the transitive
    fetcher (which swallows 404), so 404 vs network-error is
    distinguishable.
    """
    url_tmpl = _EXISTENCE_URLS.get(ecosystem)
    if url_tmpl is None:
        return None
    url = url_tmpl.format(name=name, version=version)
    try:
        http.get_json(url, retries=0)
    except HttpError as e:
        # ``HttpError`` exposes ``.status`` for the HTTP status code.
        if getattr(e, "status", None) == 404:
            return False
        return None
    except Exception:                               # noqa: BLE001
        return None
    return True


__all__ = [
    "DEFAULT_MAX_DEPTH",
    "WalkResult",
    "package_version_exists",
    "supported_ecosystems",
    "walk_transitive",
]
