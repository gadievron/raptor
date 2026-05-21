"""Transitive-dependency expansion orchestrator.

Mode (b) — cascade resolver in sandbox — is the default. The matching
resolver from ``packages/sca/resolvers/`` runs against the manifest's
parent dir and emits a real lockfile; we then parse those lockfile
bytes to extract the transitive dep set with exact resolved versions.

Mode (c) — registry-metadata recursive walk — is the opt-in fallback
(``--fallback-registry-metadata``) for when (b) can't run (toolchain
not in PATH, sandbox unavailable, resolver fails or times out, network
refusal at proxy). Approximation; emits findings tagged
``source_kind="metadata_walk"`` with low parser_confidence so
operators know to triage with caution.

Per-manifest, ecosystem-by-ecosystem decision tree:

  1. Sibling lockfile already present? → already parsed by the
     pipeline; skip orchestration.
  2. ``--no-resolve-transitive``? → skip; emit hygiene reason
     ``"resolver disabled by flag"``.
  3. Run (b) cascade resolver in sandbox.
     - success → parse generated lockfile bytes; emit transitives
       with ``source_kind="cascade_resolver"`` and high confidence.
     - skipped (toolchain unavailable) / failed (registry refused,
       resolver couldn't satisfy, timeout) → log specific reason,
       fall through.
  4. ``--fallback-registry-metadata`` enabled? → run (c). Approximation
     with low confidence.
  5. Else → skip; the existing ``lockfile_missing`` hygiene finding
     surfaces the gap.

Returns ``(transitive_deps, [TransitiveStatus, ...])``. Status rows
feed the operator-facing report so they can see, per ecosystem,
whether transitive coverage was real / approximate / missing-and-why.
"""

from __future__ import annotations

import logging
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import (
    Callable, Dict, List, Optional, Sequence, Tuple,
)

from core.http import HttpClient
from core.json import JsonCache

from .models import Dependency, Manifest

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class TransitiveStatus:
    """Per-(manifest, ecosystem) record of how transitive expansion went."""

    manifest: Path
    ecosystem: str
    method: str          # "cascade_resolver" / "metadata_walk" /
                          # "skipped_lockfile_present" /
                          # "skipped_resolver_disabled" /
                          # "skipped_no_method_succeeded"
    reason: Optional[str]
    deps_added: int = 0
    failures: int = 0


def expand_missing_transitives(
    manifests: Sequence[Manifest],
    direct_deps: Sequence[Dependency],
    *,
    http: Optional[HttpClient] = None,
    cache: Optional[JsonCache] = None,
    enable_resolver: bool = True,
    enable_metadata_fallback: bool = False,
) -> Tuple[List[Dependency], List[TransitiveStatus]]:
    """Expand transitive deps for manifests that don't have a sibling
    lockfile already in ``manifests``.

    Args:
      manifests: every Manifest discovered by ``find_manifests``,
        including any lockfiles already on disk.
      direct_deps: every dep parsed from those manifests (post
        ``parse_manifest``, pre ``join_deps``). Used to dedup the
        new transitives against direct deps already declared.
      http: HttpClient for the metadata-walk fallback. ``None``
        disables (c) entirely.
      cache: JsonCache for metadata-walk caching. Optional.
      enable_resolver: when False, skip mode (b) entirely. Operators
        running ``--no-resolve-transitive`` get this. Useful for
        fast CI gates on lockfile-equipped projects.
      enable_metadata_fallback: when True, fall through to mode (c)
        when (b) fails. Operators running
        ``--fallback-registry-metadata`` get this. Default False —
        approximate findings hurt operator trust by default.

    Returns ``(transitive_deps, statuses)``. Caller merges
    ``transitive_deps`` into ``direct_deps`` before ``join_deps``.
    """
    statuses: List[TransitiveStatus] = []
    new_transitives: List[Dependency] = []

    # Build the "lockfile already on disk" set keyed by ecosystem-
    # parent-dir so we can detect "this manifest has a sibling
    # lockfile, skip transitive expansion".
    lockfile_dirs: Dict[Tuple[str, Path], Manifest] = {}
    for m in manifests:
        if m.is_lockfile:
            lockfile_dirs[(m.ecosystem, m.path.parent)] = m

    # We expand per (ecosystem, project_dir) — one cascade run covers
    # every manifest of that ecosystem in that dir. Group accordingly.
    # ``Inline`` manifests (Dockerfile / GHA / devcontainer / shell)
    # are skipped: they don't have an ecosystem in the cascade-resolver
    # sense (pip / npm / cargo). Inline-extracted deps still join the
    # direct-dep set; they just don't trigger lockfile generation.
    by_eco_dir: Dict[Tuple[str, Path], List[Manifest]] = {}
    for m in manifests:
        if m.is_lockfile:
            continue
        if m.ecosystem == "Inline":
            continue
        by_eco_dir.setdefault((m.ecosystem, m.path.parent), []).append(m)

    # Pre-resolution typosquat gate. The cascade resolver will fetch
    # PyPI / npm / etc. metadata for every name in the manifest — if
    # one of those names is a confident typosquat (e.g. ``requessts``
    # for ``requests``), the operator's manifest is pointing at an
    # attacker-controlled name. We don't want to silently follow
    # that into ``pip-compile`` resolution: skip cascade for any
    # (ecosystem, project_dir) whose direct deps include a
    # typosquat-flagged name. The mechanical-layer typosquat finding
    # still surfaces; cascade just doesn't compound it.
    typosquat_dirs = _typosquat_dirs(direct_deps)

    # First filter pass: drop entries with sibling lockfile / disabled
    # resolver. Build per-ecosystem work lists for the cascade pass —
    # one resolver per ecosystem can amortise its setup cost (e.g.
    # PipResolver builds ONE shared venv across N manifests instead
    # of one per manifest), so dispatching by ecosystem rather than
    # by (ecosystem, project_dir) is what unlocks batching.
    cascade_work: Dict[str, List[Tuple[Path, Path]]] = {}
    for (eco, project_dir), eco_manifests in by_eco_dir.items():
        if (eco, project_dir) in lockfile_dirs:
            statuses.append(TransitiveStatus(
                manifest=eco_manifests[0].path, ecosystem=eco,
                method="skipped_lockfile_present",
                reason=f"sibling lockfile: {lockfile_dirs[(eco, project_dir)].path.name}",
            ))
            continue
        if not enable_resolver and not enable_metadata_fallback:
            statuses.append(TransitiveStatus(
                manifest=eco_manifests[0].path, ecosystem=eco,
                method="skipped_resolver_disabled",
                reason="--no-resolve-transitive set and metadata-walk fallback off",
            ))
            continue
        # Pre-resolution typosquat refusal — the manifest's own deps
        # include a flagged name. Don't follow into resolver; surface
        # the reason so operators see why transitives are missing.
        if (eco, project_dir) in typosquat_dirs:
            squatted = typosquat_dirs[(eco, project_dir)]
            statuses.append(TransitiveStatus(
                manifest=eco_manifests[0].path, ecosystem=eco,
                method="skipped_typosquat_refused",
                reason=(
                    f"manifest declares typosquat-flagged name(s) "
                    f"({', '.join(sorted(squatted))}); refusing to "
                    f"query resolver. Fix the typosquat before "
                    f"re-running."
                ),
            ))
            continue
        cascade_work.setdefault(eco, []).append(
            (project_dir, eco_manifests[0].path),
        )

    # Cascade pass — one batch per ecosystem, dispatched in parallel
    # across ecosystems via threads. Each ecosystem's batch holds the
    # GIL only briefly to launch the sandbox subprocess, then sleeps
    # in ``select.epoll`` waiting for it to finish — so threads work
    # fine here even though Python is GIL-bound. The
    # cross-ecosystem parallelism matters for polyglot projects;
    # within an ecosystem, batched dry_run_batch already runs the
    # per-manifest pip-compile calls concurrently inside one
    # sandbox session.
    cascade_results: Dict[Tuple[str, Path], Tuple[Optional[List[Dependency]], Optional[str]]] = {}
    if cascade_work and enable_resolver:
        cascade_results = _run_cascades_parallel(cascade_work, cache=cache)

    # Second pass: emit transitives + statuses per (eco, project_dir).
    # ``by_eco_dir`` is the original work list; we look up cascade
    # results by key. Ordering of statuses still matches input order.
    for (eco, project_dir), eco_manifests in by_eco_dir.items():
        if (eco, project_dir) in lockfile_dirs:
            continue                        # already statused above
        if not enable_resolver and not enable_metadata_fallback:
            continue                        # already statused above
        if (eco, project_dir) in typosquat_dirs:
            continue                        # already statused above

        added: List[Dependency] = []
        method = "skipped_no_method_succeeded"
        reason: Optional[str] = None
        failures = 0
        cascade_reason: Optional[str] = None

        if enable_resolver:
            cascade_deps, cascade_reason = cascade_results.get(
                (eco, project_dir), (None, None),
            )
            if cascade_deps is not None:
                added = cascade_deps
                method = "cascade_resolver"
                reason = None

        # Registry-metadata walk — opt-in fallback, approximate.
        if not added and enable_metadata_fallback and http is not None:
            walk_deps, c_failures = _try_metadata_walk(
                eco, [d for d in direct_deps if d.ecosystem == eco],
                http=http, cache=cache,
            )
            if walk_deps:
                added = walk_deps
                method = "metadata_walk"
                reason = (
                    "approximate transitive set: cascade resolver "
                    "unavailable, fell back to registry metadata "
                    "(less accurate; declared deps not resolved)"
                )
                failures = c_failures

        # When nothing succeeded, surface the most-informative reason
        # we have — cascade's specific failure beats the generic
        # "no method succeeded" message.
        if not added and method == "skipped_no_method_succeeded":
            reason = cascade_reason or (
                "no transitive-expansion method succeeded"
            )

        # Dedup against direct_deps — emit only NEW deps the project
        # didn't already declare directly.
        direct_keys = {(d.ecosystem, d.name, d.version or "*")
                       for d in direct_deps}
        deduped = [
            d for d in added
            if (d.ecosystem, d.name, d.version or "*") not in direct_keys
        ]
        new_transitives.extend(deduped)

        statuses.append(TransitiveStatus(
            manifest=eco_manifests[0].path, ecosystem=eco,
            method=method, reason=reason,
            deps_added=len(deduped), failures=failures,
        ))

    return new_transitives, statuses


def _run_cascades_parallel(
    cascade_work: Dict[str, List[Tuple[Path, Path]]],
    cache: Optional["JsonCache"] = None,
) -> Dict[Tuple[str, Path], Tuple[Optional[List[Dependency]], Optional[str]]]:
    """Dispatch one batched cascade per ecosystem in parallel.

    Within each ecosystem the resolver's ``dry_run_batch`` (when it
    has one) shares setup cost across manifests; across ecosystems
    we use threads because each batch sleeps on its sandbox
    subprocess.

    Returns ``{(ecosystem, project_dir): (deps_or_None, reason_or_None)}``
    for every input work item. Call sites match by key.
    """
    from concurrent.futures import ThreadPoolExecutor

    out: Dict[Tuple[str, Path], Tuple[Optional[List[Dependency]], Optional[str]]] = {}
    if not cascade_work:
        return out

    # Bound concurrency at the number of ecosystems. ThreadPoolExecutor
    # context manager joins on exit so per-batch exceptions surface
    # back to the orchestrator.
    with ThreadPoolExecutor(
        max_workers=max(1, len(cascade_work)),
        thread_name_prefix="sca-cascade",
    ) as pool:
        futs = {
            pool.submit(_try_cascade_batch, eco, items, cache): eco
            for eco, items in cascade_work.items()
        }
        for fut in futs:
            eco = futs[fut]
            try:
                results = fut.result()
            except Exception as e:                      # noqa: BLE001
                # Defensive: a batch crash shouldn't abort the whole
                # transitive pass — surface as a failure for every
                # work item in that ecosystem so the per-manifest
                # status row carries a meaningful reason.
                logger.warning(
                    "transitive: cascade batch crashed for %s: %s", eco, e,
                )
                for project_dir, _host in cascade_work[eco]:
                    out[(eco, project_dir)] = (
                        None, f"cascade batch crashed: {e}",
                    )
                continue
            for (pd, _host, deps, reason) in results:
                out[(eco, pd)] = (deps, reason)
    return out


def _try_cascade_batch(
    ecosystem: str,
    work_items: List[Tuple[Path, Path]],
    cache: Optional["JsonCache"] = None,
) -> List[Tuple[Path, Path, Optional[List[Dependency]], Optional[str]]]:
    """Run cascade resolution for every (project_dir, host_manifest)
    in a single ecosystem. Uses ``dry_run_batch`` so resolvers that
    support shared-setup batching (currently :class:`PipResolver`)
    amortise venv-creation across the batch.

    Returns ``[(project_dir, host_manifest, deps_or_None, reason_or_None), ...]``
    aligned with ``work_items``.
    """
    _ensure_lockfile_parsers_loaded()
    from .resolvers import get_resolver
    from .resolvers._cache import cached_dry_run_batch

    out: List[Tuple[Path, Path, Optional[List[Dependency]], Optional[str]]] = []
    if not work_items:
        return out

    project_dirs = [pd for pd, _ in work_items]
    resolver = get_resolver(ecosystem, project_dir=project_dirs[0])
    if resolver is None:
        for pd, host in work_items:
            out.append(
                (pd, host, None,
                 f"no cascade resolver registered for {ecosystem}"),
            )
        return out
    if not resolver.is_available():
        for pd, host in work_items:
            out.append(
                (pd, host, None,
                 f"{ecosystem} toolchain not installed (cascade resolver "
                 f"requires it for transitive resolution)"),
            )
        return out
    parser = _LOCKFILE_PARSERS.get(ecosystem)
    if parser is None:
        for pd, host in work_items:
            out.append(
                (pd, host, None,
                 f"no lockfile parser wired for {ecosystem}; transitive "
                 f"data was generated but cannot be ingested"),
            )
        return out

    # Common ancestor of every project_dir lets the sandbox cover
    # them all in one ``target=common_root`` session. When
    # ``dry_run_batch`` finds it can't honour the batch (mismatched
    # paths, single item, no-batch resolver), it falls back to
    # sequential per-dir ``dry_run`` automatically.
    common_root = _common_ancestor(project_dirs)
    if cache is not None:
        results = cached_dry_run_batch(
            resolver, project_dirs, cache=cache,
            common_root=common_root,
        )
    else:
        # No cache wired — fall through to the direct subprocess
        # path. Tests + early-bootstrap callers hit this branch.
        from .resolvers import dry_run_batch as _dry_run_batch
        results = _dry_run_batch(
            resolver, project_dirs, common_root=common_root,
        )
    for (pd, host), result in zip(work_items, results):
        if not result.success:
            out.append((
                pd, host, None,
                f"{ecosystem} resolver failed: "
                f"{(result.error or 'unknown error')[:140]}",
            ))
            continue
        if result.proposed_lockfile is None:
            out.append((
                pd, host, None,
                f"{ecosystem} resolver succeeded but produced no "
                f"lockfile bytes (transitive ingest not possible)",
            ))
            continue
        deps = _parse_lockfile_bytes(
            ecosystem, result.proposed_lockfile, parser, host,
        )
        if deps is None:
            out.append((
                pd, host, None,
                f"{ecosystem} lockfile parse failed for cascade output "
                f"(unexpected format from resolver)",
            ))
            continue
        # PyPI cascade outputs (pip-compile) carry ``# via <parent>``
        # annotations after each transitive; extract that map before
        # parsing strips comments so we can record parent linkage in
        # the Dependency's source_extra.
        parents_by_name: Dict[str, List[str]] = {}
        if ecosystem == "PyPI":
            parents_by_name = _extract_pip_compile_via(
                result.proposed_lockfile
            )
        elif ecosystem == "npm":
            parents_by_name = _extract_npm_lock_parents(
                result.proposed_lockfile
            )
        elif ecosystem == "Cargo":
            parents_by_name = _extract_cargo_lock_parents(
                result.proposed_lockfile
            )
        elif ecosystem == "Packagist":
            parents_by_name = _extract_composer_lock_parents(
                result.proposed_lockfile
            )
        elif ecosystem == "RubyGems":
            parents_by_name = _extract_gemfile_lock_parents(
                result.proposed_lockfile
            )
        tagged = [
            _with_cascade_source(
                d, host,
                parents=parents_by_name.get(
                    d.name.lower().replace("_", "-"), [],
                ),
            )
            for d in deps
        ]
        out.append((pd, host, tagged, None))
    return out


def _typosquat_dirs(
    direct_deps: Sequence[Dependency],
) -> Dict[Tuple[str, Path], List[str]]:
    """Run the existing typosquat detector against direct deps and
    return ``{(ecosystem, project_dir): [flagged_name, ...]}`` for
    any (eco, project_dir) tuple whose direct deps include at least
    one confidently-flagged typosquat. Used to gate the cascade
    resolver — we don't want pip-compile / npm install fetching
    metadata for attacker-controlled names.

    The detector is medium-confidence at best (Damerau-Levenshtein
    distance against a popular-names list), so we additionally
    require the dep to be ``direct=True`` (operator-declared, not
    inherited). The manifest-author can correct the typo and
    re-run; meanwhile cascade staying out keeps the network
    request from happening at all.
    """
    from .supply_chain.typosquat import scan_deps as _typo_scan
    out: Dict[Tuple[str, Path], List[str]] = {}
    if not direct_deps:
        return out
    findings = _typo_scan(direct_deps)
    for f in findings:
        # Only refuse on high-confidence flags. The detector emits
        # medium for "looks similar to" cases; those should still
        # surface to the operator but shouldn't block cascade.
        if f.confidence.level != "high":
            continue
        key = (f.dependency.ecosystem, f.dependency.declared_in.parent)
        out.setdefault(key, []).append(f.dependency.name)
    return out


def _common_ancestor(paths: Sequence[Path]) -> Path:
    """Common-prefix path that every input is under. Used by the
    cascade batch to size the sandbox cwd to cover all manifests in
    one session. Single-input collapses to that input's parent (so
    behaviour matches the sequential per-manifest path)."""
    if len(paths) == 1:
        return paths[0]
    parts_lists = [p.resolve().parts for p in paths]
    shortest = min(len(pl) for pl in parts_lists)
    common: List[str] = []
    for i in range(shortest):
        seg = parts_lists[0][i]
        if all(pl[i] == seg for pl in parts_lists):
            common.append(seg)
        else:
            break
    if not common:
        return Path("/")
    return Path(*common)


# ---------------------------------------------------------------------------
# Mode (b): cascade resolver in sandbox
# ---------------------------------------------------------------------------

def _try_cascade(
    ecosystem: str, project_dir: Path, host_manifest_path: Path,
    cache: Optional["JsonCache"] = None,
) -> Tuple[Optional[List[Dependency]], Optional[str]]:
    """Run the matching cascade resolver. Return
    ``(deps, None)`` on success and ``(None, reason)`` on any failure
    (no toolchain, resolver couldn't satisfy, no lockfile parser, etc.)
    so the orchestrator can surface a specific operator-facing message
    rather than a generic "no method succeeded".
    """
    _ensure_lockfile_parsers_loaded()
    from .resolvers import get_resolver
    resolver = get_resolver(ecosystem, project_dir=project_dir)
    if resolver is None:
        return None, f"no cascade resolver registered for {ecosystem}"
    if not resolver.is_available():
        # Resolver implementations encode the toolchain name in
        # `is_available()` via a `<tool> --version` probe; surface
        # it explicitly so operators don't have to guess which
        # tool is missing.
        return None, (
            f"{ecosystem} toolchain not installed (cascade resolver "
            f"requires it for transitive resolution)"
        )
    if cache is not None:
        from .resolvers._cache import cached_dry_run
        result = cached_dry_run(resolver, project_dir, cache=cache)
    else:
        result = resolver.dry_run(project_dir)
    if not result.success:
        return None, (
            f"{ecosystem} resolver failed: "
            f"{(result.error or 'unknown error')[:140]}"
        )
    if result.proposed_lockfile is None:
        return None, (
            f"{ecosystem} resolver succeeded but produced no "
            f"lockfile bytes (transitive ingest not possible)"
        )
    parser = _LOCKFILE_PARSERS.get(ecosystem)
    if parser is None:
        return None, (
            f"no lockfile parser wired for {ecosystem}; transitive "
            f"data was generated but cannot be ingested"
        )
    deps = _parse_lockfile_bytes(
        ecosystem, result.proposed_lockfile, parser, host_manifest_path,
    )
    if deps is None:
        return None, (
            f"{ecosystem} lockfile parse failed for cascade output "
            f"(unexpected format from resolver)"
        )
    # Re-tag every dep with cascade_resolver source_kind + direct=False.
    # Subtle: pip-compile output is a flat pinned-requirements file;
    # the requirements.txt parser has no signal to mark anything
    # transitive (it parses a manifest shape, defaults direct=True).
    # But cascade output IS the transitive closure by definition —
    # the operator's actual direct deps are already in ``direct_deps``
    # at the orchestrator's caller. The orchestrator's dedup against
    # direct_deps strips overlap; what's left here is purely transitive,
    # so direct=False is correct for the whole list.
    #
    # ``declared_in`` is also re-tagged to the host manifest path —
    # the cascade lockfile lives in a per-call ``TemporaryDirectory``
    # whose path looks like ``/tmp/raptor-sca-cascade-<rand>/...``
    # and is gone before the report renders. Pointing operators at
    # the host manifest (the file they can actually edit) is more
    # useful than at a vanished temp.
    # For pip-compile output specifically, the lockfile carries
    # ``# via <parent>`` comments after each transitive — extract
    # them BEFORE the requirements.txt parser strips comments, so
    # the resulting Dependency rows can record who pulled each
    # transitive in. The ``transitive_drop`` detector uses this to
    # suggest bumps that drop CVE-bearing transitives.
    parents_by_name: Dict[str, List[str]] = {}
    if ecosystem == "PyPI":
        parents_by_name = _extract_pip_compile_via(
            result.proposed_lockfile
        )
    tagged = [
        _with_cascade_source(
            d, host_manifest_path,
            parents=parents_by_name.get(d.name.lower(), []),
        )
        for d in deps
    ]
    return tagged, None


def _extract_cargo_lock_parents(blob: bytes) -> Dict[str, List[str]]:
    """Cargo.lock parent extraction. Each ``[[package]]`` entry
    has ``dependencies = ["name version checksum", ...]``."""
    try:
        try:
            import tomllib
        except ImportError:
            import tomli as tomllib   # type: ignore[import]
        data = tomllib.loads(blob.decode("utf-8", errors="replace"))
    except Exception:                                       # noqa: BLE001
        return {}
    out: Dict[str, List[str]] = {}
    packages = data.get("package") or []
    if not isinstance(packages, list):
        return {}
    for pkg in packages:
        if not isinstance(pkg, dict):
            continue
        parent_name = pkg.get("name")
        if not isinstance(parent_name, str):
            continue
        for dep_str in pkg.get("dependencies") or []:
            if not isinstance(dep_str, str):
                continue
            # ``"<name> <version> (<source>)"`` or ``"<name>"``.
            child = dep_str.split(" ", 1)[0]
            if child:
                out.setdefault(child.lower(), []).append(parent_name.lower())
    return out


def _extract_composer_lock_parents(blob: bytes) -> Dict[str, List[str]]:
    """composer.lock parent extraction. JSON shape with
    ``packages: [{name, require: {...}}, ...]`` and
    ``packages-dev: [...]``."""
    import json as _json
    try:
        data = _json.loads(blob)
    except Exception:                                       # noqa: BLE001
        return {}
    out: Dict[str, List[str]] = {}
    for group in ("packages", "packages-dev"):
        for pkg in data.get(group) or []:
            if not isinstance(pkg, dict):
                continue
            parent_name = pkg.get("name")
            if not isinstance(parent_name, str):
                continue
            for child_name in (pkg.get("require") or {}):
                out.setdefault(
                    child_name.lower(), [],
                ).append(parent_name.lower())
    return out


def _extract_gemfile_lock_parents(blob: bytes) -> Dict[str, List[str]]:
    """Gemfile.lock parent extraction. Format:

        GEM
          remote: https://rubygems.org/
          specs:
            actionpack (8.0.1)
              actionview (= 8.0.1)
              activesupport (= 8.0.1)
            actionview (8.0.1)
              activesupport (= 8.0.1)

    Each top-level (non-indented gem line) names a parent; each
    child line indented under it is a dependency."""
    out: Dict[str, List[str]] = {}
    text = blob.decode("utf-8", errors="replace")
    in_specs = False
    current_parent: Optional[str] = None
    import re as _re
    spec_re = _re.compile(r"^(\s+)([a-zA-Z0-9._-]+)")
    for line in text.splitlines():
        stripped = line.strip()
        if stripped == "specs:":
            in_specs = True
            continue
        if not in_specs:
            continue
        if not line.startswith(" "):
            # Out of the specs block; reset.
            in_specs = False
            current_parent = None
            continue
        m = spec_re.match(line)
        if not m:
            continue
        indent, name = m.group(1), m.group(2)
        # Top-level gems in specs: are 4-space indented;
        # their children are 6-space indented (2 deeper).
        if len(indent) == 4:
            current_parent = name.lower()
        elif len(indent) >= 6 and current_parent is not None:
            out.setdefault(name.lower(), []).append(current_parent)
    return out


def _extract_npm_lock_parents(blob: bytes) -> Dict[str, List[str]]:
    """Extract child → [parents] map from a package-lock.json blob.

    npm v2/v3 lockfile shape:
      ``packages: {"": {...}, "node_modules/<pkg>": {dependencies: {...}}, ...}``
    Each package entry's ``dependencies`` field lists its direct
    requires (transitive children). We invert that to record the
    PARENTS of each package, then the transitive-drop detector
    can ask "if I bump <parent>, does <child> disappear?".

    Returns lowercased names. The root entry ("") is the
    user's own project — its declared deps are direct, not
    transitives, so the root → child edges are excluded
    (a transitive "via" listing the root would be misleading)."""
    import json as _json
    try:
        data = _json.loads(blob)
    except (ValueError, TypeError):
        return {}
    packages = data.get("packages") if isinstance(data, dict) else None
    if not isinstance(packages, dict):
        return {}
    out: Dict[str, List[str]] = {}
    for path, meta in packages.items():
        if not isinstance(meta, dict):
            continue
        # Root entry has empty path; its deps are direct.
        if path == "":
            continue
        parent_name = path.rsplit("node_modules/", 1)[-1]
        if not parent_name:
            continue
        # Strip nested-namespace: ``node_modules/x/node_modules/y``
        # means y is a child of x. The path's last segment is the
        # package name; everything before identifies the parent.
        for dep_name in (meta.get("dependencies") or {}):
            child_canon = dep_name.lower()
            out.setdefault(child_canon, []).append(parent_name.lower())
    return out


def _extract_pip_compile_via(blob: bytes) -> Dict[str, List[str]]:
    """Parse a pip-compile lockfile and return a name → [parents]
    map from the ``# via <parent>`` annotations.

    pip-compile emits two shapes:
        diskcache==5.6.3
            # via instructor
    OR (multiple parents):
        requests==2.31.0
            # via
            #   instructor
            #   sphinx

    We only need the parent list per package; downstream consumers
    use it to ask "if I bump <parent>, does this transitive
    disappear?". Returns lowercased package names (PEP 503
    canonicalised at the call site)."""
    import re as _re

    text = blob.decode("utf-8", errors="replace")
    # Match: ``<name>==<version>`` followed by indented ``# via``
    # block, possibly continuing across lines as ``#   <parent>``.
    pkg_re = _re.compile(
        r"^([A-Za-z0-9][A-Za-z0-9._-]*)==[^\s]+\s*$",
        _re.MULTILINE,
    )
    out: Dict[str, List[str]] = {}
    lines = text.splitlines()
    for i, line in enumerate(lines):
        m = pkg_re.match(line.strip())
        if m is None:
            continue
        name = m.group(1).lower().replace("_", "-")
        parents: List[str] = []
        # Look at subsequent indented ``# via`` block.
        j = i + 1
        in_via = False
        while j < len(lines):
            sub = lines[j]
            stripped = sub.lstrip()
            if not stripped.startswith("#"):
                break
            content = stripped.lstrip("#").strip()
            if content.startswith("via"):
                rest = content[3:].strip()
                if rest:
                    # Single-line form: ``# via <parent>``
                    for p in rest.split(","):
                        p = p.strip()
                        if p and not p.startswith("-"):
                            parents.append(p.lower().replace("_", "-"))
                in_via = True
            elif in_via:
                # Continuation: ``#   <parent>``
                if content and not content.startswith("-"):
                    parents.append(content.lower().replace("_", "-"))
            j += 1
        if parents:
            out[name] = parents
    return out


def _parse_lockfile_bytes(
    ecosystem: str, blob: bytes,
    parser: Callable[[Path], List[Dependency]],
    host_manifest_path: Path,
) -> Optional[List[Dependency]]:
    """Most lockfile parsers take a ``Path``. Write the bytes to a
    temp file matching the parser's expected name, parse, return."""
    expected_name = _CASCADE_LOCKFILE_NAMES[ecosystem]
    try:
        with tempfile.TemporaryDirectory(prefix="raptor-sca-cascade-") as td:
            tmp = Path(td) / expected_name
            tmp.write_bytes(blob)
            return list(parser(tmp))
    except Exception as e:                          # noqa: BLE001
        logger.debug(
            "transitive: cascade lockfile parse failed for %s: %s",
            ecosystem, e,
        )
        return None


def _with_cascade_source(
    d: Dependency, host_manifest_path: Path,
    *, parents: Optional[List[str]] = None,
) -> Dependency:
    """Re-tag a Dependency as cascade_resolver-sourced.

    Three re-tags happen here:
      - ``source_kind="cascade_resolver"`` — the bytes came from an
        in-sandbox cascade run, not a checked-in lockfile; the
        report distinction matters for triage trust.
      - ``direct=False`` — cascade output is the transitive closure;
        the orchestrator dedups against the operator's actual
        direct deps before the result reaches ``join_deps``.
      - ``declared_in=host_manifest_path`` — the original
        ``declared_in`` from the parser points at the cascade temp
        lockfile (``/tmp/raptor-sca-cascade-<rand>/...``), which is
        deleted before the report renders. The operator-actionable
        path is the host manifest that triggered the cascade — what
        they need to edit to change the resolution input.

    ``parents`` (optional, PyPI-only today) records the direct
    deps that pulled this transitive in, extracted from
    pip-compile's ``# via <parent>`` annotations. Surfaces via
    ``source_extra["via"]`` so the transitive-drop detector can
    suggest parent bumps that drop CVE-bearing transitives.
    """
    extra = dict(d.source_extra or {})
    if parents:
        extra["via"] = list(parents)
    return Dependency(
        ecosystem=d.ecosystem, name=d.name, version=d.version,
        declared_in=host_manifest_path, scope=d.scope,
        is_lockfile=d.is_lockfile, pin_style=d.pin_style,
        direct=False,
        purl=d.purl,
        parser_confidence=d.parser_confidence,
        declared_license=d.declared_license,
        commented_out=d.commented_out,
        source_kind="cascade_resolver",
        source_extra=extra or None,
    )


# ---------------------------------------------------------------------------
# Mode (c): registry metadata walk
# ---------------------------------------------------------------------------

def _try_metadata_walk(
    ecosystem: str, eco_direct_deps: List[Dependency],
    *, http: HttpClient, cache: Optional[JsonCache],
) -> Tuple[List[Dependency], int]:
    """Walk the registry metadata for an ecosystem's direct deps.
    Returns (deps, failures). Empty deps + non-zero failures is
    "tried, couldn't get data"; empty deps + zero failures is
    "tried, found no transitives"."""
    from .registry_metadata_walk import walk_transitive
    result = walk_transitive(
        eco_direct_deps, http=http, cache=cache,
        ecosystems={ecosystem},
    )
    return (result.deps_added, result.failures)


# ---------------------------------------------------------------------------
# Per-ecosystem cascade-output parsing
# ---------------------------------------------------------------------------

# Filename the cascade resolver's bytes should be written under so
# the matching parser recognises the format. Different per ecosystem
# because parsers do filename-based dispatch internally.
_CASCADE_LOCKFILE_NAMES: Dict[str, str] = {
    "PyPI": "requirements.txt",        # pip-compile output is a pinned reqs
    "npm": "package-lock.json",
    "Cargo": "Cargo.lock",
    "Go": "go.sum",
    "RubyGems": "Gemfile.lock",
    "Packagist": "composer.lock",
    "NuGet": "packages.lock.json",
    # "Maven", "Maven (Gradle)" — the resolvers emit dep-tree text
    # rather than a structured lockfile; cascade-result parsing for
    # these is a separate follow-up. Default behaviour: skip with
    # "no lockfile parser wired" log.
}


def _import_lockfile_parser(ecosystem: str) -> Optional[Callable]:
    """Lazy-import the matching lockfile parser. Avoids import-time
    cycles between transitive.py and the parsers package."""
    if ecosystem == "PyPI":
        from .parsers.requirements import parse as _parse
        return _parse
    if ecosystem == "npm":
        from .parsers.package_lock_json import parse as _parse
        return _parse
    if ecosystem == "Cargo":
        from .parsers.cargo import parse_lockfile as _parse
        return _parse
    if ecosystem == "Go":
        from .parsers.gomod import parse_lockfile as _parse
        return _parse
    if ecosystem == "RubyGems":
        from .parsers.gemfile import parse_lockfile as _parse
        return _parse
    if ecosystem == "Packagist":
        from .parsers.composer import parse_lockfile as _parse
        return _parse
    if ecosystem == "NuGet":
        from .parsers.nuget import parse_lockfile as _parse
        return _parse
    return None


# Initialised lazily on first orchestrator call to avoid import-time
# parser imports leaking into modules that don't need them.
_LOCKFILE_PARSERS: Dict[str, Callable] = {}


def _ensure_lockfile_parsers_loaded() -> None:
    if _LOCKFILE_PARSERS:
        return
    for eco in _CASCADE_LOCKFILE_NAMES:
        p = _import_lockfile_parser(eco)
        if p is not None:
            _LOCKFILE_PARSERS[eco] = p


__all__ = [
    "TransitiveStatus",
    "expand_missing_transitives",
]
