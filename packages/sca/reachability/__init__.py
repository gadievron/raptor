"""Module-level reachability — orchestrator + per-language scanners.

Public entry: ``scan(target, deps)`` returns a ``Dict[dep_key,
Reachability]`` where ``dep_key`` is ``Dependency.key()``. The pipeline
threads this map into ``findings.build_vuln_findings`` so each
``VulnFinding`` carries a verdict + evidence lines.

Python (AST-based), npm (regex sweep), Cargo, Go, RubyGems, NuGet,
Composer all covered. Ecosystems without a handler return
``not_evaluated`` so the reporter can be honest about the gap.

**Tier-3 escalation (PyPI only):** when the caller passes ``http``
plus a set of ``cve_dep_keys`` (deps that have at least one
matching OSV advisory), every PyPI dep that came up
``not_reachable`` after tiers 1 and 2 gets a second resolution pass
with on-demand wheel-metadata fetch enabled
(:mod:`packages.sca.python_modules`). Cost is bounded by a
forever-cache keyed on (name, version) and gated to CVE-bearing
deps so clean projects pay nothing extra. See ``design/sca.md``
§856.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Set, Tuple

from ..models import Confidence, Dependency, Reachability
from . import cargo as _cargo
from . import composer as _composer
from . import gemfile as _gemfile
from . import gomod as _gomod
from . import maven as _maven
from . import nodejs as _nodejs
from . import nuget as _nuget
from . import python as _python

logger = logging.getLogger(__name__)


# Per-ecosystem scanner: returns the raw module → evidence map.
_Scanner = Callable[
    [Path],
    Dict[str, List[Tuple[Path, int, bool]]],
]
# Per-ecosystem resolver: dep name + scan → Reachability.
_Resolver = Callable[
    [str, Dict[str, List[Tuple[Path, int, bool]]], Optional[Path]],
    Reachability,
]

_HANDLERS: Dict[str, Tuple[_Scanner, _Resolver]] = {
    "PyPI": (_python.scan_imports,
             lambda name, scan, target=None:
                 _python.resolve_dep(name, scan, target=target)),
    "npm":  (_nodejs.scan_imports,
             lambda name, scan, target=None:
                 _nodejs.resolve_dep(name, scan, target=target)),
    "Cargo": (_cargo.scan_imports,
              lambda name, scan, target=None:
                  _cargo.resolve_dep(name, scan, target=target)),
    "Go": (_gomod.scan_imports,
           lambda name, scan, target=None:
               _gomod.resolve_dep(name, scan, target=target)),
    "RubyGems": (_gemfile.scan_imports,
                  lambda name, scan, target=None:
                      _gemfile.resolve_dep(name, scan, target=target)),
    "NuGet": (_nuget.scan_imports,
              lambda name, scan, target=None:
                  _nuget.resolve_dep(name, scan, target=target)),
    "Packagist": (_composer.scan_imports,
                   lambda name, scan, target=None:
                       _composer.resolve_dep(name, scan, target=target)),
    "Maven": (_maven.scan_imports,
              lambda name, scan, target=None:
                  _maven.resolve_dep(name, scan, target=target)),
}


def scan(
    target: Path, deps: Iterable[Dependency],
    *,
    http: Optional[Any] = None,
    cache: Optional[Any] = None,
    cve_dep_keys: Optional[Set[str]] = None,
    osv_results: Optional[List[Any]] = None,
) -> Dict[str, Reachability]:
    """Build per-dep ``Reachability`` for every dep we can analyse.

    When ``http`` and ``cve_dep_keys`` are both provided, PyPI deps
    in ``cve_dep_keys`` that come up ``not_reachable`` from the first
    pass get a second pass with on-demand wheel-metadata fetch
    enabled. This is the design's Tier-3 escalation: only deps that
    matter (have a CVE) AND that the curated map + PEP 503 fallback
    couldn't resolve pay the per-dep network cost. Other ecosystems
    are unchanged — their resolvers don't know about wheel fetch.
    """
    deps_list = list(deps)
    out: Dict[str, Reachability] = {}

    by_eco: Dict[str, List[Dependency]] = defaultdict(list)
    for d in deps_list:
        by_eco[d.ecosystem].append(d)

    # Cache the per-ecosystem ``scan_imports`` result so the Tier-3
    # escalation pass (below) doesn't re-walk the source tree.
    eco_scans: Dict[str, Dict[str, List[Tuple[Path, int, bool]]]] = {}

    for eco, eco_deps in by_eco.items():
        handler = _HANDLERS.get(eco)
        if handler is None:
            for d in eco_deps:
                out[d.key()] = Reachability(
                    verdict="not_evaluated",
                    confidence=Confidence(
                        "low",
                        reason=f"reachability not implemented for {eco}",
                    ),
                    evidence=[],
                )
            continue
        scanner, resolver = handler
        try:
            # Pass ``cache`` through when the scanner accepts it (the
            # Python scanner does; others may not). Inspect rather
            # than try/except so we don't swallow real errors.
            import inspect
            sig = inspect.signature(scanner)
            scan_kwargs = {"cache": cache} if "cache" in sig.parameters else {}
            scan_result = scanner(target, **scan_kwargs)
        except Exception:                   # noqa: BLE001
            logger.warning(
                "sca.reachability: %s scanner failed; deps marked "
                "not_evaluated", eco, exc_info=True,
            )
            for d in eco_deps:
                out[d.key()] = Reachability(
                    verdict="not_evaluated",
                    confidence=Confidence(
                        "low",
                        reason=f"{eco} reachability scan errored",
                    ),
                    evidence=[],
                )
            continue
        eco_scans[eco] = scan_result
        # Dedup by dep name within ecosystem so multiple version rows
        # for the same dep share one resolve call.
        seen: Dict[str, Reachability] = {}
        # Pre-build advisory symbol map for Go function-level reachability.
        go_symbols = _build_go_symbol_map(osv_results) if eco == "Go" else {}
        for d in eco_deps:
            if d.name not in seen:
                if eco == "Go" and d.key() in go_symbols:
                    seen[d.name] = _gomod.resolve_dep(
                        d.name, scan_result, target=target,
                        advisory_symbols=go_symbols[d.key()],
                    )
                else:
                    seen[d.name] = resolver(d.name, scan_result, target)
            out[d.key()] = seen[d.name]

    # Tier-3 escalation. Only PyPI today; other ecosystems' resolvers
    # don't yet support wheel-style on-demand metadata. Gated on:
    #   - caller supplied ``http`` (production path) — tests that
    #     don't want network calls just don't pass it,
    #   - ``cve_dep_keys`` is set — at least one OSV advisory matched,
    #   - the dep is in that set,
    #   - the first-pass verdict was ``not_reachable`` (the only
    #     verdict the wheel fetch can possibly upgrade).
    if http is not None and cve_dep_keys:
        py_scan = eco_scans.get("PyPI")
        if py_scan is not None:
            _escalate_pypi_not_reachable(
                deps_list, out, py_scan, target,
                cve_dep_keys=cve_dep_keys, http=http, cache=cache,
            )

    # Free the per-ecosystem scan_result mappings — the function-level
    # tiers don't consult them (they build their own inventory + index).
    # On Grafana ~30 MB total; cheap drop, but every MB before the
    # function-level index build helps on memory-constrained hosts.
    eco_scans.clear()

    # Function-level reachability tier. Inventory-based resolver
    # from ``core.inventory.reachability`` consumes per-language
    # call_graph data emitted by the inventory builder (Python AST
    # + JS / TS tree-sitter). Gated per-ecosystem on the presence
    # of advisory-shipped affected-function data — when no dep in
    # an ecosystem has any, that ecosystem's tier is a no-op (no
    # inventory build, no resolver imports). Runs after tier-3
    # wheel-fetch so it operates on the most upgraded verdict set.
    #
    # Inventory is built ONCE per run when at least one ecosystem
    # tier has work to do; subsequent tiers reuse it via the
    # ``inventory`` kwarg.
    if osv_results:
        shared_inventory = None

        from .python_function_level import (
            build_pypi_symbol_map,
            refine_pypi_verdicts,
        )
        pypi_symbols = build_pypi_symbol_map(osv_results)
        if pypi_symbols:
            shared_inventory = _shared_inventory(target, shared_inventory)
            refine_pypi_verdicts(
                deps_list, out,
                target=target,
                pypi_symbol_map=pypi_symbols,
                inventory=shared_inventory,
            )

        from .npm_function_level import (
            build_npm_symbol_map,
            refine_npm_verdicts,
        )
        npm_symbols = build_npm_symbol_map(osv_results)
        if npm_symbols:
            shared_inventory = _shared_inventory(target, shared_inventory)
            refine_npm_verdicts(
                deps_list, out,
                target=target,
                npm_symbol_map=npm_symbols,
                inventory=shared_inventory,
            )

        from .go_function_level import (
            build_go_symbol_map,
            refine_go_verdicts,
        )
        go_symbols = build_go_symbol_map(osv_results)
        if go_symbols:
            shared_inventory = _shared_inventory(target, shared_inventory)
            refine_go_verdicts(
                deps_list, out,
                target=target,
                go_symbol_map=go_symbols,
                inventory=shared_inventory,
            )

        from .java_function_level import (
            build_maven_symbol_map,
            refine_maven_verdicts,
        )
        maven_symbols = build_maven_symbol_map(osv_results)
        if maven_symbols:
            shared_inventory = _shared_inventory(target, shared_inventory)
            refine_maven_verdicts(
                deps_list, out,
                target=target,
                maven_symbol_map=maven_symbols,
                inventory=shared_inventory,
            )

        from .cargo_function_level import (
            build_cargo_symbol_map,
            refine_cargo_verdicts,
        )
        cargo_symbols = build_cargo_symbol_map(osv_results)
        if cargo_symbols:
            shared_inventory = _shared_inventory(target, shared_inventory)
            refine_cargo_verdicts(
                deps_list, out,
                target=target,
                cargo_symbol_map=cargo_symbols,
                inventory=shared_inventory,
            )

        from .rubygems_function_level import (
            build_rubygems_symbol_map,
            refine_rubygems_verdicts,
        )
        rubygems_symbols = build_rubygems_symbol_map(osv_results)
        if rubygems_symbols:
            shared_inventory = _shared_inventory(target, shared_inventory)
            refine_rubygems_verdicts(
                deps_list, out,
                target=target,
                rubygems_symbol_map=rubygems_symbols,
                inventory=shared_inventory,
            )

        from .nuget_function_level import (
            build_nuget_symbol_map,
            refine_nuget_verdicts,
        )
        nuget_symbols = build_nuget_symbol_map(osv_results)
        if nuget_symbols:
            shared_inventory = _shared_inventory(target, shared_inventory)
            refine_nuget_verdicts(
                deps_list, out,
                target=target,
                nuget_symbol_map=nuget_symbols,
                inventory=shared_inventory,
            )

        from .packagist_function_level import (
            build_packagist_symbol_map,
            refine_packagist_verdicts,
        )
        packagist_symbols = build_packagist_symbol_map(osv_results)
        if packagist_symbols:
            shared_inventory = _shared_inventory(target, shared_inventory)
            refine_packagist_verdicts(
                deps_list, out,
                target=target,
                packagist_symbol_map=packagist_symbols,
                inventory=shared_inventory,
            )

    return out


def _shared_inventory(target: Path, current: Optional[Any]) -> Any:
    """Build the inventory once and share across function-level
    tiers. ``current`` is the value cached so far (None on first
    call). Returns the cached or freshly-built inventory.

    Uses a STABLE per-target cache dir under ``~/.raptor/cache/sca/
    inventory/<target-hash>/`` rather than a tempdir. ``build_inventory``
    already does SHA-256-keyed incremental work — when an unchanged
    file's hash matches its checklist.json record, the parsed entry
    is reused without re-parsing. With a tempdir the checklist
    vanished after every scan; with persistence, re-scans of an
    unchanged tree drop the inventory build from ~21s (istio) to
    sub-second.

    The cache key is a SHA-256 prefix of the absolute target path —
    distinct projects don't share state. Operators wanting to force
    a refresh run ``raptor-sca clean-cache`` (or just delete the
    inventory subdir; ``checklist.json`` regenerates from scratch
    on a missing file).
    """
    if current is not None:
        return current
    try:
        from core.inventory.builder import build_inventory
        cache_dir = _inventory_cache_dir(target)
        cache_dir.mkdir(parents=True, exist_ok=True)
        return build_inventory(str(target), str(cache_dir))
    except Exception:                                # noqa: BLE001
        logger.warning(
            "sca.reachability: inventory build failed; "
            "function-level tiers will skip",
            exc_info=True,
        )
        return None


def _inventory_cache_dir(target: Path) -> Path:
    """Return the persistent cache directory for ``target``'s
    inventory checklist. Keyed on a SHA-256 prefix of the absolute
    target path so distinct projects get distinct cache dirs.
    """
    import hashlib
    from packages.sca import SCA_CACHE_ROOT
    target_abs = str(target.resolve())
    target_hash = hashlib.sha256(
        target_abs.encode("utf-8"),
    ).hexdigest()[:16]
    return SCA_CACHE_ROOT / "inventory" / target_hash


def _build_go_symbol_map(
    osv_results: Optional[List[Any]],
) -> Dict[str, List[str]]:
    """Extract advisory symbols for Go deps from OSV results.

    Returns ``{dep_key: [symbol_name, ...]}`` from
    ``advisory.ecosystem_specific.imports[].symbols``.
    """
    if not osv_results:
        return {}
    out: Dict[str, List[str]] = {}
    for r in osv_results:
        if not hasattr(r, "advisories"):
            continue
        for adv in r.advisories:
            es = adv.ecosystem_specific
            if not es:
                continue
            imports = es.get("imports", [])
            for imp in imports:
                syms = imp.get("symbols", [])
                if syms:
                    out.setdefault(r.dep_key, []).extend(syms)
    for key in out:
        out[key] = list(dict.fromkeys(out[key]))
    return out


def _escalate_pypi_not_reachable(
    deps: List[Dependency],
    out: Dict[str, Reachability],
    py_scan: Dict[str, List[Tuple[Path, int, bool]]],
    target: Path,
    *,
    cve_dep_keys: Set[str],
    http: Any,
    cache: Optional[Any],
) -> None:
    """Re-resolve PyPI ``not_reachable`` deps via on-demand wheel
    metadata when they have CVEs. Mutates ``out`` in place.

    Verdict translation: when tier-3 was attempted but didn't upgrade
    the verdict to ``imported`` / ``likely_called`` (resolve_modules
    returned None for ANY reason — sdist-only release, wheel >cap,
    server didn't honour Range, parse error, registry hiccup — OR
    the wheel's modules didn't match anything in the project scan),
    the result is downgraded from ``not_reachable`` (medium-confidence
    "we looked, no import found") to ``not_evaluated`` ("we tried
    everything, can't tell"). Per design §856: pathological wheels
    abort gracefully → ``not_evaluated``. Generalised here to every
    tier-3 failure mode — they all share the "we engaged escalation
    and it didn't help" semantic, and the risk-score multiplier
    difference (``not_reachable high → 0.335×`` vs ``not_evaluated
    → 0.85×``) makes the verdict materially affect ranking.
    """
    seen: Dict[str, Reachability] = {}
    for d in deps:
        if d.ecosystem != "PyPI":
            continue
        if d.key() not in cve_dep_keys:
            continue
        if d.version is None:
            continue
        current = out.get(d.key())
        if current is None or current.verdict != "not_reachable":
            continue
        if d.name in seen:
            out[d.key()] = seen[d.name]
            continue
        logger.info(
            "sca.reachability: tier-3 escalation for %s==%s "
            "(CVE-bearing, not_reachable from tiers 1+2)",
            d.name, d.version,
        )
        try:
            new_verdict = _python.resolve_dep(
                d.name, py_scan, target=target,
                version=d.version, http=http, cache=cache,
            )
        except Exception:                   # noqa: BLE001
            logger.debug(
                "sca.reachability: tier-3 fetch failed for %s==%s",
                d.name, d.version, exc_info=True,
            )
            new_verdict = _not_evaluated_after_tier3(d)
        else:
            if new_verdict.verdict == "not_reachable":
                # Tier-3 ran (resolve_dep didn't raise) but didn't
                # find a module mapping that matches the scan.
                # Downgrade verdict honestly.
                new_verdict = _not_evaluated_after_tier3(d)
        seen[d.name] = new_verdict
        out[d.key()] = new_verdict


def _not_evaluated_after_tier3(d: Dependency) -> Reachability:
    return Reachability(
        verdict="not_evaluated",
        confidence=Confidence(
            "low",
            reason=(
                f"tier-3 wheel-metadata fetch attempted for {d.name}"
                f"=={d.version} but no module mapping resolved "
                f"against project scan"
            ),
        ),
        evidence=[],
    )


__all__ = ["scan"]
