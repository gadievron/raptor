"""Joern CPG integration backend for /audit.

Server lifecycle, evidence building, taint flow resolution, and
target-detection helpers.  Separated from orchestrator.py — called
by the orchestrator but doesn't reference its mutable state.
"""

from __future__ import annotations

import json
import logging
import threading
from collections import deque
from collections.abc import Callable
from concurrent.futures import Future, ThreadPoolExecutor
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_C_EXTENSIONS = frozenset({".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh"})
_JOERN_STALL_FLOOR_S = 30

_JOERN_EXTENSIONS = frozenset({
    ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".scala", ".kt",
    ".go", ".rb", ".php",
})


def target_has_c_sources(target_path: Path | None) -> bool:
    """Check if target directory contains C/C++ source files."""
    if not target_path or not target_path.is_dir():
        return False
    for p in target_path.rglob("*"):
        if p.is_file() and p.suffix.lower() in _C_EXTENSIONS:
            return True
    return False


def target_has_joern_sources(target_path: Path | None) -> bool:
    """Check if target has non-C sources that Joern can parse."""
    if not target_path or not target_path.is_dir():
        return False
    for p in target_path.rglob("*"):
        if p.is_file() and p.suffix.lower() in _JOERN_EXTENSIONS:
            return True
    return False


def joern_available(overrides: dict[str, Any] | None = None) -> bool:
    """Check if Joern is installed, importable, and enabled in tuning."""
    if overrides and overrides.get("enabled") is False:
        return False
    try:
        from core.tuning import get_tuning
        if not get_tuning().joern_enabled:
            return False
    except Exception:
        logger.debug("joern tuning probe failed", exc_info=True)
    try:
        from packages.joern.prereqs import is_available
        return is_available()
    except ImportError:
        return False


def joern_tunables(overrides: dict[str, Any] | None = None):
    """Load JoernTunables from the central tuning config."""
    try:
        from packages.joern.tunables import JoernTunables
        return JoernTunables.from_tuning(overrides=overrides)
    except Exception:
        logger.debug("joern tunables from_tuning failed", exc_info=True)
        try:
            from packages.joern.tunables import JoernTunables
            return JoernTunables()
        except Exception:
            logger.debug("joern tunables unavailable", exc_info=True)
            return None


def start_joern_server(target_path, joern_overrides=None, tunables=None):
    """Start or reuse a persistent Joern server if Joern is available.

    Returns the server instance or None.  When reusing a lifecycle-managed
    server, builds/imports the CPG for *target_path* so queries run
    against the correct codebase.
    """
    if not joern_available(overrides=joern_overrides):
        return None

    if not (target_has_c_sources(target_path)
            or target_has_joern_sources(target_path)):
        return None

    srv = None
    try:
        from packages.joern.lifecycle import joern_acquire
        srv = joern_acquire(tunables)
    except Exception:
        logger.debug("joern lifecycle acquire failed; trying direct start",
                     exc_info=True)

    if srv is None:
        try:
            from packages.joern.server import JoernServer
        except ImportError:
            return None
        try:
            srv = JoernServer.from_tunables(tunables)
            srv.start()
        except Exception:
            logger.debug("Joern server failed to start; using subprocess fallback",
                         exc_info=True)
            return None

    if not _ensure_cpg_loaded(srv, target_path, tunables):
        logger.warning("Joern CPG failed to load for %s — disabling Joern", target_path)
        try:
            srv.stop()
        except Exception:
            logger.debug("joern server stop failed", exc_info=True)
        return None
    return srv


def _ensure_cpg_loaded(srv, target_path, tunables=None):
    """Build and import the CPG for *target_path* into *srv*.

    Returns True if the CPG was loaded (or already was), False on failure.
    """
    if getattr(srv, "_cpg_loaded", False):
        return True
    try:
        from packages.joern.runner import build_cpg_cached
    except ImportError:
        logger.debug("joern runner not importable; skipping CPG import")
        return False

    cpg_timeout = getattr(tunables, "cpg_timeout_s", 600) if tunables else 600
    import_timeout = getattr(tunables, "import_timeout_s", 120) if tunables else 120

    cache_dir = Path.home() / ".cache" / "raptor" / "joern-cpg"
    cache_dir.mkdir(parents=True, exist_ok=True)

    try:
        cpg = build_cpg_cached(Path(target_path), cache_dir, timeout=cpg_timeout)
        if cpg.exists():
            srv.import_cpg(cpg.path, timeout=import_timeout)
            return True
        return False
    except Exception:
        logger.debug("CPG build/import failed for %s", target_path, exc_info=True)
        return False


def stop_joern_server(server) -> None:
    """Stop the Joern server if it was started."""
    if server is None:
        return

    def _do_stop():
        try:
            server.stop()
        except Exception:
            logger.debug("Joern server shutdown error", exc_info=True)

    t = threading.Thread(target=_do_stop, daemon=True)
    t.start()
    t.join(timeout=30)
    if t.is_alive():
        logger.warning("Joern server stop timed out after 30s — abandoning")


def joern_live_query(
    server,
    function_name: str,
    sinks: list[str],
    timeout: int = 30,
    *,
    label: str | None = None,
    max_call_depth: int | None = None,
) -> list[Any]:
    """Fire a targeted taint query via the live Joern server."""
    from packages.joern.runner import _validate_substitution_value

    if not _validate_substitution_value(function_name):
        return []

    depth_kwargs: dict[str, int] = {}
    if max_call_depth is not None:
        depth_kwargs["max_call_depth"] = max_call_depth

    for sink in sinks:
        sink_name = sink.split(".")[-1] if "." in sink else sink
        if not _validate_substitution_value(sink_name):
            continue
        try:
            flows = server.run_taint_query(
                function_name, sink_name, timeout=timeout,
                **depth_kwargs,
            )
            if flows:
                logger.info(
                    "joern live query: %s → %s = %d flow(s)",
                    function_name, sink_name, len(flows),
                )
                return flows
        except Exception:
            logger.debug(
                "joern live query failed: %s → %s",
                function_name, sink_name, exc_info=True,
            )

    return []


def enrich_joern_evidence(
    evidence_index: dict[str, Any] | None,
    key: str,
    function_name: str,
    sinks: list[str],
    joern_server,
) -> None:
    """Add unguarded-sink details and tainted arg indices to evidence."""
    if not evidence_index:
        return
    rec = evidence_index.get(key)
    if not rec:
        return

    from core.analysis.reachability_gates import (
        query_sink_arg_index,
        query_unguarded_sinks,
    )

    if not rec.joern_unguarded_sinks:
        unguarded = query_unguarded_sinks(function_name, joern_server)
        if unguarded:
            rec.joern_unguarded_sinks = unguarded

    if not rec.joern_sink_args:
        from packages.joern.runner import _validate_substitution_value
        for sink in sinks:
            sink_name = sink.split(".")[-1] if "." in sink else sink
            if not _validate_substitution_value(sink_name):
                continue
            args = query_sink_arg_index(function_name, sink_name, joern_server)
            if args:
                rec.joern_sink_args.extend(args)
        if rec.joern_sink_args:
            seen = set()
            deduped = []
            for a in rec.joern_sink_args:
                k = (a.get("sink"), a.get("arg_index"), a.get("source_param"))
                if k not in seen:
                    seen.add(k)
                    deduped.append(a)
            rec.joern_sink_args = deduped


def build_joern_evidence(
    target_path, out_dir, joern_overrides=None,
    on_progress: Callable | None = None,
    joern_server=None,
) -> dict[str, list] | None:
    """Run Joern pre-sweep (standard_sinks.sc) if available."""
    try:
        from .sweep import run_joern_pre_sweep
    except ImportError:
        return None

    tunables = joern_tunables(overrides=joern_overrides)
    if tunables is None:
        return None
    cache_dir = resolve_cpg_cache_dir(out_dir)
    flows = run_joern_pre_sweep(
        target_path, {},
        cache_dir=cache_dir,
        on_progress=on_progress,
        stall_timeout=tunables.cpg_timeout_s,
        query_timeout=tunables.query_timeout_s,
        heap_mb=tunables.heap_mb,
        server=joern_server,
    )
    return flows or None


def enrich_summaries_from_joern(
    joern_server,
    joern_flows: dict[str, list],
    taint_summary_results: dict[str, Any],
) -> None:
    """Run Joern summary batch for flow-involved methods and merge results."""
    try:
        from core.analysis.summaries import (
            EvidenceTier,
            FunctionSummary,
            Precondition,
            ReturnCondition,
            TaintRule,
        )
        from packages.joern.models import TaintFlow
    except ImportError:
        return

    methods: set[str] = set()
    file_for_method: dict[str, str] = {}
    for file_key, flow_list in joern_flows.items():
        for flow_dict in flow_list:
            try:
                flow = TaintFlow.from_dict(flow_dict) if isinstance(flow_dict, dict) else flow_dict
            except Exception:
                logger.debug("unparseable joern flow skipped", exc_info=True)
                continue
            if flow.source_method:
                methods.add(flow.source_method)
                file_for_method.setdefault(flow.source_method, file_key)
            for step in getattr(flow, "steps", []):
                fn = getattr(step, "function", "")
                if fn:
                    methods.add(fn)
                    file_for_method.setdefault(fn, getattr(step, "file", file_key))

    if not methods:
        return

    try:
        summaries = joern_server.run_summary_batch(
            list(methods), timeout=60,
        )
    except Exception:
        logger.debug("joern summary batch failed", exc_info=True)
        return

    if not summaries:
        return

    merged = 0
    for method_name, js in summaries.items():
        file_path = file_for_method.get(method_name, "")
        key = f"{file_path}:{method_name}" if file_path else method_name

        fs = FunctionSummary(
            function=method_name,
            file=file_path,
            taint_rules=[
                TaintRule(
                    source_param=t, source_index=0,
                    sink_call="", sink_arg_index=0,
                    evidence_tier=EvidenceTier.XREF_BACKED,
                )
                for t in js.taint_rules
            ],
            preconditions=[
                Precondition(
                    param="", param_index=0,
                    conditions=[p],
                    evidence_tier=EvidenceTier.XREF_BACKED,
                )
                for p in js.preconditions
            ],
            returns=[
                ReturnCondition(
                    code=r,
                    evidence_tier=EvidenceTier.XREF_BACKED,
                )
                for r in js.returns
            ],
            evidence_tier=EvidenceTier.XREF_BACKED,
            source="joern_cpg",
            confidence="high",
        )

        existing = taint_summary_results.get(key)
        if existing is None or getattr(existing, "source", "") != "joern_cpg":
            taint_summary_results[key] = fs
            merged += 1

    if merged:
        logger.info("joern_summary_batch: merged %d CPG-backed summaries", merged)


def resolve_joern_evidence(
    target_path, joern_overrides=None,
    on_joern_progress: Callable[[str], None] | None = None,
    joern_server=None,
    out_dir=None,
) -> tuple:
    """Resolve Joern evidence.

    Returns (joern_flows, joern_future).
    """
    if not joern_available(overrides=joern_overrides):
        return (None, None)

    if not (target_has_c_sources(target_path)
            or target_has_joern_sources(target_path)):
        return (None, None)

    def _progress(msg: str) -> None:
        # ONE channel per message: the progress callback renders on
        # the operator console (stdout); emitting the same text
        # through the logger too printed every Joern progress line
        # twice (stderr + stdout). The logger is the fallback when no
        # callback exists.
        if on_joern_progress:
            on_joern_progress(msg)
        else:
            logger.info(msg)

    if joern_server is not None and joern_server.is_alive():
        _progress("Joern pre-sweep (server mode, background)...")

    executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="joern-cpg")
    future = executor.submit(
        build_joern_evidence, target_path, out_dir, joern_overrides,
        _progress, joern_server,
    )
    executor.shutdown(wait=False)
    return (None, future)


def merge_joern_flows(
    joern_flows: dict[str, list],
    evidence_index: dict[str, Any],
    checklist: dict[str, Any],
    sarif_cache,
) -> dict[str, Any]:
    """Merge Joern taint flows into the evidence index."""
    from core.evidence import build_evidence_index
    merged = build_evidence_index(
        checklist=checklist,
        joern_flows=joern_flows,
        sarif_cache=sarif_cache,
    )
    from .safe_env import truncate_output
    for key, rec in merged.items():
        if key in evidence_index:
            existing = evidence_index[key]
            if rec.joern_flows and not existing.joern_flows:
                truncated, _note = truncate_output(rec.joern_flows, "joern")
                existing.joern_flows = truncated
        else:
            if rec.joern_flows:
                rec.joern_flows, _note = truncate_output(rec.joern_flows, "joern")
            evidence_index[key] = rec

    enriched = sum(1 for r in merged.values() if r.joern_flows)
    logger.info(
        "Joern evidence merged: %d functions enriched",
        enriched,
    )
    return evidence_index


def drain_joern_future(
    future: Future,
    evidence_index: dict[str, Any],
    checklist: dict[str, Any],
    sarif_cache,
) -> dict[str, Any]:
    """Drain a completed Joern future and merge flows into evidence_index."""
    try:
        joern_flows = future.result(timeout=0)
    except Exception:
        logger.warning("Joern background build failed", exc_info=True)
        return evidence_index

    if not joern_flows:
        return evidence_index

    return merge_joern_flows(joern_flows, evidence_index, checklist, sarif_cache)


def resolve_cpg_cache_dir(out_dir) -> Path | None:
    """Resolve the CPG cache directory for project-level reuse."""
    if not out_dir:
        return None
    project_dir = Path(out_dir).parent
    if project_dir and project_dir != Path(out_dir):
        return project_dir
    return None


def _current_content_hash(out_dir, target_path) -> str | None:
    """The current run's target content hash, or None when unavailable.

    Prefers the current run's own .raptor-run.json manifest; falls back
    to deriving it from the target tree the same way the CPG cache does.
    """
    manifest_path = Path(out_dir) / ".raptor-run.json"
    if manifest_path.exists():
        try:
            with open(manifest_path, encoding="utf-8") as f:
                own = json.load(f)
            own_hash = own.get("content_hash", "")
            if own_hash:
                return own_hash
        except (json.JSONDecodeError, OSError):
            pass
    if target_path is None or not Path(target_path).is_dir():
        return None
    try:
        from packages.joern.runner import _target_content_hash
        return _target_content_hash(Path(target_path))
    except Exception:
        logger.debug("content hash derivation failed", exc_info=True)
        return None


def import_sibling_joern_flows(
    out_dir,
    target_path=None,
) -> dict[str, list] | None:
    """Step 0i: import Joern taint flows from sibling project runs."""
    siblings = sibling_run_dirs(out_dir, target_path=target_path)
    if not siblings:
        return None
    imported: dict[str, list] = {}
    current_hash: str | None = None
    current_hash_resolved = False
    for sibling_dir in siblings:
        flows_path = sibling_dir / "joern-flows.json"
        if not flows_path.exists():
            continue
        manifest_path = sibling_dir / ".raptor-run.json"
        if manifest_path.exists():
            try:
                with open(manifest_path, encoding="utf-8") as f:
                    manifest = json.load(f)
                sibling_hash = manifest.get("content_hash", "")
                if sibling_hash:
                    # Staleness gate: a sibling run at a different
                    # commit carries taint flows for code that no
                    # longer exists. Only enforced when both hashes
                    # are known — legacy siblings without hashes
                    # import as before.
                    if not current_hash_resolved:
                        current_hash = _current_content_hash(
                            out_dir, target_path,
                        )
                        current_hash_resolved = True
                    if current_hash and sibling_hash != current_hash:
                        logger.info(
                            "sibling %s joern-flows stale "
                            "(hash %s → %s) — skipped",
                            sibling_dir.name,
                            sibling_hash[:8], current_hash[:8],
                        )
                        continue
            except (json.JSONDecodeError, OSError):
                pass
        try:
            with open(flows_path, encoding="utf-8") as f:
                flows_data = json.load(f)
            for key, flows in flows_data.items():
                imported.setdefault(key, []).extend(flows)
        except (json.JSONDecodeError, OSError):
            logger.debug("failed to import joern-flows from %s", sibling_dir.name)
    return imported if imported else None


def sibling_run_dirs(
    out_dir,
    *,
    target_path=None,
) -> list[Path]:
    """List sibling run directories under the same project."""
    out_dir = Path(out_dir)
    project_dir = out_dir.parent
    if not project_dir or project_dir == out_dir:
        return []
    dirs = []
    for child in sorted(project_dir.iterdir()):
        if not child.is_dir() or child == out_dir:
            continue
        if target_path is not None:
            manifest = child / ".raptor-run.json"
            if manifest.exists():
                try:
                    with open(manifest, encoding="utf-8") as f:
                        m = json.load(f)
                    sibling_target = m.get("target_path") or m.get("target", "")
                    if sibling_target and Path(sibling_target).resolve() != Path(target_path).resolve():
                        continue
                except (json.JSONDecodeError, OSError):
                    continue
            else:
                continue
        dirs.append(child)
    return dirs


def adaptive_max_depth(
    inventory: dict[str, Any] | None,
    entry_points: set,
    operator_override: int | None = None,
) -> int:
    """Compute propagation depth from call graph density."""
    from .propagation import DEFAULT_MAX_DEPTH

    if operator_override is not None:
        return operator_override

    if not inventory:
        return DEFAULT_MAX_DEPTH

    depths = _sample_entry_point_depths(inventory, entry_points)

    if not depths:
        return DEFAULT_MAX_DEPTH

    p90 = sorted(depths)[int(len(depths) * 0.9)]

    return max(5, min(p90 + 2, 15))


def _sample_entry_point_depths(
    inventory: dict[str, Any],
    entry_points: set,
) -> list[int]:
    """BFS from each entry point, recording reachable function depths."""
    edges: dict[str, list[str]] = {}
    for edge in inventory.get("call_edges", inventory.get("edges", [])):
        caller = edge.get("caller", "")
        callee = edge.get("callee", "")
        if caller and callee:
            edges.setdefault(caller, []).append(callee)

    if not edges:
        return []

    depths: list[int] = []
    for ep in list(entry_points)[:50]:
        name = ep.split(":")[-1] if ":" in ep else ep
        visited: set = set()
        queue = deque([(name, 0)])
        while queue:
            func, depth = queue.popleft()
            if func in visited:
                continue
            visited.add(func)
            depths.append(depth)
            for callee in edges.get(func, []):
                if callee not in visited and depth < 20:
                    queue.append((callee, depth + 1))

    return depths
