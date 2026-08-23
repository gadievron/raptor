"""CodeQL pre-sweep and taint/sink discovery backend for /audit.

Runs CodeQL suites before the LLM loop and builds sink/taint
summaries from the target.  Separated from orchestrator.py.
"""

from __future__ import annotations

import logging
import os
import stat as stat_mod
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Byte budgets for the taint-summary walk over the (target-controlled)
# source tree. Per-file: real source files this large are generated
# code, not worth summarising; the multi-language pass historically
# skipped >500k-char files AFTER reading them fully — now the lstat
# size gate fires before any read. Aggregate: caps the total bytes the
# walk will ever read/parse so a tree of many cap-sized files cannot
# grind the pre-sweep.
_TAINT_PER_FILE_CAP = 500_000
_TAINT_AGGREGATE_CAP = 128 * 1024 * 1024


def _admit_taint_file(path: Path, budget: dict[str, int]) -> bool:
    """lstat-based admission for one candidate file.

    Refuses symlinks and non-regular files (lstat, never follows),
    over-cap files, and files that would exceed the remaining
    aggregate budget. Mutates ``budget["remaining"]`` on admission.
    """
    try:
        st = path.lstat()
    except OSError:
        return False
    if not stat_mod.S_ISREG(st.st_mode):
        return False
    if st.st_size > _TAINT_PER_FILE_CAP:
        return False
    if st.st_size > budget["remaining"]:
        if not budget["warned"]:
            budget["warned"] = True
            logger.warning(
                "taint_summary: aggregate byte budget (%d) exhausted; "
                "remaining files skipped", _TAINT_AGGREGATE_CAP,
            )
        return False
    budget["remaining"] -= st.st_size
    return True


def codeql_pre_sweep(
    codeql_db_path, out_dir, sarif_cache,
) -> None:
    """Step 0g: run standard CodeQL suites before the LLM loop."""
    try:
        from packages.codeql.query_runner import QueryRunner
    except ImportError:
        logger.debug("codeql runner not importable; skipping pre-sweep")
        return

    db_path = Path(codeql_db_path)
    if not db_path.is_dir():
        logger.warning("codeql_pre_sweep: database not found: %s", db_path)
        return

    import subprocess as _sp
    try:
        from core.config import RaptorConfig

        info = _sp.run(
            ["codeql", "resolve", "database", str(db_path)],
            capture_output=True, text=True, timeout=30,
            # Sanitised environment like every other subprocess that
            # touches scan-derived paths (the database may live under
            # the scanned repo).
            env=RaptorConfig.get_safe_env(),
        )
        language = None
        for line in info.stdout.splitlines():
            if line.startswith("primaryLanguage:"):
                language = line.split(":", 1)[1].strip()
                break
        if not language:
            logger.warning("codeql_pre_sweep: could not detect language")
            return
    except (OSError, _sp.TimeoutExpired) as exc:
        logger.warning("codeql_pre_sweep: resolve database failed: %s", exc)
        return

    scan_dir = Path(out_dir) / "scan"
    scan_dir.mkdir(parents=True, exist_ok=True)

    try:
        runner = QueryRunner()
        result = runner.run_suite(
            database_path=db_path,
            language=language,
            out_dir=scan_dir,
            use_extended=True,
        )
    except Exception as exc:
        logger.warning("codeql_pre_sweep: suite run failed: %s", exc)
        return

    if not result.success or not result.sarif_path:
        logger.warning(
            "codeql_pre_sweep: suite returned success=%s sarif=%s errors=%s",
            result.success, result.sarif_path, result.errors,
        )
        return

    import json as _json_mod
    try:
        data = _json_mod.loads(result.sarif_path.read_text())
    except (OSError, _json_mod.JSONDecodeError) as exc:
        logger.warning("codeql_pre_sweep: failed to read SARIF: %s", exc)
        return

    ingested = 0
    for run in data.get("runs", []):
        for r in run.get("results", []):
            locs = r.get("locations") or [{}]
            loc = locs[0] if locs else {}
            phys = loc.get("physicalLocation", {})
            uri = phys.get("artifactLocation", {}).get("uri", "")
            from .sweep import _normalize_sarif_path
            normalized = _normalize_sarif_path(uri)
            if normalized:
                sarif_cache._by_file.setdefault(normalized, []).append(r)
                ingested += 1

    logger.info(
        "codeql_pre_sweep: %s findings=%d ingested=%d duration=%.1fs",
        language, result.findings_count, ingested,
        result.duration_seconds,
    )


_SINK_CACHE_FILENAME = "sink-discovery-cache.json"


def _sink_discovery_fingerprint(target_path, scope_dirs) -> str | None:
    """Deterministic fingerprint of the discovery inputs: the file
    set + contents the discovery walk would read, enumerated by the
    walk's own gate chain (:func:`iter_discovery_source_files`) so
    the fingerprint and the build can never drift. Hashing the bytes
    is a small fraction of re-extracting every call graph."""
    try:
        from core.inventory.sink_discovery import (
            iter_discovery_source_files,
        )

        from .prep_cache import content_fingerprint

        return content_fingerprint(
            (rel, path.read_bytes())
            for path, rel, _lang in iter_discovery_source_files(
                Path(target_path), scope_dirs=scope_dirs,
            )
        )
    except Exception:
        logger.debug("sink-discovery fingerprint failed", exc_info=True)
        return None


def build_sink_results(
    target_path, taint_approx_results=None,
    *, checklist=None, out_dir=None, scope=None,
):
    """Run sink discovery on the target.

    The discovery result (a pure function of the source tree) rides
    the prep-cache reload seam: a resumed segment reloads it on an
    unchanged tree instead of re-extracting every call graph. The
    heuristic project-sink pass below stays live every run — it also
    consumes this run's taint approximation, and it is cheap next to
    the tree parse.
    """
    if not target_path or not Path(target_path).is_dir():
        return None

    scope_dirs = (
        [str(Path(target_path) / s) for s in scope]
        if scope else None
    )

    result = None
    fingerprint: str | None = None
    if out_dir is not None:
        from .prep_cache import load_prep_cache

        fingerprint = _sink_discovery_fingerprint(target_path, scope_dirs)
        if fingerprint is not None:
            cached = load_prep_cache(
                out_dir, _SINK_CACHE_FILENAME, fingerprint,
                label="sink discovery",
            )
            if isinstance(cached, dict):
                try:
                    from core.inventory.sink_discovery import (
                        SinkDiscoveryResult,
                    )

                    result = SinkDiscoveryResult.from_full_dict(cached)
                    logger.info(
                        "sink discovery: reloaded %d direct / %d "
                        "transitive sinks from the prep cache (tree "
                        "fingerprint match) — call-graph re-extraction "
                        "skipped",
                        len(result.direct_sinks),
                        len(result.transitive_reach),
                    )
                except Exception:
                    result = None
                    logger.debug(
                        "sink-discovery cache reload failed — "
                        "re-extracting", exc_info=True,
                    )

    if result is None:
        try:
            from core.inventory.sink_discovery import (
                discover_sinks_for_target,
            )
            result = discover_sinks_for_target(
                Path(target_path), scope_dirs=scope_dirs,
            )
        except ImportError:
            return None
        except Exception:
            logger.debug("sink discovery failed", exc_info=True)
            return None
        if out_dir is not None and fingerprint is not None:
            from .prep_cache import write_prep_cache

            # Persist BEFORE the heuristic merge below mutates the
            # result — the cache holds the pure function of the tree.
            write_prep_cache(
                out_dir, _SINK_CACHE_FILENAME, fingerprint,
                result.to_full_dict(), label="sink discovery",
            )

    call_graphs: dict[str, Any] | None = None
    if checklist:
        call_graphs = {}
        for fi in checklist.get("files", []):
            cg = fi.get("call_graph")
            if isinstance(cg, dict) and cg.get("calls"):
                call_graphs[fi["path"]] = cg

    try:
        from .sink_heuristics import discover_project_sinks, merge_discovered_sinks
        heuristic = discover_project_sinks(
            result,
            call_graphs=call_graphs,
            taint_approx=taint_approx_results,
        )
        if heuristic.discovered:
            merge_discovered_sinks(result, heuristic)
            logger.info(
                "sink_heuristics: %d project-specific sinks "
                "(wrapper=%d, naming=%d, side_effect=%d)",
                len(heuristic.discovered),
                heuristic.wrapper_count,
                heuristic.naming_count,
                heuristic.side_effect_count,
            )
            if out_dir:
                import json as _json
                hp = Path(out_dir) / "discovered-sinks.json"
                hp.write_text(
                    _json.dumps(heuristic.to_dict(), indent=2) + "\n",
                )
    except Exception:
        logger.debug("sink heuristics failed", exc_info=True)

    return result


def _path_in_scope_dirs(p, scope_dirs) -> bool:
    """Separator-anchored scope containment.

    A bare ``startswith`` on the resolved-path string admitted sibling
    directories — scope ``src`` matched ``src2/...``. Anchor on
    ``os.sep`` (or exact equality) instead. ``scope_dirs`` holds
    resolved directory strings; falsy means unscoped (everything in).
    """
    if not scope_dirs:
        return True
    rp = str(Path(p).resolve())
    return any(
        rp == d or rp.startswith(d + os.sep) for d in scope_dirs
    )


def build_taint_summary(
    target_path,
    scope=None,
) -> dict[str, Any] | None:
    """Build taint summaries for all supported languages."""
    if not target_path or not Path(target_path).is_dir():
        return None

    target_path = Path(target_path)
    scope_dirs = (
        tuple(str((target_path / s).resolve()) for s in scope)
        if scope else None
    )
    results: dict[str, Any] = {}

    def _in_scope(p):
        return _path_in_scope_dirs(p, scope_dirs)

    # Shared across both language passes: total bytes admitted.
    budget = {"remaining": _TAINT_AGGREGATE_CAP, "warned": False}

    try:
        from core.analysis.python_module_callgraph import build_python_module_callgraph
        from core.analysis.taint_summaries import build_taint_summaries

        for path in target_path.rglob("*.py"):
            if not _in_scope(path):
                continue
            if not _admit_taint_file(path, budget):
                continue
            try:
                cg = build_python_module_callgraph(path)
            except Exception:
                continue
            if cg is None:
                continue
            try:
                summaries = build_taint_summaries(cg, path)
            except Exception:
                continue
            rel = str(path.relative_to(target_path))
            for func_name, summary in summaries.items():
                results[f"{rel}:{func_name}"] = summary
    except ImportError:
        pass

    try:
        from core.analysis.taint_multi_lang import (
            extract_summaries_for_file,
            _LANG_EXTENSIONS,
        )
        multi_lang_count = 0
        for path in target_path.rglob("*"):
            # Cheap name-based filters first, then the lstat-based
            # admission (symlink refusal + per-file cap + aggregate
            # budget) — nothing is read before every gate passes.
            if path.suffix.lower() not in _LANG_EXTENSIONS:
                continue
            if not _in_scope(path):
                continue
            if not _admit_taint_file(path, budget):
                continue
            try:
                content = path.read_text(errors="replace")
            except OSError:
                continue
            rel = str(path.relative_to(target_path))
            try:
                summaries = extract_summaries_for_file(content, rel)
            except Exception:
                continue
            for func_name, summary in summaries.items():
                results[f"{rel}:{func_name}"] = summary
                multi_lang_count += 1
        if multi_lang_count:
            logger.info(
                "taint_summary: %d multi-language functions analysed "
                "(Java/JS/Go/Rust)",
                multi_lang_count,
            )
    except ImportError:
        pass

    if results:
        py_count = sum(
            1 for k in results if k.rsplit(":", 1)[0].endswith(".py")
        )
        if py_count:
            logger.info("taint_summary: %d Python functions analysed", py_count)
    return results or None
