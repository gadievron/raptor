"""CodeQL pre-sweep and taint/sink discovery backend for /audit.

Runs CodeQL suites before the LLM loop and builds sink/taint
summaries from the target.  Separated from orchestrator.py.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


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
        info = _sp.run(
            ["codeql", "resolve", "database", str(db_path)],
            capture_output=True, text=True, timeout=30,
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


def build_sink_results(
    target_path, taint_approx_results=None,
    *, checklist=None, out_dir=None, scope=None,
):
    """Run sink discovery on the target."""
    if not target_path or not Path(target_path).is_dir():
        return None

    try:
        from core.inventory.sink_discovery import discover_sinks_for_target
        scope_dirs = (
            [str(Path(target_path) / s) for s in scope]
            if scope else None
        )
        result = discover_sinks_for_target(
            Path(target_path), scope_dirs=scope_dirs,
        )
    except ImportError:
        return None
    except Exception:
        logger.debug("sink discovery failed", exc_info=True)
        return None

    call_graphs: Optional[Dict[str, Any]] = None
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


def build_taint_summary(
    target_path,
    scope=None,
) -> Optional[Dict[str, Any]]:
    """Build taint summaries for all supported languages."""
    if not target_path or not Path(target_path).is_dir():
        return None

    target_path = Path(target_path)
    scope_prefixes = (
        tuple(str((target_path / s).resolve()) for s in scope)
        if scope else None
    )
    results: Dict[str, Any] = {}

    def _in_scope(p):
        return not scope_prefixes or str(p.resolve()).startswith(scope_prefixes)

    try:
        from core.analysis.python_module_callgraph import build_python_module_callgraph
        from core.analysis.taint_summaries import build_taint_summaries

        for path in target_path.rglob("*.py"):
            if not path.is_file():
                continue
            if not _in_scope(path):
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
            if not path.is_file():
                continue
            if not _in_scope(path):
                continue
            if path.suffix.lower() not in _LANG_EXTENSIONS:
                continue
            try:
                content = path.read_text(errors="replace")
            except OSError:
                continue
            if len(content) > 500_000:
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
