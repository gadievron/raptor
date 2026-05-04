"""Cross-run correlation for /project correlate.

Aggregates findings and tool coverage across all runs in a project to
produce: persistent findings, tool coverage matrix, gaps, and trends.
Pure Python, no LLM calls.
"""

from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from core.json import load_json
from core.run import load_run_metadata

from .findings_utils import dedup_key, load_findings_from_dir


def correlate_project(project) -> Dict[str, Any]:
    """Correlate findings and coverage across all runs in a project.

    Returns:
        persistent_findings: findings appearing in 2+ runs
        tool_coverage: {tool: [files...]} across all runs
        gaps: files in target not covered by any run
        trends: {finding_key: [{run, status, score}]}
        summary: counts
    """
    run_dirs = project.get_run_dirs(sweep=False)
    if not run_dirs:
        return _empty_result()

    findings_by_run = _load_all_findings(run_dirs)
    persistent = _find_persistent(findings_by_run)
    trends = _build_trends(findings_by_run, run_dirs)
    tool_coverage = _build_tool_coverage(run_dirs)

    n_persistent = len(persistent)
    n_total_unique = len({
        dedup_key(f)
        for findings in findings_by_run.values()
        for f in findings
    })
    n_runs = len(run_dirs)
    tools_used = sorted(tool_coverage.keys())

    return {
        "persistent_findings": persistent,
        "tool_coverage": tool_coverage,
        "trends": trends,
        "summary": {
            "runs": n_runs,
            "total_unique_findings": n_total_unique,
            "persistent_findings": n_persistent,
            "tools_used": tools_used,
        },
    }


def _empty_result() -> Dict[str, Any]:
    return {
        "persistent_findings": [],
        "tool_coverage": {},
        "trends": {},
        "summary": {
            "runs": 0,
            "total_unique_findings": 0,
            "persistent_findings": 0,
            "tools_used": [],
        },
    }


def _load_all_findings(
    run_dirs: List[Path],
) -> Dict[str, List[Dict[str, Any]]]:
    """Load findings from each run dir, keyed by run dir name."""
    result = {}
    for d in run_dirs:
        findings = load_findings_from_dir(d)
        if findings:
            result[d.name] = findings
    return result


def _find_persistent(
    findings_by_run: Dict[str, List[Dict]],
) -> List[Dict[str, Any]]:
    """Find findings that appear across 2+ runs."""
    key_to_runs: Dict[tuple, List[str]] = defaultdict(list)
    key_to_finding: Dict[tuple, Dict] = {}

    for run_name, findings in findings_by_run.items():
        for f in findings:
            k = dedup_key(f)
            key_to_runs[k].append(run_name)
            key_to_finding[k] = f

    persistent = []
    for k, runs in sorted(key_to_runs.items(), key=lambda x: -len(x[1])):
        if len(runs) < 2:
            continue
        f = key_to_finding[k]
        persistent.append({
            "file": f.get("file", ""),
            "function": f.get("function", ""),
            "line": f.get("line", 0),
            "vuln_type": f.get("vuln_type", ""),
            "status": f.get("final_status") or f.get("status", ""),
            "runs_seen": len(runs),
            "run_names": sorted(runs),
        })

    return persistent


def _build_trends(
    findings_by_run: Dict[str, List[Dict]],
    run_dirs: List[Path],
) -> Dict[str, List[Dict[str, Any]]]:
    """Track how each finding's status changed across runs.

    Returns {finding_label: [{run, status, score}]} ordered by run time.
    """
    run_order = [d.name for d in run_dirs]

    key_to_history: Dict[tuple, List[Dict]] = defaultdict(list)
    for run_name, findings in findings_by_run.items():
        for f in findings:
            k = dedup_key(f)
            key_to_history[k].append({
                "run": run_name,
                "status": f.get("final_status") or f.get("status", ""),
                "score": f.get("exploitability_score") or f.get("cvss_score_estimate"),
            })

    # Only include findings seen in 2+ runs (single-run = no trend)
    trends = {}
    for k, history in key_to_history.items():
        if len(history) < 2:
            continue
        history.sort(key=lambda h: run_order.index(h["run"]) if h["run"] in run_order else 999)
        label = f"{k[0]}:{k[1]}:{k[2]}" if k[1] else f"{k[0]}:{k[2]}"
        trends[label] = history

    return trends


def _build_tool_coverage(run_dirs: List[Path]) -> Dict[str, List[str]]:
    """Build tool → files-covered mapping from run metadata.

    Reads .raptor-run.json command field to determine which tool produced
    each run, then collects files from findings.
    """
    tool_files: Dict[str, set] = defaultdict(set)

    for d in run_dirs:
        meta = load_run_metadata(d)
        tool = (meta or {}).get("command", "unknown")
        findings = load_findings_from_dir(d)
        for f in findings:
            fp = f.get("file", "")
            if fp:
                tool_files[tool].add(fp)

    return {tool: sorted(files) for tool, files in sorted(tool_files.items())}
