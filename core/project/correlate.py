"""Cross-run correlation for /project correlate.

Aggregates findings and tool coverage across all runs in a project to
produce: disagreements, new/resolved findings, tool gaps, persistent
findings, and trends. Pure Python, no LLM calls.

Output is action-oriented: every section answers "what should I look at next?"
"""

from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from core.json import load_json
from core.run import load_run_metadata

from .findings_utils import dedup_key, load_findings_from_dir

# --- Status normalization ---

POSITIVE_VERDICTS = frozenset({
    "exploitable", "confirmed", "confirmed_unverified",
    "confirmed_constrained", "confirmed_blocked", "poc_success",
    "validated",
})

NEGATIVE_VERDICTS = frozenset({
    "ruled_out", "disproven", "false_positive",
    "test_code", "dead_code", "mitigated", "unreachable",
})

INCONCLUSIVE_VERDICTS = frozenset({
    "not_disproven",
})

SCAN_COMMAND_TYPES = frozenset({"scan", "codeql"})
LLM_COMMAND_TYPES = frozenset({"agentic", "validate"})


def normalize_verdict(status: str) -> str:
    s = (status or "").strip().lower()
    if s in POSITIVE_VERDICTS:
        return "positive"
    if s in NEGATIVE_VERDICTS:
        return "negative"
    if s in INCONCLUSIVE_VERDICTS:
        return "inconclusive"
    return "unknown"


def get_finding_status(finding: Dict) -> str:
    if "is_true_positive" in finding or "is_exploitable" in finding:
        if finding.get("is_true_positive") is False:
            return "false_positive"
        if finding.get("is_exploitable"):
            return "exploitable"
        if finding.get("is_true_positive"):
            return "confirmed"
    return finding.get("final_status") or finding.get("status") or ""


# --- Main entry point ---

def correlate_project(project) -> Dict[str, Any]:
    """Correlate findings and coverage across all runs in a project.

    Returns an action-oriented result: disagreements first, then new/resolved
    findings, tool gaps, and finally the existing persistent/trends/coverage.
    """
    run_dirs = project.get_run_dirs(sweep=False)
    if not run_dirs:
        return _empty_result()

    run_models = {d.name: _get_run_model(d) for d in run_dirs}
    run_types = _get_run_types(run_dirs)
    findings_by_run = _load_all_findings(run_dirs)

    # Existing
    persistent = _find_persistent(findings_by_run, run_models)
    trends = _build_trends(findings_by_run, run_dirs, run_models)
    tool_coverage = _build_tool_coverage(run_dirs)

    # New actionable analyses
    disagreements = _find_disagreements(findings_by_run, run_models)
    new_resolved = _find_new_and_resolved(findings_by_run, run_dirs, run_types)
    tool_gaps = _build_tool_gaps(run_dirs, findings_by_run, run_types)
    actions = _build_action_list(
        disagreements, new_resolved, tool_gaps, persistent,
    )

    n_persistent = len(persistent)
    n_total_unique = len({
        dedup_key(f)
        for findings in findings_by_run.values()
        for f in findings
    })

    return {
        "actions": actions,
        "disagreements": disagreements,
        "new_findings": new_resolved["new_findings"],
        "potentially_resolved": new_resolved["potentially_resolved"],
        "tool_gaps": tool_gaps,
        "persistent_findings": persistent,
        "tool_coverage": tool_coverage,
        "trends": trends,
        "summary": {
            "runs": len(run_dirs),
            "total_unique_findings": n_total_unique,
            "persistent_findings": n_persistent,
            "tools_used": sorted(tool_coverage.keys()),
            "disagreements": len(disagreements),
            "new_findings": len(new_resolved["new_findings"]),
            "potentially_resolved": len(new_resolved["potentially_resolved"]),
        },
    }


def _empty_result() -> Dict[str, Any]:
    return {
        "actions": [],
        "disagreements": [],
        "new_findings": [],
        "potentially_resolved": [],
        "tool_gaps": {
            "scanned_not_validated": [],
            "validated_not_scanned": [],
            "missing_command_types": [],
            "suggested_next_runs": [],
        },
        "persistent_findings": [],
        "tool_coverage": {},
        "trends": {},
        "summary": {
            "runs": 0,
            "total_unique_findings": 0,
            "persistent_findings": 0,
            "tools_used": [],
            "disagreements": 0,
            "new_findings": 0,
            "potentially_resolved": 0,
        },
    }


# --- Helpers ---

def _get_run_model(run_dir: Path) -> str:
    """Extract the analysis model name for a run."""
    orch = load_json(run_dir / "orchestrated_report.json")
    if orch and isinstance(orch, dict):
        o = orch.get("orchestration", {})
        models = o.get("analysis_models", [])
        if models:
            return ", ".join(models)
        m = o.get("analysis_model")
        if m:
            return m
    meta = load_run_metadata(run_dir)
    if meta:
        extra = meta.get("extra", {})
        models = extra.get("analysis_models", [])
        if models:
            return ", ".join(models)
        m = extra.get("analysis_model")
        if m:
            return m
    return ""


def _get_run_types(run_dirs: List[Path]) -> Dict[str, str]:
    """Map run dir name -> command type (scan, agentic, validate, etc.)."""
    result = {}
    for d in run_dirs:
        meta = load_run_metadata(d)
        result[d.name] = (meta or {}).get("command", "unknown")
    return result


def _load_all_findings(
    run_dirs: List[Path],
) -> Dict[str, List[Dict[str, Any]]]:
    """Load findings from each run dir, keyed by run dir name.

    Prefers orchestrated_report.json results (which have analysed_by and
    multi_model_analyses) over plain findings.json.
    """
    result = {}
    for d in run_dirs:
        orch = load_json(d / "orchestrated_report.json")
        if orch and isinstance(orch, dict):
            findings = orch.get("results", [])
            if findings:
                result[d.name] = findings
                continue
        findings = load_findings_from_dir(d)
        if findings:
            result[d.name] = findings
    return result


# --- Disagreement detection ---

def _find_disagreements(
    findings_by_run: Dict[str, List[Dict]],
    run_models: Dict[str, str],
) -> List[Dict[str, Any]]:
    """Find findings where runs disagree on verdict (positive vs negative)."""
    key_to_verdicts: Dict[tuple, List[Dict]] = defaultdict(list)
    key_to_finding: Dict[tuple, Dict] = {}

    for run_name, findings in findings_by_run.items():
        for f in findings:
            k = dedup_key(f)
            key_to_finding[k] = f
            status = get_finding_status(f)
            if not status:
                continue
            verdict = normalize_verdict(status)
            if verdict == "unknown":
                continue
            model = f.get("analysed_by") or run_models.get(run_name, "")
            key_to_verdicts[k].append({
                "run": run_name,
                "status": status,
                "verdict": verdict,
                "model": model,
                "score": f.get("exploitability_score")
                         or f.get("cvss_score_estimate"),
            })

    disagreements = []
    for k, verdicts in key_to_verdicts.items():
        verdict_set = {v["verdict"] for v in verdicts}
        if "positive" in verdict_set and "negative" in verdict_set:
            dtype = "positive_vs_negative"
        elif "positive" in verdict_set and "inconclusive" in verdict_set:
            dtype = "positive_vs_inconclusive"
        else:
            continue

        f = key_to_finding[k]
        scores = [v["score"] for v in verdicts if v["score"]]
        disagreements.append({
            "file": f.get("file", ""),
            "function": f.get("function", ""),
            "line": f.get("line", 0),
            "vuln_type": f.get("vuln_type", ""),
            "verdicts": verdicts,
            "disagreement_type": dtype,
            "max_score": max(scores) if scores else 0,
        })

    disagreements.sort(key=lambda d: (
        0 if d["disagreement_type"] == "positive_vs_negative" else 1,
        -(d["max_score"] or 0),
    ))
    return disagreements


# --- New / resolved detection ---

def _find_new_and_resolved(
    findings_by_run: Dict[str, List[Dict]],
    run_dirs: List[Path],
    run_types: Dict[str, str],
) -> Dict[str, List[Dict]]:
    """Detect findings that appeared or disappeared across runs.

    Only compares runs of the same command type — a finding in scan-001
    but absent from validate-001 is expected, not "resolved."
    """
    run_order = [d.name for d in run_dirs]

    key_to_runs_by_type: Dict[tuple, Dict[str, List[str]]] = defaultdict(
        lambda: defaultdict(list),
    )
    key_to_finding: Dict[tuple, Dict] = {}

    for run_name, findings in findings_by_run.items():
        cmd_type = run_types.get(run_name, "unknown")
        for f in findings:
            k = dedup_key(f)
            key_to_runs_by_type[k][cmd_type].append(run_name)
            key_to_finding[k] = f

    new_findings = []
    potentially_resolved = []

    for k, type_runs in key_to_runs_by_type.items():
        f = key_to_finding[k]
        for cmd_type, runs in type_runs.items():
            typed_order = [r for r in run_order if run_types.get(r) == cmd_type]
            if len(typed_order) < 2:
                continue

            earliest = typed_order[0]
            latest = typed_order[-1]

            first_run = min(runs, key=lambda r: (
                run_order.index(r) if r in run_order else 999
            ))
            if first_run != earliest:
                status = get_finding_status(f)
                new_findings.append({
                    "file": f.get("file", ""),
                    "function": f.get("function", ""),
                    "line": f.get("line", 0),
                    "vuln_type": f.get("vuln_type", ""),
                    "status": status,
                    "verdict": normalize_verdict(status),
                    "first_seen_run": first_run,
                    "command_type": cmd_type,
                })

            if latest not in runs:
                last_run = max(runs, key=lambda r: (
                    run_order.index(r) if r in run_order else 0
                ))
                absent = [
                    r for r in typed_order
                    if r not in runs
                    and run_order.index(r) > run_order.index(last_run)
                ]
                potentially_resolved.append({
                    "file": f.get("file", ""),
                    "function": f.get("function", ""),
                    "line": f.get("line", 0),
                    "vuln_type": f.get("vuln_type", ""),
                    "last_seen_run": last_run,
                    "absent_from": absent,
                    "command_type": cmd_type,
                })

    new_findings.sort(key=lambda n: (
        0 if n["verdict"] == "positive" else 1,
    ))
    return {"new_findings": new_findings, "potentially_resolved": potentially_resolved}


# --- Tool gap analysis ---

def _build_tool_gaps(
    run_dirs: List[Path],
    findings_by_run: Dict[str, List[Dict]],
    run_types: Dict[str, str],
) -> Dict[str, Any]:
    """Identify coverage gaps between scan tools and LLM analysis."""
    scan_files: Dict[str, set] = defaultdict(set)
    llm_files: Dict[str, set] = defaultdict(set)

    for run_name, findings in findings_by_run.items():
        cmd = run_types.get(run_name, "unknown")
        for f in findings:
            fp = f.get("file", "")
            if not fp:
                continue
            k = dedup_key(f)
            if cmd in SCAN_COMMAND_TYPES:
                scan_files[fp].add(k)
            elif cmd in LLM_COMMAND_TYPES:
                llm_files[fp].add(k)

    scanned_not_validated = []
    for fp in sorted(scan_files.keys() - llm_files.keys()):
        n = len(scan_files[fp])
        scanned_not_validated.append({
            "file": fp,
            "finding_count": n,
        })

    validated_not_scanned = sorted(llm_files.keys() - scan_files.keys())

    types_present = set(run_types.values())
    missing = []
    if not types_present & SCAN_COMMAND_TYPES:
        missing.append("scan")
    if not types_present & LLM_COMMAND_TYPES:
        missing.append("validate")

    suggested = []
    if scanned_not_validated:
        n = sum(item["finding_count"] for item in scanned_not_validated)
        suggested.append(
            f"raptor validate  # {n} unvalidated scan finding"
            f"{'s' if n != 1 else ''}"
        )
    if validated_not_scanned:
        suggested.append(
            f"raptor scan  # {len(validated_not_scanned)} file"
            f"{'s' if len(validated_not_scanned) != 1 else ''}"
            f" with LLM findings but no static analysis"
        )
    for cmd in missing:
        suggested.append(f"raptor {cmd}  # no {cmd} runs found")

    return {
        "scanned_not_validated": scanned_not_validated,
        "validated_not_scanned": [{"file": fp} for fp in validated_not_scanned],
        "missing_command_types": missing,
        "suggested_next_runs": suggested,
    }


# --- Action list ---

def _build_action_list(
    disagreements: List[Dict],
    new_resolved: Dict[str, List[Dict]],
    tool_gaps: Dict[str, Any],
    persistent: List[Dict],
) -> List[Dict[str, Any]]:
    """Synthesize all analyses into a single prioritised action list."""
    actions: List[Dict[str, Any]] = []

    for d in disagreements:
        pos = [v for v in d["verdicts"] if v["verdict"] == "positive"]
        neg = [v for v in d["verdicts"] if v["verdict"] == "negative"]
        inc = [v for v in d["verdicts"] if v["verdict"] == "inconclusive"]
        if d["disagreement_type"] == "positive_vs_negative":
            summary = (
                f"{d['file']}:{d['line']} ({d['vuln_type']}) — "
                f"{len(pos)} positive vs {len(neg)} negative verdict"
                f"{'s' if len(neg) != 1 else ''}"
            )
            priority = 1
        else:
            summary = (
                f"{d['file']}:{d['line']} ({d['vuln_type']}) — "
                f"{len(pos)} positive vs {len(inc)} inconclusive"
            )
            priority = 4
        actions.append({
            "priority": priority,
            "category": "disagreement",
            "summary": summary,
            "detail": d,
        })

    for nf in new_resolved.get("new_findings", []):
        actions.append({
            "priority": 2 if nf["verdict"] == "positive" else 6,
            "category": "new_finding",
            "summary": (
                f"{nf['file']}:{nf['line']} ({nf['vuln_type']}) — "
                f"new in {nf['first_seen_run']}"
            ),
            "detail": nf,
        })

    for gap in tool_gaps.get("scanned_not_validated", []):
        actions.append({
            "priority": 3,
            "category": "tool_gap",
            "summary": (
                f"{gap['file']} — {gap['finding_count']} scan finding"
                f"{'s' if gap['finding_count'] != 1 else ''}"
                f" never LLM-validated"
            ),
            "detail": gap,
        })

    for r in new_resolved.get("potentially_resolved", []):
        actions.append({
            "priority": 5,
            "category": "resolved",
            "summary": (
                f"{r['file']}:{r['line']} ({r['vuln_type']}) — "
                f"absent from latest {r['command_type']} run"
            ),
            "detail": r,
        })

    for cmd in tool_gaps.get("missing_command_types", []):
        actions.append({
            "priority": 7,
            "category": "tool_gap",
            "summary": f"No {cmd} runs found",
            "command": f"raptor {cmd}",
            "detail": {"missing": cmd},
        })

    actions.sort(key=lambda a: a["priority"])
    return actions


# --- Existing analyses (persistent, trends, coverage) ---

def _find_persistent(
    findings_by_run: Dict[str, List[Dict]],
    run_models: Dict[str, str],
) -> List[Dict[str, Any]]:
    """Find findings that appear across 2+ runs."""
    key_to_runs: Dict[tuple, List[str]] = defaultdict(list)
    key_to_finding: Dict[tuple, Dict] = {}
    key_to_models: Dict[tuple, set] = defaultdict(set)

    for run_name, findings in findings_by_run.items():
        for f in findings:
            k = dedup_key(f)
            key_to_runs[k].append(run_name)
            key_to_finding[k] = f
            model = f.get("analysed_by") or run_models.get(run_name, "")
            if model:
                key_to_models[k].add(model)

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
            "models": sorted(key_to_models.get(k, set())),
        })

    return persistent


def _build_trends(
    findings_by_run: Dict[str, List[Dict]],
    run_dirs: List[Path],
    run_models: Dict[str, str],
) -> Dict[str, List[Dict[str, Any]]]:
    """Track how each finding's status changed across runs.

    Returns {finding_label: [{run, status, score, model}]} ordered by run time.
    """
    run_order = [d.name for d in run_dirs]

    key_to_history: Dict[tuple, List[Dict]] = defaultdict(list)
    for run_name, findings in findings_by_run.items():
        for f in findings:
            k = dedup_key(f)
            model = f.get("analysed_by") or run_models.get(run_name, "")
            key_to_history[k].append({
                "run": run_name,
                "status": f.get("final_status") or f.get("status", ""),
                "score": f.get("exploitability_score") or f.get("cvss_score_estimate"),
                "model": model,
            })

    trends = {}
    for k, history in key_to_history.items():
        if len(history) < 2:
            continue
        history.sort(key=lambda h: run_order.index(h["run"]) if h["run"] in run_order else 999)
        label = f"{k[0]}:{k[1]}:{k[2]}" if k[1] else f"{k[0]}:{k[2]}"
        trends[label] = history

    return trends


def _build_tool_coverage(run_dirs: List[Path]) -> Dict[str, List[str]]:
    """Build tool -> files-covered mapping from run metadata."""
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
