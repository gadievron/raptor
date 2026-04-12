"""Findings diff between two run directories.

Compares findings.json from two runs and reports what changed:
new findings, removed findings, changed rulings, and unchanged count.
Matches findings by (file, function, line) — stable across runs.
"""

from pathlib import Path
from typing import Any, Dict, List, Optional

from core.logging import get_logger
from core.project.findings_utils import dedup_key as _dedup_key
from core.project.findings_utils import load_findings_from_dir as _load_findings

logger = get_logger()


def _get_status(finding: Dict[str, Any]) -> Optional[str]:
    """Extract the ruling status from a finding."""
    ruling = finding.get("ruling")
    if isinstance(ruling, dict) and ruling.get("status"):
        return ruling["status"]
    if isinstance(ruling, str) and ruling:
        return ruling
    # Agentic format: boolean fields
    if "is_exploitable" in finding:
        return finding["is_exploitable"]  # Return bool, not str
    return None


def _finding_label(finding: Dict[str, Any]) -> str:
    """Human-readable label for a finding: file:function:line."""
    f = finding.get("file", "?")
    fn = finding.get("function", "?")
    line = finding.get("line", "?")
    return f"{f}:{fn}:{line}"


def _index_by_location(findings: List[Dict[str, Any]]) -> Dict[tuple, Dict[str, Any]]:
    """Index findings by (file, function, line). Stable across runs."""
    indexed = {}
    for f in findings:
        indexed[_dedup_key(f)] = f
    return indexed


def diff_runs(run_dir_a: Path, run_dir_b: Path) -> Dict[str, Any]:
    """Diff findings between two run directories.

    Args:
        run_dir_a: Earlier run directory (baseline).
        run_dir_b: Later run directory (comparison).

    Returns:
        Dict with keys:
            new: findings in B but not A (by location)
            removed: findings in A but not B
            changed: findings in both but with different status/ruling
            unchanged: count of identical findings
    """
    run_dir_a = Path(run_dir_a)
    run_dir_b = Path(run_dir_b)

    findings_a = _load_findings(run_dir_a)
    findings_b = _load_findings(run_dir_b)

    index_a = _index_by_location(findings_a)
    index_b = _index_by_location(findings_b)

    keys_a = set(index_a.keys())
    keys_b = set(index_b.keys())

    new = [index_b[k] for k in sorted(keys_b - keys_a)]
    removed = [index_a[k] for k in sorted(keys_a - keys_b)]

    changed = []
    unchanged = 0

    for key in sorted(keys_a & keys_b):
        status_a = _get_status(index_a[key])
        status_b = _get_status(index_b[key])
        if status_a != status_b:
            changed.append({
                "label": _finding_label(index_b[key]),
                "before": index_a[key],
                "after": index_b[key],
                "status_before": status_a,
                "status_after": status_b,
            })
        else:
            unchanged += 1

    return {
        "new": new,
        "removed": removed,
        "changed": changed,
        "unchanged": unchanged,
        "summary": {
            "run_a": str(run_dir_a),
            "run_b": str(run_dir_b),
            "findings_a": len(findings_a),
            "findings_b": len(findings_b),
            "new_count": len(new),
            "removed_count": len(removed),
            "changed_count": len(changed),
            "unchanged_count": unchanged,
        },
    }
