"""Findings diff between two run directories.

Compares findings.json from two runs and reports what changed:
new findings, removed findings, changed rulings, and unchanged count.
"""

from pathlib import Path
from typing import Any, Dict, List, Optional

from core.logging import get_logger
from core.project.findings_utils import get_finding_id as _get_finding_id
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


def _index_by_id(findings: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """Index findings by their ID. Skips findings without an ID."""
    indexed = {}
    for f in findings:
        fid = _get_finding_id(f)
        if fid:
            indexed[fid] = f
    return indexed


def diff_runs(run_dir_a: Path, run_dir_b: Path) -> Dict[str, Any]:
    """Diff findings between two run directories.

    Args:
        run_dir_a: Earlier run directory (baseline).
        run_dir_b: Later run directory (comparison).

    Returns:
        Dict with keys:
            new: findings in B but not A (by finding ID)
            removed: findings in A but not B
            changed: findings in both but with different status/ruling
            unchanged: count of identical findings
    """
    run_dir_a = Path(run_dir_a)
    run_dir_b = Path(run_dir_b)

    findings_a = _load_findings(run_dir_a)
    findings_b = _load_findings(run_dir_b)

    index_a = _index_by_id(findings_a)
    index_b = _index_by_id(findings_b)

    ids_a = set(index_a.keys())
    ids_b = set(index_b.keys())

    new = [index_b[fid] for fid in sorted(ids_b - ids_a)]
    removed = [index_a[fid] for fid in sorted(ids_a - ids_b)]

    changed = []
    unchanged = 0

    for fid in sorted(ids_a & ids_b):
        status_a = _get_status(index_a[fid])
        status_b = _get_status(index_b[fid])
        if status_a != status_b:
            changed.append({
                "id": fid,
                "before": index_a[fid],
                "after": index_b[fid],
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
