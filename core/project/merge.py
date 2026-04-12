"""Merge findings and SARIF across multiple run directories.

Combines findings.json, SARIF files, and artefacts from multiple runs
into a single output directory. Deduplicates findings by (file, function, line),
latest wins.
"""

import re
import shutil
from pathlib import Path
from typing import Any, Dict, List

from core.json import save_json
from core.logging import get_logger
from core.project.findings_utils import count_vulns as _count_vulns
from core.project.findings_utils import dedup_key as _dedup_key
from core.project.findings_utils import load_findings_from_dir as _load_findings_from_dir
from core.sarif.parser import merge_sarif

logger = get_logger()

# Files that the merge logic knows how to handle directly.
KNOWN_FILES = {
    "findings.json",
    ".raptor-run.json",
    "checklist.json",
    "validation-report.md",
    "agentic-report.md",
    "summary.txt",
    "diagrams.md",
    "scan_metrics.json",
    "scan-manifest.json",
    "verification.json",
    "orchestrated_report.json",
    "raptor_agentic_report.json",
}

# Patterns for known file types (matched by extension).
KNOWN_EXTENSIONS = {".sarif", ".exit", ".stderr.log"}


def _is_known_file(name: str) -> bool:
    """Check if a filename is in the known set or matches known extensions."""
    if name in KNOWN_FILES:
        return True
    for ext in KNOWN_EXTENSIONS:
        if name.endswith(ext):
            return True
    return False


def _extract_date_from_dir(run_dir: Path) -> str:
    """Extract a date-like suffix from a run directory name for collision renaming."""
    match = re.search(r'(\d{8}[-_]\d{6})', run_dir.name)
    if match:
        return match.group(1)
    match = re.search(r'(\d{8})', run_dir.name)
    if match:
        return match.group(1)
    return run_dir.name


def _finding_key(finding: Dict[str, Any]) -> tuple:
    """Dedup key for a finding: (file, function, line). More stable than ID."""
    return _dedup_key(finding)


# Status progression: higher rank = more information about the finding.
# When merging across runs, prefer the finding with the highest-ranked status
# so that a correct ruling from one run isn't overwritten by stale data from
# another run (e.g. one that hit a pipeline bug or where the LLM got it wrong).
_STATUS_RANK = {
    "exploitable": 7,
    "confirmed_constrained": 6,
    "confirmed_blocked": 6,
    "confirmed_unverified": 5,
    "confirmed": 5,
    "ruled_out": 4,
    "disproven": 4,
    "false_positive": 4,
    "test_code": 4,
    "dead_code": 4,
    "mitigated": 4,
    "unreachable": 4,
    "poc_success": 3,
    "not_disproven": 2,
}


def _status_rank(finding: Dict[str, Any]) -> int:
    """Return a rank for how far a finding has progressed through validation."""
    status = finding.get("final_status") or finding.get("status") or ""
    return _STATUS_RANK.get(status, 0)


def merge_findings(run_dirs: List[Path]) -> List[Dict[str, Any]]:
    """Merge findings from multiple runs. Deduplicate by (file, function, line).

    When the same finding appears in multiple runs, prefer the version with the
    most progressed status (e.g. "confirmed" beats "not_disproven"). Among equal
    statuses, the latest run wins.

    Args:
        run_dirs: Ordered list of run directories (later entries override earlier).

    Returns:
        Deduplicated list of findings.
    """
    merged: Dict[tuple, Dict[str, Any]] = {}

    for run_dir in run_dirs:
        findings = _load_findings_from_dir(Path(run_dir))
        for finding in findings:
            key = _finding_key(finding)
            existing = merged.get(key)
            if existing is None or _status_rank(finding) >= _status_rank(existing):
                merged[key] = finding

    return list(merged.values())


def verify_merge(merged_findings: List, source_findings_count: int,
                 unique_count: int) -> bool:
    """Verify merged count >= expected deduplicated count.

    Args:
        merged_findings: The merged findings list.
        source_findings_count: Total findings across all source runs.
        unique_count: Expected number of unique finding IDs.

    Returns:
        True if the merge looks valid.
    """
    return len(merged_findings) >= unique_count


def merge_runs(run_dirs: List[Path], output_dir: Path) -> Dict[str, Any]:
    """Merge findings and artefacts from multiple run directories.

    Args:
        run_dirs: Ordered list of run directories to merge.
        output_dir: Destination directory for merged output.

    Returns:
        Stats dict with merge summary.
    """
    run_dirs = [Path(d) for d in run_dirs]
    output_dir = Path(output_dir)

    # Safety: don't merge into an existing run directory
    if output_dir.exists() and any((output_dir / f).exists() for f in ("findings.json", ".raptor-run.json")):
        raise ValueError(f"Output directory {output_dir} already contains data. Use an empty directory.")

    if output_dir.resolve() in {d.resolve() for d in run_dirs}:
        raise ValueError("output_dir cannot be one of the source run directories")

    output_dir.mkdir(parents=True, exist_ok=True)

    # --- Merge findings ---
    total_findings = 0
    all_keys: set = set()
    for run_dir in run_dirs:
        findings = _load_findings_from_dir(run_dir)
        total_findings += len(findings)
        for f in findings:
            all_keys.add(_finding_key(f))

    merged = merge_findings(run_dirs)
    unique_count = len(all_keys)

    if not verify_merge(merged, total_findings, unique_count):
        logger.warning(
            f"Merge verification warning: {len(merged)} merged findings "
            f"< {unique_count} unique IDs"
        )

    if merged:
        save_json(output_dir / "findings.json", {"findings": merged})

    # --- Merge SARIF ---
    sarif_paths: List[str] = []
    for run_dir in run_dirs:
        for sarif_file in run_dir.glob("*.sarif"):
            sarif_paths.append(str(sarif_file))

    sarif_files_merged = len(sarif_paths)
    if sarif_paths:
        merged_sarif = merge_sarif(sarif_paths)
        save_json(output_dir / "merged.sarif", merged_sarif)

    # --- Copy unknown artefacts ---
    artefacts_preserved = 0
    for run_dir in run_dirs:
        if not run_dir.is_dir():
            continue
        for item in run_dir.iterdir():
            if item.is_dir():
                continue
            if _is_known_file(item.name):
                continue

            dest = output_dir / item.name
            if dest.exists():
                # Rename on collision: append source date
                stem = item.stem
                suffix = item.suffix
                date_tag = _extract_date_from_dir(run_dir)
                dest = output_dir / f"{stem}-{date_tag}{suffix}"

            shutil.copy2(str(item), str(dest))
            artefacts_preserved += 1

    # Copy unknown subdirectories
    for run_dir in run_dirs:
        if not run_dir.is_dir():
            continue
        for item in run_dir.iterdir():
            if not item.is_dir():
                continue
            if item.name.startswith("."):
                continue
            dest = output_dir / item.name
            if dest.exists():
                # Rename on collision: append source date
                date_tag = _extract_date_from_dir(run_dir)
                dest = output_dir / f"{item.name}-{date_tag}"
            if not dest.exists():
                shutil.copytree(str(item), str(dest))
                artefacts_preserved += 1

    vuln_count = _count_vulns(merged)

    stats = {
        "runs_merged": len(run_dirs),
        "total_findings": total_findings,
        "unique_findings": len(merged),
        "unique_vulns": vuln_count,
        "sarif_files_merged": sarif_files_merged,
        "artefacts_preserved": artefacts_preserved,
    }

    findings_label = f"{len(merged)} findings"
    if vuln_count != len(merged):
        findings_label = f"{vuln_count} findings"

    logger.info(
        f"Merged {len(run_dirs)} runs: {findings_label}, "
        f"{sarif_files_merged} SARIF files, {artefacts_preserved} artefacts"
    )

    return stats
