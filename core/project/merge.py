"""Merge findings and SARIF across multiple run directories.

Combines findings.json, SARIF files, and artefacts from multiple runs
into a single output directory. Deduplicates findings by ID (latest wins).
"""

import re
import shutil
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.json import load_json, save_json
from core.logging import get_logger
from core.project.findings_utils import get_finding_id as _get_finding_id
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


def merge_findings(run_dirs: List[Path]) -> List[Dict[str, Any]]:
    """Merge findings from multiple runs. Deduplicate by finding ID, latest wins.

    Args:
        run_dirs: Ordered list of run directories (later entries override earlier).

    Returns:
        Deduplicated list of findings.
    """
    merged: Dict[str, Dict[str, Any]] = {}
    no_id_findings: List[Dict[str, Any]] = []

    for run_dir in run_dirs:
        findings = _load_findings_from_dir(Path(run_dir))
        for finding in findings:
            fid = _get_finding_id(finding)
            if fid:
                merged[fid] = finding
            else:
                no_id_findings.append(finding)

    return list(merged.values()) + no_id_findings


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
    all_ids: set = set()
    for run_dir in run_dirs:
        findings = _load_findings_from_dir(run_dir)
        total_findings += len(findings)
        for f in findings:
            fid = _get_finding_id(f)
            if fid:
                all_ids.add(fid)

    merged = merge_findings(run_dirs)
    unique_count = len(all_ids)

    if not verify_merge(merged, total_findings, unique_count):
        logger.warning(
            f"Merge verification warning: {len(merged)} merged findings "
            f"< {unique_count} unique IDs"
        )

    if merged:
        save_json(output_dir / "findings.json", merged)

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

    stats = {
        "runs_merged": len(run_dirs),
        "total_findings": total_findings,
        "unique_findings": len(merged),
        "sarif_files_merged": sarif_files_merged,
        "artefacts_preserved": artefacts_preserved,
    }

    logger.info(
        f"Merged {len(run_dirs)} runs: {len(merged)} findings, "
        f"{sarif_files_merged} SARIF files, {artefacts_preserved} artefacts"
    )

    return stats
