"""Coverage record — what a tool examined during a run.

Written to coverage-record.json in the run output directory.
Built from the reads manifest (populated by the PostToolUse hook)
and/or from tool-specific data (Semgrep JSON, CodeQL database).
"""

import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.json import load_json, save_json

COVERAGE_RECORD_FILE = "coverage-record.json"
READS_MANIFEST = ".reads-manifest"


def build_from_manifest(run_dir: Path, tool: str,
                        rules_applied: List[str] = None,
                        extra_files: List[str] = None) -> Optional[Dict[str, Any]]:
    """Build a coverage record from the reads manifest.

    The manifest is populated by the PostToolUse hook on Read.
    Deduplicates and normalises paths relative to the target.

    Args:
        run_dir: Run output directory containing .reads-manifest.
        tool: Tool identifier (e.g., "llm:validate", "understand").
        rules_applied: Optional list of rules/stages that ran.
        extra_files: Additional files to include (from other sources).

    Returns:
        Coverage record dict, or None if no manifest exists.
    """
    run_dir = Path(run_dir)
    manifest = run_dir / READS_MANIFEST

    files = set()

    # Read manifest
    if manifest.exists():
        try:
            for line in manifest.read_text().splitlines():
                line = line.strip()
                if line:
                    files.add(line)
        except OSError:
            pass

    # Add extra files from tool-specific sources
    if extra_files:
        files.update(extra_files)

    if not files:
        return None

    record = {
        "tool": tool,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "files_examined": sorted(files),
    }
    if rules_applied:
        record["rules_applied"] = rules_applied

    return record


def build_from_semgrep(run_dir: Path, semgrep_json_path: Path,
                       rules_applied: List[str] = None) -> Optional[Dict[str, Any]]:
    """Build a coverage record from Semgrep JSON output.

    Reads paths.scanned from Semgrep's JSON output for authoritative
    file list, and errors for files_failed.
    """
    data = load_json(semgrep_json_path)
    if not data or not isinstance(data, dict):
        return None

    paths = data.get("paths", {})
    scanned = paths.get("scanned", [])
    if not scanned:
        return None

    errors = data.get("errors", [])
    version = data.get("version", "")

    record = {
        "tool": "semgrep",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "files_examined": sorted(scanned),
    }
    if version:
        record["version"] = version
    if rules_applied:
        record["rules_applied"] = rules_applied
    if errors:
        record["files_failed"] = [
            {"path": e.get("path", ""), "reason": e.get("message", "error")}
            for e in errors if e.get("path")
        ]

    return record


def write_record(run_dir: Path, record: Dict[str, Any]) -> Path:
    """Write a coverage record to the run directory."""
    path = Path(run_dir) / COVERAGE_RECORD_FILE
    save_json(path, record)
    return path


def load_record(run_dir: Path) -> Optional[Dict[str, Any]]:
    """Load a coverage record from a run directory."""
    return load_json(Path(run_dir) / COVERAGE_RECORD_FILE)


def cleanup_manifest(run_dir: Path) -> None:
    """Remove the reads manifest after converting to a coverage record."""
    manifest = Path(run_dir) / READS_MANIFEST
    if manifest.exists():
        manifest.unlink(missing_ok=True)
