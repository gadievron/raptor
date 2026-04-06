"""Run metadata — .raptor-run.json lifecycle helpers.

Every run directory gets a .raptor-run.json file tracking what command
produced it, when, and whether it succeeded. Tools use start_run/complete_run/fail_run.
"""

import contextlib
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from core.json import load_json, save_json

RUN_METADATA_FILE = ".raptor-run.json"

# Status enum
STATUS_RUNNING = "running"
STATUS_COMPLETED = "completed"
STATUS_FAILED = "failed"
STATUS_CANCELLED = "cancelled"

# Known command prefixes for inferring command type from directory names
# Known command prefixes for inferring command type from directory names.
# Includes both legacy prefixes (raptor_, autonomous, exploitability-validation)
# and project-mode prefixes (agentic, validate, understand, fuzz, web).
_PREFIX_MAP = {
    # Scanning
    "scan": "scan",
    "codeql": "codeql",
    # Agentic (legacy: raptor_, autonomous)
    "agentic": "agentic",
    "raptor_": "agentic",
    "autonomous": "agentic",
    # Validation (legacy: exploitability-validation)
    "validate": "validate",
    "exploitability-validation": "validate",
    # Other commands
    "understand": "understand",
    "code-understanding": "understand",
    "fuzz": "fuzz",
    "web": "web",
    "crash-analysis": "crash-analysis",
    "oss-forensics": "oss-forensics",
}


def start_run(output_dir: Path, command: str, extra: Dict[str, Any] = None) -> Path:
    """Write initial .raptor-run.json with status=running.

    Call this at the start of a command. Returns the output_dir (for chaining).
    Creates the directory if it doesn't exist.
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    metadata = {
        "version": 1,
        "command": command,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "status": STATUS_RUNNING,
        "extra": extra or {},
    }

    save_json(output_dir / RUN_METADATA_FILE, metadata)
    return output_dir


def complete_run(output_dir: Path, extra: Dict[str, Any] = None) -> None:
    """Update .raptor-run.json to status=completed."""
    _update_status(output_dir, STATUS_COMPLETED, extra)


def fail_run(output_dir: Path, error: str = None, extra: Dict[str, Any] = None) -> None:
    """Update .raptor-run.json to status=failed."""
    extra = extra or {}
    if error:
        extra["error"] = error
    _update_status(output_dir, STATUS_FAILED, extra)


def cancel_run(output_dir: Path, extra: Dict[str, Any] = None) -> None:
    """Update .raptor-run.json to status=cancelled."""
    _update_status(output_dir, STATUS_CANCELLED, extra)


@contextlib.contextmanager
def tracked_run(output_dir: Path, command: str, extra: Dict[str, Any] = None):
    """Context manager for run lifecycle. Writes metadata automatically.

    Usage:
        with tracked_run(out_dir, "agentic") as run_dir:
            # do work...
        # .raptor-run.json: completed on success, failed on exception, cancelled on Ctrl-C
    """
    run_dir = start_run(output_dir, command, extra)
    try:
        yield run_dir
        complete_run(run_dir)
    except KeyboardInterrupt:
        cancel_run(run_dir)
        raise
    except Exception as e:
        fail_run(run_dir, error=str(e))
        raise


def load_run_metadata(run_dir: Path) -> Optional[Dict[str, Any]]:
    """Load .raptor-run.json from a run directory. Returns None if missing."""
    return load_json(run_dir / RUN_METADATA_FILE)


def is_run_directory(path: Path) -> bool:
    """Check if a directory looks like a RAPTOR run output.

    True if it has .raptor-run.json, or matches known naming patterns,
    or contains typical output files.
    """
    if not path.is_dir():
        return False

    # Has metadata file
    if (path / RUN_METADATA_FILE).exists():
        return True

    # Matches known prefix patterns
    name = path.name
    if any(name.startswith(prefix) for prefix in _PREFIX_MAP):
        return True

    # Contains typical output files
    typical_files = {"findings.json", "checklist.json", "scan_metrics.json",
                     "orchestrated_report.json", "validation-report.md"}
    if any((path / f).exists() for f in typical_files):
        return True

    return False


def infer_command_type(run_dir: Path) -> str:
    """Infer the command type from a run directory.

    Checks .raptor-run.json first, falls back to directory name prefix.
    """
    # Check metadata file
    metadata = load_run_metadata(run_dir)
    if metadata and metadata.get("command"):
        return metadata["command"]

    # Infer from directory name
    name = run_dir.name
    for prefix, cmd_type in _PREFIX_MAP.items():
        if name.startswith(prefix):
            return cmd_type

    return "unknown"


def generate_run_metadata(run_dir: Path) -> None:
    """Generate .raptor-run.json for a directory that doesn't have one.

    Used when adopting existing directories into a project. Infers
    command type from directory name and timestamp from directory mtime.
    """
    if (run_dir / RUN_METADATA_FILE).exists():
        return

    command = infer_command_type(run_dir)

    # Try to get timestamp from directory name (e.g. scan-20260406-100000)
    timestamp = parse_timestamp_from_name(run_dir.name)
    if not timestamp:
        # Fall back to directory modification time
        mtime = run_dir.stat().st_mtime
        timestamp = datetime.fromtimestamp(mtime, tz=timezone.utc).isoformat()

    metadata = {
        "version": 1,
        "command": command,
        "timestamp": timestamp,
        "status": STATUS_COMPLETED,  # Assume completed if it exists
        "extra": {"adopted": True},
    }

    save_json(run_dir / RUN_METADATA_FILE, metadata)


def _update_status(output_dir: Path, status: str, extra: Dict[str, Any] = None) -> None:
    """Update the status field in .raptor-run.json.

    Raises FileNotFoundError if metadata file doesn't exist (call start_run first).
    """
    path = Path(output_dir) / RUN_METADATA_FILE
    metadata = load_json(path)
    if metadata is None:
        raise FileNotFoundError(f"No {RUN_METADATA_FILE} in {output_dir} — call start_run() first")
    metadata["status"] = status
    if extra:
        existing_extra = metadata.get("extra", {})
        existing_extra.update(extra)
        metadata["extra"] = existing_extra
    save_json(path, metadata)


def parse_timestamp_from_name(name: str) -> Optional[str]:
    """Try to extract an ISO timestamp from a directory name.

    Matches patterns like:
    - scan-20260406-100000
    - scan_vulns_20260406_100000
    - exploitability-validation-20260406-100000
    """
    # Look for YYYYMMDD_HHMMSS or YYYYMMDD-HHMMSS
    match = re.search(r'(\d{4})(\d{2})(\d{2})[_-](\d{2})(\d{2})(\d{2})', name)
    if match:
        y, mo, d, h, mi, s = match.groups()
        try:
            dt = datetime(int(y), int(mo), int(d), int(h), int(mi), int(s), tzinfo=timezone.utc)
            return dt.isoformat()
        except ValueError:
            pass

    # Look for YYYYMMDD only
    match = re.search(r'(\d{4})(\d{2})(\d{2})', name)
    if match:
        y, mo, d = match.groups()
        try:
            dt = datetime(int(y), int(mo), int(d), tzinfo=timezone.utc)
            return dt.isoformat()
        except ValueError:
            pass

    return None
