#!/usr/bin/env python3
"""
Initialize OSS Forensics Investigation

This script is used exclusively by the oss-forensics-agent (orchestrator) to:
1. Check prerequisites (GOOGLE_APPLICATION_CREDENTIALS)
2. Create working directory
3. Initialize empty evidence store

Usage:
    python init_investigation.py [--timestamp YYYYMMDD_HHMMSS]

Returns:
    JSON output with working directory path
"""

import os
import sys
import json
from datetime import datetime
from pathlib import Path

# Add skill dir to path for package imports
script_dir = Path(__file__).parent
skill_dir = script_dir.parent
sys.path.insert(0, str(skill_dir))

from src.store import EvidenceStore


def check_prerequisites():
    """Check required environment variables and dependencies."""
    errors = []

    # Check for BigQuery credentials
    if not os.environ.get("GOOGLE_APPLICATION_CREDENTIALS"):
        errors.append({
            "error": "GOOGLE_APPLICATION_CREDENTIALS not set",
            "details": "GH Archive requires BigQuery credentials.",
            "help": "See: .claude/skills/oss-forensics/github-archive/SKILL.md"
        })

    return errors


def create_working_directory(timestamp=None):
    """Create investigation working directory.

    Args:
        timestamp: Optional timestamp string (YYYYMMDD_HHMMSS)

    Returns:
        Path to working directory
    """
    if timestamp is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    workdir = Path(f".out/oss-forensics-{timestamp}")
    workdir.mkdir(parents=True, exist_ok=True)
    (workdir / "repos").mkdir(exist_ok=True)

    return workdir


def initialize_evidence_store(workdir):
    """Initialize empty evidence.json in working directory.

    Args:
        workdir: Path to working directory

    Returns:
        Path to evidence.json
    """
    store = EvidenceStore()
    evidence_path = workdir / "evidence.json"
    store.save(str(evidence_path))

    return evidence_path


def main():
    """Main entry point."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Initialize OSS forensics investigation"
    )
    parser.add_argument(
        "--timestamp",
        help="Optional timestamp (YYYYMMDD_HHMMSS)",
        default=None
    )

    args = parser.parse_args()

    # Check prerequisites
    errors = check_prerequisites()
    if errors:
        result = {
            "success": False,
            "errors": errors
        }
        print(json.dumps(result, indent=2))
        sys.exit(1)

    # Create working directory
    workdir = create_working_directory(args.timestamp)

    # Initialize evidence store
    evidence_path = initialize_evidence_store(workdir)

    # Return success
    result = {
        "success": True,
        "workdir": str(workdir),
        "evidence_path": str(evidence_path),
        "timestamp": args.timestamp or datetime.now().strftime("%Y%m%d_%H%M%S")
    }

    print(json.dumps(result, indent=2))
    sys.exit(0)


if __name__ == "__main__":
    main()
