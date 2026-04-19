#!/usr/bin/env python3
"""Export helpers for memory snapshots."""

import os
from pathlib import Path
from typing import Dict

from .memory_store import Memory


def _exports_enabled() -> bool:
    value = os.environ.get("RAPTOR_EXPORT_MEMORY_SNAPSHOTS", "")
    return value.strip().lower() in {"1", "true", "yes", "on"}


def export_memory_views(
    memory: Memory,
    base_dir: Path | None = None,
    enabled: bool | None = None,
) -> Dict[str, str]:
    """Export JSON snapshot views when explicitly enabled."""
    should_export = _exports_enabled() if enabled is None else enabled
    if not should_export:
        return {}
    out_base = base_dir or (Path.home() / ".raptor")
    out_base.mkdir(parents=True, exist_ok=True)

    paths = {
        "fuzzing_memory": str(memory.export_json(out_base / "fuzzing_memory.json", domain="fuzzing")),
        "agentic_memory": str(memory.export_json(out_base / "agentic_memory.json", domain="agentic")),
        "codeql_memory": str(memory.export_json(out_base / "codeql_memory.json", domain="codeql")),
        "crash_analysis_memory": str(memory.export_json(out_base / "crash_analysis_memory.json", domain="crash_analysis")),
        "web_memory": str(memory.export_json(out_base / "web_memory.json", domain="web")),
        "memory_knowledge": str(memory.export_json(out_base / "memory_knowledge.json")),
    }
    return paths
