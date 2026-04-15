#!/usr/bin/env python3
"""Export helpers for unified memory snapshots."""

from pathlib import Path
from typing import Dict

from .unified_memory import UnifiedMemory


def export_memory_views(memory: UnifiedMemory, base_dir: Path | None = None) -> Dict[str, str]:
    out_base = base_dir or (Path.home() / ".raptor")
    out_base.mkdir(parents=True, exist_ok=True)

    paths = {
        "fuzzing_memory": str(memory.export_json(out_base / "fuzzing_memory.json", domain="fuzzing")),
        "agentic_memory": str(memory.export_json(out_base / "agentic_memory.json", domain="agentic")),
        "codeql_memory": str(memory.export_json(out_base / "codeql_memory.json", domain="codeql")),
        "crash_analysis_memory": str(memory.export_json(out_base / "crash_analysis_memory.json", domain="crash_analysis")),
        "web_memory": str(memory.export_json(out_base / "web_memory.json", domain="web")),
        "unified_knowledge": str(memory.export_json(out_base / "unified_knowledge.json")),
    }
    return paths
