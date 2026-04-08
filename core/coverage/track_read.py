"""Track file reads for coverage — Python implementation.

The production hook is libexec/raptor-hook-read (bash+jq, runs async).
This module provides the same logic in Python for:
- Testing (test_record.py)
- Fallback when jq is unavailable
- Direct invocation: python3 -m core.coverage.track_read
"""

import json
import os
import sys
from pathlib import Path

# Ensure repo root is on path regardless of cwd
# core/coverage/track_read.py -> repo root
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

MANIFEST_NAME = ".reads-manifest"

_SOURCE_EXTENSIONS = frozenset({
    ".py", ".js", ".ts", ".jsx", ".tsx", ".c", ".h", ".cpp", ".hpp",
    ".cc", ".cxx", ".java", ".go", ".rs", ".rb", ".php", ".cs",
    ".swift", ".kt", ".scala", ".sh", ".bash", ".zsh",
})


def _find_active_run():
    """Find the running run directory via project symlink.

    Returns (run_dir, target) or (None, None).
    """
    active_link = Path.home() / ".raptor" / "projects" / ".active"
    if not active_link.is_symlink():
        return None, None

    try:
        link_target = os.readlink(active_link)
        if not link_target.endswith(".json"):
            return None, None
        project_file = active_link.parent / link_target
        if not project_file.exists():
            return None, None

        data = json.loads(project_file.read_text())
        project_dir = data.get("output_dir", "")
        target = data.get("target", "")
        if not project_dir or not Path(project_dir).is_dir():
            return None, None

        # Find most recent running run
        for d in sorted(Path(project_dir).iterdir(), key=lambda d: d.stat().st_mtime, reverse=True):
            if not d.is_dir() or d.name.startswith((".", "_")):
                continue
            meta_file = d / ".raptor-run.json"
            if meta_file.exists():
                meta = json.loads(meta_file.read_text())
                if meta.get("status") == "running":
                    return str(d), target

    except (OSError, json.JSONDecodeError, KeyError):
        pass

    return None, None


def main():
    # Find active run via project symlink
    run_dir, target = _find_active_run()
    if not run_dir:
        return

    # Also check env var for target (may be more current)
    target = os.environ.get("RAPTOR_PROJECT_TARGET", target or "")

    # Read hook payload from stdin
    try:
        payload = json.load(sys.stdin)
    except (json.JSONDecodeError, ValueError):
        return

    file_path = payload.get("tool_input", {}).get("file_path", "")
    if not file_path:
        return

    # Skip non-source files
    dot = file_path.rfind(".")
    if dot == -1 or file_path[dot:].lower() not in _SOURCE_EXTENSIONS:
        return

    # Skip files outside the target directory
    if target and not file_path.startswith(target):
        return

    # Append to manifest
    try:
        with open(os.path.join(run_dir, MANIFEST_NAME), "a") as f:
            f.write(file_path + "\n")
    except OSError:
        pass


if __name__ == "__main__":
    main()
