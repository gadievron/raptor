"""Size SCA's pytest-split matrix without collecting or dropping any tests.

The committed per-nodeid timings are estimates, not selection data. Unknown
files or malformed timings keep the historical four groups. Case count also
caps consolidation: thousands of individually cheap cases still cost collection
and fixture time that old duration records may not include.
"""
from __future__ import annotations

import json
import math
import os
from pathlib import Path

MAX_GROUPS = 4
TARGET_SECONDS = 30
TARGET_CASES = 1000


def sca_matrix(files: list[str], durations_path: Path) -> list[dict[str, int]]:
    """Return contiguous split groups; every group receives the same file list."""
    selected = set(files)
    if not selected:
        return []
    groups = MAX_GROUPS
    try:
        durations = json.loads(durations_path.read_text())
        if not isinstance(durations, dict) or not durations:
            raise ValueError("missing timing records")
        seconds = 0.0
        cases = 0
        covered = set()
        for nodeid, duration in durations.items():
            filename, separator, _ = nodeid.partition("::")
            if filename not in selected:
                continue
            if (not separator or isinstance(duration, bool)
                    or not isinstance(duration, (int, float))
                    or not math.isfinite(duration) or duration < 0):
                raise ValueError("invalid timing record")
            covered.add(filename)
            seconds += duration
            cases += 1
        if not math.isfinite(seconds):
            raise ValueError("invalid timing total")
        if covered == selected and seconds > 0:
            groups = min(MAX_GROUPS, max(
                1, math.ceil(seconds / TARGET_SECONDS), math.ceil(cases / TARGET_CASES),
            ))
    except (OSError, ValueError, TypeError, AttributeError):
        pass  # Performance hints must never prevent test dispatch.
    return [{"group": group, "groups": groups} for group in range(1, groups + 1)]


def main() -> None:
    matrix = sca_matrix(
        os.environ.get("SCA_FILES", "").split(),
        Path("packages/sca/test-durations.json"),
    )
    with open(os.environ["GITHUB_OUTPUT"], "a") as output:
        output.write("matrix=" + json.dumps(matrix) + "\n")
    print(f"SCA selection uses {len(matrix)} runner group(s)")


if __name__ == "__main__":
    main()
