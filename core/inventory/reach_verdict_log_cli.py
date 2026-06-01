"""CLI entry point for ``raptor-reach-verdict-log``.

Inspects + maintains the per-language reachability verdict-frequency
log (``core.inventory.reach_verdict_log``).

Default action prints a human-readable per-language table:

    reach verdicts (out/reach_verdict_log.json):
      python:
        reachable           : 1023
        no_path_from_entry  :   47
        uncertain           :   12
      c:
        ...

Flags:
  --json      Emit the raw verdict distribution as JSON
  --reset     Delete the sidecar and clear in-memory counts
  --path P    Override sidecar location (else env/default resolution)
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from core.inventory.reach_verdict_log import (
    SCHEMA_VERSION,
    _sidecar_path,
    reset,
    summarize,
)


def _format_table(data: dict) -> str:
    if not data:
        return "no verdicts recorded yet"
    lines = []
    for lang in sorted(data):
        verdicts = data[lang]
        if not verdicts:
            continue
        lines.append(f"  {lang}:")
        # Sort by count desc, then verdict name for tie-break.
        items = sorted(verdicts.items(), key=lambda kv: (-kv[1], kv[0]))
        width = max(len(v) for v, _ in items)
        for v, n in items:
            lines.append(f"    {v:<{width}} : {n:>6}")
    if not lines:
        return "no verdicts recorded yet"
    return "\n".join(lines)


def main() -> int:
    p = argparse.ArgumentParser(
        prog="raptor-reach-verdict-log",
        description=(
            "Inspect the per-language reachability verdict-frequency log. "
            "Sidecar accumulates (language, verdict) counts from every "
            "classify_reachability call; flushes at process exit."
        ),
    )
    p.add_argument("--json", action="store_true",
                   help="Emit the raw counts as JSON instead of a table.")
    p.add_argument("--reset", action="store_true",
                   help="Delete the sidecar and clear in-memory counts.")
    p.add_argument("--path", type=Path, default=None,
                   help="Override sidecar location (default: $RAPTOR_DIR/out/reach_verdict_log.json).")
    args = p.parse_args()

    path = args.path or _sidecar_path()

    if args.reset:
        reset(path)
        print(f"reset {path}")
        return 0

    data = summarize(path)
    if args.json:
        print(json.dumps(data, indent=2, sort_keys=True))
        return 0

    print(f"reach verdicts ({path}, schema v{SCHEMA_VERSION}):")
    print(_format_table(data))
    return 0


if __name__ == "__main__":
    sys.exit(main())
