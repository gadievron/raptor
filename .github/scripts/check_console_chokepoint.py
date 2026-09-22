#!/usr/bin/env python3
"""Console-chokepoint closure gate.

Every runtime console-handler acquisition must route through
``core.logging.configure_cli_logging`` (or the run-logging setup in
core/logging itself) — that chokepoint is what guarantees foreign
bytes in log lines reach the operator's TTY escaped, and the
report-writer audit's exception-relay arm excludes logging sinks on
exactly that basis. The closure's regression surface is tree-wide
(any new file can add a bare ``basicConfig`` / same-line
``addHandler(StreamHandler())`` / ``logging.config`` loader), so it
needs a per-PR home: the test-tier sweep of the same detector runs in
the slow tier, where a PR could merge green with a fresh bare sink.

Same dual structure as the report-writer sweep: the detector and walk
live in ``core/logging/console_audit.py`` (predicate spellings,
exemptions, and documented line-regex residuals are specified there),
the gated pytest variant pins them, and this gate runs them per PR.

Usage:
    python3 .github/scripts/check_console_chokepoint.py
    python3 .github/scripts/check_console_chokepoint.py --root <tree>

Exit codes: 0 clean, 1 offences, 2 usage error.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

_DEFAULT_ROOT = Path(__file__).resolve().parents[2]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=_DEFAULT_ROOT)
    args = parser.parse_args(argv)
    root = args.root.resolve()

    sys.path.insert(0, str(root))
    from core.logging.console_audit import runtime_console_offences

    offenders = runtime_console_offences(root)
    if offenders:
        print("console-handler configuration outside the chokepoint in "
              "runtime source — route it through "
              "core.logging.configure_cli_logging (escaping formatter, "
              "idempotent against preconfigured roots):")
        for off in offenders:
            print(f"  {off}")
        return 1
    print("console-chokepoint closure: no offences in the tracked "
          "runtime tree")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
