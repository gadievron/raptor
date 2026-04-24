#!/usr/bin/env python3
"""RAPTOR Studio — web UI launcher.

Usage:
    python3 raptor_studio.py                       # default: 127.0.0.1:8765
    python3 raptor_studio.py --port 9000
    python3 raptor_studio.py --host 0.0.0.0 --reload

Reads raptor projects from ``~/.raptor/projects/`` by default (configurable
via ``RAPTOR_PROJECTS_DIR``). Job queue lives at ``~/.raptor-studio/jobs.db``.
See ``packages/studio/README.md`` for the full feature set and environment
knobs, and ``packages/studio/docs/PRD.md`` for the product rationale.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Match raptor_agentic.py / raptor_codeql.py / raptor_fuzzing.py bootstrap:
# make the repo root importable so ``from packages.studio.app import app``
# resolves without PYTHONPATH gymnastics.
sys.path.insert(0, str(Path(__file__).parent))


def main() -> None:
    parser = argparse.ArgumentParser(
        description="RAPTOR Studio — web UI for raptor",
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--reload", action="store_true",
                        help="auto-reload templates + code on change (dev only)")
    parser.add_argument("--log-level", default="info",
                        choices=["critical", "error", "warning", "info", "debug", "trace"])
    args = parser.parse_args()

    try:
        import uvicorn
    except ImportError:
        print(
            "uvicorn not installed. Install raptor-studio deps with:\n"
            "    pip install fastapi uvicorn[standard] jinja2 python-multipart markdown",
            file=sys.stderr,
        )
        sys.exit(1)

    uvicorn.run(
        "packages.studio.app:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
        log_level=args.log_level,
    )


if __name__ == "__main__":
    main()
