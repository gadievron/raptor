#!/usr/bin/env python3
"""RAPTOR Studio — web UI launcher.

Usage:
    python3 raptor_studio.py                       # default: 127.0.0.1:8765
    python3 raptor_studio.py --port 9000
    python3 raptor_studio.py --host 0.0.0.0 --reload

Reads raptor projects from raptor's own registry (``~/.raptor/projects/``;
``STUDIO_PROJECTS_DIR`` points studio at an alternate view, e.g. the demo
registry). Job queue lives at ``~/.raptor-studio/jobs.db``.
See ``packages/studio/README.md`` for the full feature set and environment
knobs, and ``packages/studio/docs/PRD.md`` for the product rationale.
"""

from __future__ import annotations

import argparse
import ipaddress
import os
import secrets
import sys
from pathlib import Path

# Match raptor_agentic.py / raptor_codeql.py / raptor_fuzzing.py bootstrap:
# make the repo root importable so ``from packages.studio.app import app``
# resolves without PYTHONPATH gymnastics.
sys.path.insert(0, str(Path(__file__).parent))


def _is_loopback_bind_host(host: str) -> bool:
    """True if binding to `host` is reachable from this machine only.

    Kept dependency-free (no fastapi import) so argument validation works
    even before studio's deps are installed. Unknown hostnames count as
    non-loopback — conservative for a bind address.
    """
    host = host.strip().lower().strip("[]")
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def main() -> None:
    parser = argparse.ArgumentParser(
        description="RAPTOR Studio — web UI for raptor",
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--allow-remote", action="store_true",
                        help="permit binding to a non-loopback host; every "
                             "client (local browsers included) must then "
                             "present the access token printed at startup")
    parser.add_argument("--reload", action="store_true",
                        help="auto-reload templates + code on change (dev only)")
    parser.add_argument("--log-level", default="info",
                        choices=["critical", "error", "warning", "info", "debug", "trace"])
    args = parser.parse_args()

    if not _is_loopback_bind_host(args.host):
        if not args.allow_remote:
            parser.error(
                f"refusing to bind to non-loopback host {args.host!r}: studio "
                "is an unauthenticated single-user UI that can launch raptor "
                "jobs and browse the filesystem. Pass --allow-remote if you "
                "really mean to expose it beyond this machine."
            )
        # Provision the shared secret the app's RemoteAccessProtection
        # middleware enforces for non-loopback clients. Env is the channel
        # because uvicorn (re)spawns the app from an import string.
        token = os.environ.get("STUDIO_AUTH_TOKEN") or secrets.token_urlsafe(32)
        os.environ["STUDIO_AUTH_TOKEN"] = token
        os.environ["STUDIO_ALLOW_REMOTE"] = "1"
        print(
            "\n"
            "  WARNING: binding to a non-loopback interface. Anyone who can\n"
            f"  reach {args.host}:{args.port} can browse this machine's files\n"
            "  and launch raptor jobs once they hold the access token below.\n"
            "  Prefer an SSH tunnel to 127.0.0.1 where possible.\n"
            "\n"
            "  Every client must present this token — including browsers on\n"
            "  this machine (host-header validation is off in remote mode,\n"
            "  so loopback gets no exemption).\n"
            "\n"
            f"  Access token: {token}\n"
            f"  First visit: http://<this-host>:{args.port}/?token={token}\n"
            "  (the token in that URL lands in browser history and access\n"
            "  logs; treat it accordingly, or send it as an\n"
            "  'Authorization: Bearer' header instead)\n",
            file=sys.stderr,
        )

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
