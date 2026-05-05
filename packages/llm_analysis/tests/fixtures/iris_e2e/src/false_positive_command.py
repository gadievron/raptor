"""Hallucinatable dataflow: looks like command injection at the
subprocess line but the input is sanitized via a strict allowlist
that returns None on any unsafe value, then the call only happens
when the value is None-checked. CodeQL dataflow will NOT find a
reachable path because the sanitizer breaks the taint propagation,
but the LLM might claim "request input flows to subprocess" based on
the surface pattern.

Semgrep should flag the subprocess call. CodeQL TaintTracking
should refute the claim. IRIS should set verdict=refuted and
recommend downgrade.
"""

import re
import subprocess
from typing import Optional

from flask import Flask, request

app = Flask(__name__)

_SAFE_COMMAND_RE = re.compile(r"^[a-zA-Z0-9_-]{1,32}$")
_ALLOWLIST = {"ls", "pwd", "whoami", "uptime"}


def sanitize(s: str) -> Optional[str]:
    """Strict allowlist sanitizer. Returns None for anything unsafe."""
    if not _SAFE_COMMAND_RE.match(s):
        return None
    if s not in _ALLOWLIST:
        return None
    return s


def execute_safe(cmd: Optional[str]) -> int:
    """Sink-shaped, but only fires for sanitised input.

    The subprocess call here looks dangerous (shell=True) but the
    sanitizer returns None for any unsafe input, and the None check
    breaks the dataflow before the call.
    """
    if cmd is None:
        return 1
    # By this point cmd is one of the four allowlist entries.
    # CodeQL dataflow will NOT propagate taint past the sanitizer.
    return subprocess.call(cmd, shell=True)


@app.route("/run")
def run_cmd():
    user_arg = request.args.get("cmd", "")
    sanitized = sanitize(user_arg)
    return str(execute_safe(sanitized))


if __name__ == "__main__":
    app.run()
