"""Identity scrubbing for subprocess environments in the fuzzing
pipeline.

``get_safe_env()`` strips credentials; this strips operator/host
IDENTITY on top — for env dicts handed to untrusted target executions
(campaign, showmap replay, libFuzzer harness) and, belt-and-braces,
to the trusted toolchain probes whose output lands in reports.
"""

from __future__ import annotations

import os


def scrub_identity_env(env: dict) -> dict:
    """Strip operator/host identity from *env*. Mutates and returns it.

    Drops the direct identity vars, ``XDG_*`` values and
    ``/home/<user>`` PATH components (username bearing), and
    RAPTOR-internal markers. HOME gets a neutral value — ``/tmp`` is a
    fresh per-sandbox tmpfs in every sandboxed mode.
    """
    for ident in ("USER", "LOGNAME", "HOSTNAME", "PWD", "OLDPWD",
                  "RAPTOR_DIR", "RAPTOR_OUT_DIR", "_RAPTOR_TRUSTED",
                  "CLAUDECODE"):
        env.pop(ident, None)
    for key in [k for k in env if k.startswith("XDG_")]:
        env.pop(key, None)
    env["HOME"] = "/tmp"
    if "PATH" in env:
        env["PATH"] = os.pathsep.join(
            p for p in env["PATH"].split(os.pathsep)
            if not p.startswith("/home/"))
    return env
