"""Sandboxed execution glue for Frida.

The only module that talks to ``core.sandbox``. It runs ``frida_driver.py``
*inside* the sandbox so the driver and the target it spawns share one
process tree (parent→descendant ptrace, authorised by ptrace_scope=1 - the
same model ``/crash-analysis`` uses for gdb/rr).

Default profile is ``debug`` (full Landlock + seccomp-with-ptrace + network
block). Empirically, Frida's spawn loader reads ``/proc/<pid>/auxv``, which
needs ``/proc`` correctly remounted inside the PID namespace; on hosts where
the mount namespace can't be set up that read fails, so the runner detects
the failure signature and transparently falls back to ``profile="none"``
(no isolation) with a loud warning - rather than leaving the operator with a
cryptic ``NotSupportedError``. Network isolation is the property lost in the
fallback; the target is still operator-chosen and spawn-only.
"""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

_DRIVER = Path(__file__).resolve().parent / "frida_driver.py"

# Stderr/stdout signatures that mean "spawn failed because the PID namespace's
# /proc isn't usable" - the documented fall-back-to-no-isolation trigger.
_NS_SPAWN_FAIL = (
    "auxv", "No such process", "NotSupportedError",
    "unable to find process", "ptrace",
)


def _parse_result(stdout: str) -> Optional[dict]:
    for line in stdout.splitlines():
        if line.startswith("FRIDA_RESULT="):
            try:
                return json.loads(line[len("FRIDA_RESULT="):])
            except ValueError:
                return None
    return None


def run_agent(
    target: str,
    agent_js: str,
    *,
    output_dir: str,
    events_name: str = "frida-events.jsonl",
    agent_name: str = "agent.js",
    timeout: float = 30.0,
    spawn_args: Optional[List[str]] = None,
    profile: str = "debug",
    _allow_fallback: bool = True,
) -> Dict[str, Any]:
    """Spawn ``target`` under Frida with ``agent_js`` attached, inside the
    sandbox. Returns a dict with ``events_path``, ``result`` (the driver's
    summary), ``profile_used``, ``returncode`` and trailing ``stderr``.

    Never raises on instrumentation failure - a failed run is reported via the
    ``result.error`` field so callers (skill, api) can surface it cleanly.
    """
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    agent_path = out / agent_name
    agent_path.write_text(agent_js)
    events_path = out / events_name

    cmd = [
        sys.executable, str(_DRIVER),
        "--agent", str(agent_path),
        "--events-out", str(events_path),
        "--timeout", str(timeout),
        "--", str(target),
    ] + [str(a) for a in (spawn_args or [])]

    from core.sandbox import sandbox, SandboxSetupError

    def _fallback(reason: str) -> Dict[str, Any]:
        logger.warning(
            "frida: %s under profile %r - retrying with NO isolation "
            "(network not blocked; target is still operator-chosen + "
            "spawn-only). Pass profile='debug' on a host with working "
            "mount namespaces for full isolation.", reason, profile,
        )
        return run_agent(
            target, agent_js, output_dir=output_dir, events_name=events_name,
            agent_name=agent_name, timeout=timeout, spawn_args=spawn_args,
            profile="none", _allow_fallback=False,
        )

    try:
        with sandbox(profile=profile, output=str(out)) as run:
            proc = run(cmd, capture_output=True, text=True, check=False,
                       timeout=timeout + 30)
    except SandboxSetupError as e:
        if _allow_fallback and profile != "none":
            return _fallback(f"sandbox unavailable ({e})")
        raise

    result = _parse_result(proc.stdout) or {}
    combined = f"{result.get('error', '')} {proc.stderr or ''}"
    if (_allow_fallback and profile != "none"
            and any(sig in combined for sig in _NS_SPAWN_FAIL)):
        return _fallback("spawn failed (PID-namespace / proc-remount)")

    return {
        "events_path": str(events_path),
        "result": result,
        "profile_used": profile,
        "returncode": proc.returncode,
        "stderr": (proc.stderr or "")[-2000:],
    }
