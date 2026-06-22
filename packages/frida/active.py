"""Programmatic active observation — launch frida sessions from RAPTOR pipelines.

Two modes:

  observe_target(binary, ...) — spawn mode, single sandbox.
  observe_paired(target_cmd, ...) — netns coordinator for networked targets.

Plus auto_observe() for pipeline integration: skips if fresh evidence
already exists for the target.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional

from core.logging import get_logger

from .evidence import discover_evidence

log = get_logger("frida.active")

__all__ = ["auto_observe", "observe_paired", "observe_target"]

_STALENESS_THRESHOLD_S = 3600.0
_MAX_STDOUT_CAPTURE = 10 * 1024 * 1024  # 10MB cap on captured output


def _safe_env() -> dict[str, str]:
    """Build a safe subprocess environment via RaptorConfig.get_safe_env().

    Falls back to a minimal env if RaptorConfig is unavailable (e.g., in
    tests without full RAPTOR bootstrap).
    """
    try:
        from core.config import RaptorConfig
        env = RaptorConfig.get_safe_env()
    except (ImportError, AttributeError, TypeError):
        env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "HOME": os.environ.get("HOME", "/tmp"),
            "LANG": os.environ.get("LANG", "C.UTF-8"),
            "TERM": "dumb",
        }
    env.pop("_RAPTOR_TRUSTED", None)
    env["RAPTOR_DIR"] = os.environ["RAPTOR_DIR"]
    env["CLAUDECODE"] = "1"
    env["PYTHONPATH"] = os.environ["RAPTOR_DIR"]
    return env


def observe_target(
    target: str,
    template: str = "api-trace",
    out_dir: Optional[Path] = None,
    duration_sec: float = 30.0,
) -> Optional[Path]:
    """Launch a frida observation of a target binary (spawn mode).

    Runs frida under the sandbox frida profile via libexec/raptor-frida.
    The target binary is spawned by frida, hooked, and observed for
    ``duration_sec`` seconds.

    Returns the run output directory (containing events.jsonl,
    metadata.json) on success, or None on failure.
    """
    from . import available

    if not available():
        log.warning("frida not available on this host; skipping observation")
        return None

    target_p = Path(target)
    if not target_p.is_file():
        log.error("target binary not found: %s", target)
        return None

    raptor_dir = os.environ.get("RAPTOR_DIR")
    if not raptor_dir:
        log.error("RAPTOR_DIR not set")
        return None

    libexec = Path(raptor_dir) / "libexec" / "raptor-frida"

    cmd = [
        str(libexec),
        "--target", str(target_p.resolve()),
        "--template", template,
        "--spawn",
        "--duration", str(max(1, int(duration_sec))),
    ]
    if out_dir is not None:
        cmd.extend(["--out", str(out_dir)])

    env = _safe_env()

    log.info("launching frida observation: %s (template=%s, duration=%ds)",
             target, template, duration_sec)

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=duration_sec + 30,
            env=env,
        )
    except subprocess.TimeoutExpired:
        log.error("frida observation timed out for %s", target)
        return None

    if result.returncode != 0:
        stderr_tail = result.stderr[-500:] if result.stderr else ""
        log.error("frida observation failed (rc=%d): %s",
                  result.returncode, stderr_tail)
        return None

    run_dir = _extract_output_dir(result.stdout)
    if run_dir and run_dir.is_dir() and (run_dir / "metadata.json").is_file():
        log.info("observation complete: %s", run_dir)
        return run_dir

    log.error("frida observation produced no output directory")
    return None


def observe_paired(
    target_cmd: list[str],
    template: str = "api-trace",
    out_dir: Optional[Path] = None,
    duration_sec: float = 30.0,
    wait_port: int = 0,
    wait_timeout_s: float = 5.0,
) -> Optional[Path]:
    """Launch paired frida observation via the netns coordinator.

    The target runs in one sandbox child (target_run profile); frida
    attaches by process name in the other (frida profile). Both share
    an isolated network namespace.

    Use when the target is a network service that listens on loopback.

    Returns the run output directory on success, or None on failure.

    NOTE: Requires core/sandbox/netns_coordinator.py (PR #830) to be
    available. Returns None with a log message if not found.
    """
    from . import available

    if not available():
        log.warning("frida not available on this host; skipping paired observation")
        return None

    if not target_cmd:
        log.error("empty target_cmd")
        return None

    raptor_dir = os.environ.get("RAPTOR_DIR")
    if not raptor_dir:
        log.error("RAPTOR_DIR not set")
        return None

    coordinator = Path(raptor_dir) / "core" / "sandbox" / "netns_coordinator.py"
    if not coordinator.is_file():
        log.error("netns coordinator not found at %s; "
                  "observe_paired requires PR #830 on main", coordinator)
        return None

    run_dir = out_dir or _make_run_dir(raptor_dir)
    run_dir.mkdir(parents=True, exist_ok=True)

    target_binary = Path(target_cmd[0])
    target_name = target_binary.name[:15]  # TASK_COMM_LEN truncation

    frida_cmd = [
        sys.executable, "-m", "packages.frida.cli",
        "--target", target_name,
        "--template", template,
        "--duration", str(max(1, int(duration_sec))),
        "--out", str(run_dir),
    ]

    request = {
        "target": {
            "cmd": target_cmd,
            "env": {
                "RAPTOR_DIR": raptor_dir,
                "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                "HOME": os.environ.get("HOME", "/tmp"),
                "LANG": os.environ.get("LANG", "C.UTF-8"),
            },
            "timeout_s": duration_sec + 10,
            "profile": "target_run",
            "block_network": False,
        },
        "exploit": {
            "cmd": frida_cmd,
            "env": {
                "RAPTOR_DIR": raptor_dir,
                "PYTHONPATH": raptor_dir,
                "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            },
            "timeout_s": duration_sec + 10,
            "profile": "frida",
            "block_network": False,
        },
        "wait_listen_port": wait_port,
        "wait_listen_timeout_s": wait_timeout_s,
    }

    env = _safe_env()

    log.info("launching paired observation via netns coordinator: "
             "target=%s, template=%s", target_name, template)

    proc = None
    try:
        proc = subprocess.Popen(
            [sys.executable, str(coordinator)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            start_new_session=True,
        )
        stdout, stderr = proc.communicate(
            json.dumps(request).encode(),
            timeout=duration_sec + 30,
        )
    except subprocess.TimeoutExpired:
        if proc is not None:
            try:
                os.killpg(os.getpgid(proc.pid), 9)
            except (OSError, ProcessLookupError):
                proc.kill()
            proc.communicate()
        log.error("paired observation timed out")
        return None
    except OSError as exc:
        log.error("failed to launch coordinator: %s", exc)
        return None

    if proc.returncode != 0:
        log.error("coordinator exited %d: %s",
                  proc.returncode, stderr.decode(errors="replace")[-500:])
        return None

    try:
        response = json.loads(stdout)
    except (json.JSONDecodeError, ValueError) as exc:
        log.error("coordinator response not parseable: %s", exc)
        return None

    if response.get("error"):
        log.error("coordinator error: %s", response["error"])
        return None

    if run_dir.is_dir() and (run_dir / "metadata.json").is_file():
        log.info("paired observation complete: %s", run_dir)
        return run_dir

    log.warning("paired observation produced no metadata; "
                "frida may have failed to attach")
    return None


def auto_observe(
    target_path: str,
    search_dirs: list[Path],
    out_dir: Optional[Path] = None,
    duration_sec: float = 30.0,
    template: str = "api-trace",
    staleness_s: float = _STALENESS_THRESHOLD_S,
) -> Optional[Path]:
    """Observe a target only if no fresh evidence exists.

    Checks search_dirs for existing frida evidence matching target_path.
    If found and newer than staleness_s, returns None (no new observation
    needed — caller should use existing evidence via discover_evidence).
    Otherwise launches observe_target() and returns the output dir.

    Pipeline integration hook: /agentic and /validate can call this to
    get frida evidence on-demand without duplicate runs.
    """
    existing = discover_evidence(search_dirs, target_path=target_path)
    if existing:
        newest = existing[0]
        meta_path = newest.run_dir / "metadata.json"
        try:
            age = time.time() - meta_path.stat().st_mtime
        except OSError:
            age = float("inf")
        if age >= 0 and age < staleness_s:
            log.info("fresh frida evidence exists at %s (%.0fs old); "
                     "skipping new observation", newest.run_dir, age)
            return None

    return observe_target(
        target=target_path,
        template=template,
        out_dir=out_dir,
        duration_sec=duration_sec,
    )


def _extract_output_dir(stdout: str) -> Optional[Path]:
    """Parse OUTPUT_DIR=<path> from libexec output."""
    for line in stdout.splitlines():
        if line.startswith("OUTPUT_DIR="):
            p = Path(line[len("OUTPUT_DIR="):].strip())
            if p.is_dir():
                return p
    return None


def _make_run_dir(raptor_dir: str) -> Path:
    """Create a uniquely-named run directory under out/."""
    ts = time.strftime("%Y%m%d_%H%M%S")
    pid = os.getpid()
    return Path(raptor_dir) / "out" / f"frida_{ts}_{pid}"
