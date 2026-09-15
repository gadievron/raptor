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

from core.logging import get_logger

from .evidence import discover_evidence
from core.security.env_sanitisation import safe_subprocess_env

log = get_logger("frida.active")

__all__ = ["auto_observe", "observe_paired", "observe_target", "watch_sinks"]

_STALENESS_THRESHOLD_S = 3600.0
_MAX_STDOUT_CAPTURE = 10 * 1024 * 1024  # 10MB cap on captured output


def _safe_env() -> dict[str, str]:
    """Frida-CLI subprocess environment.

    Sanitised base from the shared fail-closed helper
    (``safe_subprocess_env``), minus the target-facing strip set,
    plus the RAPTOR runtime variables the hook pipeline itself needs
    (the frida CLI is RAPTOR tooling, not the observed target — the
    markers are re-added deliberately below).
    """
    env = safe_subprocess_env()
    # Subtract the target-facing strip set (trust markers + the
    # session credential): several of its members sit on the safe-env
    # allowlist for RAPTOR's own tooling, but the process observed
    # here is TARGET code — it must not inherit the session token.
    try:
        from core.config import RaptorConfig as _RC
        for _k in _RC.TARGET_ENV_STRIP_SET:
            env.pop(_k, None)
    except (ImportError, AttributeError):
        env.pop("_RAPTOR_TRUSTED", None)
        env.pop("RAPTOR_SESSION_PID", None)
        env.pop("RAPTOR_SESSION_TOKEN", None)
        env.pop("CLAUDECODE", None)
    env["RAPTOR_DIR"] = os.environ["RAPTOR_DIR"]
    env["CLAUDECODE"] = "1"
    env["PYTHONPATH"] = os.environ["RAPTOR_DIR"]
    return env


def observe_target(
    target: str,
    template: str = "api-trace",
    out_dir: Path | None = None,
    duration_sec: float = 30.0,
) -> Path | None:
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
    nonce = _mint_nonce()
    env["RAPTOR_FRIDA_RUNDIR_NONCE"] = nonce

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

    # An explicit out_dir is the caller's choice and always wins —
    # parsed sentinels only resolve wrapper-owned lifecycle dirs.
    if out_dir is not None:
        run_dir = Path(out_dir)
    else:
        run_dir = _extract_output_dir(result.stderr or "", nonce)
    if run_dir and run_dir.is_dir() and (run_dir / "metadata.json").is_file():
        log.info("observation complete: %s", run_dir)
        return run_dir

    log.error("frida observation produced no output directory")
    return None


def watch_sinks(
    target: str,
    sinks_file: Path,
    out_dir: Path | None = None,
    duration_sec: float = 30.0,
    stdin_file: Path | None = None,
) -> Path | None:
    """Launch a finding-parameterized sink watch of a target binary.

    Same sandboxed launch path as :func:`observe_target`, but the hook
    script is rendered from *sinks_file* (a sinks JSON or a validation
    run's ``attack-paths.json``). When *stdin_file* is given its bytes
    are fed to the spawned target on stdin (PoC delivery); without it
    the target runs bare, so sinks that only fire under crafted input
    gain no evidence — absence of evidence is never used against a
    finding.

    Returns the run output directory on success, or None on failure.
    """
    from . import available

    if not available():
        log.warning("frida not available on this host; skipping sink watch")
        return None

    target_p = Path(target)
    if not target_p.is_file():
        log.error("target binary not found: %s", target)
        return None
    if not Path(sinks_file).is_file():
        log.error("sinks file not found: %s", sinks_file)
        return None

    raptor_dir = os.environ.get("RAPTOR_DIR")
    if not raptor_dir:
        log.error("RAPTOR_DIR not set")
        return None

    libexec = Path(raptor_dir) / "libexec" / "raptor-frida"

    cmd = [
        str(libexec),
        "--target", str(target_p.resolve()),
        "--sink-watch", str(Path(sinks_file).resolve()),
        "--spawn",
        "--duration", str(max(1, int(duration_sec))),
    ]
    if stdin_file is not None:
        if not Path(stdin_file).is_file():
            log.error("stdin file not found: %s", stdin_file)
            return None
        cmd.extend(["--stdin", str(Path(stdin_file).resolve())])
    if out_dir is not None:
        cmd.extend(["--out", str(out_dir)])

    env = _safe_env()
    nonce = _mint_nonce()
    env["RAPTOR_FRIDA_RUNDIR_NONCE"] = nonce

    log.info("launching frida sink watch: %s (sinks=%s, duration=%ds%s)",
             target, sinks_file, duration_sec,
             ", stdin=poc" if stdin_file is not None else "")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=duration_sec + 30,
            env=env,
        )
    except subprocess.TimeoutExpired:
        log.error("frida sink watch timed out for %s", target)
        return None

    if result.returncode != 0:
        stderr_tail = result.stderr[-500:] if result.stderr else ""
        log.error("frida sink watch failed (rc=%d): %s",
                  result.returncode, stderr_tail)
        return None

    if out_dir is not None:
        run_dir = Path(out_dir)
    else:
        run_dir = _extract_output_dir(result.stderr or "", nonce)
    if run_dir and run_dir.is_dir() and (run_dir / "metadata.json").is_file():
        log.info("sink watch complete: %s", run_dir)
        return run_dir

    log.error("frida sink watch produced no output directory")
    return None


def observe_paired(
    target_cmd: list[str],
    template: str = "api-trace",
    out_dir: Path | None = None,
    duration_sec: float = 30.0,
    wait_port: int = 0,
    wait_timeout_s: float = 5.0,
) -> Path | None:
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
            # The target binary is HOSTILE code: confine its writes to
            # the run directory and restrict its reads. Without a
            # filesystem boundary the coordinator (fail-closed) refuses
            # the spec — network-only isolation is not enough for a
            # hostile child.
            "output": str(run_dir),
            "restrict_reads": True,
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
    out_dir: Path | None = None,
    duration_sec: float = 30.0,
    template: str = "api-trace",
    staleness_s: float = _STALENESS_THRESHOLD_S,
) -> Path | None:
    """Observe a target only if no fresh evidence exists.

    Checks search_dirs for existing frida evidence matching target_path.
    If found and newer than staleness_s, returns None (no new observation
    needed — caller should use existing evidence via discover_evidence).
    Otherwise launches observe_target() and returns the output dir.

    Pipeline integration hook: /agentic and /validate can call this to
    get frida evidence on-demand without duplicate runs.
    """
    from .evidence import observation_capable

    # Only observation-capable runs (api-trace/binary-flow-trace or
    # unknown operator scripts) count as existing evidence here — a
    # fresh sink-watch/seed-harvest/jni-trace run emits categories the
    # observe profile ignores and must not suppress a real observation.
    existing = [ev for ev in
                discover_evidence(search_dirs, target_path=target_path)
                if observation_capable(ev.script_origin)]
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


_RUN_DIR_SENTINEL = "RAPTOR_FRIDA_RUN_DIR:"


def _mint_nonce() -> str:
    """Fresh per-launch sentinel nonce."""
    return os.urandom(8).hex()


def _extract_output_dir(stderr: str, nonce: str) -> Path | None:
    """Parse the nonce-framed run-dir sentinel from WRAPPER stderr.

    The spawned target inherits the wrapper's stdio, so both captured
    streams carry attacker bytes once the target runs — the previous
    stdout-first scan for a bare ``OUTPUT_DIR=`` line let the target
    substitute a pre-planted evidence directory. The wrapper emits
    ``RAPTOR_FRIDA_RUN_DIR:<nonce>=<path>`` on stderr BEFORE spawning
    the target (and unsets the nonce from the child env): the nonce
    is unguessable to bytes baked into the target, and the FIRST
    framed line wins, so a later forged line can never displace the
    wrapper's own. The bare ``OUTPUT_DIR=`` lifecycle line stays on
    stderr for operators and downstream lifecycle steps; it is no
    longer trusted for evidence-dir selection.
    """
    marker = f"{_RUN_DIR_SENTINEL}{nonce}="
    for line in (stderr or "").splitlines():
        if line.startswith(marker):
            p = Path(line[len(marker):].strip())
            if p.is_dir():
                return p
            return None  # first framed line decides; never fall through
    return None


def _make_run_dir(raptor_dir: str) -> Path:
    """Create a uniquely-named run directory under out/."""
    ts = time.strftime("%Y%m%d_%H%M%S")
    pid = os.getpid()
    return Path(raptor_dir) / "out" / f"frida_{ts}_{pid}"
