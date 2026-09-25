"""Interpreter resolution and sandboxed execution for the sanitizer
witness.

Resolution ladder (each tier CAPABILITY-VERIFIED by executing a
version probe — a binary's presence is never trusted, per the
silent-empty-output lesson):

1. **native** — ``php`` on PATH; the witness executes under
   ``core.sandbox`` through the dark_verify script-witness machinery
   (network denied, reads restricted, bounded on-disk capture,
   fail-closed when core.sandbox is absent).
2. **docker** — the proven container shim: pinned image,
   ``--pull=never`` (a missing image is capability-absent, never a
   network fetch), ``--network=none``, all caps dropped, read-only
   rootfs, unprivileged uid, pids/memory caps; the script directory
   is bind-mounted read-only at its identical path.
3. **absent** — recorded honestly with the per-tier probe results;
   the channel verdict becomes not-executable, never a guess.
"""

from __future__ import annotations

import contextlib
import logging
import os
import re
import shutil
import subprocess
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from core.run.workdir import exec_workdir
from core.source import read_text_capped

logger = logging.getLogger(__name__)

#: Pinned docker fallback image. Version-pinned so the interpreter
#: recorded in receipts is stable per host; bump deliberately (the
#: verdict is scoped to the interpreter version by design).
DOCKER_IMAGE = "php:8.3-cli-alpine"

#: Capability-probe timeout. Native php answers in milliseconds;
#: docker needs a cold container start — larger only delays the
#: absent verdict on a wedged daemon, smaller risks refusing a slow
#: but working host.
PROBE_TIMEOUT_S = 60

#: Witness execution timeouts per tier. The probe runs a handful of
#: <= 64-byte payloads through builtin transforms — seconds of real
#: work; the headroom is container start (docker) and sandbox setup
#: (native). Larger only delays error verdicts on hangs (hostile
#: literal regexes land here as timeouts, by design); smaller risks
#: flapping on loaded hosts.
NATIVE_TIMEOUT_S = 30
DOCKER_TIMEOUT_S = 90

_STDOUT_CAP = 64 * 1024

#: Bounded-read cap for the daemon-written cidfile. A container id
#: is 12-64 hex chars (+ trailing newline); anything larger than
#: this generous margin is not a cid and the cleanup belt treats it
#: like a missing file. Larger buys nothing; smaller risks refusing
#: a legitimate cid spelling with daemon-added whitespace.
_CIDFILE_CAP = 256

#: Container-side RLIMIT_FSIZE (bytes) for the docker tier. Scope
#: stated precisely: it bounds REGULAR-FILE writes by the
#: containerized process (e.g. /dev/shm on a read-only rootfs) —
#: it does NOT bound stdout/stderr, which are pipes to the daemon
#: relayed by the host-side client. The stream bound is therefore
#: the parent-side incremental read loop below (cap + terminate),
#: and this rlimit is only the file-write belt.
_DOCKER_FSIZE_LIMIT = 1024 * 1024

#: Diagnostics kept from the container's stderr stream (tail only).
_DOCKER_STDERR_TAIL = 4096

#: Drain grace after terminating an over-cap/timed-out client: the
#: pipes keep being read (and discarded) for this long so the attach
#: stream can never back up — a blocked attach stops SIGTERM from
#: reaching the container and the wedge cascades daemon-wide. Longer
#: only delays the error verdict; shorter risks killing the client
#: before a graceful container exit.
_DRAIN_GRACE_S = 10


@dataclass(frozen=True)
class PhpRuntime:
    """A capability-verified PHP execution tier."""

    tier: str  # "native" | "docker"
    version: str
    php_path: str = ""
    docker_path: str = ""
    image: str = ""

    def describe(self) -> dict[str, str]:
        d = {"tier": self.tier, "version": self.version}
        if self.image:
            d["image"] = self.image
        return d


@dataclass(frozen=True)
class RuntimeUnavailable:
    """No tier verified; ``reason`` records what each probe said."""

    reason: str


@dataclass
class ExecOutcome:
    """One probe execution's raw outcome."""

    ok: bool
    stdout: str = ""
    reason: str = ""
    floor_refusal: bool = False


def _safe_env() -> dict[str, str]:
    from core.config import RaptorConfig

    return RaptorConfig.get_safe_env()


def _probe_native(php: str) -> tuple[str, str]:
    """(version, "") or ("", refusal reason)."""
    try:
        proc = subprocess.run(  # noqa: S603 — fixed argv, no target data
            [php, "-n", "-r", "echo PHP_VERSION;"],
            capture_output=True, text=True, env=_safe_env(),
            timeout=PROBE_TIMEOUT_S, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return "", f"native probe failed: {type(exc).__name__}"
    version = (proc.stdout or "").strip()
    if proc.returncode == 0 and version[:1].isdigit():
        return version, ""
    return "", (
        f"native probe rc={proc.returncode}, output not a version"
    )


def _docker_base_args(
    docker: str,
    script_dir: str | None = None,
    cidfile: str | None = None,
) -> list[str]:
    args = [
        docker, "run", "--rm", "--pull=never", "--network=none",
        "--cap-drop=ALL", "--security-opt", "no-new-privileges",
        "--read-only", "--pids-limit", "64", "--memory", "256m",
        "--ulimit", f"fsize={_DOCKER_FSIZE_LIMIT}",
        # The witness only ever reads the attach stream; without
        # this, a flooding probe ALSO pours its stdout into the
        # daemon's log driver, and the daemon busy writing gigabytes
        # of json-file log is exactly what makes kill/rm crawl.
        "--log-driver", "none",
        "--user", "65534:65534",
    ]
    if cidfile:
        # Per-execution container id record: --rm's AutoRemove never
        # fires when the CLIENT dies (a killed attach leaves the
        # container running), so every exit path finishes with a
        # cid-based daemon-side rm -f (see _cleanup_container).
        args += ["--cidfile", cidfile]
    if script_dir:
        args += ["-v", f"{script_dir}:{script_dir}:ro"]
    args.append(DOCKER_IMAGE)
    return args


def _cleanup_container(docker: str, cidfile: str) -> None:
    """Daemon-side termination belt, idempotent and best-effort.

    Signaling the CLIENT is not enough: SIGKILL on the client (or a
    client that dies with its attach stream backed up) leaves the
    container running with AutoRemove unfired — and a wedged attach
    can cascade daemon-wide. ``docker rm -f <cid>`` kills and removes
    the container at the daemon, whatever happened to the client. A
    normally-exited --rm container is already gone; the error is
    suppressed.

    The cidfile PATH is RAPTOR-created but its CONTENT is written by
    the docker daemon, so the read is bounded
    (``core.source.read_text_capped``: non-regular files refuse
    instead of blocking, undecodable bytes land in the charset check
    rather than raising through the cleanup belt) and an oversized
    or off-charset file means "not a daemon-written cid" — belt out,
    same as a missing file.
    """
    got = read_text_capped(cidfile, _CIDFILE_CAP)
    if got is None or got[1]:
        return
    cid = got[0].strip()
    if not re.fullmatch(r"[0-9a-f]{12,64}", cid):
        return
    # kill first: the daemon-side SIGKILL stops a flooding process
    # immediately even when the full remove is slow on a loaded
    # daemon; rm -f then reaps (both idempotent, best-effort — a
    # normally-exited --rm container is already gone).
    for verb in (["kill"], ["rm", "-f"]):
        with contextlib.suppress(OSError, subprocess.TimeoutExpired):
            subprocess.run(  # noqa: S603 — fixed argv; cid charset-checked
                [docker, *verb, cid],
                capture_output=True, env=_safe_env(),
                timeout=30, check=False,
            )


def _probe_docker(docker: str) -> tuple[str, str]:
    """(version, "") or ("", refusal reason)."""
    cid_dir = tempfile.mkdtemp(prefix="raptor_sanwit_cid_",
                               dir=exec_workdir())
    cidfile = os.path.join(cid_dir, "cid")
    cmd = [*_docker_base_args(docker, cidfile=cidfile),
           "php", "-n", "-r", "echo PHP_VERSION;"]
    try:
        proc = subprocess.run(  # noqa: S603 — fixed argv, no target data
            cmd, capture_output=True, text=True, env=_safe_env(),
            timeout=PROBE_TIMEOUT_S, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        # The timeout path SIGKILLs the CLIENT only — the container
        # can outlive it; the cid cleanup below is the belt.
        return "", f"docker probe failed: {type(exc).__name__}"
    finally:
        _cleanup_container(docker, cidfile)
        shutil.rmtree(cid_dir, ignore_errors=True)
    version = (proc.stdout or "").strip()
    if proc.returncode == 0 and version[:1].isdigit():
        return version, ""
    detail = (proc.stderr or "").strip().splitlines()
    return "", (
        f"docker probe rc={proc.returncode}"
        + (f": {detail[-1][:120]}" if detail else "")
    )


_RESOLVE_LOCK = threading.Lock()
_RESOLVED: PhpRuntime | RuntimeUnavailable | None = None


def resolve_php_runtime(
    refresh: bool = False,
) -> PhpRuntime | RuntimeUnavailable:
    """Resolve (and memoize) the best available PHP tier."""
    global _RESOLVED
    with _RESOLVE_LOCK:
        if _RESOLVED is not None and not refresh:
            return _RESOLVED
        reasons: list[str] = []
        php = shutil.which("php")
        if php:
            version, why = _probe_native(php)
            if version:
                _RESOLVED = PhpRuntime(
                    tier="native", version=version, php_path=php,
                )
                return _RESOLVED
            reasons.append(why)
        else:
            reasons.append("php-cli not on PATH")
        docker = shutil.which("docker")
        if docker:
            version, why = _probe_docker(docker)
            if version:
                _RESOLVED = PhpRuntime(
                    tier="docker", version=version,
                    docker_path=docker, image=DOCKER_IMAGE,
                )
                return _RESOLVED
            reasons.append(why)
        else:
            reasons.append("docker not on PATH")
        _RESOLVED = RuntimeUnavailable(
            reason="php interpreter unavailable: " + "; ".join(reasons),
        )
        return _RESOLVED


def _reset_runtime_cache() -> None:
    """Test hook."""
    global _RESOLVED
    with _RESOLVE_LOCK:
        _RESOLVED = None


def _php_cli_args(script_dir: Path) -> list[str]:
    # -n: ignore host ini (deterministic across hosts); open_basedir
    # pins reads to the script directory (probe + payload file only).
    return [
        "-n",
        "-d", f"open_basedir={script_dir}",
        "-d", "memory_limit=64M",
    ]


def _execute_native(
    runtime: PhpRuntime,
    script_dir: Path,
    probe_file: Path,
    payloads_file: Path,
    audit_run_dir: Path | None,
) -> ExecOutcome:
    """Run the probe under core.sandbox (fail closed without it)."""
    from core.audit.dark_verify._execute import (
        _import_sandbox_run,
        _sandbox_exec_path,
        _sandbox_run_capped,
        _toolchain_read_paths,
    )

    sandbox_run = _import_sandbox_run()
    if sandbox_run is None:
        return ExecOutcome(
            ok=False,
            reason=(
                "core.sandbox unavailable — witness execution refused "
                "(no unsandboxed fallback)"
            ),
        )
    try:
        from core.sandbox import SandboxFloorError
        floor_errors: tuple[type[BaseException], ...] = (SandboxFloorError,)
    except ImportError:  # pragma: no cover — sandbox import succeeded above
        floor_errors = ()

    cap_dir = Path(tempfile.mkdtemp(
        prefix="raptor_sanwit_cap_", dir=exec_workdir()))
    try:
        tool_reads = [str(script_dir),
                      *_toolchain_read_paths(runtime.php_path)]
        proc = _sandbox_run_capped(
            sandbox_run,
            [
                _sandbox_exec_path(runtime.php_path, tool_reads),
                *_php_cli_args(script_dir),
                str(probe_file), str(payloads_file),
            ],
            cap_dir=cap_dir,
            block_network=True,
            restrict_reads=True,
            target=str(script_dir),
            output=str(cap_dir),
            timeout=NATIVE_TIMEOUT_S,
            caller_label="audit-sanwit-php",
            tool_paths=tool_reads,
            **({"audit_run_dir": audit_run_dir} if audit_run_dir else {}),
        )
    except floor_errors as exc:
        from core.witness.sandbox_outcome import refusal_detail

        detail = refusal_detail(exc) or {}
        return ExecOutcome(
            ok=False, floor_refusal=True,
            reason=(
                "containment floor "
                f"{detail.get('floor', '?')} required, "
                f"{detail.get('achievable', '?')} achievable — "
                "witness never executed"
            ),
        )
    except subprocess.TimeoutExpired:
        return ExecOutcome(
            ok=False, reason=f"witness timed out after {NATIVE_TIMEOUT_S}s",
        )
    except Exception as exc:  # noqa: BLE001 — leg errors must not kill the run
        logger.debug("sanwit native execution failed", exc_info=True)
        return ExecOutcome(
            ok=False,
            reason=f"execution failed: {type(exc).__name__}",
        )
    finally:
        shutil.rmtree(cap_dir, ignore_errors=True)
    return ExecOutcome(ok=True, stdout=(proc.stdout or "")[:_STDOUT_CAP])


def _execute_docker(
    runtime: PhpRuntime,
    script_dir: Path,
    probe_file: Path,
    payloads_file: Path,
) -> ExecOutcome:
    """Run the probe in the pinned container (docker provides the
    containment; core.sandbox cannot wrap a daemon-mediated spawn)."""
    # The container runs uid 65534: the bind-mounted files must be
    # world-readable (path resolution starts AT the mount, so parent
    # directory modes do not apply).
    try:
        os.chmod(script_dir, 0o755)
        for f in (probe_file, payloads_file):
            os.chmod(f, 0o644)
    except OSError as exc:
        return ExecOutcome(
            ok=False, reason=f"chmod failed: {type(exc).__name__}",
        )
    cid_dir = Path(tempfile.mkdtemp(
        prefix="raptor_sanwit_cid_", dir=exec_workdir()))
    cidfile = str(cid_dir / "cid")
    cmd = [
        *_docker_base_args(
            runtime.docker_path, str(script_dir), cidfile=cidfile,
        ),
        "php", *_php_cli_args(script_dir),
        str(probe_file), str(payloads_file),
    ]
    # Bounded parent-side capture: the container's stdout/stderr are
    # PIPES relayed by the host-side docker client (the container's
    # fsize rlimit cannot bound them), so the flood bound must be the
    # read loop itself — accumulation stops at cap+1, the client is
    # terminated while both pipes keep draining, and the container is
    # removed daemon-side by cid on every exit path. The bound is the
    # CAP, not timeout x throughput onto scratch; an oversized stream
    # is indeterminate, never a verdict.
    try:
        return _run_capped_pipes(
            cmd, env=_safe_env(),
            cleanup=lambda: _cleanup_container(
                runtime.docker_path, cidfile,
            ),
        )
    finally:
        shutil.rmtree(cid_dir, ignore_errors=True)


def _run_capped_pipes(
    cmd: list[str],
    *,
    env: dict[str, str],
    cleanup: Callable[[], None] | None = None,
) -> ExecOutcome:
    """Run *cmd* with both output pipes read incrementally: stdout
    accumulates up to the cap, stderr keeps a bounded diagnostic
    tail. Over-cap/timeout terminates the client while CONTINUING to
    drain-and-discard both pipes — stopping the reads would back up
    the attach stream, block the client, and stop SIGTERM from ever
    reaching the container. *cleanup* (the cid-based daemon-side
    remove) runs unconditionally on every exit path."""
    import select

    try:
        proc = subprocess.Popen(  # noqa: S603 — argv list; probe text
            # is grammar-validated, payloads ride a data file
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=env,
        )
    except OSError as exc:
        if cleanup is not None:
            cleanup()
        return ExecOutcome(
            ok=False, reason=f"docker execution failed: {type(exc).__name__}",
        )
    assert proc.stdout is not None and proc.stderr is not None
    deadline = time.monotonic() + DOCKER_TIMEOUT_S
    out = bytearray()
    err_tail = bytearray()
    overflow = False
    timed_out = False
    drain_deadline: float | None = None
    open_fds = {proc.stdout: "out", proc.stderr: "err"}
    rc: int | None = None
    try:
        while open_fds:
            now = time.monotonic()
            if not (overflow or timed_out) and now >= deadline:
                timed_out = True
            if (overflow or timed_out) and drain_deadline is None:
                proc.terminate()
                drain_deadline = time.monotonic() + _DRAIN_GRACE_S
            if drain_deadline is not None:
                if time.monotonic() >= drain_deadline:
                    break
                wait_s = 0.2
            else:
                wait_s = max(min(deadline - now, 1.0), 0.05)
            ready, _, _ = select.select(list(open_fds), [], [], wait_s)
            if not ready:
                if drain_deadline is not None and proc.poll() is not None:
                    break
                continue
            for fd in ready:
                chunk = fd.read1(65536)
                if not chunk:
                    del open_fds[fd]
                    continue
                if overflow or timed_out:
                    continue  # drain and discard
                if open_fds.get(fd) == "out":
                    out += chunk
                    if len(out) > _STDOUT_CAP:
                        overflow = True
                else:
                    err_tail += chunk
                    del err_tail[:-_DOCKER_STDERR_TAIL]
        if overflow or timed_out:
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                with contextlib.suppress(subprocess.TimeoutExpired):
                    proc.wait(timeout=10)
            if overflow:
                return ExecOutcome(
                    ok=False,
                    reason=(
                        f"probe stdout exceeded the {_STDOUT_CAP}-byte "
                        "cap — terminated, indeterminate"
                    ),
                )
            return ExecOutcome(
                ok=False,
                reason=f"witness timed out after {DOCKER_TIMEOUT_S}s",
            )
        rc = proc.wait(timeout=max(1.0, deadline - time.monotonic()))
    except (OSError, ValueError) as exc:
        proc.kill()
        return ExecOutcome(
            ok=False, reason=f"docker execution failed: {type(exc).__name__}",
        )
    except subprocess.TimeoutExpired:
        proc.kill()
        return ExecOutcome(
            ok=False,
            reason=f"witness timed out after {DOCKER_TIMEOUT_S}s",
        )
    finally:
        proc.stdout.close()
        proc.stderr.close()
        if proc.poll() is None:
            proc.kill()
        if cleanup is not None:
            cleanup()
    if rc != 0:
        tail = err_tail.decode("utf-8", errors="replace").strip()
        last = tail.splitlines()[-1][:120] if tail else ""
        return ExecOutcome(
            ok=False,
            reason=f"probe exited {rc}" + (f": {last}" if last else ""),
        )
    return ExecOutcome(
        ok=True, stdout=out.decode("utf-8", errors="replace"),
    )


def execute_probe(
    runtime: PhpRuntime,
    probe_src: str,
    payloads_json: str,
    audit_run_dir: Path | None = None,
) -> ExecOutcome:
    """Write probe + payload documents to a dedicated scratch dir and
    execute them on *runtime*."""
    script_dir = Path(tempfile.mkdtemp(
        prefix="raptor_sanwit_", dir=exec_workdir()))
    try:
        probe_file = script_dir / "probe.php"
        payloads_file = script_dir / "payloads.json"
        probe_file.write_text(probe_src, encoding="utf-8")
        payloads_file.write_text(payloads_json, encoding="utf-8")
        if runtime.tier == "native":
            return _execute_native(
                runtime, script_dir, probe_file, payloads_file,
                audit_run_dir,
            )
        if runtime.tier == "docker":
            return _execute_docker(
                runtime, script_dir, probe_file, payloads_file,
            )
        return ExecOutcome(  # pragma: no cover — resolver contract
            ok=False, reason=f"unknown runtime tier {runtime.tier!r}",
        )
    finally:
        shutil.rmtree(script_dir, ignore_errors=True)
