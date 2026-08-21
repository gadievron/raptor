"""Single-container launch/inspect/stop mechanics over the docker CLI.

Invariants every consumer inherits:

* **Ephemeral loopback ports only.** Ports bind ``127.0.0.1:0``; the
  allocated host port is read back from ``docker inspect`` post-launch.
  Nothing here can publish on ``0.0.0.0``.
* **Hardened defaults.** ``--cap-drop ALL`` with a minimal cap_add set,
  ``no-new-privileges``, memory/cpu/pids limits.
* **Label-scoped ownership.** Callers stamp their containers with
  labels; :func:`stop_container` refuses to touch a container missing
  the caller's ownership label, so an agent-driven consumer can never
  stop arbitrary host containers.

Failures are data (:class:`LaunchResult` with a ``reason`` +
``reason_class``), never exceptions — the callers are planners that
branch on discriminated failure classes. Cross-call pivot state
(sticky duplicate-attempt guards, hint text) belongs to the caller,
not here.
"""

from __future__ import annotations

import json
import logging
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

from core.container.failures import classify_docker_stderr, is_retry_eligible
from core.container.proc import run_cli

logger = logging.getLogger(__name__)

HARDENED_CAP_DROP: tuple[str, ...] = ("ALL",)
HARDENED_CAP_ADD: tuple[str, ...] = (
    "CHOWN",
    "DAC_OVERRIDE",
    "SETGID",
    "SETUID",
    "NET_BIND_SERVICE",
)
HARDENED_SECURITY_OPT: tuple[str, ...] = ("no-new-privileges:true",)

# Retry-on-transient before surfacing failure.
_RETRY_BACKOFF_S: float = 5.0
_RETRY_MAX_ATTEMPTS: int = 2  # original + 1 retry

# Bound the post-launch `docker inspect`/`docker logs` calls so a wedged
# daemon can't hang the caller (these are fast local daemon queries).
_INSPECT_POLL_TIMEOUT_S: float = 10.0
_LOGS_TAIL_TIMEOUT_S: float = 15.0


def is_external_image(image: str, *, local_prefixes: tuple[str, ...] = ()) -> bool:
    """True iff ``image`` came from a public registry (and should be
    pulled fresh with ``--pull``). False for locally-built references.

    Heuristic (pure text, no docker call): empty, ``scratch``,
    ``localhost/*``, and any caller-supplied ``local_prefixes`` (e.g. a
    builder's naming convention) classify local; everything else —
    including bare Docker Hub names like ``debian:11`` — is external.
    Err-toward-external: misclassifying local as external fails loudly
    at ``--pull``; the reverse silently reuses a stale cache.
    """
    if not image:
        return False
    if image == "scratch":
        return False
    if image.startswith("localhost/"):
        return False
    return not any(image.startswith(p) for p in local_prefixes)


@dataclass
class LaunchResult:
    """Result of :func:`launch_container` — data, never an exception."""

    ok: bool
    container_id: str = ""
    host_port: int = 0
    container_port: int = 0
    host_ip: str = "127.0.0.1"
    reason: str = ""  # "" | invalid_env_key | pull_timeout | run_failed |
    #                   no_container_id | no_host_port
    reason_class: str = "ok"
    logs_tail: str = ""
    stderr: str = ""
    extras: dict[str, Any] = field(default_factory=dict)


def read_allocated_host_port(
    container_id: str,
    *,
    container_port: int,
    timeout_s: float = 10.0,
) -> tuple[int | None, str]:
    """Poll ``docker inspect`` until the allocated host port appears.

    Docker may report ``Ports=[]`` for a tick after ``run -d`` returns.
    Returns ``(host_port, "")`` or ``(None, diagnostic)``.
    """
    deadline = time.monotonic() + timeout_s
    last_bindings: list[dict[str, Any]] = []
    while time.monotonic() < deadline:
        outcome = run_cli(
            [
                "docker",
                "inspect",
                "--format",
                "{{json .NetworkSettings.Ports}}",
                container_id,
            ],
            timeout=_INSPECT_POLL_TIMEOUT_S,
        )
        if outcome.returncode == 0 and outcome.stdout.strip():
            try:
                ports = json.loads(outcome.stdout)
            except json.JSONDecodeError:
                ports = None
            if isinstance(ports, dict):
                key = f"{container_port}/tcp"
                bindings = ports.get(key) or []
                last_bindings = bindings if isinstance(bindings, list) else []
                for binding in last_bindings:
                    if (
                        not isinstance(binding, dict)
                        or binding.get("HostIp") != "127.0.0.1"
                    ):
                        continue
                    host_port = binding.get("HostPort")
                    if host_port is None:
                        continue
                    try:
                        return int(host_port), ""
                    except (TypeError, ValueError):
                        continue
        time.sleep(0.3)
    return None, (
        f"no 127.0.0.1 host binding for {container_port}/tcp "
        f"(bindings={last_bindings})"
    )


def container_logs_tail(container_id: str, n: int = 80,
                        max_bytes: int = 4000) -> str:
    """Last ``n`` lines of ``docker logs`` (stdout+stderr combined),
    truncated to ``max_bytes``. Best-effort — "" on any failure."""
    outcome = run_cli(
        ["docker", "logs", "--tail", str(n), container_id],
        timeout=_LOGS_TAIL_TIMEOUT_S,
    )
    if outcome.timed_out or outcome.returncode is None:
        return ""
    combined = f"{outcome.stdout or ''}\n{outcome.stderr or ''}".strip()
    return combined[-max_bytes:]


def inspect_state(container_id: str, *, timeout_s: float = 30.0) -> dict[str, Any]:
    """``docker inspect .State`` as a dict; failures fold into an
    ``{"_error": reason}`` shape so inspection can never raise."""
    outcome = run_cli(
        ["docker", "inspect", "--format", "{{json .State}}", container_id],
        timeout=timeout_s,
    )
    if outcome.timed_out:
        return {"_error": "docker inspect timed out"}
    if outcome.returncode != 0:
        return {"_error": outcome.stderr.strip() or "docker inspect failed"}
    try:
        state = json.loads(outcome.stdout)
    except json.JSONDecodeError:
        return {"_error": "docker inspect returned non-JSON"}
    return state if isinstance(state, dict) else {"_error": "State is not a dict"}


def launch_container(
    *,
    image: str,
    container_port: int,
    name_prefix: str = "raptor-env",
    labels: dict[str, str] | None = None,
    platform: str | None = None,
    env: dict[str, str] | None = None,
    pull_always: bool | None = None,
    local_prefixes: tuple[str, ...] = (),
    memory: str = "4g",
    cpus: str = "2",
    pids_limit: int = 512,
    run_timeout_s: float = 600.0,
) -> LaunchResult:
    """Launch a single container with an ephemeral ``127.0.0.1`` binding.

    ``pull_always=None`` (default) derives ``--pull always`` from
    :func:`is_external_image` — registry images are always pulled fresh
    (the local layer cache silently serves stale bytes under registry
    rate limits); locally-built images have no upstream to pull.

    One automatic retry (with a dangling prune on ``disk_full``) fires
    for retry-eligible stderr classes; a stalled pull (wall timeout)
    fails fast instead — an identical re-pull won't recover and would
    double the wall spend.
    """
    # Reject env keys containing '=' — a caller-controlled key like
    # "FOO=BAR" would produce `-e FOO=BAR=value`, creating misnamed env
    # var "FOO" with value "BAR=value" inside the container.
    if env:
        bad_keys = [k for k in env if "=" in k]
        if bad_keys:
            return LaunchResult(
                ok=False,
                reason="invalid_env_key",
                reason_class="unknown",
                stderr=f"env key(s) contain '=': {bad_keys!r}",
            )

    cmd: list[str] = ["docker", "run", "-d", "--name",
                      f"{name_prefix}-{uuid.uuid4().hex[:12]}"]
    for cap in HARDENED_CAP_DROP:
        cmd.extend(["--cap-drop", cap])
    for cap in HARDENED_CAP_ADD:
        cmd.extend(["--cap-add", cap])
    for opt in HARDENED_SECURITY_OPT:
        cmd.extend(["--security-opt", opt])
    cmd.extend(["--memory", memory, "--memory-swap", memory])
    cmd.extend(["--cpus", cpus])
    cmd.extend(["--pids-limit", str(pids_limit)])
    cmd.extend(["-p", f"127.0.0.1::{container_port}"])
    for k, v in (labels or {}).items():
        cmd.extend(["--label", f"{k}={v}"])
    if platform:
        cmd.extend(["--platform", platform])
    for k, v in (env or {}).items():
        if k.startswith("-"):
            continue  # reject flag-shaped keys
        cmd.extend(["-e", f"{k}={v}"])
    if pull_always is None:
        pull_always = is_external_image(image, local_prefixes=local_prefixes)
    if pull_always:
        cmd.extend(["--pull", "always"])
    cmd.append(image)

    proc = None
    last_reason_class = "ok"
    for attempt in range(1, _RETRY_MAX_ATTEMPTS + 1):
        proc = run_cli(cmd, timeout=run_timeout_s)
        if proc.returncode == 0:
            break
        if proc.timed_out:
            last_reason_class = "transport"
            break
        last_reason_class = classify_docker_stderr(proc.stderr)
        if attempt >= _RETRY_MAX_ATTEMPTS or not is_retry_eligible(
            last_reason_class
        ):
            break
        if last_reason_class == "disk_full":
            logger.info(
                "launch_container disk_full on %s; pruning + retrying in %ss",
                image, _RETRY_BACKOFF_S,
            )
            run_cli(["docker", "system", "prune", "-f"], timeout=30)
        else:
            logger.info(
                "launch_container %s on %s; retrying in %ss",
                last_reason_class, image, _RETRY_BACKOFF_S,
            )
        time.sleep(_RETRY_BACKOFF_S)
        # Fresh container name so the second attempt doesn't collide.
        for i, arg in enumerate(cmd):
            if arg == "--name" and i + 1 < len(cmd):
                cmd[i + 1] = f"{name_prefix}-{uuid.uuid4().hex[:12]}"
                break

    assert proc is not None  # noqa: S101 — loop above always assigns
    if proc.returncode != 0:
        if proc.timed_out:
            return LaunchResult(
                ok=False,
                reason="pull_timeout",
                reason_class="transport",
                stderr=(
                    f"docker run --pull always exceeded {run_timeout_s:.0f}s "
                    "— registry pull slow/stalled"
                ),
            )
        return LaunchResult(
            ok=False,
            reason="run_failed",
            reason_class=last_reason_class,
            stderr=proc.stderr.strip()[-4000:],
        )

    container_id = proc.stdout.strip()
    if not container_id:
        return LaunchResult(
            ok=False,
            reason="no_container_id",
            reason_class="unknown",
            stderr=proc.stderr.strip()[-4000:],
        )

    host_port, port_diag = read_allocated_host_port(
        container_id, container_port=container_port
    )
    if host_port is None:
        return LaunchResult(
            ok=False,
            container_id=container_id,
            container_port=container_port,
            reason="no_host_port",
            logs_tail=container_logs_tail(container_id),
            stderr=port_diag,
        )

    return LaunchResult(
        ok=True,
        container_id=container_id,
        host_port=host_port,
        container_port=container_port,
        host_ip="127.0.0.1",
    )


def stop_container(
    container_id: str,
    *,
    required_label: tuple[str, str] | None = None,
) -> bool:
    """Stop + remove ``container_id``. Errors swallowed (best effort).

    When ``required_label=(key, value)`` is given, the container must
    carry exactly that label or the call refuses (returns False) — the
    ownership gate that keeps agent-driven consumers from stopping
    arbitrary host containers.
    """
    if required_label is not None:
        key, value = required_label
        outcome = run_cli(
            [
                "docker",
                "inspect",
                "--format",
                f'{{{{index .Config.Labels "{key}"}}}}',
                container_id,
            ],
            timeout=5.0,
        )
        if outcome.returncode != 0 or (outcome.stdout or "").strip() != value:
            logger.warning(
                "stop_container: %s lacks label %s=%s; refusing",
                container_id, key, value,
            )
            return False
    run_cli(["docker", "stop", container_id], timeout=30)
    run_cli(["docker", "rm", "-f", container_id], timeout=30)
    return True
