"""docker run + docker compose up with localhost-only ephemeral ports.

Uses subprocess (``docker`` CLI) directly instead of docker-py /
testcontainers -- subprocess is portable, has fewer deps, avoids
docker-py / testcontainers issues on Colima, and matches how the rest
of the agent speaks to docker.

Scope: one container, one primary HTTP port, teardown via the caller.

Invariants preserved:

* **P9** -- ephemeral port binding ``127.0.0.1:0`` only; allocated port
  read from ``docker inspect`` post-launch.
* **P17** -- hardened defaults (``--cap-drop ALL``,
  ``--security-opt=no-new-privileges:true``, minimal cap_add).
* **P18** -- bind only to ``127.0.0.1``; never ``0.0.0.0``.
"""

from __future__ import annotations

import json
import logging
import os
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cve_env.config import CVE_LABEL
from cve_env.tools._failure_class import classify_docker_stderr, is_retry_eligible
from cve_env.tools._image_origin import _is_external_image
from cve_env.utils.run import run_with_timeout

logger = logging.getLogger(__name__)

# Auto-retry-on-transient before surfacing failure.
_DOCKER_RETRY_BACKOFF_S: float = 5.0  # short wait before retry
_DOCKER_RETRY_MAX_ATTEMPTS: int = 2  # original + 1 retry

# Bound `docker run --pull always` so a slow or stalled registry pull fails
# fast and the agent can pivot, instead of hanging until the wall-guard
# SIGKILLs the worker. Large legit-pulls land in ~390s; 600s leaves time to
# pivot before the wall-guard fires.
_DOCKER_RUN_TIMEOUT_S: float = float(
    os.environ.get("CVE_ENV_DOCKER_RUN_TIMEOUT_S", "600")
)

# Bound the post-launch `docker inspect`/`docker logs` calls so a wedged daemon
# can't hang a worker to the wall (these run between SDK messages, where no
# on_message guard fires). Short — both are fast local daemon queries.
_INSPECT_POLL_TIMEOUT_S: float = 10.0
_LOGS_TAIL_TIMEOUT_S: float = 15.0


class RunError(RuntimeError):
    """Raised when ``docker run`` fails before the container is usable.

    Carries ``reason`` so the agent can branch on a discriminated failure
    class (``no_image``, ``no_host_port``, ``startup_timeout``) without
    regex-parsing the message.
    """

    def __init__(
        self, message: str, *, reason: str = "", image_ref: str | None = None
    ) -> None:
        super().__init__(message)
        self.reason = reason
        self.image_ref = image_ref


DEFAULT_CAP_DROP: tuple[str, ...] = ("ALL",)
DEFAULT_CAP_ADD: tuple[str, ...] = (
    "CHOWN",
    "DAC_OVERRIDE",
    "SETGID",
    "SETUID",
    "NET_BIND_SERVICE",
)
DEFAULT_SECURITY_OPT: tuple[str, ...] = ("no-new-privileges:true",)

OWNER_LABEL = "cve-env.owner"
# CVE_LABEL imported from config (single source); re-exported here for the
# existing ``docker_run.CVE_LABEL`` references.

# Sticky retry guard: track (image, platform) pairs that have already failed in
# the current process. Agents that keep trying the same args burn budget; the
# prompt discourages this but the guard enforces it.
_FAILED_ATTEMPTS: set[tuple[str, str]] = set()

# Registry of per-CVE module-level state so the parametric lock-test in
# tests/unit/test_reset_registry_complete.py can verify the reset function
# clears every named global. Adding a new per-CVE global without appending
# to this tuple AND clearing it in reset_failed_attempts() is the bug shape.
_RESET_GLOBALS: tuple[str, ...] = ("_FAILED_ATTEMPTS",)


def reset_failed_attempts() -> None:
    """Clear the sticky-retry memory. The agent loop calls this at the start of
    each ``build(cve_id)`` so one CVE's failed attempts don't bleed into the next."""
    _FAILED_ATTEMPTS.clear()


@dataclass
class RunningContainer:
    """Running container handle."""

    container_id: str
    host_port: int
    container_port: int
    host_ip: str = "127.0.0.1"
    image: str = ""
    platform: str | None = None
    compose_project: str | None = None
    compose_file_path: Path | None = None

    def get_url(self) -> str:
        return f"http://{self.host_ip}:{self.host_port}"


@dataclass
class RunResult:
    """Result of ``docker_run`` suitable for JSON return to the agent."""

    ok: bool
    container_id: str = ""
    host_port: int = 0
    container_port: int = 0
    host_ip: str = "127.0.0.1"
    reason: str = ""
    reason_class: str = "ok"  # ok/disk_full/manifest_unknown/transport/auth/network
    logs_tail: str = ""
    stderr: str = ""
    next_step_hint: str = ""  # concrete next action on failure
    extras: dict[str, Any] = field(default_factory=dict)


def _docker_run_next_step_hint(reason: str, reason_class: str, stderr: str) -> str:
    """Pick a concrete next action based on the failure shape."""
    if reason == "duplicate_failing_attempt":
        return (
            "change `image` OR `platform` argument before retrying — the "
            "sticky-retry guard rejected an identical (image, platform) pair"
        )
    if reason_class == "manifest_unknown":
        return (
            "the image ref isn't on the registry. Re-call `image_resolve` "
            "with a different version, or `source_build` against the upstream "
            "GitHub repo"
        )
    if reason_class == "auth":
        return (
            "registry refused auth. Try a different image (public alternative) "
            "or, if running locally, `docker login` first"
        )
    if reason_class == "disk_full":
        return (
            "host docker daemon ran out of disk. The auto-retry already "
            "pruned + retried once; if still failing, no clean recovery "
            "in-process — give_up(no_image) and report disk pressure"
        )
    if reason_class in ("transport", "network"):
        return (
            "transient network failure. Auto-retry already fired once; "
            "if still failing, retry the same call after a short pause"
        )
    if "platform" in stderr.lower() and "match" in stderr.lower():
        return (
            "arch mismatch between image and host. Pass `platform=linux/amd64` "
            "(if host has Rosetta) or call `image_resolve` with a different "
            "version that publishes a multi-arch manifest"
        )
    return (
        "docker_run failed. Read `stderr` and `logs_tail`; common pivots: "
        "different image, different platform, or `source_build` to compose"
    )


def _normalize_ports(ports_config: dict[Any, Any]) -> tuple[int, str]:
    """Pick the primary ``(container_port, bind_ip)`` from the plan.

    Accepts either ``{container_port: {"bind": "127.0.0.1"}}`` or a
    plain ``{container_port: bind_ip_string}``. Returns the first entry;
    only one primary HTTP port is supported.
    """
    if not ports_config:
        msg = "run plan has no ports"
        raise RunError(msg, reason="no_ports")
    for key, spec in ports_config.items():
        try:
            container_port = int(key)
        except (TypeError, ValueError):
            continue
        bind = (
            str(spec.get("bind", "127.0.0.1")) if isinstance(spec, dict) else str(spec)
        )
        if bind != "127.0.0.1":
            msg = (
                f"run plan binds port {container_port} to {bind!r}; "
                "only 127.0.0.1 is allowed (P18)"
            )
            raise RunError(msg, reason="disallowed_bind")
        return container_port, bind
    msg = "no valid container port found in run plan"
    raise RunError(msg, reason="no_ports")


def _read_allocated_host_port(
    container_id: str,
    *,
    container_port: int,
    timeout_s: float = 10.0,
) -> int:
    """Poll ``docker inspect`` until the allocated host port appears.

    Docker may report ``Ports=[]`` for a tick after ``run -d`` returns.
    Poll up to ``timeout_s``.
    """
    deadline = time.monotonic() + timeout_s
    last_bindings: list[dict[str, Any]] = []
    while time.monotonic() < deadline:
        # run_with_timeout applies safe_subprocess_env() by default, so
        # dangerous env vars are still stripped. Bound each poll so a wedged
        # daemon can't hang past the deadline (timed_out → returncode None →
        # this poll is skipped, the deadline loop exits, no_host_port raised).
        outcome = run_with_timeout(
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
                        return int(host_port)
                    except (TypeError, ValueError):
                        continue
        time.sleep(0.3)
    msg = (
        f"no 127.0.0.1 host binding for {container_port}/tcp (bindings={last_bindings})"
    )
    raise RunError(msg, reason="no_host_port")


def _logs_tail(container_id: str, n: int = 80) -> str:
    # run_with_timeout applies safe_subprocess_env() by default. Bound so a
    # wedged daemon can't hang; best-effort on timeout.
    outcome = run_with_timeout(
        ["docker", "logs", "--tail", str(n), container_id],
        timeout=_LOGS_TAIL_TIMEOUT_S,
    )
    out = outcome.stdout or ""
    err = outcome.stderr or ""
    combined = f"{out}\n{err}".strip()
    return combined[-4000:]


def docker_run(
    *,
    image: str,
    container_port: int,
    run_id: str = "",
    cve_id: str = "",
    platform: str | None = None,
    env: dict[str, str] | None = None,
) -> RunResult:
    """Launch a single container with ephemeral ``127.0.0.1`` port binding.

    Returns a :class:`RunResult`. On failure, ``ok=False`` and ``reason``
    carries the discriminated failure class. Does NOT raise -- tool
    results are returned to the agent as data.

    Sticky-retry guard: if the exact (image, platform) combination already
    failed in this process, refuse to re-run without first trying something
    different. The agent receives ``reason="duplicate_failing_attempt"`` and
    an instruction to change the image ref or platform argument.
    """
    attempt_key = (image, platform or "")
    if attempt_key in _FAILED_ATTEMPTS:
        return RunResult(
            ok=False,
            reason="duplicate_failing_attempt",
            reason_class="unknown",
            stderr=(
                f"(image={image!r}, platform={platform!r}) already failed in this run. "
                "Change the image ref or the platform argument before retrying. "
                "If the image is amd64-only on an arm64 host, pass "
                "platform='linux/amd64' (Rosetta); if the image lacks the needed "
                "arch entirely, consider give_up(arch_incompatible) or source_build."
            ),
        )

    name = f"cve-env-{uuid.uuid4().hex[:12]}"
    cmd: list[str] = [
        "docker",
        "run",
        "-d",
        "--name",
        name,
    ]
    for cap in DEFAULT_CAP_DROP:
        cmd.extend(["--cap-drop", cap])
    for cap in DEFAULT_CAP_ADD:
        cmd.extend(["--cap-add", cap])
    for opt in DEFAULT_SECURITY_OPT:
        cmd.extend(["--security-opt", opt])
    cmd.extend(["--memory", "4g", "--memory-swap", "4g"])
    cmd.extend(["--cpus", "2"])
    cmd.extend(["--pids-limit", "512"])
    cmd.extend(["-p", f"127.0.0.1::{container_port}"])
    cmd.extend(["--label", f"{OWNER_LABEL}=cve-env"])
    if cve_id:
        cmd.extend(["--label", f"{CVE_LABEL}={cve_id}"])
    if run_id:
        cmd.extend(["--label", f"cve-env.run-id={run_id}"])
    if platform:
        cmd.extend(["--platform", platform])
    # Reject env keys containing '=' — an LLM-controlled key like "FOO=BAR"
    # would produce `-e FOO=BAR=value`, creating misnamed env var "FOO" with
    # value "BAR=value" inside the container.
    if env:
        bad_keys = [k for k in env if "=" in k]
        if bad_keys:
            return RunResult(
                ok=False,
                reason="invalid_env_key",
                reason_class="unknown",
                stderr=f"env key(s) contain '=': {bad_keys!r}",
                next_step_hint=(
                    "env dict keys must not contain '='. Fix the key names "
                    "and retry."
                ),
            )
    for k, v in (env or {}).items():
        if k.startswith("-"):
            continue  # reject flag-shaped keys
        cmd.extend(["-e", f"{k}={v}"])
    # Force fresh pull for registry-pulled images. Bypasses the local Docker
    # layer cache, which can silently re-use cached layers even when Docker
    # Hub is rate-limited. Skipped for locally-built images (source_build
    # output, bare names) which have no upstream to pull from.
    if _is_external_image(image):
        cmd.extend(["--pull", "always"])
    cmd.append(image)

    # Auto-retry-on-transient. If the first run fails with a retry-eligible
    # class (disk_full, transport, network, unknown), prune dangling images +
    # retry once before declaring failure.
    proc = None
    last_reason_class = "ok"
    for attempt in range(1, _DOCKER_RETRY_MAX_ATTEMPTS + 1):
        # Bound the `docker run --pull always` call. run_with_timeout applies
        # safe_subprocess_env() when env is None, so dangerous env vars are
        # stripped before docker run. RunOutcome exposes
        # .returncode/.stdout/.stderr; on timeout .returncode is None and
        # .timed_out is True.
        proc = run_with_timeout(cmd, timeout=_DOCKER_RUN_TIMEOUT_S)
        if proc.returncode == 0:
            break
        # A stalled pull (timed_out) won't recover on an identical retry, and a
        # 2nd full _DOCKER_RUN_TIMEOUT_S window would push the docker_run budget
        # toward the wall-guard this timeout exists to beat. Fail FAST → the
        # post-loop pull_timeout branch tells the agent to pivot. Other
        # transient failures (transport/disk_full from stderr) still get the
        # original one retry.
        if proc.timed_out:
            last_reason_class = "transport"
            break
        last_reason_class = classify_docker_stderr(proc.stderr)
        if attempt >= _DOCKER_RETRY_MAX_ATTEMPTS or not is_retry_eligible(
            last_reason_class
        ):
            break
        # Retry-eligible failure: prune + wait briefly, then retry.
        if last_reason_class == "disk_full":
            logger.info(
                "docker_run disk_full on %s; pruning + retrying in %ss",
                image,
                _DOCKER_RETRY_BACKOFF_S,
            )
            # Best-effort prune; run_with_timeout catches all transport
            # failures (a prune timeout must not break the retry) and we
            # ignore the outcome.
            run_with_timeout(
                ["docker", "system", "prune", "-f"],
                timeout=30,
            )
        else:
            logger.info(
                "docker_run %s on %s; retrying in %ss",
                last_reason_class,
                image,
                _DOCKER_RETRY_BACKOFF_S,
            )
        time.sleep(_DOCKER_RETRY_BACKOFF_S)
        # Generate a fresh container name so the second attempt doesn't collide.
        for i, arg in enumerate(cmd):
            if arg == "--name" and i + 1 < len(cmd):
                cmd[i + 1] = f"cve-env-{uuid.uuid4().hex[:12]}"
                break

    assert proc is not None  # noqa: S101 -- loop above always assigns
    if proc.returncode != 0:
        _FAILED_ATTEMPTS.add(attempt_key)
        # A stalled `docker run --pull always` hit the timeout. Tell the agent
        # to pivot rather than re-pull the same ref.
        if proc.timed_out:
            return RunResult(
                ok=False,
                reason="pull_timeout",
                reason_class="transport",
                stderr=(
                    f"docker run --pull always exceeded {_DOCKER_RUN_TIMEOUT_S:.0f}s "
                    "— registry pull slow/stalled"
                ),
                next_step_hint=(
                    "image pull exceeded the timeout (slow/stalled registry). "
                    "Do NOT retry the same pull — pivot: source_build from the "
                    "upstream repo, or a different image tag/registry."
                ),
            )
        stderr_text = proc.stderr.strip()[-4000:]
        return RunResult(
            ok=False,
            reason="docker_run_failed",
            reason_class=last_reason_class,
            stderr=stderr_text,
            next_step_hint=_docker_run_next_step_hint(
                "docker_run_failed", last_reason_class, stderr_text
            ),
        )

    container_id = proc.stdout.strip()
    if not container_id:
        _FAILED_ATTEMPTS.add(attempt_key)
        return RunResult(
            ok=False,
            reason="no_container_id",
            reason_class="unknown",
            stderr=proc.stderr.strip()[-4000:],
            next_step_hint=(
                "docker run returned no container_id. The image likely failed "
                "to pull or couldn't be created. Check stderr; consider a "
                "different image or `docker_build` from source"
            ),
        )

    try:
        host_port = _read_allocated_host_port(
            container_id, container_port=container_port
        )
    except RunError as exc:
        _FAILED_ATTEMPTS.add(attempt_key)
        return RunResult(
            ok=False,
            container_id=container_id,
            container_port=container_port,
            reason=exc.reason or "no_host_port",
            logs_tail=_logs_tail(container_id),
            stderr=str(exc),
            next_step_hint=(
                "container started but didn't bind the expected host port. "
                "It may have crashed early — check logs_tail. Otherwise "
                "the container exposes a different port; retry with the "
                "correct `container_port` arg"
            ),
        )

    return RunResult(
        ok=True,
        container_id=container_id,
        host_port=host_port,
        container_port=container_port,
        host_ip="127.0.0.1",
        next_step_hint=(
            f"container running on 127.0.0.1:{host_port} "
            f"(container port {container_port} → host {host_port}). "
            "YOUR LITERAL NEXT TOOL CALL MUST BE `verify` with a plan "
            "including container_status + http_check (or tcp_probe_check "
            "for non-HTTP services like Redis/Postgres/SSH) + a "
            "version-assertion exec_check (e.g. `pip show <pkg>`, "
            "`dpkg -l | grep <pkg>`, `<binary> --version`). Do NOT emit "
            "end_turn until verify has been attempted at least once — "
            "the runtime classifies launched-but-never-verified as a "
            "distinct failure mode (Phase 57 launched_unverified)."
        ),
    )


def _is_owned_container(container_id: str) -> bool:
    """Return True only if the container carries the ``cve-env.owner=cve-env`` label.

    Prevents the agent from stopping arbitrary host containers.
    """
    outcome = run_with_timeout(
        [
            "docker",
            "inspect",
            "--format",
            f'{{{{index .Config.Labels "{OWNER_LABEL}"}}}}',
            container_id,
        ],
        timeout=5.0,
    )
    return (
        outcome.returncode == 0
        and (outcome.stdout or "").strip() == "cve-env"
    )


def docker_stop(container_id: str) -> None:
    """Stop + remove ``container_id``. Errors are swallowed (best effort).

    ``run_with_timeout`` catches all transport failures (including timeouts)
    so the "errors are swallowed" contract holds.
    """
    if not _is_owned_container(container_id):
        logger.warning(
            "docker_stop: container %s is not owned by cve-env; skipping",
            container_id,
        )
        return
    run_with_timeout(["docker", "stop", container_id], timeout=30)
    run_with_timeout(["docker", "rm", "-f", container_id], timeout=30)
