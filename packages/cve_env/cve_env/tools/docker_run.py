"""docker run planner layer — mechanics live in ``core.container``.

The launch mechanics (hardened defaults, ephemeral ``127.0.0.1:0``
binding with the allocated port read back from ``docker inspect``,
fresh-pull policy, transient-failure retry with prune, label-scoped
ownership stop) moved to :mod:`core.container.containers`. What stays
here is the agent-facing layer: the sticky duplicate-attempt guard,
the discriminated ``next_step_hint`` text, and the tool-result shape.

Invariants preserved (enforced in core now):

* **P9** -- ephemeral port binding ``127.0.0.1:0`` only.
* **P17** -- hardened defaults (``--cap-drop ALL``,
  ``--security-opt=no-new-privileges:true``, minimal cap_add).
* **P18** -- bind only to ``127.0.0.1``; never ``0.0.0.0``.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from core.container.containers import (
    container_logs_tail,
    launch_container,
    read_allocated_host_port,
    stop_container,
)

from cve_env.config import CVE_LABEL

logger = logging.getLogger(__name__)

# source_build's local image naming convention — refs with this prefix
# have no upstream registry, so core skips `--pull always` for them.
_LOCAL_IMAGE_PREFIXES: tuple[str, ...] = ("cve-",)


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


OWNER_LABEL = "cve-env.owner"
# CVE_LABEL imported from config (single source); re-exported here for the
# existing ``docker_run.CVE_LABEL`` references.

# Sticky retry guard: track (image, platform) pairs that have already failed in
# the current process. Agents that keep trying the same args burn budget; the
# prompt discourages this but the guard enforces it.
_FAILED_ATTEMPTS: set[tuple[str, str]] = set()

# Container ids THIS process launched (docker_run + docker_compose_up).
# The verify tool's tcp-probe port allowlist is scoped to exactly these
# containers, so under concurrent cve-env runs one run's plan can never
# aim probe payloads at a sibling run's published sidecar ports —
# labels alone cannot provide that scope (the owner label is
# product-global and label values are prompt-threaded).
_SESSION_CONTAINER_IDS: set[str] = set()

# Registry of per-CVE module-level state so the parametric lock-test in
# tests/unit/test_reset_registry_complete.py can verify the reset function
# clears every named global. Adding a new per-CVE global without appending
# to this tuple AND clearing it in reset_failed_attempts() is the bug shape.
_RESET_GLOBALS: tuple[str, ...] = ("_FAILED_ATTEMPTS", "_SESSION_CONTAINER_IDS")


def reset_failed_attempts() -> None:
    """Clear the sticky-retry memory. The agent loop calls this at the start of
    each ``build(cve_id)`` so one CVE's failed attempts don't bleed into the next."""
    _FAILED_ATTEMPTS.clear()
    _SESSION_CONTAINER_IDS.clear()


def record_session_container(container_id: str) -> None:
    """Register a container this process launched (see
    ``_SESSION_CONTAINER_IDS``). Empty ids ignored."""
    if container_id:
        _SESSION_CONTAINER_IDS.add(container_id)


def session_container_ids() -> frozenset[str]:
    """Container ids this process launched (docker_run + compose)."""
    return frozenset(_SESSION_CONTAINER_IDS)


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
    """Poll for the allocated host port; raise :class:`RunError` when it
    never appears (core returns data; this shim restores the local
    exception contract for in-package callers)."""
    host_port, diag = read_allocated_host_port(
        container_id, container_port=container_port, timeout_s=timeout_s
    )
    if host_port is None:
        raise RunError(diag, reason="no_host_port")
    return host_port


def _logs_tail(container_id: str, n: int = 80) -> str:
    return container_logs_tail(container_id, n=n)


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
            next_step_hint=_docker_run_next_step_hint(
                "duplicate_failing_attempt", "unknown", ""
            ),
        )

    labels: dict[str, str] = {OWNER_LABEL: "cve-env"}
    if cve_id:
        labels[CVE_LABEL] = cve_id
    if run_id:
        labels["cve-env.run-id"] = run_id

    if env:
        bad_keys = [k for k in env if "=" in k]
        if bad_keys:
            # Shape check surfaced HERE (before core) so the hint text and
            # the no-sticky-guard behaviour stay exactly as before.
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

    launch = launch_container(
        image=image,
        container_port=container_port,
        name_prefix="cve-env",
        labels=labels,
        platform=platform,
        env=env,
        local_prefixes=_LOCAL_IMAGE_PREFIXES,
        run_timeout_s=_docker_run_timeout_s(),
    )

    if launch.ok:
        record_session_container(launch.container_id)
        return RunResult(
            ok=True,
            container_id=launch.container_id,
            host_port=launch.host_port,
            container_port=launch.container_port,
            host_ip=launch.host_ip,
            next_step_hint=(
                f"container running on 127.0.0.1:{launch.host_port} "
                f"(container port {launch.container_port} → host "
                f"{launch.host_port}). "
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

    _FAILED_ATTEMPTS.add(attempt_key)
    if launch.reason == "pull_timeout":
        return RunResult(
            ok=False,
            reason="pull_timeout",
            reason_class="transport",
            stderr=launch.stderr,
            next_step_hint=(
                "image pull exceeded the timeout (slow/stalled registry). "
                "Do NOT retry the same pull — pivot: source_build from the "
                "upstream repo, or a different image tag/registry."
            ),
        )
    if launch.reason == "no_container_id":
        return RunResult(
            ok=False,
            reason="no_container_id",
            reason_class="unknown",
            stderr=launch.stderr,
            next_step_hint=(
                "docker run returned no container_id. The image likely failed "
                "to pull or couldn't be created. Check stderr; consider a "
                "different image or `docker_build` from source"
            ),
        )
    if launch.reason == "no_host_port":
        return RunResult(
            ok=False,
            container_id=launch.container_id,
            container_port=launch.container_port,
            reason="no_host_port",
            logs_tail=launch.logs_tail,
            stderr=launch.stderr,
            next_step_hint=(
                "container started but didn't bind the expected host port. "
                "It may have crashed early — check logs_tail. Otherwise "
                "the container exposes a different port; retry with the "
                "correct `container_port` arg"
            ),
        )
    # launch.reason == "run_failed"
    return RunResult(
        ok=False,
        reason="docker_run_failed",
        reason_class=launch.reason_class,
        stderr=launch.stderr,
        next_step_hint=_docker_run_next_step_hint(
            "docker_run_failed", launch.reason_class, launch.stderr
        ),
    )


def _docker_run_timeout_s() -> float:
    """Operator override for the `docker run --pull always` wall bound.

    Large legit-pulls land in ~390s; the 600s default leaves time to
    pivot before the per-CVE wall-guard fires.
    """
    import os

    raw = os.environ.get("CVE_ENV_DOCKER_RUN_TIMEOUT_S", "")
    if not raw:
        return 600.0
    try:
        val = float(raw)
    except ValueError:
        return 600.0
    if not (10.0 <= val <= 3600.0):
        return 600.0
    return val


def docker_stop(container_id: str) -> None:
    """Stop + remove ``container_id``. Errors are swallowed (best effort).

    Core's ownership gate refuses containers that don't carry the
    ``cve-env.owner=cve-env`` label — the agent can never stop
    arbitrary host containers.
    """
    stop_container(container_id, required_label=(OWNER_LABEL, "cve-env"))
