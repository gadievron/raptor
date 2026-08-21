"""Compose tool surface — the stack mechanics live in ``core.container.compose``.

The defensive staging rewrite (loopback-only ephemeral ports, privilege
stripping, docker-socket bind removal, device filtering, label
injection), the compose invocation (V2 plugin / legacy fallback), the
``ps --format json`` parsing, and the primary-service pick all moved to
:mod:`core.container.compose`. What stays here is the agent-facing
layer: the per-CVE active-stack registry (idempotent re-up + teardown
between CVEs), the transient-failure retry with prune, the label
binding, the ``CVE_ENV_ALLOW_DEVICES`` opt-out, and the tool-result
shape with its next-step hint.
"""

from __future__ import annotations

import contextlib
import logging
import os
import shutil
import time
from pathlib import Path
from typing import Any

from core.container.compose import (
    ComposeContainer,
    ComposeError,
    ComposeStack,
    _compose_invocation,
    _extract_container_ports,
    _filter_devices,
    _mounts_docker_socket,
    _pick_host_port,
    build_stack,
    down_stack,
    inject_labels,
    parse_ps_json,
    pick_primary,
    project_name,
    up_stack,
)
from core.container.compose import (
    _rewrite_ports_in_place as _core_rewrite_ports_in_place,
)
from core.container.compose import (
    rewrite_for_localhost as _core_rewrite_for_localhost,
)

from cve_env.config import CVE_LABEL

logger = logging.getLogger(__name__)

__all__ = [
    "ComposeContainer",
    "ComposeError",
    "ComposeStack",
    "build_stack",
    "docker_compose_up_payload",
    "down_stack",
    "parse_ps_json",
    "pick_primary",
    "project_name_for",
    "reset_active_stacks",
    "rewrite_for_localhost",
    "up_stack",
]

# Re-exported mechanics kept importable under their historical names.
_ = (_compose_invocation, _extract_container_ports, _filter_devices,
     _mounts_docker_socket, _pick_host_port)


def _lifecycle_labels(cve_id: str) -> dict[str, str]:
    """Owner + CVE labels, parity with ``docker_run``'s container labels."""
    return {"cve-env.owner": "cve-env", CVE_LABEL: cve_id}


def _allow_all_devices(allow_devices: bool) -> bool:
    """Tool parameter OR the ``CVE_ENV_ALLOW_DEVICES=1`` operator env."""
    return (
        allow_devices
        or os.environ.get("CVE_ENV_ALLOW_DEVICES", "").strip() == "1"
    )


def project_name_for(cve_id: str) -> str:
    """Deterministic compose project name (``cveenv-<sanitized-cve-id>``)."""
    return project_name("cveenv", cve_id)


def rewrite_for_localhost(
    compose_file: Path,
    cve_id: str = "",
    *,
    allow_devices: bool = False,
) -> tuple[Path, Path]:
    """Stage + defensively rewrite a compose dir (see core docstring).

    ``cve_id`` (when non-empty) binds the lifecycle labels so
    ``lifecycle.cleanup_containers(cve_id)`` finds compose-launched
    containers.
    """
    return _core_rewrite_for_localhost(
        compose_file,
        labels=_lifecycle_labels(cve_id) if cve_id else None,
        allow_devices=_allow_all_devices(allow_devices),
    )


def _rewrite_ports_in_place(
    compose_file: Path, cve_id: str = "", *, allow_devices: bool = False,
) -> None:
    """In-place defensive rewrite (see core docstring)."""
    _core_rewrite_ports_in_place(
        compose_file,
        labels=_lifecycle_labels(cve_id) if cve_id else None,
        allow_devices=_allow_all_devices(allow_devices),
    )


def _inject_lifecycle_labels(spec: dict[str, Any], *, cve_id: str) -> None:
    """Add the cve-env lifecycle labels to a compose service spec."""
    inject_labels(spec, labels=_lifecycle_labels(cve_id))


# -- MCP tool front-end -------------------------------------------------------


# Active stacks this process has brought up -- keyed by cve_id. The agent
# loop calls ``reset_active_stacks()`` at the start of each CVE to tear
# down any leftover stack and purge the tmpdir. Mirrors the pattern in
# tools/docker_run.py::_FAILED_ATTEMPTS.
# cve_id -> (project, compose_path, staging_dir)
_ACTIVE_STACKS: dict[str, tuple[str, Path, Path]] = {}

# Per-CVE state registry. See note in docker_run.py for the contract.
_RESET_GLOBALS: tuple[str, ...] = ("_ACTIVE_STACKS",)


def _teardown_stack(cve_id: str) -> None:
    entry = _ACTIVE_STACKS.pop(cve_id, None)
    if entry is None:
        return
    project, compose_path, staging = entry
    try:
        down_stack(project, compose_path)
    except Exception as exc:  # noqa: BLE001 -- teardown is best-effort
        logger.warning("teardown: compose down failed: %s", exc)
    try:
        if staging.exists():
            shutil.rmtree(staging, ignore_errors=True)
    except OSError as exc:
        logger.warning("teardown: rmtree %s failed: %s", staging, exc)


def reset_active_stacks() -> None:
    """Tear down any stacks this process brought up and clear the registry.

    Called by the agent loop at the start of each CVE (analogous to
    ``docker_run.reset_failed_attempts``). This prevents a crashed
    previous build from leaving orphan containers / volumes / networks
    around for the next CVE.
    """
    for cve_id in list(_ACTIVE_STACKS.keys()):
        _teardown_stack(cve_id)


def docker_compose_up_payload(
    *,
    compose_yaml_path: str,
    cve_id: str,
    platform: str | None = None,
    allow_devices: bool = False,
) -> dict[str, Any]:
    """Agent-tool-ready dict shape.

    Stages a fresh tmpdir copy of the compose dir, rewrites ports
    to 127.0.0.1:0:<target>, runs ``docker compose up -d``, and returns
    the primary container's id + allocated host_port so the agent can
    go straight to ``verify`` or ``run_in_container``.
    """
    compose_path = Path(compose_yaml_path)
    if not compose_path.exists():
        return {
            "ok": False,
            "reason": f"compose file not found: {compose_yaml_path}",
            "reason_class": "unknown",
            "cve_id": cve_id,
        }

    # Idempotency guard: if the agent re-calls with the same cve_id,
    # tear down the previous stack first so ports don't collide.
    if cve_id in _ACTIVE_STACKS:
        _teardown_stack(cve_id)

    try:
        rewritten, staging = rewrite_for_localhost(
            compose_path, cve_id=cve_id, allow_devices=allow_devices,
        )
    except (OSError, ComposeError) as exc:
        return {
            "ok": False,
            "reason": f"could not stage compose dir: {exc}",
            "reason_class": "disk_full"
            if "no space" in str(exc).lower()
            else "unknown",
            "cve_id": cve_id,
        }

    project = project_name_for(cve_id)
    # Auto-retry-on-transient. If `up_stack` fails with a retry-eligible
    # class, prune + retry once before surfacing.
    from cve_env.tools._failure_class import classify_docker_stderr, is_retry_eligible

    last_exc: ComposeError | None = None
    last_class = "ok"
    for attempt in range(1, 3):  # 2 attempts total
        try:
            containers, primary = up_stack(project, rewritten, platform=platform)
            last_class = "ok"
            last_exc = None
            break
        except ComposeError as exc:
            last_exc = exc
            last_class = classify_docker_stderr(exc.stderr)
            with contextlib.suppress(Exception):
                down_stack(project, rewritten)
            if attempt >= 2 or not is_retry_eligible(last_class):
                break
            if last_class == "disk_full":
                # Best-effort prune; run_with_timeout catches all transport
                # failures (a prune timeout must not break the retry) and we
                # ignore the result.
                from cve_env.utils.run import run_with_timeout

                run_with_timeout(
                    ["docker", "system", "prune", "-f"],
                    timeout=30,
                )
            time.sleep(5)

    if last_exc is not None:
        shutil.rmtree(staging, ignore_errors=True)
        return {
            "ok": False,
            "reason": f"compose up failed: {last_exc}",
            "reason_class": last_class,
            "stderr": last_exc.stderr[-4000:],
            "cve_id": cve_id,
        }

    # Register for later teardown.
    _ACTIVE_STACKS[cve_id] = (project, rewritten, staging)

    return {
        "ok": True,
        "cve_id": cve_id,
        "project_name": project,
        "compose_file": str(rewritten),
        "primary_container_id": primary.container_id,
        "primary_service": primary.service,
        "host_ip": "127.0.0.1",
        "host_port": primary.host_port,
        "container_port": primary.container_port,
        "services": [
            {
                "service": c.service,
                "container_id": c.container_id,
                "host_port": c.host_port,
                "container_port": c.container_port,
            }
            for c in containers
        ],
        # Explicit hint pushing the agent to call verify next rather than emit
        # end_turn after the compose stack comes up.
        "next_step_hint": (
            f"compose stack '{project}' running; primary service "
            f"'{primary.service}' on 127.0.0.1:{primary.host_port}. "
            "YOUR LITERAL NEXT TOOL CALL MUST BE `verify` with a plan "
            "that includes container_status + http_check (or "
            "tcp_probe_check for non-HTTP) + a version-assertion "
            "exec_check. Do NOT emit end_turn until verify has been "
            "attempted — runtime classifies launched-but-never-verified "
            "as a distinct failure mode (Phase 57 launched_unverified)."
        ),
    }
