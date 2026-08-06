"""Docker-compose wrappers for multi-service vulhub builds.

Vulhub composes with ``volumes``, ``command``, ``environment``, or
multi-service ``depends_on`` blocks cannot be reduced to a single
``docker pull`` (they fail at ``unresolvable_metadata`` for this
reason). This module shells out to ``docker compose`` to build + start
such stacks and picks a primary service to hand back to the agent's
single-container verify abstraction.

The project name is deterministic (``cveenv-<sanitized-cve-id>``) so
``down_stack`` can always find the stack even after crashes. Every
stack is torn down with ``down -v --remove-orphans`` to guarantee
volume + network cleanup between iterations.

Invariants preserved: P18 localhost-only ports via
``rewrite_for_localhost``; deterministic project name.
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
import re
import shutil
import tempfile
import time
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

from cve_env.config import CVE_LABEL
from cve_env.utils.safe_env import safe_subprocess_env

logger = logging.getLogger(__name__)


class ComposeError(RuntimeError):
    """Raised when a ``docker compose`` invocation fails. Carries
    ``stderr`` so callers can forward the raw subprocess stderr without
    re-parsing ``str(exc)``.
    """

    def __init__(self, message: str, *, stderr: str = "") -> None:
        super().__init__(message)
        self.stderr = stderr


# Cached for process lifetime. If Docker restarts mid-bench, stale path will cause errors.
@lru_cache(maxsize=1)
def _compose_invocation() -> tuple[str, ...]:
    """Return the argv prefix for compose -- V2 plugin if available,
    else legacy ``docker-compose`` binary. Cached per process.
    """
    # Even probe calls strip dangerous env vars. run_with_timeout folds
    # timeout/OSError into RunOutcome with returncode=None on transport
    # failure; we just check returncode == 0 for plugin presence, otherwise
    # fall through to legacy `docker-compose` discovery.
    from cve_env.utils.run import run_with_timeout

    docker_bin = shutil.which("docker")
    if docker_bin is not None:
        outcome = run_with_timeout(
            [docker_bin, "compose", "version"],
            timeout=10.0,
            env=safe_subprocess_env(),
        )
        if outcome.returncode == 0:
            return (docker_bin, "compose")
    legacy = shutil.which("docker-compose")
    if legacy is not None:
        return (legacy,)
    msg = "neither 'docker compose' plugin nor 'docker-compose' binary found on PATH"
    raise ComposeError(msg)


@dataclass(frozen=True)
class ComposeContainer:
    service: str
    container_id: str
    host_port: int | None
    container_port: int | None


@dataclass(frozen=True)
class ComposeStack:
    project_name: str
    compose_file: Path
    staging_dir: Path  # tmpdir created by rewrite_for_localhost; caller should rmtree on teardown
    containers: tuple[ComposeContainer, ...]
    primary: ComposeContainer


_PROJECT_NAME_INVALID = re.compile(r"[^a-z0-9_-]")
_PREFERRED_SERVICE_HINTS: tuple[str, ...] = ("web", "app", "http", "nginx", "server")
_PREFERRED_CONTAINER_PORTS: frozenset[int] = frozenset(
    {80, 8080, 8000, 3000, 443, 8443}
)


def project_name_for(cve_id: str) -> str:
    """Deterministic compose project name. Compose requires ``[a-z0-9_-]``."""
    name = cve_id.lower()
    return f"cveenv-{_PROJECT_NAME_INVALID.sub('-', name)}"


def _extract_container_ports(spec: Any) -> list[int]:
    """Pull container-side port numbers from a compose ``ports:`` list.

    Compose accepts short (``"80"``, ``"8080:80"``) and long
    (``{target: 80, published: 8080}``) forms. We only need the
    *container* port so the override can re-publish on 127.0.0.1:0:<target>.
    """
    ports = spec.get("ports") if isinstance(spec, dict) else None
    if not isinstance(ports, list):
        return []
    out: list[int] = []
    for p in ports:
        target: int | None = None
        if isinstance(p, dict):
            raw = p.get("target")
            try:
                target = int(raw) if raw is not None else None
            except (TypeError, ValueError):
                target = None
        elif isinstance(p, (int, str)):
            text = str(p)
            tail = text.rsplit(":", 1)[-1]
            tail = tail.split("/", 1)[0]  # strip "/tcp"
            if "-" in tail:
                # Port range like "80-81": expose every port in the range.
                parts = tail.split("-", 1)
                try:
                    lo, hi = int(parts[0]), int(parts[1])
                except ValueError:
                    lo = hi = -1
                for port in range(lo, hi + 1):
                    if 0 < port < 65536:
                        out.append(port)
                continue
            try:
                target = int(tail)
            except ValueError:
                target = None
        if target is not None and 0 < target < 65536:
            out.append(target)
    return out


def rewrite_for_localhost(
    compose_file: Path,
    cve_id: str = "",
    *,
    allow_devices: bool = False,
) -> tuple[Path, Path]:
    """Copy ``compose_file``'s parent dir to a tmpdir + rewrite ports to 127.0.0.1:0.

    Returns ``(rewritten_compose_path, staging_dir)``. The staging_dir
    MUST be cleaned up by the caller (``shutil.rmtree``) after ``down_stack``.

    Relative build contexts + volume mounts resolve against the tmpdir
    copy, so upstream files are never mutated. Host port 0 lets Docker
    assign an ephemeral port and ``compose ps`` reports it back.

    ``cve_id`` (when non-empty) is injected as a per-service
    ``labels: cve-env.cve-id`` so ``lifecycle.cleanup_containers`` can find
    compose-launched containers (otherwise the compose path would be exempt
    from auto-cleanup).
    """
    source_dir = compose_file.parent
    staging = Path(tempfile.mkdtemp(prefix="cveenv-compose-"))
    try:
        shutil.copytree(source_dir, staging, dirs_exist_ok=True, symlinks=False)
    except OSError:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    staged_compose = staging / compose_file.name
    try:
        _rewrite_ports_in_place(staged_compose, cve_id=cve_id, allow_devices=allow_devices)
    except ComposeError:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    return staged_compose, staging


def _mounts_docker_socket(volume: Any) -> bool:
    """True if a compose ``volumes:`` entry binds the host docker socket.

    Mounting ``/var/run/docker.sock`` into a container grants control of the
    host/VM docker daemon (= root), so such a bind is stripped while all other
    volumes are kept. Handles the short form ``"src:dst[:mode]"`` and the long
    form ``{"source": "..."}``.
    """
    if isinstance(volume, str):
        source = volume.split(":", 1)[0]
    elif isinstance(volume, dict):
        source = str(volume.get("source", ""))
    else:
        return False
    source = source.strip()
    if (
        source == "/var/run/docker.sock"
        or source == "docker.sock"
        or source.endswith("/docker.sock")
    ):
        return True
    # Parent directory mounts that would expose the docker socket.
    source_norm = source.rstrip("/") or "/"
    if source_norm in ('/', '/var', '/var/run', '/run'):
        return True
    return False


_SAFE_DEVICE_PREFIXES = (
    "/dev/null",
    "/dev/zero",
    "/dev/urandom",
    "/dev/random",
    "/dev/stdin",
    "/dev/stdout",
    "/dev/stderr",
    "/dev/fd/",
)


def _filter_devices(spec: dict, *, allow_all: bool = False) -> None:
    """Strip dangerous device mappings, keep safe pseudo-devices.

    When ``allow_all`` is True (from the tool's ``allow_devices``
    parameter) or ``CVE_ENV_ALLOW_DEVICES=1`` is set, all devices
    pass through unfiltered.
    """
    devices = spec.get("devices")
    if not isinstance(devices, list) or not devices:
        spec.pop("devices", None)
        return
    if allow_all or os.environ.get("CVE_ENV_ALLOW_DEVICES", "").strip() == "1":
        return
    kept = []
    for dev in devices:
        src = str(dev).split(":")[0] if isinstance(dev, str) else ""
        if any(src == p or src.startswith(p) for p in _SAFE_DEVICE_PREFIXES):
            kept.append(dev)
    if kept:
        spec["devices"] = kept
    else:
        spec.pop("devices", None)


def _rewrite_ports_in_place(
    compose_file: Path, cve_id: str = "", *, allow_devices: bool = False,
) -> None:
    """Rewrite each service's ``ports:`` list to ``127.0.0.1:0:<container>``.

    Also strips compose features that bypass the P17 (no-priv) / P18
    (127.0.0.1 only) invariants. Specifically: ``network_mode: host``,
    ``network_mode: container:...``, ``privileged: true``, ``pid: host``, and
    dangerous ``cap_add`` entries (``SYS_ADMIN``, ``SYS_PTRACE``,
    ``NET_ADMIN``) are removed from each service so the launched stack stays
    loopback-bound and unprivileged.

    Injects ``labels: cve-env.owner=cve-env`` and
    ``labels: cve-env.cve-id={cve_id}`` per service so
    ``lifecycle.cleanup_containers(cve_id)`` matches compose-launched
    containers (parity with ``docker_run``). ``cve_id`` is optional — empty
    value skips the cve-id label but still sets owner.
    """
    try:
        data = yaml.safe_load(compose_file.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise ComposeError(
            f"cannot parse compose file {compose_file} for security rewrite: {exc}",
            stderr=str(exc),
        ) from exc
    if not isinstance(data, dict):
        msg = f"compose file {compose_file} did not parse as a YAML mapping"
        raise ComposeError(msg)
    services = data.get("services")
    if not isinstance(services, dict):
        msg = f"compose file {compose_file} has no 'services' mapping"
        raise ComposeError(msg)
    dangerous_caps = {
        "SYS_ADMIN",
        "SYS_PTRACE",
        "NET_ADMIN",
        "SYS_MODULE",
        "SYS_RAWIO",
        "DAC_READ_SEARCH",
        "NET_RAW",
        "SYS_CHROOT",
        "ALL",
    }
    for spec in services.values():
        if not isinstance(spec, dict):
            continue
        container_ports = _extract_container_ports(spec)
        if container_ports:
            spec["ports"] = [f"127.0.0.1:0:{port}" for port in container_ports]
        elif spec.get('ports'):
            # All port entries failed parsing but original ports list was
            # non-empty. Explicitly clear to prevent original (potentially
            # non-localhost) bindings from surviving the rewrite.
            spec['ports'] = []
        # Strip P18-bypass network_mode (any host-* form).
        net_mode = spec.get("network_mode")
        if isinstance(net_mode, str) and (
            net_mode == "host" or net_mode.startswith("container:") or net_mode.startswith("service:")
        ):
            spec.pop("network_mode", None)
        # Security hardening: strip P17-bypass privileged (bool ``True`` OR
        # the YAML string ``"true"``).
        if str(spec.get("privileged")).strip().lower() == "true":
            spec.pop("privileged", None)
        # Security hardening: strip P17-bypass pid: host (also the quoted
        # ``"host"`` string form).
        if str(spec.get("pid")).strip().lower() == "host":
            spec.pop("pid", None)
        # Security hardening: filter dangerous cap_add entries (incl. ``ALL``,
        # which would otherwise grant every capability).
        cap_add = spec.get("cap_add")
        if isinstance(cap_add, list):
            cleaned = [c for c in cap_add if str(c).upper() not in dangerous_caps]
            if cleaned:
                spec["cap_add"] = cleaned
            else:
                spec.pop("cap_add", None)
        # Security hardening: drop a host docker-socket bind mount (= host/VM
        # daemon control) while keeping all other volumes.
        volumes = spec.get("volumes")
        if isinstance(volumes, list):
            kept = [v for v in volumes if not _mounts_docker_socket(v)]
            if kept:
                spec["volumes"] = kept
            else:
                spec.pop("volumes", None)
        # Security hardening: strip seccomp/apparmor-unconfined etc. (Docker's
        # default profiles then apply).
        spec.pop("security_opt", None)
        _filter_devices(spec, allow_all=allow_devices)
        if str(spec.get("ipc")).strip().lower() == "host":
            spec.pop("ipc", None)
        if str(spec.get("userns_mode")).strip().lower() == "host":
            spec.pop("userns_mode", None)
        # Inject lifecycle labels (parity with docker_run). Compose's
        # `labels:` accepts either a dict OR a list of "key=value" strings;
        # normalize to dict for deterministic merge with any user-supplied
        # labels. Conditional on cve_id to preserve existing test contracts
        # that pass no cve_id (e.g., test_rewrite_ports_no_op_when_no_ports).
        if cve_id:
            _inject_lifecycle_labels(spec, cve_id=cve_id)
    compose_file.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")


def _inject_lifecycle_labels(spec: dict[str, Any], *, cve_id: str) -> None:
    """Add lifecycle labels to a compose service spec (in-place).

    Sets ``cve-env.owner=cve-env`` and ``cve-env.cve-id={cve_id}``.
    Caller is responsible for skipping this call when ``cve_id`` is
    empty (matches the gating in ``_rewrite_ports_in_place``).

    Preserves any user-supplied labels (collisions on our keys resolve
    in favor of ours to keep cleanup matching reliable).

    Handles both compose label schemas:
      * dict form: ``labels: {key: value}``
      * list form: ``labels: ["key=value", ...]``
    Normalizes to dict form for deterministic round-trip.
    """
    existing = spec.get("labels")
    merged: dict[str, str] = {}
    if isinstance(existing, dict):
        for k, v in existing.items():
            merged[str(k)] = str(v)
    elif isinstance(existing, list):
        for item in existing:
            text = str(item)
            if "=" in text:
                k, v = text.split("=", 1)
                merged[k.strip()] = v.strip()
            else:
                merged[text] = ""
    merged["cve-env.owner"] = "cve-env"
    merged[CVE_LABEL] = cve_id
    spec["labels"] = merged


def _run_compose(
    args: list[str],
    *,
    cwd: Path | None = None,
    timeout: float = 300.0,
    platform: str | None = None,
) -> str:
    """Invoke compose with ``<args>``; raise on non-zero rc."""
    # Start from safe_subprocess_env so HTTPS_PROXY / GIT_SSH_COMMAND /
    # LD_PRELOAD don't reach docker compose. Layer the DOCKER_DEFAULT_PLATFORM
    # override on top when an explicit platform was requested.
    # run_with_timeout turns timeout into outcome.timed_out=True; we re-raise
    # it as ComposeError.
    from cve_env.utils.run import run_with_timeout

    prefix = _compose_invocation()
    env: dict[str, str] = safe_subprocess_env()
    if platform:
        env["DOCKER_DEFAULT_PLATFORM"] = platform
    outcome = run_with_timeout(
        [*prefix, *args],
        timeout=timeout,
        cwd=str(cwd) if cwd else None,
        env=env,
    )
    if outcome.timed_out:
        msg = f"compose {args[0]} timed out after {timeout}s"
        raise ComposeError(msg, stderr=outcome.stderr)
    if outcome.returncode != 0:
        stderr = (outcome.stderr or "").strip()
        stdout = (outcome.stdout or "").strip()
        msg = (
            f"compose {args[0]!r} failed (rc={outcome.returncode}): {stderr or stdout}"
        )
        raise ComposeError(msg, stderr=stderr or stdout)
    return outcome.stdout or ""


def build_stack(
    project_name: str,
    compose_file: Path,
    *,
    build_timeout_seconds: float = 900.0,
    platform: str | None = None,
) -> None:
    """``docker compose -p <project> -f <file> build``."""
    _run_compose(
        ["-p", project_name, "-f", str(compose_file), "build"],
        timeout=build_timeout_seconds,
        platform=platform,
    )


def up_stack(
    project_name: str,
    compose_file: Path,
    *,
    up_timeout_seconds: float = 300.0,
    platform: str | None = None,
) -> tuple[tuple[ComposeContainer, ...], ComposeContainer]:
    """``docker compose up -d`` + parse ``ps --format json``. Returns
    ``(all_containers, primary)``.
    """
    # Force fresh pull of every service's image. Bypasses the local Docker
    # layer cache, which can silently re-use cached vulhub/X images even when
    # the registry is rate-limited. Compose stacks reference registry images;
    # locally-built compose stacks are extremely rare (vulhub-compose method's
    # images are all vulhub/X). If a service does FROM a local-only image,
    # --pull always fails loudly + the agent sees the error and pivots.
    # --pull missing: pull images only when not locally available. Using
    # "always" breaks locally-built services (compose stacks that `build:`
    # their own images have no upstream to pull from). Trade-off: a stale
    # cached registry image won't be refreshed automatically; operator can
    # `docker compose pull` explicitly when needed.
    _run_compose(
        ["-p", project_name, "-f", str(compose_file), "up", "-d", "--pull", "missing"],
        timeout=up_timeout_seconds,
        platform=platform,
    )
    ps_raw = _run_compose(
        ["-p", project_name, "-f", str(compose_file), "ps", "--format", "json"],
        timeout=30.0,
    )
    containers = parse_ps_json(ps_raw)
    if not containers:
        msg = f"docker compose ps returned no containers for {project_name}"
        raise ComposeError(msg)
    primary = pick_primary(containers)
    return containers, primary


def down_stack(
    project_name: str,
    compose_file: Path,
    *,
    timeout_seconds: float = 120.0,
) -> None:
    """``docker compose down -v --remove-orphans``. Best-effort; never raises."""
    try:
        _run_compose(
            [
                "-p",
                project_name,
                "-f",
                str(compose_file),
                "down",
                "-v",
                "--remove-orphans",
            ],
            timeout=timeout_seconds,
        )
    except ComposeError as exc:
        logger.warning("compose down failed for %s: %s", project_name, exc)


def parse_ps_json(raw: str) -> tuple[ComposeContainer, ...]:
    """Parse ``docker compose ps --format json`` (array OR line-delimited)."""
    text = raw.strip()
    if not text:
        return ()
    entries: list[dict[str, Any]] = []
    if text.startswith("["):
        try:
            decoded = json.loads(text)
        except json.JSONDecodeError:
            return ()
        if isinstance(decoded, list):
            entries = [e for e in decoded if isinstance(e, dict)]
    else:
        for raw_line in text.splitlines():
            line = raw_line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(obj, dict):
                entries.append(obj)
    results: list[ComposeContainer] = []
    for e in entries:
        service = str(e.get("Service") or "")
        cid = str(e.get("ID") or "")
        if not service or not cid:
            continue
        host_port, container_port = _pick_host_port(e.get("Publishers"))
        results.append(
            ComposeContainer(
                service=service,
                container_id=cid,
                host_port=host_port,
                container_port=container_port,
            )
        )
    return tuple(results)


def _pick_host_port(publishers: Any) -> tuple[int | None, int | None]:
    """Pick (host_port, container_port) -- prefer HTTP-shaped target ports."""
    if not isinstance(publishers, list):
        return None, None
    best_priority: int | None = None
    best_published: int | None = None
    best_target: int | None = None
    for p in publishers:
        if not isinstance(p, dict):
            continue
        target = p.get("TargetPort")
        published = p.get("PublishedPort")
        if target is None or published is None:
            continue
        try:
            tp = int(target)
            pp = int(published)
        except (TypeError, ValueError):
            continue
        if pp == 0:
            continue
        priority = 0 if tp in _PREFERRED_CONTAINER_PORTS else tp
        if best_priority is None or priority < best_priority:
            best_priority = priority
            best_published = pp
            best_target = tp
    if best_priority is None:
        return None, None
    return best_published, best_target


def pick_primary(containers: tuple[ComposeContainer, ...]) -> ComposeContainer:
    """Pick the HTTP-facing service; fall back to first-with-port, else first."""
    with_port = [c for c in containers if c.host_port]
    for hint in _PREFERRED_SERVICE_HINTS:
        for c in with_port:
            if hint in c.service.lower():
                return c
    if with_port:
        return with_port[0]
    return containers[0]


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

    Downloads a fresh tmpdir copy of the compose dir, rewrites ports
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
                    env=safe_subprocess_env(),
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
