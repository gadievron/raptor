"""docker-compose mechanics for multi-service stacks.

Stacks with ``volumes``, ``command``, ``environment``, or multi-service
``depends_on`` blocks cannot be reduced to a single ``docker pull``.
This module shells out to ``docker compose`` (V2 plugin, legacy binary
fallback) to build + start such stacks and picks a primary service so
callers keep a single-container abstraction.

Before anything launches, ``rewrite_for_localhost`` stages a tmpdir
copy of the compose dir and rewrites it defensively: every published
port becomes ``127.0.0.1:0:<target>`` (loopback-only, ephemeral),
host/container network_mode, privileged, pid:host, ipc:host,
userns_mode:host, and dangerous cap_add entries are stripped, docker-
socket bind mounts are dropped (host-daemon control = root), devices
are filtered to safe pseudo-devices unless the caller opts out, and
caller labels are injected per service so label-scoped cleanup finds
compose-launched containers.

Project names are caller-derived and deterministic so ``down_stack``
finds the stack even after crashes; teardown is ``down -v
--remove-orphans`` for volume + network cleanup.
"""

from __future__ import annotations

import json
import logging
import re
import shutil
import tempfile
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

from core.container.proc import docker_child_env, run_cli

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
    # Even probe calls use the allowlisted env. run_cli folds
    # timeout/OSError into RunOutcome with returncode=None on transport
    # failure; we just check returncode == 0 for plugin presence, otherwise
    # fall through to legacy `docker-compose` discovery.
    docker_bin = shutil.which("docker")
    if docker_bin is not None:
        outcome = run_cli(
            [docker_bin, "compose", "version"],
            timeout=10.0,
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


def project_name(prefix: str, key: str) -> str:
    """Deterministic compose project name. Compose requires ``[a-z0-9_-]``."""
    name = key.lower()
    return f"{prefix}-{_PROJECT_NAME_INVALID.sub('-', name)}"


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
    *,
    labels: dict[str, str] | None = None,
    allow_devices: bool = False,
) -> tuple[Path, Path]:
    """Copy ``compose_file``'s parent dir to a tmpdir + rewrite ports to 127.0.0.1:0.

    Returns ``(rewritten_compose_path, staging_dir)``. The staging_dir
    MUST be cleaned up by the caller (``shutil.rmtree``) after ``down_stack``.

    Relative build contexts + volume mounts resolve against the tmpdir
    copy, so upstream files are never mutated. Host port 0 lets Docker
    assign an ephemeral port and ``compose ps`` reports it back.

    ``labels`` (when non-empty) are injected per service so the
    caller's label-scoped cleanup can find compose-launched containers
    (otherwise the compose path would be exempt from auto-cleanup).
    """
    source_dir = compose_file.parent
    staging = Path(tempfile.mkdtemp(prefix="raptor-compose-"))
    try:
        shutil.copytree(source_dir, staging, dirs_exist_ok=True, symlinks=False)
    except OSError:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    staged_compose = staging / compose_file.name
    try:
        _rewrite_ports_in_place(staged_compose, labels=labels,
                                allow_devices=allow_devices)
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

    When ``allow_all`` is True (caller opt-in — cve-env exposes it as a
    tool parameter and an env var), all devices pass through unfiltered.
    """
    devices = spec.get("devices")
    if not isinstance(devices, list) or not devices:
        spec.pop("devices", None)
        return
    if allow_all:
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
    compose_file: Path, *, labels: dict[str, str] | None = None,
    allow_devices: bool = False,
) -> None:
    """Rewrite each service's ``ports:`` list to ``127.0.0.1:0:<container>``.

    Also strips compose features that bypass the P17 (no-priv) / P18
    (127.0.0.1 only) invariants. Specifically: ``network_mode: host``,
    ``network_mode: container:...``, ``privileged: true``, ``pid: host``, and
    dangerous ``cap_add`` entries (``SYS_ADMIN``, ``SYS_PTRACE``,
    ``NET_ADMIN``) are removed from each service so the launched stack stays
    loopback-bound and unprivileged.

    Injects the caller's ``labels`` per service so label-scoped cleanup
    matches compose-launched containers (parity with the single-
    container launch path). ``labels`` empty/None skips injection.
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
        # Inject caller labels (parity with the single-container launch
        # path). Compose's `labels:` accepts either a dict OR a list of
        # "key=value" strings; normalize to dict for deterministic merge
        # with any user-supplied labels.
        if labels:
            inject_labels(spec, labels=labels)
    compose_file.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")


def inject_labels(spec: dict[str, Any], *, labels: dict[str, str]) -> None:
    """Merge the caller's labels into a compose service spec (in-place).

    Preserves any user-supplied labels (collisions on the caller's keys
    resolve in the caller's favor to keep cleanup matching reliable).

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
    merged.update(labels)
    spec["labels"] = merged


def run_compose(
    args: list[str],
    *,
    cwd: Path | None = None,
    timeout: float = 300.0,
    platform: str | None = None,
) -> str:
    """Invoke compose with ``<args>``; raise on non-zero rc."""
    # Start from the allowlisted env so HTTPS_PROXY / GIT_SSH_COMMAND /
    # LD_PRELOAD don't reach docker compose. Layer the DOCKER_DEFAULT_PLATFORM
    # override on top when an explicit platform was requested.
    # run_cli turns timeout into outcome.timed_out=True; we re-raise
    # it as ComposeError.
    prefix = _compose_invocation()
    env: dict[str, str] = docker_child_env()
    if platform:
        env["DOCKER_DEFAULT_PLATFORM"] = platform
    outcome = run_cli(
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
    run_compose(
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
    run_compose(
        ["-p", project_name, "-f", str(compose_file), "up", "-d", "--pull", "missing"],
        timeout=up_timeout_seconds,
        platform=platform,
    )
    ps_raw = run_compose(
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
        run_compose(
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


