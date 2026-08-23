"""docker-compose mechanics for multi-service stacks.

Stacks with ``volumes``, ``command``, ``environment``, or multi-service
``depends_on`` blocks cannot be reduced to a single ``docker pull``.
This module shells out to ``docker compose`` (V2 plugin, legacy binary
fallback) to build + start such stacks and picks a primary service so
callers keep a single-container abstraction.

Before anything launches, ``rewrite_for_localhost`` stages a tmpdir
copy of the compose dir (symlinks preserved; links escaping the
staging dir are pruned), gates the FULL resolution graph (the primary
document plus every transitively ``extends``-referenced document —
each file reference confined to staging, refused otherwise), resolves
the effective service model through ``docker compose config`` run with
a minimal interpolation environment and — where the host supports it —
inside a read-confined sandbox (interpolation, ``extends``, YAML
anchors, ``.env`` are applied by compose itself; the sanitizer must
see what the daemon would run, not the raw text), then rebuilds each
service from a KEY ALLOWLIST: every published port becomes
``127.0.0.1:0:<target>``, bind-mount sources must resolve inside the
staging dir, ``build`` contexts are confined to the staging dir,
``cap_add`` is filtered to a safe-capability allowlist, devices are
filtered to safe pseudo-devices unless the caller opts out,
single-container-parity resource limits are injected per service, and
caller labels are injected per service so label-scoped cleanup finds
compose-launched containers. Every stack network (including the
implicit default) is forced ``internal`` — no routed egress; the
verify endpoint moves to the container's own network address (see
``up_stack``); the host's bridge gateway address remains reachable
from inside for host services bound on 0.0.0.0 (documented residual —
loopback-bound host services are not reachable). Host-resource keys
(``privileged``, ``pid``, ``network_mode: host``, ``security_opt``,
``userns_mode``, ``ulimits``, ...) never survive because unknown keys
are DROPPED, not passed through. Constructs the resolution graph
cannot be vouched for — ``include:``, out-of-staging or interpolated
``extends``/``env_file`` references at any depth, external/host-file
secrets — are REFUSED (fail closed), never passed through.

Project names are caller-derived and deterministic so ``down_stack``
finds the stack even after crashes; teardown is ``down -v
--remove-orphans`` for volume + network cleanup.
"""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

from core.container.proc import docker_child_env, run_cli
from core.run.scratch import keepalive_register, keepalive_unregister

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
    #: Address the endpoint is reachable at. ``127.0.0.1`` for published
    #: ports; the container's own network address on internal (no-egress)
    #: stack networks, where publishing is unavailable — ``host_port``
    #: then equals ``container_port``.
    host_ip: str = "127.0.0.1"


@dataclass(frozen=True)
class ComposeStack:
    project_name: str
    compose_file: Path
    staging_dir: Path  # tmpdir from rewrite_for_localhost; caller runs cleanup_staging() on teardown
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
                # Endpoints are validated BEFORE the range is constructed —
                # a hostile "0-4000000000" must not spin the worker.
                parts = tail.split("-", 1)
                try:
                    lo, hi = int(parts[0]), int(parts[1])
                except ValueError:
                    continue
                if not (1 <= lo <= hi <= 65535):
                    continue
                out.extend(range(lo, hi + 1))
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
    # Hand-rolled (not scratch_dir): ownership transfers to the caller,
    # who runs cleanup_staging() after down_stack. The raptor-compose-
    # prefix is listed in core.run.tmp_reaper's static tuple, so a
    # SIGKILLed stack strands nothing past the age floor — and the
    # keepalive is what makes that listing safe: a long-running stack
    # bind-mounts from this dir while nothing refreshes its top-level
    # mtime, so the owner keeps it fresh until teardown.
    staging = Path(tempfile.mkdtemp(prefix="raptor-compose-"))
    keepalive_register(staging)
    try:
        # symlinks=True preserves links AS links — symlinks=False would
        # DEREFERENCE them, copying arbitrary host files (~/.aws/credentials,
        # /etc/shadow) into the staging dir where they become build-context /
        # bind-mount content shipped into a hostile stack.
        shutil.copytree(source_dir, staging, dirs_exist_ok=True, symlinks=True)
    except OSError:
        cleanup_staging(staging)
        raise
    pruned = _prune_escaping_symlinks(staging)
    if pruned:
        logger.warning(
            "compose staging: pruned %d symlink(s) escaping the staging dir",
            pruned,
        )
    staged_compose = staging / compose_file.name
    try:
        _rewrite_ports_in_place(staged_compose, labels=labels,
                                allow_devices=allow_devices)
    except ComposeError:
        cleanup_staging(staging)
        raise
    return staged_compose, staging


def cleanup_staging(staging: str | Path) -> None:
    """Release a staging dir made by :func:`rewrite_for_localhost`.

    The one teardown path for staging ownership: drops the keepalive
    (so a dir this process abandoned can age out for the reaper) and
    best-effort-removes the tree. Callers run it after ``down_stack``;
    the rewrite's own failure paths use it too.
    """
    keepalive_unregister(staging)
    shutil.rmtree(staging, ignore_errors=True)


def _prune_escaping_symlinks(staging: Path) -> int:
    """Remove symlinks under ``staging`` whose resolved target escapes it.

    The staged tree is copied with ``symlinks=True`` (never dereferenced);
    links that point inside the staging copy keep working, links that point
    at host paths are unlinked so no later consumer (build context tar,
    bind-mount source resolution) can be steered at a host file.
    Returns the number of links removed.
    """
    removed = 0
    staging_real = staging.resolve()
    prefix = str(staging_real) + os.sep
    for dirpath, dirnames, filenames in os.walk(staging, followlinks=False):
        for name in (*dirnames, *filenames):
            p = Path(dirpath) / name
            if not p.is_symlink():
                continue
            target = os.path.realpath(p)
            if not target.startswith(prefix):
                try:
                    p.unlink()
                except OSError:  # pragma: no cover — racy delete, stay closed
                    pass
                removed += 1
    return removed


def _mounts_docker_socket(volume: Any) -> bool:
    """True if a compose ``volumes:`` entry binds the host docker socket.

    Superseded as the primary defense by :func:`_filter_volumes` (bind
    sources are now allowlist-confined to the staging dir), retained as a
    belt-and-braces named-volume guard and for its importers.
    Handles the short form ``"src:dst[:mode]"`` and the long
    form ``{"source": "..."}``.
    """
    if isinstance(volume, str):
        source = volume.split(":", 1)[0]
    elif isinstance(volume, dict):
        source = str(volume.get("source", ""))
    else:
        return False
    source = source.strip()
    if not source:
        # No source at all (anonymous volume, tmpfs long form) — there is
        # nothing to bind, so nothing can expose the socket. Without this,
        # the parent-dir normalization below turns "" into "/" and drops
        # every sourceless mount.
        return False
    if (
        source in {"/var/run/docker.sock", "docker.sock"} or source.endswith("/docker.sock")
    ):
        return True
    # Parent directory mounts that would expose the docker socket.
    source_norm = source.rstrip("/") or "/"
    return source_norm in ('/', '/var', '/var/run', '/run')


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
        if isinstance(dev, str):
            src = dev.split(":")[0]
        elif isinstance(dev, dict):
            # ``compose config`` normalizes devices to the long form
            # ``{source, target, permissions}``.
            src = str(dev.get("source") or "")
        else:
            src = ""
        if any(src == p or src.startswith(p) for p in _SAFE_DEVICE_PREFIXES):
            kept.append(dev)
    if kept:
        spec["devices"] = kept
    else:
        spec.pop("devices", None)


# Safe-to-grant cap_add entries: Docker's default capability set (harmless
# to re-add) plus SYS_NICE. Compared AFTER normalization (upper-case, the
# optional ``CAP_`` prefix stripped — Docker accepts both spellings, so the
# filter must too). Everything else — SYS_ADMIN, SYS_PTRACE, NET_ADMIN,
# NET_RAW, BPF, ALL, ... — is dropped, allowlist-style.
_SAFE_CAP_ADD: frozenset[str] = frozenset({
    "AUDIT_WRITE", "CHOWN", "DAC_OVERRIDE", "FOWNER", "FSETID", "KILL",
    "MKNOD", "NET_BIND_SERVICE", "SETFCAP", "SETGID", "SETPCAP", "SETUID",
    "SYS_NICE",
})

#: Fail-closed cap on stack size — a hostile stack must not fan out
#: arbitrary services under the host daemon.
_MAX_SERVICES = 12
#: Cap the rewritten publish list per service (range forms expand).
_MAX_PORTS_PER_SERVICE = 64

# Single-container-parity resource limits (containers.py hardened defaults),
# injected into every compose service. Legacy service-level keys work on both
# compose V2 (mapped into resources) and the V1 binary.
_SERVICE_LIMITS: dict[str, Any] = {
    "mem_limit": "4g",
    "memswap_limit": "4g",
    "cpus": 2,
    "pids_limit": 512,
}

# Service keys copied through as-is. Everything not listed here and not
# specially handled below (ports, volumes, build, cap_add, devices,
# environment, network_mode, ipc, pid, labels, extra_hosts) is DROPPED —
# privileged, security_opt, userns_mode, cgroup_parent,
# device_cgroup_rules, volumes_from, runtime, deploy, container_name,
# oom_kill_disable and any future host-resource key never survive by
# construction. Notably NOT listed: ``ulimits`` (memlock -1 pins
# unswappable host RAM past the injected mem_limit) and
# ``stop_grace_period`` (an attacker-chosen grace outlives ``down``'s
# timeout and holds the stack alive through teardown).
_SERVICE_ALLOWED_KEYS: frozenset[str] = frozenset({
    "image", "command", "entrypoint", "depends_on", "expose", "healthcheck",
    "links", "networks", "working_dir", "user", "restart", "hostname",
    "domainname", "stop_signal", "tty", "stdin_open",
    "init", "platform", "pull_policy", "read_only", "tmpfs", "shm_size",
    "cap_drop", "dns", "dns_search", "dns_opt",
    "sysctls", "profiles", "secrets", "configs",
})

# build: sub-keys copied through (context/dockerfile confined separately).
# Dropped by omission: ssh, network, privileged, cache_from, cache_to,
# platforms, tags, entitlements, additional_contexts (refused), ...
_BUILD_ALLOWED_KEYS: frozenset[str] = frozenset({
    "context", "dockerfile", "dockerfile_inline", "args", "target",
    "labels", "no_cache", "pull", "shm_size", "secrets",
})


#: Recursive pre-gate bounds: ``extends`` chains deeper than this refuse
#: (fail closed), and each gated file is size-capped before parsing.
_PRE_GATE_MAX_DEPTH = 5
_PRE_GATE_MAX_FILE_BYTES = 5 << 20  # 5 MiB per gated YAML document


def _require_staging_relative(value: Any, staging: Path, *, what: str) -> Path:
    """Refuse ``value`` unless it is a plain relative path inside ``staging``.

    Guards raw-model path references that the resolver consumes BEFORE the
    sanitizer sees the resolved output (``env_file``, ``extends.file``,
    ``label_file``): a host path here reads host files into the effective
    model. Interpolated values are refused outright — their expansion is
    not decidable here. Returns the confined resolved path so the gate can
    recurse into referenced compose documents.
    """
    if not isinstance(value, str) or not value:
        raise ComposeError(f"compose {what} must be a non-empty string")
    if "${" in value:
        raise ComposeError(
            f"compose {what} {value!r} uses interpolation — refusing "
            "(cannot confine an interpolated path to the staging dir)"
        )
    if value.startswith(("/", "~")):
        raise ComposeError(
            f"compose {what} {value!r} references a host path — refusing"
        )
    staging_real = staging.resolve()
    resolved = os.path.realpath(os.path.join(staging_real, value))
    if not resolved.startswith(str(staging_real) + os.sep):
        raise ComposeError(
            f"compose {what} {value!r} escapes the staging dir — refusing"
        )
    return Path(resolved)


def _load_gated_document(path: Path, *, what: str) -> Any:
    """Bounded parse of a staging-confined YAML document for the pre-gate."""
    try:
        if path.stat().st_size > _PRE_GATE_MAX_FILE_BYTES:
            raise ComposeError(
                f"compose {what} {path.name!r} exceeds the "
                f"{_PRE_GATE_MAX_FILE_BYTES}-byte gate budget — refusing"
            )
        return yaml.safe_load(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ComposeError(
            f"compose {what} {path.name!r} is not readable: {exc}"
        ) from exc
    except yaml.YAMLError as exc:
        raise ComposeError(
            f"compose {what} {path.name!r} did not parse as YAML: {exc}"
        ) from exc


def _gate_document(
    data: Any,
    staging: Path,
    *,
    source: str,
    seen: set[str],
    depth: int,
) -> None:
    """Gate ONE document's file references and recurse into extends targets.

    The resolver follows ``extends`` chains and reads every referenced
    document's own ``env_file``/``extends.file``/``label_file`` — gating
    only the primary file leaves a one-hop bypass: a staged extends
    target declaring ``env_file: /host/path`` would be read by ``docker
    compose config``. Every document the resolution graph can touch is
    gated, depth-capped and cycle-checked, BEFORE the resolver runs.
    (``label_file`` is ignored by current compose but gated anyway —
    version drift must not reopen the family.)
    """
    if depth > _PRE_GATE_MAX_DEPTH:
        raise ComposeError(
            f"compose extends chain exceeds depth {_PRE_GATE_MAX_DEPTH} "
            f"(at {source}) — refusing"
        )
    if not isinstance(data, dict):
        raise ComposeError(
            f"compose document {source} did not parse as a mapping — refusing"
        )
    if "include" in data:
        raise ComposeError(
            f"compose 'include:' in {source} is refused — included files "
            "bypass staging confinement; inline the services instead"
        )
    services = data.get("services")
    if not isinstance(services, dict):
        return  # the resolver will produce the authoritative error
    for name, spec in services.items():
        if not isinstance(spec, dict):
            continue
        for key in ("env_file", "label_file"):
            value = spec.get(key)
            if value is None:
                continue
            entries = value if isinstance(value, list) else [value]
            for entry in entries:
                if entry is None:
                    continue
                path = entry.get("path") if isinstance(entry, dict) else entry
                _require_staging_relative(
                    path, staging,
                    what=f"service {name!r} {key} (in {source})",
                )
        extends = spec.get("extends")
        if isinstance(extends, dict) and "file" in extends:
            target = _require_staging_relative(
                extends["file"], staging,
                what=f"service {name!r} extends.file (in {source})",
            )
            marker = str(target)
            if marker in seen:
                continue  # cycle or already-gated document
            seen.add(marker)
            _gate_document(
                _load_gated_document(target, what="extends target"),
                staging,
                source=extends["file"],
                seen=seen,
                depth=depth + 1,
            )


def _pre_resolution_gate(data: dict[str, Any], staging: Path) -> None:
    """Refuse raw-model constructs that make the resolver read host files.

    ``docker compose config`` resolves ``include``, ``extends`` and
    ``env_file`` by READING the referenced files. The gate walks the FULL
    resolution graph — the primary document plus every (transitively)
    ``extends``-referenced document — and confines each file reference to
    the staging dir, refusing otherwise (fail closed). The sandboxed
    resolver invocation is the kernel-level backstop for anything this
    parser-level walk misses.
    """
    _gate_document(
        data, staging, source="the primary compose file", seen=set(), depth=0
    )


#: Static generic PATH for the resolver — the real PATH would leak the
#: host tool layout through ``${PATH}`` interpolation.
_RESOLVER_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"
_RESOLVER_TIMEOUT_S = 60.0


def _resolver_env(staging: Path) -> dict[str, str]:
    """Minimal environment for the ``compose config`` resolution step.

    Interpolation reads THIS environment — a hostile compose file's
    ``${HOME}``/``${PATH}``/``${DOCKER_HOST}`` would otherwise inline the
    launcher's allowlisted process env into the resolved model and ship
    it into the container. Only a static generic PATH plus a throwaway
    HOME/DOCKER_CONFIG inside staging are provided: unset variables
    interpolate to empty (compose semantics, with a compose-side
    warning); ``${VAR:?}`` forms make resolution fail, which refuses the
    stack (fail closed). ``build``/``up``/``ps``/``down`` keep the normal
    allowlisted docker env — the sanitized file they consume contains no
    live interpolation (``$`` survives only ``$$``-escaped).
    """
    scratch = staging / ".raptor-resolver-home"
    scratch.mkdir(exist_ok=True)
    return {
        "PATH": _RESOLVER_PATH,
        "HOME": str(scratch),
        "DOCKER_CONFIG": str(scratch / ".docker"),
    }


def _run_resolver(argv: list[str], staging: Path, env: dict[str, str]) -> str:
    """Run the resolver, sandboxed with reads confined to staging.

    The resolver invocation is itself attack surface — it follows file
    references in hostile YAML — so it runs under ``core.sandbox`` with
    ``restrict_reads`` scoped to the staging dir: an out-of-staging read
    the parser-level gate missed fails at the kernel. When the sandbox
    cannot ENGAGE (unsupported host), resolution proceeds unconfined
    with the recursive pre-gate as the remaining defense (logged loudly).
    A non-zero exit INSIDE the sandbox is a resolution failure and
    refuses the stack — it is never retried unconfined.
    """
    try:
        from core.sandbox import SandboxSetupError
        from core.sandbox import run as sandbox_run
    except ImportError:  # pragma: no cover — core.sandbox always ships
        sandbox_run = None
        SandboxSetupError = Exception  # noqa: N806
    if sandbox_run is not None:
        try:
            proc = sandbox_run(
                argv,
                block_network=True,
                target=str(staging),
                restrict_reads=True,
                # The resolver has no business reading host-identity
                # files: swap the wholesale /etc read grant for the
                # loader/TLS minimum. This holds on the Landlock-only
                # tier too, where no private mount view narrows /etc.
                omit_etc_reads=True,
                cwd=str(staging),
                env=env,
                # The env is CONSTRUCTED minimal (static PATH + throwaway
                # HOME/DOCKER_CONFIG), not a passthrough of process env.
                env_caller_filtered=True,
                capture_output=True,
                text=True,
                timeout=_RESOLVER_TIMEOUT_S,
                caller_label="compose-config-resolve",
            )
        except SandboxSetupError as exc:
            logger.warning(
                "compose resolver sandbox could not engage (%s); resolving "
                "unconfined — the staged-graph pre-gate remains the read "
                "boundary", exc,
            )
        except subprocess.TimeoutExpired as exc:
            raise ComposeError(
                f"compose config timed out after {_RESOLVER_TIMEOUT_S}s",
                stderr=str(exc),
            ) from exc
        else:
            # The sandbox ENGAGED but may have fallen back from the
            # mount-ns tier to Landlock-only mid-setup (uid-mapping
            # failure, missing helpers). The read boundary then loses
            # the private mount view — surface the degraded tier
            # instead of letting the fallback stay silent. Not a
            # refusal: the recursive pre-gate stays the primary
            # defense and Landlock still confines reads.
            degraded = getattr(proc, "sandbox_info", {}).get(
                "mount_ns_degraded")
            if degraded:
                logger.warning(
                    "compose resolver sandbox degraded from mount-ns to "
                    "the Landlock-only tier (%s) — read confinement is "
                    "kernel-enforced but has no private mount view for "
                    "this resolution", degraded,
                )
            if proc.returncode != 0:
                stderr = (proc.stderr or "").strip()
                raise ComposeError(
                    f"compose config failed (rc={proc.returncode}): {stderr}",
                    stderr=stderr,
                )
            return proc.stdout or ""
    outcome = run_cli(
        argv, timeout=_RESOLVER_TIMEOUT_S, cwd=str(staging), env=env,
    )
    if outcome.timed_out:
        msg = f"compose config timed out after {_RESOLVER_TIMEOUT_S}s"
        raise ComposeError(msg, stderr=outcome.stderr)
    if outcome.returncode != 0:
        stderr = (outcome.stderr or "").strip()
        raise ComposeError(
            f"compose config failed (rc={outcome.returncode}): {stderr}",
            stderr=stderr,
        )
    return outcome.stdout or ""


def _resolve_effective_model(compose_file: Path) -> dict[str, Any]:
    """Resolve the FULL effective service model via ``compose config``.

    Interpolation (``${VAR:-default}``), ``extends``, YAML anchors/merges,
    ``.env`` and profile gating are applied by compose itself — the
    sanitizer then operates on what ``up`` would actually run instead of
    the raw text. The step runs with a minimal interpolation environment
    (:func:`_resolver_env`) and, where the host supports it, inside a
    read-confined sandbox (:func:`_run_resolver`). Resolution failure
    raises :class:`ComposeError` (fail closed): a stack the resolver
    cannot vouch for never launches.
    """
    staging = compose_file.parent
    prefix = _compose_invocation()
    raw = _run_resolver(
        [*prefix, "-f", str(compose_file), "config"],
        staging,
        _resolver_env(staging),
    )
    try:
        data = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        raise ComposeError(
            f"compose config output for {compose_file} did not parse: {exc}",
            stderr=str(exc),
        ) from exc
    if not isinstance(data, dict):
        msg = f"compose config output for {compose_file} is not a mapping"
        raise ComposeError(msg)
    return data


def _filter_volumes(volumes: list[Any], staging: Path) -> list[Any]:
    """Allowlist-filter a service ``volumes:`` list.

    Kept: named/anonymous volumes, ``tmpfs`` mounts, and bind mounts whose
    SOURCE resolves (symlinks followed) inside the staging dir. Everything
    else — absolute host paths (``/etc``), non-canonical evasions
    (``/var/../var/run``), ``~`` expansions, npipe/cluster types — is
    dropped. The old docker-socket blocklist is subsumed: a host bind is
    dropped for not living under staging, whatever its suffix.
    """
    staging_real = staging.resolve()
    prefix = str(staging_real) + os.sep

    def _bind_source_ok(source: str) -> bool:
        source = source.strip()
        if not source or source.startswith("~"):
            return False
        if source.startswith("/"):
            resolved = os.path.realpath(source)
        else:
            resolved = os.path.realpath(os.path.join(staging_real, source))
        return resolved == str(staging_real) or resolved.startswith(prefix)

    kept: list[Any] = []
    for vol in volumes:
        if isinstance(vol, str):
            if _mounts_docker_socket(vol):
                logger.warning("compose sanitize: dropping volume %r", vol)
                continue
            parts = vol.split(":")
            if len(parts) == 1:
                kept.append(vol)  # anonymous volume, container path only
                continue
            source = parts[0].strip()
            if source.startswith(("/", ".", "~")):
                if _bind_source_ok(source):
                    kept.append(vol)
                else:
                    logger.warning(
                        "compose sanitize: dropping host bind %r", vol)
            else:
                kept.append(vol)  # named volume
        elif isinstance(vol, dict):
            vtype = str(vol.get("type") or "volume")
            if vtype in ("volume", "tmpfs"):
                if _mounts_docker_socket(vol):
                    logger.warning("compose sanitize: dropping volume %r", vol)
                    continue
                kept.append(vol)
            elif vtype == "bind":
                source = str(vol.get("source") or "")
                if _bind_source_ok(source):
                    kept.append(vol)
                else:
                    logger.warning(
                        "compose sanitize: dropping host bind %r", vol)
            else:
                logger.warning(
                    "compose sanitize: dropping %s mount %r", vtype, vol)
        # non-str/dict entries dropped
    return kept


def _sanitize_build(build: Any, staging: Path, *, service: str) -> dict[str, Any]:
    """Confine a service ``build:`` block to the staging dir.

    ``docker compose build`` tars the context to the daemon — an absolute
    (``/home/user``) or escaping (``../../..``) context ships that host
    directory into an image the hostile stack then reads. Context and
    dockerfile must resolve inside staging; URLs, ``additional_contexts``
    and out-of-staging paths are REFUSED (an explicit host-directory
    request is hostile or broken — refusal beats silent rewriting).
    """
    if isinstance(build, str):
        build = {"context": build}
    if not isinstance(build, dict):
        raise ComposeError(
            f"compose service {service!r} build block is not a mapping")
    if "additional_contexts" in build:
        raise ComposeError(
            f"compose service {service!r} uses build.additional_contexts — "
            "refusing (extra contexts bypass staging confinement)"
        )
    staging_real = staging.resolve()
    prefix = str(staging_real) + os.sep
    context = str(build.get("context") or ".")
    if "://" in context or context.startswith("git@"):
        raise ComposeError(
            f"compose service {service!r} build context {context!r} is a "
            "URL — refusing (remote contexts bypass staging confinement)"
        )
    if context.startswith("/"):
        context_real = os.path.realpath(context)
    else:
        context_real = os.path.realpath(os.path.join(staging_real, context))
    if context_real != str(staging_real) and not context_real.startswith(prefix):
        raise ComposeError(
            f"compose service {service!r} build context {context!r} escapes "
            "the staging dir — refusing"
        )
    out: dict[str, Any] = {
        k: v for k, v in build.items() if k in _BUILD_ALLOWED_KEYS
    }
    dropped = sorted(set(build) - set(out))
    if dropped:
        logger.warning(
            "compose sanitize: dropping build key(s) %s from service %r",
            ", ".join(dropped), service,
        )
    out["context"] = context
    if "dockerfile_inline" in out:
        out.pop("dockerfile", None)
    elif "dockerfile" in out:
        dockerfile = str(out["dockerfile"])
        if dockerfile.startswith("/"):
            df_real = os.path.realpath(dockerfile)
        else:
            df_real = os.path.realpath(os.path.join(context_real, dockerfile))
        if not df_real.startswith(prefix):
            raise ComposeError(
                f"compose service {service!r} dockerfile {dockerfile!r} "
                "escapes the staging dir — refusing"
            )
    return out


def _sanitize_cap_add(cap_add: Any) -> list[str]:
    """Normalize (``CAP_`` prefix stripped, upper-cased) and allowlist."""
    if not isinstance(cap_add, list):
        return []
    kept: list[str] = []
    for cap in cap_add:
        norm = str(cap).strip().upper()
        if norm.startswith("CAP_"):
            norm = norm[4:]
        if norm in _SAFE_CAP_ADD:
            kept.append(norm)
        else:
            logger.warning("compose sanitize: dropping cap_add %r", cap)
    return kept


def _sanitize_environment(env: Any) -> Any:
    """Drop pass-through (null-valued) environment entries.

    ``environment: [FOO]`` / ``FOO:`` (no value) makes compose forward the
    launcher's own environment variable into the hostile container at
    ``up`` time; only explicit values survive.
    """
    if isinstance(env, dict):
        return {k: v for k, v in env.items() if v is not None}
    if isinstance(env, list):
        return [e for e in env if isinstance(e, str) and "=" in e]
    return env


def _sanitize_service(
    name: str,
    spec: dict[str, Any],
    staging: Path,
    *,
    labels: dict[str, str] | None,
    allow_devices: bool,
) -> dict[str, Any]:
    """Rebuild one RESOLVED service spec from the key allowlist."""
    out: dict[str, Any] = {
        k: v for k, v in spec.items() if k in _SERVICE_ALLOWED_KEYS
    }

    # User-supplied labels are inert metadata — keep them; the caller's
    # labels are merged on top below (caller wins on collision).
    if isinstance(spec.get("labels"), (dict, list)):
        out["labels"] = spec["labels"]

    container_ports = _extract_container_ports(spec)
    if container_ports:
        unique = list(dict.fromkeys(container_ports))
        if len(unique) > _MAX_PORTS_PER_SERVICE:
            logger.warning(
                "compose sanitize: service %r publishes %d ports; keeping "
                "the first %d", name, len(unique), _MAX_PORTS_PER_SERVICE,
            )
            unique = unique[:_MAX_PORTS_PER_SERVICE]
        out["ports"] = [f"127.0.0.1:0:{port}" for port in unique]

    if "environment" in spec:
        cleaned_env = _sanitize_environment(spec["environment"])
        if cleaned_env:
            out["environment"] = cleaned_env

    volumes = spec.get("volumes")
    if isinstance(volumes, list):
        kept_volumes = _filter_volumes(volumes, staging)
        if kept_volumes:
            out["volumes"] = kept_volumes

    if "build" in spec:
        out["build"] = _sanitize_build(spec["build"], staging, service=name)

    caps = _sanitize_cap_add(spec.get("cap_add"))
    if caps:
        out["cap_add"] = caps

    # network_mode/ipc/pid: safe values only; host/container: forms die
    # here. "bridge"/"default" are NOT kept — they would detach the
    # service from the project's internal network onto the masqueraded
    # default bridge (full egress).
    net_mode = spec.get("network_mode")
    if isinstance(net_mode, str) and net_mode == "none":
        out["network_mode"] = net_mode
    ipc = spec.get("ipc")
    if isinstance(ipc, str) and (
        ipc in ("private", "shareable") or ipc.startswith("service:")
    ):
        out["ipc"] = ipc
    pid = spec.get("pid")
    if isinstance(pid, str) and pid.startswith("service:"):
        out["pid"] = pid

    devices = spec.get("devices")
    if isinstance(devices, list) and devices:
        probe = {"devices": list(devices)}
        _filter_devices(probe, allow_all=allow_devices)
        if probe.get("devices"):
            out["devices"] = probe["devices"]

    # extra_hosts: keep plain host:ip entries, drop host-gateway mappings —
    # "hostgw:host-gateway" hands the container a stable name for the
    # bridge gateway, sweetening host-service reachability.
    extra_hosts = spec.get("extra_hosts")
    kept_hosts: Any = None
    if isinstance(extra_hosts, list):
        kept_hosts = [
            e for e in extra_hosts
            if not (isinstance(e, str) and "host-gateway" in e)
        ]
    elif isinstance(extra_hosts, dict):
        kept_hosts = {
            k: v for k, v in extra_hosts.items()
            if "host-gateway" not in str(v)
        }
    if kept_hosts is not None:
        if len(kept_hosts) != len(extra_hosts):
            logger.warning(
                "compose sanitize: dropping host-gateway extra_hosts "
                "entr%s from service %r",
                "y" if len(extra_hosts) - len(kept_hosts) == 1 else "ies",
                name,
            )
        if kept_hosts:
            out["extra_hosts"] = kept_hosts

    dropped = sorted(set(spec) - set(out) - {"ports", "deploy"})
    if dropped:
        logger.warning(
            "compose sanitize: dropping key(s) %s from service %r",
            ", ".join(dropped), name,
        )

    # Single-container-parity resource limits — the compose path must not
    # be the unlimited path (containers.py enforces the same values).
    out.update(_SERVICE_LIMITS)

    if labels:
        inject_labels(out, labels=labels)
    return out


def _sanitize_volume_defs(defs: Any) -> dict[str, Any]:
    """Top-level ``volumes:`` — keep bare named volumes (labels only).

    ``driver_opts`` (the ``type: none / o: bind / device: /host/path``
    escape), ``external`` (mounts pre-existing host volumes) and custom
    drivers are dropped; compose then creates a plain project-scoped volume.
    """
    out: dict[str, Any] = {}
    if not isinstance(defs, dict):
        return out
    for name, definition in defs.items():
        cleaned: dict[str, Any] = {}
        if isinstance(definition, dict):
            if isinstance(definition.get("labels"), (dict, list)):
                cleaned["labels"] = definition["labels"]
            dropped = sorted(set(definition) - set(cleaned))
            if dropped:
                logger.warning(
                    "compose sanitize: dropping volume-definition key(s) %s "
                    "from %r", ", ".join(dropped), name,
                )
        out[str(name)] = cleaned or None
    return out


def _sanitize_network_defs(defs: Any) -> dict[str, Any]:
    """Top-level ``networks:`` — internal project-scoped bridges only.

    ``external``/``name`` (attachment to pre-existing networks, including
    the literal host network), non-bridge drivers, ``driver_opts`` and
    ``ipam`` (hostile subnet choices can shadow host routes) are dropped,
    and EVERY definition is forced ``internal: true`` — a hostile stack
    runs with no routed egress (see :func:`_sanitize_model`).
    """
    out: dict[str, Any] = {}
    if not isinstance(defs, dict):
        return out
    for name, definition in defs.items():
        cleaned: dict[str, Any] = {"internal": True}
        if isinstance(definition, dict):
            if isinstance(definition.get("labels"), (dict, list)):
                cleaned["labels"] = definition["labels"]
            if definition.get("driver") == "bridge":
                cleaned["driver"] = "bridge"
            dropped = sorted(set(definition) - set(cleaned) - {"internal"})
            if dropped:
                logger.warning(
                    "compose sanitize: dropping network-definition key(s) %s "
                    "from %r", ", ".join(dropped), name,
                )
        out[str(name)] = cleaned
    return out


def _sanitize_file_source_defs(
    defs: Any, staging: Path, *, what: str
) -> dict[str, Any]:
    """Top-level ``configs:``/``secrets:`` — staging-confined files only.

    ``external`` and ``environment`` sources are refused (they read
    pre-existing host state into the stack); ``file`` sources must resolve
    inside the staging dir. Inline ``content`` is fine — it came from the
    compose file itself.
    """
    out: dict[str, Any] = {}
    if not isinstance(defs, dict):
        return out
    staging_real = staging.resolve()
    prefix = str(staging_real) + os.sep
    for name, definition in defs.items():
        if not isinstance(definition, dict):
            raise ComposeError(f"compose {what} {name!r} is not a mapping")
        if definition.get("external"):
            raise ComposeError(
                f"compose {what} {name!r} is external — refusing")
        if "environment" in definition:
            raise ComposeError(
                f"compose {what} {name!r} reads a launcher environment "
                "variable — refusing"
            )
        cleaned: dict[str, Any] = {}
        if "content" in definition:
            cleaned["content"] = definition["content"]
        elif "file" in definition:
            file_ref = str(definition["file"])
            if file_ref.startswith("~"):
                raise ComposeError(
                    f"compose {what} {name!r} file {file_ref!r} references "
                    "a home path — refusing"
                )
            if file_ref.startswith("/"):
                resolved = os.path.realpath(file_ref)
            else:
                resolved = os.path.realpath(
                    os.path.join(staging_real, file_ref))
            if not resolved.startswith(prefix):
                raise ComposeError(
                    f"compose {what} {name!r} file {file_ref!r} escapes the "
                    "staging dir — refusing"
                )
            cleaned["file"] = file_ref
        else:
            raise ComposeError(
                f"compose {what} {name!r} has no file/content source — "
                "refusing"
            )
        out[str(name)] = cleaned
    return out


def _sanitize_model(
    data: dict[str, Any],
    staging: Path,
    *,
    labels: dict[str, str] | None,
    allow_devices: bool,
) -> dict[str, Any]:
    """Rebuild the RESOLVED compose model from allowlists (see module doc)."""
    services = data.get("services")
    if not isinstance(services, dict) or not services:
        msg = "resolved compose model has no 'services' mapping"
        raise ComposeError(msg)
    if len(services) > _MAX_SERVICES:
        raise ComposeError(
            f"compose stack declares {len(services)} services — exceeds the "
            f"cap of {_MAX_SERVICES}; refusing"
        )
    out: dict[str, Any] = {}
    if isinstance(data.get("name"), str):
        out["name"] = data["name"]
    out["services"] = {}
    for name, spec in services.items():
        if not isinstance(spec, dict):
            raise ComposeError(
                f"compose service {name!r} is not a mapping — refusing")
        out["services"][str(name)] = _sanitize_service(
            str(name), spec, staging,
            labels=labels, allow_devices=allow_devices,
        )
    if "volumes" in data:
        out["volumes"] = _sanitize_volume_defs(data["volumes"])
    # Egress isolation: every stack network — including the implicit
    # project default — is forced ``internal: true``. Routed egress
    # (LAN / cloud-metadata / Internet) dies; inter-service traffic and
    # the host->container-IP verify path keep working. Known residual,
    # stated rather than oversold: the host itself stays reachable at
    # the network's bridge gateway address, so host services bound on
    # 0.0.0.0 (including docker-proxy listeners other tools published
    # on 0.0.0.0) are reachable from inside; loopback-bound host
    # services are not. Closing that requires host-level firewall
    # authority (a DOCKER-USER rule) RAPTOR does not own.
    out["networks"] = _sanitize_network_defs(data.get("networks") or {})
    out["networks"].setdefault("default", {"internal": True})
    for section in ("configs", "secrets"):
        if section in data:
            out[section] = _sanitize_file_source_defs(
                data[section], staging, what=section)
    dropped = sorted(
        set(data) - set(out) - {"version"}
    )
    if dropped:
        logger.warning(
            "compose sanitize: dropping top-level key(s) %s",
            ", ".join(dropped),
        )
    return out


def _rewrite_ports_in_place(
    compose_file: Path, *, labels: dict[str, str] | None = None,
    allow_devices: bool = False,
) -> None:
    """Resolve + sanitize ``compose_file`` in place (see module docstring).

    Three stages, each fail-closed:

    1. Raw pre-gate: refuse constructs that would make the resolver read
       files outside the staging dir (``include``, out-of-staging
       ``extends.file``/``env_file``, interpolated path references).
    2. Resolution: ``docker compose config`` produces the FULL effective
       service model — interpolation, ``extends``, anchors and ``.env``
       applied. Sanitizing the raw text instead would let
       ``privileged: ${X:-true}``-style constructs ride through to ``up``.
    3. Allowlist sanitize: every service is REBUILT from known-safe keys;
       ports become ``127.0.0.1:0:<target>``, bind sources and build
       contexts are confined to staging, resource limits are injected.
    """
    # The primary document gets the same size budget as every gated
    # extends/env_file target — without it, a multi-GiB compose file in
    # a hostile repo is a memory DoS on the sanitizer process.
    try:
        raw = _load_gated_document(compose_file, what="file")
    except ComposeError as exc:
        msg = f"cannot parse compose file {compose_file} for security rewrite: {exc}"
        raise ComposeError(
            msg,
            stderr=str(exc),
        ) from exc
    if not isinstance(raw, dict):
        msg = f"compose file {compose_file} did not parse as a YAML mapping"
        raise ComposeError(msg)
    if not isinstance(raw.get("services"), dict):
        msg = f"compose file {compose_file} has no 'services' mapping"
        raise ComposeError(msg)
    staging = compose_file.parent
    _pre_resolution_gate(raw, staging)
    resolved = _resolve_effective_model(compose_file)
    sanitized = _sanitize_model(
        resolved, staging, labels=labels, allow_devices=allow_devices)
    compose_file.write_text(
        yaml.safe_dump(sanitized, sort_keys=False), encoding="utf-8")


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
    # Sanitized stacks run on internal (no-egress) networks where port
    # publishing is unavailable — the reachable endpoint is then the
    # container's own network address (the host holds the bridge-side
    # interface). Resolve it per unpublished container, best-effort.
    containers = tuple(
        _with_container_endpoint(c) if c.host_port is None else c
        for c in containers
    )
    primary = pick_primary(containers)
    return containers, primary


def _with_container_endpoint(container: ComposeContainer) -> ComposeContainer:
    """Fill an unpublished container's endpoint from ``docker inspect``.

    Returns the container unchanged when no address or exposed port can
    be determined (callers treat a port-less container as non-primary).
    """
    outcome = run_cli(
        [
            "docker", "inspect", "--format",
            '{"nets":{{json .NetworkSettings.Networks}},'
            '"exposed":{{json .Config.ExposedPorts}}}',
            container.container_id,
        ],
        timeout=10.0,
    )
    if outcome.returncode != 0 or not (outcome.stdout or "").strip():
        return container
    try:
        info = json.loads(outcome.stdout)
    except json.JSONDecodeError:
        return container
    if not isinstance(info, dict):
        return container
    ip = ""
    nets = info.get("nets")
    if isinstance(nets, dict):
        for net in nets.values():
            candidate = (net or {}).get("IPAddress") if isinstance(net, dict) else ""
            if candidate:
                ip = str(candidate)
                break
    ports: list[int] = []
    exposed = info.get("exposed")
    if isinstance(exposed, dict):
        for spec in exposed:
            head = str(spec).split("/", 1)[0]
            try:
                port = int(head)
            except ValueError:
                continue
            if 0 < port < 65536:
                ports.append(port)
    if not ip or not ports:
        return container
    preferred = [p for p in ports if p in _PREFERRED_CONTAINER_PORTS]
    port = preferred[0] if preferred else min(ports)
    return ComposeContainer(
        service=container.service,
        container_id=container.container_id,
        host_port=port,
        container_port=port,
        host_ip=ip,
    )


def down_stack(
    project_name: str,
    compose_file: Path,
    *,
    timeout_seconds: float = 120.0,
) -> None:
    """``docker compose down -v --remove-orphans``. Best-effort; never raises.

    ``--timeout 30`` bounds each container's stop grace so a
    SIGTERM-ignoring entrypoint cannot hold the stack (and its volumes
    and networks — ``-v`` runs only when ``down`` completes) alive past
    teardown.
    """
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
                "--timeout",
                "30",
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


