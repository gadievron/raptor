"""RuntimeHandle — the seam between an environment and where it runs.

Five methods cover everything the verify engine and downstream
consumers need from a live environment. ``tier`` tags every outcome
with the runtime that produced it, so evidence consumers can weigh
docker-tier confirmations (product mode: the environment ran under the
host daemon) differently from sandbox-tier ones (witness mode:
namespace-isolated, syscall-observable).
"""

from __future__ import annotations

import inspect as _inspect
import shutil
import time
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

from core.container.containers import (
    container_logs_tail,
    inspect_state,
    stop_container,
)
from core.container.exec import ExecOutcome, classify_exec_exit, exec_in_container


class RuntimeHandle(ABC):
    """A live environment instance, wherever it runs."""

    #: Evidence tier: "docker" (product mode) or "sandbox" (witness mode).
    tier: str = "unknown"

    @abstractmethod
    def endpoint(self) -> tuple[str, int] | None:
        """``(host_ip, host_port)`` of the primary service surface, or
        None for environments with no network surface."""

    @abstractmethod
    def state(self) -> dict[str, Any]:
        """Instance state in the docker ``.State`` shape: ``Running``
        (bool), ``Status`` (str), ``ExitCode``, ``OOMKilled``.
        Failures fold into ``{"_error": reason}`` — never raises."""

    @abstractmethod
    def logs(self, tail: int = 500) -> str:
        """Last ``tail`` lines of instance output (stdout+stderr
        combined). Best-effort: "" on any failure."""

    @abstractmethod
    def exec(
        self,
        command: str,
        *,
        timeout_seconds: float = 30.0,
        workdir: str = "",
    ) -> ExecOutcome:
        """Run ``command`` (through ``sh -c``) inside the environment."""

    @abstractmethod
    def teardown(self) -> None:
        """Stop and remove the instance. Best-effort; never raises."""

    # Shared convenience -------------------------------------------------

    def running(self) -> bool:
        state = self.state()
        return bool(state.get("Running")) and state.get("Status") == "running"

    def wait_stable(self, seconds: float) -> bool:
        """Sleep, then report whether the instance is still running —
        catches slow-boot apps that respond briefly then crash-loop."""
        time.sleep(seconds)
        return self.running()


class DockerHandle(RuntimeHandle):
    """Product-tier handle: a container under the host docker daemon.

    ``owner_label`` (a ``(key, value)`` pair) gates exec and teardown —
    a handle constructed over an arbitrary container id refuses to
    touch containers its launcher didn't stamp.
    """

    tier = "docker"

    def __init__(
        self,
        container_id: str,
        *,
        host_ip: str = "127.0.0.1",
        host_port: int = 0,
        owner_label: tuple[str, str] | None = None,
    ) -> None:
        self.container_id = container_id
        self.host_ip = host_ip
        self.host_port = int(host_port or 0)
        self.owner_label = owner_label

    def __repr__(self) -> str:  # pragma: no cover — debug aid
        return (
            f"DockerHandle({self.container_id[:12]!r}, "
            f"endpoint={self.host_ip}:{self.host_port})"
        )

    def endpoint(self) -> tuple[str, int] | None:
        if not self.host_port:
            return None
        return (self.host_ip, self.host_port)

    def state(self) -> dict[str, Any]:
        return inspect_state(self.container_id)

    def logs(self, tail: int = 500) -> str:
        # Uncapped-by-bytes here (the verify log_check greps the text);
        # container_logs_tail's own cap is generous enough for `tail`
        # lines of typical service logs.
        return container_logs_tail(self.container_id, n=tail,
                                   max_bytes=1024 * 1024)

    def exec(
        self,
        command: str,
        *,
        timeout_seconds: float = 30.0,
        workdir: str = "",
    ) -> ExecOutcome:
        return exec_in_container(
            container_id=self.container_id,
            command=command,
            timeout_seconds=timeout_seconds,
            workdir=workdir,
            required_label=self.owner_label,
        )

    def teardown(self) -> None:
        stop_container(self.container_id, required_label=self.owner_label)


def sandbox_rootfs_supported() -> bool:
    """True when this tree's sandbox exposes the image-rootfs mode
    (``core.sandbox.run(rootfs=...)``). SandboxHandle refuses to
    construct without it — an exec that silently ran against the host
    filesystem would be a substrate violation, not a degradation."""
    try:
        from core.sandbox import run as sandbox_run
    except ImportError:  # pragma: no cover — core.sandbox always present
        return False
    return "rootfs" in _inspect.signature(sandbox_run).parameters


class SandboxHandle(RuntimeHandle):
    """Witness-tier handle: an unpacked image rootfs run under the
    RAPTOR sandbox (namespace isolation, fail-closed rootfs mode).

    Exec-oriented in this iteration: ``exec`` runs commands inside the
    image filesystem under full isolation (version assertions, local
    PoC probes, build steps), ``logs`` replays the accumulated exec
    output, and ``endpoint`` is None — the long-lived service surface
    (paired netns launch, published loopback port) arrives with the
    service-runner integration. Verify plans against this tier use
    exec/log checks.

    The rootfs directory is the environment's sacrificial writable
    upper layer; ``teardown`` deletes it.
    """

    tier = "sandbox"

    def __init__(
        self,
        rootfs: str | Path,
        *,
        env: dict[str, str] | None = None,
        workdir: str = "",
        block_network: bool = True,
    ) -> None:
        if not sandbox_rootfs_supported():
            msg = (
                "SandboxHandle requires the sandbox image-rootfs mode "
                "(core.sandbox.run(rootfs=...)), which this tree does "
                "not expose yet"
            )
            raise RuntimeError(msg)
        self.rootfs = Path(rootfs)
        if not self.rootfs.is_dir():
            msg = f"rootfs is not a directory: {rootfs}"
            raise ValueError(msg)
        self.env = dict(env or {})
        self.workdir = workdir
        self.block_network = block_network
        self._log_chunks: list[str] = []
        self._torn_down = False

    def endpoint(self) -> tuple[str, int] | None:
        return None

    def state(self) -> dict[str, Any]:
        alive = not self._torn_down and self.rootfs.is_dir()
        if alive:
            return {"Running": True, "Status": "running"}
        return {"Running": False, "Status": "exited", "ExitCode": 0,
                "OOMKilled": False}

    def logs(self, tail: int = 500) -> str:
        lines = "".join(self._log_chunks).splitlines()
        return "\n".join(lines[-tail:])

    def exec(
        self,
        command: str,
        *,
        timeout_seconds: float = 30.0,
        workdir: str = "",
    ) -> ExecOutcome:
        from core.sandbox import run as sandbox_run

        start = time.monotonic()
        argv = ["/bin/sh", "-c", command]
        try:
            result = sandbox_run(
                argv,
                rootfs=str(self.rootfs),
                block_network=self.block_network,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
                cwd=(workdir or self.workdir) or None,
                env=(dict(self.env) if self.env else None),
                # ``self.env`` merges the built container image's
                # config Env — every ENV line of an agent-authored
                # (target-influenceable) Dockerfile flows through here
                # verbatim. strict_env strips DANGEROUS_ENV_VARS
                # (LD_PRELOAD / LD_LIBRARY_PATH / DYLD_* / PYTHON*
                # loader vars) before the sandbox applies the dict, so
                # a hostile `ENV LD_PRELOAD=...` can never ride the
                # target env — and, on any future tier change, can
                # never reach a launcher exec. Rootfs runs are pinned
                # to the mount-ns tier by rootfs fail-closed gate #5
                # (context.py — spawn-setup failure raises
                # SandboxSetupError instead of degrading to the
                # host-filesystem path); this is the single-gate
                # reinforcement so the containment does not rest on
                # that gate alone. Images that legitimately set loader
                # vars in config Env lose them — accepted: loader vars
                # from an untrusted image are exactly the primitive
                # being removed. Residual: DANGEROUS_ENV_VARS is an
                # exact-name blocklist — loader-adjacent names outside
                # it (e.g. GCONV_PATH-class knobs) ride through; the
                # gate-#5 mount-ns pin remains the containment for
                # anything the list misses.
                strict_env=True,
            )
        except Exception as exc:  # noqa: BLE001 — outcome shape, not raise
            # SandboxSetupError is a BaseException and deliberately NOT
            # caught here: "isolation could not engage" must propagate.
            return ExecOutcome(
                ok=False,
                container_id=str(self.rootfs),
                command=command,
                exit_code=-1,
                stderr=str(exc)[:400],
                duration_s=time.monotonic() - start,
                reason=f"{type(exc).__name__}: {exc}",
                reason_class="unknown",
            )
        duration = time.monotonic() - start
        stdout = result.stdout or ""
        stderr = result.stderr or ""
        self._log_chunks.append(stdout)
        if stderr:
            self._log_chunks.append(stderr)
        exit_code = result.returncode
        ok = exit_code == 0
        return ExecOutcome(
            ok=ok,
            container_id=str(self.rootfs),
            command=command,
            exit_code=exit_code,
            stdout=stdout[-8192:],
            stderr=stderr[-4096:],
            duration_s=duration,
            reason="" if ok else f"exit_code={exit_code}",
            reason_class=classify_exec_exit(exit_code, stderr),
        )

    def teardown(self) -> None:
        self._torn_down = True
        shutil.rmtree(self.rootfs, ignore_errors=True)
