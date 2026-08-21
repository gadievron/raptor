"""Export a container image to an on-disk rootfs + runtime config.

The bridge from product mode to witness mode: ``docker create`` +
``docker export`` flatten an image into one filesystem tree, and
``docker image inspect`` yields the runtime config (env, entrypoint,
cmd, workdir, user, exposed ports). The pair is exactly what the
sandbox rootfs mode consumes — the environment then runs under
namespace isolation with witness-grade observability instead of under
the host daemon.

Extraction treats the tarball as ATTACKER-INFLUENCED (images come from
registries): members are extracted under PEP 706's ``data`` filter
(absolute paths, traversal, unsafe links refused), and members the
filter rejects — device nodes, setuid oddities — are SKIPPED and
counted rather than trusted. An image that needs real device nodes
gets them from the sandbox's per-namespace /dev anyway.
"""

from __future__ import annotations

import json
import logging
import tarfile
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from core.container.failures import classify_docker_stderr
from core.container.proc import run_cli

logger = logging.getLogger(__name__)

_EXPORT_TIMEOUT_S = 600.0
_INSPECT_TIMEOUT_S = 30.0


@dataclass(frozen=True)
class ImageRuntimeConfig:
    """The runtime half of an image: how it expects to be started."""

    env: tuple[str, ...] = ()          # "KEY=value" strings as shipped
    entrypoint: tuple[str, ...] = ()
    cmd: tuple[str, ...] = ()
    workdir: str = ""
    user: str = ""
    exposed_ports: tuple[int, ...] = ()

    def argv(self) -> list[str]:
        """The effective start command (entrypoint + cmd)."""
        return [*self.entrypoint, *self.cmd]


@dataclass
class ExportOutcome:
    ok: bool
    rootfs_dir: str = ""
    config: ImageRuntimeConfig | None = None
    members_extracted: int = 0
    members_skipped: int = 0
    reason: str = ""  # "" | create_failed | export_failed | inspect_failed |
    #                   extract_failed
    reason_class: str = "ok"
    stderr: str = ""
    extras: dict[str, Any] = field(default_factory=dict)


def parse_image_config(inspect_json: str) -> ImageRuntimeConfig | None:
    """Parse ``docker image inspect`` output into a runtime config."""
    try:
        data = json.loads(inspect_json)
    except json.JSONDecodeError:
        return None
    if isinstance(data, list):
        data = data[0] if data else None
    if not isinstance(data, dict):
        return None
    cfg = data.get("Config")
    if not isinstance(cfg, dict):
        return None

    def _tup(key: str) -> tuple[str, ...]:
        val = cfg.get(key)
        if isinstance(val, list):
            return tuple(str(x) for x in val)
        return ()

    ports: list[int] = []
    exposed = cfg.get("ExposedPorts")
    if isinstance(exposed, dict):
        for spec in exposed:
            head = str(spec).split("/", 1)[0]
            try:
                port = int(head)
            except ValueError:
                continue
            if 0 < port < 65536:
                ports.append(port)
    return ImageRuntimeConfig(
        env=_tup("Env"),
        entrypoint=_tup("Entrypoint"),
        cmd=_tup("Cmd"),
        workdir=str(cfg.get("WorkingDir") or ""),
        user=str(cfg.get("User") or ""),
        exposed_ports=tuple(sorted(ports)),
    )


def extract_rootfs_tar(tar_path: str | Path,
                       dest_dir: str | Path) -> tuple[int, int]:
    """Extract an image-export tarball into ``dest_dir`` safely.

    Returns ``(extracted, skipped)``. Members PEP 706's ``data`` filter
    refuses (device nodes, absolute paths, traversal, unsafe links) are
    skipped and counted — never trusted. Raises ``tarfile.TarError`` /
    ``OSError`` only for whole-archive failures.
    """
    dest = Path(dest_dir)
    dest.mkdir(parents=True, exist_ok=True)
    extracted = 0
    skipped = 0
    with tarfile.open(tar_path) as tf:
        for member in tf:
            try:
                tf.extract(member, dest, filter="data")
                extracted += 1
            except tarfile.FilterError:
                skipped += 1
            except OSError:
                # e.g. hardlink target skipped earlier, exotic perms.
                skipped += 1
    if skipped:
        logger.debug("rootfs extract: %d members skipped by the data filter",
                     skipped)
    return extracted, skipped


def export_rootfs(
    image_ref: str,
    dest_dir: str | Path,
    *,
    platform: str | None = None,
    timeout_seconds: float = _EXPORT_TIMEOUT_S,
) -> ExportOutcome:
    """Flatten ``image_ref`` into ``dest_dir`` and read its runtime config.

    ``docker create`` pulls the image when absent (bounded by
    ``timeout_seconds``); the throwaway container is removed on every
    path. The resulting directory is the sacrificial writable upper
    layer for ``sandbox(rootfs=...)`` runs — treat it as consumed after
    the environment runs.
    """
    create_cmd = ["docker", "create"]
    if platform:
        create_cmd.extend(["--platform", platform])
    create_cmd.append(image_ref)
    create = run_cli(create_cmd, timeout=timeout_seconds)
    if create.returncode != 0 or not create.stdout.strip():
        stderr = (create.stderr or "").strip()[-4000:]
        return ExportOutcome(
            ok=False,
            reason="create_failed",
            reason_class=("transport" if create.timed_out
                          else classify_docker_stderr(stderr)),
            stderr=stderr,
        )
    cid = create.stdout.strip()

    tar_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(prefix="raptor-rootfs-",
                                         suffix=".tar",
                                         delete=False) as fd:
            tar_path = Path(fd.name)
        export = run_cli(
            ["docker", "export", "-o", str(tar_path), cid],
            timeout=timeout_seconds,
        )
        if export.returncode != 0:
            return ExportOutcome(
                ok=False,
                reason="export_failed",
                reason_class=("transport" if export.timed_out
                              else classify_docker_stderr(export.stderr)),
                stderr=(export.stderr or "").strip()[-4000:],
            )

        inspect = run_cli(
            ["docker", "image", "inspect", image_ref],
            timeout=_INSPECT_TIMEOUT_S,
        )
        config = (parse_image_config(inspect.stdout)
                  if inspect.returncode == 0 else None)
        if config is None:
            return ExportOutcome(
                ok=False,
                reason="inspect_failed",
                reason_class="unknown",
                stderr=(inspect.stderr or "").strip()[-4000:],
            )

        try:
            extracted, skipped = extract_rootfs_tar(tar_path, dest_dir)
        except (tarfile.TarError, OSError) as exc:
            return ExportOutcome(
                ok=False,
                reason="extract_failed",
                reason_class="unknown",
                stderr=str(exc)[:400],
            )
        return ExportOutcome(
            ok=True,
            rootfs_dir=str(Path(dest_dir)),
            config=config,
            members_extracted=extracted,
            members_skipped=skipped,
        )
    finally:
        run_cli(["docker", "rm", "-f", cid], timeout=30)
        if tar_path is not None:
            try:
                tar_path.unlink(missing_ok=True)
            except OSError:
                pass
