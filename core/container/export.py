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

#: Refuse to export images whose daemon-reported flattened size exceeds
#: this — the export tar + extracted rootfs are two more full host-disk
#: copies of a registry-supplied (attacker-influenced) image.
DEFAULT_MAX_IMAGE_BYTES = 8 << 30  # 8 GiB
#: Extraction quotas: cumulative header-declared bytes and member count.
DEFAULT_MAX_ROOTFS_BYTES = 8 << 30  # 8 GiB
DEFAULT_MAX_ROOTFS_ENTRIES = 400_000
#: Above this skipped-member fraction the rootfs is flagged degraded.
_DEGRADED_SKIP_RATIO = 0.05


class RootfsQuotaExceeded(RuntimeError):
    """Raised when rootfs extraction exceeds its byte/entry quota."""


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
    config: ImageRuntimeConfig | None = None
    reason: str = ""  # "" | create_failed | export_failed | inspect_failed |
    #                   extract_failed | quota_exceeded
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


def extract_rootfs_tar(
    tar_path: str | Path,
    dest_dir: str | Path,
    *,
    max_total_bytes: int = DEFAULT_MAX_ROOTFS_BYTES,
    max_entry_count: int = DEFAULT_MAX_ROOTFS_ENTRIES,
) -> tuple[int, int]:
    """Extract an image-export tarball into ``dest_dir`` safely.

    Returns ``(extracted, skipped)``. Members PEP 706's ``data`` filter
    refuses (device nodes, absolute paths, traversal, unsafe links) are
    skipped and counted — never trusted. Cumulative header-declared
    bytes and member count are quota-checked BEFORE each extract (a
    hostile image must not fill host disk/inodes mid-walk); breach
    raises :class:`RootfsQuotaExceeded`. Raises ``tarfile.TarError`` /
    ``OSError`` only for whole-archive failures.
    """
    dest = Path(dest_dir)
    dest.mkdir(parents=True, exist_ok=True)
    extracted = 0
    skipped = 0
    total_bytes = 0
    with tarfile.open(tar_path) as tf:
        for count, member in enumerate(tf, start=1):
            if count > max_entry_count:
                raise RootfsQuotaExceeded(
                    f"rootfs tar exceeds {max_entry_count} entries; refusing")
            total_bytes += member.size
            if total_bytes > max_total_bytes:
                raise RootfsQuotaExceeded(
                    f"rootfs tar exceeds {max_total_bytes} bytes; refusing")
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


def _image_size_bytes(inspect_json: str) -> int | None:
    """Daemon-reported flattened image size from ``docker image inspect``."""
    try:
        data = json.loads(inspect_json)
    except json.JSONDecodeError:
        return None
    if isinstance(data, list):
        data = data[0] if data else None
    if not isinstance(data, dict):
        return None
    size = data.get("Size")
    return size if isinstance(size, int) else None


def export_rootfs(
    image_ref: str,
    dest_dir: str | Path,
    *,
    platform: str | None = None,
    timeout_seconds: float = _EXPORT_TIMEOUT_S,
    max_image_bytes: int = DEFAULT_MAX_IMAGE_BYTES,
    max_rootfs_bytes: int = DEFAULT_MAX_ROOTFS_BYTES,
    max_rootfs_entries: int = DEFAULT_MAX_ROOTFS_ENTRIES,
) -> ExportOutcome:
    """Flatten ``image_ref`` into ``dest_dir`` and read its runtime config.

    ``docker create`` pulls the image when absent (bounded by
    ``timeout_seconds``); the throwaway container is removed on every
    path. The resulting directory is the sacrificial writable upper
    layer for ``sandbox(rootfs=...)`` runs — treat it as consumed after
    the environment runs.

    Quotas: the daemon-reported image size is gated BEFORE ``docker
    export`` writes a host-tmp tar copy (``max_image_bytes``), and the
    extraction walk is byte/entry-bounded (``max_rootfs_bytes`` /
    ``max_rootfs_entries``) — a hostile image must not fill host
    disk/inodes during witness-tier export. Extraction counts land in
    ``extras`` (``rootfs_extracted``/``rootfs_skipped``); a rootfs
    where nothing extracted FAILS instead of silently feeding the
    sandbox tier an empty tree, and a high skip ratio is flagged
    ``rootfs_degraded``.
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
        image_size = _image_size_bytes(inspect.stdout)
        if image_size is not None and image_size > max_image_bytes:
            return ExportOutcome(
                ok=False,
                reason="quota_exceeded",
                reason_class="unknown",
                stderr=(
                    f"image size {image_size} bytes exceeds the "
                    f"{max_image_bytes}-byte export quota; refusing"
                ),
                extras={"image_size": image_size},
            )

        # Stage the tar NEXT TO the destination, not in the default
        # temp dir: the flattened image can be many GB, and on hosts
        # where /tmp is a tmpfs a handful of concurrent exports
        # exhausts it (observed live: multiple AFL++-image exports
        # filled a 248G tmpfs). dest_dir's filesystem must hold the
        # unpacked rootfs anyway, so it can hold the tar first.
        staging_dir = Path(dest_dir).parent
        staging_dir.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(prefix="raptor-rootfs-",
                                         suffix=".tar",
                                         dir=str(staging_dir),
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

        try:
            extracted, skipped = extract_rootfs_tar(
                tar_path, dest_dir,
                max_total_bytes=max_rootfs_bytes,
                max_entry_count=max_rootfs_entries,
            )
        except RootfsQuotaExceeded as exc:
            return ExportOutcome(
                ok=False,
                reason="quota_exceeded",
                reason_class="unknown",
                stderr=str(exc)[:400],
            )
        except (tarfile.TarError, OSError) as exc:
            return ExportOutcome(
                ok=False,
                reason="extract_failed",
                reason_class="unknown",
                stderr=str(exc)[:400],
            )
        extras: dict[str, Any] = {
            "rootfs_extracted": extracted,
            "rootfs_skipped": skipped,
        }
        if extracted == 0:
            return ExportOutcome(
                ok=False,
                reason="extract_failed",
                reason_class="unknown",
                stderr="rootfs extraction produced no files — refusing to "
                       "run the sandbox tier on an empty tree",
                extras=extras,
            )
        if skipped > extracted * _DEGRADED_SKIP_RATIO:
            extras["rootfs_degraded"] = True
            logger.warning(
                "rootfs export of %s: %d/%d members skipped — tree flagged "
                "degraded", image_ref, skipped, extracted + skipped,
            )
        return ExportOutcome(ok=True, config=config, extras=extras)
    finally:
        run_cli(["docker", "rm", "-f", cid], timeout=30)
        if tar_path is not None:
            try:
                tar_path.unlink(missing_ok=True)
            except OSError:
                pass
