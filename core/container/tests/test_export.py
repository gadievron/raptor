"""Contract tests for core.container.export (docker intercepted /
pure parts exercised directly)."""

from __future__ import annotations

import io
import tarfile
from pathlib import Path
from typing import Any
from unittest.mock import patch

from core.container import export as ex
from core.container.proc import RunOutcome

_INSPECT = """[
  {"Config": {
    "Env": ["PATH=/usr/bin", "APP_KEY=x"],
    "Entrypoint": ["/docker-entrypoint.sh"],
    "Cmd": ["nginx", "-g", "daemon off;"],
    "WorkingDir": "/app",
    "User": "www-data",
    "ExposedPorts": {"80/tcp": {}, "443/tcp": {}, "bogus/tcp": {}}
  }}
]"""


def test_parse_image_config_full_shape() -> None:
    cfg = ex.parse_image_config(_INSPECT)
    assert cfg is not None
    assert cfg.env == ("PATH=/usr/bin", "APP_KEY=x")
    assert cfg.argv() == ["/docker-entrypoint.sh", "nginx", "-g",
                          "daemon off;"]
    assert cfg.workdir == "/app" and cfg.user == "www-data"
    assert cfg.exposed_ports == (80, 443)


def test_parse_image_config_tolerates_garbage() -> None:
    assert ex.parse_image_config("not json") is None
    assert ex.parse_image_config("[]") is None
    assert ex.parse_image_config('[{"Config": null}]') is None
    minimal = ex.parse_image_config('[{"Config": {}}]')
    assert minimal is not None and minimal.argv() == []


def _tar_with(members: list[tuple[tarfile.TarInfo, bytes | None]],
              path: Path) -> Path:
    with tarfile.open(path, "w") as tf:
        for info, data in members:
            tf.addfile(info, io.BytesIO(data) if data is not None else None)
    return path


def test_extract_skips_hostile_members(tmp_path: Path) -> None:
    """Traversal and device members are skipped, not trusted; benign
    files and in-tree symlinks extract."""
    good = tarfile.TarInfo("etc/os-release")
    payload = b"ID=test\n"
    good.size = len(payload)
    dirm = tarfile.TarInfo("etc")
    dirm.type = tarfile.DIRTYPE
    link = tarfile.TarInfo("etc/alias")
    link.type = tarfile.SYMTYPE
    link.linkname = "os-release"
    evil_traversal = tarfile.TarInfo("../../outside")
    evil_traversal.size = 1
    dev = tarfile.TarInfo("dev/sda")
    dev.type = tarfile.BLKTYPE

    tar = _tar_with([(dirm, None), (good, payload), (link, None),
                     (evil_traversal, b"x"), (dev, None)],
                    tmp_path / "img.tar")
    dest = tmp_path / "rootfs"
    extracted, skipped = ex.extract_rootfs_tar(tar, dest)
    assert (dest / "etc" / "os-release").read_bytes() == payload
    assert (dest / "etc" / "alias").is_symlink()
    assert not (tmp_path / "outside").exists()
    assert not (dest / "dev" / "sda").exists()
    assert extracted == 3 and skipped == 2


def test_export_rootfs_happy_path_and_cleanup(tmp_path: Path) -> None:
    tar = tmp_path / "canned.tar"
    info = tarfile.TarInfo("bin/init")
    info.size = 2
    _tar_with([(info, b"#!")], tar)
    captured: list[list[str]] = []

    def fake(cmd: list[str], **_kw: Any) -> RunOutcome:
        captured.append(list(cmd))
        if cmd[:2] == ["docker", "create"]:
            return RunOutcome(returncode=0, stdout="cid123\n", stderr="",
                              timed_out=False)
        if cmd[:2] == ["docker", "export"]:
            out_path = Path(cmd[cmd.index("-o") + 1])
            out_path.write_bytes(tar.read_bytes())
            return RunOutcome(returncode=0, stdout="", stderr="",
                              timed_out=False)
        if cmd[:3] == ["docker", "image", "inspect"]:
            return RunOutcome(returncode=0, stdout=_INSPECT, stderr="",
                              timed_out=False)
        return RunOutcome(returncode=0, stdout="", stderr="",
                          timed_out=False)

    dest = tmp_path / "rootfs"
    with patch.object(ex, "run_cli", side_effect=fake):
        outcome = ex.export_rootfs("nginx@sha256:" + "a" * 64, dest)
    assert outcome.ok, outcome.reason
    assert (dest / "bin" / "init").is_file()
    assert outcome.config is not None and outcome.config.workdir == "/app"
    assert ["docker", "rm", "-f", "cid123"] in captured  # throwaway removed


def test_export_rootfs_create_failure_classified(tmp_path: Path) -> None:
    def fake(cmd: list[str], **_kw: Any) -> RunOutcome:
        if cmd[:2] == ["docker", "create"]:
            return RunOutcome(returncode=1, stdout="",
                              stderr="manifest unknown", timed_out=False)
        return RunOutcome(returncode=0, stdout="", stderr="",
                          timed_out=False)

    with patch.object(ex, "run_cli", side_effect=fake):
        outcome = ex.export_rootfs("gone:1", tmp_path / "r")
    assert not outcome.ok
    assert outcome.reason == "create_failed"
    assert outcome.reason_class == "manifest_unknown"


def test_export_tar_staged_next_to_dest_not_default_tmp(
        tmp_path: Path) -> None:
    """The flattened-image tar (potentially many GB) must be staged on
    dest_dir's filesystem, never the default temp dir — on tmpfs /tmp
    hosts a few concurrent exports exhaust the mount (observed live).
    """
    tar = tmp_path / "canned.tar"
    info = tarfile.TarInfo("bin/init")
    info.size = 2
    _tar_with([(info, b"#!")], tar)
    tar_dests: list[Path] = []

    def fake(cmd: list[str], **_kw: Any) -> RunOutcome:
        if cmd[:2] == ["docker", "create"]:
            return RunOutcome(returncode=0, stdout="cid123\n", stderr="",
                              timed_out=False)
        if cmd[:2] == ["docker", "export"]:
            out_path = Path(cmd[cmd.index("-o") + 1])
            tar_dests.append(out_path)
            out_path.write_bytes(tar.read_bytes())
            return RunOutcome(returncode=0, stdout="", stderr="",
                              timed_out=False)
        if cmd[:3] == ["docker", "image", "inspect"]:
            return RunOutcome(returncode=0, stdout=_INSPECT, stderr="",
                              timed_out=False)
        return RunOutcome(returncode=0, stdout="", stderr="",
                          timed_out=False)

    dest = tmp_path / "deep" / "run" / "rootfs"
    with patch.object(ex, "run_cli", side_effect=fake):
        outcome = ex.export_rootfs("nginx@sha256:" + "a" * 64, dest)
    assert outcome.ok, outcome.reason
    assert len(tar_dests) == 1
    assert tar_dests[0].parent == dest.parent
    assert not tar_dests[0].exists()  # staged tar removed after extract


def _fake_docker(tar: Path, *, size: int | None = None):
    inspect = _INSPECT
    if size is not None:
        inspect = inspect.replace('[\n  {"Config"',
                                  '[\n  {"Size": %d, "Config"' % size)

    def fake(cmd: list[str], **_kw: Any) -> RunOutcome:
        if cmd[:2] == ["docker", "create"]:
            return RunOutcome(returncode=0, stdout="cid123\n", stderr="",
                              timed_out=False)
        if cmd[:2] == ["docker", "export"]:
            Path(cmd[cmd.index("-o") + 1]).write_bytes(tar.read_bytes())
            return RunOutcome(returncode=0, stdout="", stderr="",
                              timed_out=False)
        if cmd[:3] == ["docker", "image", "inspect"]:
            return RunOutcome(returncode=0, stdout=inspect, stderr="",
                              timed_out=False)
        return RunOutcome(returncode=0, stdout="", stderr="", timed_out=False)

    return fake


def test_extract_quota_bytes_refuses(tmp_path: Path) -> None:
    """Cumulative declared bytes are checked BEFORE extraction — a
    hostile export tar cannot fill host disk mid-walk."""
    import pytest

    members = []
    for i in range(4):
        info = tarfile.TarInfo(f"f{i}")
        info.size = 512
        members.append((info, b"x" * 512))
    tar = _tar_with(members, tmp_path / "big.tar")
    with pytest.raises(ex.RootfsQuotaExceeded):
        ex.extract_rootfs_tar(tar, tmp_path / "r", max_total_bytes=1024)


def test_extract_quota_entries_refuses(tmp_path: Path) -> None:
    import pytest

    members = []
    for i in range(6):
        info = tarfile.TarInfo(f"f{i}")
        info.size = 1
        members.append((info, b"x"))
    tar = _tar_with(members, tmp_path / "many.tar")
    with pytest.raises(ex.RootfsQuotaExceeded):
        ex.extract_rootfs_tar(tar, tmp_path / "r", max_entry_count=3)


def test_export_rootfs_gates_image_size_before_export(tmp_path: Path) -> None:
    """An oversized image refuses BEFORE `docker export` writes the
    host-tmp tar copy."""
    tar = tmp_path / "canned.tar"
    info = tarfile.TarInfo("bin/init")
    info.size = 2
    _tar_with([(info, b"#!")], tar)
    seen: list[list[str]] = []

    fake = _fake_docker(tar, size=10 << 30)

    def spy(cmd: list[str], **kw: Any) -> RunOutcome:
        seen.append(list(cmd))
        return fake(cmd, **kw)

    with patch.object(ex, "run_cli", side_effect=spy):
        outcome = ex.export_rootfs("huge@sha256:" + "a" * 64, tmp_path / "r")
    assert not outcome.ok and outcome.reason == "quota_exceeded"
    assert outcome.extras["image_size"] == 10 << 30
    assert not any(c[:2] == ["docker", "export"] for c in seen)
    assert ["docker", "rm", "-f", "cid123"] in seen  # throwaway removed


def test_export_rootfs_reports_counts_and_flags_degraded(tmp_path: Path) -> None:
    """Extraction counts thread into extras; heavy skipping is flagged."""
    good = tarfile.TarInfo("bin/init")
    good.size = 2
    dev1 = tarfile.TarInfo("dev/sda")
    dev1.type = tarfile.BLKTYPE
    dev2 = tarfile.TarInfo("dev/sdb")
    dev2.type = tarfile.BLKTYPE
    tar = _tar_with([(good, b"#!"), (dev1, None), (dev2, None)],
                    tmp_path / "img.tar")
    with patch.object(ex, "run_cli", side_effect=_fake_docker(tar)):
        outcome = ex.export_rootfs("x@sha256:" + "a" * 64, tmp_path / "r")
    assert outcome.ok
    assert outcome.extras["rootfs_extracted"] == 1
    assert outcome.extras["rootfs_skipped"] == 2
    assert outcome.extras["rootfs_degraded"] is True


def test_export_rootfs_empty_extraction_fails(tmp_path: Path) -> None:
    """A rootfs where nothing extracted must FAIL, not feed the sandbox
    tier a silently empty tree."""
    dev = tarfile.TarInfo("dev/sda")
    dev.type = tarfile.BLKTYPE
    tar = _tar_with([(dev, None)], tmp_path / "img.tar")
    with patch.object(ex, "run_cli", side_effect=_fake_docker(tar)):
        outcome = ex.export_rootfs("x@sha256:" + "a" * 64, tmp_path / "r")
    assert not outcome.ok and outcome.reason == "extract_failed"
    assert outcome.extras["rootfs_extracted"] == 0
