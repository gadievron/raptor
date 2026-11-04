"""Rootfs publication owns its scratch and never exposes failed extraction."""

import errno
import io
import json
import tarfile
from pathlib import Path

import pytest

from core.container import export as ex
from core.container.proc import RunOutcome


def archive(root):
    path = root / "image.tar"
    with tarfile.open(path, "w") as tar:
        for name in ("first", "second"):
            info = tarfile.TarInfo(name)
            info.size = 16
            tar.addfile(info, io.BytesIO(b"x" * 16))
    return path


def scratch(root):
    return list(root.glob("raptor-rootfs-*"))


@pytest.mark.parametrize("quota", ["bytes", "entries"])
@pytest.mark.parametrize("existing", [False, True])
def test_quota_failure_does_not_publish_partial_rootfs(tmp_path, quota, existing):
    tar = archive(tmp_path)
    dest = tmp_path / "rootfs"
    if existing:
        dest.mkdir()
    limits = {"max_total_bytes": 16} if quota == "bytes" else {"max_entry_count": 1}
    with pytest.raises(ex.RootfsQuotaExceeded):
        ex.extract_rootfs_tar(tar, dest, **limits)
    assert dest.exists() is existing
    if existing:
        assert list(dest.iterdir()) == []
    assert scratch(tmp_path) == []


@pytest.mark.parametrize(
    "error",
    [errno.ENOSPC, errno.EDQUOT, errno.EIO, errno.EROFS, errno.EMFILE, errno.ENFILE],
)
def test_storage_failure_aborts_and_reclaims_partial_rootfs(
    tmp_path, monkeypatch, error
):
    tar = archive(tmp_path)
    dest = tmp_path / "rootfs"
    original = tarfile.TarFile.extract

    def extract(self, member, *args, **kwargs):
        if member.name == "second":
            raise OSError(error, "storage unavailable")
        return original(self, member, *args, **kwargs)

    monkeypatch.setattr(tarfile.TarFile, "extract", extract)
    with pytest.raises(OSError) as failure:
        ex.extract_rootfs_tar(tar, dest)
    assert failure.value.errno == error
    assert not dest.exists()
    assert scratch(tmp_path) == []


@pytest.mark.parametrize("error", [KeyboardInterrupt, tarfile.ReadError])
def test_interruption_or_corruption_removes_owned_extraction(
    tmp_path, monkeypatch, error
):
    tar = archive(tmp_path)
    dest = tmp_path / "rootfs"
    original = tarfile.TarFile.extract

    def extract(self, member, *args, **kwargs):
        if member.name == "second":
            raise error("stopped")
        return original(self, member, *args, **kwargs)

    monkeypatch.setattr(tarfile.TarFile, "extract", extract)
    with pytest.raises(error):
        ex.extract_rootfs_tar(tar, dest)
    assert not dest.exists()
    assert scratch(tmp_path) == []


@pytest.mark.parametrize("kind", ["populated", "symlink", "file"])
def test_existing_destination_is_never_merged_or_overwritten(tmp_path, kind):
    tar = archive(tmp_path)
    real = tmp_path / "operator-data"
    real.mkdir()
    (real / "first").write_text("keep")
    dest = tmp_path / "rootfs"
    if kind == "populated":
        real.rename(dest)
        real = dest
    elif kind == "symlink":
        dest.symlink_to(real, target_is_directory=True)
    else:
        dest.write_text("keep")
    with pytest.raises(OSError):
        ex.extract_rootfs_tar(tar, dest)
    assert (real / "first").read_text() == "keep"
    assert scratch(tmp_path) == []


@pytest.mark.parametrize("name", ["max_total_bytes", "max_entry_count"])
@pytest.mark.parametrize("limit", [float("nan"), float("inf"), -1, True, "10"])
def test_invalid_extraction_limits_create_no_destination(tmp_path, name, limit):
    tar = archive(tmp_path)
    dest = tmp_path / "rootfs"
    with pytest.raises(ValueError):
        ex.extract_rootfs_tar(tar, dest, **{name: limit})
    assert not dest.exists()
    assert scratch(tmp_path) == []


def test_success_publishes_once_on_destination_filesystem(tmp_path, monkeypatch):
    tar = archive(tmp_path)
    dest = tmp_path / "rootfs"
    original = tarfile.TarFile.extract
    locations = []

    def extract(self, member, path, **kwargs):
        assert not dest.exists()
        locations.append(Path(path))
        return original(self, member, path, **kwargs)

    monkeypatch.setattr(tarfile.TarFile, "extract", extract)
    assert ex.extract_rootfs_tar(tar, dest) == (2, 0)
    assert (dest / "first").read_bytes() == b"x" * 16
    assert all(path.parent.parent == dest.parent for path in locations)
    assert scratch(tmp_path) == []


def test_destination_populated_during_extract_survives_failed_publication(
    tmp_path, monkeypatch
):
    tar = archive(tmp_path)
    dest = tmp_path / "rootfs"
    original = tarfile.TarFile.extract

    def extract(self, member, *args, **kwargs):
        if member.name == "second":
            dest.mkdir(exist_ok=True)
            (dest / "operator-data").write_text("keep")
        return original(self, member, *args, **kwargs)

    monkeypatch.setattr(tarfile.TarFile, "extract", extract)
    with pytest.raises(OSError):
        ex.extract_rootfs_tar(tar, dest)
    assert (dest / "operator-data").read_text() == "keep"
    assert not (dest / "first").exists()
    assert scratch(tmp_path) == []


@pytest.mark.parametrize("limit", [float("nan"), float("inf"), -1, True])
@pytest.mark.parametrize(
    "name", ["max_image_bytes", "max_rootfs_bytes", "max_rootfs_entries"]
)
def test_invalid_export_limits_fail_before_docker_runs(
    tmp_path, monkeypatch, name, limit
):
    calls = []

    def docker(*args, **kwargs):
        calls.append(args)
        return RunOutcome(returncode=1, stdout="", stderr="missing", timed_out=False)

    monkeypatch.setattr(ex, "run_cli", docker)
    with pytest.raises(ValueError):
        ex.export_rootfs("image", tmp_path / "rootfs", **{name: limit})
    assert calls == []


@pytest.mark.parametrize("failure", ["bytes", "entries", "disk_full", "corrupt"])
def test_export_failure_reclaims_tar_and_partial_tree_and_removes_container(
    tmp_path, monkeypatch, failure
):
    tar = archive(tmp_path)
    dest = tmp_path / "rootfs"
    calls = []

    def docker(cmd, **kwargs):
        calls.append(cmd)
        output = ""
        if cmd[:2] == ["docker", "create"]:
            output = "container-id"
        elif cmd[:3] == ["docker", "image", "inspect"]:
            output = json.dumps([{"Config": {}, "Size": 1024}])
        elif cmd[:2] == ["docker", "export"]:
            Path(cmd[cmd.index("-o") + 1]).write_bytes(tar.read_bytes())
        return RunOutcome(returncode=0, stdout=output, stderr="", timed_out=False)

    original = tarfile.TarFile.extract

    def extract(self, member, *args, **kwargs):
        if member.name == "second":
            if failure == "disk_full":
                raise OSError(errno.ENOSPC, "disk full")
            if failure == "corrupt":
                raise tarfile.ReadError("corrupt archive")
        return original(self, member, *args, **kwargs)

    monkeypatch.setattr(ex, "run_cli", docker)
    monkeypatch.setattr(tarfile.TarFile, "extract", extract)
    limits = (
        {"max_rootfs_bytes": 16}
        if failure == "bytes"
        else {"max_rootfs_entries": 1}
        if failure == "entries"
        else {}
    )
    result = ex.export_rootfs("image", dest, **limits)
    assert not result.ok
    assert result.reason == (
        "quota_exceeded" if failure in ("bytes", "entries") else "extract_failed"
    )
    assert ["docker", "rm", "-f", "container-id"] in calls
    assert not dest.exists()
    assert scratch(tmp_path) == []


def test_failed_extract_reclaims_restricted_subtrees(tmp_path, monkeypatch):
    tar = archive(tmp_path)
    dest = tmp_path / "rootfs"
    original = tarfile.TarFile.extract

    def extract(self, member, path, **kwargs):
        if member.name == "second":
            raise tarfile.ReadError("corrupt archive")
        result = original(self, member, path, **kwargs)
        restricted = Path(path) / "locked"
        restricted.mkdir()
        (restricted / "payload").write_text("partial")
        restricted.chmod(0)
        return result

    monkeypatch.setattr(tarfile.TarFile, "extract", extract)
    with pytest.raises(tarfile.ReadError):
        ex.extract_rootfs_tar(tar, dest)
    assert not dest.exists()
    assert scratch(tmp_path) == []


@pytest.mark.parametrize("size", [True, False, -1, "1024", None])
def test_invalid_daemon_image_sizes_are_not_accepted_as_byte_counts(size):
    assert ex._image_size_bytes(json.dumps([{"Size": size}])) is None
