"""Header sizes cannot subtract from a rootfs extraction quota."""
import io
import tarfile

import pytest

from core.container import export


@pytest.fixture(autouse=True)
def local_scratch_without_heartbeat(monkeypatch):
    native_scratch = export.scratch_dir

    def local_scratch(*args, **kwargs):
        assert kwargs.pop("keepalive") is True
        return native_scratch(*args, keepalive=False, **kwargs)

    monkeypatch.setattr(export, "scratch_dir", local_scratch)


def write_tar(path, *, negative_directory=False, archive_format=tarfile.GNU_FORMAT):
    payload = b"x" * 32
    with tarfile.open(path, "w", format=archive_format) as archive:
        first = tarfile.TarInfo("first")
        first.size = 4
        archive.addfile(first, io.BytesIO(b"safe"))
        directory = tarfile.TarInfo("directory")
        directory.type = tarfile.DIRTYPE
        directory.size = -64 if negative_directory else 0
        archive.addfile(directory)
        final = tarfile.TarInfo("directory/final")
        final.size = len(payload)
        archive.addfile(final, io.BytesIO(payload))
    return path


@pytest.mark.parametrize("archive_format", [tarfile.GNU_FORMAT, tarfile.PAX_FORMAT], ids=["gnu", "pax"])
def test_negative_directory_size_cannot_credit_later_payload(tmp_path, archive_format):
    archive = write_tar(tmp_path / "negative.tar", negative_directory=True,
                        archive_format=archive_format)
    with tarfile.open(archive) as reader:
        members = reader.getmembers()
        assert members[1].isdir() and members[1].size == -64
        assert members[2].size == 32
    destination = tmp_path / "rootfs"
    try:
        export.extract_rootfs_tar(archive, destination, max_total_bytes=8)
    except tarfile.ReadError as error:
        assert "negative" in str(error) and "size" in str(error)
    else:
        published = sum(path.stat().st_size for path in destination.rglob("*") if path.is_file())
        pytest.fail(f"negative header published {published} regular bytes under an 8-byte quota")
    assert not destination.exists()
    assert not list(tmp_path.glob("raptor-rootfs-extract-*"))


def test_negative_size_preserves_borrowed_empty_destination(tmp_path):
    archive = write_tar(tmp_path / "negative.tar", negative_directory=True)
    destination = tmp_path / "borrowed"
    destination.mkdir()
    before = destination.stat()
    with pytest.raises(tarfile.ReadError, match="negative.*size"):
        export.extract_rootfs_tar(archive, destination, max_total_bytes=8)
    after = destination.stat()
    assert (after.st_dev, after.st_ino) == (before.st_dev, before.st_ino)
    assert not list(destination.iterdir())
    assert not list(tmp_path.glob("raptor-rootfs-extract-*"))


def test_positive_payload_still_hits_quota_before_publication(tmp_path):
    archive = write_tar(tmp_path / "positive.tar")
    destination = tmp_path / "rootfs"
    with pytest.raises(export.RootfsQuotaExceeded):
        export.extract_rootfs_tar(archive, destination, max_total_bytes=8)
    assert not destination.exists()
    assert not list(tmp_path.glob("raptor-rootfs-extract-*"))


def test_exact_quota_keeps_zero_size_directory_and_payload(tmp_path):
    archive = write_tar(tmp_path / "exact.tar")
    destination = tmp_path / "rootfs"
    assert export.extract_rootfs_tar(archive, destination, max_total_bytes=36) == (3, 0)
    assert (destination / "first").read_bytes() == b"safe"
    assert (destination / "directory/final").read_bytes() == b"x" * 32
    assert not list(tmp_path.glob("raptor-rootfs-extract-*"))
