"""Library extraction never caches partial source or loses a prior good tree."""

import io
import os
import tarfile
from pathlib import Path

import pytest

from core.concepts import library_detect as ld


def write_archive(path, value=b"new", roots=("library",)):
    with tarfile.open(path, "w") as tar:
        for root in roots:
            directory = tarfile.TarInfo(root)
            directory.type = tarfile.DIRTYPE
            tar.addfile(directory)
            for name in ("first.c", "second.c"):
                info = tarfile.TarInfo(f"{root}/{name}")
                info.size = len(value)
                tar.addfile(info, io.BytesIO(value))
    return path


@pytest.fixture
def archive(tmp_path):
    return write_archive(tmp_path / "source.tar")


@pytest.mark.parametrize("existing", [False, True])
@pytest.mark.parametrize("error", [OSError, tarfile.ReadError, KeyboardInterrupt])
def test_failed_extraction_discards_partial_tree_and_preserves_previous_cache(
    tmp_path, archive, monkeypatch, existing, error
):
    cache = tmp_path / "cache"
    if existing:
        write_archive(archive, b"old")
        assert ld._extract_tarball(archive, cache)
        old = archive.stat().st_mtime
        write_archive(archive, b"new")
        os.utime(archive, (old + 5, old + 5))
    extract = tarfile.TarFile.extractall

    def fail(self, path, members, **kwargs):
        extract(self, path, members=list(members)[:2], **kwargs)
        raise error("extraction failed")

    with monkeypatch.context() as fault:
        fault.setattr(tarfile.TarFile, "extractall", fail)
        if error is KeyboardInterrupt:
            with pytest.raises(KeyboardInterrupt):
                ld._extract_tarball(archive, cache)
        else:
            assert ld._extract_tarball(archive, cache) is None
    root = cache / "library"
    assert root.exists() is existing
    if existing:
        assert (root / "first.c").read_bytes() == b"old"
        assert (root / "second.c").read_bytes() == b"old"
    assert list(cache.glob(".library-extract-*")) == []
    assert ld._extract_tarball(archive, cache) == root
    assert (root / "second.c").read_bytes() == b"new"


def test_unstamped_partial_cache_is_rebuilt(tmp_path, archive):
    cache = tmp_path / "cache"
    root = cache / "library"
    root.mkdir(parents=True)
    (root / "leftover").write_text("partial")
    assert ld._extract_tarball(archive, cache) == root
    assert (root / "first.c").read_bytes() == b"new"
    assert not (root / "leftover").exists()


@pytest.mark.parametrize("replacement", [False, True])
def test_archive_change_with_preserved_mtime_invalidates_cache(
    tmp_path, archive, replacement
):
    cache = tmp_path / "cache"
    write_archive(archive, b"old")
    root = ld._extract_tarball(archive, cache)
    before = archive.stat()
    if replacement:
        other = write_archive(tmp_path / "replacement.tar", b"new")
        os.replace(other, archive)
    else:
        write_archive(archive, b"new")
    os.utime(archive, ns=(before.st_atime_ns, before.st_mtime_ns))
    assert ld._extract_tarball(archive, cache) == root
    assert (root / "first.c").read_bytes() == b"new"


def test_multiroot_archive_leaves_no_unowned_extractions(tmp_path):
    archive = write_archive(tmp_path / "source.tar", roots=("library", "extra"))
    cache = tmp_path / "cache"
    assert ld._extract_tarball(archive, cache) is None
    assert not (cache / "library").exists()
    assert not (cache / "extra").exists()
    assert list(cache.glob(".library-extract-*")) == []


@pytest.mark.parametrize("limit", ["_EXTRACT_MAX_TOTAL_BYTES", "_EXTRACT_MAX_ENTRIES"])
def test_cumulative_extraction_limits_refuse_without_residue(
    tmp_path, archive, monkeypatch, limit
):
    monkeypatch.setattr(ld, limit, 2, raising=False)
    cache = tmp_path / "cache"
    assert ld._extract_tarball(archive, cache) is None
    assert not (cache / "library").exists()
    assert list(cache.glob(".library-extract-*")) == []


def test_changed_archive_during_extraction_is_not_stamped_as_new_source(
    tmp_path, archive, monkeypatch
):
    cache = tmp_path / "cache"
    write_archive(archive, b"old")
    extract = tarfile.TarFile.extractall

    def change(self, path, **kwargs):
        extract(self, path, **kwargs)
        write_archive(archive, b"new")

    with monkeypatch.context() as fault:
        fault.setattr(tarfile.TarFile, "extractall", change)
        assert ld._extract_tarball(archive, cache) is None
    assert not (cache / "library").exists()
    root = ld._extract_tarball(archive, cache)
    assert (root / "first.c").read_bytes() == b"new"


def test_cache_root_symlink_is_not_followed(tmp_path, archive):
    cache = tmp_path / "cache"
    cache.mkdir()
    outside = tmp_path / "operator-data"
    outside.mkdir()
    (outside / "payload").write_text("keep")
    root = cache / "library"
    root.symlink_to(outside, target_is_directory=True)
    assert ld._extract_tarball(archive, cache) is None
    assert (outside / "payload").read_text() == "keep"
    assert root.is_symlink()


def test_completion_stamp_failure_does_not_publish_unverifiable_cache(
    tmp_path, archive, monkeypatch
):
    cache = tmp_path / "cache"
    write = Path.write_text

    def fail(*args, **kwargs):
        raise OSError("stamp failed")

    def old_stamp(path, *args, **kwargs):
        if path.name == ".raptor-extract-mtime":
            raise OSError("stamp failed")
        return write(path, *args, **kwargs)

    monkeypatch.setattr(ld, "save_json", fail, raising=False)
    monkeypatch.setattr(Path, "write_text", old_stamp)
    assert ld._extract_tarball(archive, cache) is None
    assert not (cache / "library").exists()
    assert list(cache.glob(".library-extract-*")) == []


def test_unchanged_archive_reuses_completed_cache_without_extraction(
    tmp_path, archive, monkeypatch
):
    cache = tmp_path / "cache"
    root = ld._extract_tarball(archive, cache)

    def forbidden(*args, **kwargs):
        raise AssertionError("unnecessary extraction")

    monkeypatch.setattr(tarfile.TarFile, "extractall", forbidden)
    assert ld._extract_tarball(archive, cache) == root


@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
@pytest.mark.parametrize("phase", ["retire_before", "retire_after", "publish"])
def test_failed_cache_publication_restores_previous_tree(
    tmp_path, archive, monkeypatch, error, phase
):
    cache = tmp_path / "cache"
    write_archive(archive, b"old")
    root = ld._extract_tarball(archive, cache)
    write_archive(archive, b"new")
    rename = os.rename

    def move(src, dst, *args, **kwargs):
        if Path(src) == root:
            if phase == "retire_before":
                raise error("retire failed")
            if phase == "retire_after":
                rename(src, dst, *args, **kwargs)
                raise error("retirement completed before failure")
        if (
            phase == "publish"
            and Path(dst) == root
            and Path(src).parent.name.startswith(".library-extract-")
        ):
            raise error("publish failed")
        return rename(src, dst, *args, **kwargs)

    with monkeypatch.context() as fault:
        fault.setattr(os, "rename", move)
        if error is KeyboardInterrupt:
            with pytest.raises(KeyboardInterrupt):
                ld._extract_tarball(archive, cache)
        else:
            assert ld._extract_tarball(archive, cache) is None
    assert (root / "first.c").read_bytes() == b"old"
    assert list(cache.glob(".library-extract-*")) == []
    assert list(cache.glob(".library-stale-*")) == []
    assert ld._extract_tarball(archive, cache) == root
    assert (root / "first.c").read_bytes() == b"new"


def test_failed_rollback_preserves_recovery_tree(tmp_path, archive, monkeypatch):
    cache = tmp_path / "cache"
    write_archive(archive, b"old")
    root = ld._extract_tarball(archive, cache)
    write_archive(archive, b"new")
    rename = os.rename

    def move(src, dst, *args, **kwargs):
        if Path(dst) == root:
            raise OSError("cannot publish or roll back")
        return rename(src, dst, *args, **kwargs)

    monkeypatch.setattr(os, "rename", move)
    assert ld._extract_tarball(archive, cache) is None
    recovery = list(cache.glob(".library-stale-*"))
    assert len(recovery) == 1
    assert (recovery[0] / "first.c").read_bytes() == b"old"
    assert list(cache.glob(".library-extract-*")) == []


@pytest.mark.parametrize("existing", [False, True])
def test_changed_destination_is_not_retired_or_deleted(
    tmp_path, archive, monkeypatch, existing
):
    cache = tmp_path / "cache"
    root = cache / "library"
    if existing:
        write_archive(archive, b"old")
        assert ld._extract_tarball(archive, cache) == root
        write_archive(archive, b"new")
    extract = tarfile.TarFile.extractall

    def change(self, path, **kwargs):
        extract(self, path, **kwargs)
        if root.exists():
            root.rename(tmp_path / "original-cache")
        root.mkdir()
        (root / "operator-data").write_text("keep")

    monkeypatch.setattr(tarfile.TarFile, "extractall", change)
    assert ld._extract_tarball(archive, cache) is None
    assert (root / "operator-data").read_text() == "keep"
    assert not (root / "first.c").exists()
    assert list(cache.glob(".library-extract-*")) == []


@pytest.mark.parametrize("legacy_stamp", [False, True])
def test_source_archive_inside_destination_is_never_removed(tmp_path, legacy_stamp):
    cache = tmp_path / "cache"
    root = cache / "library"
    root.mkdir(parents=True)
    archive = write_archive(root / "source.tar")
    if legacy_stamp:
        (root / ".raptor-extract-mtime").write_text("0")
    before = archive.read_bytes()
    assert ld._extract_tarball(archive, cache) is None
    assert archive.read_bytes() == before


@pytest.mark.parametrize("kind", ["file", "root", "hard"])
def test_in_tree_library_links_remain_supported(tmp_path, kind):
    archive = write_archive(tmp_path / "source.tar")
    with tarfile.open(archive, "a") as tar:
        link = tarfile.TarInfo("library/alias")
        link.type = tarfile.LNKTYPE if kind == "hard" else tarfile.SYMTYPE
        link.linkname = {"file": "first.c", "root": ".", "hard": "library/first.c"}[
            kind
        ]
        tar.addfile(link)
    root = ld._extract_tarball(archive, tmp_path / "cache")
    assert root is not None
    if kind == "root":
        assert (root / "alias").resolve() == root
    else:
        assert (root / "alias").read_bytes() == b"new"


@pytest.mark.parametrize("mode", [0o000, 0o500, 0o555])
def test_replacement_reclaims_restricted_old_cache(tmp_path, archive, mode):
    from core.testing.restricted_tree import restricted_tree

    cache = tmp_path / "cache"
    write_archive(archive, b"old")
    root = ld._extract_tarball(archive, cache)
    with restricted_tree(root / "locked", mode):
        write_archive(archive, b"new")
        assert ld._extract_tarball(archive, cache) == root
        assert (root / "first.c").read_bytes() == b"new"
        assert list(cache.glob(".library-stale-*")) == []


@pytest.mark.parametrize("marker", ["missing", "malformed", "oversized", "symlink"])
def test_unverifiable_completion_marker_forces_rebuild(
    tmp_path, archive, monkeypatch, marker
):
    cache = tmp_path / "cache"
    root = ld._extract_tarball(archive, cache)
    stamp = root / ld._EXTRACT_STAMP
    if marker == "missing":
        stamp.unlink()
    elif marker == "malformed":
        stamp.write_text("not JSON")
    elif marker == "oversized":
        stamp.write_text("x" * 4097)
    else:
        stamp.rename(tmp_path / "old-stamp")
        stamp.symlink_to(tmp_path / "old-stamp")
    extract = tarfile.TarFile.extractall
    calls = []

    def observe(self, *args, **kwargs):
        calls.append(args)
        return extract(self, *args, **kwargs)

    monkeypatch.setattr(tarfile.TarFile, "extractall", observe)
    assert ld._extract_tarball(archive, cache) == root
    assert len(calls) == 1
    assert not stamp.is_symlink()


def test_lock_refusal_does_not_publish_unlocked_cache(tmp_path, archive, monkeypatch):
    from contextlib import contextmanager

    @contextmanager
    def refused(*args, **kwargs):
        assert kwargs["required"] is True
        raise OSError("cache lock unavailable")
        yield

    monkeypatch.setattr(ld, "artifact_lock", refused)
    cache = tmp_path / "cache"
    assert ld._extract_tarball(archive, cache) is None
    assert not (cache / "library").exists()
    assert list(cache.glob(".library-extract-*")) == []


@pytest.mark.parametrize("failure", [False, True])
def test_library_detection_only_offers_complete_source(tmp_path, monkeypatch, failure):
    archive = tmp_path / "source.tar"
    with tarfile.open(archive, "w") as tar:
        info = tarfile.TarInfo("library/include/example.h")
        info.size = 3
        tar.addfile(info, io.BytesIO(b"new"))

    class Resolver:
        name = "fixture"

        def header_to_source_package(self, header):
            return "example"

        def find_source_tarball(self, package):
            return archive

    monkeypatch.setattr(ld, "harvest_system_includes", lambda target: {"example.h"})
    monkeypatch.setattr(ld, "_detect_resolver", Resolver)
    if failure:

        def fail(*args, **kwargs):
            raise OSError("disk full")

        monkeypatch.setattr(tarfile.TarFile, "extractall", fail)
    ready, missing = ld.detect_library_candidates(tmp_path, tmp_path / "cache")
    if failure:
        assert ready == []
        assert len(missing) == 1
        assert missing[0].installed
        assert missing[0].extracted_root is None
        assert not (tmp_path / "cache/library").exists()
    else:
        assert ready == [(str(tmp_path / "cache/library/include"), "example_include")]
        assert missing == []
