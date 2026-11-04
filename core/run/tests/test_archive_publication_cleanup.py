"""Archive cache publication must not report success or leak failed work."""

import errno
import os
import zipfile
from contextlib import ExitStack
from pathlib import Path

import pytest

import raptor
from core.archive import safe_cache_name
from core.run.provenance import archive_snapshot
from core.testing.restricted_tree import restricted_tree


@pytest.fixture
def archive_run(tmp_path):
    archive = tmp_path / "source.zip"
    with zipfile.ZipFile(archive, "w") as z:
        z.writestr("source/main.c", b"old")
    out = tmp_path / "project/run"
    out.mkdir(parents=True)
    snap = archive_snapshot(archive)
    cache = (
        out.parent
        / "_sources"
        / safe_cache_name(snap["archive_name"], snap["archive_sha256"])
    )
    return archive, out, cache


def unpack(archive, out):
    return raptor._unpack_archive_target(str(archive), ["--repo", str(archive)], out)


@pytest.mark.parametrize("error", [errno.ENOSPC, errno.EACCES, errno.EIO])
def test_failed_publication_is_not_success(archive_run, monkeypatch, error):
    archive, out, cache = archive_run
    replace = os.replace

    def fail(src, dst):
        if Path(dst) == cache:
            raise OSError(error, "publication failed")
        return replace(src, dst)

    monkeypatch.setattr(os, "replace", fail)
    assert unpack(archive, out) is None
    assert not cache.exists()
    assert not (out / "_source").is_symlink()
    assert not list(cache.parent.glob(".extract-*"))


@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("mode", [0, 0o500, 0o555])
def test_failed_extraction_cleans_restricted_partial_tree(
    archive_run, monkeypatch, error, mode
):
    archive, out, cache = archive_run
    failure = error("extract failed")
    with ExitStack() as stack:

        def fail(source, dest):
            stack.enter_context(restricted_tree(Path(dest) / "objects", mode))
            raise failure

        monkeypatch.setattr("core.archive.extract_to_dir", fail)
        if error is OSError:
            assert unpack(archive, out) is None
        else:
            with pytest.raises(error) as caught:
                unpack(archive, out)
            assert caught.value is failure
        assert not cache.exists()
        assert not list(cache.parent.glob(".extract-*"))


@pytest.mark.parametrize("kind", ["file", "symlink", "dangling"])
def test_non_directory_cache_slot_is_refused_without_touching_it(
    archive_run, tmp_path, kind
):
    archive, out, cache = archive_run
    cache.parent.mkdir(parents=True)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "keep").write_text("keep")
    if kind == "file":
        cache.write_text("keep")
    else:
        cache.symlink_to(
            outside if kind == "symlink" else tmp_path / "absent",
            target_is_directory=True,
        )
    assert unpack(archive, out) is None
    assert os.path.lexists(cache)
    assert (outside / "keep").read_text() == "keep"
    assert not list(cache.parent.glob(".extract-*"))


@pytest.mark.parametrize("change", ["modify", "replace", "delete"])
def test_changed_source_is_not_published_under_old_digest(
    archive_run, monkeypatch, change
):
    import core.archive

    archive, out, cache = archive_run
    extract = core.archive.extract_to_dir

    def changed(source, dest):
        result = extract(source, dest)
        if change == "delete":
            archive.unlink()
        else:
            replacement = archive if change == "modify" else archive.with_suffix(".new")
            before = archive.stat()
            with zipfile.ZipFile(replacement, "w") as z:
                z.writestr("source/main.c", b"new")
            if change == "replace":
                os.replace(replacement, archive)
            os.utime(archive, ns=(before.st_atime_ns, before.st_mtime_ns))
        return result

    monkeypatch.setattr("core.archive.extract_to_dir", changed)
    assert unpack(archive, out) is None
    assert not cache.exists()
    assert not list(cache.parent.glob(".extract-*"))


@pytest.mark.parametrize("collision", [errno.EEXIST, errno.ENOTEMPTY])
def test_completed_legacy_publisher_collision_is_reused(
    archive_run, monkeypatch, collision
):
    archive, out, cache = archive_run
    replace = os.replace

    def publish(src, dst):
        if Path(dst) == cache:
            cache.mkdir()
            (cache / "winner").write_text("complete")
            raise OSError(collision, "another publisher won")
        return replace(src, dst)

    monkeypatch.setattr(os, "replace", publish)
    assert unpack(archive, out) is not None
    assert (cache / "winner").read_text() == "complete"
    assert not list(cache.parent.glob(".extract-*"))


def test_required_writer_lock_failure_prevents_extraction(archive_run, monkeypatch):
    from contextlib import contextmanager

    archive, out, cache = archive_run

    @contextmanager
    def refuse(*args, **kwargs):
        assert kwargs["required"] is True
        raise OSError("lock unavailable")
        yield

    monkeypatch.setattr("core.atomic_fs.fs_lock.artifact_lock", refuse)

    def forbidden(*args, **kwargs):
        pytest.fail("must not extract without the writer lock")

    monkeypatch.setattr("core.archive.extract_to_dir", forbidden)
    assert unpack(archive, out) is None
    assert not cache.exists()
    assert not list(cache.parent.glob(".extract-*"))


@pytest.mark.parametrize("error", [KeyboardInterrupt, SystemExit])
def test_cancelled_publication_reclaims_staging(archive_run, monkeypatch, error):
    archive, out, cache = archive_run
    replace = os.replace
    failure = error("cancelled")

    def fail(src, dst):
        if Path(dst) == cache:
            raise failure
        return replace(src, dst)

    monkeypatch.setattr(os, "replace", fail)
    with pytest.raises(error) as caught:
        unpack(archive, out)
    assert caught.value is failure
    assert not cache.exists()
    assert not list(cache.parent.glob(".extract-*"))


def test_concurrent_runs_share_one_extraction(archive_run, monkeypatch):
    import core.archive
    from concurrent.futures import ThreadPoolExecutor
    from contextlib import contextmanager
    from threading import Event, Lock
    from core.atomic_fs.fs_lock import artifact_lock

    archive, out, cache = archive_run
    out2 = out.with_name("run2")
    out2.mkdir()
    entered = Event()
    second_attempt = Event()
    release = Event()
    guard = Lock()
    calls = []
    attempts = 0
    extract = core.archive.extract_to_dir

    def slow_extract(*args, **kwargs):
        calls.append(args)
        entered.set()
        assert release.wait(10)
        return extract(*args, **kwargs)

    @contextmanager
    def track_lock(*args, **kwargs):
        nonlocal attempts
        with guard:
            attempts += 1
            if attempts == 2:
                second_attempt.set()
        with artifact_lock(*args, **kwargs):
            yield

    monkeypatch.setattr("core.archive.extract_to_dir", slow_extract)
    monkeypatch.setattr("core.atomic_fs.fs_lock.artifact_lock", track_lock)
    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(unpack, archive, out)
        try:
            assert entered.wait(5)
            second = pool.submit(unpack, archive, out2)
            assert second_attempt.wait(5)
            assert len(calls) == 1
        finally:
            release.set()
        assert first.result(timeout=10) is not None
        assert second.result(timeout=10) is not None
    assert len(calls) == 1
    assert (cache / "source/main.c").read_bytes() == b"old"
    assert not list(cache.parent.glob(".extract-*"))
