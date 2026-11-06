"""Only completed image binaries become visible at their final name."""

import errno
import hashlib
import os
import stat
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest

import core.atomic_fs as atomic
from core.run import scratch
from packages.sca.bump import image_binary_extract as extraction
from packages.sca.bump.tests.test_image_binary_extract import _stub_client_with_binary

DATA = b"\x7fELF" + b"x" * 200
NAME = hashlib.sha256(DATA).hexdigest()[:32] + "-foo"


@pytest.fixture
def case(monkeypatch, tmp_path):
    default_roots = []
    staging = []
    real_mkdtemp = extraction.tempfile.mkdtemp

    def allocate(**kwargs):
        root = real_mkdtemp(dir=tmp_path, **kwargs)
        default_roots.append(Path(root))
        return root

    @contextmanager
    def stage(prefix, *, dir, keepalive):
        assert keepalive
        with scratch.scratch_dir(prefix, dir=dir, keepalive=keepalive) as root:
            staging.append(root)
            assert str(root) in scratch._keepalive_paths
            yield root

    monkeypatch.setattr(extraction, "tempfile", SimpleNamespace(mkdtemp=allocate))
    monkeypatch.setattr(extraction, "scratch_dir", stage)
    output = tmp_path / "output"
    output.mkdir()
    sentinel = output / "keep"
    sentinel.write_bytes(b"caller file")

    def run(owned):
        return extraction.fetch_image_binary(
            "docker.io/library/test:1", client=_stub_client_with_binary(DATA),
            out_dir=None if owned else output,
        )

    state = SimpleNamespace(run=run, output=output, roots=default_roots, staging=staging)
    try:
        yield state
    finally:
        # The caller owns successful default extractions; register teardown
        # before invoking production, including assertion-failure paths.
        for root in default_roots:
            atomic.rmtree_hardened(root)


def assert_reclaimed(case, owned):
    assert all(not p.exists() for p in case.staging)
    assert all(str(p) not in scratch._keepalive_paths for p in case.staging)
    if owned:
        assert len(case.roots) == 1
        assert not case.roots[0].exists()
    assert (case.output / "keep").read_bytes() == b"caller file"
    assert not (case.output / NAME).exists()


@pytest.mark.parametrize("owned", [False, True], ids=["caller-output", "default-output"])
@pytest.mark.parametrize("error_type", [OSError, RuntimeError, KeyboardInterrupt, SystemExit])
def test_partial_writes_are_private_and_retryable(case, monkeypatch, owned, error_type):
    error = error_type("write interrupted")
    real_write = extraction.write_new_bytes

    def fail(path, content, **kwargs):
        assert not (path.parent.parent / NAME).exists()
        path.write_bytes(content[:4])
        nested = path.parent / "nested"
        nested.mkdir()
        (nested / "partial").write_bytes(b"partial")
        nested.chmod(0)
        raise error

    monkeypatch.setattr(extraction, "write_new_bytes", fail)
    if error_type is OSError:
        assert case.run(owned) is None
    else:
        with pytest.raises(error_type) as caught:
            case.run(owned)
        assert caught.value is error
    assert_reclaimed(case, owned)
    monkeypatch.setattr(extraction, "write_new_bytes", real_write)
    result = case.run(owned)
    assert result is not None
    assert result.read_bytes() == DATA
    assert all(not p.exists() for p in case.staging)


@pytest.mark.parametrize("owned", [False, True], ids=["caller-output", "default-output"])
@pytest.mark.parametrize("shape", ["different", "same", "symlink", "dangling", "directory", "fifo"])
def test_racing_destination_is_never_overwritten(case, monkeypatch, tmp_path, owned, shape):
    victim = tmp_path / "victim"
    victim.write_bytes(b"preserve")
    occupied = []

    def publish(source, destination):
        assert source.read_bytes() == DATA
        assert str(source.parent) in scratch._keepalive_paths
        assert not destination.exists()
        if shape in {"different", "same"}:
            destination.write_bytes(DATA if shape == "same" else b"contender")
            destination.chmod(0o600)
        elif shape == "symlink":
            destination.symlink_to(victim)
        elif shape == "dangling":
            destination.symlink_to(tmp_path / "missing")
        elif shape == "directory":
            destination.mkdir()
        else:
            os.mkfifo(destination)
        occupied.append((destination, destination.lstat().st_ino))
        return os.link(source, destination)

    monkeypatch.setattr(extraction, "os", SimpleNamespace(**{**vars(os), "link": publish}))
    result = case.run(owned)
    assert (result is not None) == (shape == "same")
    assert victim.read_bytes() == b"preserve"
    assert all(not p.exists() for p in case.staging)
    destination, inode = occupied[0]
    if owned and shape != "same":
        assert not case.roots[0].exists()
    else:
        assert destination.lstat().st_ino == inode
    if shape == "same":
        assert result == destination
        assert result.read_bytes() == DATA


@pytest.mark.parametrize("owned", [False, True], ids=["caller-output", "default-output"])
@pytest.mark.parametrize("mode", ["short", "zero", "oserror", "interrupt", "exit", "close"])
def test_real_writer_closes_descriptors_and_handles_short_writes(case, monkeypatch, owned, mode):
    descriptors = []
    primary = {"oserror": OSError("disk full"), "interrupt": KeyboardInterrupt(), "exit": SystemExit(7)}.get(mode)

    def write(fd, content):
        descriptors.append(fd)
        assert not (case.staging[-1].parent / NAME).exists()
        if mode == "zero":
            return 0
        if primary is not None:
            os.write(fd, content[:1])
            raise primary
        return os.write(fd, content[:3] if mode == "short" else content)

    def close(fd):
        os.close(fd)
        if mode == "close":
            raise OSError("close failed")

    monkeypatch.setattr(atomic, "os", SimpleNamespace(**{**vars(os), "write": write, "close": close}))
    if mode in {"interrupt", "exit"}:
        with pytest.raises(type(primary)) as caught:
            case.run(owned)
        assert caught.value is primary
    else:
        result = case.run(owned)
        if mode == "short":
            assert result is not None and result.read_bytes() == DATA
            assert stat.S_IMODE(result.stat().st_mode) == 0o600
        else:
            assert result is None
    assert descriptors
    for fd in set(descriptors):
        with pytest.raises(OSError) as caught:
            os.fstat(fd)
        assert caught.value.errno == errno.EBADF
    assert all(not p.exists() for p in case.staging)
    if mode != "short":
        assert_reclaimed(case, owned)


@pytest.mark.parametrize("error_type", [OSError, RuntimeError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("cleanup_type", [OSError, RuntimeError, KeyboardInterrupt, SystemExit])
def test_default_root_cleanup_preserves_write_failure(case, monkeypatch, error_type, cleanup_type):
    primary = error_type("write failed")
    remove = extraction.rmtree_hardened

    def write(path, content, **kwargs):
        path.write_bytes(content[:1])
        raise primary

    def cleanup(path):
        assert remove(path)
        raise cleanup_type("cleanup failed")

    monkeypatch.setattr(extraction, "write_new_bytes", write)
    monkeypatch.setattr(extraction, "rmtree_hardened", cleanup)
    if error_type is OSError:
        assert case.run(True) is None
    else:
        with pytest.raises(error_type) as caught:
            case.run(True)
        assert caught.value is primary
    assert_reclaimed(case, True)


@pytest.mark.parametrize("shape", ["reusable", "invalid"])
def test_existing_destination_does_not_allocate_or_write(case, monkeypatch, shape):
    path = case.output / NAME
    path.write_bytes(DATA if shape == "reusable" else b"existing")
    path.chmod(0o600)

    def unexpected(*args, **kwargs):
        pytest.fail("existing destination must not allocate staging or write")

    monkeypatch.setattr(extraction, "scratch_dir", unexpected)
    monkeypatch.setattr(extraction, "write_new_bytes", unexpected)
    result = case.run(False)
    assert result == (path if shape == "reusable" else None)
    assert path.read_bytes() == (DATA if shape == "reusable" else b"existing")


def test_successful_publication_uses_same_inode(case, monkeypatch):
    linked = []

    def publish(source, destination):
        assert source.read_bytes() == DATA
        assert not destination.exists()
        os.link(source, destination)
        assert source.stat().st_ino == destination.stat().st_ino
        linked.append(destination.stat().st_ino)

    monkeypatch.setattr(extraction, "os", SimpleNamespace(**{**vars(os), "link": publish}))
    result = case.run(False)
    assert result is not None
    assert result.stat().st_ino == linked[0]
    assert result.stat().st_nlink == 1
    assert result.read_bytes() == DATA
    assert all(not p.exists() for p in case.staging)
