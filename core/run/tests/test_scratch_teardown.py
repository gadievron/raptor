"""Shared scratch teardown never abandons the remaining owned resources."""

from pathlib import Path

import pytest

from core.run import scratch


from core.testing.module_bindings import patch_module_attribute


@pytest.fixture
def allocation(tmp_path, monkeypatch):
    path = tmp_path / "scratch"
    path.mkdir()
    patch_module_attribute(monkeypatch, scratch, 'tempfile', "mkdtemp", lambda **kw: str(path))
    monkeypatch.setattr(scratch, "keepalive_register", lambda path: None)
    monkeypatch.setattr(scratch, "_inode_ceiling_advisory", lambda path: None)
    return path


def test_unregister_failure_does_not_skip_removal(allocation, monkeypatch):
    def fail(path):
        raise OSError("unregister failure")

    monkeypatch.setattr(scratch, "keepalive_unregister", fail)
    with scratch.scratch_dir("raptor-test-"):
        pass
    assert not allocation.exists()


def test_cleanup_cancellation_preserves_primary_error(allocation, monkeypatch):
    def cancel(path):
        raise KeyboardInterrupt("cleanup cancellation")

    monkeypatch.setattr(scratch, "rmtree_hardened", cancel)
    with pytest.raises(ValueError, match="primary failure"):
        with scratch.scratch_dir("raptor-test-"):
            raise ValueError("primary failure")


def test_temp_unlink_cancellation_preserves_write_error(tmp_path, monkeypatch):
    path = tmp_path / "partial.txt"
    stream = path.open("w")

    class Broken:
        name = str(path)

        def __enter__(self):
            return self

        def __exit__(self, *args):
            self.close()

        def close(self):
            stream.close()

        def write(self, text):
            stream.write(text[:2])
            raise ValueError("primary write failure")

    def cancel_unlink(*args, **kwargs):
        raise KeyboardInterrupt("cleanup cancellation")

    patch_module_attribute(monkeypatch, scratch, 'tempfile', "NamedTemporaryFile", lambda **kw: Broken())
    try:
        with monkeypatch.context() as fault:
            fault.setattr(Path, "unlink", cancel_unlink)
            with pytest.raises(ValueError, match="primary write failure"):
                scratch.write_temp_text("payload", prefix="input-", suffix=".txt")
    finally:
        stream.close()
        path.unlink(missing_ok=True)


@pytest.mark.parametrize("stage", ["unregister", "remove"])
@pytest.mark.parametrize("cleanup_error", [OSError("cleanup failed"), KeyboardInterrupt("cleanup cancelled")])
@pytest.mark.parametrize("primary", [ValueError("body failed"), KeyboardInterrupt("body cancelled")])
def test_body_error_keeps_precedence(allocation, monkeypatch, caplog, stage, cleanup_error, primary):
    def fail(path):
        raise cleanup_error

    target = "keepalive_unregister" if stage == "unregister" else "rmtree_hardened"
    monkeypatch.setattr(scratch, target, fail)
    with pytest.raises(type(primary)) as caught:
        with scratch.scratch_dir("raptor-test-"):
            raise primary
    assert caught.value is primary
    assert str(allocation) in caplog.text
    if stage == "unregister":
        assert not allocation.exists()


@pytest.mark.parametrize("stage", ["unregister", "remove"])
def test_new_cleanup_cancellation_propagates_after_teardown(allocation, monkeypatch, stage):
    def cancel(path):
        raise KeyboardInterrupt("new cleanup cancellation")

    target = "keepalive_unregister" if stage == "unregister" else "rmtree_hardened"
    monkeypatch.setattr(scratch, target, cancel)
    with pytest.raises(KeyboardInterrupt, match="new cleanup cancellation"):
        with scratch.scratch_dir("raptor-test-"):
            pass
    if stage == "unregister":
        assert not allocation.exists()


@pytest.mark.parametrize("keep", [False, True])
def test_setup_error_and_failed_unregister_still_remove_tree(allocation, monkeypatch, keep):
    def fail_register(path):
        raise ValueError("setup failed")

    def fail_unregister(path):
        raise OSError("cleanup failed")

    monkeypatch.setattr(scratch, "keepalive_register", fail_register)
    monkeypatch.setattr(scratch, "keepalive_unregister", fail_unregister)
    with pytest.raises(ValueError, match="setup failed"):
        with scratch.scratch_dir("raptor-test-", keep=keep):
            pytest.fail("setup must not yield")
    assert not allocation.exists()


def test_keep_ownership_survives_unregister_failure(allocation, monkeypatch):
    def fail_unregister(path):
        raise OSError("cleanup failed")

    def forbidden_remove(path):
        pytest.fail("successfully transferred scratch must be retained")

    monkeypatch.setattr(scratch, "keepalive_unregister", fail_unregister)
    monkeypatch.setattr(scratch, "rmtree_hardened", forbidden_remove)
    with scratch.scratch_dir("raptor-test-", keep=True) as path:
        (path / "retained").write_bytes(b"data")
    assert (allocation / "retained").read_bytes() == b"data"


def test_refused_removal_is_reported_with_path(allocation, monkeypatch, caplog):
    monkeypatch.setattr(scratch, "rmtree_hardened", lambda path: False)
    with scratch.scratch_dir("raptor-test-", dir=allocation.parent):
        pass
    assert allocation.exists()
    assert "retained after failed removal" in caplog.text
    assert str(allocation) in caplog.text


@pytest.mark.parametrize("close_error", [OSError("close failed"), KeyboardInterrupt("close cancelled")])
def test_failed_write_still_unlinks_when_close_fails(tmp_path, monkeypatch, close_error):
    path = tmp_path / "partial.txt"
    stream = path.open("w")
    closed = []

    class Broken:
        name = str(path)

        def write(self, text):
            stream.write(text[:2])
            raise ValueError("primary write failure")

        def close(self):
            stream.close()
            closed.append(True)
            raise close_error

    patch_module_attribute(monkeypatch, scratch, 'tempfile', "NamedTemporaryFile", lambda **kw: Broken())
    try:
        with pytest.raises(ValueError, match="primary write failure"):
            scratch.write_temp_text("payload", prefix="input-", suffix=".txt")
        assert closed and stream.closed
        assert not path.exists()
    finally:
        stream.close()
        path.unlink(missing_ok=True)


def test_failed_temp_allocation_has_no_cleanup_target(monkeypatch):
    def fail_allocate(**kwargs):
        raise OSError("allocation failed")

    def forbidden_unlink(*args, **kwargs):
        pytest.fail("no temporary file was allocated")

    patch_module_attribute(monkeypatch, scratch, 'tempfile', "NamedTemporaryFile", fail_allocate)
    monkeypatch.setattr(Path, "unlink", forbidden_unlink)
    with pytest.raises(OSError, match="allocation failed"):
        scratch.write_temp_text("payload", prefix="input-", suffix=".txt")
