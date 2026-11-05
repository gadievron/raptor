"""Process-cached prompts retain ownership until complete cleanup succeeds."""

import os
from contextlib import contextmanager
import threading
import types

import pytest


@pytest.fixture(autouse=True)
def _owned_cache(sysprompt_cache):
    return sysprompt_cache


def test_unexpected_partial_files_are_reclaimed(sysprompt_cache):
    path = sysprompt_cache._sysprompt_file("prompt")
    root = path.parent
    (root / "unexpected.part").write_bytes(b"partial data")
    sysprompt_cache._cleanup_sysprompt_cache()
    assert not root.exists()


def test_failed_cleanup_keeps_retry_ownership(sysprompt_cache, monkeypatch):
    path = sysprompt_cache._sysprompt_file("prompt")
    root = path.parent
    with monkeypatch.context() as fault:
        fault.setattr(sysprompt_cache, "rmtree_hardened", lambda path: False, raising=False)
        sysprompt_cache._cleanup_sysprompt_cache()
        assert sysprompt_cache._sysprompt_dir == root
        assert sysprompt_cache._sysprompt_cache
    sysprompt_cache._cleanup_sysprompt_cache()
    assert not root.exists()


def test_changed_cached_content_is_recreated(sysprompt_cache):
    path = sysprompt_cache._sysprompt_file("prompt")
    path.write_text("changed content")
    again = sysprompt_cache._sysprompt_file("prompt")
    assert again.read_text() == "prompt"


def test_cache_hit_does_not_follow_or_touch_symlink(sysprompt_cache, tmp_path):
    path = sysprompt_cache._sysprompt_file("prompt")
    external = tmp_path / "external"
    external.write_text("prompt")
    external.chmod(0o600)
    os.utime(external, ns=(1_600_000_000_000_000_000,) * 2)
    before = external.stat().st_mtime_ns
    path.unlink()
    path.symlink_to(external)
    again = sysprompt_cache._sysprompt_file("prompt")
    assert not again.is_symlink()
    assert external.stat().st_mtime_ns == before


@pytest.mark.parametrize("mode", [0o000, 0o500, 0o555])
def test_restricted_cache_children_are_reclaimed(sysprompt_cache, mode):
    path = sysprompt_cache._sysprompt_file("prompt")
    nested = path.parent / "locked" / "nested"
    nested.mkdir(parents=True)
    (nested / "partial").write_bytes(b"data")
    (path.parent / "locked").chmod(mode)
    sysprompt_cache._cleanup_sysprompt_cache()
    assert not path.parent.exists()


@pytest.mark.parametrize("cancel", [False, True])
def test_registration_failure_removes_allocation(sysprompt_cache, monkeypatch, cancel):
    from core.run import scratch
    paths = []

    def fail_register(path):
        paths.append(path)
        scratch._keepalive_paths.add(str(path))
        if cancel:
            raise KeyboardInterrupt("registration cancelled")
        raise OSError("registration failed")

    with monkeypatch.context() as fault:
        fault.setattr(scratch, "keepalive_register", fail_register)
        with pytest.raises(KeyboardInterrupt if cancel else OSError):
            sysprompt_cache._sysprompt_file("prompt")
    assert paths and all(not path.exists() for path in paths)
    assert sysprompt_cache._sysprompt_dir is None
    assert not scratch._keepalive_paths


@pytest.mark.parametrize("mode", [0o755, 0o777])
def test_private_directory_validation_failure_reclaims_allocation(sysprompt_cache, monkeypatch, mode):
    from core.run import scratch
    allocate = scratch.scratch_dir
    paths = []

    @contextmanager
    def wrong_mode(*args, **kwargs):
        with allocate(*args, **kwargs) as path:
            paths.append(path)
            path.chmod(mode)
            yield path

    with monkeypatch.context() as fault:
        fault.setattr(scratch, "scratch_dir", wrong_mode)
        with pytest.raises(AssertionError, match="0700"):
            sysprompt_cache._sysprompt_file("prompt")
    assert paths and all(not path.exists() for path in paths)
    assert sysprompt_cache._sysprompt_dir is None


def test_unregister_failure_still_removes_tree_and_can_retry(sysprompt_cache, monkeypatch):
    from core.run import scratch
    path = sysprompt_cache._sysprompt_file("prompt")

    def fail_unregister(path):
        raise OSError("unregister failed")

    with monkeypatch.context() as fault:
        fault.setattr(scratch, "keepalive_unregister", fail_unregister)
        sysprompt_cache._cleanup_sysprompt_cache()
        assert not path.parent.exists()
        assert sysprompt_cache._sysprompt_dir == path.parent
    sysprompt_cache._cleanup_sysprompt_cache()
    assert sysprompt_cache._sysprompt_dir is None
    assert not scratch._keepalive_paths


def test_reuse_after_failed_cleanup_restores_keepalive(sysprompt_cache, monkeypatch):
    from core.run import scratch
    path = sysprompt_cache._sysprompt_file("prompt")
    with monkeypatch.context() as fault:
        fault.setattr(sysprompt_cache, "rmtree_hardened", lambda path: False)
        sysprompt_cache._cleanup_sysprompt_cache()
    assert str(path.parent) not in scratch._keepalive_paths
    assert sysprompt_cache._sysprompt_file("prompt") == path
    assert str(path.parent) in scratch._keepalive_paths


@pytest.mark.parametrize("mode", [0o644, 0o640, 0o400])
def test_cache_hit_restores_exact_private_mode(sysprompt_cache, mode):
    path = sysprompt_cache._sysprompt_file("prompt")
    path.chmod(mode)
    again = sysprompt_cache._sysprompt_file("prompt")
    assert again.stat().st_mode & 0o777 == 0o600
    assert again.read_text() == "prompt"


def test_cache_hit_replaces_hard_link_without_touching_other_name(sysprompt_cache, tmp_path):
    path = sysprompt_cache._sysprompt_file("prompt")
    other = tmp_path / "other-name"
    os.link(path, other)
    os.utime(other, ns=(1_600_000_000_000_000_000,) * 2)
    before = other.stat().st_mtime_ns
    again = sysprompt_cache._sysprompt_file("prompt")
    assert again.stat().st_nlink == 1
    assert other.read_text() == "prompt"
    assert other.stat().st_mtime_ns == before


@pytest.mark.parametrize("shape", ["mode", "symlink"])
def test_replaced_or_public_cache_directory_is_refused(sysprompt_cache, tmp_path, shape):
    path = sysprompt_cache._sysprompt_file("prompt")
    root = path.parent
    parked = root.with_name(root.name + "-parked")
    external = tmp_path / "external-dir"
    external.mkdir()
    (external / "keep").write_text("external data")
    try:
        if shape == "mode":
            root.chmod(0o755)
        else:
            root.rename(parked)
            root.symlink_to(external, target_is_directory=True)
        with pytest.raises(OSError, match="not private"):
            sysprompt_cache._sysprompt_file("another prompt")
        assert list(external.iterdir()) == [external / "keep"]
    finally:
        if parked.exists():
            root.unlink(missing_ok=True)
            parked.rename(root)
        elif root.is_dir():
            root.chmod(0o700)


@pytest.mark.parametrize("cancel", [False, True])
def test_atomic_publication_failure_leaves_no_partial_file(sysprompt_cache, monkeypatch, cancel):
    from core import atomic_fs
    isolated_os = types.ModuleType("owned_atomic_os")
    isolated_os.__dict__.update(vars(os))

    def fail_replace(*args, **kwargs):
        if cancel:
            raise KeyboardInterrupt("publication cancelled")
        raise OSError("publication failed")

    isolated_os.replace = fail_replace
    with monkeypatch.context() as fault:
        fault.setattr(atomic_fs, "os", isolated_os)
        with pytest.raises(KeyboardInterrupt if cancel else OSError):
            sysprompt_cache._sysprompt_file("prompt")
    assert not sysprompt_cache._sysprompt_cache
    assert sysprompt_cache._sysprompt_dir is not None
    assert not list(sysprompt_cache._sysprompt_dir.iterdir())


def test_concurrent_cleanup_and_creation_keep_new_owner(sysprompt_cache, monkeypatch):
    old = sysprompt_cache._sysprompt_file("old")
    entered, release = threading.Event(), threading.Event()
    remove = sysprompt_cache.rmtree_hardened
    errors, paths = [], []

    def remove_slowly(path):
        entered.set()
        assert release.wait(3), "cleanup was not released"
        return remove(path)

    def cleanup():
        try:
            sysprompt_cache._cleanup_sysprompt_cache()
        except BaseException as exc:
            errors.append(exc)

    def create():
        try:
            paths.append(sysprompt_cache._sysprompt_file("new"))
        except BaseException as exc:
            errors.append(exc)

    monkeypatch.setattr(sysprompt_cache, "rmtree_hardened", remove_slowly)
    workers = [threading.Thread(target=cleanup), threading.Thread(target=create)]
    try:
        workers[0].start()
        assert entered.wait(3), "cleanup did not start"
        workers[1].start()
    finally:
        release.set()
        for worker in workers:
            if worker.ident is not None:
                worker.join(timeout=3)
    assert not any(worker.is_alive() for worker in workers), "owned workers did not exit"
    assert not errors
    assert len(paths) == 1 and paths[0].read_text() == "new"
    assert paths[0].parent != old.parent
    assert sysprompt_cache._sysprompt_dir == paths[0].parent


def test_cleanup_cancellation_still_attempts_removal(sysprompt_cache, monkeypatch):
    from core.run import scratch
    path = sysprompt_cache._sysprompt_file("prompt")

    def cancel(path):
        raise KeyboardInterrupt("cleanup cancelled")

    with monkeypatch.context() as fault:
        fault.setattr(scratch, "keepalive_unregister", cancel)
        with pytest.raises(KeyboardInterrupt, match="cleanup cancelled"):
            sysprompt_cache._cleanup_sysprompt_cache()
    assert not path.parent.exists()
    sysprompt_cache._cleanup_sysprompt_cache()


def test_failed_setup_keeps_precedence_over_cleanup_cancellation(sysprompt_cache, monkeypatch):
    from core.run import scratch
    paths = []

    def fail_register(path):
        paths.append(path)
        raise ValueError("primary setup failure")

    def cancel_cleanup(path):
        raise KeyboardInterrupt("secondary cancellation")

    with monkeypatch.context() as fault:
        fault.setattr(scratch, "keepalive_register", fail_register)
        fault.setattr(scratch, "keepalive_unregister", cancel_cleanup)
        with pytest.raises(ValueError, match="primary setup failure"):
            sysprompt_cache._sysprompt_file("prompt")
    assert paths and all(not path.exists() for path in paths)
    sysprompt_cache._cleanup_sysprompt_cache()


@pytest.mark.integration
@pytest.mark.skipif(not hasattr(os, "fork"), reason="requires POSIX fork")
def test_forked_child_replaces_inherited_locked_mutex(tmp_path):
    import subprocess
    import sys
    from pathlib import Path
    from core.testing.processes import reap_on_exit

    temporary = tmp_path / "fork-tmp"
    temporary.mkdir()
    code = r"""
import os
import select
import signal
from core.llm import cc_adapter as adapter
from core.run import scratch

# The fixture exercises the cache mutex/PID contract, not the ticker.
scratch.keepalive_register = lambda path: None
scratch.keepalive_unregister = lambda path: None
parent = adapter._sysprompt_file("parent")
lock = adapter._sysprompt_lock
reader, writer = os.pipe()
lock.acquire()
pid = os.fork()
if pid == 0:
    os.close(reader)
    try:
        child = adapter._sysprompt_file("child")
        assert child.parent != parent.parent and parent.exists()
        adapter._cleanup_sysprompt_cache()
        assert not child.parent.exists() and parent.exists()
        os.write(writer, b"ok")
    except BaseException as error:
        os.write(writer, repr(error).encode()[:512])
    finally:
        os._exit(0)
os.close(writer)
reaped = False
try:
    ready = select.select([reader], [], [], 5)[0]
    assert ready, "child blocked behind the inherited cache mutex"
    payload = os.read(reader, 512)
    _, status = os.waitpid(pid, 0)
    reaped = True
    assert payload == b"ok", payload
    assert os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0
    assert parent.read_text() == "parent"
finally:
    if not reaped:
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        os.waitpid(pid, 0)
    os.close(reader)
    lock.release()
    adapter._cleanup_sysprompt_cache()
    assert not parent.parent.exists()
"""
    env = dict(os.environ, TMPDIR=str(temporary))
    with reap_on_exit(subprocess.Popen(
        [sys.executable, "-c", code], cwd=Path(__file__).resolve().parents[3],
        env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, start_new_session=True,
    ), process_group=True) as process:
        stdout, stderr = process.communicate(timeout=15)
        assert process.returncode == 0, (stdout, stderr)
    assert not list(temporary.glob("cc-sysprompt-*"))
