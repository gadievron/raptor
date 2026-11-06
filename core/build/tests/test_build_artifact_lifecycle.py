"""Build scratch ownership starts at creation and ends after consumer use."""

import os
import tempfile

import pytest

from core.build import build_detector as bd
from core.testing.restricted_tree import restricted_tree


import core.build.build_detector as _os_fault_consumer
from core.testing.module_bindings import patch_module_attribute


@pytest.fixture
def detector(tmp_path, monkeypatch):
    monkeypatch.setattr(
        bd.BuildDetector,
        "_detect_build_params",
        lambda *a: ([tmp_path / "a.c"], "gcc", [], []),
    )
    monkeypatch.setattr(
        bd.BuildDetector, "detect_missing_config_headers", lambda *a: []
    )
    monkeypatch.setattr(bd.BuildDetector, "_write_build_script", lambda *a: None)
    monkeypatch.setattr(bd.BuildDetector, "_dry_run", lambda *a, **kw: [])
    return bd.BuildDetector(tmp_path)


@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("stage", ["script_create", "script_close", "result"])
def test_creation_and_transfer_failures_leave_no_artifacts(
    detector, tmp_path, monkeypatch, error, stage
):
    failure = error("primary failure")

    def fail(*args, **kwargs):
        raise failure

    if stage == "script_create":
        monkeypatch.setattr(tempfile, "mkstemp", fail)
    elif stage == "script_close":
        close = os.close

        failed = False

        def close_then_fail(fd):
            nonlocal failed
            close(fd)
            if not failed:
                failed = True
                raise failure

        patch_module_attribute(monkeypatch, _os_fault_consumer, "os", "close", close_then_fail)
    else:
        monkeypatch.setattr(bd, "BuildSystem", fail)
    with pytest.raises(error) as caught:
        detector.synthesise_build_command("cpp")
    assert caught.value is failure
    assert list(tmp_path.glob(".raptor_build_*")) == []


@pytest.mark.parametrize("mode", [0, 0o500, 0o555])
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt, SystemExit])
def test_failed_build_reclaims_restricted_output(
    detector, tmp_path, monkeypatch, mode, error
):
    failure = error("build failed")

    # Keep permissions restricted through the producer's cleanup, then restore
    # only for pytest if the implementation regresses.
    from contextlib import ExitStack

    stack = ExitStack()

    def restricted_run(script, **kwargs):
        build_dir = next(p for p in tmp_path.glob(".raptor_build_*") if p.is_dir())
        stack.enter_context(restricted_tree(build_dir / "objects", mode))
        raise failure

    monkeypatch.setattr(detector, "_dry_run", restricted_run)
    try:
        with pytest.raises(error) as caught:
            detector.synthesise_build_command("cpp")
        assert caught.value is failure
        assert list(tmp_path.glob(".raptor_build_*")) == []
    finally:
        stack.close()


@pytest.mark.parametrize(
    "kind", ["file", "directory", "symlink", "dangling", "fifo", "socket", "missing"]
)
def test_cleanup_handles_each_owned_node_without_following_links(tmp_path, kind):
    import socket
    from core.build.artifacts import cleanup_build_paths

    outside = tmp_path / "outside"
    outside.mkdir()
    payload = outside / "keep"
    payload.write_text("keep")
    owned = tmp_path / "owned"
    sock = None
    if kind == "file":
        owned.write_text("script")
    elif kind == "directory":
        owned.mkdir()
        (owned / "object").write_text("output")
        (owned / "external").symlink_to(outside, target_is_directory=True)
    elif kind in ("symlink", "dangling"):
        owned.symlink_to(
            outside if kind == "symlink" else tmp_path / "absent",
            target_is_directory=True,
        )
    elif kind == "fifo":
        os.mkfifo(owned)
    elif kind == "socket":
        sock = socket.socket(socket.AF_UNIX)
        sock.bind(str(owned))
    paths = [owned]
    try:
        cleanup_build_paths(paths)
        assert paths == []
        assert not os.path.lexists(owned)
        assert payload.read_text() == "keep"
        cleanup_build_paths(paths)
    finally:
        if sock:
            sock.close()


@pytest.mark.parametrize("operation", ["stat", "unlink", "rmtree"])
def test_one_cleanup_failure_does_not_skip_other_paths_and_can_be_retried(
    tmp_path, monkeypatch, operation
):
    from pathlib import Path
    from core.build import artifacts

    blocked = tmp_path / "blocked"
    other = tmp_path / "other"
    if operation == "rmtree":
        blocked.mkdir()
    else:
        blocked.write_text("first")
    other.write_text("second")
    paths = [blocked, other]
    with monkeypatch.context() as fault:
        if operation == "rmtree":
            fault.setattr(artifacts, "rmtree_hardened", lambda path: False)
        else:
            method = Path.lstat if operation == "stat" else Path.unlink

            def fail(path, *args, **kwargs):
                if path == blocked:
                    raise PermissionError("busy")
                return method(path, *args, **kwargs)

            fault.setattr(Path, "lstat" if operation == "stat" else "unlink", fail)
        artifacts.cleanup_build_paths(paths)
    assert paths == [blocked]
    assert not other.exists()
    artifacts.cleanup_build_paths(paths)
    assert paths == []
    assert not blocked.exists()
