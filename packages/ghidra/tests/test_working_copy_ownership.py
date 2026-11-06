"""Working copies remain protected only while their database owners need them."""

import logging
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
from types import ModuleType, SimpleNamespace
from unittest.mock import Mock

import pytest

from core.atomic_fs import rmtree_hardened
from core.build import artifacts
from core.run import scratch
from packages.ghidra import headless, project_util, server, session


@pytest.fixture
def owned(tmp_path, monkeypatch, caplog, _owned_ghidra_keepalive):
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    source = tmp_path / "source"
    source.mkdir()
    gpr = source / "owned.gpr"
    gpr.write_text('<PROJECT NAME="owned"/>')
    rep = source / "owned.rep"
    rep.mkdir()
    (rep / "project.prp").write_text('<ROOT><STATE NAME="OWNER" VALUE="old-owner"/></ROOT>')
    binary = tmp_path / "input.bin"
    binary.write_bytes(b"owned binary fixture")
    destination = tmp_path / "destination"
    destination.mkdir()
    (destination / "operator.txt").write_text("operator data")
    monkeypatch.setenv("RAPTOR_REGISTRY_HOME", str(tmp_path / "state"))
    monkeypatch.setenv("GHIDRA_INSTALL_DIR", str(tmp_path / "install"))
    logger = logging.getLogger("test.ghidra-working-copy-owned")
    monkeypatch.setattr(logger, "handlers", [caplog.handler])
    monkeypatch.setattr(logger, "propagate", False)
    for module in (session, server, headless, project_util, scratch, artifacts):
        monkeypatch.setattr(module, "logger", logger)
    allocated = []
    def allocate(**kwargs):
        path = Path(tempfile.mkdtemp(**{**kwargs, "dir": runtime}))
        allocated.append(path)
        return str(path)
    for module in (session, server):
        local = SimpleNamespace(**vars(tempfile))
        local.mkdtemp = allocate
        monkeypatch.setattr(module, "tempfile", local)
    monkeypatch.setattr(session.GhidraSession, "ensure_jvm", classmethod(lambda cls: None))
    monkeypatch.setattr(server, "pyghidra_available", lambda: True)
    monkeypatch.setattr(server.GhidraServer, "_boot", lambda self: None)
    project = Mock(spec=["close"])
    program = Mock(spec=["release", "getLanguage"])
    program.getLanguage.return_value.getLanguageDescription.return_value.getProcessor.return_value = "owned"
    consumer = object()
    api = ModuleType("pyghidra.api")
    api.open_project = lambda *args: project
    api.consume_program = lambda *args: (program, consumer)
    package = ModuleType("pyghidra")
    package.api = api
    monkeypatch.setitem(sys.modules, "pyghidra", package)
    monkeypatch.setitem(sys.modules, "pyghidra.api", api)
    instances = []
    def new_session():
        owner = session.GhidraSession()
        instances.append(owner)
        return owner
    def new_server():
        owner = server.GhidraServer(gpr)
        instances.append(owner)
        return owner
    try:
        yield SimpleNamespace(runtime=runtime, gpr=gpr, binary=binary, destination=destination,
                              project=project, program=program, api=api, consumer=consumer,
                              pins=_owned_ghidra_keepalive, allocated=allocated,
                              new_session=new_session, new_server=new_server)
    finally:
        for owner in instances:
            if isinstance(owner, session.GhidraSession):
                owner.close(preserve_error=True)
            else:
                owner.stop(preserve_error=True)
        assert rmtree_hardened(runtime)
        assert rmtree_hardened(destination)


@pytest.mark.parametrize("phase", ["registration", "copy", "project", "program", "metadata"])
@pytest.mark.parametrize("error", [RuntimeError, KeyboardInterrupt, SystemExit])
def test_open_failure_releases_every_acquired_owner(owned, monkeypatch, phase, error):
    owner = owned.new_session()
    failure = error("open stopped")
    def fail(*args, **kwargs):
        raise failure
    if phase == "registration":
        register = session.keepalive_register
        def register_then_fail(path):
            register(path)
            raise failure
        monkeypatch.setattr(session, "keepalive_register", register_then_fail)
    elif phase == "copy":
        monkeypatch.setattr(session, "prepare_working_copy", fail)
    elif phase == "project":
        monkeypatch.setattr(owned.api, "open_project", fail)
    elif phase == "program":
        monkeypatch.setattr(owned.api, "consume_program", fail)
    else:
        owned.program.getLanguage.side_effect = failure
    with pytest.raises((error, session.GhidraSessionError)) as caught:
        owner.open(owned.gpr, program_name="owned")
    assert caught.value is failure or caught.value.__cause__ is failure
    assert owner._work_dir is None and owner._project is None and owner._program is None
    assert not list(owned.runtime.iterdir())
    assert not owned.pins
    assert owned.gpr.read_text() == '<PROJECT NAME="owned"/>'


@pytest.mark.parametrize("phase", ["decompiler", "program", "project"])
@pytest.mark.parametrize("error", [KeyboardInterrupt, SystemExit])
def test_interrupted_close_keeps_live_children_protected_for_retry(owned, monkeypatch, phase, error):
    owner = owned.new_session()
    owner.open(owned.gpr, program_name="owned")
    decompiler = Mock(spec=["dispose"])
    owner._decomp = decompiler
    method = {"decompiler": decompiler.dispose, "program": owned.program.release,
              "project": owned.project.close}[phase]
    failure = error("close interrupted")
    with monkeypatch.context() as fault:
        fault.setattr(method, "side_effect", failure)
        with pytest.raises(error) as caught:
            owner.close()
        assert caught.value is failure
        assert owner._work_dir is not None
        assert str(owner._work_dir) in owned.pins
        assert Path(owner._work_dir).is_dir()
        if phase == "decompiler":
            owned.program.release.assert_not_called()
            owned.project.close.assert_not_called()
        elif phase == "program":
            owned.project.close.assert_not_called()
    owner.close()
    assert owner._work_dir is None
    assert not owned.pins
    assert not list(owned.runtime.iterdir())


@pytest.mark.parametrize("error", [RuntimeError, KeyboardInterrupt, SystemExit])
def test_open_error_is_not_replaced_by_failed_program_release(owned, monkeypatch, error):
    owner = owned.new_session()
    failure = error("metadata failed")
    owned.program.getLanguage.side_effect = failure
    with monkeypatch.context() as fault:
        fault.setattr(owned.program.release, "side_effect", KeyboardInterrupt("secondary close"))
        with pytest.raises(error) as caught:
            owner.open(owned.gpr, program_name="owned")
        assert caught.value is failure
        assert owner._program is owned.program
        assert owner._work_dir is not None and str(owner._work_dir) in owned.pins
    owner.close()
    assert not owned.pins


def test_context_body_error_keeps_precedence_over_close_interrupt(owned, monkeypatch):
    owner = owned.new_session()
    failure = RuntimeError("body failed")
    with monkeypatch.context() as fault:
        fault.setattr(owned.program.release, "side_effect", KeyboardInterrupt("secondary close"))
        with pytest.raises(RuntimeError) as caught:
            with owner:
                owner.open(owned.gpr, program_name="owned")
                raise failure
        assert caught.value is failure
        assert owner._work_dir is not None and str(owner._work_dir) in owned.pins
    owner.close()
    assert not owned.pins


@pytest.mark.parametrize("owner_kind", ["session", "server"])
def test_closed_database_cleanup_failure_unpins_and_retries(owned, monkeypatch, owner_kind):
    owner = owned.new_session() if owner_kind == "session" else owned.new_server()
    if owner_kind == "session":
        owner.open(owned.gpr, program_name="owned")
        close, module = owner.close, session
    else:
        owner.start()
        close, module = owner.stop, server
    root = Path(owner._work_dir)
    with monkeypatch.context() as fault:
        fault.setattr(module, "rmtree_hardened", lambda path: False)
        close()
    assert root.is_dir() and owner._work_dir is not None
    assert str(root) not in owned.pins
    close()
    assert not root.exists() and owner._work_dir is None


@pytest.mark.parametrize("error", [RuntimeError, KeyboardInterrupt, SystemExit])
def test_startup_error_survives_shutdown_transport_failure(owned, monkeypatch, error):
    owner = owned.new_server()
    failure = error("boot failed")
    def fail():
        raise failure
    def fail_disconnect():
        raise KeyboardInterrupt("secondary disconnect")
    monkeypatch.setattr(owner, "_boot", fail)
    with monkeypatch.context() as fault:
        fault.setattr(owner, "_disconnect", fail_disconnect)
        with pytest.raises(error) as caught:
            owner.start()
        assert caught.value is failure
    assert owner._work_dir is None
    assert not owned.pins


@pytest.mark.parametrize("error", [RuntimeError, KeyboardInterrupt, SystemExit])
def test_disconnect_attempts_both_closers_and_retains_failed_object(owned, monkeypatch, error):
    owner = owned.new_server()
    stream, sock = Mock(spec=["close"]), Mock(spec=["close"])
    owner._stream, owner._sock = stream, sock
    failure = error("close failed")
    with monkeypatch.context() as fault:
        fault.setattr(stream.close, "side_effect", failure)
        with pytest.raises(error) as caught:
            owner._disconnect()
        assert caught.value is failure
        assert owner._stream is stream and owner._sock is None
        sock.close.assert_called_once()
    owner._disconnect()
    assert owner._stream is None


@pytest.mark.parametrize("retain_first_removal", [False, True])
def test_stopped_live_worker_reclaims_working_copy_when_it_finishes(owned, monkeypatch, retain_first_removal):
    import core.sandbox as sandbox
    owner = owned.new_server()
    owner.start()
    root = owner._work_dir
    ready, release = threading.Event(), threading.Event()
    remove = server.rmtree_hardened
    attempts = []
    def remove_once(path):
        attempts.append(path)
        if retain_first_removal and len(attempts) == 1:
            return False
        return remove(path)
    monkeypatch.setattr(server, "rmtree_hardened", remove_once)
    def worker(*args, **kwargs):
        ready.set()
        assert release.wait(10), "controlled worker was never released"
        return subprocess.CompletedProcess([], 0, "", "")
    monkeypatch.setattr(sandbox, "run", worker)
    monkeypatch.setattr(server, "_SHUTDOWN_GRACE_S", 0)
    monkeypatch.setattr(server, "_install_read_paths", lambda path: [])
    monkeypatch.setattr(owner, "_boot_wait_socketpair", lambda parent, deadline: parent.close())
    try:
        owner._boot_transport(use_pathname=False)
        assert ready.wait(3), "controlled worker did not enter"
        owner.stop()
        assert owner._thread.is_alive()
        assert owner._cleanup_pending
        assert root.is_dir() and str(root) in owned.pins
    finally:
        release.set()
        if owner._thread is not None:
            owner._thread.join(timeout=5)
            assert not owner._thread.is_alive(), "controlled worker did not exit"
    if retain_first_removal:
        assert owner._work_dir == root and owner._cleanup_pending
        assert root.exists() and str(root) not in owned.pins
        owner.stop()
    assert owner._work_dir is None and owner._work_gpr is None
    assert not root.exists()
    assert not owned.pins


@pytest.mark.parametrize("owner_kind", ["session", "server"])
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
def test_failed_unregistration_retains_cleanup_obligation_after_tree_removal(owned, monkeypatch, owner_kind, error):
    owner = owned.new_session() if owner_kind == "session" else owned.new_server()
    if owner_kind == "session":
        owner.open(owned.gpr, program_name="owned")
        close = owner.close
    else:
        owner.start()
        close = owner.stop
    root = Path(owner._work_dir)
    failure = error("unregister failed")
    def fail(path):
        raise failure
    with monkeypatch.context() as fault:
        fault.setattr(project_util, "keepalive_unregister", fail)
        if error is KeyboardInterrupt:
            with pytest.raises(error) as caught:
                close()
            assert caught.value is failure
        else:
            close()
        assert not root.exists()
        assert owner._work_dir is not None and str(root) in owned.pins
    close()
    assert owner._work_dir is None
    assert not owned.pins



def test_server_context_body_error_survives_disconnect_interruption(owned, monkeypatch):
    owner = owned.new_server()
    failure = RuntimeError("body stopped")
    def disconnect():
        raise KeyboardInterrupt("secondary disconnect")
    with monkeypatch.context() as fault:
        fault.setattr(owner, "_disconnect", disconnect)
        with pytest.raises(RuntimeError) as caught:
            with owner:
                assert str(owner._work_dir) in owned.pins
                raise failure
        assert caught.value is failure
    assert owner._work_dir is None and not owned.pins


def test_shutdown_interruption_still_closes_parent_transport(owned, monkeypatch):
    import socket
    owner = owned.new_server()
    owner.start()
    left, right = socket.socketpair()
    with left, right:
        stream = Mock(spec=["close"])
        owner._stream, owner._sock = stream, left
        failure = KeyboardInterrupt("shutdown interrupted")
        def shutdown(*args, **kwargs):
            raise failure
        monkeypatch.setattr(owner, "_request", shutdown)
        with pytest.raises(KeyboardInterrupt) as caught:
            owner.stop()
        assert caught.value is failure
        stream.close.assert_called_once()
        assert left.fileno() == -1
        assert owner._stream is None and owner._sock is None
        assert owner._work_dir is None and not owned.pins
