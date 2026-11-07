"""Audit capture owns producers and helper threads until cleanup is confirmed."""

import atexit
import json
import subprocess
import sys
import threading
from types import ModuleType, SimpleNamespace
from unittest.mock import Mock

import pytest

from core.sandbox import evidence, seatbelt_audit as audit
from core.testing.state_isolation import pin_user_state_dirs


def private_module(module):
    private = ModuleType(module.__name__)
    vars(private).update(vars(module))
    return private


@pytest.fixture
def case(tmp_path, monkeypatch, request):
    pin_user_state_dirs(monkeypatch, tmp_path / "state")
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    callbacks, processes, callers, releases, errors = [], [], [], [], []
    workers = []
    threads = private_module(audit.threading)

    def construct(*args, **kwargs):
        thread = threading.Thread(*args, **kwargs)
        workers.append(thread)
        return thread

    threads.Thread = construct
    monkeypatch.setattr(audit, "threading", threads)
    exits = private_module(atexit)
    exits.register = lambda callback: callbacks.append(callback)
    exits.unregister = lambda callback: callbacks.remove(callback)
    monkeypatch.setattr(audit, "atexit", exits, raising=False)
    module = private_module(subprocess)
    native_popen = subprocess.Popen

    def launch(*args, **kwargs):
        proc = native_popen(
            [sys.executable, "-u", "-c", "import time; time.sleep(60)"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            text=True, encoding="utf-8", start_new_session=True,
        )
        processes.append(proc)
        return proc

    module.Popen = launch
    monkeypatch.setattr(audit, "subprocess", module)
    native = private_module(audit.os)
    native.getsid = lambda pid: pid
    monkeypatch.setattr(audit, "os", native)
    owner = audit.LogStreamer(
        tmp_path / "run", observe_mode=True, observe_nonce="owned",
        get_ppid=lambda pid: None, getpgid=lambda pid: pid,
        list_pid_ppids=lambda: [], lineage_poll_interval=0.001,
    )
    monkeypatch.setattr(owner, "_warm_up_until_attached", lambda: True)

    def spawn(call):
        def run():
            try:
                call()
            except BaseException as error:
                errors.append(error)
        thread = threading.Thread(target=run)
        callers.append(thread)
        thread.start()
        return thread

    def finish():
        for event in releases:
            event.set()
        for thread in callers:
            thread.join(5)
            assert not thread.is_alive(), "owned lifecycle caller did not finish"
        try:
            owner.stop(drain_timeout=0)
        finally:
            # Independent handles keep a faulty implementation from
            # abandoning real children or blocked reader threads in tests.
            for proc in processes:
                if proc.poll() is None:
                    proc.kill()
                proc.wait(timeout=5)
            for thread in workers:
                if thread is not None and thread.ident is not None:
                    thread.join(5)
                    assert not thread.is_alive(), "owned capture thread did not finish"
            for proc in processes:
                if proc.stdout is not None:
                    proc.stdout.close()
        assert not callbacks, "capture left an owned exit callback registered"

    request.addfinalizer(finish)
    return SimpleNamespace(owner=owner, callbacks=callbacks, processes=processes,
                           releases=releases, errors=errors, spawn=spawn, launch=launch)


def summary(case):
    path = case.owner._run_dir / evidence.AUDIT_SUBDIR / audit.OBSERVE_FILE
    data = path.read_bytes()
    rows = [json.loads(line) for line in data.splitlines()]
    return data, rows[-1]


@pytest.mark.parametrize("failure", [OSError, subprocess.TimeoutExpired], ids=["io", "timeout"])
def test_unconfirmed_producer_remains_retryable(case, monkeypatch, failure):
    owner = case.owner
    owner.start()
    proc = case.processes[0]
    error = failure("owned wait", 0) if failure is subprocess.TimeoutExpired else failure("owned wait")
    with monkeypatch.context() as patch:
        patch.setattr(proc, "wait", Mock(side_effect=error))
        owner.stop(drain_timeout=0)
        assert owner._capture_closed and not owner._stop_complete
        assert owner._proc is proc and case.callbacks == [owner._stop_at_exit]
        before, tail = summary(case)
        assert tail["producer_reaped"] is False
    owner.stop(drain_timeout=0)
    assert owner._stop_complete and case.callbacks == []
    assert proc.returncode is not None and proc.stdout.closed
    assert summary(case)[0] == before


@pytest.mark.parametrize("kind", [RuntimeError, KeyboardInterrupt], ids=["failure", "cancel"])
def test_failed_startup_retains_unconfirmed_producer(case, monkeypatch, kind):
    owner = case.owner
    original = kind("owned warm-up interrupted")
    with monkeypatch.context() as patch:
        def launch(*args, **kwargs):
            proc = case.launch(*args, **kwargs)
            patch.setattr(proc, "wait", Mock(side_effect=OSError("owned reap unavailable")))
            return proc
        patch.setattr(audit.subprocess, "Popen", launch)
        patch.setattr(owner, "_warm_up_until_attached", Mock(side_effect=original))
        with pytest.raises(kind) as caught:
            owner.start()
        assert caught.value is original
        assert owner._proc is case.processes[0]
        assert not owner._stop_complete and case.callbacks == [owner._stop_at_exit]
        with pytest.raises(RuntimeError, match="started|stopped"):
            owner.start()
        assert len(case.processes) == 1
    owner.stop(drain_timeout=0)
    assert owner._stop_complete and not case.callbacks


def test_start_and_stop_share_lifecycle_lock(case, monkeypatch):
    owner = case.owner
    entered, release, stopping = threading.Event(), threading.Event(), threading.Event()
    case.releases.append(release)

    def launch(*args, **kwargs):
        entered.set()
        assert release.wait(5), "owned producer creation not released"
        return case.launch(*args, **kwargs)

    monkeypatch.setattr(audit.subprocess, "Popen", launch)
    first = case.spawn(owner.start)
    assert entered.wait(5)
    available = owner._stop_lock.acquire(blocking=False)
    if available:
        owner._stop_lock.release()

    def stop():
        stopping.set()
        owner.stop(drain_timeout=0)

    last = case.spawn(stop)
    assert stopping.wait(5)
    release.set()
    first.join(5)
    last.join(5)
    assert not first.is_alive() and not last.is_alive()
    assert not available, "startup did not own the lifecycle lock"
    assert case.errors == []
    assert len(case.processes) == 1
    assert owner._stop_complete and case.processes[0].returncode is not None
    assert not case.callbacks


def test_concurrent_starts_create_one_producer(case, monkeypatch):
    owner = case.owner
    entered, release = threading.Event(), threading.Event()
    case.releases.append(release)

    def launch(*args, **kwargs):
        entered.set()
        assert release.wait(5)
        return case.launch(*args, **kwargs)

    monkeypatch.setattr(audit.subprocess, "Popen", launch)
    first = case.spawn(owner.start)
    assert entered.wait(5)
    available = owner._stop_lock.acquire(blocking=False)
    if available:
        owner._stop_lock.release()
    second = case.spawn(owner.start)
    release.set()
    first.join(5)
    second.join(5)
    assert not first.is_alive() and not second.is_alive()
    assert not available
    assert len(case.processes) == 1
    assert len(case.errors) == 1 and isinstance(case.errors[0], RuntimeError)
    owner.stop(drain_timeout=0)


def test_registration_is_terminal_after_stop(case):
    case.owner.stop(drain_timeout=0)
    with pytest.raises(RuntimeError, match="stopped"):
        case.owner.register_target_pid(123456)
    assert case.owner._lineage_poller is None
    assert not case.callbacks


def test_concurrent_registration_creates_one_poller(case, monkeypatch):
    owner = case.owner
    owner._require_scope = True
    entered, release = threading.Event(), threading.Event()
    case.releases.append(release)
    native_thread = threading.Thread
    created = []
    private = private_module(audit.threading)

    def construct(*args, **kwargs):
        entered.set()
        assert release.wait(5)
        thread = native_thread(*args, **kwargs)
        created.append(thread)
        return thread

    private.Thread = construct
    monkeypatch.setattr(audit, "threading", private)
    first = case.spawn(lambda: owner.register_target_pid(123456))
    assert entered.wait(5)
    available = owner._stop_lock.acquire(blocking=False)
    if available:
        owner._stop_lock.release()
    second = case.spawn(lambda: owner.register_target_pid(123457))
    release.set()
    first.join(5)
    second.join(5)
    try:
        assert not available
        assert case.errors == [] and len(created) == 1
    finally:
        owner.stop(drain_timeout=0)
        for thread in created:
            thread.join(5)
            assert not thread.is_alive()


def test_reader_timeout_retries_cleanup_without_new_summary(case, monkeypatch):
    owner = case.owner
    entered, release = threading.Event(), threading.Event()
    case.releases.append(release)

    def read():
        entered.set()
        assert release.wait(5)

    monkeypatch.setattr(owner, "_read_loop", read)
    owner.start()
    assert entered.wait(5)
    reader = owner._reader
    native_join = reader.join
    with monkeypatch.context() as patch:
        patch.setattr(reader, "join", lambda timeout: None)
        owner.stop(drain_timeout=0)
    before, tail = summary(case)
    assert tail["reader_drained"] is False
    assert not owner._stop_complete and case.callbacks == [owner._stop_at_exit]
    release.set()
    native_join(5)
    assert not reader.is_alive()
    owner.stop(drain_timeout=0)
    assert owner._stop_complete and not case.callbacks
    assert summary(case)[0] == before


def test_lineage_timeout_retries_cleanup_without_new_summary(case, monkeypatch):
    owner = case.owner
    owner._require_scope = True
    entered, release = threading.Event(), threading.Event()
    case.releases.append(release)

    def tree():
        entered.set()
        assert release.wait(5)
        return []

    monkeypatch.setattr(owner, "_list_pid_ppids", tree)
    owner.register_target_pid(123456)
    assert entered.wait(5)
    poller = owner._lineage_poller
    native_join = poller.join
    with monkeypatch.context() as patch:
        patch.setattr(poller, "join", lambda timeout: None)
        owner.stop(drain_timeout=0)
    before, tail = summary(case)
    assert tail["lineage_stopped"] is False
    assert not owner._stop_complete and case.callbacks == [owner._stop_at_exit]
    release.set()
    native_join(5)
    assert not poller.is_alive()
    owner.stop(drain_timeout=0)
    assert owner._stop_complete and not case.callbacks
    assert summary(case)[0] == before


def test_stdout_close_failure_remains_retryable(case, monkeypatch):
    owner = case.owner
    monkeypatch.setattr(owner, "_read_loop", lambda: None)
    owner.start()
    owner._reader.join(5)
    proc = case.processes[0]
    with monkeypatch.context() as patch:
        patch.setattr(proc.stdout, "close", Mock(side_effect=OSError("owned close unavailable")))
        owner.stop(drain_timeout=0)
    before, tail = summary(case)
    assert tail["stdout_closed"] is False
    assert not owner._stop_complete and case.callbacks == [owner._stop_at_exit]
    owner.stop(drain_timeout=0)
    assert proc.stdout.closed and owner._stop_complete and not case.callbacks
    assert summary(case)[0] == before


def test_exit_registration_precedes_process_creation(case, monkeypatch):
    error = RuntimeError("owned registration unavailable")
    monkeypatch.setattr(audit.atexit, "register", Mock(side_effect=error))
    with pytest.raises(RuntimeError) as caught:
        case.owner.start()
    assert caught.value is error
    assert not case.processes and not case.callbacks


@pytest.mark.parametrize("kind", [RuntimeError, KeyboardInterrupt], ids=["failure", "cancel"])
def test_constructor_finishes_before_pid_registration(tmp_path, monkeypatch, kind):
    private = private_module(audit._audit_budget)
    error = kind("owned budget setup failed")
    private.from_cli_state = Mock(side_effect=error)
    monkeypatch.setattr(audit, "_audit_budget", private)
    registration = Mock()
    monkeypatch.setattr(audit.LogStreamer, "register_target_pid", registration)
    with pytest.raises(kind) as caught:
        audit.LogStreamer(tmp_path, target_pid=123456, require_scope=True)
    assert caught.value is error
    registration.assert_not_called()


@pytest.mark.parametrize("kind", [OSError, RuntimeError], ids=["io", "runtime"])
def test_poller_start_failure_flushes_pending_records_and_marks_loss(case, monkeypatch, kind):
    owner = case.owner
    owner._require_scope = True
    record = {"type": "read", "syscall": "open", "path": "/owned/pending",
              "target_pid": 123456, "observe": True, "nonce": "owned"}
    owner._filter_and_append(record)
    assert len(owner._pending) == 1
    private = private_module(audit.threading)
    private.Thread = Mock(side_effect=kind("owned thread creation unavailable"))
    monkeypatch.setattr(audit, "threading", private)
    owner.register_target_pid(123456)
    assert owner._pending == [] and owner._lineage_failed
    owner.stop(drain_timeout=0)
    before, tail = summary(case)
    rows = [json.loads(line) for line in before.splitlines()]
    assert any(row.get("path") == "/owned/pending" for row in rows)
    assert tail["lineage_failed"] is True and owner._stop_complete


@pytest.mark.parametrize("kind", [OSError, RuntimeError], ids=["io", "runtime"])
def test_exited_poller_failure_remains_incomplete(case, monkeypatch, kind):
    owner = case.owner
    owner._require_scope = True
    monkeypatch.setattr(owner, "_list_pid_ppids", Mock(side_effect=kind("owned tree read unavailable")))
    owner.register_target_pid(123456)
    owner._lineage_poller.join(5)
    assert not owner._lineage_poller.is_alive()
    owner.stop(drain_timeout=0)
    tail = summary(case)[1]
    assert tail["lineage_stopped"] is True and tail["lineage_failed"] is True
    assert owner._stop_complete and not case.callbacks


def test_poller_start_cancellation_marks_loss_and_preserves_identity(case, monkeypatch):
    owner = case.owner
    owner._require_scope = True
    original = KeyboardInterrupt("owned poller start cancelled")
    private = private_module(audit.threading)
    private.Thread = Mock(side_effect=original)
    monkeypatch.setattr(audit, "threading", private)
    with pytest.raises(KeyboardInterrupt) as caught:
        owner.register_target_pid(123456)
    assert caught.value is original and owner._lineage_failed
    owner.stop(drain_timeout=0)
    assert summary(case)[1]["lineage_failed"] is True
    assert owner._stop_complete and not case.callbacks


def test_exit_callback_cleans_up_without_mutating_registry(case, monkeypatch):
    owner = case.owner
    owner.start()
    assert len(case.callbacks) == 1
    callback = case.callbacks.pop()  # The exit dispatcher consumes its call.
    with monkeypatch.context() as patch:
        register = Mock(side_effect=AssertionError("exit handler mutated registry"))
        unregister = Mock(side_effect=AssertionError("exit handler mutated registry"))
        patch.setattr(audit.atexit, "register", register)
        patch.setattr(audit.atexit, "unregister", unregister)
        callback()
        register.assert_not_called()
        unregister.assert_not_called()
    assert owner._stop_complete and not owner._exit_registered
    assert case.processes[0].returncode is not None
    assert case.processes[0].stdout.closed
