"""Cgroup control protocol checks; these do not claim kernel enforcement."""
import os

import pytest

from core.security import cgroup_scope


@pytest.fixture
def scope(tmp_path):
    node = tmp_path / 'scope'
    node.mkdir()
    (node / 'cgroup.events').write_text('populated 0\nfrozen 0\n')
    (node / 'cgroup.procs').touch()
    (node / 'cgroup.kill').touch()
    result = cgroup_scope.Scope(node, os.open(node, os.O_RDONLY | os.O_DIRECTORY),
                               os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY))
    try:
        yield result
    finally:
        result.close()


def test_attach_requires_open_admission_and_positive_exact_pid(scope):
    scope.attach(123)
    assert (scope.path / 'cgroup.procs').read_text() == '123'
    scope.close_admission()
    for pid in (124, True, 0, -1):
        with pytest.raises(ValueError):
            scope.attach(pid)
    assert (scope.path / 'cgroup.procs').read_text() == '123'


def test_teardown_requires_closed_admission(scope):
    with pytest.raises(ValueError):
        scope.stop()
    scope.close_admission()
    scope.stop()
    assert not scope.populated()


def test_populated_timeout_is_not_success(scope):
    (scope.path / 'cgroup.events').write_text('populated 1\n')
    scope.close_admission()
    with pytest.raises(TimeoutError):
        scope.stop(timeout=0)
    assert (scope.path / 'cgroup.kill').read_text() == '1'
    with pytest.raises(ValueError):
        scope.release()


@pytest.mark.parametrize('events', ['frozen 0\n', 'populated 2\n', 'populated\n', 'x' * 16385])
def test_invalid_events_do_not_prove_emptiness(scope, events):
    (scope.path / 'cgroup.events').write_text(events)
    with pytest.raises(ValueError):
        scope.populated()


def test_arbitrary_directory_cannot_be_used_as_a_cgroup(tmp_path):
    with pytest.raises(ValueError):
        cgroup_scope.Scope.create(tmp_path)


def test_missing_mount_or_delegation_is_an_explicit_failure(monkeypatch, tmp_path):
    monkeypatch.setattr(cgroup_scope, 'CGROUP_ROOT', tmp_path / 'unavailable')
    with pytest.raises(OSError):
        cgroup_scope.current_group()


def test_closing_admission_waits_for_an_inflight_attach(scope, monkeypatch):
    import threading
    entered, proceed, closed = threading.Event(), threading.Event(), threading.Event()
    original = cgroup_scope._write
    def write(node, name, data):
        entered.set()
        assert proceed.wait(2)
        original(node, name, data)
    monkeypatch.setattr(cgroup_scope, '_write', write)
    attaching = threading.Thread(target=scope.attach, args=(123,))
    def close():
        scope.close_admission()
        closed.set()
    closing = threading.Thread(target=close)
    attaching.start()
    try:
        assert entered.wait(2)
        closing.start()
        assert not closed.wait(.05)
    finally:
        proceed.set()
        attaching.join(2)
        if closing.ident is not None:
            closing.join(2)
    assert closed.is_set()
    assert (scope.path / 'cgroup.procs').read_text() == '123'
    with pytest.raises(ValueError):
        scope.attach(124)
