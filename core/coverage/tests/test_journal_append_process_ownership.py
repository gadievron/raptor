"""Native process ownership controls for the actual journal append caller."""
from types import FunctionType, ModuleType
import subprocess

import pytest

from core.coverage.tests import test_journal_append as native
from core.testing.processes import reap_on_exit
from core.testing.state_isolation import pin_user_state_dirs


def _exercise(tmp_path, monkeypatch, operation, position, error, after=False):
    pin_user_state_dirs(monkeypatch, tmp_path / "user")
    children = []
    failure = error("owned appender boundary fault") if error else None
    fired = False
    original = native.TestConcurrentAppend.test_cross_process_large_appends_never_interleave
    native_popen = subprocess.Popen

    class Child(native_popen):
        def communicate(self, *args, **kwargs):
            nonlocal fired
            if operation == "communicate" and children.index(self) == position and not fired:
                fired = True
                if after:
                    super().communicate(*args, **kwargs)
                raise failure
            return super().communicate(*args, **kwargs)

    def popen(*args, **kwargs):
        nonlocal fired
        if operation == "spawn" and len(children) == position:
            fired = True
            raise failure
        child = Child(*args, **kwargs)
        children.append(child)
        return child

    private = ModuleType("subprocess")
    vars(private).update(vars(subprocess))
    private.Popen = popen
    body = FunctionType(original.__code__, {**original.__globals__, "subprocess": private})
    try:
        if error:
            with pytest.raises(error) as caught:
                body(native.TestConcurrentAppend(), tmp_path / "journal")
            assert caught.value is failure
            assert fired
        else:
            body(native.TestConcurrentAppend(), tmp_path / "journal")
        assert len(children) == (position if operation == "spawn" else 4)
        for child in children:
            assert child.returncode is not None
            assert child.stdout is not None and child.stdout.closed
            assert child.stderr is not None and child.stderr.closed
        assert subprocess.Popen is native_popen
        assert native.TestConcurrentAppend.test_cross_process_large_appends_never_interleave is original
    finally:
        for child in children:
            with reap_on_exit(child):
                pass
            assert child.returncode is not None
            assert child.stdout.closed and child.stderr.closed


@pytest.mark.parametrize("position", [0, 1, 3])
@pytest.mark.parametrize("error", [RuntimeError, KeyboardInterrupt, SystemExit])
def test_partial_spawn_retires_prior_children(tmp_path, monkeypatch, position, error):
    _exercise(tmp_path, monkeypatch, "spawn", position, error)


@pytest.mark.parametrize("position", [0, 1, 3])
@pytest.mark.parametrize("error", [RuntimeError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("after", [False, True])
def test_communication_fault_retires_children(tmp_path, monkeypatch, position, error, after):
    _exercise(tmp_path, monkeypatch, "communicate", position, error, after)


def test_native_process_positive_control(tmp_path, monkeypatch):
    _exercise(tmp_path, monkeypatch, None, None, None)
