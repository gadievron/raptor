"""Native pipes remain owned through actual capture fixture setup."""
from contextlib import contextmanager
import os
from types import FunctionType, ModuleType

import pytest

from core.sandbox import _spawn
from core.sandbox.tests import test_capture_post_exit_drain as capture
from core.testing.pipes import pipes_for_setup
from core.testing.tests import test_capture_fd_cleanup as native


def _exercise(monkeypatch, caller, phase=None, error=None, after=False):
    identities, pairs = {}, []
    allocations = records = 0
    failure = error("owned capture setup fault") if error else None
    fired = False
    borrowed_pipe, borrowed_open, borrowed_capture_os = os.pipe, _spawn._open_capture_pipes, capture.os
    original = (native.test_capture_dup_failure_rolls_back_only_current_call if caller == "duplicate"
                else native.test_capture_fixture_closes_retained_fds_on_every_exit)

    def pipe():
        nonlocal allocations, fired
        allocations += 1
        if phase == "allocate" and allocations == 2:
            fired = True
            raise failure
        pair = borrowed_pipe()
        pairs.append(pair)
        for fd in pair:
            stat = os.fstat(fd)
            identities[fd] = (stat.st_dev, stat.st_ino)
        return pair

    private = ModuleType("os")
    vars(private).update(vars(os))
    private.pipe = pipe
    # Same existing setup guard code, with only this consumer's allocator seam.
    guard = pipes_for_setup.__wrapped__
    local_guard = contextmanager(FunctionType(guard.__code__, {**guard.__globals__, "os": private}))

    @contextmanager
    def descriptors():
        with native._descriptors() as (record, entries):
            def own(fd):
                nonlocal records, fired
                records += 1
                if phase == "record" and records == 1:
                    fired = True
                    if after:
                        record(fd)
                    raise failure
                return record(fd)
            yield own, entries

    body = FunctionType(original.__code__, {**original.__globals__, "os": private,
                                          "pipes_for_setup": local_guard, "_descriptors": descriptors})
    try:
        def invoke():
            if caller == "duplicate":
                body(False, 1, OSError, monkeypatch)
            else:
                body("close", monkeypatch)
        if error:
            with pytest.raises(error) as caught:
                invoke()
            assert caught.value is failure
            assert fired
        else:
            invoke()
        assert len(pairs) == (1 if phase == "allocate" else 2)
        assert all(not native._owned(fd, identity) for fd, identity in identities.items())
        assert os.pipe is borrowed_pipe
        assert _spawn._open_capture_pipes is borrowed_open
        assert capture.os is borrowed_capture_os
        selected = (native.test_capture_dup_failure_rolls_back_only_current_call if caller == "duplicate"
                    else native.test_capture_fixture_closes_retained_fds_on_every_exit)
        assert selected is original
    finally:
        for fd, identity in identities.items():
            if native._owned(fd, identity):
                os.close(fd)


@pytest.mark.parametrize("caller", ["duplicate", "fixture-exit"])
@pytest.mark.parametrize("phase,after", [("allocate", False), ("record", False), ("record", True)])
@pytest.mark.parametrize("error", [RuntimeError, KeyboardInterrupt, SystemExit])
def test_actual_capture_setup_failure_retires_partial_pipes(monkeypatch, caller, phase, after, error):
    _exercise(monkeypatch, caller, phase, error, after)


@pytest.mark.parametrize("caller", ["duplicate", "fixture-exit"])
def test_actual_capture_positive_controls_preserved(monkeypatch, caller):
    _exercise(monkeypatch, caller)
