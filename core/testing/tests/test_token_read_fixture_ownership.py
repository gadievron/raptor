"""Ownership of native pipes used by the existing token-read regression."""
from contextlib import contextmanager
import os
from types import FunctionType, ModuleType

import pytest

from core.testing.pipes import pipes_for_setup
from core.testing.tests import test_token_read_cleanup as native


def _exercise(monkeypatch, fault, phase=None, error=None):
    pairs, identities = [], {}
    failure = error("owned token fixture setup fault") if error else None
    original = native.test_token_read_releases_its_owned_descriptor
    borrowed_pipe, borrowed_write, borrowed_stat = os.pipe, os.write, os.fstat
    fired = False

    @contextmanager
    def owned_pipes(count):
        with pipes_for_setup(count) as values:
            pairs.extend(values)
            for pair in values:
                for fd in pair:
                    stat = borrowed_stat(fd)
                    identities[fd] = (stat.st_dev, stat.st_ino)
            yield values

    def stat(fd):
        nonlocal fired
        if phase == "identity" and not fired:
            fired = True
            raise failure
        return borrowed_stat(fd)

    def write(fd, data):
        nonlocal fired
        if phase == "write":
            fired = True
            raise failure
        return borrowed_write(fd, data)

    private = ModuleType("os")
    vars(private).update(vars(os))
    private.fstat, private.write = stat, write
    body = FunctionType(original.__code__, {**original.__globals__, "os": private, "pipes_for_setup": owned_pipes})
    borrowed_support_os = native.support.os
    try:
        if error:
            with pytest.raises(error) as caught:
                body(native.CASES[0], fault, monkeypatch)
            assert caught.value is failure
            assert fired
        else:
            body(native.CASES[0], fault, monkeypatch)
        assert len(pairs) == 1 and len(identities) == 2
        assert all(not native._owned(fd, identity) for fd, identity in identities.items())
        assert native.support.os is borrowed_support_os
        assert os.pipe is borrowed_pipe
        assert os.write is borrowed_write
        assert os.fstat is borrowed_stat
        assert native.test_token_read_releases_its_owned_descriptor is original
    finally:
        for fd, identity in identities.items():
            if native._owned(fd, identity):
                os.close(fd)


@pytest.mark.parametrize("fault", ["none", "decode"])
@pytest.mark.parametrize("phase", ["identity", "write"])
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt, SystemExit])
def test_actual_token_fixture_setup_fault_retires_pipe(monkeypatch, fault, phase, error):
    _exercise(monkeypatch, fault, phase, error)


@pytest.mark.parametrize("fault", ["read_error", "interrupt", "decode", "none"])
def test_actual_token_fixture_read_controls_preserved(monkeypatch, fault):
    _exercise(monkeypatch, fault)
