"""Actual broker-key test owns mock publication and its native token pipe."""
from contextlib import contextmanager
import errno
import os
from types import FunctionType, ModuleType
import subprocess

import pytest

from core.llm.dispatcher import spawn
from core.llm.model_brokers.tests import test_registry as native


def _same_descriptor(fd, identity):
    try:
        current = os.fstat(fd)
    except OSError as error:
        assert error.errno == errno.EBADF
        return False
    return (current.st_dev, current.st_ino) == identity


def _exercise(tmp_path, phase=None, error=None, after=False, recycle=False):
    pairs, identities, recycled, publications = [], {}, [], []
    failure = error("owned spawn-fixture setup fault") if error else None
    fired = False
    borrowed_popen = subprocess.Popen
    borrowed_binding = spawn.subprocess
    original = native.test_spawn_strips_broker_keys_even_from_explicit_env

    @contextmanager
    def pipe():
        with native._owned_token_pipe() as pair:
            pairs.append(pair)
            for fd in pair:
                current = os.fstat(fd)
                identities[fd] = (current.st_dev, current.st_ino)
            yield pair
            if recycle:
                assert all(not _same_descriptor(fd, identities[fd]) for fd in pair)
                fd = os.open(tmp_path / "replacement", os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
                stamp = os.fstat(fd)
                recycled.append((fd, (stamp.st_dev, stamp.st_ino)))
                assert fd in pair, "native control did not reuse a consumed pipe descriptor"
                os.write(fd, b"replacement remains owned")

    def close(fd):
        nonlocal fired
        if phase == "close" and not fired:
            fired = True
            if after:
                os.close(fd)
            raise failure
        return os.close(fd)

    def install(*args, **kwargs):
        nonlocal fired
        assert subprocess.Popen is borrowed_popen
        if phase == "patch":
            fired = True
            if after:
                native.patch_module_attribute(*args, **kwargs)
                publications.append(spawn.subprocess)
                assert spawn.subprocess is not borrowed_binding
                assert subprocess.Popen is borrowed_popen
            raise failure
        result = native.patch_module_attribute(*args, **kwargs)
        publications.append(spawn.subprocess)
        assert subprocess.Popen is borrowed_popen
        return result

    private = ModuleType("os")
    vars(private).update(vars(os))
    private.close = close
    body = FunctionType(original.__code__, {**original.__globals__, "os": private, "_owned_token_pipe": pipe, "patch_module_attribute": install})
    try:
        with pytest.MonkeyPatch.context() as patch:
            if error:
                with pytest.raises(error) as caught:
                    body(patch)
                assert caught.value is failure
                assert fired
            else:
                body(patch)
            assert len(pairs) == 1
            assert all(not _same_descriptor(fd, identities[fd]) for fd in pairs[0])
            assert subprocess.Popen is borrowed_popen
            assert native.test_spawn_strips_broker_keys_even_from_explicit_env is original
        assert spawn.subprocess is borrowed_binding
        for fd, identity in recycled:
            assert _same_descriptor(fd, identity)
            os.lseek(fd, 0, os.SEEK_SET)
            assert os.read(fd, 128) == b"replacement remains owned"
    finally:
        for pair in pairs:
            for fd in pair:
                if _same_descriptor(fd, identities[fd]):
                    os.close(fd)
        for fd, identity in recycled:
            if _same_descriptor(fd, identity):
                os.close(fd)


@pytest.mark.parametrize("phase", ["patch", "close"])
@pytest.mark.parametrize("after", [False, True])
@pytest.mark.parametrize("error", [RuntimeError, KeyboardInterrupt, SystemExit])
def test_actual_spawn_fixture_setup_failure_retires_pipe(tmp_path, phase, after, error):
    _exercise(tmp_path, phase, error, after)


def test_actual_mocked_spawn_positive_control(tmp_path):
    _exercise(tmp_path)


def test_consumed_pipe_descriptor_replacement_survives_cleanup(tmp_path):
    _exercise(tmp_path, recycle=True)
