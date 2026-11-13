"""Normal cleanup chmod guards stay on the atomic filesystem consumer."""
from contextlib import nullcontext
import os

import pytest

import core.atomic_fs as atomic_fs
from core.run.tests import test_permission_cleanup as native


@pytest.mark.parametrize('failure', [None, RuntimeError, KeyboardInterrupt],
                         ids=['normal', 'error', 'interrupt'])
def test_actual_normal_cleanup_guard_restores_consumer(tmp_path, failure):
    namespace, chmod = atomic_fs.os, os.chmod
    calls = []

    def unrelated(*args, **kwargs):
        calls.append((args, kwargs))

    expected = pytest.raises(failure, match='owned body failure') if failure else nullcontext()
    with pytest.MonkeyPatch.context() as owner:
        owner.setattr(os, 'chmod', unrelated)
        with expected:
            with pytest.MonkeyPatch.context() as patch:
                native.test_common_removal_does_not_repair_permissions_on_normal_tree(tmp_path, patch)
                assert atomic_fs.os is not namespace
                assert atomic_fs.os.lstat is os.lstat
                assert os.chmod is unrelated
                os.chmod(tmp_path, 0o700)
                assert calls == [((tmp_path, 0o700), {})]
                if failure:
                    raise failure('owned body failure')
        assert atomic_fs.os is namespace
        assert os.chmod is unrelated
    assert os.chmod is chmod


def test_actual_normal_cleanup_guard_rejects_unnecessary_repair(tmp_path, monkeypatch):
    original = native.rmtree_hardened

    def unsafe(path):
        atomic_fs.os.chmod(path, 0o700)
        return original(path)

    monkeypatch.setattr(native, 'rmtree_hardened', unsafe)
    with pytest.MonkeyPatch.context() as patch:
        with pytest.raises(AssertionError, match='normal cleanup must not chmod every directory'):
            native.test_common_removal_does_not_repair_permissions_on_normal_tree(tmp_path, patch)
