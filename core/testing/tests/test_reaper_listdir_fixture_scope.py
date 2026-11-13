"""Reaper directory-listing faults preserve unrelated filesystem consumers."""
from contextlib import contextmanager, nullcontext
import os
from pathlib import Path

import pytest

from core.run import tmp_reaper as reaper
from core.run.tests import test_tmp_reaper as native


@contextmanager
def _owned_reaper_environment(tmp_path):
    with contextmanager(native._user_state_in_tmp.__wrapped__)(tmp_path):
        with pytest.MonkeyPatch.context() as patch:
            for setup in (native._owned_tempfile_namespace, native._idle_fixture_cwds,
                          native._pin_sweep_roots, native._pin_root_pidns,
                          native._guard_pid_one_kill):
                setup.__wrapped__(patch)
            yield native.tmp_root.__wrapped__(tmp_path, patch, None)


@pytest.mark.parametrize('failure', [None, RuntimeError, KeyboardInterrupt],
                         ids=['normal', 'error', 'interrupt'])
def test_actual_reaper_listing_fault_owns_only_its_consumer(tmp_path, failure):
    listdir = os.listdir
    patch_attribute = native.patch_module_attribute
    calls, faults = [], []
    token = object()

    def unrelated(*args, **kwargs):
        calls.append((args, kwargs))
        return token

    def instrument(patch, consumer, binding, name, value, **kwargs):
        assert consumer is reaper and binding == 'os' and name == 'listdir'
        def tracked(*args, **kw):
            faults.append((args, kw))
            return value(*args, **kw)
        return patch_attribute(patch, consumer, binding, name, tracked, **kwargs)

    expected = pytest.raises(failure, match='owned body failure') if failure else nullcontext()
    with _owned_reaper_environment(tmp_path) as root:
        namespace = reaper.os
        with pytest.MonkeyPatch.context() as owner:
            owner.setattr(os, 'listdir', unrelated)
            owner.setattr(native, 'patch_module_attribute', instrument)
            with expected:
                with pytest.MonkeyPatch.context() as patch:
                    native.TestConfigAndSafety().test_never_raises(root, patch)
                    assert len(faults) == 1
                    assert Path(faults[0][0][0]) == root
                    assert reaper.os is not namespace
                    assert reaper.os.kill is os.kill
                    assert os.listdir(tmp_path) is token
                    assert calls == [((tmp_path,), {})]
                    if failure:
                        raise failure('owned body failure')
            assert reaper.os is namespace
            assert os.listdir is unrelated
    assert os.listdir is listdir
    assert native.patch_module_attribute is patch_attribute
