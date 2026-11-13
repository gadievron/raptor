"""Paired-timeout cleanup fixtures never replace canonical signal functions."""
from contextlib import contextmanager, nullcontext
import os

import pytest

from packages.frida.tests import test_active as native


@pytest.mark.parametrize("failure", [None, RuntimeError, KeyboardInterrupt],
                         ids=["normal", "error", "interrupt"])
def test_actual_timeout_fixture_restores_os_namespace(tmp_path, failure):
    getpgid, killpg = os.getpgid, os.killpg
    module = native._mock_owner("packages.frida.active")
    namespace = module.os
    observe = native.observe_paired
    scope = native.mock_module_attribute
    entered, results = [], []

    def observed(*args, **kwargs):
        assert (os.getpgid, os.killpg) == (getpgid, killpg)
        result = observe(*args, **kwargs)
        assert result is None
        results.append(result)
        return result

    @contextmanager
    def checked(consumer, binding, name, *args, **kwargs):
        assert consumer is module
        assert (binding, name) in (("subprocess", "Popen"), ("os", "getpgid"), ("os", "killpg"))
        with scope(consumer, binding, name, *args, **kwargs) as mocked:
            entered.append((name, mocked))
            assert (os.getpgid, os.killpg) == (getpgid, killpg)
            yield mocked
            if name == "killpg" and failure:
                raise failure("owned body failure")

    expected = pytest.raises(failure, match="owned body failure") if failure else nullcontext()
    with pytest.MonkeyPatch.context() as owner:
        native._isolate_host_probe_patches.__wrapped__(owner)
        process_namespace = module.subprocess
        owner.setattr(native, "observe_paired", observed)
        owner.setattr(native, "mock_module_attribute", checked)
        with expected:
            with pytest.MonkeyPatch.context() as patch:
                native.TestObservePaired().test_returns_none_on_timeout(tmp_path, patch)
        assert [name for name, _ in entered] == ["Popen", "getpgid", "killpg"]
        mocks = dict(entered)
        mocks["Popen"].assert_called_once()
        assert mocks["Popen"].return_value.communicate.call_count == 2
        mocks["getpgid"].assert_called_once_with(12345)
        mocks["killpg"].assert_called_once_with(12345, 9)
        assert results == [None]
        assert module.os is namespace
        assert module.subprocess is process_namespace
        assert (os.getpgid, os.killpg) == (getpgid, killpg)
    assert native.observe_paired is observe
    assert native.mock_module_attribute is scope
