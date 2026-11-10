"""Exact process fixture namespaces unwind before any publication fault can spawn."""
import importlib
import os
import subprocess
from contextlib import contextmanager
from types import ModuleType

import pytest

from core.testing.tests import test_resource_setup_cleanup as native

pytestmark = pytest.mark.skipif(os.name != "posix", reason="owned child process fixtures")

CASES = [
    ("scratch-second", "core.security.tests.test_launch_scratch", None),
    ("broker-read", "packages.joern.tests.test_broker", None),
    ("cache", "packages.sca.tests.test_cache_budget", "test_cross_process_scan_lease"),
    ("stress", "packages.sca.calibration.tests.test_stress_remeasure", "test_sigterm_prints_in_flight_and_partial_summary"),
]


@pytest.mark.parametrize("case,path,local_name", CASES)
@pytest.mark.parametrize("after", [False, True])
@pytest.mark.parametrize("error", [RuntimeError, KeyboardInterrupt, SystemExit])
def test_actual_process_namespace_publication_fault_restores_bindings(case, path, local_name, after, error, tmp_path, monkeypatch):
    module = importlib.import_module(path)
    missing = object()
    borrowed_view = vars(module).get("subprocess", missing)
    borrowed_function = getattr(module, local_name) if local_name else None
    borrowed_popen, borrowed_run = subprocess.Popen, subprocess.run
    original = native.test_process_setup_failure_reaps_and_closes
    failure = error("owned process namespace publication fault")
    handles, publications = [], []

    class OwnedPath(type(tmp_path)):
        def open(self, *args, **kwargs):
            value = super().open(*args, **kwargs)
            handles.append(value)
            return value

    class Patch:
        def __getattr__(self, name):
            return getattr(monkeypatch, name)

        @contextmanager
        def context(self):
            with monkeypatch.context() as actual:
                class Scope:
                    def __getattr__(self, name):
                        return getattr(actual, name)

                    def setattr(self, *args, **kwargs):
                        actual.setattr(*args, **kwargs)
                        assert subprocess.Popen is borrowed_popen

                    def setitem(self, mapping, key, value):
                        if key != "subprocess":
                            actual.setitem(mapping, key, value)
                            return
                        prior = mapping[key]
                        assert isinstance(prior, ModuleType) and isinstance(value, ModuleType)
                        assert value is not prior and value.Popen is not prior.Popen
                        assert value.PIPE == prior.PIPE and value.DEVNULL == prior.DEVNULL
                        if local_name:
                            assert mapping is not vars(module)
                            assert getattr(module, local_name) is not borrowed_function
                            assert vars(module).get("subprocess", missing) is borrowed_view
                        else:
                            assert mapping is vars(module) and prior is borrowed_view
                        publications.append((mapping, prior, value))
                        if after:
                            actual.setitem(mapping, key, value)
                            assert mapping[key] is value
                        else:
                            assert mapping[key] is prior
                        assert subprocess.Popen is borrowed_popen
                        raise failure

                yield Scope()

    try:
        with pytest.raises(error) as caught:
            original(case, OSError, OwnedPath(tmp_path), Patch())
        assert caught.value is failure
        assert len(publications) == 1
        mapping, prior, _ = publications[0]
        assert mapping["subprocess"] is prior
        assert len(handles) == 1 and handles[0].closed
        assert vars(module).get("subprocess", missing) is borrowed_view
        if local_name:
            assert getattr(module, local_name) is borrowed_function
        assert subprocess.Popen is borrowed_popen and subprocess.run is borrowed_run
        assert native.test_process_setup_failure_reaps_and_closes is original
    finally:
        for handle in handles:
            handle.close()
