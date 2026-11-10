"""Actual lease fixture Popen refusal is private to the current broker caller."""
from contextlib import contextmanager
import subprocess
from types import ModuleType

import pytest

from core.testing.tests import test_resource_setup_cleanup as native
from packages.joern.tests import test_broker as consumer


@pytest.mark.parametrize("state", ["ordinary", "borrowed"])
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
@pytest.mark.parametrize("outcome", ["normal", "error", "interrupt"])
def test_actual_broker_popen_fault_preserves_borrowed_namespace(state, error, outcome, tmp_path, monkeypatch):
    handles, publications, outer_calls = [], [], []
    borrowed_popen, borrowed_view, borrowed_lease = subprocess.Popen, consumer.subprocess, consumer._lease
    original = native.test_broker_lease_survives_later_setup_failure
    failure_type = {"normal": None, "error": RuntimeError, "interrupt": KeyboardInterrupt}[outcome]
    failure = failure_type("owned broker fault-scope boundary") if failure_type else None

    class OwnedPath(type(tmp_path)):
        def open(self, *args, **kwargs):
            handle = super().open(*args, **kwargs)
            handles.append(handle)
            return handle

    def outer(*args, **kwargs):
        outer_calls.append((args, kwargs))
        raise AssertionError("borrowed outer Popen was reached")

    view = ModuleType("subprocess")
    vars(view).update(vars(subprocess))
    view.Popen = outer
    expected_view = view if state == "borrowed" else borrowed_view

    class Patch:
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
                        actual.setitem(mapping, key, value)
                        assert subprocess.Popen is borrowed_popen
                        if mapping is vars(consumer) and key == "subprocess":
                            publications.append(value)
                            assert isinstance(value, ModuleType)
                            assert value is not expected_view
                            assert value.Popen is not expected_view.Popen
                            assert value.PIPE == expected_view.PIPE
                            assert value.DEVNULL == expected_view.DEVNULL
                            assert value.TimeoutExpired is expected_view.TimeoutExpired

                yield Scope()
                assert len(publications) == 1 and consumer.subprocess is publications[0]
                assert subprocess.Popen is borrowed_popen
                if failure is not None:
                    raise failure

    try:
        with monkeypatch.context() as ambient:
            if state == "borrowed":
                ambient.setattr(consumer, "subprocess", view)
            if failure is None:
                original("test_killed_client_releases_only_its_lease", error, OwnedPath(tmp_path), Patch())
            else:
                with pytest.raises(failure_type) as caught:
                    original("test_killed_client_releases_only_its_lease", error, OwnedPath(tmp_path), Patch())
                assert caught.value is failure
            assert len(handles) == 1 and handles[0].closed
            assert outer_calls == []
            assert consumer.subprocess is expected_view
            assert consumer._lease is borrowed_lease
            assert subprocess.Popen is borrowed_popen
            assert expected_view.Popen is (outer if state == "borrowed" else borrowed_popen)
        assert consumer.subprocess is borrowed_view
        assert native.test_broker_lease_survives_later_setup_failure is original
    finally:
        for handle in handles:
            handle.close()
