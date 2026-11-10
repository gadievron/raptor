"""Readiness launch substitutions stay at their consuming import."""
from contextlib import contextmanager
import importlib
import os
import subprocess

import pytest

from core.testing.tests import test_startup_cleanup as native


@pytest.mark.skipif(os.name != "posix", reason="POSIX owned child fixtures")
@pytest.mark.parametrize("helper", ["holder", "wrapper"])
@pytest.mark.parametrize("fault", ["none", "io", "interrupt"])
@pytest.mark.parametrize("outcome", [None, RuntimeError, KeyboardInterrupt])
def test_readiness_launch_binding_restores_after_exit(
    helper, fault, outcome, tmp_path, monkeypatch
):
    module = importlib.import_module(native._MODULES[helper])
    borrowed = subprocess.Popen
    original_binding = module.subprocess
    original_method = (module.TestStallKillAddressesTheGroup._wrapper_with_grandchild
                       if helper == "wrapper" else None)
    started = []
    published = []

    class Patch:
        @contextmanager
        def context(self):
            with monkeypatch.context() as actual:
                class Scope:
                    def __getattr__(self, key):
                        return getattr(actual, key)

                    def setattr(self, target, name, value, *args, **kwargs):
                        if name == "Popen":
                            assert target is not subprocess
                            replacement = value

                            def tracked(*args, **kwargs):
                                assert subprocess.Popen is borrowed
                                process = replacement(*args, **kwargs)
                                started.append(process)
                                return process

                            value = tracked
                            published.append(True)
                        actual.setattr(target, name, value, *args, **kwargs)
                        assert subprocess.Popen is borrowed
                yield Scope()
                assert published and subprocess.Popen is borrowed
                if outcome is not None:
                    raise outcome("outer readiness scope exit")

    def invoke():
        native.test_readiness_setup_owns_child_until_return(
            helper, fault, tmp_path, Patch()
        )

    if outcome is None:
        invoke()
    else:
        with pytest.raises(outcome, match="outer readiness scope exit"):
            invoke()
    assert published == [True] and len(started) == 1
    process = started[0]
    assert process.returncode is not None
    with pytest.raises(ChildProcessError):
        os.waitpid(process.pid, os.WNOHANG)
    assert all(s is None or s.closed for s in
               (process.stdin, process.stdout, process.stderr))
    assert subprocess.Popen is borrowed
    assert module.subprocess is original_binding
    if original_method is not None:
        assert module.TestStallKillAddressesTheGroup._wrapper_with_grandchild is original_method
