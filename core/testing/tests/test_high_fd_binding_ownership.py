"""Emulated descriptor-limit functions stay at their consumer imports."""
from contextlib import contextmanager
import importlib
import resource

import pytest

from core.testing.tests import test_high_fd_fixture_cleanup as native


@pytest.mark.parametrize("kind,fault", [
    ("spawn", "none"), ("spawn", "limit"),
    ("audit", "none"), ("audit", "backend"),
])
@pytest.mark.parametrize("outcome", [None, RuntimeError, KeyboardInterrupt])
def test_modeled_limit_binding_restores_after_exit(
    kind, fault, outcome, tmp_path, monkeypatch
):
    name = ("core.sandbox.tests.test_spawn_lifecycle_hardening" if kind == "spawn"
            else "core.sandbox.tests.test_landlock_audit_fd_sweep")
    module = importlib.import_module(name)
    original = vars(module).get("resource")
    present = "resource" in vars(module)
    borrowed = resource.getrlimit, resource.setrlimit
    tables = []
    seen = []

    class Patch:
        @contextmanager
        def context(self):
            with monkeypatch.context() as actual:
                class Scope:
                    def __getattr__(self, key):
                        return getattr(actual, key)

                    def setattr(self, target, key, value, *args, **kwargs):
                        assert (resource.getrlimit, resource.setrlimit) == borrowed
                        if key in ("getrlimit", "setrlimit"):
                            assert target is not resource
                            seen.append(key)
                            if key == "setrlimit":
                                tables.append(value.__self__)
                        actual.setattr(target, key, value, *args, **kwargs)
                yield Scope()
                assert seen == ["getrlimit", "setrlimit"]
                assert (resource.getrlimit, resource.setrlimit) == borrowed
                if outcome is not None:
                    raise outcome("outer model scope exit")

    def invoke():
        native._exercise_modeled_fixture(kind, fault, OSError, tmp_path, Patch())

    if outcome is None:
        invoke()
    else:
        with pytest.raises(outcome, match="outer model scope exit"):
            invoke()
    assert len(tables) == 1
    assert tables[0].fds == tables[0].original
    assert tables[0].limit == tables[0].prior
    assert not (tmp_path / "owned-output").exists()
    assert (resource.getrlimit, resource.setrlimit) == borrowed
    assert ("resource" in vars(module)) is present
    assert vars(module).get("resource") is original
