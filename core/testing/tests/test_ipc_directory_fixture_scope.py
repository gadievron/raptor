"""Shared IPC fixture scopes restore borrowed state and own setup failures."""
from contextlib import contextmanager, ExitStack
import inspect
import os
from pathlib import Path
import shutil
import tempfile
from types import ModuleType

import pytest

from core.testing.module_views import module_function_view
from core.testing.module_bindings import patch_module_attribute


def _fixture(channel):
    if channel == "dispatcher":
        from core.llm.dispatcher.tests import conftest as fixture
        from core.llm.dispatcher import server
        return fixture, server, fixture._af_unix_safe_tmp.__wrapped__
    from packages.joern.tests import conftest as fixture
    return fixture, None, fixture.uds_dir.__wrapped__


def _raw(raw, patch):
    # The original Joern fixture had no dependency; use that exact old API in
    # counterfactual controls and the real dependency in the patched tree.
    return raw(patch) if inspect.signature(raw).parameters else raw()


def _namespace(owner, before):
    assert vars(owner).keys() == before.keys(), owner.__name__
    assert all(vars(owner)[name] is value for name, value in before.items()), owner.__name__


def _env():
    return "TMPDIR" in os.environ, os.environ.get("TMPDIR")


@contextmanager
def _caller(channel, tmp_path, shape, policy, env_state):
    fixture, server, raw = _fixture(channel)
    # Own the short physical root before any subsequent setup can fail.
    with ExitStack() as resources, pytest.MonkeyPatch.context() as caller:
        short = Path(tempfile.mkdtemp(prefix="ipc-scope-", dir="/tmp"))
        resources.callback(shutil.rmtree, short, ignore_errors=True)
        deep = tmp_path / ("deep-" * 30)
        deep.mkdir()
        selected = short if policy == "short" else deep
        view = module_function_view(tempfile) if shape == "function-view" else ModuleType(tempfile.__name__)
        if shape == "shallow":
            vars(view).update(vars(tempfile))
        view.tempdir = str(selected)
        paths, allocations = [], []
        real_mkdtemp = tempfile.mkdtemp

        def allocate(*args, **kwargs):
            allocations.append((args, kwargs.copy()))
            path = Path(real_mkdtemp(prefix="owned-", dir=short))
            paths.append(path)
            return str(path)

        view.mkdtemp = allocate
        caller.setattr(fixture, "tempfile", view)
        if server is not None:
            caller.setattr(server, "tempfile", view)
        # An unfixed fixture can read/write this cached field. Register its
        # inherited value before the counterfactual, and assert before undo.
        caller.setattr(tempfile, "tempdir", tempfile.tempdir)
        if env_state == "absent":
            caller.delenv("TMPDIR", raising=False)
        else:
            caller.setenv("TMPDIR", "" if env_state == "empty" else str(deep))
        before_env = _env()
        snapshots = [(fixture, vars(fixture).copy()), (view, vars(view).copy()), (tempfile, vars(tempfile).copy())]
        if server is not None:
            snapshots.append((server, vars(server).copy()))
        try:
            yield fixture, server, raw, view, paths, allocations, before_env, snapshots, deep
        finally:
            for path in paths:
                shutil.rmtree(path, ignore_errors=True)


def _restored(before_env, snapshots):
    assert _env() == before_env
    for owner, values in snapshots:
        _namespace(owner, values)


@pytest.mark.parametrize("channel", ["dispatcher", "joern"])
@pytest.mark.parametrize("shape", ["shallow", "function-view"])
@pytest.mark.parametrize("policy", ["short", "long"])
@pytest.mark.parametrize("env_state", ["absent", "empty", "value"])
@pytest.mark.parametrize("exit_mode", ["normal", "error", "interrupt"])
def test_real_fixture_scope_owns_namespaces_and_directory(tmp_path, channel, shape, policy, env_state, exit_mode):
    with _caller(channel, tmp_path, shape, policy, env_state) as state:
        fixture, server, raw, view, paths, calls, before_env, snapshots, deep = state
        patch = pytest.MonkeyPatch()
        generator = _raw(raw, patch)
        caught = None
        failure = RuntimeError("IPC fixture body") if exit_mode == "error" else KeyboardInterrupt("IPC fixture body")
        try:
            try:
                yielded = next(generator)
                active = fixture.tempfile
                assert active is not view
                assert active.gettempdir() == (str(paths[0]) if channel == "dispatcher" and policy == "long" else view.tempdir)
                if server is not None:
                    assert server.tempfile is active
                _namespace(tempfile, snapshots[2][1])
                expected = 1 if channel == "joern" or policy == "long" else 0
                assert len(paths) == expected
                if channel == "joern":
                    assert yielded == str(paths[0])
                    assert calls == [((), {"prefix": "j", "dir": view.tempdir if policy == "short" else "/tmp"})]
                elif policy == "long":
                    assert calls == [((), {"prefix": "raptor-llm-sock-", "dir": "/tmp"})]
                    assert _env() == (True, str(paths[0]))
                else:
                    assert _env() == before_env
                if exit_mode != "normal":
                    raise failure
            except BaseException as error:
                caught = error
            finally:
                generator.close()
            _restored(before_env, snapshots)
            assert all(not path.exists() for path in paths)
            if exit_mode == "normal":
                assert caught is None, repr(caught)
            else:
                assert caught is failure, repr(caught)
        finally:
            generator.close()
            patch.undo()


@pytest.mark.parametrize("shape", ["shallow", "function-view"])
@pytest.mark.parametrize("env_state", ["absent", "empty", "value"])
@pytest.mark.parametrize("stage", ["server", "fixture", "env", "cache"])
@pytest.mark.parametrize("error_type", [OSError, KeyboardInterrupt, SystemExit])
def test_dispatcher_setup_failure_unwinds_owned_effects(tmp_path, shape, env_state, stage, error_type):
    with _caller("dispatcher", tmp_path, shape, "long", env_state) as state:
        fixture, server, raw, view, paths, _, before_env, snapshots, _ = state
        failure = error_type("injected IPC setup")
        hit = []

        class FaultPatch(pytest.MonkeyPatch):
            def setattr(self, target, name, value, raising=True):
                super().setattr(target, name, value, raising=raising)
                if (stage == "server" and target is server and name == "tempfile"
                        or stage == "cache" and name == "tempdir"):
                    hit.append(stage)
                    raise failure

            def setitem(self, mapping, name, value):
                super().setitem(mapping, name, value)
                if (stage == "fixture" and mapping is vars(fixture) and name == "tempfile"
                        or stage == "env" and mapping is os.environ and name == "TMPDIR"):
                    hit.append(stage)
                    raise failure

        patch = FaultPatch()
        generator = _raw(raw, patch)
        try:
            caught = None
            try:
                next(generator)
            except BaseException as error:
                caught = error
            finally:
                generator.close()
            assert caught is failure
            assert hit == [stage]
            _restored(before_env, snapshots)
            assert all(not path.exists() for path in paths)
            assert len(paths) == (1 if stage in ("env", "cache") else 0)
        finally:
            generator.close()
            patch.undo()


@pytest.mark.parametrize("shape", ["shallow", "function-view"])
@pytest.mark.parametrize("env_state", ["absent", "empty", "value"])
def test_joern_failed_budget_assertion_removes_allocation(tmp_path, shape, env_state):
    with _caller("joern", tmp_path, shape, "long", env_state) as state:
        fixture, _, raw, view, paths, _, before_env, snapshots, deep = state
        real_mkdtemp = tempfile.mkdtemp
        def oversized(*args, **kwargs):
            path = Path(real_mkdtemp(prefix="over-budget-", dir=deep))
            paths.append(path)
            return str(path)
        with pytest.MonkeyPatch.context() as inputs:
            inputs.setattr(view, "mkdtemp", oversized)
            snapshots[1] = (view, vars(view).copy())
            patch = pytest.MonkeyPatch()
            generator = _raw(raw, patch)
            try:
                with pytest.raises(AssertionError):
                    next(generator)
                _restored(before_env, snapshots)
                assert len(paths) == 1 and not paths[0].exists()
            finally:
                generator.close()
                patch.undo()


@pytest.mark.parametrize("shape", ["shallow", "function-view"])
@pytest.mark.parametrize("env_state", ["absent", "empty", "value"])
@pytest.mark.parametrize("exit_mode", ["normal", "error", "interrupt"])
def test_nested_dispatcher_scope_restores_live_outer_scope(tmp_path, shape, env_state, exit_mode):
    with _caller("dispatcher", tmp_path, shape, "long", env_state) as state:
        fixture, server, raw, view, paths, _, before_env, snapshots, deep = state
        patch = pytest.MonkeyPatch()
        outer = _raw(raw, patch)
        try:
            next(outer)
            outer_view = fixture.tempfile
            assert outer_view is not view and server.tempfile is outer_view
            outer_path = paths[0]
            with pytest.MonkeyPatch.context() as inputs:
                inputs.setattr(outer_view, "tempdir", str(deep))
                inputs.setenv("TMPDIR", str(deep))
                nested_env = _env()
                nested = _raw(raw, patch)
                failure = RuntimeError("nested scope") if exit_mode == "error" else KeyboardInterrupt("nested scope")
                caught = None
                try:
                    try:
                        next(nested)
                        assert fixture.tempfile is not outer_view
                        assert server.tempfile is fixture.tempfile
                        assert _env() == (True, str(paths[1]))
                        if exit_mode != "normal":
                            raise failure
                    except BaseException as error:
                        caught = error
                    finally:
                        nested.close()
                    assert caught is (None if exit_mode == "normal" else failure)
                    assert fixture.tempfile is outer_view and server.tempfile is outer_view
                    assert _env() == nested_env and outer_path.is_dir()
                    assert not paths[1].exists()
                finally:
                    nested.close()
            assert _env() == (True, str(outer_path))
            outer.close()
            _restored(before_env, snapshots)
            assert not outer_path.exists()
        finally:
            outer.close()
            patch.undo()


@pytest.mark.parametrize("shape", ["shallow", "function-view"])
@pytest.mark.parametrize("error_type", [OSError, KeyboardInterrupt, SystemExit])
def test_dispatcher_cleanup_failure_still_restores_bindings(tmp_path, shape, error_type):
    with _caller("dispatcher", tmp_path, shape, "long", "value") as state:
        fixture, server, raw, view, paths, _, before_env, snapshots, _ = state
        failure = error_type("injected IPC cleanup")
        def refuse(*args, **kwargs):
            raise failure
        with pytest.MonkeyPatch.context() as inputs:
            patch_module_attribute(inputs, fixture, "shutil", "rmtree", refuse)
            snapshots[0] = (fixture, vars(fixture).copy())
            patch = pytest.MonkeyPatch()
            generator = _raw(raw, patch)
            try:
                next(generator)
                assert fixture.tempfile is not view and server.tempfile is fixture.tempfile
                caught = None
                try:
                    generator.close()
                except BaseException as error:
                    caught = error
                assert caught is failure
                _restored(before_env, snapshots)
                assert len(paths) == 1 and paths[0].is_dir()
            finally:
                try:
                    generator.close()
                except BaseException as error:
                    if error is not failure:
                        raise
                finally:
                    patch.undo()


@pytest.mark.parametrize("channel", ["dispatcher", "joern"])
@pytest.mark.parametrize("shape", ["shallow", "function-view"])
@pytest.mark.parametrize("env_state", ["absent", "empty", "value"])
def test_unmodified_ipc_fixture_control(tmp_path, channel, shape, env_state):
    with _caller(channel, tmp_path, shape, "long", env_state) as state:
        _, _, _, _, paths, _, before_env, snapshots, _ = state
        _restored(before_env, snapshots)
        assert paths == []
