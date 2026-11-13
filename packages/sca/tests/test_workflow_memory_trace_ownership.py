"""The workflow read refusal proof owns tracing and credential lookups."""

import builtins
from contextlib import contextmanager
from types import ModuleType
import tracemalloc

import pytest

from packages.sca.tests import test_hash_pin as native
from packages.sca import hash_pin as producer
import os
from core.testing.module_views import module_function_view

pytestmark = pytest.mark.slow


@contextmanager
def caller_trace(frames=25, prior_peak=True):
    assert not tracemalloc.is_tracing(), "companion requires its own caller trace"
    try:
        tracemalloc.start(frames)
        retained = bytearray(8192)
        provenance = tracemalloc.get_object_traceback(retained)
        if prior_peak:
            previous = bytearray(32 * 1024 * 1024)
            del previous
        peak = tracemalloc.get_traced_memory()[1]
        yield
        assert tracemalloc.is_tracing()
        assert tracemalloc.get_traceback_limit() == frames
        assert provenance is not None
        assert tracemalloc.get_object_traceback(retained) == provenance
        assert tracemalloc.get_traced_memory()[1] >= peak
    finally:
        tracemalloc.stop()


@pytest.mark.parametrize("frames", [1, 25])
@pytest.mark.parametrize("prior_peak", [False, True])
def test_actual_workflow_reader_preserves_borrowed_trace(frames, prior_peak, tmp_path):
    with caller_trace(frames, prior_peak):
        native.test_workflow_read_is_bounded_and_no_follow(tmp_path)


def test_refused_child_fixture_path_preserves_trace(tmp_path):
    refused = tmp_path / "owned"
    refused.write_text("not a directory")
    with caller_trace():
        with pytest.raises(AssertionError, match="NotADirectoryError"):
            native.test_workflow_read_is_bounded_and_no_follow(refused)


@pytest.mark.parametrize("after", [False, True])
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt, SystemExit])
def test_managed_runner_fault_preserves_primary_and_trace(after, error, tmp_path):
    failure = error("owned workflow memory runner fault")
    original = native._run_memory_process
    completed = []

    def run(*args, **kwargs):
        if after:
            result = original(*args, **kwargs)
            assert result.returncode == 0, result.stderr
            completed.append(result)
        raise failure

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(native, "_run_memory_process", run)
        with caller_trace():
            with pytest.raises(error) as caught:
                native.test_workflow_read_is_bounded_and_no_follow(tmp_path)
            assert caught.value is failure
            assert len(completed) == int(after)
    assert native._run_memory_process is original


def case_view(trace=tracemalloc, reader=None):
    def importer(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "tracemalloc":
            return trace
        if name == "packages.sca.hash_pin" and reader is not None:
            consumer = ModuleType(name)
            consumer.hash_pin_workflows = reader
            return consumer
        return builtins.__import__(name, globals, locals, fromlist, level)

    function = native.test_workflow_read_is_bounded_and_no_follow
    return module_function_view(
        native, bindings={"_owned_case": function}, import_hook=importer,
    )


@pytest.mark.parametrize("after", [False, True])
@pytest.mark.parametrize("error", [RuntimeError, KeyboardInterrupt])
def test_owned_measurement_start_fault_retires_trace(after, error, tmp_path):
    assert not tracemalloc.is_tracing()
    failure = error("owned workflow trace startup fault")
    trace = ModuleType("tracemalloc")
    vars(trace).update(vars(tracemalloc))

    def start():
        if after:
            tracemalloc.start()
        raise failure

    trace.start = start
    view = case_view(trace)
    try:
        with pytest.raises(error) as caught:
            view._owned_case(tmp_path)
        assert caught.value is failure
        assert not tracemalloc.is_tracing()
    finally:
        tracemalloc.stop()


@pytest.mark.parametrize("error", [RuntimeError, KeyboardInterrupt])
def test_reader_boundary_fault_retires_owned_trace(error, tmp_path):
    assert not tracemalloc.is_tracing()
    failure = error("owned reader boundary fault")
    entered = []

    def fail(path, *, github_token):
        assert tracemalloc.is_tracing()
        assert github_token == "owned-workflow-memory"
        assert (path / ".github/workflows/huge.yml").stat().st_size == 60 * 1024 * 1024
        entered.append(path)
        raise failure

    view = case_view(reader=fail)
    try:
        with pytest.raises(error) as caught:
            view._owned_case(tmp_path)
        assert caught.value is failure
        assert len(entered) == 1
        assert not tracemalloc.is_tracing()
    finally:
        tracemalloc.stop()


@pytest.mark.parametrize("after", [False, True])
@pytest.mark.parametrize("error", [RuntimeError, KeyboardInterrupt])
def test_caller_trace_acquisition_failure_retires_trace(after, error):
    import sys

    assert not tracemalloc.is_tracing()
    failure = error("owned caller trace startup fault")
    trace = ModuleType("tracemalloc")
    vars(trace).update(vars(tracemalloc))

    def start(frames):
        if after:
            tracemalloc.start(frames)
        raise failure

    trace.start = start
    view = module_function_view(
        sys.modules[__name__],
        bindings={"tracemalloc": trace, "_owned_trace": caller_trace.__wrapped__},
    )
    try:
        with pytest.raises(error) as caught:
            with contextmanager(view._owned_trace)():
                pytest.fail("failed trace acquisition entered its body")
        assert caught.value is failure
        assert not tracemalloc.is_tracing()
    finally:
        tracemalloc.stop()


def owned_case(tmp_path):
    reads, lookups, denied = [], [], []
    borrowed = (producer.os, producer.read_bounded, producer._rewrite_file, producer._resolve_sha, native.hash_pin_workflows)
    class Environment(dict):
        def get(self, key, default=None):
            assert key == "GITHUB_TOKEN"
            lookups.append(key)
            return "owned-workflow-memory"
    owned_os = ModuleType("os")
    vars(owned_os).update(vars(os))
    owned_os.environ = Environment()
    real_read = producer.read_bounded
    def read(path, **kwargs):
        result = real_read(path, **kwargs)
        reads.append((path.name, kwargs, result, path.is_symlink()))
        return result
    def refuse(*args, **kwargs):
        denied.append(True)
        raise AssertionError("workflow refusal reached rewrite or resolver")
    product = module_function_view(producer, bindings={"os": owned_os, "read_bounded": read, "_rewrite_file": refuse, "_resolve_sha": refuse})
    def importer(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "packages.sca.hash_pin":
            return product
        return builtins.__import__(name, globals, locals, fromlist, level)
    view = module_function_view(native, import_hook=importer)
    assert view.test_workflow_read_is_bounded_and_no_follow.__code__ is native.test_workflow_read_is_bounded_and_no_follow.__code__
    assert product.hash_pin_workflows.__code__ is producer.hash_pin_workflows.__code__
    def verify():
        assert reads == [("huge.yml", {"follow_symlinks": False}, None, False), ("linked.yml", {"follow_symlinks": False}, None, True)]
        assert not denied
        assert (tmp_path / "repo/.github/workflows/huge.yml").stat().st_size == 60 * 1024 * 1024
        assert (tmp_path / "outside.yml").read_text() == "on: push\n"
        assert (producer.os, producer.read_bounded, producer._rewrite_file, producer._resolve_sha, native.hash_pin_workflows) == borrowed
        assert producer.os is os
    return lambda: view.test_workflow_read_is_bounded_and_no_follow(tmp_path), lookups, verify


def test_actual_refusals_do_not_read_inherited_credentials(tmp_path):
    assert not tracemalloc.is_tracing()
    invoke, lookups, verify = owned_case(tmp_path)
    invoke()
    verify()
    assert not lookups
    assert not tracemalloc.is_tracing()


def test_memory_child_omits_caller_token_without_mutating_it(tmp_path):
    with pytest.MonkeyPatch.context() as patch:
        patch.setenv("GITHUB_TOKEN", "owned-caller-placeholder")
        with caller_trace():
            native.test_workflow_read_is_bounded_and_no_follow(tmp_path)
        assert os.environ["GITHUB_TOKEN"] == "owned-caller-placeholder"
