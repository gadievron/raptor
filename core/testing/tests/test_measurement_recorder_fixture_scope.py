"""Measurement argument fixtures preserve inherited fake-client records."""
import builtins
from contextlib import nullcontext
import sys

import pytest

from core.llm import client
from core.testing.module_views import module_function_view
from packages.source_intel.tests import test_measurement as native

_TARGETS = ("_iter_memory_corruption_corpus", "make_evidence_collector", "SourceIntelCache",
            "make_source_intel_collector", "make_cwe_dispatched_collector", "DataflowValidator", "_run_one")


@pytest.mark.parametrize("method", ["test_model_flag_pins_llm_client", "test_no_model_flag_uses_client_default"])
@pytest.mark.parametrize("failure", [None, RuntimeError, KeyboardInterrupt],
                         ids=["normal", "error", "interrupt"])
def test_actual_model_argument_fixture_restores_recorder(method, capsys, failure):
    calls = native._RecordingLLMClient.calls
    real_client = client.LLMClient
    argv = sys.argv
    bindings = {name: getattr(native.M, name) for name in _TARGETS}
    inherited = [{"args": ("previous-owned-call",), "kwargs": {}}]
    expected = pytest.raises(failure, match="owned body failure") if failure else nullcontext()
    with pytest.MonkeyPatch.context() as owner:
        owner.setattr(native._RecordingLLMClient, "calls", inherited)
        with expected:
            with pytest.MonkeyPatch.context() as body:
                harness = native.harness.__wrapped__(body)
                getattr(native, method)(harness, body, capsys)
                assert native._RecordingLLMClient.calls is not inherited
                assert inherited == [{"args": ("previous-owned-call",), "kwargs": {}}]
                if failure:
                    raise failure("owned body failure")
        assert native._RecordingLLMClient.calls is inherited
        assert inherited == [{"args": ("previous-owned-call",), "kwargs": {}}]
        assert client.LLMClient is real_client
        assert sys.argv is argv
        for name, value in bindings.items():
            assert getattr(native.M, name) is value
    assert native._RecordingLLMClient.calls is calls


@pytest.mark.parametrize("error", [ImportError, KeyboardInterrupt])
def test_actual_recorder_setup_restores_before_client_import(error):
    calls = native._RecordingLLMClient.calls
    real_client = client.LLMClient
    importer = builtins.__import__
    inherited = [{"args": ("previous-owned-call",), "kwargs": {}}]
    attempted = []

    def refuse(name, *args, **kwargs):
        if name == "core.llm.client":
            assert native._RecordingLLMClient.calls is not inherited
            attempted.append(name)
            raise error("owned setup refusal")
        return importer(name, *args, **kwargs)

    private = module_function_view(native, bindings={"_setup": native.harness.__wrapped__}, import_hook=refuse)
    assert private._setup.__code__ is native.harness.__wrapped__.__code__
    with pytest.MonkeyPatch.context() as owner:
        owner.setattr(native._RecordingLLMClient, "calls", inherited)
        with pytest.raises(error, match="owned setup refusal"):
            with pytest.MonkeyPatch.context() as body:
                private._setup(body)
        assert attempted == ["core.llm.client"]
        assert native._RecordingLLMClient.calls is inherited
        assert inherited == [{"args": ("previous-owned-call",), "kwargs": {}}]
        assert client.LLMClient is real_client
        assert builtins.__import__ is importer
    assert native._RecordingLLMClient.calls is calls
