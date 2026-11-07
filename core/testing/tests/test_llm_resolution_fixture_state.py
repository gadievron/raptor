"""Warm caller state must survive native selection fixture lifetimes."""

import importlib
from types import ModuleType
from threading import Lock

import pytest

from core.testing.llm_state import isolated_llm_resolution


CASES = [
    ("core.llm.tests.test_bedrock_entry_resolution", "_isolated_env"),
    ("core.llm.tests.test_ollama_primary_resolution", "_isolated_env"),
    ("core.llm.tests.test_transport_route_matrix", "_hermetic_resolution"),
    ("core.llm.tests.test_config_file", "_restore_llm_caches"),
    ("core.llm.tests.test_dispatcher_integration", "clear_detection_cache"),
]


def _warm(monkeypatch):
    from core.llm import config, detection

    values = {
        "_cached_llm_availability": detection.LLMAvailability(True, False, True),
        "_cached_ollama_models": ["caller"],
        "_cached_ollama_capabilities": {("http://caller:11434", "caller"): frozenset({"completion"})},
        "_ollama_capability_probing_disabled": {"http://caller:11434"},
        "_ollama_checked": True,
    }
    selections = {
        "_cached_thinking_model": config.ModelConfig(provider="ollama", model_name="caller"),
        "_thinking_model_checked": True,
        "_operator_primary_override": config.ModelConfig(provider="ollama", model_name="override"),
    }
    for owner, entries in ((detection, values), (config, selections)):
        for name, value in entries.items():
            monkeypatch.setattr(owner, name, value)
    return config, detection, values, selections


@pytest.mark.parametrize("module_name,fixture_name", CASES)
@pytest.mark.parametrize("finish", ["resume", "close", "interrupt"])
@pytest.mark.parametrize("body_override", [False, True])
def test_native_fixture_preserves_warm_state(monkeypatch, tmp_path, module_name, fixture_name, finish, body_override):
    fixture = getattr(importlib.import_module(module_name), fixture_name).__wrapped__
    config, detection, values, selections = _warm(monkeypatch)
    lock = config._thinking_model_lock
    patch = pytest.MonkeyPatch()
    kwargs = {}
    if "monkeypatch" in fixture.__code__.co_varnames[:fixture.__code__.co_argcount]:
        kwargs["monkeypatch"] = patch
    if "tmp_path" in fixture.__code__.co_varnames[:fixture.__code__.co_argcount]:
        kwargs["tmp_path"] = tmp_path
    generator = fixture(**kwargs)
    try:
        next(generator)
        assert detection._cached_llm_availability is None
        assert config._cached_thinking_model is None
        assert config._operator_primary_override is None
        assert detection._cached_ollama_capabilities == {}
        assert detection._cached_ollama_capabilities is not values["_cached_ollama_capabilities"]
        if body_override:
            patch.setattr(config, "_cached_thinking_model", None)
            patch.setattr(detection, "_cached_ollama_models", ["body"])
        if finish == "resume":
            with pytest.raises(StopIteration):
                next(generator)
        elif finish == "interrupt":
            with pytest.raises(KeyboardInterrupt):
                generator.throw(KeyboardInterrupt)
        else:
            generator.close()
        patch.undo()
        for owner, entries in ((detection, values), (config, selections)):
            for name, value in entries.items():
                assert getattr(owner, name) is value, name
        assert values["_cached_ollama_models"] == ["caller"]
        assert values["_ollama_capability_probing_disabled"] == {"http://caller:11434"}
        assert config._thinking_model_lock is lock
    finally:
        generator.close()
        patch.undo()


@pytest.mark.parametrize("fail_at", [1, 5, 6, 8])
def test_partial_publication_restores_both_modules(monkeypatch, fail_at):
    from core.testing import llm_state, module_state
    from contextlib import contextmanager
    from types import FunctionType

    config, detection, values, selections = _warm(monkeypatch)
    calls = 0

    class FailingPatch(pytest.MonkeyPatch):
        def setattr(self, *args, **kwargs):
            nonlocal calls
            super().setattr(*args, **kwargs)
            calls += 1
            if calls == fail_at:
                raise RuntimeError("publication interrupted")

    view = ModuleType("pytest")
    view.__dict__.update(vars(pytest))
    view.MonkeyPatch = FailingPatch
    original = module_state.isolated_module_state.__wrapped__
    private = FunctionType(original.__code__, {**original.__globals__, "pytest": view})
    private.__kwdefaults__ = original.__kwdefaults__
    monkeypatch.setattr(llm_state, "isolated_module_state", contextmanager(private))
    with pytest.raises(RuntimeError, match="publication interrupted"):
        with isolated_llm_resolution(config, detection):
            pytest.fail("body reached after setup failure")
    for owner, entries in ((detection, values), (config, selections)):
        for name, value in entries.items():
            assert getattr(owner, name) is value, name


def test_scope_uses_original_lock_and_nested_private_containers():
    from core.llm import config as real_config, detection as real_detection

    config = ModuleType(real_config.__name__)
    config.__dict__.update(vars(real_config))
    detection = ModuleType(real_detection.__name__)
    detection.__dict__.update(vars(real_detection))
    config._thinking_model_lock = Lock()
    config._cached_thinking_model = None
    config._thinking_model_checked = True
    config._operator_primary_override = None
    detection._cached_llm_availability = None
    detection._cached_ollama_models = ["caller"]
    detection._cached_ollama_capabilities = {}
    detection._ollama_capability_probing_disabled = set()
    detection._ollama_checked = True
    original = detection._cached_ollama_models
    with isolated_llm_resolution(config, detection):
        private = detection._cached_ollama_capabilities
        private[("local", "model")] = frozenset({"completion"})
        with isolated_llm_resolution(config, detection):
            assert detection._cached_ollama_capabilities == {}
            assert not config._thinking_model_lock.locked()
        assert detection._cached_ollama_capabilities is private
    assert detection._cached_ollama_models is original
