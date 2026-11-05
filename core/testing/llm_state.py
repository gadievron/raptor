"""Per-test ownership of coupled LLM detection and selection caches."""

from contextlib import ExitStack, contextmanager

from core.testing.module_state import isolated_module_state


@contextmanager
def isolated_llm_resolution(config, detection):
    """Use cold private caches while retaining caller objects and the model lock."""
    with ExitStack() as scope:
        scope.enter_context(isolated_module_state(detection, {
            "_cached_llm_availability": None,
            "_cached_ollama_models": None,
            "_cached_ollama_capabilities": {},
            "_ollama_capability_probing_disabled": set(),
            "_ollama_checked": False,
        }))
        scope.enter_context(isolated_module_state(config, {
            "_cached_thinking_model": None,
            "_thinking_model_checked": False,
            "_operator_primary_override": None,
        }, lock=config._thinking_model_lock))
        yield
