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


@contextmanager
def scoped_claudecode_discovery(config, detection):
    """Own Claude PATH discovery through local imports and provider dispatch.

    Detection's module lookup follows the current private import view, including
    body-installed mocks. Cache ownership remains the caller's responsibility.
    """
    import shutil
    import pytest

    from core.testing.module_bindings import patch_module_attribute
    from core.testing.module_views import scoped_function_imports

    with (
        scoped_function_imports(
            config, ("_entry_auth_resolvable", "_build_claudecode_config"),
            {"shutil": shutil}, registries=("_PROVIDER_BUILDERS",),
        ) as imports,
        pytest.MonkeyPatch.context() as scope,
    ):
        patch_module_attribute(
            scope, detection, "shutil", "which",
            lambda *args, **kwargs: imports.shutil.which(*args, **kwargs),
        )
        yield imports
