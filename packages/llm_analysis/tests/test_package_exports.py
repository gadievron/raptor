"""Leaf imports stay light; the public facade retains its canonical objects."""
from __future__ import annotations

from importlib import import_module
import os
from pathlib import Path
import subprocess
import sys
from types import ModuleType

import pytest

import packages.llm_analysis as package


_ROOT = Path(__file__).resolve().parents[3]
_SOURCE = _ROOT / "packages/llm_analysis/__init__.py"
_PUBLIC = {
    "AutonomousSecurityAgentV2": ("packages.llm_analysis.agent", "AutonomousSecurityAgentV2"),
    "LLMAvailability": ("core.llm.detection", "LLMAvailability"),
    "LLMClient": ("core.llm.client", "LLMClient"),
    "LLMConfig": ("core.llm.config", "LLMConfig"),
    "ModelConfig": ("core.llm.config", "ModelConfig"),
    "detect_llm_availability": ("core.llm.detection", "detect_llm_availability"),
    "get_client": ("core.llm.factory", "get_client"),
}
_CONTRACTS = {**_PUBLIC, "agent": ("packages.llm_analysis.agent", None)}


@pytest.fixture
def owned_facade():
    # Never publish this namespace or fake providers in sys.modules. Reload
    # and failure probes therefore cannot alter another test's imports.
    code = compile(_SOURCE.read_text(encoding="utf-8"), str(_SOURCE), "exec")
    facade = ModuleType(package.__name__)
    exec(code, vars(facade))
    providers = {}
    for module_name, attribute in _CONTRACTS.values():
        provider = providers.setdefault(module_name, ModuleType(module_name))
        if attribute is not None:
            setattr(provider, attribute, object())
    calls = []

    def load(name):
        calls.append(name)
        return providers[name]

    facade._import_module = load
    return facade, providers, calls, code, load


@pytest.mark.parametrize("name", _CONTRACTS)
def test_export_resolves_once_to_its_provider_object(owned_facade, name):
    facade, providers, calls, _, _ = owned_facade
    module_name, attribute = _CONTRACTS[name]
    expected = providers[module_name] if attribute is None else getattr(providers[module_name], attribute)
    assert getattr(facade, name) is expected
    assert getattr(facade, name) is expected
    assert vars(facade)[name] is expected
    assert calls == [module_name]


def test_discovery_and_unknown_names_do_not_load_providers(owned_facade):
    facade, _, calls, _, _ = owned_facade
    assert facade.__all__ == list(_PUBLIC)
    assert set(_CONTRACTS) <= set(dir(facade))
    with pytest.raises(AttributeError, match="not_a_public_export"):
        getattr(facade, "not_a_public_export")
    assert calls == []


@pytest.mark.parametrize("failure", ["import", "attribute"])
def test_failed_resolution_is_not_cached_and_can_retry(owned_facade, failure):
    facade, providers, _, _, load = owned_facade
    provider = providers["core.llm.client"]
    expected = provider.LLMClient

    def fail(name):
        raise ImportError("provider unavailable")

    if failure == "import":
        facade._import_module = fail
    else:
        del provider.LLMClient
    with pytest.raises(ImportError if failure == "import" else AttributeError):
        getattr(facade, "LLMClient")
    assert "LLMClient" not in vars(facade)
    provider.LLMClient = expected
    facade._import_module = load
    assert facade.LLMClient is expected


def test_reexecution_refreshes_owned_cached_aliases(owned_facade):
    facade, providers, calls, code, load = owned_facade
    for name in _CONTRACTS:
        getattr(facade, name)
    for module_name, attribute in _PUBLIC.values():
        setattr(providers[module_name], attribute, object())
    exec(code, vars(facade))
    assert not set(_CONTRACTS).intersection(vars(facade))
    assert len(calls) == len(_CONTRACTS)
    facade._import_module = load
    for name, (module_name, attribute) in _CONTRACTS.items():
        expected = providers[module_name] if attribute is None else getattr(providers[module_name], attribute)
        assert getattr(facade, name) is expected
    assert len(calls) == 2 * len(_CONTRACTS)


def test_leaf_import_and_reload_work_without_site_packages(tmp_path):
    home, scratch, output = (tmp_path / name for name in ("home", "tmp", "out"))
    for directory in (home, scratch, output):
        directory.mkdir()
    env = dict(os.environ, HOME=str(home), TMPDIR=str(scratch), RAPTOR_OUT_DIR=str(output),
               RAPTOR_WORK_DIR=str(scratch), RAPTOR_DIR=str(_ROOT),
               XDG_CONFIG_HOME=str(home / "config"), XDG_CACHE_HOME=str(home / "cache"),
               XDG_DATA_HOME=str(home / "data"), XDG_STATE_HOME=str(home / "state"),
               RAPTOR_REGISTRY_HOME=str(home / "registry"))
    env.pop("RAPTOR_CALLER_DIR", None)
    code = f"import sys; sys.path.insert(0, {str(_ROOT)!r})\n" + '''
from importlib import reload
import packages.llm_analysis as package
assert set(package.__all__) <= set(dir(package))
try:
    package.not_a_public_export
except AttributeError:
    pass
else:
    raise AssertionError("unknown name was accepted")
package.LLMClient = object()
package.agent = object()
reload(package)
assert "LLMClient" not in vars(package) and "agent" not in vars(package)
from packages.llm_analysis import journal_emit
assert journal_emit.build_journal_body({"reasoning": "bounded"}) == "bounded"
for name in ("packages.llm_analysis.agent", "core.llm.client", "core.llm.providers",
             "core.llm.model_brokers", "openai", "anthropic"):
    assert name not in sys.modules, name
'''
    result = subprocess.run([sys.executable, "-I", "-S", "-c", code],
                            cwd=_ROOT, env=env, stdin=subprocess.DEVNULL,
                            capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, (result.stdout, result.stderr)


# Resolving the complete API intentionally loads the agent and SDKs. The fast
# owned-provider contracts pin every target; this adds native object parity.
@pytest.mark.slow
def test_native_public_exports_and_star_import_keep_canonical_identity():
    assert package.__all__ == list(_PUBLIC)
    for name, (module_name, attribute) in _PUBLIC.items():
        assert getattr(package, name) is getattr(import_module(module_name), attribute)
    assert package.agent is import_module("packages.llm_analysis.agent")
    namespace = {}
    exec("from packages.llm_analysis import *", namespace)
    assert all(namespace[name] is getattr(package, name) for name in _PUBLIC)
