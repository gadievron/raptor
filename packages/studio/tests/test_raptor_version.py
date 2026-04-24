"""Tests for raptor_version.

Inside the raptor tree the version is a direct ``from core.config import
RaptorConfig`` — no RAPTOR_HOME env var, no regex, no git fallback. The
companion repo (yesnet0/raptor-studio) uses the scrape-based fallback.
"""

from __future__ import annotations


def _fresh_module():
    """Reimport the version module so the lru_cache starts empty and any
    patches to ``core.config`` are observed."""
    import importlib, sys
    name = "packages.studio.services.raptor_version"
    if name in sys.modules:
        importlib.reload(sys.modules[name])
    from packages.studio.services import raptor_version as mod
    mod.raptor_version.cache_clear()
    return mod


def test_reads_version_from_raptor_config():
    mod = _fresh_module()
    # When run inside raptor's tree, RaptorConfig.VERSION is importable.
    val = mod.raptor_version()
    assert isinstance(val, str)
    assert val != ""  # raptor always has a version


def test_returns_empty_when_import_fails(monkeypatch):
    mod = _fresh_module()

    def raise_import(*a, **kw):  # pragma: no cover — used only via patch
        raise ImportError("core.config missing")

    # Force the import-guard branch.
    monkeypatch.setattr(
        mod, "raptor_version",
        mod.raptor_version.__wrapped__,  # type: ignore[attr-defined]
    )
    # Patch the module's `from core.config import RaptorConfig` site by
    # removing core.config from sys.modules and blocking the import.
    import sys, builtins
    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "core.config" or name == "core":
            raise ImportError("blocked for test")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    sys.modules.pop("core.config", None)
    assert mod.raptor_version() == ""


def test_returns_empty_when_version_attr_missing(monkeypatch):
    mod = _fresh_module()

    class _StubCfg:
        OTHER = "noise"  # no VERSION

    import sys
    stub = type(sys)("core.config")
    stub.RaptorConfig = _StubCfg
    monkeypatch.setitem(sys.modules, "core.config", stub)
    # Reload so the cached import inside raptor_version picks up the stub
    import importlib
    importlib.reload(sys.modules["packages.studio.services.raptor_version"])
    from packages.studio.services import raptor_version as reloaded
    reloaded.raptor_version.cache_clear()
    assert reloaded.raptor_version() == ""


def test_strips_whitespace(monkeypatch):
    mod = _fresh_module()

    class _StubCfg:
        VERSION = "  3.4.5  "

    import sys, importlib
    stub = type(sys)("core.config")
    stub.RaptorConfig = _StubCfg
    monkeypatch.setitem(sys.modules, "core.config", stub)
    importlib.reload(sys.modules["packages.studio.services.raptor_version"])
    from packages.studio.services import raptor_version as reloaded
    reloaded.raptor_version.cache_clear()
    assert reloaded.raptor_version() == "3.4.5"
