"""Regression tests for F046.

`core/json/__init__.py` eagerly re-exported `CacheEnvelope` and
`TTL_FOREVER` despite having zero external (non-test) production
callers. The names are public surface — keeping them accessible
through `core.json` is intentional — but the *eager* re-export
imported `core.json.cache` on `import core.json`, paying the full
class-definition + dataclass-init cost for any consumer that only
wanted `load_json` / `save_json` from `core.json.utils`.

Mirrors 94712e5 (`fix(core/__init__): lazy re-exports via PEP 562
__getattr__`). Same shape: low-traffic re-exported symbols whose
import cost was paid by every consumer regardless of need.

Acceptance tests:
  1. The symbols remain accessible (public-API preservation).
  2. `from core.json import X` works for X in {CacheEnvelope,
     JsonCache, MISSING, TTL_FOREVER, load_json, save_json,
     load_json_with_comments} — round-trip identical to direct
     submodule import.
  3. AttributeError raised for unknown names (PEP 562 contract).
  4. `__all__` still includes all 7 names (no documentation drift).
  5. dir(core.json) surfaces all 7 (IDE tab-completion).
  6. `import core.json` alone does NOT eagerly load `core.json.cache`
     into `sys.modules` (the proof that the re-export is lazy).

The "import core.json doesn't pull cache" test is the RED-then-GREEN
fence — pre-fix it eagerly imports cache.
"""

from __future__ import annotations

import contextlib
import sys
from typing import Iterator

import pytest


@contextlib.contextmanager
def _fresh_core_json_window() -> Iterator[None]:
    """Drop core.json + submodules from sys.modules so a fresh
    `import core.json` re-runs __init__.py top-level, then RESTORE
    the pre-purge module objects on exit.

    Restoration is load-bearing: production modules bind names from
    core.json at import time (`from core.json import load_json` in
    packages/openant/recovery.py), so those functions live in the
    ORIGINAL core.json.utils namespace. Leaving fresh duplicates in
    sys.modules would make a later test's `import core.json.utils`
    resolve a module object production code never reads — its
    patch.object() calls would land on the wrong module.
    """
    saved = {
        mod: sys.modules.pop(mod)
        for mod in list(sys.modules)
        if mod == "core.json" or mod.startswith("core.json.")
    }
    try:
        yield
    finally:
        for mod in list(sys.modules):
            if mod == "core.json" or mod.startswith("core.json."):
                del sys.modules[mod]
        sys.modules.update(saved)
        # `import core.json` inside the window rebound the parent
        # package's `json` attribute to the fresh module; point it
        # back at the restored original (attribute access on an
        # already-imported package bypasses sys.modules).
        core_pkg = sys.modules.get("core")
        if core_pkg is not None:
            if "core.json" in saved:
                core_pkg.json = saved["core.json"]
            else:
                core_pkg.__dict__.pop("json", None)


@pytest.fixture
def fresh_core_json() -> Iterator[None]:
    with _fresh_core_json_window():
        yield


def test_f046_import_core_json_does_not_eagerly_load_cache(fresh_core_json):
    """After `import core.json`, `core.json.cache` should NOT yet be
    in sys.modules. Lazy access via __getattr__ pulls it on demand."""
    import core.json  # noqa: F401  — side-effect import
    assert "core.json.cache" not in sys.modules, (
        "core.json.cache eagerly loaded by `import core.json`; "
        "expected lazy access (94712e5 PEP 562 pattern)."
    )


def test_f046_lazy_attribute_access_returns_correct_objects(fresh_core_json):
    """After `import core.json`, accessing each lazy name must return
    the same object as a direct submodule import."""
    import core.json
    from core.json import cache as cache_mod
    from core.json import utils as utils_mod

    assert core.json.CacheEnvelope is cache_mod.CacheEnvelope
    assert core.json.JsonCache is cache_mod.JsonCache
    assert core.json.MISSING is cache_mod.MISSING
    assert core.json.TTL_FOREVER == cache_mod.TTL_FOREVER
    assert core.json.load_json is utils_mod.load_json
    assert core.json.save_json is utils_mod.save_json
    assert core.json.load_json_with_comments is utils_mod.load_json_with_comments


def test_f046_unknown_attribute_raises_attribute_error(fresh_core_json):
    """PEP 562 __getattr__ must raise AttributeError for unknown
    names so the standard 'module has no attribute' error reaches
    callers."""
    import core.json
    with pytest.raises(AttributeError, match=r"has no attribute"):
        _ = core.json.this_symbol_does_not_exist  # type: ignore[attr-defined]


def test_f046_dir_includes_all_public_names(fresh_core_json):
    """`dir(core.json)` must surface all 7 public re-exports so IDE
    tab-completion and inspection tools see them."""
    import core.json
    names = set(dir(core.json))
    expected = {
        "CacheEnvelope", "JsonCache", "MISSING", "TTL_FOREVER",
        "load_json", "save_json", "load_json_with_comments",
    }
    missing = expected - names
    assert not missing, f"dir(core.json) missing: {missing}"


def test_f046_fresh_import_window_restores_preexisting_modules():
    """The fresh-import window must hand back the ORIGINAL core.json*
    module objects when it closes.

    In-process regression for the deterministic 2-test repro: running
    this file then packages/openant test_recovery's
    test_nonfinite_confidence_dropped_record_stays_serializable in one
    pytest process. recovery.py binds `from core.json import load_json`
    at import time; the recovery test patches `_orjson` on whatever
    `import core.json.utils` resolves at call time. If this file's
    purge leaves fresh duplicates in sys.modules, the patch lands on a
    module object the held load_json never reads and the orjson lane
    stays live.
    """
    import core.json.utils as utils_before

    held = utils_before.load_json  # what an import-time consumer holds
    with _fresh_core_json_window():
        import core.json

        # The window really is fresh: lazy access re-imports utils
        # as a new module object.
        _ = core.json.load_json
        assert sys.modules["core.json.utils"] is not utils_before

    import core.json.utils as utils_after

    assert utils_after is utils_before, (
        "fresh-import window did not restore the pre-purge "
        "core.json.utils; import-time consumers now hold a module "
        "object patch.object() can no longer reach"
    )
    assert held.__globals__ is utils_after.__dict__


def test_f046_all_unchanged(fresh_core_json):
    """`__all__` must list every public name — no documentation
    drift introduced by the lazy refactor (or by later additions:
    ``append_jsonl`` / ``load_jsonl`` joined with core.json.jsonl;
    the bounded loaders joined with core.json.bounded)."""
    import core.json
    assert set(core.json.__all__) == {
        "CacheEnvelope", "DEFAULT_JSON_MAX_BYTES",
        "JsonBudgetExceededError", "JsonCache",
        "MISSING", "RE_DATABASE_MAX_BYTES", "TTL_FOREVER",
        "append_jsonl", "dumps_artifact", "dumps_canonical",
        "dumps_display",
        "load_json", "load_json_bounded", "load_json_unbounded",
        "load_json_with_comments", "load_jsonl", "loads",
        "loads_bounded", "save_json",
    }
