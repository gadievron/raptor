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

import sys

import pytest


def _force_fresh_core_json_import():
    """Drop core.json + core.json.cache from sys.modules so a fresh
    `import core.json` re-runs __init__.py top-level."""
    for mod in list(sys.modules):
        if mod == "core.json" or mod.startswith("core.json."):
            del sys.modules[mod]


def test_f046_import_core_json_does_not_eagerly_load_cache():
    """After `import core.json`, `core.json.cache` should NOT yet be
    in sys.modules. Lazy access via __getattr__ pulls it on demand."""
    _force_fresh_core_json_import()
    import core.json  # noqa: F401  — side-effect import
    assert "core.json.cache" not in sys.modules, (
        "core.json.cache eagerly loaded by `import core.json`; "
        "expected lazy access (94712e5 PEP 562 pattern)."
    )


def test_f046_lazy_attribute_access_returns_correct_objects():
    """After `import core.json`, accessing each lazy name must return
    the same object as a direct submodule import."""
    _force_fresh_core_json_import()
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


def test_f046_unknown_attribute_raises_attribute_error():
    """PEP 562 __getattr__ must raise AttributeError for unknown
    names so the standard 'module has no attribute' error reaches
    callers."""
    _force_fresh_core_json_import()
    import core.json
    with pytest.raises(AttributeError, match=r"has no attribute"):
        _ = core.json.this_symbol_does_not_exist  # type: ignore[attr-defined]


def test_f046_dir_includes_all_public_names():
    """`dir(core.json)` must surface all 7 public re-exports so IDE
    tab-completion and inspection tools see them."""
    _force_fresh_core_json_import()
    import core.json
    names = set(dir(core.json))
    expected = {
        "CacheEnvelope", "JsonCache", "MISSING", "TTL_FOREVER",
        "load_json", "save_json", "load_json_with_comments",
    }
    missing = expected - names
    assert not missing, f"dir(core.json) missing: {missing}"


def test_f046_all_unchanged():
    """`__all__` must still list all 7 public names — no
    documentation drift introduced by the lazy refactor."""
    _force_fresh_core_json_import()
    import core.json
    assert set(core.json.__all__) == {
        "CacheEnvelope", "JsonCache", "MISSING", "TTL_FOREVER",
        "load_json", "save_json", "load_json_with_comments",
    }
