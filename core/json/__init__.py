"""JSON utilities — one-shot load/save + TTL'd disk cache.

Re-exports are LAZY (PEP 562) so `import core.json` doesn't drag in
`core.json.cache` (and its `JsonCache` class definition + dataclass
machinery) for consumers that only need `load_json` / `save_json` /
`load_json_with_comments` from `core.json.utils`.

Pre-fix:
    from .cache import CacheEnvelope, JsonCache, MISSING, TTL_FOREVER
    from .utils import load_json, save_json, load_json_with_comments

That eagerly imported both submodules on every `import core.json`,
even though F046's wider audit found `CacheEnvelope` and `TTL_FOREVER`
have ZERO production callers outside `core.json.cache` itself — they
are public sentinel/value-type surface kept for future consumers, not
for the current caller set.

Mirrors 94712e5 (`fix(core/__init__): lazy re-exports via PEP 562
__getattr__`) at sibling package depth. Same shape, same rationale.

`__all__` is unchanged; `dir(core.json)` still surfaces the full set
for tab-completion. Direct submodule imports
(`from core.json.cache import JsonCache`) continue to work and are
the preferred form when the consumer knows it needs cache machinery.
"""

from typing import Any

# Map of public name → (submodule, attribute_name). Keep in sync
# with __all__ below.
_LAZY_EXPORTS = {
    "CacheEnvelope":          ("core.json.cache", "CacheEnvelope"),
    "JsonCache":              ("core.json.cache", "JsonCache"),
    "MISSING":                ("core.json.cache", "MISSING"),
    "TTL_FOREVER":            ("core.json.cache", "TTL_FOREVER"),
    "load_json":              ("core.json.utils", "load_json"),
    "save_json":              ("core.json.utils", "save_json"),
    "load_json_with_comments": ("core.json.utils", "load_json_with_comments"),
}


def __getattr__(name: str) -> Any:
    """Lazily import re-exported attributes (PEP 562).

    Raises AttributeError for unknown names so the standard
    "module has no attribute X" error message reaches callers.
    """
    spec = _LAZY_EXPORTS.get(name)
    if spec is None:
        raise AttributeError(
            f"module 'core.json' has no attribute {name!r}"
        )
    submod_name, attr_name = spec
    import importlib
    submod = importlib.import_module(submod_name)
    value = getattr(submod, attr_name)
    # Cache on this module so subsequent accesses bypass __getattr__.
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    """Expose lazy exports to ``dir(core.json)`` and tab-completion."""
    return sorted(set(globals()) | set(_LAZY_EXPORTS))


__all__ = [
    "CacheEnvelope",
    "JsonCache",
    "MISSING",
    "TTL_FOREVER",
    "load_json",
    "save_json",
    "load_json_with_comments",
]
