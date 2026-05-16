"""
RAPTOR Core Utilities

Re-exports key components for easy importing — LAZILY so that
``import core`` doesn't drag in every transitive dependency at
module-load time.

Pre-fix this module did unconditional eager imports:

    from core.config import RaptorConfig
    from core.logging import get_logger
    from core.sarif.parser import (
        deduplicate_findings, parse_sarif_findings, validate_sarif,
        generate_scan_metrics, sanitize_finding_for_display,
    )
    from core.git import clone_repository
    from core.hash import sha256_tree

`import core` (or any `from core import X`) thus paid the full
cost of:

  * core.sarif.parser — regex compiles, schema validation imports
    (jsonschema, hashlib, json, re).
  * core.git — git-clone wrapper + sandbox imports.
  * core.hash — hashlib + filesystem walking helpers.

For consumers that only need (say) `from core.config import
RaptorConfig` directly, the eager re-exports added 100-300 ms
to import time on a cold startup — measurable on small CLI
tools that do a single read-config-then-exit.

Use PEP 562 ``__getattr__`` so each attribute is imported on
first access only. ``from core import RaptorConfig`` triggers
__getattr__("RaptorConfig"), imports core.config, returns the
class. Subsequent accesses hit the module's regular namespace
because __getattr__ stores the resolved value.
"""

from typing import Any

# Map of public name → (submodule, attribute_name). Keep in sync
# with __all__ below.
_LAZY_EXPORTS = {
    "RaptorConfig":               ("core.config",       "RaptorConfig"),
    "get_logger":                 ("core.logging",      "get_logger"),
    "deduplicate_findings":       ("core.sarif.parser", "deduplicate_findings"),
    "parse_sarif_findings":       ("core.sarif.parser", "parse_sarif_findings"),
    "validate_sarif":             ("core.sarif.parser", "validate_sarif"),
    "generate_scan_metrics":      ("core.sarif.parser", "generate_scan_metrics"),
    "sanitize_finding_for_display": ("core.sarif.parser", "sanitize_finding_for_display"),
    "clone_repository":           ("core.git",          "clone_repository"),
    "sha256_tree":                ("core.hash",         "sha256_tree"),
}


def __getattr__(name: str) -> Any:
    """Lazily import re-exported attributes (PEP 562).

    Raises AttributeError for unknown names so the standard
    "module has no attribute X" error message reaches callers.
    """
    spec = _LAZY_EXPORTS.get(name)
    if spec is None:
        raise AttributeError(f"module 'core' has no attribute {name!r}")
    submod_name, attr_name = spec
    import importlib
    submod = importlib.import_module(submod_name)
    value = getattr(submod, attr_name)
    # Cache on this module so subsequent accesses bypass __getattr__.
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    """Expose lazy exports to ``dir(core)`` and tab-completion."""
    return sorted(set(globals()) | set(_LAZY_EXPORTS))


__all__ = [
    "RaptorConfig",
    "get_logger",
    "deduplicate_findings",
    "parse_sarif_findings",
    "validate_sarif",
    "generate_scan_metrics",
    "sanitize_finding_for_display",
    "clone_repository",
    "sha256_tree",
]
