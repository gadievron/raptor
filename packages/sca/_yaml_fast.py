"""Faster ``yaml.safe_load`` / ``yaml.safe_load_all`` shims.

PyYAML ships two safe-loader implementations: ``SafeLoader`` (pure
Python, the default) and ``CSafeLoader`` (libyaml-backed C
extension, 4-10× faster on big YAML walks). When libyaml is
available, ``CSafeLoader`` produces byte-identical output for
documents PyYAML's safe loader handles, so callers that only need
to read scalar / mapping / sequence shapes can swap one for the
other without behavioural change.

The 2026-05-09 cProfile of a saleor scan showed ~4.7s spent in the
pure-Python YAML loader across 14 call sites (k8s manifests under
saleor/Dockerfile-FROM, compose files, pre-commit configs,
yarn.lock, suppression overlays). Importing ``CSafeLoader`` once
here and re-exporting two thin wrappers lets every site benefit
from one edit per file rather than per-site try/except imports.

Falls back transparently to the pure-Python loader when libyaml
isn't present (Alpine builds without ``python-yaml-libyaml``,
operator boxes that pip-installed PyYAML from sdist on a
``--no-binary`` policy, etc.). Behaviour is identical in both
modes — only speed differs.

PyYAML itself is an OPTIONAL dependency of the sca package: every
consumer guards its yaml-format lane with a use-site
``import yaml`` try/except and degrades to its non-yaml behaviour
when the library is absent (minimal environments such as the
data-refresh workflow install only what the JSON feeds need). This
module must uphold that contract, so the import is deferred: merely
importing the shim (which happens transitively from the package
``__init__`` fan-out) never requires PyYAML — only actually calling
``safe_load`` / ``safe_load_all`` does, and doing so without PyYAML
raises ``ModuleNotFoundError`` naming the missing dependency.
"""

from __future__ import annotations

from typing import Any, TYPE_CHECKING

try:
    import yaml as _yaml
except ModuleNotFoundError:
    _yaml = None  # type: ignore[assignment]

if TYPE_CHECKING:
    from collections.abc import Iterator

# None only when PyYAML is absent — unreachable from the load
# functions, which raise via _require_yaml() first.
_Loader: Any = None
if _yaml is not None:
    try:
        # libyaml-backed loader — present when PyYAML was built
        # against the system libyaml dev headers.
        _Loader = _yaml.CSafeLoader  # type: ignore[attr-defined]
    except AttributeError:
        _Loader = _yaml.SafeLoader


def _require_yaml() -> Any:
    """Return the ``yaml`` module, or raise a precise use-time error."""
    if _yaml is None:
        raise ModuleNotFoundError(
            "PyYAML is not installed — packages.sca imports without it "
            "(yaml parsing is an optional lane), but this call needs it. "
            "Install 'pyyaml' to parse YAML documents."
        )
    return _yaml


def safe_load(stream: Any) -> Any:
    """``yaml.safe_load`` using ``CSafeLoader`` when available."""
    return _require_yaml().load(stream, Loader=_Loader)


def safe_load_all(stream: Any) -> Iterator[Any]:
    """``yaml.safe_load_all`` using ``CSafeLoader`` when available."""
    return _require_yaml().load_all(stream, Loader=_Loader)


__all__ = ["safe_load", "safe_load_all"]
