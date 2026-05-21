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
"""

from __future__ import annotations

from typing import Any, Iterator

import yaml

try:
    # libyaml-backed loader — present when PyYAML was built
    # against the system libyaml dev headers.
    _Loader = yaml.CSafeLoader  # type: ignore[attr-defined]
except AttributeError:
    _Loader = yaml.SafeLoader


def safe_load(stream: Any) -> Any:
    """``yaml.safe_load`` using ``CSafeLoader`` when available."""
    return yaml.load(stream, Loader=_Loader)


def safe_load_all(stream: Any) -> Iterator[Any]:
    """``yaml.safe_load_all`` using ``CSafeLoader`` when available."""
    return yaml.load_all(stream, Loader=_Loader)


__all__ = ["safe_load", "safe_load_all"]
