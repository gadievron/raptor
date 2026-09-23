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


# Flow-nesting depth bound, checked BEFORE the loader sees the text.
# Deeply nested flow collections (``x: `` + ``[`` * 50000) overflow
# the loader's stack: on current CPython the C-stack guard converts
# that into a RecursionError, but on interpreters without the guard
# (inside the supported >=3.10 floor) libyaml dies in a native stack
# overflow — a hard crash no except clause can catch. The pre-scan is
# linear and deliberately QUOTE-BLIND: modelling YAML string syntax
# here would have to be exactly right in both directions, and an
# unmatched quote in a plain scalar must never swallow a later
# bracket run the loader still sees. Counting every bracket can only
# over-estimate depth, and over-estimation is safe — refusal is the
# bounded path (an ordinary YAMLError). Trade-off, both directions:
# lower rejects legitimate documents whose string content carries
# many net-unclosed openers; higher readmits the stack-overflow
# window on unguarded interpreters (default recursion headroom is
# ~1000 frames and the composer spends several per level). A
# legitimate manifest needing >1000 net-unclosed brackets — even
# counting every quoted one — is not a shape observed anywhere.
MAX_FLOW_DEPTH = 1000


def _flow_depth_exceeded(text: str, limit: int = MAX_FLOW_DEPTH) -> bool:
    """True when raw flow-bracket depth in *text* exceeds *limit*
    (quote-blind by design — see the bound's comment)."""
    depth = 0
    for ch in text:
        if ch in "[{":
            depth += 1
            if depth > limit:
                return True
        elif ch in "]}":
            if depth:
                depth -= 1
    return False


def _check_depth(stream: Any) -> None:
    if isinstance(stream, str) and _flow_depth_exceeded(stream):
        raise _yaml.YAMLError(
            f"flow nesting deeper than {MAX_FLOW_DEPTH} — refusing to "
            "load (deep flow nesting overflows the YAML loader stack)"
        )


def safe_load(stream: Any) -> Any:
    """``yaml.safe_load`` using ``CSafeLoader`` when available."""
    yaml_mod = _require_yaml()
    _check_depth(stream)
    return yaml_mod.load(stream, Loader=_Loader)


def safe_load_all(stream: Any) -> Iterator[Any]:
    """``yaml.safe_load_all`` using ``CSafeLoader`` when available."""
    yaml_mod = _require_yaml()
    _check_depth(stream)
    return yaml_mod.load_all(stream, Loader=_Loader)


__all__ = ["safe_load", "safe_load_all"]
