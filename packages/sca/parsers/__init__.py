"""Manifest parsers — one per file format.

Every parser implements:

    class ManifestParser(Protocol):
        ecosystem: str
        filenames: List[str]
        def parse(self, path: Path) -> List[Dependency]: ...

Discovery emits ``Manifest`` records keyed by filename; ``parse_manifest``
dispatches to the right parser. Parsers do not call out to the network,
do not execute code in the target repo, and do not raise on syntactically
mangled input — they emit best-effort ``Dependency`` rows with a
``parser_confidence`` reflecting how sure they are.

Why a registry instead of importing a parser by name at the call site:
new ecosystems land as additive commits, and the dispatch layer should
not need editing for each one. Each parser module registers itself when
imported.

Parser failure policy:
- Unrecoverable I/O / syntax error → return [] and log a warning. The
  pipeline records this via the ``parse_failures`` counter on the run
  report; it does not abort.
- Partial parse (e.g., one bad <dependency> in a 200-entry POM) → emit
  the rows we got, drop the bad one with a debug log.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Callable, Dict, List, Optional, Protocol

from ..models import Dependency, Manifest

logger = logging.getLogger(__name__)


class ManifestParser(Protocol):
    """Structural type every parser conforms to."""

    ecosystem: str
    filenames: List[str]

    def parse(self, path: Path) -> List[Dependency]: ...


# Filename → parser function. Populated by each parser module's
# ``register()`` call at import time. Functions take an absolute path and
# return a list of Dependency rows.
_REGISTRY: Dict[str, Callable[[Path], List[Dependency]]] = {}

# Suffix → parser function for extension-based dispatch (e.g., .csproj).
_SUFFIX_REGISTRY: Dict[str, Callable[[Path], List[Dependency]]] = {}

# Predicate → parser function for shapes that can't be keyed by name alone
# (e.g., the requirements*.txt convention).
_PREDICATE_REGISTRY: List[
    "tuple[Callable[[Path], bool], Callable[[Path], List[Dependency]]]"
] = []


def register(
    *,
    filenames: Optional[List[str]] = None,
    suffixes: Optional[List[str]] = None,
    predicate: Optional[Callable[[Path], bool]] = None,
) -> Callable[
    [Callable[[Path], List[Dependency]]], Callable[[Path], List[Dependency]]
]:
    """Register a parser function for the given filename / suffix / predicate.

    A parser may register under any combination of the three. At dispatch
    time we try (in order): exact filename, predicate, suffix.
    """

    def _wrap(
        fn: Callable[[Path], List[Dependency]],
    ) -> Callable[[Path], List[Dependency]]:
        for name in filenames or ():
            if name in _REGISTRY and _REGISTRY[name] is not fn:
                raise RuntimeError(
                    f"sca.parsers: duplicate registration for filename {name!r}"
                )
            _REGISTRY[name] = fn
        for sfx in suffixes or ():
            if sfx in _SUFFIX_REGISTRY and _SUFFIX_REGISTRY[sfx] is not fn:
                raise RuntimeError(
                    f"sca.parsers: duplicate registration for suffix {sfx!r}"
                )
            _SUFFIX_REGISTRY[sfx] = fn
        if predicate is not None:
            _PREDICATE_REGISTRY.append((predicate, fn))
        return fn

    return _wrap


def parse_manifest(manifest: Manifest) -> List[Dependency]:
    """Dispatch a Manifest record to its parser; return [] on miss/failure."""
    fn = _resolve(manifest.path)
    if fn is None:
        logger.debug("sca.parsers: no parser for %s", manifest.path)
        return []
    try:
        return fn(manifest.path)
    except Exception:  # noqa: BLE001 — parsers must never break the pipeline
        logger.warning(
            "sca.parsers: parser raised on %s; emitting empty dep list",
            manifest.path,
            exc_info=True,
        )
        return []


def _resolve(
    path: Path,
) -> Optional[Callable[[Path], List[Dependency]]]:
    name = path.name
    if name in _REGISTRY:
        return _REGISTRY[name]
    for pred, fn in _PREDICATE_REGISTRY:
        try:
            if pred(path):
                return fn
        except Exception:  # noqa: BLE001 — predicate is best-effort
            continue
    sfx = path.suffix
    if sfx in _SUFFIX_REGISTRY:
        return _SUFFIX_REGISTRY[sfx]
    return None


# Side-effect imports: each module calls register() at import time.
# Order is irrelevant — the registry is keyed by filename.
from . import cargo               # noqa: E402,F401
from . import cmake_fetchcontent  # noqa: E402,F401
from . import compose             # noqa: E402,F401
from . import composer            # noqa: E402,F401
from . import conan               # noqa: E402,F401
from . import gemfile             # noqa: E402,F401
from . import gitlab_ci           # noqa: E402,F401
from . import gitmodules          # noqa: E402,F401
from . import gomod               # noqa: E402,F401
from . import gradle_dsl          # noqa: E402,F401
from . import gradle_lockfile     # noqa: E402,F401
from . import helm_chart          # noqa: E402,F401
from . import inline_installs     # noqa: E402,F401
from . import kubernetes          # noqa: E402,F401
from . import nuget               # noqa: E402,F401
from . import package_json        # noqa: E402,F401
from . import package_lock_json   # noqa: E402,F401
from . import pipfile_lock        # noqa: E402,F401
from . import pnpm_lock           # noqa: E402,F401
from . import poetry_lock         # noqa: E402,F401
from . import pom                 # noqa: E402,F401
from . import precommit           # noqa: E402,F401
from . import pyproject           # noqa: E402,F401
from . import requirements        # noqa: E402,F401
from . import uv_lock             # noqa: E402,F401
from . import vcpkg               # noqa: E402,F401
from . import yarn_lock           # noqa: E402,F401


__all__ = [
    "ManifestParser",
    "parse_manifest",
    "register",
]
