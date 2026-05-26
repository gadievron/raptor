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
import re
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, Iterator, List, Optional, Protocol

from ..models import Dependency, Manifest

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ParseFailure:
    """One swallowed parser warning surfaced for the run report.

    ``parsers/<eco>/parse`` modules catch I/O / syntax errors
    internally and return ``[]`` rather than crash the pipeline —
    correct policy for individual parsers, but operationally
    invisible: an operator running ``raptor-sca`` against a tree
    where every pom.xml is malformed gets back "0 deps analysed"
    with no indication of WHY. This record lets the runner expose
    the failure in ``report.md`` so the operator can fix the
    manifest instead of mistaking the empty result for a clean
    project.
    """

    path: Path
    reason: str


# Pattern matching the warning shape every parser emits when it
# catches a parse error. The format (``sca.parsers.<eco>: <kind>
# parse failed for <path>: <message>``) is stable across the
# codebase — see ``pom.py``, ``pipfile_lock.py``,
# ``package_lock_json.py``, etc. The path captured is the
# parser's view of the manifest, which is what we want to show
# operators.
_PARSE_FAILURE_RE = re.compile(
    r"sca\.parsers\.[\w_]+:\s+"
    r"(?P<kind>\w+(?:\s\w+)?)\s+parse failed for\s+"
    r"(?P<path>.+?):\s+(?P<reason>.+)$"
)


class _ParseFailureCollector(logging.Handler):
    """Logging handler that captures ``sca.parsers.*`` parse-failed
    warnings into a thread-local list.

    Attached/detached around the discovery stage via
    :func:`capture_parse_failures`. Catches the warnings parsers
    already emit (no per-parser source edit), parses the path +
    reason out of the formatted message, and surfaces them on the
    run report.
    """

    def __init__(self) -> None:
        super().__init__(level=logging.WARNING)
        self.failures: List[ParseFailure] = []

    def emit(self, record: logging.LogRecord) -> None:
        try:
            msg = record.getMessage()
        except Exception:                               # noqa: BLE001
            return
        m = _PARSE_FAILURE_RE.search(msg)
        if m is None:
            return
        path_str = m.group("path").strip()
        reason = m.group("reason").strip()
        try:
            path = Path(path_str)
        except (TypeError, ValueError):
            return
        self.failures.append(ParseFailure(path=path, reason=reason))


# Thread-local collector ref so concurrent runs (rare today but
# defensible — pytest collection, embedded scans) don't bleed into
# one another's failure lists.
_TLS = threading.local()


@contextmanager
def capture_parse_failures() -> Iterator[List[ParseFailure]]:
    """Capture parser-emitted parse-failed warnings for the
    duration of the context.

    Usage::

        with capture_parse_failures() as failures:
            for m in manifests:
                parse_manifest(m)
        # ``failures`` now holds one ``ParseFailure`` per swallowed
        # parser warning matching the canonical format string.

    Attaches a logging handler at the ``packages.sca.parsers``
    logger so warnings from any descendent parser (e.g.
    ``packages.sca.parsers.pom``, ``packages.sca.parsers.pipfile_lock``)
    propagate through and get captured. Detaches on exit so a
    pipeline failure doesn't leak the handler across runs.
    """
    handler = _ParseFailureCollector()
    parsers_logger = logging.getLogger(__name__)
    parsers_logger.addHandler(handler)
    _TLS.collector = handler
    try:
        yield handler.failures
    finally:
        parsers_logger.removeHandler(handler)
        _TLS.collector = None


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
