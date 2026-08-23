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
from typing import Protocol, TYPE_CHECKING


if TYPE_CHECKING:
    from ..models import Dependency, Manifest
    from collections.abc import Callable, Iterator

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

# Pattern matching ``_safe_read.read_bounded``'s refusal warnings
# (``sca.parsers: refusing to read <path> (size=N > max=M) ...`` for
# oversize manifests, and the non-regular-file variant). Without this
# an over-cap manifest is warning-logged but invisible in the
# structured ``parse_failures`` on the run report, while a malformed
# sibling shows up — the operator would have no structured trace of
# the skipped file.
_READ_REFUSAL_RE = re.compile(
    r"sca\.parsers:\s+refusing to read\s+"
    r"(?P<path>.+?)\s+\((?P<reason>[^)]+)\)"
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
        self.failures: list[ParseFailure] = []

    def emit(self, record: logging.LogRecord) -> None:
        if getattr(_TLS, 'collector', None) is not self:
            return
        try:
            msg = record.getMessage()
        except Exception:                               # noqa: BLE001
            return
        m = _PARSE_FAILURE_RE.search(msg)
        if m is None:
            m = _READ_REFUSAL_RE.search(msg)
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
def capture_parse_failures() -> Iterator[list[ParseFailure]]:
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
    filenames: list[str]

    def parse(self, path: Path) -> list[Dependency]: ...


# Filename → parser function. Populated by each parser module's
# ``register()`` call at import time. Functions take an absolute path and
# return a list of Dependency rows.
_REGISTRY: dict[str, Callable[[Path], list[Dependency]]] = {}

# Suffix → parser function for extension-based dispatch (e.g., .csproj).
_SUFFIX_REGISTRY: dict[str, Callable[[Path], list[Dependency]]] = {}

# Predicate → parser function for shapes that can't be keyed by name alone
# (e.g., the requirements*.txt convention).
_PREDICATE_REGISTRY: list[
    tuple[Callable[[Path], bool], Callable[[Path], list[Dependency]]]
] = []


def register(
    *,
    filenames: list[str] | None = None,
    suffixes: list[str] | None = None,
    predicate: Callable[[Path], bool] | None = None,
) -> Callable[
    [Callable[[Path], list[Dependency]]], Callable[[Path], list[Dependency]]
]:
    """Register a parser function for the given filename / suffix / predicate.

    A parser may register under any combination of the three. At dispatch
    time we try (in order): exact filename, predicate, suffix.
    """

    def _wrap(
        fn: Callable[[Path], list[Dependency]],
    ) -> Callable[[Path], list[Dependency]]:
        for name in filenames or ():
            if name in _REGISTRY and _REGISTRY[name] is not fn:
                msg = f"sca.parsers: duplicate registration for filename {name!r}"
                raise RuntimeError(msg)
            _REGISTRY[name] = fn
        for sfx in suffixes or ():
            if sfx in _SUFFIX_REGISTRY and _SUFFIX_REGISTRY[sfx] is not fn:
                msg = f"sca.parsers: duplicate registration for suffix {sfx!r}"
                raise RuntimeError(msg)
            _SUFFIX_REGISTRY[sfx] = fn
        if predicate is not None:
            _PREDICATE_REGISTRY.append((predicate, fn))
        return fn

    return _wrap


def parse_manifest(manifest: Manifest) -> list[Dependency]:
    """Dispatch a Manifest record to its parser; return [] on miss/failure."""
    fn = _resolve(manifest.path)
    if fn is None:
        logger.debug("sca.parsers: no parser for %s", manifest.path)
        return []
    try:
        return fn(manifest.path)
    except Exception:  # noqa: BLE001 — parsers must never break the pipeline
        logger.warning(
            "sca.parsers.dispatch: uncaught parse failed for %s: "
            "parser raised an unhandled exception",
            manifest.path,
            exc_info=True,
        )
        return []


def _resolve(
    path: Path,
) -> Callable[[Path], list[Dependency]] | None:
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
