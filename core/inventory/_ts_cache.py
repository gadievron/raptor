"""Shared tree-sitter grammar-import and Parser caches for
``core.inventory``.

``extractors.py`` (function extraction) and ``call_graph.py`` (call
edges) each grew their own grammar/parser caching, and the copies had
diverged: only call_graph's import cache remembered FAILED imports,
so on a grammar-less install every file of that language sent the
extractors loader back through the full import machinery. This module
is the one implementation both consume.

Grammar-import cache — success AND failure. Python does NOT cache
failed imports, so a per-file ``import tree_sitter_go`` on a
grammar-less install re-ran the full import machinery — plus a log
emission — for every file of that language. Besides the hot-loop
cost, both the import lock and the logging handler locks are exactly
what a fork-pool worker inherits FROZEN when the parent process is
multi-threaded (the stress sweep runs scans as threads), turning any
file of a grammar-less language into a deadlock site. Cache hits
touch neither lock, and the missing-grammar note fires once per
process instead of once per file.

Parser cache — per-thread. Each ``Parser`` holds C-side mutable
state (libtree-sitter's internal parse stack) — NOT thread-safe for
concurrent ``.parse()`` calls. The inventory builder fans out via
ThreadPoolExecutor, so a shared module-level dict would hand the same
Parser to multiple workers simultaneously. ``threading.local`` gives
every thread its own dict of parsers; the grammar is immutable, so
each thread still gets exactly one Parser per key for its lifetime.
The three consumers share the dict with disjoint key spaces:
extractors keys by language-name string, call_graph by
grammar-function identity (int), lexical_view by a
``("lexical_view", language)`` tuple — so the spaces cannot collide.
"""

from __future__ import annotations

import hashlib
import importlib
import logging
import os
import threading
import time
import warnings
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Callable

logger = logging.getLogger(__name__)

_GRAMMAR_CACHE: dict[str, Any] = {}


def import_grammar(module_name: str) -> Any:
    """Import a tree-sitter grammar module, caching success AND
    failure. Returns the module or ``None`` when not installed."""
    if module_name in _GRAMMAR_CACHE:
        return _GRAMMAR_CACHE[module_name]
    try:
        mod = importlib.import_module(module_name)
    except ImportError:
        logger.debug(
            "inventory: %s not installed; files of this language "
            "degrade to the regex / empty-call-graph fallbacks",
            module_name,
        )
        mod = None
    _GRAMMAR_CACHE[module_name] = mod
    return mod


# ---------------------------------------------------------------------------
# Bounded parse — the one chokepoint every tree-sitter parse of
# target-repo content goes through.
#
# tree-sitter error recovery is superlinear on crafted input: a
# ~50-byte JavaScript prefix of nested unterminated template literals
# drives the C-level parse loop for minutes (uninterruptible from
# Python — SIGALRM never fires because the GIL is held inside the C
# extension) and under memory pressure the grammar dies on a failed
# allocation (SIGSEGV) instead of raising. Scanned repos are
# untrusted, so every parse gets a wall budget enforced with the
# binding's native cancellation knob.
#
# Mechanism choice: ``Parser.timeout_micros`` — deprecated upstream
# in favour of ``progress_callback``, but the ONLY knob that works
# here: the binding ignores ``progress_callback`` for bytestring
# parses (every call site parses bytes), and routing bytes through a
# read-callable to make the callback effective is not memory-safe
# under error-recovery blowup. Revisit on binding upgrades; the
# regression tests pin the observable contract (hostile input aborts
# within budget, parser reusable after), not the knob.
# ---------------------------------------------------------------------------

# Default per-parse wall budget (seconds). Trade-off, both
# directions: larger admits more of the superlinear blowup per
# hostile file (N crafted files cost N x budget of wall time);
# smaller risks abandoning legitimately huge sources (multi-MB
# generated/minified files parse in low single-digit seconds — 20s
# is an order of magnitude above that while staying well under the
# inventory pool's 60s stall window, so a budgeted parse always
# resolves before the pool declares the worker wedged). Override
# with RAPTOR_TS_PARSE_BUDGET_S; <= 0 disables the bound (debugging
# escape hatch only).
DEFAULT_PARSE_BUDGET_S = 20.0
_BUDGET_ENV = "RAPTOR_TS_PARSE_BUDGET_S"

_missing_knob_warned = False


class ParseBudgetExceeded(Exception):
    """A tree-sitter parse exceeded its wall budget and was abandoned.

    Raised by :class:`BoundedParser` AFTER the analysis-gap record is
    emitted — catching this (or any broad ``except Exception``
    degradation around a parse) never silences the gap: the file is
    already on the run's ``analysis-gaps.jsonl`` trail.
    """


def parse_budget_s() -> float:
    """Resolve the per-parse wall budget from the environment."""
    raw = os.environ.get(_BUDGET_ENV, "")
    if raw:
        try:
            return float(raw)
        except ValueError:
            logger.warning(
                "%s=%r is not a number; using the %ss default",
                _BUDGET_ENV, raw, DEFAULT_PARSE_BUDGET_S,
            )
    return DEFAULT_PARSE_BUDGET_S


class BoundedParser:
    """Proxy over ``tree_sitter.Parser`` enforcing a per-parse wall
    budget.

    On budget exhaustion the underlying parser is reset (safe for
    reuse), a loud analysis-gap record is emitted naming the file the
    surrounding loop declared via ``core.run.gaps.parse_origin`` (or
    a content digest when unattributed), and
    :class:`ParseBudgetExceeded` is raised. All other attributes
    delegate to the wrapped parser.
    """

    __slots__ = ("_parser", "_label", "_budget_s")

    def __init__(self, parser: Any, label: str = "",
                 budget_s: float | None = None) -> None:
        global _missing_knob_warned
        self._parser = parser
        self._label = label
        self._budget_s = parse_budget_s() if budget_s is None else budget_s
        if self._budget_s > 0:
            # Probe the CLASS descriptor — a hasattr on the instance
            # would invoke the (deprecation-warning) getter.
            if hasattr(type(parser), "timeout_micros"):
                with warnings.catch_warnings():
                    # The deprecation points at progress_callback,
                    # which is a no-op for bytestring parses — see
                    # the mechanism-choice note above.
                    warnings.simplefilter("ignore", DeprecationWarning)
                    parser.timeout_micros = int(self._budget_s * 1_000_000)
            else:
                self._budget_s = 0.0
                if not _missing_knob_warned:
                    _missing_knob_warned = True
                    logger.warning(
                        "tree-sitter binding lacks Parser.timeout_micros; "
                        "parses run UNBOUNDED — crafted input can stall "
                        "analysis for minutes per file",
                    )

    def __getattr__(self, name: str) -> Any:
        return getattr(self._parser, name)

    def parse(self, source: Any, old_tree: Any = None) -> Any:
        # The binding rejects an explicit ``old_tree=None`` (it
        # demands a Tree), so only forward it when provided.
        args = (source,) if old_tree is None else (source, old_tree)
        if self._budget_s <= 0:
            return self._parser.parse(*args)
        started = time.monotonic()
        try:
            return self._parser.parse(*args)
        except ValueError:
            # The binding signals cancellation as a bare
            # ValueError("Parsing failed") — it offers no
            # discriminator, and a bytes parse with a valid language
            # raises ValueError for no other reason.
            elapsed = time.monotonic() - started
            try:
                self._parser.reset()
            except Exception:  # noqa: BLE001 — reset is best-effort
                logger.debug("bounded parse: reset failed", exc_info=True)
            try:
                self._record_gap(source, elapsed)
            except Exception:  # noqa: BLE001 — the abandonment signal
                # must stay ParseBudgetExceeded even when the trail
                # write itself fails; degradation paths key on it.
                logger.warning(
                    "bounded parse: gap record failed", exc_info=True,
                )
            raise ParseBudgetExceeded(
                f"{self._label or 'tree-sitter'} parse abandoned after "
                f"{elapsed:.1f}s (budget {self._budget_s:g}s)"
            ) from None

    def _record_gap(self, source: Any, elapsed: float) -> None:
        from core.run.gaps import current_parse_origin, record_analysis_gap
        origin = current_parse_origin()
        if origin is None:
            try:
                digest = hashlib.sha256(bytes(source)).hexdigest()[:12]
                size = len(source)
            except (TypeError, ValueError):
                digest, size = "unknown", -1
            origin = f"<unattributed content sha256:{digest} len={size}>"
        record_analysis_gap(
            file_path=origin,
            reason="parser budget exceeded",
            tool="tree-sitter",
            detail=(
                f"{self._label or 'parse'} abandoned after "
                f"{elapsed:.1f}s (budget {self._budget_s:g}s)"
            ),
        )


def bounded(parser: Any, label: str = "") -> Any:
    """Wrap *parser* in the parse budget; None and already-wrapped
    parsers pass through (the chokepoint is idempotent so routing
    call sites can never stack budgets)."""
    if parser is None or isinstance(parser, BoundedParser):
        return parser
    return BoundedParser(parser, label)


_TS_PARSER_LOCAL = threading.local()


def cached_parser(key: Any, make_language: "Callable[[], Any]") -> Any:
    """Per-thread cached tree-sitter ``Parser`` for *key*.

    ``make_language`` is called on a cache miss and must return a
    ``tree_sitter.Language`` (or ``None`` when the grammar OR the
    tree_sitter runtime is unavailable — the miss is NOT cached:
    absence is already cheap via the grammar-import cache, and not
    caching it lets a monkeypatched loader seam take effect
    immediately in tests). When tree_sitter itself isn't installed
    the in-repo loaders return None and so does this function —
    consumers degrade to their fallback extraction rather than
    catching an exception.
    """
    cache: dict[Any, Any] | None = getattr(
        _TS_PARSER_LOCAL, "parsers", None,
    )
    if cache is None:
        cache = {}
        _TS_PARSER_LOCAL.parsers = cache
    cached = cache.get(key)
    if cached is not None:
        return cached
    language = make_language()
    if language is None:
        return None
    from tree_sitter import Parser
    parser = bounded(Parser(language), label=str(key))
    cache[key] = parser
    return parser
