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
The two consumers share the dict with disjoint key spaces: extractors
keys by language-name string, call_graph by grammar-function identity
(int), so the spaces cannot collide.
"""

from __future__ import annotations

import importlib
import logging
import threading
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
    parser = Parser(language)
    cache[key] = parser
    return parser
