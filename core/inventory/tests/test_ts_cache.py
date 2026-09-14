"""Shared tree-sitter grammar/parser cache (core.inventory._ts_cache).

The failure-caching importer is a deadlock defence, not a perf
nicety: Python does NOT cache failed imports, so a per-file grammar
import on a grammar-less install re-acquires the import lock and the
logging handler locks for every file — the two acquisition sites a
fork-pool worker inherits FROZEN when the parent is multi-threaded.
The regression tests here pin the defence's shape on BOTH consumers
(extractors' loader historically lacked it): after one failed import,
subsequent lookups must touch neither the import machinery nor the
log handler again.
"""

from __future__ import annotations

import builtins
import importlib
import logging
import threading

import pytest

from core.inventory import _ts_cache, call_graph, extractors

_FAKE = "tree_sitter_zz_nonexistent"


@pytest.fixture
def fresh_caches(monkeypatch):
    """Empty shared grammar + parser caches, restored afterwards."""
    monkeypatch.setattr(_ts_cache, "_GRAMMAR_CACHE", {})
    monkeypatch.setattr(_ts_cache._TS_PARSER_LOCAL, "parsers", {},
                        raising=False)
    return _ts_cache


@pytest.fixture
def import_counter(monkeypatch):
    """Force + count import-machinery entries for the fake grammar."""
    calls: list[str] = []
    real = importlib.import_module

    def _counting(name, *a, **kw):
        if name.startswith("tree_sitter_"):
            calls.append(name)
            raise ImportError(f"forced absent: {name}")
        return real(name, *a, **kw)

    monkeypatch.setattr(importlib, "import_module", _counting)
    return calls


@pytest.fixture
def runtime_gate_open(monkeypatch):
    """Pin extractors' tree_sitter-runtime gate open.

    The failure-cache defence exists for runtime-PRESENT, grammar-less
    installs; the loader's mixed-install guard answers None before the
    shared cache when the runtime itself is absent. Bare environments
    (CI installs requirements-dev.txt only — no tree_sitter) would
    otherwise exercise the guard instead of the cache path these tests
    pin. The grammar import below is force-failed either way, so the
    ``Language(...)`` wrap the gate protects is never reached."""
    monkeypatch.setattr(extractors, "_TS_AVAILABLE", True)


def test_failed_import_runs_import_machinery_once(
        fresh_caches, import_counter, caplog):
    with caplog.at_level(logging.DEBUG, logger=_ts_cache.__name__):
        for _ in range(5):
            assert _ts_cache.import_grammar(_FAKE) is None
    assert import_counter == [_FAKE], (
        "failed grammar import must be cached — every retry re-enters "
        "the import machinery (fork-frozen lock hazard)"
    )
    notes = [r for r in caplog.records if _FAKE in r.getMessage()]
    assert len(notes) == 1, "missing-grammar note must fire once per process"


def test_extractors_loader_inherits_the_failure_cache(
        fresh_caches, import_counter, runtime_gate_open):
    """The historical gap: extractors._ts_language re-imported per
    call on a grammar-less install."""
    for _ in range(5):
        assert extractors._ts_language("go") is None
    assert import_counter == ["tree_sitter_go"]


def test_extractors_parser_path_inherits_the_failure_cache(
        fresh_caches, import_counter, runtime_gate_open):
    for _ in range(5):
        assert extractors._ts_parser_for("go") is None
    assert import_counter == ["tree_sitter_go"]


def test_call_graph_loader_shares_the_same_cache(
        fresh_caches, import_counter, runtime_gate_open):
    assert extractors._ts_language("go") is None
    assert call_graph._import_grammar("tree_sitter_go") is None
    assert import_counter == ["tree_sitter_go"], (
        "the two consumers must share ONE grammar cache"
    )


def test_success_is_cached_and_absence_is_not_sticky(fresh_caches):
    """Success caches the module; a monkeypatched loader seam takes
    effect immediately because parser-cache misses are re-probed."""
    mod = _ts_cache.import_grammar("json")  # any importable module
    assert mod is not None
    assert _ts_cache.import_grammar("json") is mod

    probes: list[int] = []

    def _absent():
        probes.append(1)
        return None

    assert _ts_cache.cached_parser("zz-lang", _absent) is None
    assert _ts_cache.cached_parser("zz-lang", _absent) is None
    assert len(probes) == 2, (
        "absence must NOT be cached in the parser cache — the grammar "
        "cache already makes it cheap, and test seams rely on re-probe"
    )


def test_parser_cache_is_shared_and_key_spaces_disjoint(fresh_caches):
    pytest.importorskip("tree_sitter")
    ts_python = pytest.importorskip("tree_sitter_python")

    p1 = extractors._ts_parser_for("python")
    p2 = extractors._ts_parser_for("python")
    assert p1 is not None and p1 is p2

    cg = call_graph._get_ts_parser(ts_python.language)
    assert cg is call_graph._get_ts_parser(ts_python.language)

    cache = _ts_cache._TS_PARSER_LOCAL.parsers
    assert "python" in cache
    assert id(ts_python.language) in cache
    assert extractors._TS_PARSER_LOCAL is _ts_cache._TS_PARSER_LOCAL


def test_parser_cache_is_per_thread(fresh_caches):
    pytest.importorskip("tree_sitter")
    pytest.importorskip("tree_sitter_python")

    main_parser = extractors._ts_parser_for("python")
    seen: list[object] = []

    def _worker():
        seen.append(extractors._ts_parser_for("python"))

    t = threading.Thread(target=_worker)
    t.start()
    t.join()
    assert seen[0] is not None
    assert seen[0] is not main_parser, (
        "Parser holds C-side parse state — threads must not share one"
    )


def test_missing_tree_sitter_raises_from_call_graph_seam(
        fresh_caches, monkeypatch):
    """_get_ts_parser's documented contract: ImportError when
    tree_sitter itself is absent (callers catch it per-file)."""
    real_import = builtins.__import__

    def _no_ts(name, *a, **kw):
        if name == "tree_sitter":
            raise ImportError("forced absent: tree_sitter")
        return real_import(name, *a, **kw)

    monkeypatch.setattr(builtins, "__import__", _no_ts)
    with pytest.raises(ImportError):
        call_graph._get_ts_parser(lambda: None)
