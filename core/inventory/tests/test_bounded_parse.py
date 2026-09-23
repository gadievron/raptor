"""Bounded tree-sitter parse chokepoint (core.inventory._ts_cache).

The fixture below is a crafted ~50-char JavaScript prefix whose
nested unterminated template literals drive tree-sitter's C-level
error recovery superlinearly: unbudgeted, a fresh process parses it
for minutes (uninterruptible from Python) and can die on a failed
allocation under memory pressure. The chokepoint contract: the parse
aborts within the wall budget, the parser survives for reuse, and a
loud analysis-gap record names the file.
"""

from __future__ import annotations

import time

import pytest

ts = pytest.importorskip("tree_sitter")
pytest.importorskip("tree_sitter_javascript")

from core.inventory import _ts_cache, lexical_view  # noqa: E402
from core.run import gaps  # noqa: E402

# Crafted hostile input: nested unterminated template literals.
HOSTILE_JS = "`${e=\xff+(```` re =\xff+(nst s = `t ${ f() + `n}` } end`;\nc"

# Generous CI headroom above the sub-second test budget, far below
# the minutes the unbudgeted parse takes.
_WALL_CEILING_S = 8.0
_TEST_BUDGET_S = 0.5


@pytest.fixture(autouse=True)
def _fresh_gap_state(monkeypatch):
    monkeypatch.setattr(gaps, "_gap_count", 0)
    monkeypatch.setattr(gaps, "_pending", [])


def _fresh_js_parser(budget_s: float | None = None):
    import tree_sitter_javascript
    language = ts.Language(tree_sitter_javascript.language())
    return _ts_cache.BoundedParser(
        ts.Parser(language), label="javascript", budget_s=budget_s,
    )


def test_hostile_parse_aborts_within_budget(tmp_path, monkeypatch):
    import core.sandbox.summary as summary
    monkeypatch.setattr(summary, "_active_run_dir", tmp_path)
    parser = _fresh_js_parser(budget_s=_TEST_BUDGET_S)
    started = time.monotonic()
    with pytest.raises(_ts_cache.ParseBudgetExceeded):
        parser.parse(HOSTILE_JS.encode())
    assert time.monotonic() - started < _WALL_CEILING_S
    # The abandonment is durable and loud, not a silent skip.
    records = gaps.load_gaps(tmp_path)
    assert len(records) == 1
    assert records[0]["reason"] == "parser budget exceeded"
    assert records[0]["tool"] == "tree-sitter"


def test_parser_reusable_after_abandonment():
    parser = _fresh_js_parser(budget_s=_TEST_BUDGET_S)
    with pytest.raises(_ts_cache.ParseBudgetExceeded):
        parser.parse(HOSTILE_JS.encode())
    tree = parser.parse(b"var x = f(2);\n")
    assert tree.root_node.type == "program"
    assert not tree.root_node.has_error


def test_normal_parse_unaffected_by_budget():
    # Other direction of the budget trade-off: legitimate input must
    # parse well inside the default budget.
    parser = _fresh_js_parser()
    src = ("function f(a) { return a + 1; }\n" * 2000).encode()
    started = time.monotonic()
    tree = parser.parse(src)
    assert time.monotonic() - started < _WALL_CEILING_S
    assert not tree.root_node.has_error


def test_gap_record_names_parse_origin(tmp_path, monkeypatch):
    import core.sandbox.summary as summary
    monkeypatch.setattr(summary, "_active_run_dir", tmp_path)
    parser = _fresh_js_parser(budget_s=_TEST_BUDGET_S)
    with gaps.parse_origin("src/attacker.js"):
        with pytest.raises(_ts_cache.ParseBudgetExceeded):
            parser.parse(HOSTILE_JS.encode())
    records = gaps.load_gaps(tmp_path)
    assert records[0]["file_path"] == "src/attacker.js"


def test_gap_record_unattributed_names_content_digest(tmp_path, monkeypatch):
    import core.sandbox.summary as summary
    monkeypatch.setattr(summary, "_active_run_dir", tmp_path)
    parser = _fresh_js_parser(budget_s=_TEST_BUDGET_S)
    with pytest.raises(_ts_cache.ParseBudgetExceeded):
        parser.parse(HOSTILE_JS.encode())
    file_path = gaps.load_gaps(tmp_path)[0]["file_path"]
    assert file_path.startswith("<unattributed content sha256:")


def test_cached_parser_is_bounded():
    parser = lexical_view._parser_for("javascript")
    assert parser is not None
    assert isinstance(parser, _ts_cache.BoundedParser)


def test_blank_noncode_budget_refusal_not_silent_none(monkeypatch):
    monkeypatch.setenv("RAPTOR_TS_PARSE_BUDGET_S", str(_TEST_BUDGET_S))
    # A fresh thread gets a fresh parser cache, so the env budget
    # applies to the parser this call constructs.
    result: dict[str, object] = {}

    def _run() -> None:
        try:
            result["view"] = lexical_view.blank_noncode(
                "javascript", HOSTILE_JS,
            )
        except lexical_view.LexicalRefusal as exc:
            result["refusal"] = str(exc)

    import threading
    worker = threading.Thread(target=_run)
    worker.start()
    worker.join(timeout=60)
    assert not worker.is_alive()
    assert "refusal" in result, (
        "budget exhaustion must surface as LexicalRefusal, got "
        f"{result!r}"
    )
    assert "budget" in str(result["refusal"])


def test_bounded_wrap_idempotent_and_none_passthrough():
    assert _ts_cache.bounded(None) is None
    parser = _fresh_js_parser()
    assert _ts_cache.bounded(parser) is parser


def test_extract_names_file_in_gap_record(tmp_path, monkeypatch):
    import core.sandbox.summary as summary
    from core.inventory.extractors import TreeSitterExtractor
    monkeypatch.setattr(summary, "_active_run_dir", tmp_path)
    monkeypatch.setenv("RAPTOR_TS_PARSE_BUDGET_S", str(_TEST_BUDGET_S))
    result: dict[str, object] = {}

    def _run() -> None:
        extractor = TreeSitterExtractor("javascript")
        result["functions"] = extractor.extract(
            "src/salted.js", HOSTILE_JS,
        )

    import threading
    worker = threading.Thread(target=_run)
    worker.start()
    worker.join(timeout=60)
    assert not worker.is_alive()
    # Degrades to [] (regex fallback in the caller) — but never
    # silently: the gap record names the file.
    assert result["functions"] == []
    records = gaps.load_gaps(tmp_path)
    assert len(records) == 1
    assert records[0]["file_path"] == "src/salted.js"


def test_budget_env_override_and_bad_value(monkeypatch):
    monkeypatch.setenv("RAPTOR_TS_PARSE_BUDGET_S", "3.5")
    assert _ts_cache.parse_budget_s() == 3.5
    monkeypatch.setenv("RAPTOR_TS_PARSE_BUDGET_S", "not-a-number")
    assert _ts_cache.parse_budget_s() == _ts_cache.DEFAULT_PARSE_BUDGET_S
    monkeypatch.delenv("RAPTOR_TS_PARSE_BUDGET_S")
    assert _ts_cache.parse_budget_s() == _ts_cache.DEFAULT_PARSE_BUDGET_S


def test_zero_budget_disables_bound():
    parser = _fresh_js_parser(budget_s=0.0)
    tree = parser.parse(b"var x = 1;\n")
    assert not tree.root_node.has_error


def test_gap_fixture_reproduces_unbudgeted_hang_class():
    """Sanity: the fixture still drives error recovery hard enough
    that a short budget fires — guards against grammar upgrades
    quietly fixing the blowup and leaving these tests vacuous."""
    parser = _fresh_js_parser(budget_s=0.2)
    with pytest.raises(_ts_cache.ParseBudgetExceeded):
        parser.parse((HOSTILE_JS * 4).encode())


def test_budget_signal_survives_gap_record_failure(monkeypatch):
    """A failing trail write must not replace ParseBudgetExceeded:
    every degradation path (regex fallback, LexicalRefusal mapping)
    keys on that exception type."""
    parser = _fresh_js_parser(budget_s=_TEST_BUDGET_S)

    def boom(*a, **k):
        raise OSError("trail write refused")

    monkeypatch.setattr(gaps, "record_analysis_gap", boom)
    with pytest.raises(_ts_cache.ParseBudgetExceeded):
        parser.parse(HOSTILE_JS.encode())
