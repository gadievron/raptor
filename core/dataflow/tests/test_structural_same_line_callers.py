import functools

import pytest

from core.dataflow import structural_validator as sv
from core.testing.module_state import isolated_module_state


@pytest.fixture(autouse=True)
def _private_function_span_memo():
    original = sv._extract_functions_cached
    private = functools.lru_cache(**original.cache_parameters())(original.__wrapped__)
    with isolated_module_state(sv, {"_extract_functions_cached": private}):
        yield


@pytest.mark.parametrize("first_line", [
    "function first(v) { other(v); } function second(v) { helper(v); }",
    "other(value); function second(v) { unrelated(v); }",
])
def test_distinct_callers_on_one_line_cannot_prove_a_broken_edge(tmp_path, first_line):
    pytest.importorskip("tree_sitter_javascript")
    (tmp_path / "app.js").write_text(first_line + "\nfunction helper(v) { return v; }\n")
    result = sv.validate_structurally({
        "source": {"file": "app.js", "line": 1},
        "sink": {"file": "app.js", "line": 2},
    }, tmp_path, language="javascript")
    assert result.verdict == "inconclusive"
    assert not result.refuted


@pytest.mark.parametrize("callee,expected", [("helper", "confirmed"), ("other", "refuted")])
def test_repeated_calls_from_one_caller_remain_resolved(tmp_path, callee, expected):
    pytest.importorskip("tree_sitter_javascript")
    (tmp_path / "app.js").write_text(
        f"function first(v) {{ other(v); {callee}(v); }}\n"
        "function helper(v) { return v; }\n",
    )
    result = sv.validate_structurally({
        "source": {"file": "app.js", "line": 1},
        "sink": {"file": "app.js", "line": 2},
    }, tmp_path, language="javascript")
    assert result.verdict == expected


def test_ambiguous_destination_cannot_prove_a_broken_edge(tmp_path):
    pytest.importorskip("tree_sitter_javascript")
    (tmp_path / "app.js").write_text(
        "function start(v) { other(v); }\n"
        "function left(v) { sink(v); } function right(v) { start(v); }\n",
    )
    result = sv.validate_structurally({
        "source": {"file": "app.js", "line": 1},
        "sink": {"file": "app.js", "line": 2},
    }, tmp_path, language="javascript")
    assert result.verdict == "inconclusive"
