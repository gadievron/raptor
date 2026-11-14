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


@pytest.mark.parametrize("name", ["module..py", "pkg..name/module.py"])
def test_literal_dots_in_contained_names_do_not_hide_structural_source(tmp_path, name):
    source = tmp_path / name
    source.parent.mkdir(parents=True, exist_ok=True)
    source.write_text("def run():\n    value = input()\n    sink(value)\n")
    result = sv.validate_structurally({
        "source": {"file": name, "line": 2},
        "sink": {"file": name, "line": 3},
    }, tmp_path, language="python")
    assert result.verdict == "confirmed"
    assert all(step["exists"] for step in result.evidence)


def test_parent_segment_is_still_refused_for_contained_target(tmp_path):
    (tmp_path / "child").mkdir()
    (tmp_path / "module..py").write_text("def run():\n    return input()\n")
    name = "child/../module..py"
    result = sv.validate_structurally({
        "source": {"file": name, "line": 1},
        "sink": {"file": name, "line": 2},
    }, tmp_path, language="python")
    assert result.verdict == "inconclusive"
    assert all(not step["exists"] for step in result.evidence)
